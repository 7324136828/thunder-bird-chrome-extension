//! Bounded in-process audit workers with cooperative cancellation (port of
//! `backend/app/doctor/services/runner.py`), plus the route-level operations
//! of `backend/app/doctor/router.py` so the HTTP layer stays thin.
//!
//! Workers run the pipeline on their own threads (at most two at a time;
//! up to `max_active_jobs` queued or running). A discarded job is marked
//! immediately, but its workspace is only purged after its worker exits, so
//! no thread can recreate files after the purge.
//!
//! Every method blocks; call them from `tokio::task::spawn_blocking`.

use crate::cancellation::{cancellation_context, check_cancel, AuditCancelled, ShouldCancel};
use crate::config::DoctorSettings;
use crate::db::{utcnow, JobField, JobRecord, JobStore, NewJob};
use crate::mailbox_download::{
    self, DownloadError, DownloadHooks, DownloadOptions, MailboxAuth, MailboxDownloadError,
};
use crate::metrics::MetricStore;
use crate::oauth::{render_callback_page, CallbackMessage, OAuthService};
use crate::pipeline::{PipelineError, PipelineEvent};
use crate::schemas::{AccountJobIn, JobOut, MailCredentialsIn, OAuthStartIn, PasteJobIn};
use crate::temp_manager::{self, Workspace, WorkspaceError};
use mail_core::{MailAccount, MailError, SessionStore};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, RwLock};
use std::thread::ThreadId;
use std::time::{Duration, Instant};

/// Human-readable stage names written to the job log (`STAGE_LABELS`).
pub fn stage_label(stage: &str) -> &str {
    match stage {
        "connecting" => "Connecting to mailbox",
        "downloading" => "Downloading recent INBOX messages",
        "snapshot" => "Refreshing audit snapshot",
        "extract" => "Parsing messages",
        "group" => "Grouping senders",
        "summarize" => "Building summary",
        "worklist" => "Generating cleanup worklist",
        "report" => "Rendering HTML report",
        "done" => "Done",
        other => other,
    }
}

/// Detail of the 429 returned while every worker slot is taken.
pub const CAPACITY_MESSAGE: &str = "Too many audits are running; wait for a job to finish";
/// Name of the packaged report archive (`temp_manager.ZIP_NAME`).
pub const ZIP_NAME: &str = temp_manager::ZIP_NAME;
/// Concurrent pipeline executions (`threading.Semaphore(2)`).
const WORKER_SLOTS: usize = 2;
/// Extensions that count as mail data in an upload.
const DATA_EXTENSIONS: [&str; 3] = [".eml", ".mbox", ".zip"];

/// Python `JobRunner._safe_error`: redact the password / access token, then
/// cap the message at 4000 characters.
pub fn safe_error(message: &str, auth: Option<&MailboxAuth>) -> String {
    let mut message = message.to_string();
    if let Some(auth) = auth {
        for secret in auth.secrets() {
            message = message.replace(secret, "[redacted]");
        }
    }
    message.chars().take(4000).collect()
}

// ---------------------------------------------------------------------------
// Reentrant lock (Python `threading.RLock`)
// ---------------------------------------------------------------------------

/// A reentrant mutex without data, like Python's `RLock`: the owning thread
/// may lock it again (e.g. `create_mail_job` → `ensure_capacity`).
#[derive(Debug, Default)]
pub struct ReentrantLock {
    state: Mutex<(Option<ThreadId>, usize)>,
    released: Condvar,
}

/// Guard returned by [`ReentrantLock::lock`].
#[must_use]
pub struct ReentrantGuard<'a> {
    lock: &'a ReentrantLock,
}

impl ReentrantLock {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn lock(&self) -> ReentrantGuard<'_> {
        let me = std::thread::current().id();
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        loop {
            match state.0 {
                Some(owner) if owner == me => break,
                None => {
                    state.0 = Some(me);
                    break;
                }
                Some(_) => state = self.released.wait(state).unwrap_or_else(|p| p.into_inner()),
            }
        }
        state.1 += 1;
        ReentrantGuard { lock: self }
    }
}

impl Drop for ReentrantGuard<'_> {
    fn drop(&mut self) {
        let mut state = self.lock.state.lock().unwrap_or_else(|p| p.into_inner());
        state.1 -= 1;
        if state.1 == 0 {
            state.0 = None;
            self.lock.released.notify_one();
        }
    }
}

// ---------------------------------------------------------------------------
// Small synchronization helpers
// ---------------------------------------------------------------------------

/// Counting semaphore with a timed acquire.
#[derive(Debug)]
struct Slots {
    free: Mutex<usize>,
    changed: Condvar,
}

impl Slots {
    fn new(count: usize) -> Self {
        Self {
            free: Mutex::new(count),
            changed: Condvar::new(),
        }
    }

    fn acquire(&self, timeout: Duration) -> bool {
        let free = self.free.lock().unwrap_or_else(|p| p.into_inner());
        let (mut free, _) = self
            .changed
            .wait_timeout_while(free, timeout, |free| *free == 0)
            .unwrap_or_else(|p| p.into_inner());
        if *free == 0 {
            return false;
        }
        *free -= 1;
        true
    }

    fn release(&self) {
        *self.free.lock().unwrap_or_else(|p| p.into_inner()) += 1;
        self.changed.notify_one();
    }
}

/// A one-shot "worker finished" signal supporting `join(timeout)`.
#[derive(Debug, Default)]
struct Done {
    finished: Mutex<bool>,
    changed: Condvar,
}

impl Done {
    fn set(&self) {
        *self.finished.lock().unwrap_or_else(|p| p.into_inner()) = true;
        self.changed.notify_all();
    }

    fn wait(&self, timeout: Duration) -> bool {
        let finished = self.finished.lock().unwrap_or_else(|p| p.into_inner());
        let (finished, _) = self
            .changed
            .wait_timeout_while(finished, timeout, |finished| !*finished)
            .unwrap_or_else(|p| p.into_inner());
        *finished
    }
}

struct ActiveJob {
    cancel: Arc<AtomicBool>,
    done: Arc<Done>,
}

// ---------------------------------------------------------------------------
// Injectable pipeline / downloader (Python tests patched these functions)
// ---------------------------------------------------------------------------

/// Signature of [`crate::pipeline::try_run_pipeline`]: the event callback
/// may fail (Python's `_event` raised `AuditCancelled` from inside the
/// pipeline once the job was discarded) and its error aborts the run.
pub type PipelineHook = Arc<
    dyn Fn(
            &Path,
            Option<i64>,
            &mut dyn FnMut(PipelineEvent) -> Result<(), PipelineError>,
            u64,
            usize,
        ) -> Result<(), PipelineError>
        + Send
        + Sync,
>;
/// Signature of [`mailbox_download::download_inbox`].
pub type DownloadHook = Arc<
    dyn Fn(&DownloadOptions<'_>, &mut DownloadHooks<'_>) -> Result<(usize, usize), DownloadError>
        + Send
        + Sync,
>;

/// The functions a runner calls to audit and download. The default is the
/// real report pipeline ([`crate::pipeline::try_run_pipeline`]) and the real
/// IMAP downloader; tests replace them where the Python tests patched
/// `pipeline.run_pipeline` / `mailbox_download.download_inbox`.
#[derive(Clone)]
pub struct RunnerHooks {
    pub pipeline: PipelineHook,
    pub download: DownloadHook,
}

impl RunnerHooks {
    /// The production report pipeline.
    pub fn real_pipeline() -> PipelineHook {
        Arc::new(crate::pipeline::try_run_pipeline)
    }

    /// The production IMAP downloader.
    pub fn real_download() -> DownloadHook {
        Arc::new(mailbox_download::download_inbox)
    }
}

impl Default for RunnerHooks {
    fn default() -> Self {
        Self {
            pipeline: Self::real_pipeline(),
            download: Self::real_download(),
        }
    }
}

// ---------------------------------------------------------------------------
// Worker errors
// ---------------------------------------------------------------------------

enum WorkerError {
    Cancelled,
    Failed(String),
}

impl From<AuditCancelled> for WorkerError {
    fn from(_: AuditCancelled) -> Self {
        Self::Cancelled
    }
}

impl From<PipelineError> for WorkerError {
    fn from(error: PipelineError) -> Self {
        match error {
            PipelineError::Cancelled(_) => Self::Cancelled,
            other => Self::Failed(other.to_string()),
        }
    }
}

impl From<DownloadError> for WorkerError {
    fn from(error: DownloadError) -> Self {
        if error.is_cancellation() {
            Self::Cancelled
        } else {
            Self::Failed(error.to_string())
        }
    }
}

impl From<MailboxDownloadError> for WorkerError {
    fn from(error: MailboxDownloadError) -> Self {
        Self::Failed(error.0)
    }
}

impl From<MailError> for WorkerError {
    fn from(error: MailError) -> Self {
        Self::Failed(error.to_string())
    }
}

impl From<std::io::Error> for WorkerError {
    fn from(error: std::io::Error) -> Self {
        Self::Failed(error.to_string())
    }
}

impl From<WorkspaceError> for WorkerError {
    fn from(error: WorkspaceError) -> Self {
        match error {
            WorkspaceError::Cancelled(_) => Self::Cancelled,
            other => Self::Failed(other.to_string()),
        }
    }
}

/// Python lets `ValueError` from the workspace (an invalid job ID) reach the
/// `ValueError` handler (422 with the message); I/O failures are 500s.
fn workspace_error(error: WorkspaceError) -> MailError {
    match error {
        WorkspaceError::Invalid(message) => MailError::validation(message),
        other => internal(other),
    }
}

// ---------------------------------------------------------------------------
// Route helper types
// ---------------------------------------------------------------------------

/// One uploaded file for [`JobRunner::create_upload_job`].
pub struct UploadFile<'a> {
    /// The client-supplied filename (untrusted; sanitized before use).
    pub filename: Option<String>,
    pub reader: Box<dyn Read + Send + 'a>,
}

/// A complete file response read under the runner lock.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileResponse {
    pub body: Vec<u8>,
    /// `Content-Type`, including `; charset=utf-8` for `text/*` like Starlette.
    pub media_type: String,
    pub headers: Vec<(String, String)>,
}

fn http(status: u16, detail: &str) -> MailError {
    MailError::http(status, detail)
}

fn internal(error: impl std::fmt::Display) -> MailError {
    MailError::Settings(error.to_string())
}

/// Python `router.validate_email`.
pub fn validate_email(address: &str) -> Result<String, MailError> {
    let address = address.trim();
    if address.matches('@').count() != 1
        || mailbox_download::email_domain(address).is_empty()
        || address.chars().any(char::is_whitespace)
        || address.contains('\0')
    {
        return Err(MailError::bad_request("Enter a valid email address"));
    }
    Ok(address.to_string())
}

// ---------------------------------------------------------------------------
// JobRunner
// ---------------------------------------------------------------------------

struct Inner {
    settings: DoctorSettings,
    db: JobStore,
    metrics: MetricStore,
    workspace: Workspace,
    oauth: OAuthService,
    lock: ReentrantLock,
    active: Mutex<HashMap<String, ActiveJob>>,
    slots: Slots,
    closed: AtomicBool,
    hooks: RwLock<RunnerHooks>,
}

/// Python `JobRunner` (cheap to clone; clones share all state).
#[derive(Clone)]
pub struct JobRunner {
    inner: Arc<Inner>,
}

impl std::fmt::Debug for JobRunner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JobRunner")
            .field("settings", &self.inner.settings)
            .field("active_jobs", &self.active_job_ids())
            .finish()
    }
}

impl JobRunner {
    pub fn new(settings: DoctorSettings) -> Self {
        Self::with_hooks(settings, RunnerHooks::default())
    }

    /// A runner whose pipeline / downloader are replaced (tests).
    pub fn with_hooks(settings: DoctorSettings, hooks: RunnerHooks) -> Self {
        let db = JobStore::new(&settings);
        Self {
            inner: Arc::new(Inner {
                metrics: MetricStore::new(db.clone()),
                workspace: Workspace::new(settings.jobs_root()),
                oauth: OAuthService::new(&settings),
                db,
                settings,
                lock: ReentrantLock::new(),
                active: Mutex::new(HashMap::new()),
                slots: Slots::new(WORKER_SLOTS),
                closed: AtomicBool::new(false),
                hooks: RwLock::new(hooks),
            }),
        }
    }

    /// Replace the pipeline / downloader of this (shared) runner; jobs that
    /// start afterwards use the new hooks. For tests that drive the runner
    /// through the HTTP layer, where Python patched module functions.
    #[doc(hidden)]
    pub fn replace_hooks(&self, hooks: RunnerHooks) {
        *self.inner.hooks.write().unwrap_or_else(|p| p.into_inner()) = hooks;
    }

    fn hooks(&self) -> RunnerHooks {
        self.inner
            .hooks
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }

    pub fn settings(&self) -> &DoctorSettings {
        &self.inner.settings
    }

    pub fn db(&self) -> &JobStore {
        &self.inner.db
    }

    pub fn metrics(&self) -> &MetricStore {
        &self.inner.metrics
    }

    pub fn oauth(&self) -> &OAuthService {
        &self.inner.oauth
    }

    /// `runner.workspace` (`temp_manager.Workspace` over the jobs root).
    pub fn workspace(&self) -> &Workspace {
        &self.inner.workspace
    }

    /// The runner lock (`runner.lock`) shared with snapshot publishing,
    /// discard and file reads.
    pub fn lock(&self) -> ReentrantGuard<'_> {
        self.inner.lock.lock()
    }

    /// Python `initialize`: create the jobs root and schemas, recover
    /// interrupted jobs and backfill metrics from retained reports.
    pub fn initialize(&self) -> Result<(), MailError> {
        std::fs::create_dir_all(self.inner.settings.jobs_root()).map_err(internal)?;
        self.inner.db.init_db()?;
        self.inner.metrics.init_db()?;
        let jobs = self.inner.db.list_jobs()?;
        self.inner
            .metrics
            .backfill(&jobs, |job_id| self.job_dir_for(job_id).ok())?;
        Ok(())
    }

    // -- workspace --------------------------------------------------------

    /// `Workspace.job_dir_for`: the managed directory of a 32-hex job ID.
    pub fn job_dir_for(&self, job_id: &str) -> Result<PathBuf, MailError> {
        self.inner
            .workspace
            .job_dir_for(job_id)
            .map_err(workspace_error)
    }

    /// `Workspace.create_job_dirs`.
    pub fn create_job_dirs(&self, job_id: &str) -> Result<PathBuf, MailError> {
        self.inner
            .workspace
            .create_job_dirs(job_id)
            .map_err(workspace_error)
    }

    /// `Workspace.purge_job_dir`.
    pub fn purge_job_dir(&self, directory: &Path) -> Result<(), MailError> {
        self.inner
            .workspace
            .purge_job_dir(directory)
            .map_err(workspace_error)
    }

    // -- capacity and workers ---------------------------------------------

    pub fn active_job_ids(&self) -> Vec<String> {
        let _guard = self.lock();
        self.inner.active.lock().unwrap().keys().cloned().collect()
    }

    /// Python `ensure_capacity` (429 when closed or full).
    pub fn ensure_capacity(&self) -> Result<(), MailError> {
        let _guard = self.lock();
        let active = self.inner.active.lock().unwrap().len();
        if self.inner.closed.load(Ordering::SeqCst) || active >= self.inner.settings.max_active_jobs
        {
            return Err(http(429, CAPACITY_MESSAGE));
        }
        Ok(())
    }

    /// Start the worker of an upload / paste job.
    pub fn start_job(&self, job_id: &str) -> Result<(), MailError> {
        self.start(job_id, None)
    }

    /// Start the worker of a mailbox job; `auth` stays in memory and is
    /// wiped when the worker ends.
    pub fn start_mailbox_job(&self, job_id: &str, auth: MailboxAuth) -> Result<(), MailError> {
        self.start(job_id, Some(auth))
    }

    fn start(&self, job_id: &str, auth: Option<MailboxAuth>) -> Result<(), MailError> {
        let _guard = self.lock();
        self.ensure_capacity()?;
        let directory = self.job_dir_for(job_id)?;
        let cancel = Arc::new(AtomicBool::new(false));
        let done = Arc::new(Done::default());
        self.inner.active.lock().unwrap().insert(
            job_id.to_string(),
            ActiveJob {
                cancel: cancel.clone(),
                done: done.clone(),
            },
        );
        let runner = self.clone();
        let id = job_id.to_string();
        let spawned = std::thread::Builder::new()
            .name(format!("inbox-doctor-{}", &job_id[..8]))
            .spawn(move || runner.worker(id, auth, cancel, done));
        if spawned.is_err() {
            self.inner.active.lock().unwrap().remove(job_id);
            self.inner.db.update_job(
                job_id,
                &[
                    JobField::status("failed"),
                    JobField::stage("failed"),
                    JobField::CompletedAt(Some(utcnow())),
                    JobField::ErrorMessage(Some(
                        "The application could not start an audit worker".into(),
                    )),
                ],
                false,
            )?;
            self.purge_job_dir(&directory)?;
            return Err(internal("The application could not start an audit worker"));
        }
        Ok(())
    }

    fn update_active(&self, job_id: &str, fields: &[JobField]) -> Result<bool, MailError> {
        self.inner.db.update_job(job_id, fields, true)
    }

    fn log_active(&self, job_id: &str, line: &str) -> Result<(), MailError> {
        self.inner.db.append_log(job_id, line, true)
    }

    /// Python `_event`: record pipeline progress; once the job is cancelled
    /// the callback raises `AuditCancelled`, aborting the pipeline.
    fn record_event(
        &self,
        job_id: &str,
        cancel: &AtomicBool,
        event: PipelineEvent,
        mailbox: bool,
    ) -> Result<(), PipelineError> {
        if cancel.load(Ordering::SeqCst) {
            return Err(AuditCancelled.into());
        }
        // Database failures inside `_event` propagate (failing the job) as
        // in Python.
        let recorded = match event {
            PipelineEvent::Stage(stage) => self
                .update_active(job_id, &[JobField::Stage(Some(stage.clone()))])
                .and_then(|_| {
                    self.log_active(job_id, &format!("--- stage: {} ---", stage_label(&stage)))
                }),
            PipelineEvent::Progress(value) => {
                let progress = if mailbox {
                    60 + (value as f64 * 0.39) as i64
                } else {
                    value
                };
                self.update_active(job_id, &[JobField::Progress(progress)])
                    .map(|_| ())
            }
            PipelineEvent::Log(text) => self.log_active(job_id, &text),
        };
        recorded.map_err(|error| PipelineError::Failed(error.to_string()))
    }

    /// Python `_audit`: run the pipeline with the configured limits.
    fn audit(
        &self,
        directory: &Path,
        days: Option<i64>,
        event: &mut dyn FnMut(PipelineEvent) -> Result<(), PipelineError>,
    ) -> Result<(), PipelineError> {
        let settings = &self.inner.settings;
        let pipeline = self.hooks().pipeline;
        pipeline(
            directory,
            days,
            event,
            settings.max_expanded_bytes,
            settings.max_archive_members,
        )
    }

    /// Python `_publish_snapshot`: audit a copy of the inputs downloaded so
    /// far and atomically replace `snapshot_outputs/`.
    fn publish_snapshot(
        &self,
        job_id: &str,
        directory: &Path,
        days: Option<i64>,
    ) -> Result<(), WorkerError> {
        let build = directory.join("_snapshot_build");
        let _ = std::fs::remove_dir_all(&build);
        std::fs::create_dir_all(build.join("inputs"))?;
        let inputs = directory.join("inputs");
        for source in temp_manager::walk_files(&inputs) {
            check_cancel()?;
            let suffix = py_suffix_of(&source).to_lowercase();
            if suffix == ".eml" || suffix == ".json" {
                let relative = source.strip_prefix(&inputs).map_err(internal)?;
                let target = build.join("inputs").join(relative);
                if let Some(parent) = target.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                std::fs::copy(&source, &target)?;
            }
        }
        self.audit(&build, days, &mut |_| Ok(check_cancel()?))?;
        {
            let _guard = self.lock();
            check_cancel()?;
            let target = directory.join("snapshot_outputs");
            let old = directory.join("_snapshot_previous");
            let _ = std::fs::remove_dir_all(&old);
            if target.exists() {
                std::fs::rename(&target, &old)?;
            }
            std::fs::rename(build.join("outputs"), &target)?;
            self.update_active(
                job_id,
                &[
                    JobField::SnapshotAvailable(true),
                    JobField::SnapshotAt(Some(utcnow())),
                ],
            )?;
            self.log_active(job_id, "Audit snapshot refreshed.")?;
            let _ = std::fs::remove_dir_all(&old);
        }
        let _ = std::fs::remove_dir_all(&build);
        Ok(())
    }

    /// Python `_download`; returns `false` for an empty (healthy) window.
    fn download(
        &self,
        job_id: &str,
        job: &JobRecord,
        auth: &MailboxAuth,
        cancel: &Arc<AtomicBool>,
    ) -> Result<bool, WorkerError> {
        let directory = self.job_dir_for(job_id)?;
        let days = job.days.filter(|days| *days != 0).unwrap_or(7);
        // IMAP already selected the fixed window. A catch-up run must not
        // apply a second cutoff relative to today when producing its briefing.
        let briefing_days = if job.window_start.as_deref().is_some_and(|s| !s.is_empty()) {
            None
        } else {
            Some(days)
        };
        self.update_active(
            job_id,
            &[
                JobField::status("in_progress"),
                JobField::stage("connecting"),
                JobField::Progress(2),
            ],
        )?;
        let account_email = job.account_email.clone().unwrap_or_default();
        self.log_active(
            job_id,
            &format!("Connecting to the INBOX for {account_email}."),
        )?;

        let output_dir = directory.join("inputs").join("mailbox");
        let window_start = job.window_start.as_deref().filter(|s| !s.is_empty());
        let window_end = job.window_end.as_deref().filter(|s| !s.is_empty());
        let mut options = DownloadOptions::new(&account_email, &output_dir, days, auth);
        options.window_start = window_start;
        options.window_end = window_end;
        options.max_bytes = self.inner.settings.max_upload_bytes;
        options.max_messages = self.inner.settings.max_messages;

        let db_failure = |error: MailError| DownloadError::Other(error.to_string());
        let mut last_snapshot = 0usize;
        let snapshot_every = self.inner.settings.snapshot_every_messages;
        let cancel_flag = cancel.clone();
        let mut hooks = DownloadHooks {
            progress: Box::new(|done, total| {
                check_cancel()?;
                let progress = 8 + (47 * done / total.max(1)) as i64;
                self.update_active(
                    job_id,
                    &[
                        JobField::stage("downloading"),
                        JobField::Progress(progress),
                        JobField::DownloadedMessages(done as i64),
                        JobField::TotalMessages(Some(total as i64)),
                    ],
                )
                .map_err(db_failure)?;
                Ok(())
            }),
            log: Box::new(|message| {
                let _ = self.log_active(job_id, &safe_error(message, Some(auth)));
            }),
            should_cancel: Box::new(move || cancel_flag.load(Ordering::SeqCst)),
            on_batch: Box::new(|done, total| {
                check_cancel()?;
                if (done == 1 || done - last_snapshot >= snapshot_every) && done < total {
                    self.update_active(job_id, &[JobField::stage("snapshot")])
                        .map_err(db_failure)?;
                    let published = self.publish_snapshot(job_id, &directory, briefing_days);
                    let restored = self.update_active(job_id, &[JobField::stage("downloading")]);
                    match published {
                        Ok(()) => last_snapshot = done,
                        Err(WorkerError::Cancelled) => return Err(AuditCancelled.into()),
                        Err(WorkerError::Failed(message)) => {
                            let _ = self.log_active(
                                job_id,
                                &format!(
                                    "Snapshot refresh skipped: {}",
                                    safe_error(&message, Some(auth))
                                ),
                            );
                        }
                    }
                    restored.map_err(db_failure)?;
                }
                Ok(())
            }),
        };
        let download = self.hooks().download;
        let (downloaded, total) = download(&options, &mut hooks)?;
        drop(hooks);
        check_cancel()?;
        if total == 0 {
            self.update_active(
                job_id,
                &[
                    JobField::DownloadedMessages(0),
                    JobField::TotalMessages(Some(0)),
                ],
            )?;
            let message = if job.run_kind == "scheduled" {
                format!(
                    "No INBOX messages were found in [{}, {}).",
                    job.window_start.as_deref().unwrap_or("None"),
                    job.window_end.as_deref().unwrap_or("None")
                )
            } else {
                format!("No INBOX messages were found in the last {days} day(s).")
            };
            self.log_active(job_id, &message)?;
            return Ok(false);
        }
        if downloaded == 0 {
            return Err(MailboxDownloadError::new(
                "INBOX messages were found, but none could be downloaded for the audit.",
            )
            .into());
        }
        if job.run_kind == "scheduled" && downloaded != total {
            return Err(MailboxDownloadError::new(
                "Some messages could not be downloaded; the weekly audit will be retried.",
            )
            .into());
        }
        let size: u64 = temp_manager::walk_files(&directory.join("inputs"))
            .into_iter()
            .filter(|path| py_suffix_of(path) == ".eml")
            .filter_map(|path| std::fs::metadata(path).ok())
            .map(|metadata| metadata.len())
            .sum();
        self.update_active(
            job_id,
            &[
                JobField::FileSize(size as i64),
                JobField::DownloadedMessages(downloaded as i64),
                JobField::TotalMessages(Some(total as i64)),
                JobField::stage("extract"),
                JobField::Progress(58),
            ],
        )?;
        self.log_active(
            job_id,
            &format!("Downloaded {downloaded} messages; starting final audit."),
        )?;
        self.audit(&directory, briefing_days, &mut |event| {
            self.record_event(job_id, cancel, event, true)
        })?;
        Ok(true)
    }

    /// Python `_record_metrics`: failures never fail the audit.
    fn record_metrics(&self, job_id: &str, directory: &Path) {
        let captured = self.inner.db.get_job(job_id).and_then(|job| {
            job.map_or(Ok(false), |job| self.inner.metrics.capture(&job, directory))
        });
        if captured.is_err() {
            // Reports remain usable; startup backfills this successful run.
            let _ = self.inner.db.append_log(
                job_id,
                "Metrics could not be saved; the application will retry after restart.",
                false,
            );
        }
    }

    fn worker(
        &self,
        job_id: String,
        auth: Option<MailboxAuth>,
        cancel: Arc<AtomicBool>,
        done: Arc<Done>,
    ) {
        let mut acquired = false;
        let directory = self.inner.workspace.jobs_root().join(&job_id);
        let flag = cancel.clone();
        let should_cancel: ShouldCancel = Arc::new(move || flag.load(Ordering::SeqCst));
        let result = cancellation_context(should_cancel, self.inner.settings.max_messages, || {
            self.run_job(&job_id, auth.as_ref(), &cancel, &directory, &mut acquired)
        });
        if let Err(WorkerError::Failed(error)) = result {
            if !cancel.load(Ordering::SeqCst) {
                let message = safe_error(&error, auth.as_ref());
                let _ = self.update_active(
                    &job_id,
                    &[
                        JobField::status("failed"),
                        JobField::stage("failed"),
                        JobField::ErrorMessage(Some(message.clone())),
                        JobField::CompletedAt(Some(utcnow())),
                    ],
                );
                let _ =
                    self.inner
                        .db
                        .append_log(&job_id, &format!("Audit failed: {message}"), false);
            }
        }
        drop(auth);
        if acquired {
            self.inner.slots.release();
        }
        {
            let _guard = self.lock();
            if cancel.load(Ordering::SeqCst) {
                let _ = self.purge_job_dir(&directory);
            }
            self.inner.active.lock().unwrap().remove(&job_id);
        }
        done.set();
    }

    fn run_job(
        &self,
        job_id: &str,
        auth: Option<&MailboxAuth>,
        cancel: &Arc<AtomicBool>,
        directory: &Path,
        acquired: &mut bool,
    ) -> Result<(), WorkerError> {
        while !*acquired {
            check_cancel()?;
            *acquired = self.inner.slots.acquire(Duration::from_millis(200));
        }
        check_cancel()?;
        let Some(job) = self.inner.db.get_job(job_id)? else {
            return Ok(());
        };
        self.update_active(
            job_id,
            &[
                JobField::status("in_progress"),
                JobField::stage("starting"),
                JobField::Progress(2),
            ],
        )?;
        match auth {
            None => {
                self.audit(directory, job.days, &mut |event| {
                    self.record_event(job_id, cancel, event, false)
                })?;
            }
            Some(auth) => {
                if !self.download(job_id, &job, auth, cancel)? {
                    let _guard = self.lock();
                    check_cancel()?;
                    self.update_active(
                        job_id,
                        &[
                            JobField::status("healthy"),
                            JobField::stage("healthy"),
                            JobField::Progress(100),
                            JobField::ErrorMessage(None),
                            JobField::CompletedAt(Some(utcnow())),
                        ],
                    )?;
                    self.inner
                        .db
                        .append_log(job_id, "Audit finished; inbox is healthy.", false)?;
                    self.record_metrics(job_id, directory);
                    return Ok(());
                }
            }
        }
        check_cancel()?;
        let archive = temp_manager::package_outputs(directory)?;
        let _guard = self.lock();
        check_cancel()?;
        let mailbox = auth.is_some();
        self.update_active(
            job_id,
            &[
                JobField::status("completed"),
                JobField::stage("done"),
                JobField::Progress(100),
                JobField::ZipPath(Some(archive.to_string_lossy().into_owned())),
                JobField::CompletedAt(Some(utcnow())),
                JobField::SnapshotAvailable(mailbox),
                JobField::SnapshotAt(mailbox.then(utcnow)),
            ],
        )?;
        self.inner
            .db
            .append_log(job_id, "Audit finished; outputs packaged.", false)?;
        self.record_metrics(job_id, directory);
        Ok(())
    }

    /// Python `discard_job`: mark the job discarded, cancel its worker and
    /// purge its workspace (immediately, or when the worker exits).
    /// Returns `false` for a missing or already discarded job.
    pub fn discard_job(&self, job_id: &str) -> Result<bool, MailError> {
        let done = {
            let _guard = self.lock();
            let Some(job) = self.inner.db.get_job(job_id)? else {
                return Ok(false);
            };
            if job.status == "discarded" {
                return Ok(false);
            }
            let control = self
                .inner
                .active
                .lock()
                .unwrap()
                .get(job_id)
                .map(|active| (active.cancel.clone(), active.done.clone()));
            if let Some((cancel, _)) = &control {
                cancel.store(true, Ordering::SeqCst);
            }
            self.inner.db.update_job(
                job_id,
                &[
                    JobField::status("discarded"),
                    JobField::stage("discarded"),
                    JobField::ErrorMessage(Some("Discarded by user".into())),
                    JobField::SnapshotAvailable(false),
                    JobField::ZipPath(None),
                    JobField::CompletedAt(Some(utcnow())),
                ],
                false,
            )?;
            self.inner.db.append_log(
                job_id,
                "Audit discarded; workspace cleanup follows worker cancellation.",
                false,
            )?;
            if control.is_none() {
                self.purge_job_dir(&self.job_dir_for(job_id)?)?;
            }
            control.map(|(_, done)| done)
        };
        if let Some(done) = done {
            done.wait(Duration::from_millis(200));
        }
        Ok(true)
    }

    /// Python `close`: refuse new jobs, cancel every worker and wait up to
    /// two seconds for them to exit.
    pub fn close(&self) {
        let controls: Vec<Arc<Done>> = {
            let _guard = self.lock();
            self.inner.closed.store(true, Ordering::SeqCst);
            let active = self.inner.active.lock().unwrap();
            active
                .values()
                .map(|job| {
                    job.cancel.store(true, Ordering::SeqCst);
                    job.done.clone()
                })
                .collect()
        };
        let deadline = Instant::now() + Duration::from_secs(2);
        for done in controls {
            done.wait(deadline.saturating_duration_since(Instant::now()));
        }
    }

    /// Wait until no worker is active (tests and orderly shutdown).
    pub fn wait_idle(&self, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        loop {
            let pending: Vec<Arc<Done>> = self
                .inner
                .active
                .lock()
                .unwrap()
                .values()
                .map(|job| job.done.clone())
                .collect();
            if pending.is_empty() {
                return true;
            }
            for done in pending {
                if !done.wait(deadline.saturating_duration_since(Instant::now())) {
                    return false;
                }
            }
        }
    }

    // -- route-level operations (router.py) -------------------------------

    fn get_or_404(&self, job_id: &str) -> Result<JobRecord, MailError> {
        self.inner
            .db
            .get_job(job_id)?
            .ok_or_else(|| MailError::not_found("Job not found"))
    }

    /// Python `to_out(job, include_files=True)`.
    pub fn job_out_with_files(&self, job: &JobRecord) -> Result<JobOut, MailError> {
        let files = if job.status == "completed" {
            temp_manager::list_output_files(&self.job_dir_for(&job.id)?)
        } else {
            Vec::new()
        };
        Ok(JobOut::with_files(job, files))
    }

    fn submit_upload(
        &self,
        job_id: &str,
        directory: &Path,
        name: &str,
        size: i64,
    ) -> Result<JobRecord, MailError> {
        let _guard = self.lock();
        if let Err(error) = self.ensure_capacity() {
            self.purge_job_dir(directory)?;
            return Err(error);
        }
        let job = self.inner.db.create_job(NewJob::new(
            job_id,
            name,
            size,
            directory.to_string_lossy(),
        ))?;
        self.start_job(job_id)?;
        Ok(job)
    }

    /// `POST /api/jobs` (multipart `files`): validate names, stage every file
    /// within the combined upload limit and start the audit.
    pub fn create_upload_job(&self, files: Vec<UploadFile<'_>>) -> Result<JobOut, MailError> {
        self.ensure_capacity()?;
        if files.is_empty() || files.len() > 1000 {
            return Err(MailError::bad_request("Upload between 1 and 1000 files"));
        }
        let names: Vec<String> = files
            .iter()
            .map(|file| temp_manager::safe_filename(file.filename.as_deref(), "upload"))
            .collect();
        for name in &names {
            if !self
                .inner
                .settings
                .is_allowed_extension(temp_manager::py_suffix(name))
            {
                return Err(MailError::bad_request(format!(
                    "Unsupported file type: {name}. Accepted: .eml, .zip, .mbox, .json"
                )));
            }
        }
        if !names
            .iter()
            .any(|name| DATA_EXTENSIONS.contains(&temp_manager::py_suffix(name)))
        {
            return Err(MailError::bad_request(
                "Upload must include at least one .eml, .zip, or .mbox file",
            ));
        }
        let job_id = new_job_id();
        let directory = self.create_job_dirs(&job_id)?;
        let max_upload = i64::try_from(self.inner.settings.max_upload_bytes).unwrap_or(i64::MAX);
        let mut total: i64 = 0;
        let mut staged = Vec::new();
        for file in files {
            let staged_file = temp_manager::stage_stream(
                &directory,
                file.filename.as_deref(),
                file.reader,
                max_upload - total,
            )
            .and_then(|target| Ok((std::fs::metadata(&target)?.len(), target)));
            match staged_file {
                Ok((size, target)) => {
                    total += i64::try_from(size).unwrap_or(i64::MAX);
                    staged.push(file_name_of(&target));
                }
                Err(error) => {
                    // Python: `except (ValueError, OSError)` → purge, 400.
                    self.purge_job_dir(&directory)?;
                    return Err(MailError::bad_request(error.to_string()));
                }
            }
        }
        let name: String = staged.join(", ").chars().take(500).collect();
        let job = self.submit_upload(&job_id, &directory, &name, total)?;
        Ok(JobOut::from_record(&job))
    }

    /// `POST /api/jobs/paste`.
    pub fn create_paste_job(&self, body: &PasteJobIn) -> Result<JobOut, MailError> {
        self.ensure_capacity()?;
        if body.content.len() as u64 > self.inner.settings.max_upload_bytes {
            return Err(MailError::bad_request(
                "Pasted source exceeds maximum allowed size",
            ));
        }
        let mut name = temp_manager::safe_filename(body.filename.as_deref(), "pasted_email.eml");
        if !name.ends_with(".eml") {
            name.push_str(".eml");
        }
        let job_id = new_job_id();
        let directory = self.create_job_dirs(&job_id)?;
        let staged = temp_manager::stage_text(&directory, Some(&name), &body.content)
            .and_then(|path| Ok((std::fs::metadata(&path)?.len(), path)));
        let (size, path) = match staged {
            Ok(staged) => staged,
            Err(error) => {
                // Python let the OSError escape (500); do not leave the
                // half-created workspace behind.
                let _ = self.purge_job_dir(&directory);
                return Err(internal(error));
            }
        };
        let job = self.submit_upload(
            &job_id,
            &directory,
            &file_name_of(&path),
            i64::try_from(size).unwrap_or(i64::MAX),
        )?;
        Ok(JobOut::from_record(&job))
    }

    /// Python `create_mail_job`: create and start a mailbox audit.
    pub fn create_mailbox_job(
        &self,
        email: &str,
        days: i64,
        auth: MailboxAuth,
    ) -> Result<JobRecord, MailError> {
        let _guard = self.lock();
        self.ensure_capacity()?;
        let job_id = new_job_id();
        let directory = self.create_job_dirs(&job_id)?;
        let job = self.inner.db.create_job(
            NewJob::new(
                &job_id,
                format!("{email} INBOX ({days} days)"),
                0,
                directory.to_string_lossy(),
            )
            .mailbox(email, days),
        )?;
        self.start_mailbox_job(&job_id, auth)?;
        Ok(job)
    }

    /// `POST /api/mail/jobs/account`: audit an unlocked account (401
    /// `password_required` when it is locked).
    pub fn create_account_job(
        &self,
        sessions: &SessionStore,
        body: &AccountJobIn,
    ) -> Result<JobOut, MailError> {
        let account = sessions.require(&body.account)?;
        self.create_account_job_for(&account, body.days)
    }

    /// Audit an already unlocked account. POP3 accounts are refused (400):
    /// Inbox Doctor downloads through IMAP only.
    pub fn create_account_job_for(
        &self,
        account: &MailAccount,
        days: i64,
    ) -> Result<JobOut, MailError> {
        if account.is_pop3() {
            return Err(MailError::bad_request(
                "Inbox Doctor mailbox audits require an IMAP account.",
            ));
        }
        let auth = MailboxAuth::from_account(account);
        let job = self.create_mailbox_job(&account.email, days, auth)?;
        Ok(JobOut::from_record(&job))
    }

    /// `POST /api/mail/jobs`: audit with separately supplied credentials.
    pub fn create_credentials_job(&self, body: &MailCredentialsIn) -> Result<JobOut, MailError> {
        let address = validate_email(&body.email)?;
        let provider = mailbox_download::provider_for_email(&address);
        if provider == "microsoft" {
            return Err(MailError::bad_request(
                "Microsoft accounts must use the permission-based OAuth button.",
            ));
        }
        if provider == "google" && !body.use_app_password {
            return Err(MailError::bad_request(
                "Google accounts must use OAuth or explicitly choose the app-password fallback.",
            ));
        }
        let mut password = body.password.clone();
        if provider == "google" {
            password = password.split_whitespace().collect();
            if password.chars().count() != 16 || !password.chars().all(char::is_alphanumeric) {
                return Err(MailError::bad_request(
                    "A Google app password must contain 16 characters (letters or digits).",
                ));
            }
        }
        let auth = MailboxAuth {
            password: Some(password),
            access_token: None,
            imap_server: body.imap_server.clone(),
            imap_port: body.imap_port,
            use_ssl: body.use_ssl,
            incoming_protocol: body.incoming_protocol.clone(),
        };
        let job = self.create_mailbox_job(&address, body.days, auth)?;
        Ok(JobOut::from_record(&job))
    }

    /// `GET /api/mail/providers?email=`.
    pub fn mail_providers(&self, email: &str) -> Value {
        let address = email.trim();
        let (server, port) = mailbox_download::resolve_imap(address);
        let provider = mailbox_download::provider_for_email(address);
        let known = matches!(provider, "google" | "microsoft");
        let oauth = &self.inner.oauth;
        json!({
            "provider": provider,
            "imap_server": server,
            "imap_port": port,
            "use_ssl": port == 993,
            "oauth_configured": if known { json!(oauth.is_configured(provider)) } else { Value::Null },
            "oauth_callback_url": if known { json!(oauth.callback_url(provider)) } else { Value::Null },
            "known_domains": mailbox_download::known_domains(),
        })
    }

    /// `POST /api/mail/oauth/start`.
    pub fn start_oauth(&self, body: &OAuthStartIn) -> Result<Value, MailError> {
        self.start_oauth_for_origin(body, None)
    }

    /// `POST /api/mail/oauth/start` remembering the extension origin that
    /// asked (`message_origin`): the callback page posts its result to that
    /// origin instead of `frontend_url`. The caller must only pass an origin
    /// that already passed the backend's extension-origin check.
    pub fn start_oauth_for_origin(
        &self,
        body: &OAuthStartIn,
        message_origin: Option<&str>,
    ) -> Result<Value, MailError> {
        let address = validate_email(&body.email)?;
        if !matches!(body.provider.as_str(), "google" | "microsoft") {
            return Err(MailError::bad_request("Unsupported OAuth provider"));
        }
        if mailbox_download::provider_for_email(&address) != body.provider {
            return Err(MailError::bad_request(
                "The OAuth provider does not match this email address",
            ));
        }
        self.ensure_capacity()?;
        let (url, state) = self
            .inner
            .oauth
            .start_flow_for_origin(&body.provider, &address, body.days, message_origin)
            .map_err(|error| http(503, &error.0))?;
        Ok(json!({
            "authorization_url": url,
            "state": state,
            "message_origin": self.inner.settings.public_backend_url,
        }))
    }

    /// `GET /api/mail/oauth/{provider}/callback`: exchange the code, start
    /// the mailbox job and return the HTML page (send it with
    /// [`crate::oauth::CALLBACK_HEADERS`]; strip the query from access logs).
    pub fn oauth_callback(
        &self,
        provider: &str,
        state: &str,
        code: &str,
        error: &str,
    ) -> Result<String, MailError> {
        let mut message_origin = None;
        let outcome = self.oauth_callback_job(provider, state, code, error, &mut message_origin)?;
        // Post to the extension page that started the flow; flows started
        // without an extension origin (and failures before the flow is
        // known) use the configured frontend URL like Python.
        let target = message_origin
            .as_deref()
            .unwrap_or(&self.inner.settings.frontend_url);
        Ok(match outcome {
            Ok(job) => render_callback_page(
                "Permission granted",
                "The mailbox download has started. You can close this window.",
                &CallbackMessage::Started { job_id: job.id },
                target,
            ),
            Err(detail) => render_callback_page(
                "Could not connect mailbox",
                &detail,
                &CallbackMessage::Failed {
                    error: detail.clone(),
                },
                target,
            ),
        })
    }

    /// The `try` block of `oauth_callback`: `Ok(Err(detail))` for an
    /// `OAuthError` / `HTTPException` shown on the page; `Err` for anything
    /// unexpected (Python let those propagate as 500). `message_origin` is
    /// set once the pending flow has been taken.
    fn oauth_callback_job(
        &self,
        provider: &str,
        state: &str,
        code: &str,
        error: &str,
        message_origin: &mut Option<String>,
    ) -> Result<Result<JobRecord, String>, MailError> {
        if state.is_empty() {
            return Ok(Err("The OAuth callback was incomplete".into()));
        }
        let flow = match self.inner.oauth.take_flow(state, provider) {
            Ok(flow) => flow,
            Err(failure) => return Ok(Err(failure.0)),
        };
        message_origin.clone_from(&flow.message_origin);
        if !error.is_empty() {
            return Ok(Err(
                "Permission was not granted by the mailbox provider".into()
            ));
        }
        if code.is_empty() {
            return Ok(Err("The OAuth callback was incomplete".into()));
        }
        let token = match self.inner.oauth.exchange_code(provider, code, &flow) {
            Ok(token) => token,
            Err(failure) => return Ok(Err(failure.0)),
        };
        match self.create_mailbox_job(&flow.email, flow.days, MailboxAuth::access_token(token)) {
            Ok(job) => Ok(Ok(job)),
            Err(MailError::Http { detail, .. }) => Ok(Err(match detail {
                Value::String(text) => text,
                other => other.to_string(),
            })),
            Err(other) => Err(other),
        }
    }

    /// `GET /api/jobs`: every job, newest first, without logs.
    pub fn list_jobs(&self) -> Result<Vec<JobOut>, MailError> {
        Ok(self
            .inner
            .db
            .list_jobs()?
            .into_iter()
            .map(|mut job| {
                job.log.clear();
                JobOut::from_record(&job)
            })
            .collect())
    }

    /// `GET /api/jobs/{id}`.
    pub fn get_job(&self, job_id: &str) -> Result<JobOut, MailError> {
        let job = self.get_or_404(job_id)?;
        self.job_out_with_files(&job)
    }

    /// `GET /api/jobs/{id}/files` → `{"files": [...]}`.
    pub fn list_output_files(&self, job_id: &str) -> Result<Vec<String>, MailError> {
        if self.get_or_404(job_id)?.status != "completed" {
            return Err(MailError::bad_request("Job is not completed"));
        }
        Ok(temp_manager::list_output_files(&self.job_dir_for(job_id)?))
    }

    fn snapshot_folder(job: &JobRecord) -> &'static str {
        if job.status == "completed" {
            "outputs"
        } else {
            "snapshot_outputs"
        }
    }

    /// `GET /api/jobs/{id}/snapshot-files` → `{"files": [...]}`.
    pub fn list_snapshot_files(&self, job_id: &str) -> Result<Vec<String>, MailError> {
        let _guard = self.lock();
        let job = self.get_or_404(job_id)?;
        if !job.snapshot_available || job.status == "discarded" {
            return Err(MailError::not_found("No audit snapshot is available yet"));
        }
        Ok(temp_manager::list_files_under(
            &self.job_dir_for(job_id)?,
            Self::snapshot_folder(&job),
        ))
    }

    /// `GET /api/jobs/{id}/files/{path}` (`snapshot=false`) and
    /// `GET /api/jobs/{id}/snapshot-files/{path}` (`snapshot=true`).
    pub fn read_job_file(
        &self,
        job_id: &str,
        rel_path: &str,
        snapshot: bool,
    ) -> Result<FileResponse, MailError> {
        // Snapshot publishing/discard share this lock: read the complete file
        // before releasing it so deletion cannot race the response.
        let _guard = self.lock();
        let job = self.get_or_404(job_id)?;
        let folder = if snapshot {
            if !job.snapshot_available || job.status == "discarded" {
                return Err(MailError::not_found("No audit snapshot is available yet"));
            }
            Self::snapshot_folder(&job)
        } else {
            if job.status != "completed" {
                return Err(MailError::bad_request("Job is not completed"));
            }
            "outputs"
        };
        let target = temp_manager::resolve_file(&self.job_dir_for(job_id)?, folder, rel_path)
            .ok_or_else(|| MailError::not_found("File not found"))?;
        let body = std::fs::read(&target).map_err(|_| MailError::not_found("File not found"))?;
        let name = file_name_of(&target);
        let suffix = temp_manager::py_suffix(&name);
        let mut media_type = guess_media_type(&name).to_string();
        if suffix == ".md" || suffix == ".jsonl" {
            media_type = "text/plain".into();
        }
        if media_type.starts_with("text/") {
            media_type.push_str("; charset=utf-8");
        }
        // Deviation: Python adds the sandbox CSP only to `.html` files. Every
        // served file here gets it, so a file the browser might still render
        // as a document (`.svg`, `.xml`, a mislabelled type) is sandboxed too.
        let headers = vec![
            ("X-Content-Type-Options".to_string(), "nosniff".to_string()),
            ("Cache-Control".to_string(), "no-store".to_string()),
            (
                "Content-Security-Policy".to_string(),
                JOB_FILE_CSP.to_string(),
            ),
        ];
        Ok(FileResponse {
            body,
            media_type,
            headers,
        })
    }

    /// `POST /api/jobs/{id}/discard` (404 / 400 `Job was already discarded`).
    pub fn discard(&self, job_id: &str) -> Result<JobOut, MailError> {
        self.get_or_404(job_id)?;
        if !self.discard_job(job_id)? {
            return Err(MailError::bad_request("Job was already discarded"));
        }
        Ok(JobOut::from_record(&self.get_or_404(job_id)?))
    }

    /// `GET /api/jobs/{id}/download-zip`.
    pub fn download_zip(&self, job_id: &str) -> Result<FileResponse, MailError> {
        let _guard = self.lock();
        let job = self.get_or_404(job_id)?;
        if job.status != "completed" {
            return Err(MailError::bad_request("Job is not completed"));
        }
        let path = self.job_dir_for(job_id)?.join("archive").join(ZIP_NAME);
        if !path.is_file() {
            return Err(MailError::not_found("ZIP archive not found"));
        }
        let body =
            std::fs::read(&path).map_err(|_| MailError::not_found("ZIP archive not found"))?;
        let first = job.filename.split(',').next().unwrap_or_default();
        let first = first.rsplit('/').next().unwrap_or_default();
        let stem = temp_manager::safe_filename(Some(temp_manager::py_stem(first)), "audit");
        let disposition = format!(
            "attachment; filename*=utf-8''{}",
            quote(&format!("{stem}_audit.zip"))
        );
        Ok(FileResponse {
            body,
            media_type: "application/zip".into(),
            headers: vec![
                ("Content-Disposition".into(), disposition),
                ("Cache-Control".into(), "no-store".into()),
                ("X-Content-Type-Options".into(), "nosniff".into()),
            ],
        })
    }
}

/// The sandbox Content-Security-Policy sent with every served job file.
pub const JOB_FILE_CSP: &str =
    "sandbox; default-src 'none'; style-src 'unsafe-inline'; img-src data:";

fn new_job_id() -> String {
    uuid::Uuid::new_v4().simple().to_string()
}

/// The final component of `path` as text.
fn file_name_of(path: &Path) -> String {
    path.file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default()
}

/// `Path(path).suffix` of the final component.
fn py_suffix_of(path: &Path) -> String {
    temp_manager::py_suffix(&file_name_of(path)).to_string()
}

/// Python `mimetypes.guess_type(name)[0] or "application/octet-stream"`
/// for the file types an audit workspace can contain.
fn guess_media_type(name: &str) -> &'static str {
    match temp_manager::py_suffix(name).to_lowercase().as_str() {
        ".html" | ".htm" => "text/html",
        ".json" => "application/json",
        ".csv" => "text/csv",
        ".txt" | ".md" | ".jsonl" => "text/plain",
        ".zip" => "application/zip",
        ".eml" | ".mht" => "message/rfc822",
        ".css" => "text/css",
        ".js" => "text/javascript",
        ".png" => "image/png",
        ".jpg" | ".jpeg" => "image/jpeg",
        ".gif" => "image/gif",
        ".svg" => "image/svg+xml",
        ".pdf" => "application/pdf",
        ".xml" => "application/xml",
        _ => "application/octet-stream",
    }
}

/// Python `urllib.parse.quote(value)` (safe: `/` and `_.-~`).
fn quote(value: &str) -> String {
    let mut out = String::new();
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'_' | b'.' | b'-' | b'~' | b'/' => {
                out.push(byte as char)
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn long_credentials_are_redacted_before_error_messages_are_capped() {
        let secret = "x".repeat(4096);
        let mut auth = MailboxAuth::default();
        auth.password = Some(secret.clone());
        let message = format!("Login failed: {secret} -- retry");
        assert_eq!(
            safe_error(&message, Some(&auth)),
            "Login failed: [redacted] -- retry"
        );
        assert_eq!(safe_error(&"y".repeat(5000), None).chars().count(), 4000);
    }

    #[test]
    fn media_types_and_quoting_match_python() {
        assert_eq!(guess_media_type("summary.json"), "application/json");
        assert_eq!(guess_media_type("inbox_audit.HTML"), "text/html");
        assert_eq!(guess_media_type("senders.csv"), "text/csv");
        assert_eq!(guess_media_type("blob"), "application/octet-stream");
        assert_eq!(quote("my inbox_audit.zip"), "my%20inbox_audit.zip");
        assert_eq!(quote("é/x"), "%C3%A9/x");
    }

    #[test]
    fn reentrant_lock_allows_nested_locking() {
        let lock = Arc::new(ReentrantLock::new());
        let outer = lock.lock();
        let inner = lock.lock();
        drop(inner);
        let other = lock.clone();
        let handle = std::thread::spawn(move || {
            let _guard = other.lock();
        });
        std::thread::sleep(Duration::from_millis(20));
        assert!(!handle.is_finished());
        drop(outer);
        handle.join().unwrap();
    }
}
