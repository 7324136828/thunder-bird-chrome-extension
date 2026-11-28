//! Job runner and route-level operations (port of the non-pipeline parts of
//! `backend/tests/test_doctor.py`). The report pipeline and the IMAP
//! downloader are replaced by stubs through `RunnerHooks`, exactly where the
//! Python tests patched `pipeline.run_pipeline` / `download_inbox`.

use mail_core::schemas::RequestModel;
use mail_core::{MailAccount, SessionStore};
use mail_doctor::cancellation::check_cancel;
use mail_doctor::config::DoctorSettings;
use mail_doctor::db::{JobField, NewJob};
use mail_doctor::mailbox_download::{DownloadError, DownloadHooks, DownloadOptions, MailboxAuth};
use mail_doctor::pipeline::{PipelineError, PipelineEvent};
use mail_doctor::runner::{DownloadHook, JobRunner, PipelineHook, RunnerHooks, UploadFile};
use mail_doctor::schemas::{AccountJobIn, JobOut, MailCredentialsIn, OAuthStartIn, PasteJobIn};
use serde_json::json;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

fn message(index: usize, sender: &str) -> String {
    format!(
        "From: Newsletter <{sender}>\r\nTo: user@example.net\r\nSubject: Weekly digest {index}\r\n\
         Message-ID: <doctor-{index}@example.com>\r\nContent-Type: text/plain; charset=\"utf-8\"\r\n\r\nDigest number {index}."
    )
}

fn walk(root: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        for entry in std::fs::read_dir(&directory)
            .into_iter()
            .flatten()
            .flatten()
        {
            let path = entry.path();
            if path.is_dir() {
                pending.push(path);
            } else {
                files.push(path);
            }
        }
    }
    files
}

fn has_suffix(path: &Path, suffix: &str) -> bool {
    path.to_string_lossy().to_lowercase().ends_with(suffix)
}

/// A minimal stand-in for the report pipeline: one `messages.jsonl` record
/// per `.eml` input plus a summary and an HTML report.
fn stub_pipeline(calls: Arc<AtomicUsize>) -> PipelineHook {
    Arc::new(move |job_dir, _days, event, _max_expanded, _max_members| {
        calls.fetch_add(1, Ordering::SeqCst);
        event(PipelineEvent::Stage("extract".into()))?;
        event(PipelineEvent::Progress(5))?;
        check_cancel()?;
        let inputs: Vec<PathBuf> = walk(&job_dir.join("inputs"))
            .into_iter()
            .filter(|p| has_suffix(p, ".eml") || has_suffix(p, ".mbox"))
            .collect();
        if inputs.is_empty() {
            return Err(PipelineError::Failed(
                "No parseable .eml or .mbox messages were found in the upload.".into(),
            ));
        }
        let report = job_dir.join("outputs").join("report");
        std::fs::create_dir_all(&report)?;
        let records: Vec<String> = inputs
            .iter()
            .map(|path| {
                json!({"from_domain": "updates.example.org", "size_bytes": std::fs::metadata(path).unwrap().len()})
                    .to_string()
            })
            .collect();
        std::fs::write(job_dir.join("outputs/messages.jsonl"), records.join("\n"))?;
        std::fs::write(
            report.join("summary.json"),
            json!({"total_messages": inputs.len()}).to_string(),
        )?;
        std::fs::write(
            job_dir.join("outputs/inbox_audit.html"),
            "<html>report</html>",
        )?;
        event(PipelineEvent::Log(format!(
            "Parsed {} messages",
            inputs.len()
        )))?;
        event(PipelineEvent::Progress(97))?;
        Ok(())
    })
}

fn no_download() -> DownloadHook {
    Arc::new(|_, _| Err(DownloadError::Other("unexpected download".into())))
}

struct Fixture {
    directory: tempfile::TempDir,
    settings: DoctorSettings,
    runner: JobRunner,
    pipeline_calls: Arc<AtomicUsize>,
}

impl Fixture {
    fn new() -> Self {
        Self::with(|_| {}, None, None)
    }

    fn with(
        configure: impl FnOnce(&mut DoctorSettings),
        pipeline: Option<PipelineHook>,
        download: Option<DownloadHook>,
    ) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let mut settings = DoctorSettings::with_defaults(directory.path().join("doctor"));
        configure(&mut settings);
        let pipeline_calls = Arc::new(AtomicUsize::new(0));
        let hooks = RunnerHooks {
            pipeline: pipeline.unwrap_or_else(|| stub_pipeline(pipeline_calls.clone())),
            download: download.unwrap_or_else(no_download),
        };
        let runner = JobRunner::with_hooks(settings.clone(), hooks);
        runner.initialize().unwrap();
        Self {
            directory,
            settings,
            runner,
            pipeline_calls,
        }
    }

    fn restarted(&self) -> JobRunner {
        let runner = JobRunner::new(self.settings.clone());
        runner.initialize().unwrap();
        runner
    }

    fn wait(&self, job_id: &str) -> JobOut {
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            let job = self.runner.get_job(job_id).unwrap();
            if matches!(
                job.status.as_str(),
                "completed" | "healthy" | "failed" | "discarded"
            ) {
                // The worker may still append its final log lines after the
                // status turns terminal, so re-read once it is idle.
                self.runner.wait_idle(Duration::from_secs(5));
                return self.runner.get_job(job_id).unwrap();
            }
            assert!(Instant::now() < deadline, "job did not finish: {job:?}");
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    fn paste(&self) -> JobOut {
        let body = PasteJobIn::from_json(
            &json!({"content": message(0, "news@mail.example.com"), "filename": "paste"}),
        )
        .unwrap();
        let job = self.runner.create_paste_job(&body).unwrap();
        self.wait(&job.id)
    }

    fn files_with(&self, suffix: &str) -> Vec<PathBuf> {
        walk(self.directory.path())
            .into_iter()
            .filter(|p| has_suffix(p, suffix))
            .collect()
    }

    fn any_file_contains(&self, needle: &str) -> bool {
        walk(self.directory.path()).into_iter().any(|path| {
            let bytes = std::fs::read(&path).unwrap_or_default();
            bytes.windows(needle.len()).any(|w| w == needle.as_bytes())
        })
    }
}

fn upload(name: &str, data: &[u8]) -> UploadFile<'static> {
    UploadFile {
        filename: Some(name.into()),
        reader: Box::new(std::io::Cursor::new(data.to_vec())),
    }
}

#[test]
fn paste_audit_completes_with_reports_zip_history_and_metrics() {
    let f = Fixture::new();
    let job = f.paste();
    assert_eq!(job.status, "completed", "{}", job.log);
    assert_eq!(job.progress, 100);
    assert_eq!(job.filename, "paste.eml");
    assert!(job.log.contains("--- stage: Parsing messages ---"));
    assert!(job.log.contains("Audit finished; outputs packaged."));
    assert_eq!(
        job.output_files,
        ["inbox_audit.html", "messages.jsonl", "report/summary.json"]
    );
    assert_eq!(f.runner.list_output_files(&job.id).unwrap().len(), 3);
    let summary = f
        .runner
        .read_job_file(&job.id, "report/summary.json", false)
        .unwrap();
    assert_eq!(summary.media_type, "application/json");
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&summary.body).unwrap()["total_messages"],
        1
    );
    let html = f
        .runner
        .read_job_file(&job.id, "inbox_audit.html", false)
        .unwrap();
    assert_eq!(html.media_type, "text/html; charset=utf-8");
    assert!(html
        .headers
        .iter()
        .any(|(k, v)| k == "Content-Security-Policy" && v.starts_with("sandbox")));
    let jsonl = f
        .runner
        .read_job_file(&job.id, "messages.jsonl", false)
        .unwrap();
    assert_eq!(jsonl.media_type, "text/plain; charset=utf-8");
    // Every served file carries the sandbox CSP plus nosniff / no-store.
    for file in [&summary, &html, &jsonl] {
        for (name, value) in [
            ("X-Content-Type-Options", "nosniff"),
            ("Cache-Control", "no-store"),
            ("Content-Security-Policy", mail_doctor::runner::JOB_FILE_CSP),
        ] {
            assert!(
                file.headers.iter().any(|(k, v)| k == name && v == value),
                "{name}: {:?}",
                file.headers
            );
        }
    }

    let zip = f.runner.download_zip(&job.id).unwrap();
    assert_eq!(zip.media_type, "application/zip");
    assert!(zip.headers.contains(&(
        "Content-Disposition".into(),
        "attachment; filename*=utf-8''paste_audit.zip".into()
    )));
    let archive = zip::ZipArchive::new(std::io::Cursor::new(zip.body)).unwrap();
    let mut names: Vec<&str> = archive.file_names().collect();
    names.sort();
    assert_eq!(
        names,
        ["inbox_audit.html", "messages.jsonl", "report/summary.json"]
    );

    let history = f.runner.list_jobs().unwrap();
    assert_eq!(history[0].id, job.id);
    assert_eq!(history[0].log, "");
    assert!(history[0].output_files.is_empty());

    let runs = f.runner.metrics().list_metrics(None).unwrap().runs;
    assert_eq!(runs.len(), 1);
    assert_eq!(runs[0].id, job.id);
    assert_eq!(runs[0].total_size_bytes, job.file_size);
    assert_eq!(runs[0].domains[0].domain, "updates.example.org");
    // Discarding keeps the durable metrics.
    f.runner.discard(&job.id).unwrap();
    assert_eq!(f.runner.metrics().list_metrics(None).unwrap().runs, runs);
}

#[test]
fn history_and_report_files_survive_new_application_instance() {
    let f = Fixture::new();
    let job = f.paste();
    let restarted = f.restarted();
    assert!(restarted
        .list_jobs()
        .unwrap()
        .iter()
        .any(|row| row.id == job.id));
    assert!(restarted
        .read_job_file(&job.id, "report/summary.json", false)
        .is_ok());
}

#[test]
fn multi_file_upload_is_staged_with_sanitized_names() {
    let f = Fixture::new();
    let job = f
        .runner
        .create_upload_job(vec![
            upload("one.EML", message(1, "a@vendor.net").as_bytes()),
            upload("..\\dir/one.eml", message(2, "b@vendor.org").as_bytes()),
            upload("aliases.json", b"{}"),
        ])
        .unwrap();
    assert_eq!(job.filename, "one.eml, one_1.eml, aliases.json");
    let job = f.wait(&job.id);
    assert_eq!(job.status, "completed", "{}", job.log);
}

#[test]
fn invalid_uploads_and_missing_jobs_are_rejected() {
    let f = Fixture::new();
    for (files, detail) in [
        (
            vec![upload("run.exe", b"MZ")],
            "Unsupported file type: run.exe. Accepted: .eml, .zip, .mbox, .json",
        ),
        (
            vec![upload("aliases.json", b"{}")],
            "Upload must include at least one .eml, .zip, or .mbox file",
        ),
        (vec![], "Upload between 1 and 1000 files"),
    ] {
        let error = f.runner.create_upload_job(files).unwrap_err();
        assert_eq!((error.status(), error.detail()), (400, json!(detail)));
    }
    assert_eq!(
        PasteJobIn::from_json(&json!({"content": ""}))
            .unwrap_err()
            .status(),
        422
    );
    assert_eq!(f.runner.get_job("missing").unwrap_err().status(), 404);
    assert_eq!(f.runner.discard("missing").unwrap_err().status(), 404);
    assert!(f.runner.list_jobs().unwrap().is_empty());
}

#[test]
fn report_reads_cannot_escape_output_directory() {
    let f = Fixture::new();
    let job = f.paste();
    for path in [
        "../inputs/paste.eml",
        "..\\inputs\\paste.eml",
        "C:\\Windows\\win.ini",
        "/etc/passwd",
        "missing.txt",
    ] {
        let error = f.runner.read_job_file(&job.id, path, false).unwrap_err();
        assert!(matches!(error.status(), 400 | 404), "{path}");
    }
}

#[test]
fn upload_limit_applies_to_combined_files() {
    let raw = message(0, "news@example.com");
    let f = Fixture::with(|s| s.max_upload_bytes = raw.len() as u64 + 5, None, None);
    let error = f
        .runner
        .create_upload_job(vec![
            upload("first.eml", raw.as_bytes()),
            upload("second.eml", raw.as_bytes()),
        ])
        .unwrap_err();
    assert_eq!(error.status(), 400);
    assert_eq!(
        error.detail(),
        json!("Upload exceeds the total maximum allowed size")
    );
    assert!(f.runner.list_jobs().unwrap().is_empty());
    assert!(f.files_with(".eml").is_empty());
    let paste = PasteJobIn::from_json(&json!({"content": "x".repeat(raw.len() + 6)})).unwrap();
    assert_eq!(
        f.runner.create_paste_job(&paste).unwrap_err().detail(),
        json!("Pasted source exceeds maximum allowed size")
    );
}

#[test]
fn pipeline_failure_marks_job_failed_with_message() {
    let failing: PipelineHook = Arc::new(|_, _, _, _, _| {
        Err(PipelineError::Failed(
            "Expanded ZIP content exceeds the maximum allowed size".into(),
        ))
    });
    let f = Fixture::with(|_| {}, Some(failing), None);
    let job = f
        .runner
        .create_upload_job(vec![upload("large.zip", b"PK")])
        .unwrap();
    let job = f.wait(&job.id);
    assert_eq!(job.status, "failed");
    assert_eq!(job.stage.as_deref(), Some("failed"));
    assert!(job.error_message.unwrap().contains("size"));
    assert!(job
        .log
        .contains("Audit failed: Expanded ZIP content exceeds the maximum allowed size"));
    assert_eq!(f.runner.download_zip(&job.id).unwrap_err().status(), 400);
    assert_eq!(
        f.runner.list_output_files(&job.id).unwrap_err().detail(),
        json!("Job is not completed")
    );
}

#[test]
fn interrupted_jobs_are_reported_as_failed_after_restart() {
    let f = Fixture::new();
    let job_id = "a".repeat(32);
    f.runner
        .db()
        .create_job(NewJob::new(&job_id, "interrupted.eml", 1, ""))
        .unwrap();
    let job = f.restarted().get_job(&job_id).unwrap();
    assert_eq!(job.status, "failed");
    assert!(job.error_message.unwrap().contains("stopped"));
}

type Captured = Arc<
    Mutex<
        Vec<(
            String,
            Option<String>,
            Option<String>,
            Option<u16>,
            i64,
            Option<String>,
        )>,
    >,
>;

/// A downloader that writes `count` messages and reports progress like the
/// real one (`progress(0, n)`, then `progress(i, n)` and `on_batch(i, n)`).
fn stub_download(count: usize, reported_total: usize, captured: Captured) -> DownloadHook {
    Arc::new(
        move |options: &DownloadOptions<'_>, hooks: &mut DownloadHooks<'_>| {
            captured.lock().unwrap().push((
                options.email.to_string(),
                options.auth.password.clone(),
                options.auth.imap_server.clone(),
                options.auth.imap_port,
                options.days,
                options.window_start.map(str::to_string),
            ));
            std::fs::create_dir_all(options.output_dir)?;
            (hooks.progress)(0, reported_total)?;
            for index in 0..count {
                std::fs::write(
                    options.output_dir.join(format!("{index}.eml")),
                    message(index, "news@mail.example.com"),
                )?;
                (hooks.progress)(index + 1, reported_total)?;
                (hooks.on_batch)(index + 1, reported_total)?;
            }
            Ok((count, reported_total))
        },
    )
}

fn unlocked(secret: &str) -> SessionStore {
    let sessions = SessionStore::new();
    sessions.unlock(MailAccount::new(
        "user@example.net",
        secret,
        "custom.example.net",
        143,
        "STARTTLS",
        "smtp.example.net",
        587,
        "STARTTLS",
    ));
    sessions
}

#[test]
fn unlocked_account_audit_reuses_connection_and_does_not_persist_password() {
    let secret = "doctor-ephemeral-password";
    let captured: Captured = Arc::default();
    let f = Fixture::with(|_| {}, None, Some(stub_download(2, 2, captured.clone())));
    let sessions = unlocked(secret);
    let body = AccountJobIn::from_json(&json!({"account": "user@example.net", "days": 5})).unwrap();
    let job = f.runner.create_account_job(&sessions, &body).unwrap();
    assert_eq!(job.source_kind, "mailbox");
    assert_eq!(job.filename, "user@example.net INBOX (5 days)");
    let job = f.wait(&job.id);
    assert_eq!(job.status, "completed", "{}", job.log);
    let calls = captured.lock().unwrap().clone();
    assert_eq!(calls.len(), 1);
    let (email, password, server, port, days, _) = &calls[0];
    assert_eq!(email, "user@example.net");
    assert_eq!(password.as_deref(), Some(secret));
    assert_eq!(server.as_deref(), Some("custom.example.net"));
    assert_eq!((*port, *days), (Some(143), 5));
    assert_eq!((job.downloaded_messages, job.total_messages), (2, Some(2)));
    assert!(job.snapshot_available);
    assert!(job.log.contains("Audit snapshot refreshed."));
    assert!(job
        .log
        .contains("Downloaded 2 messages; starting final audit."));
    assert!(!serde_json::to_string(&job).unwrap().contains(secret));
    assert!(!f.any_file_contains(secret));
    let snapshot = f.runner.list_snapshot_files(&job.id).unwrap();
    assert!(snapshot.contains(&"report/summary.json".to_string()));
    assert!(f
        .runner
        .read_job_file(&job.id, "report/summary.json", true)
        .is_ok());
}

#[test]
fn account_audits_require_unlock_and_google_fallback_is_explicit() {
    let f = Fixture::new();
    let body =
        AccountJobIn::from_json(&json!({"account": "Locked@example.net", "days": 5})).unwrap();
    let error = f
        .runner
        .create_account_job(&SessionStore::new(), &body)
        .unwrap_err();
    assert_eq!(error.status(), 401);
    assert_eq!(
        error.detail(),
        json!({"error": "password_required", "email": "locked@example.net"})
    );

    let google = MailCredentialsIn::from_json(
        &json!({"email": "user@gmail.com", "password": "unused", "days": 7}),
    )
    .unwrap();
    assert_eq!(
        f.runner
            .create_credentials_job(&google)
            .unwrap_err()
            .detail(),
        json!("Google accounts must use OAuth or explicitly choose the app-password fallback.")
    );
    let short = MailCredentialsIn::from_json(
        &json!({"email": "user@gmail.com", "password": "abc", "use_app_password": true}),
    )
    .unwrap();
    assert_eq!(
        f.runner
            .create_credentials_job(&short)
            .unwrap_err()
            .detail(),
        json!("A Google app password must contain 16 characters (letters or digits).")
    );
    let microsoft =
        MailCredentialsIn::from_json(&json!({"email": "user@outlook.com", "password": "x"}))
            .unwrap();
    assert_eq!(
        f.runner
            .create_credentials_job(&microsoft)
            .unwrap_err()
            .detail(),
        json!("Microsoft accounts must use the permission-based OAuth button.")
    );
    let invalid =
        MailCredentialsIn::from_json(&json!({"email": "not an address", "password": "x"})).unwrap();
    assert_eq!(
        f.runner
            .create_credentials_job(&invalid)
            .unwrap_err()
            .detail(),
        json!("Enter a valid email address")
    );

    let provider = f.runner.mail_providers("user@proton.me");
    assert_eq!(provider["imap_port"], 1143);
    assert_eq!(provider["use_ssl"], false);
    assert_eq!(provider["oauth_configured"], serde_json::Value::Null);
    let gmail = f.runner.mail_providers(" user@gmail.com ");
    assert_eq!(gmail["provider"], "google");
    assert_eq!(gmail["oauth_configured"], false);
    assert_eq!(
        gmail["oauth_callback_url"],
        "http://localhost:48101/api/mail/oauth/google/callback"
    );
    assert_eq!(gmail["known_domains"].as_array().unwrap().len(), 14);
}

#[test]
fn pop3_accounts_cannot_start_mailbox_audits() {
    let f = Fixture::new();
    let mut account = MailAccount::new(
        "pop@example.net",
        "pw",
        "pop.example.net",
        995,
        "SSL/TLS",
        "smtp.example.net",
        465,
        "SSL/TLS",
    );
    account.incoming_mail_protocol = "pop3".into();
    assert_eq!(
        f.runner
            .create_account_job_for(&account, 7)
            .unwrap_err()
            .status(),
        400
    );
}

#[test]
fn google_app_password_whitespace_is_removed() {
    let captured: Captured = Arc::default();
    let f = Fixture::with(|_| {}, None, Some(stub_download(1, 1, captured.clone())));
    let body = MailCredentialsIn::from_json(&json!({
        "email": "user@gmail.com", "password": "abcd efgh ijkl mnop", "use_app_password": true,
    }))
    .unwrap();
    let job = f.runner.create_credentials_job(&body).unwrap();
    assert_eq!(f.wait(&job.id).status, "completed");
    assert_eq!(
        captured.lock().unwrap()[0].1.as_deref(),
        Some("abcdefghijklmnop")
    );
}

#[test]
fn empty_inbox_window_finishes_healthy_and_survives_restart() {
    let captured: Captured = Arc::default();
    let f = Fixture::with(|_| {}, None, Some(stub_download(0, 0, captured)));
    let body = MailCredentialsIn::from_json(&json!({
        "email": "user@example.net", "password": "memory-only-password", "days": 7,
    }))
    .unwrap();
    let job = f.runner.create_credentials_job(&body).unwrap();
    let job = f.wait(&job.id);
    assert_eq!(f.pipeline_calls.load(Ordering::SeqCst), 0);
    assert_eq!(job.status, "healthy", "{}", job.log);
    assert_eq!(job.stage.as_deref(), Some("healthy"));
    assert_eq!(job.progress, 100);
    assert_eq!(job.error_message, None);
    assert!(job.completed_at.is_some());
    assert_eq!((job.total_messages, job.downloaded_messages), (Some(0), 0));
    assert!(!job.snapshot_available);
    assert!(job.output_files.is_empty());
    assert!(job
        .log
        .contains("No INBOX messages were found in the last 7 day(s)."));
    assert!(!job.log.contains("Audit failed"));
    assert!(!f.any_file_contains("memory-only-password"));
    let run = &f.runner.metrics().list_metrics(None).unwrap().runs[0];
    assert_eq!((run.total_messages, run.total_size_bytes), (0, 0));
    let restarted = f.restarted();
    assert_eq!(restarted.get_job(&job.id).unwrap().status, "healthy");
    assert_eq!(restarted.list_jobs().unwrap()[0].status, "healthy");
}

#[test]
fn found_messages_that_cannot_be_downloaded_still_fail() {
    let captured: Captured = Arc::default();
    let f = Fixture::with(|_| {}, None, Some(stub_download(0, 2, captured)));
    let body =
        MailCredentialsIn::from_json(&json!({"email": "user@example.net", "password": "unused"}))
            .unwrap();
    let job = f.runner.create_credentials_job(&body).unwrap();
    let job = f.wait(&job.id);
    assert_eq!(job.status, "failed", "{}", job.log);
    assert_eq!(job.total_messages, Some(2));
    assert!(job
        .error_message
        .unwrap()
        .contains("none could be downloaded"));
}

#[test]
fn download_errors_are_redacted() {
    let secret = "very-secret-password";
    let failing: DownloadHook = Arc::new(move |options, _| {
        Err(DownloadError::Other(format!(
            "server said {} is wrong",
            options.auth.password.clone().unwrap()
        )))
    });
    let f = Fixture::with(|_| {}, None, Some(failing));
    let body =
        MailCredentialsIn::from_json(&json!({"email": "user@example.net", "password": secret}))
            .unwrap();
    let job = f.runner.create_credentials_job(&body).unwrap();
    let job = f.wait(&job.id);
    assert_eq!(
        job.error_message.as_deref(),
        Some("server said [redacted] is wrong")
    );
    assert!(!f.any_file_contains(secret));
}

#[test]
fn discard_stops_worker_and_purges_reports() {
    let (entered_tx, entered_rx) = std::sync::mpsc::channel::<()>();
    let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
    let entered_tx = Mutex::new(entered_tx);
    let release_rx = Mutex::new(release_rx);
    let blocking: PipelineHook = Arc::new(move |_, _, event, _, _| {
        entered_tx.lock().unwrap().send(()).unwrap();
        let _ = release_rx
            .lock()
            .unwrap()
            .recv_timeout(Duration::from_secs(3));
        // Python's `_event` raises AuditCancelled once the job is discarded.
        event(PipelineEvent::Stage("extract".into()))?;
        Ok(())
    });
    let f = Fixture::with(|_| {}, Some(blocking), None);
    let body = PasteJobIn::from_json(&json!({"content": message(0, "a@example.com")})).unwrap();
    let job = f.runner.create_paste_job(&body).unwrap();
    entered_rx.recv_timeout(Duration::from_secs(2)).unwrap();
    let unblock = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(50));
        let _ = release_tx.send(());
    });
    let discarded = f.runner.discard(&job.id).unwrap();
    unblock.join().unwrap();
    assert_eq!(discarded.status, "discarded");
    assert_eq!(f.wait(&job.id).status, "discarded");
    assert!(f.runner.wait_idle(Duration::from_secs(5)));
    assert!(matches!(
        f.runner.download_zip(&job.id).unwrap_err().status(),
        400 | 404
    ));
    assert!(f.files_with(".eml").is_empty());
    assert_eq!(
        f.runner.discard(&job.id).unwrap_err().detail(),
        json!("Job was already discarded")
    );
    let log = f.runner.get_job(&job.id).unwrap().log;
    assert!(!log.contains("stage: Parsing"), "{log}");
}

#[test]
fn completed_audit_can_be_discarded_without_losing_history() {
    let f = Fixture::new();
    let job = f.paste();
    let discarded = f.runner.discard(&job.id).unwrap();
    assert_eq!(discarded.status, "discarded");
    assert_eq!(
        discarded.error_message.as_deref(),
        Some("Discarded by user")
    );
    assert!(f.files_with(".eml").is_empty());
    assert!(f.files_with("inbox_audit.html").is_empty());
    let history = f.runner.list_jobs().unwrap();
    assert_eq!(
        (history[0].id.as_str(), history[0].status.as_str()),
        (job.id.as_str(), "discarded")
    );
}

#[test]
fn capacity_limit_returns_429_and_close_cancels_workers() {
    let blocking: PipelineHook = Arc::new(|_, _, _, _, _| {
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            check_cancel()?;
            std::thread::sleep(Duration::from_millis(10));
        }
        Ok(())
    });
    let f = Fixture::with(|s| s.max_active_jobs = 1, Some(blocking), None);
    let body = PasteJobIn::from_json(&json!({"content": message(0, "a@example.com")})).unwrap();
    let first = f.runner.create_paste_job(&body).unwrap();
    let error = f.runner.create_paste_job(&body).unwrap_err();
    assert_eq!(
        (error.status(), error.detail()),
        (
            429,
            json!("Too many audits are running; wait for a job to finish")
        )
    );
    assert_eq!(f.runner.active_job_ids(), std::slice::from_ref(&first.id));
    let started = Instant::now();
    f.runner.close();
    assert!(started.elapsed() < Duration::from_secs(3));
    assert!(f.runner.active_job_ids().is_empty());
    assert_eq!(f.runner.ensure_capacity().unwrap_err().status(), 429);
}

#[test]
fn oauth_routes_validate_and_render_callback_pages() {
    let f = Fixture::new();
    let mismatch =
        OAuthStartIn::from_json(&json!({"provider": "google", "email": "user@outlook.com"}))
            .unwrap();
    assert_eq!(
        f.runner.start_oauth(&mismatch).unwrap_err().detail(),
        json!("The OAuth provider does not match this email address")
    );
    let unsupported =
        OAuthStartIn::from_json(&json!({"provider": "yahoo", "email": "user@yahoo.com"})).unwrap();
    assert_eq!(
        f.runner.start_oauth(&unsupported).unwrap_err().detail(),
        json!("Unsupported OAuth provider")
    );
    let unconfigured =
        OAuthStartIn::from_json(&json!({"provider": "google", "email": "user@gmail.com"})).unwrap();
    let error = f.runner.start_oauth(&unconfigured).unwrap_err();
    assert_eq!(error.status(), 503);

    let page = f.runner.oauth_callback("google", "", "", "").unwrap();
    assert!(page.contains("<title>Could not connect mailbox</title>"));
    assert!(page.contains("The OAuth callback was incomplete"));
    let page = f
        .runner
        .oauth_callback("google", "unknown-state", "code", "")
        .unwrap();
    assert!(page.contains("OAuth request is missing, expired, or invalid"));
    assert!(page.contains(r#""type": "email-doctor-oauth", "error": "#));
    assert!(page.contains("\"http://localhost:3741\""));
}

#[test]
fn oauth_start_returns_authorization_url_when_configured() {
    let f = Fixture::with(
        |s| {
            s.google_oauth_client_id = "id".into();
            s.google_oauth_client_secret = "secret".into();
        },
        None,
        None,
    );
    let body = OAuthStartIn::from_json(
        &json!({"provider": "google", "email": "user@gmail.com", "days": 3}),
    )
    .unwrap();
    let started = f.runner.start_oauth(&body).unwrap();
    assert!(started["authorization_url"]
        .as_str()
        .unwrap()
        .starts_with("https://accounts.google.com/o/oauth2/v2/auth?"));
    assert_eq!(started["message_origin"], "http://localhost:48101");
    // Permission denied consumes the state and renders an error page.
    let state = started["state"].as_str().unwrap();
    let page = f
        .runner
        .oauth_callback("google", state, "", "access_denied")
        .unwrap();
    assert!(page.contains("Permission was not granted by the mailbox provider"));
    assert_eq!(f.runner.oauth().pending_flows(), 0);
}

#[test]
fn scheduled_partial_download_is_retried_as_failure() {
    let captured: Captured = Arc::default();
    let f = Fixture::with(|_| {}, None, Some(stub_download(1, 2, captured.clone())));
    let job_id = "d".repeat(32);
    let directory = f.runner.create_job_dirs(&job_id).unwrap();
    let mut job = NewJob::new(&job_id, "weekly", 0, directory.to_string_lossy())
        .mailbox("user@example.net", 7);
    job.run_kind = "scheduled".into();
    job.window_start = Some("2026-10-10T22:00:00+00:00".into());
    job.window_end = Some("2026-10-17T22:00:00+00:00".into());
    f.runner.db().create_job(job).unwrap();
    let mut auth = MailboxAuth::default();
    auth.password = Some("pw".into());
    f.runner.start_mailbox_job(&job_id, auth).unwrap();
    let job = f.wait(&job_id);
    assert_eq!(job.status, "failed");
    assert_eq!(
        job.error_message.as_deref(),
        Some("Some messages could not be downloaded; the weekly audit will be retried.")
    );
    assert_eq!(
        captured.lock().unwrap()[0].5.as_deref(),
        Some("2026-10-10T22:00:00+00:00")
    );
}

#[test]
fn job_out_serializes_like_python() {
    let f = Fixture::new();
    let job = f.paste();
    let value = serde_json::to_value(&job).unwrap();
    let keys: Vec<&str> = value
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    for key in [
        "id",
        "filename",
        "file_size",
        "status",
        "progress",
        "stage",
        "log",
        "error_message",
        "created_at",
        "completed_at",
        "output_files",
        "source_kind",
        "account_email",
        "days",
        "downloaded_messages",
        "total_messages",
        "snapshot_available",
        "snapshot_at",
        "run_kind",
        "scheduled_for",
        "window_start",
        "window_end",
    ] {
        assert!(keys.contains(&key), "{key}");
    }
    assert_eq!(value["snapshot_available"], false);
    assert_eq!(value["run_kind"], "adhoc");
    f.runner
        .db()
        .update_job(&job.id, &[JobField::SnapshotAvailable(true)], false)
        .unwrap();
}
