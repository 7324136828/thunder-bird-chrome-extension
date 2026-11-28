//! Deterministic durable scheduling tests without network calls or threads
//! (port of `backend/tests/test_doctor_schedule.py`).

use chrono::{DateTime, Duration, Utc};
use mail_core::{MailAccount, MailError, SessionStore};
use mail_doctor::config::DoctorSettings;
use mail_doctor::db::{isoformat, JobField, JobStore};
use mail_doctor::mailbox_download::MailboxAuth;
use mail_doctor::metrics::MetricStore;
use mail_doctor::runner::{ReentrantGuard, ReentrantLock};
use mail_doctor::scheduler::{
    next_saturday, parse_schedule_time, weekly_window, AccountScheduleStatus, ScheduledJobRunner,
    WeeklyAuditScheduler,
};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

const PASSWORD: &str = "memory-only-test-password";

type StartHook = Box<dyn Fn(&str, MailboxAuth) -> Result<(), MailError> + Send + Sync>;

struct FakeRunner {
    settings: DoctorSettings,
    db: JobStore,
    metrics: MetricStore,
    lock: ReentrantLock,
    started: Mutex<Vec<(String, MailboxAuth)>>,
    capacity: AtomicBool,
    start_hook: Mutex<Option<StartHook>>,
}

impl FakeRunner {
    fn new(settings: &DoctorSettings) -> Arc<Self> {
        let db = JobStore::new(settings);
        db.init_db().unwrap();
        let metrics = MetricStore::new(db.clone());
        metrics.init_db().unwrap();
        Arc::new(Self {
            settings: settings.clone(),
            db,
            metrics,
            lock: ReentrantLock::new(),
            started: Mutex::new(Vec::new()),
            capacity: AtomicBool::new(true),
            start_hook: Mutex::new(None),
        })
    }

    fn job_dir_for(&self, job_id: &str) -> PathBuf {
        self.settings.jobs_root().join(job_id)
    }

    fn started(&self) -> Vec<String> {
        self.started
            .lock()
            .unwrap()
            .iter()
            .map(|(id, _)| id.clone())
            .collect()
    }

    fn last_started(&self) -> String {
        self.started().last().cloned().expect("a job was started")
    }
}

impl ScheduledJobRunner for FakeRunner {
    fn db(&self) -> &JobStore {
        &self.db
    }

    fn lock(&self) -> ReentrantGuard<'_> {
        self.lock.lock()
    }

    fn ensure_capacity(&self) -> Result<(), MailError> {
        if self.capacity.load(Ordering::SeqCst) {
            Ok(())
        } else {
            Err(MailError::http(429, "At capacity"))
        }
    }

    fn create_job_dirs(&self, job_id: &str) -> Result<PathBuf, MailError> {
        let directory = self.job_dir_for(job_id);
        for name in ["inputs", "work", "outputs", "archive"] {
            std::fs::create_dir_all(directory.join(name)).unwrap();
        }
        Ok(directory)
    }

    fn purge_job_dir(&self, directory: &Path) -> Result<(), MailError> {
        let _ = std::fs::remove_dir_all(directory);
        Ok(())
    }

    fn start_mailbox_job(&self, job_id: &str, auth: MailboxAuth) -> Result<(), MailError> {
        if let Some(hook) = self.start_hook.lock().unwrap().as_ref() {
            return hook(job_id, auth);
        }
        self.started
            .lock()
            .unwrap()
            .push((job_id.to_string(), auth.clone()));
        Ok(())
    }
}

fn moment(text: &str) -> DateTime<Utc> {
    parse_schedule_time(text).unwrap()
}

fn account(email: &str) -> MailAccount {
    MailAccount::new(
        email,
        PASSWORD,
        "imap.example.com",
        993,
        "SSL/TLS",
        "smtp.example.com",
        465,
        "SSL/TLS",
    )
}

struct Fixture {
    _directory: tempfile::TempDir,
    settings: DoctorSettings,
    runner: Arc<FakeRunner>,
    sessions: SessionStore,
    scheduler: WeeklyAuditScheduler,
    initial: DateTime<Utc>,
    first_due: DateTime<Utc>,
}

impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let settings = DoctorSettings::with_defaults(directory.path());
        let runner = FakeRunner::new(&settings);
        let sessions = SessionStore::new();
        let scheduler = WeeklyAuditScheduler::new(runner.clone(), sessions.clone());
        scheduler.initialize().unwrap();
        Self {
            _directory: directory,
            settings,
            runner,
            sessions,
            scheduler,
            initial: moment("2026-10-13T12:00:00+00:00"),
            first_due: moment("2026-10-17T22:00:00+00:00"),
        }
    }

    /// A new runner (its `init_db` interrupts queued jobs) and scheduler.
    fn restart(&mut self) {
        self.runner = FakeRunner::new(&self.settings);
        self.new_scheduler();
    }

    fn new_scheduler(&mut self) {
        self.scheduler = WeeklyAuditScheduler::new(self.runner.clone(), self.sessions.clone());
    }

    fn register(&self) {
        self.sessions.unlock(account("user@example.com"));
        self.scheduler
            .register(" USER@example.com ", Some(self.initial))
            .unwrap();
    }

    fn tick(&self, at: DateTime<Utc>) {
        self.scheduler.tick(Some(at)).unwrap();
    }

    fn status(&self, at: DateTime<Utc>) -> AccountScheduleStatus {
        self.scheduler
            .get_status(Some(at))
            .unwrap()
            .accounts
            .remove(0)
    }

    fn complete(&self, completed_at: Option<DateTime<Utc>>, status: &str) -> String {
        let job_id = self.runner.last_started();
        let completed = isoformat(&completed_at.unwrap_or(self.first_due));
        self.runner
            .db
            .update_job(
                &job_id,
                &[
                    JobField::status(status),
                    JobField::CompletedAt(Some(completed)),
                ],
                false,
            )
            .unwrap();
        job_id
    }

    fn db_bytes(&self) -> Vec<u8> {
        std::fs::read(self.settings.db_path()).unwrap()
    }
}

fn contains(haystack: &[u8], needle: &str) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle.as_bytes())
}

#[test]
fn first_registration_is_strictly_future_and_is_not_reset_by_unlock() {
    let f = Fixture::new();
    f.register();
    assert_eq!(f.status(f.initial).next_run_at, isoformat(&f.first_due));
    f.scheduler
        .register("user@example.com", Some(f.first_due + Duration::days(25)))
        .unwrap();
    assert_eq!(f.status(f.initial).next_run_at, isoformat(&f.first_due));
    assert_eq!(next_saturday(f.first_due), f.first_due + Duration::days(7));
    f.tick(f.first_due - Duration::seconds(1));
    assert!(f.runner.started().is_empty());
}

#[test]
fn due_job_has_exact_local_week_and_safe_connection_options() {
    let f = Fixture::new();
    f.register();
    f.tick(f.first_due);
    f.tick(f.first_due + Duration::seconds(45));
    let started = f.runner.started.lock().unwrap().clone();
    assert_eq!(started.len(), 1);
    let job = f.runner.db.get_job(&started[0].0).unwrap().unwrap();
    assert_eq!(job.run_kind, "scheduled");
    assert_eq!(
        job.scheduled_for.as_deref(),
        Some("2026-10-17T22:00:00+00:00")
    );
    assert_eq!(
        job.window_start.as_deref(),
        Some("2026-10-10T22:00:00+00:00")
    );
    assert_eq!(job.window_end.as_deref(), Some("2026-10-17T22:00:00+00:00"));
    assert_eq!(
        job.filename,
        "user@example.com INBOX (week ending 2026-10-17)"
    );
    assert_eq!(job.days, Some(7));
    let auth = &started[0].1;
    assert_eq!(auth.password.as_deref(), Some(PASSWORD));
    assert_eq!(auth.imap_server.as_deref(), Some("imap.example.com"));
    assert_eq!(auth.imap_port, Some(993));
    assert_eq!(auth.incoming_protocol.as_deref(), Some("SSL/TLS"));
    assert_eq!((auth.access_token.as_deref(), auth.use_ssl), (None, None));
    assert_eq!(f.status(f.first_due).last_run_at, None);
    assert_eq!(f.status(f.first_due).pending_runs, 1);
    assert!(!contains(&f.db_bytes(), PASSWORD));
}

#[test]
fn missed_weeks_catch_up_sequentially_and_success_is_persisted() {
    let f = Fixture::new();
    f.register();
    let late = moment("2026-11-03T12:00:00+00:00");
    f.tick(late);
    assert_eq!(f.status(late).pending_runs, 3);
    for expected in [
        "2026-10-17T22:00:00+00:00",
        "2026-10-24T22:00:00+00:00",
        "2026-10-31T22:00:00+00:00",
    ] {
        let job = f
            .runner
            .db
            .get_job(&f.runner.last_started())
            .unwrap()
            .unwrap();
        assert_eq!(job.scheduled_for.as_deref(), Some(expected));
        f.complete(Some(late), "completed");
        f.tick(late);
    }
    assert_eq!(f.runner.started().len(), 3);
    let status = f.status(late);
    assert_eq!(status.last_run_at, Some(isoformat(&late)));
    assert_eq!(status.next_run_at, "2026-11-07T23:00:00+00:00");
    assert_eq!(status.pending_runs, 0);
}

#[test]
fn locked_account_preserves_due_until_it_is_unlocked() {
    let f = Fixture::new();
    f.register();
    f.sessions.clear();
    f.tick(f.first_due);
    assert!(f.runner.started().is_empty());
    assert!(!f.status(f.first_due).unlocked);
    assert_eq!(f.status(f.first_due).pending_runs, 1);
    f.sessions.unlock(account("user@example.com"));
    f.tick(f.first_due + Duration::hours(1));
    assert_eq!(f.runner.started().len(), 1);
}

#[test]
fn initial_tick_registers_sessions_without_retroactive_runs() {
    let f = Fixture::new();
    f.sessions.unlock(account("user@example.com"));
    f.tick(f.first_due);
    assert!(f.runner.started().is_empty());
    assert_eq!(
        f.status(f.first_due).next_run_at,
        "2026-10-24T22:00:00+00:00"
    );
}

#[test]
fn pop3_sessions_are_not_scheduled() {
    let f = Fixture::new();
    let mut pop3 = account("pop@example.com");
    pop3.incoming_mail_protocol = "pop3".into();
    f.sessions.unlock(pop3);
    f.tick(f.first_due);
    assert!(f
        .scheduler
        .get_status(Some(f.first_due))
        .unwrap()
        .accounts
        .is_empty());
}

#[test]
fn failure_waits_for_backoff_then_retries_the_same_week() {
    let f = Fixture::new();
    f.register();
    f.tick(f.first_due);
    let first = f.runner.started()[0].clone();
    f.runner
        .db
        .update_job(
            &first,
            &[
                JobField::status("failed"),
                JobField::ErrorMessage(Some("Connection unavailable".into())),
            ],
            false,
        )
        .unwrap();
    f.tick(f.first_due + Duration::minutes(1));
    f.tick(f.first_due + Duration::minutes(5) + Duration::seconds(59));
    assert_eq!(f.runner.started().len(), 1);
    assert_eq!(
        f.status(f.first_due).last_error.as_deref(),
        Some("Connection unavailable")
    );
    assert_eq!(f.status(f.first_due).last_run_at, None);
    f.tick(f.first_due + Duration::minutes(6));
    assert_eq!(f.runner.started().len(), 2);
    let retry = f
        .runner
        .db
        .get_job(&f.runner.last_started())
        .unwrap()
        .unwrap();
    assert_eq!(retry.scheduled_for, Some(isoformat(&f.first_due)));
    f.complete(Some(f.first_due + Duration::minutes(8)), "healthy");
    f.tick(f.first_due + Duration::minutes(8));
    assert_eq!(f.status(f.first_due).last_error, None);
    assert_eq!(
        f.status(f.first_due).last_run_at.as_deref(),
        Some("2026-10-17T22:08:00+00:00")
    );
}

#[test]
fn restart_recovers_interrupted_job_and_persists_backoff_without_duplicates() {
    let mut f = Fixture::new();
    f.register();
    f.tick(f.first_due);
    f.restart(); // init_db marks the queued job interrupted.
    f.tick(f.first_due + Duration::hours(1));
    assert!(f.runner.started().is_empty());
    assert!(f
        .status(f.first_due)
        .last_error
        .unwrap()
        .contains("stopped"));
    f.new_scheduler();
    f.tick(f.first_due + Duration::hours(1) + Duration::minutes(4));
    assert!(f.runner.started().is_empty());
    f.tick(f.first_due + Duration::hours(1) + Duration::minutes(5));
    f.tick(f.first_due + Duration::hours(1) + Duration::minutes(6));
    assert_eq!(f.runner.started().len(), 1);
    assert_eq!(f.runner.db.list_jobs().unwrap().len(), 2);
}

#[test]
fn restart_after_success_does_not_duplicate_the_finished_interval() {
    let mut f = Fixture::new();
    f.register();
    f.tick(f.first_due);
    f.complete(None, "completed");
    f.restart();
    f.tick(f.first_due + Duration::minutes(1));
    assert!(f.runner.started().is_empty());
    assert_eq!(
        f.status(f.first_due).last_run_at,
        Some(isoformat(&f.first_due))
    );
}

#[test]
fn discarding_success_before_reconcile_does_not_retry_or_duplicate_its_metrics() {
    let mut f = Fixture::new();
    f.register();
    f.tick(f.first_due);
    let job_id = f.complete(None, "healthy");
    f.runner
        .db
        .update_job(
            &job_id,
            &[
                JobField::TotalMessages(Some(0)),
                JobField::DownloadedMessages(0),
            ],
            false,
        )
        .unwrap();
    let job = f.runner.db.get_job(&job_id).unwrap().unwrap();
    assert!(f
        .runner
        .metrics
        .capture(&job, &f.runner.job_dir_for(&job_id))
        .unwrap());
    // The user discards the report before the scheduler's next 30s poll.
    let discarded_at = f.first_due + Duration::seconds(2);
    f.runner
        .db
        .update_job(
            &job_id,
            &[
                JobField::status("discarded"),
                JobField::CompletedAt(Some(isoformat(&discarded_at))),
            ],
            false,
        )
        .unwrap();
    f.new_scheduler();
    f.tick(f.first_due + Duration::seconds(30));
    f.tick(f.first_due + Duration::minutes(30));
    assert_eq!(f.runner.started().len(), 1);
    let status = f.status(f.first_due);
    assert_eq!(status.next_run_at, "2026-10-24T22:00:00+00:00");
    assert_eq!(status.last_run_at, Some(isoformat(&f.first_due)));
    assert_eq!(f.runner.metrics.list_metrics(None).unwrap().runs.len(), 1);
    assert_eq!(status.last_error, None);
}

#[test]
fn capacity_keeps_due_work_and_each_poll_starts_at_most_two_accounts() {
    let f = Fixture::new();
    for number in 0..4 {
        let email = format!("user{number}@example.com");
        f.sessions.unlock(account(&email));
        f.scheduler.register(&email, Some(f.initial)).unwrap();
    }
    f.runner.capacity.store(false, Ordering::SeqCst);
    f.tick(f.first_due);
    assert!(f.runner.started().is_empty());
    f.runner.capacity.store(true, Ordering::SeqCst);
    f.tick(f.first_due);
    assert_eq!(f.runner.started().len(), 2);
    f.tick(f.first_due);
    assert_eq!(f.runner.started().len(), 4);
    f.tick(f.first_due);
    assert_eq!(f.runner.started().len(), 4);
}

#[test]
fn reserved_id_without_job_recovers_after_crash() {
    let mut f = Fixture::new();
    f.register();
    f.runner
        .db
        .connection(|conn| {
            conn.execute(
                "UPDATE audit_schedule SET pending_job_id='orphan' WHERE email='user@example.com'",
                [],
            )
        })
        .unwrap();
    f.new_scheduler();
    f.tick(f.first_due);
    assert_eq!(f.runner.started().len(), 1);
}

#[test]
fn start_failure_is_sanitized_and_backed_off() {
    let f = Fixture::new();
    f.register();
    *f.runner.start_hook.lock().unwrap() = Some(Box::new(|_, _| {
        Err(MailError::operation(format!("{PASSWORD} rejected")))
    }));
    f.tick(f.first_due);
    *f.runner.start_hook.lock().unwrap() = None;
    assert_eq!(
        f.status(f.first_due).last_error.as_deref(),
        Some("[redacted] rejected")
    );
    f.tick(f.first_due + Duration::minutes(4));
    assert!(f.runner.started().is_empty());
    f.tick(f.first_due + Duration::minutes(5));
    assert_eq!(f.runner.started().len(), 1);
    assert!(!contains(&f.db_bytes(), PASSWORD));
}

#[test]
fn worker_start_error_is_redacted_even_after_runner_clears_its_auth() {
    let f = Fixture::new();
    f.register();
    *f.runner.start_hook.lock().unwrap() = Some(Box::new(|_, mut auth| {
        auth.clear();
        Err(MailError::operation(format!("{PASSWORD} rejected")))
    }));
    f.tick(f.first_due);
    assert_eq!(
        f.status(f.first_due).last_error.as_deref(),
        Some("[redacted] rejected")
    );
    assert!(!contains(&f.db_bytes(), PASSWORD));
}

#[test]
fn status_reports_all_overdue_slots_at_exact_saturday_boundary() {
    let f = Fixture::new();
    f.register();
    for (at, expected) in [
        ("2026-10-24T21:59:59+00:00", 1),
        ("2026-10-24T22:00:00+00:00", 2),
        ("2026-11-07T22:59:59+00:00", 3),
        ("2026-11-07T23:00:00+00:00", 4),
    ] {
        assert_eq!(f.status(moment(at)).pending_runs, expected, "{at}");
    }
}

#[test]
fn status_json_shape() {
    let f = Fixture::new();
    f.register();
    let value = serde_json::to_value(f.scheduler.get_status(Some(f.initial)).unwrap()).unwrap();
    assert_eq!(
        value,
        serde_json::json!({
            "enabled": true, "timezone": "America/New_York", "weekday": 5, "hour": 18, "minute": 0,
            "accounts": [{
                "email": "user@example.com", "next_run_at": "2026-10-17T22:00:00+00:00",
                "last_run_at": null, "pending_runs": 0, "unlocked": true, "last_error": null,
            }],
        })
    );
}

#[test]
fn local_saturday_schedule_and_windows_follow_both_dst_transitions() {
    for (now, expected, hours) in [
        (
            "2026-03-07T23:00:00+00:00",
            "2026-03-14T22:00:00+00:00",
            167,
        ),
        (
            "2026-10-31T22:00:00+00:00",
            "2026-11-07T23:00:00+00:00",
            169,
        ),
    ] {
        let due = next_saturday(moment(now));
        assert_eq!(due, moment(expected));
        let (start, end) = weekly_window(due);
        assert_eq!(start, moment(now));
        assert_eq!((end - start).num_seconds(), hours * 3600);
    }
    assert!(parse_schedule_time("2026-10-13T00:00:00").is_err());
}

#[test]
fn background_thread_starts_and_closes() {
    let f = Fixture::new();
    f.scheduler.start().unwrap();
    f.scheduler.start().unwrap();
    f.scheduler.close();
}
