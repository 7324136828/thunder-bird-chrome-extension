//! Durable Saturday INBOX audits; credentials remain in the session store
//! (port of `backend/app/doctor/scheduler.py`).
//!
//! Each account keeps the oldest unfinished Saturday in SQLite. Missed weeks
//! are processed one at a time, so shutting down, restarting, or locking an
//! account cannot silently skip a weekly interval.
//!
//! Time is injectable: [`WeeklyAuditScheduler::tick`],
//! [`WeeklyAuditScheduler::register`] and [`WeeklyAuditScheduler::get_status`]
//! take an optional `now` (the background thread passes `None`).

use crate::db::{isoformat, parse_isoformat, IsoDateTime, JobRecord, JobStore, NewJob};
use crate::mailbox_download::MailboxAuth;
use crate::metrics::MetricStore;
use crate::runner::{safe_error, JobRunner, ReentrantGuard, ReentrantLock};
use chrono::{DateTime, Datelike, Duration, LocalResult, NaiveDateTime, TimeZone, Utc};
use chrono_tz::Tz;
use mail_core::{MailError, SessionStore};
use rusqlite::types::Value as SqlValue;
use rusqlite::{params, params_from_iter, OptionalExtension};
use serde::Serialize;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::JoinHandle;

/// IANA name of the schedule's timezone.
pub const TIMEZONE: &str = "America/New_York";
/// The schedule's timezone (`LOCAL_ZONE`).
pub const LOCAL_ZONE: Tz = chrono_tz::America::New_York;
/// Seconds between background checks.
pub const POLL_SECONDS: u64 = 30;
/// Base retry delay after a failed start or run.
pub const RETRY_SECONDS: i64 = 300;

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS audit_schedule (
 email TEXT PRIMARY KEY,
 next_due TEXT NOT NULL,
 last_run_at TEXT,
 pending_job_id TEXT,
 retry_at TEXT,
 retry_count INTEGER NOT NULL DEFAULT 0,
 last_error TEXT,
 updated_at TEXT NOT NULL
)
";

// ---------------------------------------------------------------------------
// Time helpers
// ---------------------------------------------------------------------------

/// Python `_parse`: an aware ISO timestamp in UTC; a naive or invalid value
/// is a `ValueError` (422 here).
pub fn parse_schedule_time(text: &str) -> Result<DateTime<Utc>, MailError> {
    match parse_isoformat(text) {
        Some(IsoDateTime::Aware(value)) => Ok(value.with_timezone(&Utc)),
        Some(IsoDateTime::Naive(_)) => Err(MailError::validation(
            "Schedule times must include a timezone",
        )),
        None => Err(MailError::validation(format!(
            "Invalid isoformat string: '{text}'"
        ))),
    }
}

/// Python `_iso`.
fn iso(value: DateTime<Utc>) -> String {
    isoformat(&value)
}

/// Attach the New York zone to a wall-clock time like zoneinfo with `fold=0`
/// (earlier offset when ambiguous, pre-transition offset in a gap).
fn localize(naive: NaiveDateTime) -> DateTime<Tz> {
    match LOCAL_ZONE.from_local_datetime(&naive) {
        LocalResult::Single(value) => value,
        LocalResult::Ambiguous(earlier, _) => earlier,
        LocalResult::None => {
            let before = LOCAL_ZONE
                .from_local_datetime(&(naive - Duration::hours(3)))
                .earliest()
                .expect("three hours before a gap is a valid local time");
            let offset = *before.offset();
            let utc =
                naive - Duration::seconds(chrono::Offset::fix(&offset).local_minus_utc() as i64);
            Utc.from_utc_datetime(&utc).with_timezone(&LOCAL_ZONE)
        }
    }
}

/// Python aware-datetime `+ timedelta(days)` for a zoneinfo time: wall-clock
/// arithmetic, then the offset is recomputed.
fn add_local_days(value: DateTime<Tz>, days: i64) -> DateTime<Tz> {
    localize(value.naive_local() + Duration::days(days))
}

/// Python `next_saturday`: the first Saturday 18:00 strictly after `now` in
/// New York.
pub fn next_saturday(now: DateTime<Utc>) -> DateTime<Utc> {
    let local = now.with_timezone(&LOCAL_ZONE);
    let offset = (5 - local.weekday().num_days_from_monday() as i64).rem_euclid(7);
    let date = local.date_naive() + Duration::days(offset);
    let mut due = localize(date.and_hms_opt(18, 0, 0).expect("valid time"));
    if due <= local {
        due = add_local_days(due, 7);
    }
    due.with_timezone(&Utc)
}

/// Python `weekly_window`: `[previous Saturday 18:00, this Saturday 18:00)`,
/// honoring DST.
pub fn weekly_window(due: DateTime<Utc>) -> (DateTime<Utc>, DateTime<Utc>) {
    let end = due.with_timezone(&LOCAL_ZONE);
    (add_local_days(end, -7).with_timezone(&Utc), due)
}

// ---------------------------------------------------------------------------
// Runner abstraction (the Python tests used a FakeRunner)
// ---------------------------------------------------------------------------

/// What the scheduler needs from a job runner.
pub trait ScheduledJobRunner: Send + Sync {
    fn db(&self) -> &JobStore;
    /// The runner lock (`runner.lock`).
    fn lock(&self) -> ReentrantGuard<'_>;
    fn ensure_capacity(&self) -> Result<(), MailError>;
    fn create_job_dirs(&self, job_id: &str) -> Result<PathBuf, MailError>;
    fn purge_job_dir(&self, directory: &Path) -> Result<(), MailError>;
    fn start_mailbox_job(&self, job_id: &str, auth: MailboxAuth) -> Result<(), MailError>;
}

impl ScheduledJobRunner for JobRunner {
    fn db(&self) -> &JobStore {
        JobRunner::db(self)
    }

    fn lock(&self) -> ReentrantGuard<'_> {
        JobRunner::lock(self)
    }

    fn ensure_capacity(&self) -> Result<(), MailError> {
        JobRunner::ensure_capacity(self)
    }

    fn create_job_dirs(&self, job_id: &str) -> Result<PathBuf, MailError> {
        JobRunner::create_job_dirs(self, job_id)
    }

    fn purge_job_dir(&self, directory: &Path) -> Result<(), MailError> {
        JobRunner::purge_job_dir(self, directory)
    }

    fn start_mailbox_job(&self, job_id: &str, auth: MailboxAuth) -> Result<(), MailError> {
        JobRunner::start_mailbox_job(self, job_id, auth)
    }
}

// ---------------------------------------------------------------------------
// Rows and status
// ---------------------------------------------------------------------------

/// One `audit_schedule` row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScheduleRow {
    pub email: String,
    pub next_due: String,
    pub last_run_at: Option<String>,
    pub pending_job_id: Option<String>,
    pub retry_at: Option<String>,
    pub retry_count: i64,
    pub last_error: Option<String>,
    pub updated_at: String,
}

/// One account in `GET /api/mail/audit-schedule`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AccountScheduleStatus {
    pub email: String,
    pub next_run_at: String,
    pub last_run_at: Option<String>,
    pub pending_runs: i64,
    pub unlocked: bool,
    pub last_error: Option<String>,
}

/// `get_status()` JSON.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ScheduleStatus {
    pub enabled: bool,
    pub timezone: &'static str,
    pub weekday: u32,
    pub hour: u32,
    pub minute: u32,
    pub accounts: Vec<AccountScheduleStatus>,
}

/// A schedule column update (`_update(**fields)`).
#[derive(Debug, Clone)]
enum Field {
    NextDue(String),
    LastRunAt(Option<String>),
    PendingJobId(Option<String>),
    RetryAt(Option<String>),
    RetryCount(i64),
    LastError(Option<String>),
}

impl Field {
    fn column(&self) -> &'static str {
        match self {
            Self::NextDue(_) => "next_due",
            Self::LastRunAt(_) => "last_run_at",
            Self::PendingJobId(_) => "pending_job_id",
            Self::RetryAt(_) => "retry_at",
            Self::RetryCount(_) => "retry_count",
            Self::LastError(_) => "last_error",
        }
    }

    fn value(&self) -> SqlValue {
        let text = |v: &Option<String>| v.clone().map_or(SqlValue::Null, SqlValue::Text);
        match self {
            Self::NextDue(v) => SqlValue::Text(v.clone()),
            Self::RetryCount(v) => SqlValue::Integer(*v),
            Self::LastRunAt(v) | Self::PendingJobId(v) | Self::RetryAt(v) | Self::LastError(v) => {
                text(v)
            }
        }
    }

    fn apply(&self, row: &mut ScheduleRow) {
        match self {
            Self::NextDue(v) => row.next_due = v.clone(),
            Self::LastRunAt(v) => row.last_run_at = v.clone(),
            Self::PendingJobId(v) => row.pending_job_id = v.clone(),
            Self::RetryAt(v) => row.retry_at = v.clone(),
            Self::RetryCount(v) => row.retry_count = *v,
            Self::LastError(v) => row.last_error = v.clone(),
        }
    }
}

// ---------------------------------------------------------------------------
// Scheduler
// ---------------------------------------------------------------------------

struct Inner {
    runner: Arc<dyn ScheduledJobRunner>,
    sessions: SessionStore,
    lock: ReentrantLock,
    initialized: AtomicBool,
    stop: Mutex<bool>,
    wake: Condvar,
    thread: Mutex<Option<(JoinHandle<()>, Arc<AtomicBool>)>>,
}

/// Python `WeeklyAuditScheduler` (cheap to clone; clones share state).
#[derive(Clone)]
pub struct WeeklyAuditScheduler {
    inner: Arc<Inner>,
}

impl WeeklyAuditScheduler {
    pub fn new(runner: Arc<dyn ScheduledJobRunner>, sessions: SessionStore) -> Self {
        Self {
            inner: Arc::new(Inner {
                runner,
                sessions,
                lock: ReentrantLock::new(),
                initialized: AtomicBool::new(false),
                stop: Mutex::new(false),
                wake: Condvar::new(),
                thread: Mutex::new(None),
            }),
        }
    }

    fn db(&self) -> &JobStore {
        self.inner.runner.db()
    }

    /// Create the schedule table (and the metrics tables it reads) once.
    pub fn initialize(&self) -> Result<(), MailError> {
        let _guard = self.inner.lock.lock();
        if self.inner.initialized.load(Ordering::SeqCst) {
            return Ok(());
        }
        self.db()
            .connection(|conn| conn.execute(SCHEMA, []).map(|_| ()))?;
        MetricStore::new(self.db().clone()).init_db()?;
        self.inner.initialized.store(true, Ordering::SeqCst);
        Ok(())
    }

    /// Start the background thread that calls [`tick`](Self::tick) every 30 s.
    pub fn start(&self) -> Result<(), MailError> {
        let _guard = self.inner.lock.lock();
        self.initialize()?;
        let mut thread = self.inner.thread.lock().unwrap();
        if thread
            .as_ref()
            .is_some_and(|(_, finished)| !finished.load(Ordering::SeqCst))
        {
            return Ok(());
        }
        *self.inner.stop.lock().unwrap() = false;
        let finished = Arc::new(AtomicBool::new(false));
        let scheduler = self.clone();
        let done = finished.clone();
        let handle = std::thread::Builder::new()
            .name("inbox-doctor-schedule".into())
            .spawn(move || {
                scheduler.run_loop();
                done.store(true, Ordering::SeqCst);
            })
            .map_err(|_| {
                MailError::Settings("The weekly audit scheduler could not start".into())
            })?;
        *thread = Some((handle, finished));
        Ok(())
    }

    /// Stop the background thread (waits up to five seconds).
    pub fn close(&self) {
        *self.inner.stop.lock().unwrap() = true;
        self.inner.wake.notify_all();
        let taken = self.inner.thread.lock().unwrap().take();
        if let Some((handle, finished)) = taken {
            if handle.thread().id() == std::thread::current().id() {
                return;
            }
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
            while !finished.load(Ordering::SeqCst) && std::time::Instant::now() < deadline {
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            if finished.load(Ordering::SeqCst) {
                let _ = handle.join();
            }
        }
    }

    fn run_loop(&self) {
        loop {
            if *self.inner.stop.lock().unwrap() {
                return;
            }
            if self.tick(None).is_err() {
                // Do not include error contents: mailbox credentials are
                // memory-only, including unexpected errors in this thread.
                eprintln!("The weekly audit scheduler could not complete its check");
            }
            let stop = self.inner.stop.lock().unwrap();
            let (stop, _) = self
                .inner
                .wake
                .wait_timeout_while(stop, std::time::Duration::from_secs(POLL_SECONDS), |stop| {
                    !*stop
                })
                .unwrap();
            if *stop {
                return;
            }
        }
    }

    /// Python `register`: add an account whose first run is the next
    /// Saturday; an existing schedule is never reset.
    pub fn register(&self, email: &str, now: Option<DateTime<Utc>>) -> Result<(), MailError> {
        let email = email.trim().to_lowercase();
        if email.is_empty() {
            return Ok(());
        }
        let current = now.unwrap_or_else(Utc::now);
        let _guard = self.inner.lock.lock();
        self.initialize()?;
        self.db().connection(|conn| {
            conn.execute(
                "INSERT OR IGNORE INTO audit_schedule(email,next_due,updated_at) VALUES (?1,?2,?3)",
                params![email, iso(next_saturday(current)), iso(current)],
            )
            .map(|_| ())
        })
    }

    /// Every schedule row, ordered by `next_due, email`.
    pub fn rows(&self) -> Result<Vec<ScheduleRow>, MailError> {
        self.db().connection(|conn| {
            conn.prepare("SELECT * FROM audit_schedule ORDER BY next_due,email")?
                .query_map([], |row| {
                    Ok(ScheduleRow {
                        email: row.get("email")?,
                        next_due: row.get("next_due")?,
                        last_run_at: row.get("last_run_at")?,
                        pending_job_id: row.get("pending_job_id")?,
                        retry_at: row.get("retry_at")?,
                        retry_count: row.get("retry_count")?,
                        last_error: row.get("last_error")?,
                        updated_at: row.get("updated_at")?,
                    })
                })?
                .collect()
        })
    }

    fn update(
        &self,
        row: &mut ScheduleRow,
        current: DateTime<Utc>,
        fields: &[Field],
    ) -> Result<(), MailError> {
        let updated_at = iso(current);
        let mut clause: Vec<String> = fields.iter().map(|f| format!("{}=?", f.column())).collect();
        clause.push("updated_at=?".into());
        let mut values: Vec<SqlValue> = fields.iter().map(Field::value).collect();
        values.push(SqlValue::Text(updated_at.clone()));
        values.push(SqlValue::Text(row.email.clone()));
        let sql = format!(
            "UPDATE audit_schedule SET {} WHERE email=?",
            clause.join(", ")
        );
        self.db().connection(|conn| {
            conn.execute(&sql, params_from_iter(values.iter()))
                .map(|_| ())
        })?;
        for field in fields {
            field.apply(row);
        }
        row.updated_at = updated_at;
        Ok(())
    }

    /// Python `_reconcile`: settle the row's pending job (success advances a
    /// week, failure backs off, an orphaned reservation is released).
    fn reconcile(
        &self,
        mut row: ScheduleRow,
        current: DateTime<Utc>,
    ) -> Result<ScheduleRow, MailError> {
        let Some(job_id) = row.pending_job_id.clone() else {
            return Ok(row);
        };
        let job: Option<JobRecord> = self.db().get_job(&job_id)?;
        if job.as_ref().is_some_and(JobRecord::is_active) {
            return Ok(row);
        }
        // Discarding a completed report changes the job's terminal status and
        // timestamp. Its independent metrics snapshot still proves this weekly
        // window completed, so report cleanup must never schedule it again.
        let snapshot: Option<String> = self.db().connection(|conn| {
            conn.query_row(
                "SELECT COALESCE(completed_at,created_at) AS success_at FROM email_metric_runs \
                 WHERE id=?1 AND run_kind='scheduled'",
                [&job_id],
                |r| r.get(0),
            )
            .optional()
        })?;
        let succeeded = job
            .as_ref()
            .is_some_and(|job| matches!(job.status.as_str(), "completed" | "healthy"));
        let fields = if snapshot.is_some() || succeeded {
            let due = parse_schedule_time(&row.next_due)?.with_timezone(&LOCAL_ZONE);
            let last_run = snapshot.unwrap_or_else(|| {
                job.as_ref()
                    .and_then(|job| job.completed_at.clone())
                    .filter(|value| !value.is_empty())
                    .unwrap_or_else(|| iso(current))
            });
            vec![
                Field::NextDue(isoformat(&add_local_days(due, 7).with_timezone(&Utc))),
                Field::LastRunAt(Some(last_run)),
                Field::PendingJobId(None),
                Field::RetryAt(None),
                Field::RetryCount(0),
                Field::LastError(None),
            ]
        } else if job.is_none() {
            // A shutdown can happen after reserving an ID but before creating
            // its job. No worker ran, so this window is safe to start now.
            vec![Field::PendingJobId(None)]
        } else if row.retry_at.is_none() {
            let attempts = row.retry_count + 1;
            let seconds = (RETRY_SECONDS * 2i64.pow((attempts - 1).clamp(0, 4) as u32)).min(3600);
            let error = job
                .and_then(|job| job.error_message)
                .filter(|message| !message.is_empty())
                .unwrap_or_else(|| "The scheduled audit did not finish".into());
            vec![
                Field::RetryAt(Some(iso(current + Duration::seconds(seconds)))),
                Field::RetryCount(attempts),
                Field::LastError(Some(error)),
            ]
        } else if parse_schedule_time(row.retry_at.as_deref().unwrap_or_default())? <= current {
            vec![Field::PendingJobId(None), Field::RetryAt(None)]
        } else {
            Vec::new()
        };
        if !fields.is_empty() {
            self.update(&mut row, current, &fields)?;
        }
        Ok(row)
    }

    /// Python `_start_account`: reserve the due window and start its job.
    fn start_account(
        &self,
        row: &mut ScheduleRow,
        current: DateTime<Utc>,
    ) -> Result<bool, MailError> {
        let Some(account) = self.inner.sessions.get(&row.email) else {
            return Ok(false);
        };
        // POP3 sessions cannot be audited (IMAP download only); the window
        // stays pending like a locked account.
        if account.is_pop3() {
            return Ok(false);
        }
        let runner = &self.inner.runner;
        let _guard = runner.lock();
        if runner.ensure_capacity().is_err() {
            return Ok(false);
        }
        let job_id = uuid::Uuid::new_v4().simple().to_string();
        let (start, end) = weekly_window(parse_schedule_time(&row.next_due)?);
        let auth = MailboxAuth::from_account(&account);
        let redactions = auth.clone();
        let mut directory: Option<PathBuf> = None;
        let attempt = (|| -> Result<(), MailError> {
            // Reserve the window before creating or starting its job.
            // Reconciliation recovers any interruption between these steps.
            self.update(
                row,
                current,
                &[
                    Field::PendingJobId(Some(job_id.clone())),
                    Field::RetryAt(None),
                ],
            )?;
            let created = runner.create_job_dirs(&job_id)?;
            directory = Some(created.clone());
            let week_ending = end.with_timezone(&LOCAL_ZONE).format("%Y-%m-%d");
            let mut job = NewJob::new(
                &job_id,
                format!("{} INBOX (week ending {week_ending})", account.email),
                0,
                created.to_string_lossy(),
            )
            .mailbox(&account.email, 7);
            job.run_kind = "scheduled".into();
            job.scheduled_for = Some(iso(end));
            job.window_start = Some(iso(start));
            job.window_end = Some(iso(end));
            runner.db().create_job(job)?;
            runner.start_mailbox_job(&job_id, auth)?;
            Ok(())
        })();
        let Err(error) = attempt else {
            return Ok(true);
        };
        // A failed worker start may already have consumed its auth.
        let message = safe_error(&error.to_string(), Some(&redactions));
        drop(redactions);
        let job = runner.db().get_job(&job_id)?;
        if job.is_some() {
            runner.db().update_job(
                &job_id,
                &[
                    crate::db::JobField::status("failed"),
                    crate::db::JobField::stage("failed"),
                    crate::db::JobField::CompletedAt(Some(iso(current))),
                    crate::db::JobField::ErrorMessage(Some(message.clone())),
                ],
                false,
            )?;
        } else if let Some(directory) = &directory {
            runner.purge_job_dir(directory)?;
        }
        let retry_count = row.retry_count + 1;
        self.update(
            row,
            current,
            &[
                Field::PendingJobId(job.map(|_| job_id.clone())),
                Field::RetryAt(Some(iso(current + Duration::seconds(RETRY_SECONDS)))),
                Field::RetryCount(retry_count),
                Field::LastError(Some(message)),
            ],
        )?;
        Ok(false)
    }

    /// Python `tick`: register unlocked sessions, settle pending jobs and
    /// start due weeks (at most two new jobs per poll, one per account).
    pub fn tick(&self, now: Option<DateTime<Utc>>) -> Result<(), MailError> {
        let current = now.unwrap_or_else(Utc::now);
        let _guard = self.inner.lock.lock();
        self.initialize()?;
        for account in self.inner.sessions.list() {
            if !account.is_pop3() {
                self.register(&account.email, Some(current))?;
            }
        }
        let mut started = 0;
        for row in self.rows()? {
            let mut row = self.reconcile(row, current)?;
            if row.pending_job_id.is_some() || parse_schedule_time(&row.next_due)? > current {
                continue;
            }
            if let Some(retry_at) = &row.retry_at {
                if parse_schedule_time(retry_at)? > current {
                    continue;
                }
            }
            if started < 2 && self.start_account(&mut row, current)? {
                started += 1;
            }
        }
        Ok(())
    }

    /// Python `get_status` (`GET /api/mail/audit-schedule`).
    pub fn get_status(&self, now: Option<DateTime<Utc>>) -> Result<ScheduleStatus, MailError> {
        let current = now.unwrap_or_else(Utc::now);
        let _guard = self.inner.lock.lock();
        self.initialize()?;
        let mut accounts = Vec::new();
        for row in self.rows()? {
            let row = self.reconcile(row, current)?;
            let due = parse_schedule_time(&row.next_due)?.with_timezone(&LOCAL_ZONE);
            let local_now = current.with_timezone(&LOCAL_ZONE);
            let mut pending = 0;
            if due <= local_now {
                // Compare local dates and the 18:00 boundary so DST weeks
                // count as one interval even when their UTC length varies.
                let days = (local_now.date_naive() - due.date_naive()).num_days();
                pending = days.div_euclid(7) + 1;
                if local_now.time() < due.time() && days.rem_euclid(7) == 0 {
                    pending -= 1;
                }
            }
            accounts.push(AccountScheduleStatus {
                unlocked: self.inner.sessions.get(&row.email).is_some(),
                email: row.email,
                next_run_at: row.next_due,
                last_run_at: row.last_run_at,
                pending_runs: pending,
                last_error: row.last_error,
            });
        }
        Ok(ScheduleStatus {
            enabled: true,
            timezone: TIMEZONE,
            weekday: 5,
            hour: 18,
            minute: 0,
            accounts,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn moment(text: &str) -> DateTime<Utc> {
        parse_schedule_time(text).unwrap()
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
            assert_eq!(due, moment(expected), "{now}");
            let (start, end) = weekly_window(due);
            assert_eq!(start, moment(now));
            assert_eq!((end - start).num_seconds(), hours * 3600);
        }
        assert_eq!(
            parse_schedule_time("2026-10-13T00:00:00")
                .unwrap_err()
                .detail(),
            "Schedule times must include a timezone"
        );
    }

    #[test]
    fn next_saturday_is_strictly_future() {
        let due = moment("2026-10-17T22:00:00+00:00");
        assert_eq!(next_saturday(moment("2026-10-13T12:00:00+00:00")), due);
        assert_eq!(next_saturday(due), due + Duration::days(7));
        assert_eq!(next_saturday(due - Duration::seconds(1)), due);
        assert_eq!(iso(due), "2026-10-17T22:00:00+00:00");
    }
}
