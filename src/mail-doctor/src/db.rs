//! A per-application SQLite job registry; authentication is never stored
//! (port of `backend/app/doctor/db.py`).
//!
//! The schema, migrations and restart normalizations are identical to the
//! Python version, so an existing `jobs.sqlite3` keeps working.
//!
//! The module also hosts the Python-compatible timestamp helpers shared by
//! the runner, metrics and scheduler (`datetime.isoformat()` /
//! `datetime.fromisoformat()`).

use crate::config::DoctorSettings;
use chrono::{
    DateTime, Duration, FixedOffset, NaiveDate, NaiveDateTime, NaiveTime, Offset, TimeZone,
    Timelike, Utc,
};
use mail_core::MailError;
use rusqlite::types::Value as SqlValue;
use rusqlite::{params, Connection, OptionalExtension, Row};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

/// Statuses after which a job never changes again (except by discard).
pub const TERMINAL_STATUSES: [&str; 4] = ["completed", "healthy", "failed", "discarded"];

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS jobs (
 id TEXT PRIMARY KEY, filename TEXT NOT NULL, file_size INTEGER NOT NULL DEFAULT 0,
 status TEXT NOT NULL DEFAULT 'queued', progress INTEGER NOT NULL DEFAULT 0,
 stage TEXT, log TEXT NOT NULL DEFAULT '', error_message TEXT,
 temp_dir TEXT, zip_path TEXT, created_at TEXT NOT NULL, completed_at TEXT,
 source_kind TEXT NOT NULL DEFAULT 'upload', account_email TEXT, days INTEGER,
 downloaded_messages INTEGER NOT NULL DEFAULT 0, total_messages INTEGER,
 snapshot_available INTEGER NOT NULL DEFAULT 0, snapshot_at TEXT,
 run_kind TEXT NOT NULL DEFAULT 'adhoc', scheduled_for TEXT, window_start TEXT, window_end TEXT
)
";

const MIGRATED_COLUMNS: [(&str, &str); 4] = [
    ("run_kind", "TEXT NOT NULL DEFAULT 'adhoc'"),
    ("scheduled_for", "TEXT"),
    ("window_start", "TEXT"),
    ("window_end", "TEXT"),
];

// ---------------------------------------------------------------------------
// Timestamps
// ---------------------------------------------------------------------------

/// Python `datetime.isoformat()` for an aware datetime:
/// `YYYY-MM-DDTHH:MM:SS[.ffffff]+HH:MM` (microseconds only when non-zero).
pub fn isoformat<Tz: TimeZone>(value: &DateTime<Tz>) -> String {
    let fixed = value.with_timezone(&value.offset().fix());
    let micros = fixed.nanosecond() % 1_000_000_000 / 1_000;
    let base = fixed.format("%Y-%m-%dT%H:%M:%S").to_string();
    let offset = fixed.format("%:z").to_string();
    if micros == 0 {
        format!("{base}{offset}")
    } else {
        format!("{base}.{micros:06}{offset}")
    }
}

/// Python `db.utcnow()`: `datetime.now(timezone.utc).isoformat()`.
pub fn utcnow() -> String {
    isoformat(&Utc::now())
}

/// Result of [`parse_isoformat`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IsoDateTime {
    Aware(DateTime<FixedOffset>),
    Naive(NaiveDateTime),
}

impl IsoDateTime {
    /// The aware value, or `None` for a naive timestamp.
    pub fn aware(self) -> Option<DateTime<FixedOffset>> {
        match self {
            Self::Aware(value) => Some(value),
            Self::Naive(_) => None,
        }
    }
}

fn parse_offset(text: &str) -> Option<FixedOffset> {
    if text == "Z" || text == "z" {
        return FixedOffset::east_opt(0);
    }
    let (sign, rest) = match text.as_bytes().first()? {
        b'+' => (1, &text[1..]),
        b'-' => (-1, &text[1..]),
        _ => return None,
    };
    let digits: String = rest.chars().filter(|c| *c != ':').collect();
    if !digits.chars().all(|c| c.is_ascii_digit()) || !matches!(digits.len(), 4 | 6) {
        return None;
    }
    let hours: i32 = digits[0..2].parse().ok()?;
    let minutes: i32 = digits[2..4].parse().ok()?;
    let seconds: i32 = if digits.len() == 6 {
        digits[4..6].parse().ok()?
    } else {
        0
    };
    if hours > 23 || minutes > 59 || seconds > 59 {
        return None;
    }
    FixedOffset::east_opt(sign * (hours * 3600 + minutes * 60 + seconds))
}

fn parse_time(text: &str) -> Option<NaiveTime> {
    let (clock, fraction) = match text.split_once(['.', ',']) {
        Some((clock, fraction)) => (clock, Some(fraction)),
        None => (text, None),
    };
    let parts: Vec<&str> = clock.split(':').collect();
    if parts
        .iter()
        .any(|p| p.len() != 2 || !p.bytes().all(|b| b.is_ascii_digit()))
    {
        return None;
    }
    let (hour, minute, second) = match parts.as_slice() {
        [h] => (h.parse().ok()?, 0, 0),
        [h, m] => (h.parse().ok()?, m.parse().ok()?, 0),
        [h, m, s] => (h.parse().ok()?, m.parse().ok()?, s.parse().ok()?),
        _ => return None,
    };
    let micros = match fraction {
        None => 0,
        Some(f) if !f.is_empty() && f.len() <= 9 && f.bytes().all(|b| b.is_ascii_digit()) => {
            format!("{f:0<6}")[..6].parse().ok()?
        }
        Some(_) => return None,
    };
    NaiveTime::from_hms_micro_opt(hour, minute, second, micros)
}

/// Python `datetime.fromisoformat()` (3.11 grammar subset used by the app):
/// `YYYY-MM-DD[(T| )HH[:MM[:SS[.ffffff]]][Z|±HH:MM]]`.
pub fn parse_isoformat(text: &str) -> Option<IsoDateTime> {
    if text.len() < 10 || !text.is_char_boundary(10) {
        return None;
    }
    let date = NaiveDate::parse_from_str(&text[..10], "%Y-%m-%d").ok()?;
    let rest = &text[10..];
    if rest.is_empty() {
        return Some(IsoDateTime::Naive(date.and_time(NaiveTime::MIN)));
    }
    let mut chars = rest.chars();
    chars.next()?; // Any single separator character, like Python.
    let rest = chars.as_str();
    let split = rest.find(['+', '-', 'Z', 'z']);
    let (time_text, offset_text) = match split {
        Some(index) => (&rest[..index], Some(&rest[index..])),
        None => (rest, None),
    };
    let time = parse_time(time_text)?;
    let naive = date.and_time(time);
    match offset_text {
        None => Some(IsoDateTime::Naive(naive)),
        Some(offset) => {
            let offset = parse_offset(offset)?;
            offset
                .from_local_datetime(&naive)
                .single()
                .map(IsoDateTime::Aware)
        }
    }
}

/// An aware ISO timestamp converted to UTC; `None` for naive or invalid text.
pub fn parse_aware_utc(text: &str) -> Option<DateTime<Utc>> {
    parse_isoformat(text)?
        .aware()
        .map(|value| value.with_timezone(&Utc))
}

// ---------------------------------------------------------------------------
// Job rows
// ---------------------------------------------------------------------------

/// One `jobs` row (`dict(row)` in Python).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct JobRecord {
    pub id: String,
    pub filename: String,
    pub file_size: i64,
    pub status: String,
    pub progress: i64,
    pub stage: Option<String>,
    pub log: String,
    pub error_message: Option<String>,
    pub temp_dir: Option<String>,
    pub zip_path: Option<String>,
    pub created_at: String,
    pub completed_at: Option<String>,
    pub source_kind: String,
    pub account_email: Option<String>,
    pub days: Option<i64>,
    pub downloaded_messages: i64,
    pub total_messages: Option<i64>,
    pub snapshot_available: bool,
    pub snapshot_at: Option<String>,
    pub run_kind: String,
    pub scheduled_for: Option<String>,
    pub window_start: Option<String>,
    pub window_end: Option<String>,
}

impl JobRecord {
    fn from_row(row: &Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            id: row.get("id")?,
            filename: row.get("filename")?,
            file_size: row.get("file_size")?,
            status: row.get("status")?,
            progress: row.get("progress")?,
            stage: row.get("stage")?,
            log: row.get::<_, Option<String>>("log")?.unwrap_or_default(),
            error_message: row.get("error_message")?,
            temp_dir: row.get("temp_dir")?,
            zip_path: row.get("zip_path")?,
            created_at: row.get("created_at")?,
            completed_at: row.get("completed_at")?,
            source_kind: row.get("source_kind")?,
            account_email: row.get("account_email")?,
            days: row.get("days")?,
            downloaded_messages: row.get("downloaded_messages")?,
            total_messages: row.get("total_messages")?,
            snapshot_available: row.get::<_, i64>("snapshot_available")? != 0,
            snapshot_at: row.get("snapshot_at")?,
            run_kind: row.get("run_kind")?,
            scheduled_for: row.get("scheduled_for")?,
            window_start: row.get("window_start")?,
            window_end: row.get("window_end")?,
        })
    }

    /// `status in ('queued', 'in_progress')`.
    pub fn is_active(&self) -> bool {
        matches!(self.status.as_str(), "queued" | "in_progress")
    }

    pub fn is_terminal(&self) -> bool {
        TERMINAL_STATUSES.contains(&self.status.as_str())
    }
}

/// Arguments of `JobStore.create_job` (defaults match the Python keywords).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewJob {
    pub id: String,
    pub filename: String,
    pub file_size: i64,
    pub temp_dir: String,
    pub source_kind: String,
    pub account_email: Option<String>,
    pub days: Option<i64>,
    pub run_kind: String,
    pub scheduled_for: Option<String>,
    pub window_start: Option<String>,
    pub window_end: Option<String>,
}

impl NewJob {
    /// An `upload` / `adhoc` job.
    pub fn new(
        id: impl Into<String>,
        filename: impl Into<String>,
        file_size: i64,
        temp_dir: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            filename: filename.into(),
            file_size,
            temp_dir: temp_dir.into(),
            source_kind: "upload".into(),
            account_email: None,
            days: None,
            run_kind: "adhoc".into(),
            scheduled_for: None,
            window_start: None,
            window_end: None,
        }
    }

    /// `source_kind="mailbox", account_email=..., days=...`.
    pub fn mailbox(mut self, account_email: impl Into<String>, days: i64) -> Self {
        self.source_kind = "mailbox".into();
        self.account_email = Some(account_email.into());
        self.days = Some(days);
        self
    }
}

/// One updatable column for [`JobStore::update_job`] (Python `_UPDATABLE`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JobField {
    Filename(String),
    FileSize(i64),
    Status(String),
    Progress(i64),
    Stage(Option<String>),
    ErrorMessage(Option<String>),
    TempDir(Option<String>),
    ZipPath(Option<String>),
    CompletedAt(Option<String>),
    SourceKind(String),
    AccountEmail(Option<String>),
    Days(Option<i64>),
    DownloadedMessages(i64),
    TotalMessages(Option<i64>),
    SnapshotAvailable(bool),
    SnapshotAt(Option<String>),
}

impl JobField {
    /// `JobField::Status(value.into())`.
    pub fn status(value: &str) -> Self {
        Self::Status(value.into())
    }

    /// `JobField::Stage(Some(value.into()))`.
    pub fn stage(value: &str) -> Self {
        Self::Stage(Some(value.into()))
    }

    fn column(&self) -> &'static str {
        match self {
            Self::Filename(_) => "filename",
            Self::FileSize(_) => "file_size",
            Self::Status(_) => "status",
            Self::Progress(_) => "progress",
            Self::Stage(_) => "stage",
            Self::ErrorMessage(_) => "error_message",
            Self::TempDir(_) => "temp_dir",
            Self::ZipPath(_) => "zip_path",
            Self::CompletedAt(_) => "completed_at",
            Self::SourceKind(_) => "source_kind",
            Self::AccountEmail(_) => "account_email",
            Self::Days(_) => "days",
            Self::DownloadedMessages(_) => "downloaded_messages",
            Self::TotalMessages(_) => "total_messages",
            Self::SnapshotAvailable(_) => "snapshot_available",
            Self::SnapshotAt(_) => "snapshot_at",
        }
    }

    fn value(&self) -> SqlValue {
        fn text(value: &Option<String>) -> SqlValue {
            value.clone().map_or(SqlValue::Null, SqlValue::Text)
        }
        fn integer(value: &Option<i64>) -> SqlValue {
            value.map_or(SqlValue::Null, SqlValue::Integer)
        }
        match self {
            Self::Filename(v) | Self::Status(v) | Self::SourceKind(v) => SqlValue::Text(v.clone()),
            Self::FileSize(v) | Self::Progress(v) | Self::DownloadedMessages(v) => {
                SqlValue::Integer(*v)
            }
            Self::Stage(v)
            | Self::ErrorMessage(v)
            | Self::TempDir(v)
            | Self::ZipPath(v)
            | Self::CompletedAt(v)
            | Self::AccountEmail(v)
            | Self::SnapshotAt(v) => text(v),
            Self::Days(v) | Self::TotalMessages(v) => integer(v),
            Self::SnapshotAvailable(v) => SqlValue::Integer(i64::from(*v)),
        }
    }
}

/// Convert a database failure into the crate's error type (HTTP 500).
pub(crate) fn db_error(error: impl std::fmt::Display) -> MailError {
    MailError::Retention(format!("Inbox Doctor database error: {error}"))
}

/// Python `JobStore`. Cheap to clone; clones share one lock, which serializes
/// every connection exactly like the Python `RLock` (the lock is not
/// reentrant: never call [`JobStore::connection`] from inside its closure).
#[derive(Debug, Clone)]
pub struct JobStore {
    db_path: PathBuf,
    log_char_cap: usize,
    lock: Arc<Mutex<()>>,
}

impl JobStore {
    pub fn new(settings: &DoctorSettings) -> Self {
        Self {
            db_path: settings.db_path(),
            log_char_cap: settings.log_char_cap,
            lock: Arc::new(Mutex::new(())),
        }
    }

    pub fn db_path(&self) -> &std::path::Path {
        &self.db_path
    }

    /// Run `body` in one transaction on a fresh connection (committed when
    /// `body` succeeds, rolled back otherwise), under the store lock.
    pub fn connection<T>(
        &self,
        body: impl FnOnce(&Connection) -> rusqlite::Result<T>,
    ) -> Result<T, MailError> {
        let _guard = self
            .lock
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let mut connection = Connection::open(&self.db_path).map_err(db_error)?;
        connection
            .busy_timeout(std::time::Duration::from_secs(20))
            .map_err(db_error)?;
        let transaction = connection.transaction().map_err(db_error)?;
        let value = body(&transaction).map_err(db_error)?;
        transaction.commit().map_err(db_error)?;
        Ok(value)
    }

    /// Python `init_db`: create/migrate the schema, normalize old empty
    /// mailbox failures to `healthy`, and fail jobs interrupted by a restart.
    pub fn init_db(&self) -> Result<(), MailError> {
        if let Some(parent) = self.db_path.parent() {
            std::fs::create_dir_all(parent).map_err(db_error)?;
        }
        let now = utcnow();
        self.connection(|conn| {
            conn.execute(SCHEMA, [])?;
            let columns: Vec<String> = conn
                .prepare("PRAGMA table_info(jobs)")?
                .query_map([], |row| row.get::<_, String>("name"))?
                .collect::<rusqlite::Result<_>>()?;
            for (name, declaration) in MIGRATED_COLUMNS {
                if !columns.iter().any(|column| column == name) {
                    conn.execute(&format!("ALTER TABLE jobs ADD COLUMN {name} {declaration}"), [])?;
                }
            }
            conn.execute(
                "UPDATE jobs SET status='healthy', stage='healthy', progress=100,\
                 log=REPLACE(log, 'Audit failed: ' || error_message, 'Audit finished; inbox is healthy. ' || error_message),\
                 error_message=NULL \
                 WHERE source_kind='mailbox' AND status='failed' AND downloaded_messages=0 AND total_messages=0 \
                 AND error_message='No INBOX messages were found in the last ' || COALESCE(days,7) || ' day(s).'",
                [],
            )?;
            conn.execute(
                "UPDATE jobs SET status='failed', stage='interrupted', completed_at=?1,\
                 error_message='Application stopped before the audit finished',\
                 log=log || 'Audit interrupted by application restart.\n' \
                 WHERE status IN ('queued', 'in_progress')",
                params![now],
            )?;
            Ok(())
        })
    }

    /// Python `create_job`. A mailbox job without an explicit window gets
    /// `[created_at - days, created_at)` (`days or 7`).
    pub fn create_job(&self, job: NewJob) -> Result<JobRecord, MailError> {
        let now = Utc::now();
        let created_at = isoformat(&now);
        let (mut window_start, mut window_end) = (job.window_start.clone(), job.window_end.clone());
        if job.source_kind == "mailbox" && window_start.is_none() && window_end.is_none() {
            let days = job.days.filter(|days| *days != 0).unwrap_or(7);
            window_end = Some(created_at.clone());
            window_start = Some(isoformat(&(now - Duration::days(days))));
        }
        self.connection(|conn| {
            conn.execute(
                "INSERT INTO jobs (id,filename,file_size,temp_dir,created_at,source_kind,account_email,days,\
                 run_kind,scheduled_for,window_start,window_end) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)",
                params![
                    job.id,
                    job.filename,
                    job.file_size,
                    job.temp_dir,
                    created_at,
                    job.source_kind,
                    job.account_email,
                    job.days,
                    job.run_kind,
                    job.scheduled_for,
                    window_start,
                    window_end,
                ],
            )?;
            conn.query_row("SELECT * FROM jobs WHERE id=?1", [&job.id], JobRecord::from_row)
        })
    }

    pub fn get_job(&self, job_id: &str) -> Result<Option<JobRecord>, MailError> {
        self.connection(|conn| {
            conn.query_row(
                "SELECT * FROM jobs WHERE id=?1",
                [job_id],
                JobRecord::from_row,
            )
            .optional()
        })
    }

    /// Every job, newest first.
    pub fn list_jobs(&self) -> Result<Vec<JobRecord>, MailError> {
        self.connection(|conn| {
            conn.prepare("SELECT * FROM jobs ORDER BY created_at DESC")?
                .query_map([], JobRecord::from_row)?
                .collect()
        })
    }

    /// Python `update_job(job_id, active_only=..., **fields)`. Returns whether
    /// a row changed; with `active_only` only queued/in-progress jobs change.
    pub fn update_job(
        &self,
        job_id: &str,
        fields: &[JobField],
        active_only: bool,
    ) -> Result<bool, MailError> {
        if fields.is_empty() {
            return Ok(false);
        }
        let clause = fields
            .iter()
            .map(|field| format!("{}=?", field.column()))
            .collect::<Vec<_>>()
            .join(", ");
        let condition = if active_only {
            " AND status IN ('queued','in_progress')"
        } else {
            ""
        };
        let sql = format!("UPDATE jobs SET {clause} WHERE id=?{condition}");
        let mut values: Vec<SqlValue> = fields.iter().map(JobField::value).collect();
        values.push(SqlValue::Text(job_id.to_string()));
        self.connection(|conn| {
            conn.execute(&sql, rusqlite::params_from_iter(values.iter()))
                .map(|count| count > 0)
        })
    }

    /// Python `append_log`: append one line (trailing newlines normalized) and
    /// keep the last `log_char_cap` characters. With `active_only`, terminal
    /// jobs are left untouched.
    pub fn append_log(&self, job_id: &str, line: &str, active_only: bool) -> Result<(), MailError> {
        let cap = self.log_char_cap;
        self.connection(|conn| {
            let row: Option<(Option<String>, String)> = conn
                .query_row("SELECT log,status FROM jobs WHERE id=?1", [job_id], |row| {
                    Ok((row.get(0)?, row.get(1)?))
                })
                .optional()?;
            let Some((log, status)) = row else {
                return Ok(());
            };
            if active_only && TERMINAL_STATUSES.contains(&status.as_str()) {
                return Ok(());
            }
            let mut log = log.unwrap_or_default();
            log.push_str(line.trim_end_matches('\n'));
            log.push('\n');
            let log = keep_last_chars(&log, cap);
            conn.execute("UPDATE jobs SET log=?1 WHERE id=?2", params![log, job_id])?;
            Ok(())
        })
    }
}

/// Python `text[-cap:]` (by characters).
fn keep_last_chars(text: &str, cap: usize) -> String {
    let count = text.chars().count();
    if count <= cap {
        return text.to_string();
    }
    text.chars().skip(count - cap).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn isoformat_matches_python() {
        let value = Utc.with_ymd_and_hms(2026, 10, 17, 22, 0, 0).unwrap();
        assert_eq!(isoformat(&value), "2026-10-17T22:00:00+00:00");
        let value = value + Duration::microseconds(1500);
        assert_eq!(isoformat(&value), "2026-10-17T22:00:00.001500+00:00");
        let offset = FixedOffset::west_opt(4 * 3600).unwrap();
        let local = value.with_timezone(&offset);
        assert_eq!(isoformat(&local), "2026-10-17T18:00:00.001500-04:00");
    }

    #[test]
    fn fromisoformat_variants() {
        let expected = Utc.with_ymd_and_hms(2026, 10, 10, 22, 0, 0).unwrap();
        for text in [
            "2026-10-10T22:00:00+00:00",
            "2026-10-10 22:00:00Z",
            "2026-10-10T18:00:00-04:00",
            "2026-10-11T12:00:00+1400",
            "2026-10-10T22:00+00:00",
            "2026-10-10T22:00:00.000000+00:00",
        ] {
            assert_eq!(parse_aware_utc(text), Some(expected), "{text}");
        }
        assert!(matches!(
            parse_isoformat("2026-10-10T22:00:00"),
            Some(IsoDateTime::Naive(_))
        ));
        assert!(matches!(
            parse_isoformat("2026-10-10"),
            Some(IsoDateTime::Naive(_))
        ));
        assert_eq!(parse_aware_utc("2026-10-10T22:00:00"), None);
        for invalid in [
            "invalid",
            "",
            "2026-13-01T00:00:00+00:00",
            "2026-10-10T25:00:00+00:00",
        ] {
            assert_eq!(parse_isoformat(invalid), None, "{invalid}");
        }
        let micro = parse_aware_utc("2026-10-10T22:00:00.5+00:00").unwrap();
        assert_eq!(micro.nanosecond(), 500_000_000);
    }

    #[test]
    fn keep_last_chars_counts_characters() {
        assert_eq!(keep_last_chars("aéb\n", 3), "éb\n");
        assert_eq!(keep_last_chars("ab", 3), "ab");
    }
}
