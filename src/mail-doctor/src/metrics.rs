//! Durable metrics for complete audits, independent of temporary audit files
//! (port of `backend/app/doctor/metrics.py` and the validation in
//! `metrics_router.py`).
//!
//! Every point is one successful audit, including ad hoc audits and healthy
//! empty mailboxes. An unavailable or malformed legacy artifact is
//! deliberately omitted: an absent measurement must never look like a
//! measured zero.

use crate::db::{JobRecord, JobStore};
use mail_core::schemas::{validation_error, ValidationIssue};
use mail_core::MailError;
use regex::Regex;
use rusqlite::{params, params_from_iter, Row};
use serde::Serialize;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

const SCHEMA: [&str; 3] = [
    "
    CREATE TABLE IF NOT EXISTS email_metric_runs (
      id TEXT PRIMARY KEY,
      created_at TEXT NOT NULL, completed_at TEXT,
      account_email TEXT, source_kind TEXT NOT NULL,
      run_kind TEXT NOT NULL CHECK (run_kind IN ('scheduled', 'adhoc')),
      scheduled_for TEXT, window_start TEXT, window_end TEXT, days INTEGER,
      total_messages INTEGER NOT NULL CHECK (total_messages >= 0),
      total_size_bytes INTEGER NOT NULL CHECK (total_size_bytes >= 0)
    )
    ",
    "
    CREATE TABLE IF NOT EXISTS email_metric_domains (
      run_id TEXT NOT NULL REFERENCES email_metric_runs(id) ON DELETE CASCADE,
      domain TEXT NOT NULL,
      message_count INTEGER NOT NULL CHECK (message_count >= 0),
      size_bytes INTEGER NOT NULL CHECK (size_bytes >= 0),
      PRIMARY KEY (run_id, domain)
    )
    ",
    "CREATE INDEX IF NOT EXISTS email_metric_runs_account ON email_metric_runs(account_email)",
];

static DOMAIN_LABEL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$").unwrap());

/// Bucket for missing or invalid sender domains.
pub const UNKNOWN_DOMAIN: &str = "(unknown)";
const MAX_SQLITE_INTEGER: u64 = i64::MAX as u64;
/// `Query(max_length=320)` on `/api/email-metrics?account=`.
pub const MAX_ACCOUNT_QUERY_CHARS: usize = 320;

/// Python `normalize_domain`: keep actual sender hosts distinct (aliases and
/// registered domains differ); invalid values become `(unknown)`.
pub fn normalize_domain(value: Option<&str>) -> String {
    let Some(value) = value else {
        return UNKNOWN_DOMAIN.into();
    };
    let value = value.trim().trim_end_matches('.').to_lowercase();
    if value.is_empty() {
        return UNKNOWN_DOMAIN.into();
    }
    let value = if value.is_ascii() {
        value
    } else {
        match idna2003_to_ascii(&value) {
            Some(ascii) => ascii,
            None => return UNKNOWN_DOMAIN.into(),
        }
    };
    if value.is_empty()
        || value.len() > 253
        || value.split('.').any(|label| !DOMAIN_LABEL.is_match(label))
    {
        return UNKNOWN_DOMAIN.into();
    }
    value
}

/// Python's `str.encode("idna")` (IDNA 2003) for a non-ASCII name: split on
/// the IDNA dots, keep ASCII labels verbatim and convert every other label
/// on its own. IDNA 2003 maps characters that UTS #46 non-transitional
/// processing keeps (`ß` → `ss`, final `ς` → `σ`, and RFC 3454 table B.1
/// "mapped to nothing" such as ZWJ/ZWNJ/soft hyphen), so those are applied
/// before the `idna` crate converts the label. `None` for Python's
/// `UnicodeError`.
fn idna2003_to_ascii(value: &str) -> Option<String> {
    fn mapped_to_nothing(c: char) -> bool {
        matches!(
            c,
            '\u{ad}'
                | '\u{34f}'
                | '\u{1806}'
                | '\u{180b}'..='\u{180d}'
                | '\u{200b}'..='\u{200d}'
                | '\u{2060}'
                | '\u{fe00}'..='\u{fe0f}'
                | '\u{feff}'
        )
    }
    let mut labels = Vec::new();
    for label in value.split(['.', '\u{3002}', '\u{ff0e}', '\u{ff61}']) {
        let ascii = if label.is_ascii() {
            label.to_owned()
        } else {
            let mut prepared = String::with_capacity(label.len());
            for c in label.chars().filter(|c| !mapped_to_nothing(*c)) {
                match c {
                    'ß' => prepared.push_str("ss"),
                    'ς' => prepared.push('σ'),
                    other => prepared.push(other),
                }
            }
            let converted = idna::domain_to_ascii(&prepared).ok()?;
            if converted.contains('.') {
                return None;
            }
            converted
        };
        // ToASCII: "label empty or too long".
        if ascii.is_empty() || ascii.len() >= 64 {
            return None;
        }
        labels.push(ascii);
    }
    Some(labels.join("."))
}

/// One per-domain aggregate of a run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DomainMetric {
    pub domain: String,
    pub message_count: i64,
    pub size_bytes: i64,
}

/// One stored audit run with its domains (`email_metric_runs` row + `domains`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MetricRun {
    pub id: String,
    pub created_at: String,
    pub completed_at: Option<String>,
    pub account_email: Option<String>,
    pub source_kind: String,
    pub run_kind: String,
    pub scheduled_for: Option<String>,
    pub window_start: Option<String>,
    pub window_end: Option<String>,
    pub days: Option<i64>,
    pub total_messages: i64,
    pub total_size_bytes: i64,
    pub domains: Vec<DomainMetric>,
}

impl MetricRun {
    fn from_row(row: &Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            id: row.get("id")?,
            created_at: row.get("created_at")?,
            completed_at: row.get("completed_at")?,
            account_email: row.get("account_email")?,
            source_kind: row.get("source_kind")?,
            run_kind: row.get("run_kind")?,
            scheduled_for: row.get("scheduled_for")?,
            window_start: row.get("window_start")?,
            window_end: row.get("window_end")?,
            days: row.get("days")?,
            total_messages: row.get("total_messages")?,
            total_size_bytes: row.get("total_size_bytes")?,
            domains: Vec::new(),
        })
    }
}

/// `GET /api/email-metrics` response body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MetricsResponse {
    pub runs: Vec<MetricRun>,
    pub domains: Vec<String>,
    pub accounts: Vec<String>,
}

/// Python truthiness of a JSON value (`x or y`).
fn truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(flag) => *flag,
        Value::Number(number) => number.as_f64() != Some(0.0),
        Value::String(text) => !text.is_empty(),
        Value::Array(items) => !items.is_empty(),
        Value::Object(map) => !map.is_empty(),
    }
}

type Measurement = (i64, i64, Vec<DomainMetric>);

/// Python `_message_totals`: count messages and bytes per actual sender host
/// from the extraction output (or the grouped output as a fallback).
fn message_totals(directory: &Path) -> Option<Measurement> {
    // Prefer extraction output so a sender-group alias cannot rewrite a host.
    let outputs = directory.join("outputs");
    let path = [
        outputs.join("messages.jsonl"),
        outputs.join("messages_grouped.jsonl"),
    ]
    .into_iter()
    .find(|candidate| candidate.is_file())?;
    let bytes = std::fs::read(path).ok()?;
    let bytes = bytes.strip_prefix(b"\xef\xbb\xbf").unwrap_or(&bytes);
    let text = std::str::from_utf8(bytes).ok()?;
    let mut totals: BTreeMap<String, (u64, u64)> = BTreeMap::new();
    let (mut count, mut size) = (0u64, 0u64);
    for line in text.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let record: Value = serde_json::from_str(line).ok()?;
        let record = record.as_object()?;
        // Do not quietly substitute a zero for missing byte measurements.
        let record_size = match record.get("size_bytes") {
            Some(Value::Number(number)) => number.as_u64().filter(|n| *n <= MAX_SQLITE_INTEGER)?,
            _ => return None,
        };
        let domain_value = record
            .get("from_domain")
            .filter(|value| truthy(value))
            .or_else(|| record.get("sender_domain"));
        let domain = normalize_domain(domain_value.and_then(Value::as_str));
        let entry = totals.entry(domain).or_default();
        entry.0 += 1;
        entry.1 = entry.1.checked_add(record_size)?;
        count += 1;
        size = size.checked_add(record_size)?;
        if size > MAX_SQLITE_INTEGER {
            return None;
        }
    }
    // The pipeline cannot successfully complete with an empty extraction.
    if count == 0 {
        return None;
    }
    let domains = totals
        .into_iter()
        .map(|(domain, (messages, bytes))| DomainMetric {
            domain,
            message_count: messages as i64,
            size_bytes: bytes as i64,
        })
        .collect();
    Some((count as i64, size as i64, domains))
}

/// Python `MetricStore` (shares the job database).
#[derive(Debug, Clone)]
pub struct MetricStore {
    db: JobStore,
}

impl MetricStore {
    pub fn new(db: JobStore) -> Self {
        Self { db }
    }

    pub fn init_db(&self) -> Result<(), MailError> {
        self.db.connection(|conn| {
            for statement in SCHEMA {
                conn.execute(statement, [])?;
            }
            Ok(())
        })
    }

    /// Python `capture`: atomically record one complete audit; repeated
    /// captures are harmless. Returns whether a new snapshot was stored.
    /// Partial and failed audits, or legacy successful audits whose
    /// measurements are gone, return `false`.
    pub fn capture(&self, job: &JobRecord, directory: &Path) -> Result<bool, MailError> {
        if !matches!(job.status.as_str(), "completed" | "healthy")
            || job.id.is_empty()
            || job.created_at.is_empty()
        {
            return Ok(false);
        }
        let exists = self.db.connection(|conn| {
            conn.prepare("SELECT 1 FROM email_metric_runs WHERE id=?1")?
                .exists([&job.id])
        })?;
        if exists {
            return Ok(false);
        }
        let measured = if job.status == "healthy" {
            // Healthy is the explicit zero-message terminal state, not a
            // missing report inferred to mean there were no messages.
            if job.total_messages != Some(0) || job.downloaded_messages != 0 {
                return Ok(false);
            }
            (0, 0, Vec::new())
        } else {
            match message_totals(directory) {
                Some(measured) => measured,
                None => return Ok(false),
            }
        };
        let (count, size, domains) = measured;
        if job.source_kind == "mailbox" {
            if let Some(expected) = job.total_messages {
                // Older downloaders could finish after skipping an unreadable
                // UID. Do not plot partial data as a complete measurement.
                if expected < 0 || job.downloaded_messages != expected || count != expected {
                    return Ok(false);
                }
            }
        }
        let account = job
            .account_email
            .as_deref()
            .map(str::trim)
            .filter(|account| !account.is_empty())
            .map(str::to_lowercase);
        let days = job.days.filter(|days| *days > 0);
        let source_kind = if job.source_kind.is_empty() {
            "upload"
        } else {
            job.source_kind.as_str()
        };
        let run_kind = if job.run_kind == "scheduled" {
            "scheduled"
        } else {
            "adhoc"
        };
        self.db.connection(|conn| {
            let inserted = conn.execute(
                "INSERT OR IGNORE INTO email_metric_runs \
                 (id,created_at,completed_at,account_email,source_kind,run_kind,scheduled_for,window_start,window_end,days,total_messages,total_size_bytes) \
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)",
                params![
                    job.id,
                    job.created_at,
                    job.completed_at,
                    account,
                    source_kind,
                    run_kind,
                    job.scheduled_for,
                    job.window_start,
                    job.window_end,
                    days,
                    count,
                    size,
                ],
            )?;
            if inserted == 0 {
                return Ok(false);
            }
            let mut statement = conn.prepare(
                "INSERT INTO email_metric_domains (run_id,domain,message_count,size_bytes) VALUES (?1,?2,?3,?4)",
            )?;
            for row in &domains {
                statement.execute(params![job.id, row.domain, row.message_count, row.size_bytes])?;
            }
            Ok(true)
        })
    }

    /// Python `backfill`: import retained successful legacy artifacts without
    /// inventing data. `job_dir_for` returns `None` for an invalid job ID.
    pub fn backfill<'a>(
        &self,
        jobs: impl IntoIterator<Item = &'a JobRecord>,
        job_dir_for: impl Fn(&str) -> Option<PathBuf>,
    ) -> Result<usize, MailError> {
        let mut inserted = 0;
        for job in jobs {
            if !matches!(job.status.as_str(), "completed" | "healthy") {
                continue;
            }
            let Some(directory) = job_dir_for(&job.id) else {
                continue;
            };
            if self.capture(job, &directory)? {
                inserted += 1;
            }
        }
        Ok(inserted)
    }

    /// Python `list_metrics(account)`: runs in chronological order with their
    /// domains, the union of domains, and every known account.
    pub fn list_metrics(&self, account: Option<&str>) -> Result<MetricsResponse, MailError> {
        let account = account
            .map(str::trim)
            .filter(|account| !account.is_empty())
            .map(str::to_lowercase);
        self.db.connection(|conn| {
            let accounts: Vec<String> = conn
                .prepare(
                    "SELECT DISTINCT account_email FROM email_metric_runs \
                     WHERE account_email IS NOT NULL ORDER BY account_email",
                )?
                .query_map([], |row| row.get(0))?
                .collect::<rusqlite::Result<_>>()?;
            let filter: Vec<&str> = account.as_deref().into_iter().collect();
            let condition = if account.is_some() {
                " WHERE account_email=?1"
            } else {
                ""
            };
            let mut runs: Vec<MetricRun> = conn
                .prepare(&format!(
                    "SELECT * FROM email_metric_runs{condition} \
                     ORDER BY julianday(COALESCE(completed_at,created_at)),id"
                ))?
                .query_map(params_from_iter(filter.iter()), MetricRun::from_row)?
                .collect::<rusqlite::Result<_>>()?;
            let index: HashMap<String, usize> = runs
                .iter()
                .enumerate()
                .map(|(position, run)| (run.id.clone(), position))
                .collect();
            // Join the account filter in SQL rather than using a potentially
            // unbounded IN list of job IDs.
            let domain_condition = if account.is_some() {
                " WHERE runs.account_email=?1"
            } else {
                ""
            };
            let mut domains = BTreeSet::new();
            let mut statement = conn.prepare(&format!(
                "SELECT domains.* FROM email_metric_domains domains \
                 JOIN email_metric_runs runs ON runs.id=domains.run_id{domain_condition} \
                 ORDER BY domains.domain"
            ))?;
            let rows = statement.query_map(params_from_iter(filter.iter()), |row| {
                Ok((
                    row.get::<_, String>("run_id")?,
                    DomainMetric {
                        domain: row.get("domain")?,
                        message_count: row.get("message_count")?,
                        size_bytes: row.get("size_bytes")?,
                    },
                ))
            })?;
            for row in rows {
                let (run_id, metric) = row?;
                domains.insert(metric.domain.clone());
                if let Some(position) = index.get(&run_id) {
                    runs[*position].domains.push(metric);
                }
            }
            Ok(MetricsResponse {
                runs,
                domains: domains.into_iter().collect(),
                accounts,
            })
        })
    }
}

/// Validation of `GET /api/email-metrics?account=` (`metrics_router.py`):
/// more than 320 characters is FastAPI's 422; otherwise the value is
/// trimmed and lowercased, and a non-empty value must look like one address
/// (400 `Enter a valid account email address`).
pub fn validate_account_query(account: Option<&str>) -> Result<Option<String>, MailError> {
    let Some(raw) = account else {
        return Ok(None);
    };
    if raw.chars().count() > MAX_ACCOUNT_QUERY_CHARS {
        let input = Value::String(raw.to_string());
        return Err(validation_error(&[ValidationIssue::new(
            "string_too_long",
            format!("String should have at most {MAX_ACCOUNT_QUERY_CHARS} characters"),
            &input,
        )
        .with_ctx(json!({"max_length": MAX_ACCOUNT_QUERY_CHARS}))
        .at(&[json!("query"), json!("account")])]));
    }
    let account = raw.trim().to_lowercase();
    if !account.is_empty()
        && (account.matches('@').count() != 1
            || account
                .chars()
                .any(|c| c.is_whitespace() || (c as u32) < 32))
    {
        return Err(MailError::bad_request(
            "Enter a valid account email address",
        ));
    }
    Ok(Some(account))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domains_are_normalized_like_python() {
        assert_eq!(
            normalize_domain(Some("Mail.Example.COM.")),
            "mail.example.com"
        );
        assert_eq!(
            normalize_domain(Some("BÜCHER.example")),
            "xn--bcher-kva.example"
        );
        assert_eq!(normalize_domain(Some("")), UNKNOWN_DOMAIN);
        assert_eq!(normalize_domain(None), UNKNOWN_DOMAIN);
        assert_eq!(normalize_domain(Some("bad_domain.com")), UNKNOWN_DOMAIN);
        assert_eq!(normalize_domain(Some("-x.com")), UNKNOWN_DOMAIN);
        assert_eq!(normalize_domain(Some(&"a".repeat(64))), UNKNOWN_DOMAIN);
    }

    #[test]
    fn non_ascii_domains_follow_pythons_idna_2003_codec() {
        // Expected values from CPython's `value.encode("idna")`.
        for (input, expected) in [
            ("straße.de", "strasse.de"),
            ("faß.de", "fass.de"),
            ("ΣΊΣΥΦΟΣ.gr", "xn--kxa6akbbkh.gr"),
            ("a\u{200d}b.example", "ab.example"),
            ("a\u{200c}b.example", "ab.example"),
            ("a\u{ad}b.example", "ab.example"),
            ("a\u{200b}b.example", "ab.example"),
            ("Bücher.example", "xn--bcher-kva.example"),
            ("ＢＵＣＨＥＲ。example", "bucher.example"),
            ("😀.example", "xn--e28h.example"),
            ("xn--zz.bücher.de", "xn--zz.xn--bcher-kva.de"),
            ("\u{644}\u{627}.example", "xn--mgb1d.example"),
            ("\u{fb01}.example", "fi.example"),
        ] {
            assert_eq!(normalize_domain(Some(input)), expected, "{input:?}");
        }
        assert_eq!(normalize_domain(Some("bücher..de")), UNKNOWN_DOMAIN);
        assert_eq!(normalize_domain(Some("bücher.de\u{3002}")), UNKNOWN_DOMAIN);
    }

    #[test]
    fn account_query_validation() {
        assert_eq!(validate_account_query(None).unwrap(), None);
        assert_eq!(
            validate_account_query(Some(" FIRST@EXAMPLE.COM ")).unwrap(),
            Some("first@example.com".into())
        );
        assert_eq!(
            validate_account_query(Some("  ")).unwrap(),
            Some(String::new())
        );
        assert_eq!(
            validate_account_query(Some("invalid address"))
                .unwrap_err()
                .status(),
            400
        );
        assert_eq!(
            validate_account_query(Some("a@b@c")).unwrap_err().status(),
            400
        );
        assert_eq!(
            validate_account_query(Some(&"a".repeat(321)))
                .unwrap_err()
                .status(),
            422
        );
    }
}
