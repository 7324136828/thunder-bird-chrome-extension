//! Inbox Doctor request / response models (port of
//! `backend/app/doctor/schemas/job.py`).
//!
//! Request bodies implement [`mail_core::schemas::RequestModel`], so a
//! backend handler can call `PasteJobIn::from_body(&bytes)` and get the same
//! FastAPI/pydantic 422 error bodies as the original.

use crate::db::JobRecord;
use mail_core::schemas::{parse_python_int, RequestModel, Validated, ValidationIssue};
use serde::Serialize;
use serde_json::{json, Map, Value};
use std::fmt;

/// Maximum pasted content length in characters (`200 * 1024 * 1024`).
pub const MAX_PASTE_CHARS: usize = 200 * 1024 * 1024;
/// Incoming security choices accepted by `MailCredentialsIn`.
pub const INCOMING_PROTOCOL_PATTERN: &str = r"^(SSL/TLS|STARTTLS|NONE)$";

/// `JobOut`: the JSON shape of one job in every `/api/jobs` response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct JobOut {
    pub id: String,
    pub filename: String,
    pub file_size: i64,
    pub status: String,
    pub progress: i64,
    pub stage: Option<String>,
    pub log: String,
    pub error_message: Option<String>,
    pub created_at: String,
    pub completed_at: Option<String>,
    pub output_files: Vec<String>,
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

impl JobOut {
    /// `to_out(job)` without output files.
    pub fn from_record(job: &JobRecord) -> Self {
        Self::with_files(job, Vec::new())
    }

    /// `to_out(job, include_files=True)`: the caller lists the files of a
    /// completed job (`temp_manager.list_output_files`).
    pub fn with_files(job: &JobRecord, output_files: Vec<String>) -> Self {
        Self {
            id: job.id.clone(),
            filename: job.filename.clone(),
            file_size: job.file_size,
            status: job.status.clone(),
            progress: job.progress,
            stage: job.stage.clone(),
            log: job.log.clone(),
            error_message: job.error_message.clone(),
            created_at: job.created_at.clone(),
            completed_at: job.completed_at.clone(),
            output_files,
            source_kind: job.source_kind.clone(),
            account_email: job.account_email.clone(),
            days: job.days,
            downloaded_messages: job.downloaded_messages,
            total_messages: job.total_messages,
            snapshot_available: job.snapshot_available,
            snapshot_at: job.snapshot_at.clone(),
            run_kind: job.run_kind.clone(),
            scheduled_for: job.scheduled_for.clone(),
            window_start: job.window_start.clone(),
            window_end: job.window_end.clone(),
        }
    }
}

// ---------------------------------------------------------------------------
// Request models
// ---------------------------------------------------------------------------

/// `PasteJobIn` (`POST /api/jobs/paste`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasteJobIn {
    pub content: String,
    pub filename: Option<String>,
}

impl RequestModel for PasteJobIn {
    fn validate(value: &Value) -> Validated<Self> {
        let mut fields = Fields::new(value)?;
        let content = fields.required("content", |v| text(v, 1, Some(MAX_PASTE_CHARS)));
        let filename = fields.optional("filename", None, |v| {
            nullable(v, |v| text(v, 0, Some(1000)))
        });
        fields.finish()?;
        Ok(Self {
            content: content.unwrap(),
            filename: filename.unwrap(),
        })
    }
}

/// `MailCredentialsIn` (`POST /api/mail/jobs`). The password is memory-only
/// and never printed.
#[derive(Clone, PartialEq, Eq)]
pub struct MailCredentialsIn {
    pub email: String,
    pub password: String,
    pub days: i64,
    pub imap_server: Option<String>,
    pub imap_port: Option<u16>,
    pub use_ssl: Option<bool>,
    pub use_app_password: bool,
    pub incoming_protocol: Option<String>,
}

impl fmt::Debug for MailCredentialsIn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MailCredentialsIn")
            .field("email", &self.email)
            .field("password", &"<redacted>")
            .field("days", &self.days)
            .field("imap_server", &self.imap_server)
            .field("imap_port", &self.imap_port)
            .field("use_ssl", &self.use_ssl)
            .field("use_app_password", &self.use_app_password)
            .field("incoming_protocol", &self.incoming_protocol)
            .finish()
    }
}

impl RequestModel for MailCredentialsIn {
    fn validate(value: &Value) -> Validated<Self> {
        let mut fields = Fields::new(value)?;
        let email = fields.required("email", |v| text(v, 3, Some(320)));
        let password = fields.required("password", |v| text(v, 1, Some(4096)));
        let days = fields.optional("days", 7, days);
        let imap_server = fields.optional("imap_server", None, |v| {
            nullable(v, |v| text(v, 0, Some(253)))
        });
        let imap_port = fields.optional("imap_port", None, |v| nullable(v, port));
        let use_ssl = fields.optional("use_ssl", None, |v| nullable(v, lax_bool));
        let use_app_password = fields.optional("use_app_password", false, lax_bool);
        let incoming_protocol = fields.optional("incoming_protocol", None, |v| {
            nullable(v, incoming_protocol)
        });
        fields.finish()?;
        Ok(Self {
            email: email.unwrap(),
            password: password.unwrap(),
            days: days.unwrap(),
            imap_server: imap_server.unwrap(),
            imap_port: imap_port.unwrap(),
            use_ssl: use_ssl.unwrap(),
            use_app_password: use_app_password.unwrap(),
            incoming_protocol: incoming_protocol.unwrap(),
        })
    }
}

/// `AccountJobIn` (`POST /api/mail/jobs/account`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountJobIn {
    pub account: String,
    pub days: i64,
}

impl RequestModel for AccountJobIn {
    fn validate(value: &Value) -> Validated<Self> {
        let mut fields = Fields::new(value)?;
        let account = fields.required("account", |v| text(v, 3, Some(320)));
        let days = fields.optional("days", 7, days);
        fields.finish()?;
        Ok(Self {
            account: account.unwrap(),
            days: days.unwrap(),
        })
    }
}

/// `OAuthStartIn` (`POST /api/mail/oauth/start`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OAuthStartIn {
    pub provider: String,
    pub email: String,
    pub days: i64,
}

impl RequestModel for OAuthStartIn {
    fn validate(value: &Value) -> Validated<Self> {
        let mut fields = Fields::new(value)?;
        let provider = fields.required("provider", |v| text(v, 0, None));
        let email = fields.required("email", |v| text(v, 3, Some(320)));
        let days = fields.optional("days", 7, days);
        fields.finish()?;
        Ok(Self {
            provider: provider.unwrap(),
            email: email.unwrap(),
            days: days.unwrap(),
        })
    }
}

// ---------------------------------------------------------------------------
// Validation primitives (pydantic v2 lax-mode messages)
// ---------------------------------------------------------------------------

fn fail<T>(issue: ValidationIssue) -> Validated<T> {
    Err(vec![issue])
}

fn plural(count: usize, word: &str) -> String {
    if count == 1 {
        format!("{count} {word}")
    } else {
        format!("{count} {word}s")
    }
}

/// `str` with `min_length` / `max_length` counted in characters.
fn text(value: &Value, min: usize, max: Option<usize>) -> Validated<String> {
    let Value::String(text) = value else {
        return fail(ValidationIssue::new(
            "string_type",
            "Input should be a valid string",
            value,
        ));
    };
    let length = text.chars().count();
    if length < min {
        return fail(
            ValidationIssue::new(
                "string_too_short",
                format!("String should have at least {}", plural(min, "character")),
                value,
            )
            .with_ctx(json!({"min_length": min})),
        );
    }
    if let Some(max) = max {
        if length > max {
            return fail(
                ValidationIssue::new(
                    "string_too_long",
                    format!("String should have at most {}", plural(max, "character")),
                    value,
                )
                .with_ctx(json!({"max_length": max})),
            );
        }
    }
    Ok(text.clone())
}

fn incoming_protocol(value: &Value) -> Validated<String> {
    let protocol = text(value, 0, None)?;
    if !matches!(protocol.as_str(), "SSL/TLS" | "STARTTLS" | "NONE") {
        return fail(
            ValidationIssue::new(
                "string_pattern_mismatch",
                format!("String should match pattern '{INCOMING_PROTOCOL_PATTERN}'"),
                value,
            )
            .with_ctx(json!({"pattern": INCOMING_PROTOCOL_PATTERN})),
        );
    }
    Ok(protocol)
}

/// Lax `int`: integers, bools, whole floats and numeric strings.
fn lax_int(value: &Value) -> Validated<i128> {
    let int_type = || ValidationIssue::new("int_type", "Input should be a valid integer", value);
    match value {
        Value::Bool(flag) => Ok(i128::from(*flag)),
        Value::Number(number) => {
            if let Some(integer) = number.as_i64() {
                return Ok(i128::from(integer));
            }
            if let Some(integer) = number.as_u64() {
                return Ok(i128::from(integer));
            }
            let float = number.as_f64().unwrap_or(f64::NAN);
            if float.fract() != 0.0 {
                return fail(ValidationIssue::new(
                    "int_from_float",
                    "Input should be a valid integer, got a number with a fractional part",
                    value,
                ));
            }
            Ok(float as i128)
        }
        Value::String(text) => {
            let trimmed = text.trim();
            let whole = trimmed
                .split_once('.')
                .filter(|(_, fraction)| !fraction.is_empty() && fraction.chars().all(|c| c == '0'))
                .map_or(trimmed, |(integer, _)| integer);
            parse_python_int(whole).ok_or_else(|| {
                vec![ValidationIssue::new(
                    "int_parsing",
                    "Input should be a valid integer, unable to parse string as an integer",
                    value,
                )]
            })
        }
        _ => fail(int_type()),
    }
}

fn int_bounds(number: i128, value: &Value, ge: i128, le: i128) -> Validated<i128> {
    if number < ge {
        return fail(
            ValidationIssue::new(
                "greater_than_equal",
                format!("Input should be greater than or equal to {ge}"),
                value,
            )
            .with_ctx(json!({"ge": ge as i64})),
        );
    }
    if number > le {
        return fail(
            ValidationIssue::new(
                "less_than_equal",
                format!("Input should be less than or equal to {le}"),
                value,
            )
            .with_ctx(json!({"le": le as i64})),
        );
    }
    Ok(number)
}

/// `days: int = Field(default=7, ge=1, le=3650)`.
fn days(value: &Value) -> Validated<i64> {
    let number = lax_int(value)?;
    int_bounds(number, value, 1, 3650).map(|n| n as i64)
}

/// `int | None = Field(ge=1, le=65535)`.
fn port(value: &Value) -> Validated<u16> {
    let number = lax_int(value)?;
    int_bounds(number, value, 1, 65535).map(|n| n as u16)
}

/// Lax `bool`: also `0`/`1` and the usual case-insensitive words.
fn lax_bool(value: &Value) -> Validated<bool> {
    let parsing = || {
        ValidationIssue::new(
            "bool_parsing",
            "Input should be a valid boolean, unable to interpret input",
            value,
        )
    };
    let bool_type = || ValidationIssue::new("bool_type", "Input should be a valid boolean", value);
    match value {
        Value::Bool(flag) => Ok(*flag),
        Value::Number(number) => match number.as_f64() {
            Some(0.0) => Ok(false),
            Some(1.0) => Ok(true),
            Some(n) if n.fract() == 0.0 => fail(parsing()),
            _ => fail(bool_type()),
        },
        Value::String(text) => match text.to_lowercase().as_str() {
            "0" | "off" | "f" | "false" | "n" | "no" => Ok(false),
            "1" | "on" | "t" | "true" | "y" | "yes" => Ok(true),
            _ => fail(parsing()),
        },
        _ => fail(bool_type()),
    }
}

fn nullable<T>(
    value: &Value,
    validate: impl FnOnce(&Value) -> Validated<T>,
) -> Validated<Option<T>> {
    if value.is_null() {
        Ok(None)
    } else {
        validate(value).map(Some)
    }
}

/// Field reader over one JSON object (extra keys are ignored, as in pydantic's default).
struct Fields<'a> {
    input: &'a Value,
    object: &'a Map<String, Value>,
    issues: Vec<ValidationIssue>,
}

impl<'a> Fields<'a> {
    fn new(input: &'a Value) -> Validated<Self> {
        match input {
            Value::Object(object) => Ok(Self {
                input,
                object,
                issues: Vec::new(),
            }),
            _ => fail(ValidationIssue::new(
                "model_attributes_type",
                "Input should be a valid dictionary or object to extract fields from",
                input,
            )),
        }
    }

    fn record<T>(&mut self, name: &str, result: Validated<T>) -> Option<T> {
        match result {
            Ok(value) => Some(value),
            Err(issues) => {
                self.issues
                    .extend(issues.into_iter().map(|issue| issue.at(&[json!(name)])));
                None
            }
        }
    }

    fn required<T>(
        &mut self,
        name: &str,
        validate: impl FnOnce(&Value) -> Validated<T>,
    ) -> Option<T> {
        match self.object.get(name) {
            None => {
                self.issues
                    .push(ValidationIssue::missing(self.input).at(&[json!(name)]));
                None
            }
            Some(value) => {
                let result = validate(value);
                self.record(name, result)
            }
        }
    }

    fn optional<T>(
        &mut self,
        name: &str,
        default: T,
        validate: impl FnOnce(&Value) -> Validated<T>,
    ) -> Option<T> {
        match self.object.get(name) {
            None => Some(default),
            Some(value) => {
                let result = validate(value);
                self.record(name, result)
            }
        }
    }

    fn finish(self) -> Validated<()> {
        if self.issues.is_empty() {
            Ok(())
        } else {
            Err(self.issues)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paste_requires_non_empty_content() {
        let error = PasteJobIn::from_json(&json!({"content": ""})).unwrap_err();
        assert_eq!(error.status(), 422);
        let detail = error.detail();
        assert_eq!(detail[0]["type"], "string_too_short");
        assert_eq!(detail[0]["loc"], json!(["body", "content"]));
        let paste = PasteJobIn::from_json(&json!({"content": "x", "filename": null})).unwrap();
        assert_eq!(paste.filename, None);
    }

    #[test]
    fn credentials_defaults_and_limits() {
        let body =
            MailCredentialsIn::from_json(&json!({"email": "a@b.c", "password": "p"})).unwrap();
        assert_eq!(body.days, 7);
        assert!(!body.use_app_password);
        assert!(!format!("{body:?}").contains("\"p\""));
        for (field, value, kind) in [
            ("days", json!(0), "greater_than_equal"),
            ("days", json!(3651), "less_than_equal"),
            ("imap_port", json!(70000), "less_than_equal"),
            ("incoming_protocol", json!("TLS"), "string_pattern_mismatch"),
            ("use_ssl", json!("maybe"), "bool_parsing"),
        ] {
            let mut input = json!({"email": "a@b.c", "password": "p"});
            input[field] = value;
            let error = MailCredentialsIn::from_json(&input).unwrap_err();
            assert_eq!(error.detail()[0]["type"], kind, "{field}");
        }
        let body = MailCredentialsIn::from_json(&json!({
            "email": "a@b.c", "password": "p", "days": "5", "imap_port": 143.0,
            "incoming_protocol": "STARTTLS", "use_ssl": false,
        }))
        .unwrap();
        assert_eq!(
            (body.days, body.imap_port, body.use_ssl),
            (5, Some(143), Some(false))
        );
    }

    #[test]
    fn account_and_oauth_bodies() {
        let error = AccountJobIn::from_json(&json!({"account": "ab"})).unwrap_err();
        assert_eq!(error.detail()[0]["type"], "string_too_short");
        let body = OAuthStartIn::from_json(&json!({"provider": "google", "email": "u@gmail.com"}))
            .unwrap();
        assert_eq!(body.days, 7);
        let error = OAuthStartIn::from_json(&json!({"email": "u@gmail.com"})).unwrap_err();
        assert_eq!(error.detail()[0]["type"], "missing");
    }
}
