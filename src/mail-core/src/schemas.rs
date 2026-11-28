//! Request models for the webmail API (port of `app/mail/schemas.py`).
//!
//! Python declared these as pydantic v2 models that FastAPI validated before
//! a route ran. The Rust port validates a parsed `serde_json::Value` by hand
//! so the exact pydantic semantics are preserved:
//!
//! * lax vs. strict coercion (`Field(strict=True)`): lax ints accept `true`,
//!   whole floats and numeric strings; strict ints accept JSON integers only;
//! * length / range / pattern constraints with pydantic's error types,
//!   messages and `ctx`;
//! * `extra="forbid"` models reject unknown keys;
//! * field validators (`value_error`, `"Value error, ..."`) and model
//!   validators that only run when every field validated;
//! * "fields set" tracking (`model_fields_set` / `exclude_unset`).
//!
//! Failures produce FastAPI's 422 body: `{"detail": [{"type", "loc", "msg",
//! "input", "ctx"?}, ...]}` with locations starting at `"body"`.
//!
//! [`recipient_address`] ports Python's address validation, including a
//! faithful port of the parts of `email._header_value_parser` that
//! `HeaderRegistry()("To", value)` uses (see the `address` module).

use crate::error::{MailError, Result};
use crate::model::{EMAIL_CATEGORIES, MAX_EXPIRATION_DAYS, MAX_SIGNATURE_LENGTH};
use crate::settings::{
    normalize_expiration_days, validate_category_expiration_days, validate_local_ai_model,
    validate_signature,
};
use regex::Regex;
use serde::{Serialize, Serializer};
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::LazyLock;

/// `MAX_MESSAGE_BODY_BYTES`: text + HTML bodies combined.
pub const MAX_MESSAGE_BODY_BYTES: usize = 1024 * 1024;
/// `MAX_SEND_FILES`: attachments + inline images per message.
pub const MAX_SEND_FILES: usize = 20;
/// `MAX_SEND_FILE_BYTES`: per uploaded file.
pub const MAX_SEND_FILE_BYTES: usize = 10 * 1024 * 1024;
/// `MAX_SEND_FILES_BYTES`: all uploaded files combined.
pub const MAX_SEND_FILES_BYTES: usize = 20 * 1024 * 1024;
/// `CONTENT_ID_PATTERN` (full match).
pub const CONTENT_ID_PATTERN: &str = r"[A-Za-z0-9][A-Za-z0-9._@-]{0,199}";
/// Maximum recipients per list and per message.
pub const MAX_RECIPIENTS: usize = 100;
/// Maximum length of one recipient string.
pub const MAX_RECIPIENT_LENGTH: usize = 998;
/// Largest IMAP UID / UIDVALIDITY.
pub const MAX_UID: i128 = 4_294_967_295;
/// `uid_validity` pattern.
pub const UID_VALIDITY_PATTERN: &str = r"^[1-9][0-9]{0,9}$";

/// Incoming mail protocols accepted by the POP3 extension fields.
pub const INCOMING_MAIL_PROTOCOLS: [&str; 2] = ["imap", "pop3"];
const DISPOSITIONS: [&str; 2] = ["attachment", "inline"];

static CONTENT_ID_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(&format!("^(?:{CONTENT_ID_PATTERN})$")).unwrap());
static UID_VALIDITY_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(UID_VALIDITY_PATTERN).unwrap());
static DOMAIN_LABEL_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$").unwrap());
static PYTHON_INT_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[+-]?[0-9]+(?:_[0-9]+)*$").unwrap());
static PYTHON_INT_DECIMAL_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^([+-]?[0-9]+(?:_[0-9]+)*)\.0+$").unwrap());

/// Python `header_safe`: no C0 controls, DEL or surrogates.
pub fn header_safe(value: &str) -> bool {
    !value.chars().any(|c| (c as u32) < 32 || c as u32 == 127)
}

/// Python `int(text)` for decimal text: surrounding whitespace, an optional
/// sign and single underscores between digits are allowed.
pub fn parse_python_int(text: &str) -> Option<i128> {
    let trimmed = text.trim();
    if !PYTHON_INT_RE.is_match(trimmed) {
        return None;
    }
    let digits: String = trimmed.chars().filter(|c| *c != '_').collect();
    // Absurdly long values saturate; every caller applies a bound afterwards.
    digits.parse::<i128>().ok().or_else(|| {
        Some(if digits.starts_with('-') {
            i128::MIN
        } else {
            i128::MAX
        })
    })
}

// ---------------------------------------------------------------------------
// Validation errors (FastAPI / pydantic shape)
// ---------------------------------------------------------------------------

/// One pydantic error entry: `{"type", "loc", "msg", "input", "ctx"?}`.
#[derive(Debug, Clone, PartialEq)]
pub struct ValidationIssue {
    pub type_: String,
    pub loc: Vec<Value>,
    pub msg: String,
    pub input: Value,
    pub ctx: Option<Value>,
}

impl ValidationIssue {
    /// An issue at the current location (an empty `loc`).
    pub fn new(type_: &str, msg: impl Into<String>, input: &Value) -> Self {
        Self {
            type_: type_.into(),
            loc: Vec::new(),
            msg: msg.into(),
            input: input.clone(),
            ctx: None,
        }
    }

    pub fn with_ctx(mut self, ctx: Value) -> Self {
        self.ctx = Some(ctx);
        self
    }

    /// A field/model validator `ValueError`: `"Value error, {message}"`.
    pub fn value_error(message: &str, input: &Value) -> Self {
        Self::new("value_error", format!("Value error, {message}"), input)
            .with_ctx(json!({"error": {}}))
    }

    /// `{"type":"missing","msg":"Field required"}`; `input` is the parent object.
    pub fn missing(input: &Value) -> Self {
        Self::new("missing", "Field required", input)
    }

    /// Prepend location components (e.g. `"body"`, a field name, an index).
    pub fn at(mut self, prefix: &[Value]) -> Self {
        let mut loc = prefix.to_vec();
        loc.append(&mut self.loc);
        self.loc = loc;
        self
    }

    /// The JSON object FastAPI returns for this issue, with passwords
    /// redacted (see [`redact_issue`]).
    pub fn to_json(&self) -> Value {
        let mut object = Map::new();
        object.insert("type".into(), Value::from(self.type_.clone()));
        object.insert("loc".into(), Value::Array(self.loc.clone()));
        object.insert("msg".into(), Value::from(self.msg.clone()));
        object.insert("input".into(), self.input.clone());
        if let Some(ctx) = &self.ctx {
            object.insert("ctx".into(), ctx.clone());
        }
        let mut issue = Value::Object(object);
        redact_issue(&mut issue);
        issue
    }
}

/// Replacement for a password echoed in a validation issue.
pub const REDACTED: &str = "[redacted]";

/// Name of the request fields whose values never appear in a 422.
const SECRET_FIELD: &str = "password";

/// Remove passwords from one pydantic-style issue object
/// (`{"type","loc","msg","input","ctx"?}`), in place and idempotently:
///
/// * an issue whose `loc` ends with `"password"` gets `input: "[redacted]"`,
///   except a `missing` issue (its input is the enclosing object, which has
///   no password);
/// * every `"password"` member of an object anywhere inside `input` or `ctx`
///   (e.g. the whole body echoed by a `missing` issue) becomes
///   `"[redacted]"`, keeping the key order;
/// * a raw-text body echoed at `loc: ["body"]` (a body that was not parsed
///   as JSON) that mentions `password` is replaced by `"[redacted]"`.
///
/// Intentional deviation: pydantic/FastAPI echo the submitted password in
/// these issues (`UnlockIn`, `MailCredentialsIn`, ...). The port keeps every
/// other part of the issue identical but never sends a password back, so a
/// UI or MCP client that logs or displays error details cannot leak it.
pub fn redact_issue(issue: &mut Value) {
    let Some(object) = issue.as_object_mut() else {
        return;
    };
    let loc = object.get("loc").and_then(Value::as_array);
    let secret_loc = loc
        .and_then(|loc| loc.last())
        .and_then(Value::as_str)
        .is_some_and(|last| last == SECRET_FIELD);
    let body_loc = loc.is_some_and(|loc| loc.len() == 1 && loc[0] == "body");
    // A `missing` issue echoes the enclosing object, which by definition has
    // no password member: redact members only, so the rest stays visible.
    let missing = object.get("type").and_then(Value::as_str) == Some("missing");
    let secret_loc = secret_loc && !missing;
    if let Some(input) = object.get_mut("input") {
        let raw_secret = body_loc
            && input
                .as_str()
                .is_some_and(|text| text.to_ascii_lowercase().contains(SECRET_FIELD));
        if secret_loc || raw_secret {
            *input = Value::from(REDACTED);
        } else {
            redact_secret_members(input);
        }
    }
    if let Some(ctx) = object.get_mut("ctx") {
        redact_secret_members(ctx);
    }
}

/// Replace the value of every `"password"` member inside `value`.
fn redact_secret_members(value: &mut Value) {
    match value {
        Value::Object(object) => {
            for (key, member) in object.iter_mut() {
                if key == SECRET_FIELD {
                    *member = Value::from(REDACTED);
                } else {
                    redact_secret_members(member);
                }
            }
        }
        Value::Array(items) => items.iter_mut().for_each(redact_secret_members),
        _ => {}
    }
}

impl Serialize for ValidationIssue {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        self.to_json().serialize(serializer)
    }
}

/// FastAPI's `RequestValidationError` response: HTTP 422 with the issue list.
pub fn validation_error(issues: &[ValidationIssue]) -> MailError {
    MailError::http(
        422,
        Value::Array(issues.iter().map(ValidationIssue::to_json).collect()),
    )
}

/// FastAPI's 422 for an empty or `null` JSON body.
pub fn missing_body_error() -> MailError {
    validation_error(&[ValidationIssue::missing(&Value::Null).at(&[json!("body")])])
}

/// FastAPI's 422 for a body that is not valid JSON: `loc` is
/// `["body", <character position>]`, `input` is `{}`.
pub fn json_invalid_error(position: usize, error: &str) -> MailError {
    validation_error(&[
        ValidationIssue::new("json_invalid", "JSON decode error", &json!({}))
            .with_ctx(json!({"error": error}))
            .at(&[json!("body"), json!(position)]),
    ])
}

/// Character offset of a serde_json syntax error (Python's `JSONDecodeError.pos`).
fn error_position(text: &str, error: &serde_json::Error) -> usize {
    let mut position = 0;
    for (index, line) in text.split('\n').enumerate() {
        if index + 1 == error.line() {
            return position + line.chars().take(error.column().saturating_sub(1)).count();
        }
        position += line.chars().count() + 1;
    }
    position
}

/// Result of validating a value at some location: issues are relative.
pub type Validated<T> = std::result::Result<T, Vec<ValidationIssue>>;

/// A request body model with pydantic semantics.
pub trait RequestModel: Sized {
    /// Validate `value`; issue locations are relative to the model root.
    fn validate(value: &Value) -> Validated<Self>;

    /// Validate a parsed JSON body (`null` is a missing body); issues are
    /// reported with locations under `"body"` as a 422 [`MailError`].
    fn from_json(value: &Value) -> Result<Self> {
        if value.is_null() {
            return Err(missing_body_error());
        }
        Self::validate(value).map_err(|issues| {
            let prefixed: Vec<_> = issues
                .into_iter()
                .map(|issue| issue.at(&[json!("body")]))
                .collect();
            validation_error(&prefixed)
        })
    }

    /// Parse and validate raw JSON body bytes like FastAPI: an empty body is
    /// missing, malformed JSON is `json_invalid`.
    fn from_body(bytes: &[u8]) -> Result<Self> {
        if bytes.is_empty() {
            return Err(missing_body_error());
        }
        let text = String::from_utf8_lossy(bytes);
        let value: Value = serde_json::from_str(&text).map_err(|error| {
            json_invalid_error(error_position(&text, &error), &error.to_string())
        })?;
        Self::from_json(&value)
    }
}

// ---------------------------------------------------------------------------
// Primitive validators
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

/// A JSON string (lax and strict `str` behave the same for JSON input).
fn string(value: &Value) -> Validated<&str> {
    match value {
        Value::String(text) => Ok(text),
        _ => fail(ValidationIssue::new(
            "string_type",
            "Input should be a valid string",
            value,
        )),
    }
}

/// `str` with `min_length` / `max_length` (counted in characters).
fn text(value: &Value, min: usize, max: Option<usize>) -> Validated<String> {
    let text = string(value)?;
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
    Ok(text.to_string())
}

fn uid_validity(value: &Value) -> Validated<String> {
    let text = text(value, 0, None)?;
    if !UID_VALIDITY_RE.is_match(&text) {
        return fail(
            ValidationIssue::new(
                "string_pattern_mismatch",
                format!("String should match pattern '{UID_VALIDITY_PATTERN}'"),
                value,
            )
            .with_ctx(json!({"pattern": UID_VALIDITY_PATTERN})),
        );
    }
    if text.parse::<i128>().map(|n| n > MAX_UID).unwrap_or(true) {
        return fail(ValidationIssue::value_error(
            "UID validity must be a positive 32-bit integer string",
            value,
        ));
    }
    Ok(text)
}

fn int_type(value: &Value) -> ValidationIssue {
    ValidationIssue::new("int_type", "Input should be a valid integer", value)
}

fn json_integer(number: &serde_json::Number) -> Option<i128> {
    number
        .as_i64()
        .map(i128::from)
        .or_else(|| number.as_u64().map(i128::from))
}

fn int_from_float(number: f64, value: &Value) -> Validated<i128> {
    if number.fract() != 0.0 {
        return fail(ValidationIssue::new(
            "int_from_float",
            "Input should be a valid integer, got a number with a fractional part",
            value,
        ));
    }
    if number.abs() > i64::MAX as f64 {
        return fail(ValidationIssue::new(
            "int_parsing_size",
            "Unable to parse input string as an integer, exceeded maximum size",
            value,
        ));
    }
    Ok(number as i128)
}

/// Strict `int`: JSON integers only (no bools, floats or strings).
fn strict_int(value: &Value) -> Validated<i128> {
    match value {
        Value::Number(number) => json_integer(number).ok_or_else(|| vec![int_type(value)]),
        _ => fail(int_type(value)),
    }
}

/// Lax `int`: integers, bools, whole floats and numeric strings.
fn lax_int(value: &Value) -> Validated<i128> {
    match value {
        Value::Bool(flag) => Ok(i128::from(*flag)),
        Value::Number(number) => match json_integer(number) {
            Some(integer) => Ok(integer),
            None => int_from_float(number.as_f64().unwrap_or(f64::NAN), value),
        },
        Value::String(text) => {
            let trimmed = text.trim();
            let parsed = parse_python_int(trimmed).or_else(|| {
                PYTHON_INT_DECIMAL_RE
                    .captures(trimmed)
                    .and_then(|captures| parse_python_int(&captures[1]))
            });
            parsed.ok_or_else(|| {
                vec![ValidationIssue::new(
                    "int_parsing",
                    "Input should be a valid integer, unable to parse string as an integer",
                    value,
                )]
            })
        }
        _ => fail(int_type(value)),
    }
}

/// `ge` / `le` constraints; the reported input is the original value.
fn int_bounds(number: i128, value: &Value, ge: Option<i128>, le: Option<i128>) -> Validated<i128> {
    if let Some(ge) = ge {
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
    }
    if let Some(le) = le {
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
    }
    Ok(number)
}

fn bool_type(value: &Value) -> ValidationIssue {
    ValidationIssue::new("bool_type", "Input should be a valid boolean", value)
}

fn bool_parsing(value: &Value) -> ValidationIssue {
    ValidationIssue::new(
        "bool_parsing",
        "Input should be a valid boolean, unable to interpret input",
        value,
    )
}

/// Strict `bool`: `true` / `false` only.
fn strict_bool(value: &Value) -> Validated<bool> {
    match value {
        Value::Bool(flag) => Ok(*flag),
        _ => fail(bool_type(value)),
    }
}

/// Lax `bool`: also `0`/`1` and the usual case-insensitive words.
fn lax_bool(value: &Value) -> Validated<bool> {
    match value {
        Value::Bool(flag) => Ok(*flag),
        Value::Number(number) => match json_integer(number) {
            Some(0) => Ok(false),
            Some(1) => Ok(true),
            Some(_) => fail(bool_parsing(value)),
            None => match number.as_f64() {
                Some(0.0) => Ok(false),
                Some(1.0) => Ok(true),
                Some(f) if f.fract() == 0.0 => fail(bool_parsing(value)),
                _ => fail(bool_type(value)),
            },
        },
        Value::String(text) => match text.to_lowercase().as_str() {
            "0" | "off" | "f" | "false" | "n" | "no" => Ok(false),
            "1" | "on" | "t" | "true" | "y" | "yes" => Ok(true),
            _ => fail(bool_parsing(value)),
        },
        _ => fail(bool_type(value)),
    }
}

/// `Literal[...]` of strings.
fn literal(value: &Value, choices: &[&'static str]) -> Validated<&'static str> {
    if let Value::String(text) = value {
        if let Some(choice) = choices.iter().find(|choice| **choice == text) {
            return Ok(choice);
        }
    }
    let quoted: Vec<String> = choices.iter().map(|choice| format!("'{choice}'")).collect();
    let expected = match quoted.split_last() {
        Some((last, [])) => last.clone(),
        Some((last, rest)) => format!("{} or {last}", rest.join(", ")),
        None => String::new(),
    };
    fail(
        ValidationIssue::new(
            "literal_error",
            format!("Input should be {expected}"),
            value,
        )
        .with_ctx(json!({"expected": expected})),
    )
}

/// `X | None`: `null` is `None`, anything else must validate as `X`.
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

/// `list[T]` with `min_length` / `max_length`.
fn list<T>(
    value: &Value,
    min: usize,
    max: Option<usize>,
    item: impl Fn(&Value) -> Validated<T>,
) -> Validated<Vec<T>> {
    let Value::Array(items) = value else {
        return fail(ValidationIssue::new(
            "list_type",
            "Input should be a valid list",
            value,
        ));
    };
    let length_ctx = |key: &str, limit: usize| json!({"field_type": "List", key: limit, "actual_length": items.len()});
    if let Some(max) = max {
        if items.len() > max {
            return fail(
                ValidationIssue::new(
                    "too_long",
                    format!(
                        "List should have at most {} after validation, not {}",
                        plural(max, "item"),
                        items.len()
                    ),
                    value,
                )
                .with_ctx(length_ctx("max_length", max)),
            );
        }
    }
    let mut output = Vec::with_capacity(items.len());
    let mut issues = Vec::new();
    for (index, element) in items.iter().enumerate() {
        match item(element) {
            Ok(validated) => output.push(validated),
            Err(found) => issues.extend(found.into_iter().map(|issue| issue.at(&[json!(index)]))),
        }
    }
    if !issues.is_empty() {
        return Err(issues);
    }
    if items.len() < min {
        return fail(
            ValidationIssue::new(
                "too_short",
                format!(
                    "List should have at least {} after validation, not {}",
                    plural(min, "item"),
                    items.len()
                ),
                value,
            )
            .with_ctx(length_ctx("min_length", min)),
        );
    }
    Ok(output)
}

fn email_category(value: &Value) -> Validated<String> {
    literal(value, &EMAIL_CATEGORIES).map(str::to_string)
}

/// Field reader over one JSON object, tracking `model_fields_set`.
struct Fields<'a> {
    input: &'a Value,
    object: &'a Map<String, Value>,
    issues: Vec<ValidationIssue>,
    set: BTreeSet<String>,
}

impl<'a> Fields<'a> {
    fn new(input: &'a Value) -> Validated<Self> {
        match input {
            Value::Object(object) => Ok(Self {
                input,
                object,
                issues: Vec::new(),
                set: BTreeSet::new(),
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

    /// A field without a default.
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
                self.set.insert(name.to_string());
                let result = validate(value);
                self.record(name, result)
            }
        }
    }

    /// A field with a default (defaults are not validated, as in pydantic).
    fn optional<T>(
        &mut self,
        name: &str,
        default: T,
        validate: impl FnOnce(&Value) -> Validated<T>,
    ) -> Option<T> {
        match self.object.get(name) {
            None => Some(default),
            Some(value) => {
                self.set.insert(name.to_string());
                let result = validate(value);
                self.record(name, result)
            }
        }
    }

    /// `extra="forbid"`: report every key that is not a declared field.
    fn forbid_extra(&mut self, declared: &[&str]) {
        for (key, value) in self.object {
            if !declared.contains(&key.as_str()) {
                self.issues.push(
                    ValidationIssue::new(
                        "extra_forbidden",
                        "Extra inputs are not permitted",
                        value,
                    )
                    .at(&[json!(key)]),
                );
            }
        }
    }

    /// Field errors, or the set of supplied field names.
    fn finish(self) -> Validated<BTreeSet<String>> {
        if self.issues.is_empty() {
            Ok(self.set)
        } else {
            Err(self.issues)
        }
    }
}

/// Model validator (`mode="after"`) failure: `loc` is the model itself.
fn model_error<T>(message: &str, input: &Value) -> Validated<T> {
    fail(ValidationIssue::value_error(message, input))
}

fn header_field(value: &Value, min: usize, max: Option<usize>) -> Validated<String> {
    let text = text(value, min, max)?;
    if !header_safe(&text) {
        return fail(ValidationIssue::value_error(
            "Mail headers cannot contain control characters",
            value,
        ));
    }
    Ok(text)
}

fn account(value: &Value) -> Validated<String> {
    text(value, 3, Some(320))
}

fn folder(value: &Value) -> Validated<String> {
    text(value, 1, Some(500))
}

fn strict_uid(value: &Value) -> Validated<u32> {
    let number = strict_int(value)?;
    int_bounds(number, value, Some(1), Some(MAX_UID)).map(|n| n as u32)
}

fn port(value: &Value) -> Validated<u16> {
    let number = lax_int(value)?;
    int_bounds(number, value, Some(1), Some(65535)).map(|n| n as u16)
}

fn saturate_i64(number: i128) -> i64 {
    number.clamp(i64::MIN as i128, i64::MAX as i128) as i64
}

/// Strict int `le=MAX_EXPIRATION_DAYS`, then `normalize_expiration_days`.
fn expiration_days(value: &Value) -> Validated<i64> {
    let number = strict_int(value)?;
    let number = int_bounds(number, value, None, Some(MAX_EXPIRATION_DAYS as i128))?;
    normalize_expiration_days(&json!(saturate_i64(number)))
        .map_err(|message| vec![ValidationIssue::value_error(&message, value)])
}

// ---------------------------------------------------------------------------
// Request models
// ---------------------------------------------------------------------------

/// `MailPreferencesIn` (`PUT /api/settings`, `extra="forbid"`).
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct MailPreferencesIn {
    pub messages_per_page: u32,
    pub signature: String,
    pub category_expiration_days: Option<BTreeMap<String, i64>>,
    pub local_ai_model: Option<String>,
    #[serde(skip)]
    pub fields_set: BTreeSet<String>,
}

impl MailPreferencesIn {
    /// `save_mail_preferences(**body.model_dump(exclude_unset=True))` arguments.
    pub fn to_update(&self) -> (Value, crate::settings::MailPreferencesUpdate) {
        let set = |name: &str| self.fields_set.contains(name);
        let update = crate::settings::MailPreferencesUpdate {
            signature: set("signature").then(|| json!(self.signature)),
            category_expiration_days: set("category_expiration_days")
                .then(|| json!(self.category_expiration_days)),
            local_ai_model: set("local_ai_model").then(|| json!(self.local_ai_model)),
        };
        (json!(self.messages_per_page), update)
    }
}

fn category_expiration_map(value: &Value) -> Validated<BTreeMap<String, i64>> {
    let Value::Object(object) = value else {
        return fail(ValidationIssue::new(
            "dict_type",
            "Input should be a valid dictionary",
            value,
        ));
    };
    let mut issues = Vec::new();
    let mut output = Map::new();
    for (key, item) in object {
        let key_value = Value::from(key.clone());
        if let Err(found) = literal(&key_value, &EMAIL_CATEGORIES) {
            issues.extend(
                found
                    .into_iter()
                    .map(|issue| issue.at(&[json!(key), json!("[key]")])),
            );
        }
        match strict_int(item)
            .and_then(|n| int_bounds(n, item, None, Some(MAX_EXPIRATION_DAYS as i128)))
        {
            Ok(number) => {
                output.insert(key.clone(), json!(saturate_i64(number)));
            }
            Err(found) => issues.extend(found.into_iter().map(|issue| issue.at(&[json!(key)]))),
        }
    }
    if !issues.is_empty() {
        return Err(issues);
    }
    validate_category_expiration_days(&Value::Object(output))
        .map_err(|message| vec![ValidationIssue::value_error(&message, value)])
}

impl RequestModel for MailPreferencesIn {
    fn validate(value: &Value) -> Validated<Self> {
        let mut fields = Fields::new(value)?;
        let messages_per_page = fields.required("messages_per_page", |v| {
            int_bounds(strict_int(v)?, v, Some(1), Some(200)).map(|n| n as u32)
        });
        let signature = fields.optional("signature", String::new(), |v| {
            let text = text(v, 0, Some(MAX_SIGNATURE_LENGTH))?;
            validate_signature(&text)
                .map_err(|message| vec![ValidationIssue::value_error(&message, v)])
        });
        let category_expiration_days = fields.optional("category_expiration_days", None, |v| {
            if v.is_null() {
                // The field validator receives None and rejects it.
                return fail(ValidationIssue::value_error(
                    "Category expiration must include exactly the five email categories",
                    v,
                ));
            }
            category_expiration_map(v).map(Some)
        });
        let local_ai_model = fields.optional("local_ai_model", None, |v| {
            if v.is_null() {
                return fail(ValidationIssue::value_error(
                    "Local AI model must be a model name of at most 200 characters",
                    v,
                ));
            }
            let text = text(v, 0, Some(200))?;
            validate_local_ai_model(&text)
                .map(Some)
                .map_err(|message| vec![ValidationIssue::value_error(&message, v)])
        });
        fields.forbid_extra(&[
            "messages_per_page",
            "signature",
            "category_expiration_days",
            "local_ai_model",
        ]);
        let fields_set = fields.finish()?;
        Ok(Self {
            messages_per_page: messages_per_page.unwrap(),
            signature: signature.unwrap(),
            category_expiration_days: category_expiration_days.unwrap(),
            local_ai_model: local_ai_model.unwrap(),
            fields_set,
        })
    }
}

/// `MessageRetentionIn` (`extra="forbid"`): change a message's category or
/// expiration. At least one of the two must be supplied.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct MessageRetentionIn {
    pub account: String,
    pub folder: String,
    pub uid: u32,
    pub uid_validity: String,
    pub category: Option<String>,
    pub expiration_days: Option<i64>,
    #[serde(skip)]
    pub fields_set: BTreeSet<String>,
}

impl MessageRetentionIn {
    /// `body.model_dump(include={"category", "expiration_days"}, exclude_unset=True)`.
    pub fn changes(&self) -> Map<String, Value> {
        let mut changes = Map::new();
        if self.fields_set.contains("category") {
            changes.insert("category".into(), json!(self.category));
        }
        if self.fields_set.contains("expiration_days") {
            changes.insert("expiration_days".into(), json!(self.expiration_days));
        }
        changes
    }
}

impl RequestModel for MessageRetentionIn {
    fn validate(value: &Value) -> Validated<Self> {
        let mut fields = Fields::new(value)?;
        let account = fields.required("account", account);
        let folder = fields.required("folder", folder);
        let uid = fields.required("uid", strict_uid);
        let uid_validity = fields.required("uid_validity", uid_validity);
        let category = fields.optional("category", None, |v| nullable(v, email_category));
        let expiration_days =
            fields.optional("expiration_days", None, |v| nullable(v, expiration_days));
        fields.forbid_extra(&[
            "account",
            "folder",
            "uid",
            "uid_validity",
            "category",
            "expiration_days",
        ]);
        let fields_set = fields.finish()?;
        if !fields_set.contains("category") && !fields_set.contains("expiration_days") {
            return model_error("Choose a category or expiration to update", value);
        }
        Ok(Self {
            account: account.unwrap(),
            folder: folder.unwrap(),
            uid: uid.unwrap(),
            uid_validity: uid_validity.unwrap(),
            category: category.unwrap(),
            expiration_days: expiration_days.unwrap(),
            fields_set,
        })
    }
}

/// `MessageClassifyIn` (`extra="forbid"`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MessageClassifyIn {
    pub account: String,
    pub folder: String,
    pub uid: u32,
    pub uid_validity: String,
}

const MESSAGE_IDENTITY_FIELDS: [&str; 4] = ["account", "folder", "uid", "uid_validity"];

fn message_identity(
    fields: &mut Fields<'_>,
) -> (Option<String>, Option<String>, Option<u32>, Option<String>) {
    (
        fields.required("account", account),
        fields.required("folder", folder),
        fields.required("uid", strict_uid),
        fields.required("uid_validity", uid_validity),
    )
}

impl RequestModel for MessageClassifyIn {
    fn validate(value: &Value) -> Validated<Self> {
        let mut fields = Fields::new(value)?;
        let (account, folder, uid, uid_validity) = message_identity(&mut fields);
        fields.forbid_extra(&MESSAGE_IDENTITY_FIELDS);
        fields.finish()?;
        Ok(Self {
            account: account.unwrap(),
            folder: folder.unwrap(),
            uid: uid.unwrap(),
            uid_validity: uid_validity.unwrap(),
        })
    }
}

/// `MessageSenderRuleIn(MessageClassifyIn)` (`extra="forbid"`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MessageSenderRuleIn {
    pub account: String,
    pub folder: String,
    pub uid: u32,
    pub uid_validity: String,
    pub category: String,
    pub expected_category_revision: Option<i64>,
}

impl RequestModel for MessageSenderRuleIn {
    fn validate(value: &Value) -> Validated<Self> {
        let mut fields = Fields::new(value)?;
        let (account, folder, uid, uid_validity) = message_identity(&mut fields);
        let category = fields.required("category", email_category);
        let expected_category_revision = fields.optional("expected_category_revision", None, |v| {
            nullable(v, |v| {
                int_bounds(strict_int(v)?, v, Some(0), None).map(saturate_i64)
            })
        });
        let mut declared = MESSAGE_IDENTITY_FIELDS.to_vec();
        declared.extend(["category", "expected_category_revision"]);
        fields.forbid_extra(&declared);
        fields.finish()?;
        Ok(Self {
            account: account.unwrap(),
            folder: folder.unwrap(),
            uid: uid.unwrap(),
            uid_validity: uid_validity.unwrap(),
            category: category.unwrap(),
            expected_category_revision: expected_category_revision.unwrap(),
        })
    }
}

/// `UnlockIn`: open a mailbox session. The password is kept in memory only.
///
/// Extension: optional `incoming_mail_protocol` (`"imap"` / `"pop3"`).
#[derive(Clone, PartialEq, Serialize)]
pub struct UnlockIn {
    pub email: String,
    #[serde(skip)]
    pub password: String,
    pub profile_key: Option<String>,
    pub display_name: String,
    pub incoming_server: Option<String>,
    pub incoming_port: Option<u16>,
    pub incoming_protocol: Option<String>,
    pub outgoing_server: Option<String>,
    pub outgoing_port: Option<u16>,
    pub outgoing_protocol: Option<String>,
    pub save_profile: bool,
    pub incoming_mail_protocol: Option<String>,
    #[serde(skip)]
    pub fields_set: BTreeSet<String>,
}

impl std::fmt::Debug for UnlockIn {
    // Never print the password.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UnlockIn")
            .field("email", &self.email)
            .field("password", &"<redacted>")
            .field("profile_key", &self.profile_key)
            .field("display_name", &self.display_name)
            .field("incoming_server", &self.incoming_server)
            .field("incoming_port", &self.incoming_port)
            .field("incoming_protocol", &self.incoming_protocol)
            .field("outgoing_server", &self.outgoing_server)
            .field("outgoing_port", &self.outgoing_port)
            .field("outgoing_protocol", &self.outgoing_protocol)
            .field("save_profile", &self.save_profile)
            .field("incoming_mail_protocol", &self.incoming_mail_protocol)
            .field("fields_set", &self.fields_set)
            .finish()
    }
}

impl UnlockIn {
    /// `"display_name" in body.model_fields_set`.
    pub fn display_name_set(&self) -> bool {
        self.fields_set.contains("display_name")
    }
}

fn optional_text(max: usize) -> impl Fn(&Value) -> Validated<Option<String>> {
    move |v| nullable(v, |v| text(v, 0, Some(max)))
}

impl RequestModel for UnlockIn {
    fn validate(value: &Value) -> Validated<Self> {
        let mut fields = Fields::new(value)?;
        let email = fields.required("email", |v| text(v, 3, Some(320)));
        let password = fields.required("password", |v| text(v, 1, Some(4096)));
        let profile_key = fields.optional("profile_key", None, optional_text(200));
        let display_name = fields.optional("display_name", String::new(), |v| {
            let name = text(v, 0, Some(200))?;
            if !header_safe(&name) {
                return fail(ValidationIssue::value_error(
                    "Display name must not contain control characters",
                    v,
                ));
            }
            Ok(name)
        });
        let incoming_server = fields.optional("incoming_server", None, optional_text(253));
        let incoming_port = fields.optional("incoming_port", None, |v| nullable(v, port));
        let incoming_protocol = fields.optional("incoming_protocol", None, optional_text(20));
        let outgoing_server = fields.optional("outgoing_server", None, optional_text(253));
        let outgoing_port = fields.optional("outgoing_port", None, |v| nullable(v, port));
        let outgoing_protocol = fields.optional("outgoing_protocol", None, optional_text(20));
        let save_profile = fields.optional("save_profile", false, lax_bool);
        let incoming_mail_protocol = fields.optional("incoming_mail_protocol", None, |v| {
            nullable(v, |v| {
                literal(v, &INCOMING_MAIL_PROTOCOLS).map(str::to_string)
            })
        });
        let fields_set = fields.finish()?;
        Ok(Self {
            email: email.unwrap(),
            password: password.unwrap(),
            profile_key: profile_key.unwrap(),
            display_name: display_name.unwrap(),
            incoming_server: incoming_server.unwrap(),
            incoming_port: incoming_port.unwrap(),
            incoming_protocol: incoming_protocol.unwrap(),
            outgoing_server: outgoing_server.unwrap(),
            outgoing_port: outgoing_port.unwrap(),
            outgoing_protocol: outgoing_protocol.unwrap(),
            save_profile: save_profile.unwrap(),
            incoming_mail_protocol: incoming_mail_protocol.unwrap(),
            fields_set,
        })
    }
}

/// `ServerProfileIn`: connection attributes only, never secrets.
///
/// Extension: `incoming_mail_protocol` (`"imap"` default or `"pop3"`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ServerProfileIn {
    pub email_address: String,
    pub display_name: String,
    pub incoming_server: String,
    pub incoming_port: u16,
    pub incoming_protocol: String,
    pub outgoing_server: String,
    pub outgoing_port: u16,
    pub outgoing_protocol: String,
    pub incoming_mail_protocol: String,
}

impl RequestModel for ServerProfileIn {
    fn validate(value: &Value) -> Validated<Self> {
        let mut fields = Fields::new(value)?;
        let email_address =
            fields.optional("email_address", String::new(), |v| text(v, 0, Some(320)));
        let display_name =
            fields.optional("display_name", String::new(), |v| text(v, 0, Some(200)));
        let incoming_server = fields.required("incoming_server", |v| text(v, 1, Some(253)));
        let incoming_port = fields.optional("incoming_port", 993, port);
        let incoming_protocol = fields.optional("incoming_protocol", "SSL/TLS".into(), |v| {
            text(v, 0, Some(20))
        });
        let outgoing_server = fields.required("outgoing_server", |v| text(v, 1, Some(253)));
        let outgoing_port = fields.optional("outgoing_port", 587, port);
        let outgoing_protocol = fields.optional("outgoing_protocol", "STARTTLS".into(), |v| {
            text(v, 0, Some(20))
        });
        let incoming_mail_protocol =
            fields.optional("incoming_mail_protocol", "imap".into(), |v| {
                literal(v, &INCOMING_MAIL_PROTOCOLS).map(str::to_string)
            });
        fields.finish()?;
        Ok(Self {
            email_address: email_address.unwrap(),
            display_name: display_name.unwrap(),
            incoming_server: incoming_server.unwrap(),
            incoming_port: incoming_port.unwrap(),
            incoming_protocol: incoming_protocol.unwrap(),
            outgoing_server: outgoing_server.unwrap(),
            outgoing_port: outgoing_port.unwrap(),
            outgoing_protocol: outgoing_protocol.unwrap(),
            incoming_mail_protocol: incoming_mail_protocol.unwrap(),
        })
    }
}

/// `SendUploadIn` (`extra="forbid"`): metadata for one uploaded file of
/// `POST /api/mail/send/files`, matched to the files by position.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SendUploadIn {
    pub content_id: String,
    /// `"attachment"` (default) or `"inline"`.
    pub disposition: String,
}

impl SendUploadIn {
    pub fn is_inline(&self) -> bool {
        self.disposition == "inline"
    }
}

impl RequestModel for SendUploadIn {
    fn validate(value: &Value) -> Validated<Self> {
        let mut fields = Fields::new(value)?;
        let content_id = fields.optional("content_id", String::new(), |v| text(v, 0, Some(200)));
        let disposition = fields.optional("disposition", "attachment".into(), |v| {
            literal(v, &DISPOSITIONS).map(str::to_string)
        });
        fields.forbid_extra(&["content_id", "disposition"]);
        fields.finish()?;
        let upload = Self {
            content_id: content_id.unwrap(),
            disposition: disposition.unwrap(),
        };
        if upload.is_inline() {
            if !CONTENT_ID_RE.is_match(&upload.content_id) {
                return model_error("Inline images require a valid content ID", value);
            }
        } else if !upload.content_id.is_empty() {
            return model_error(
                "Ordinary attachments cannot have an inline content ID",
                value,
            );
        }
        Ok(upload)
    }
}

/// `SendIn`: a message to send (`POST /api/mail/send` and the JSON `message`
/// part of `POST /api/mail/send/files`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SendIn {
    pub account: String,
    pub to: Vec<String>,
    pub cc: Vec<String>,
    pub bcc: Vec<String>,
    pub subject: String,
    pub text: String,
    pub html: String,
    pub in_reply_to: String,
    pub references: String,
    pub uploads: Vec<SendUploadIn>,
}

fn recipients(value: &Value) -> Validated<Vec<String>> {
    let items = list(value, 0, Some(MAX_RECIPIENTS), |v| {
        string(v).map(str::to_string)
    })?;
    for item in &items {
        if let Err(message) = recipient_address(item) {
            return fail(ValidationIssue::value_error(&message, value));
        }
    }
    Ok(items)
}

impl RequestModel for SendIn {
    fn validate(value: &Value) -> Validated<Self> {
        let mut fields = Fields::new(value)?;
        let account = fields.required("account", |v| header_field(v, 3, Some(320)));
        let to = fields.optional("to", Vec::new(), recipients);
        let cc = fields.optional("cc", Vec::new(), recipients);
        let bcc = fields.optional("bcc", Vec::new(), recipients);
        let subject = fields.optional("subject", String::new(), |v| header_field(v, 0, Some(998)));
        let text_body = fields.optional("text", String::new(), |v| text(v, 0, None));
        let html = fields.optional("html", String::new(), |v| text(v, 0, None));
        let in_reply_to = fields.optional("in_reply_to", String::new(), |v| {
            header_field(v, 0, Some(998))
        });
        let references = fields.optional("references", String::new(), |v| {
            header_field(v, 0, Some(2048))
        });
        let uploads = fields.optional("uploads", Vec::new(), |v| {
            list(v, 0, Some(MAX_SEND_FILES), SendUploadIn::validate)
        });
        fields.finish()?;
        let message = Self {
            account: account.unwrap(),
            to: to.unwrap(),
            cc: cc.unwrap(),
            bcc: bcc.unwrap(),
            subject: subject.unwrap(),
            text: text_body.unwrap(),
            html: html.unwrap(),
            in_reply_to: in_reply_to.unwrap(),
            references: references.unwrap(),
            uploads: uploads.unwrap(),
        };
        if message.to.len() + message.cc.len() + message.bcc.len() > MAX_RECIPIENTS {
            return model_error("Send to no more than 100 recipients", value);
        }
        if message.text.len() + message.html.len() > MAX_MESSAGE_BODY_BYTES {
            return model_error("Message text and HTML must total no more than 1 MiB", value);
        }
        let inline: Vec<&str> = message
            .uploads
            .iter()
            .filter(|upload| upload.is_inline())
            .map(|upload| upload.content_id.as_str())
            .collect();
        if inline.iter().collect::<HashSet<_>>().len() != inline.len() {
            return model_error("Inline image content IDs must be unique", value);
        }
        Ok(message)
    }
}

/// `FlagsIn`: set `\Seen` / `\Flagged` on one message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FlagsIn {
    pub account: String,
    pub folder: String,
    pub uid: u64,
    pub seen: Option<bool>,
    pub flagged: Option<bool>,
}

impl RequestModel for FlagsIn {
    fn validate(value: &Value) -> Validated<Self> {
        let mut fields = Fields::new(value)?;
        let account = fields.required("account", account);
        let folder = fields.required("folder", folder);
        let uid = fields.required("uid", |v| {
            int_bounds(lax_int(v)?, v, Some(1), None).map(|n| n.min(u64::MAX as i128) as u64)
        });
        let seen = fields.optional("seen", None, |v| nullable(v, lax_bool));
        let flagged = fields.optional("flagged", None, |v| nullable(v, lax_bool));
        fields.finish()?;
        Ok(Self {
            account: account.unwrap(),
            folder: folder.unwrap(),
            uid: uid.unwrap(),
            seen: seen.unwrap(),
            flagged: flagged.unwrap(),
        })
    }
}

/// `DeleteMessagesIn`: bulk delete; `uids` are de-duplicated in order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DeleteMessagesIn {
    pub account: String,
    pub folder: String,
    pub uids: Vec<u32>,
    pub trash: String,
    pub uid_validity: Option<String>,
}

impl RequestModel for DeleteMessagesIn {
    fn validate(value: &Value) -> Validated<Self> {
        let mut fields = Fields::new(value)?;
        let account = fields.required("account", account);
        let folder = fields.required("folder", folder);
        let uids = fields.required("uids", |v| {
            let uids = list(v, 1, Some(500), strict_uid)?;
            let mut seen = HashSet::new();
            Ok(uids
                .into_iter()
                .filter(|uid| seen.insert(*uid))
                .collect::<Vec<_>>())
        });
        let trash = fields.optional("trash", String::new(), |v| text(v, 0, Some(500)));
        let uid_validity = fields.optional("uid_validity", None, |v| nullable(v, uid_validity));
        fields.finish()?;
        Ok(Self {
            account: account.unwrap(),
            folder: folder.unwrap(),
            uids: uids.unwrap(),
            trash: trash.unwrap(),
            uid_validity: uid_validity.unwrap(),
        })
    }
}

/// `PasteAuditIn`: raw message text to audit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PasteAuditIn {
    pub content: String,
}

impl RequestModel for PasteAuditIn {
    fn validate(value: &Value) -> Validated<Self> {
        let mut fields = Fields::new(value)?;
        let content = fields.required("content", |v| text(v, 1, None));
        fields.finish()?;
        Ok(Self {
            content: content.unwrap(),
        })
    }
}

/// `RemoteImageIn`: fetch one remote image through the privacy proxy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RemoteImageIn {
    pub account: String,
    pub folder: String,
    pub uid: u32,
    pub url: String,
    pub retry: bool,
}

impl RequestModel for RemoteImageIn {
    fn validate(value: &Value) -> Validated<Self> {
        let mut fields = Fields::new(value)?;
        let account = fields.required("account", account);
        let folder = fields.required("folder", folder);
        let uid = fields.required("uid", |v| {
            int_bounds(lax_int(v)?, v, Some(1), Some(MAX_UID)).map(|n| n as u32)
        });
        let url = fields.required("url", |v| text(v, 1, Some(4096)));
        let retry = fields.optional("retry", false, lax_bool);
        fields.finish()?;
        Ok(Self {
            account: account.unwrap(),
            folder: folder.unwrap(),
            uid: uid.unwrap(),
            url: url.unwrap(),
            retry: retry.unwrap(),
        })
    }
}

/// `TrashPrepareIn` (`extra="forbid"`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TrashPrepareIn {
    pub account: String,
    pub folder: String,
    pub archive: bool,
}

impl RequestModel for TrashPrepareIn {
    fn validate(value: &Value) -> Validated<Self> {
        let mut fields = Fields::new(value)?;
        let account = fields.required("account", account);
        let folder = fields.required("folder", folder);
        let archive = fields.required("archive", strict_bool);
        fields.forbid_extra(&["account", "folder", "archive"]);
        fields.finish()?;
        Ok(Self {
            account: account.unwrap(),
            folder: folder.unwrap(),
            archive: archive.unwrap(),
        })
    }
}

/// `TrashEmptyIn` (`extra="forbid"`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TrashEmptyIn {
    pub account: String,
}

impl RequestModel for TrashEmptyIn {
    fn validate(value: &Value) -> Validated<Self> {
        let mut fields = Fields::new(value)?;
        let account = fields.required("account", account);
        fields.forbid_extra(&["account"]);
        fields.finish()?;
        Ok(Self {
            account: account.unwrap(),
        })
    }
}

// ---------------------------------------------------------------------------
// Recipient validation
// ---------------------------------------------------------------------------

const CONTROL_MESSAGE: &str = "Recipients must be valid email addresses without control characters";
const INVALID_ADDRESS: &str = "Enter a valid recipient email address";
const NOT_ONE_ADDRESS: &str = "Each recipient must contain one email address";
const INVALID_NAME: &str = "Recipient names cannot contain control characters";
const INVALID_DOMAIN: &str = "Enter a valid recipient email domain";

/// Python `recipient_address`: validate exactly one mailbox (an optional
/// display name is allowed) and return its `addr_spec`. `Err` holds the
/// `ValueError` message.
///
/// Deviations: inputs that crash Python's parser with `AttributeError`
/// (an unterminated domain literal such as `a@[`, or text after a group)
/// are rejected with "Enter a valid recipient email address"; RFC 2047
/// encoded words in charsets other than UTF-8/ASCII/Latin-1 are decoded
/// byte-wise (they only feed the control-character checks).
pub fn recipient_address(value: &str) -> std::result::Result<String, String> {
    if !header_safe(value) || value.chars().count() > MAX_RECIPIENT_LENGTH {
        return Err(CONTROL_MESSAGE.into());
    }
    let parsed = address::parse_address_list(value);
    if parsed.poisoned {
        return Err(INVALID_ADDRESS.into());
    }
    // `Address(display_name, username, domain)` rejects CR/LF in any part.
    let has_line_break = |text: &Option<String>| {
        text.as_deref()
            .is_some_and(|text| text.contains('\r') || text.contains('\n'))
    };
    for mailbox in parsed.mailboxes() {
        if has_line_break(&mailbox.display_name)
            || has_line_break(&mailbox.local_part)
            || has_line_break(&mailbox.domain)
        {
            return Err(INVALID_ADDRESS.into());
        }
    }
    let mailboxes = parsed.mailboxes();
    if parsed.defects > 0 || mailboxes.len() != 1 || parsed.has_group() {
        return Err(NOT_ONE_ADDRESS.into());
    }
    let mailbox = mailboxes[0];
    if !header_safe(mailbox.display_name.as_deref().unwrap_or("")) {
        return Err(INVALID_NAME.into());
    }
    let address = mailbox.addr_spec();
    if address.matches('@').count() != 1 || address.chars().any(char::is_whitespace) {
        return Err(INVALID_ADDRESS.into());
    }
    let (local, domain) = address.rsplit_once('@').expect("one '@'");
    if local.is_empty()
        || domain.is_empty()
        || address
            .chars()
            .any(|c| matches!(c, '<' | '>' | ',' | ';' | '\\'))
    {
        return Err(INVALID_ADDRESS.into());
    }
    if !valid_recipient_domain(domain) {
        return Err(INVALID_DOMAIN.into());
    }
    Ok(address)
}

fn valid_recipient_domain(domain: &str) -> bool {
    if let Some(inner) = domain
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
    {
        let inner = match inner.get(..5) {
            Some(prefix) if prefix.eq_ignore_ascii_case("IPv6:") => &inner[5..],
            _ => inner,
        };
        return python_ip_address(inner);
    }
    match python_idna_encode(domain) {
        Some(normalized) => {
            normalized.len() <= 253
                && normalized
                    .split('.')
                    .all(|label| DOMAIN_LABEL_RE.is_match(label))
        }
        None => false,
    }
}

/// `ipaddress.ip_address(text)` succeeds (IPv6 may carry a `%scope`).
fn python_ip_address(text: &str) -> bool {
    if text.parse::<Ipv4Addr>().is_ok() {
        return true;
    }
    // IPv6Address accepts one non-empty `%scope` suffix.
    let address = match text.split_once('%') {
        Some((_, scope)) if scope.is_empty() || scope.contains('%') => return false,
        Some((address, _)) => address,
        None => text,
    };
    address.parse::<Ipv6Addr>().is_ok()
}

/// Python's `str.encode("idna")` codec (IDNA 2003 ToASCII per label).
fn python_idna_encode(domain: &str) -> Option<String> {
    if domain.is_ascii() {
        let labels: Vec<&str> = domain.split('.').collect();
        let (last, rest) = labels.split_last()?;
        if rest
            .iter()
            .any(|label| label.is_empty() || label.len() >= 64)
            || last.len() >= 64
        {
            return None;
        }
        return Some(domain.to_string());
    }
    let mut labels: Vec<&str> = domain
        .split(['.', '\u{3002}', '\u{ff0e}', '\u{ff61}'])
        .collect();
    let trailing_dot = labels.last().is_some_and(|label| label.is_empty());
    if trailing_dot {
        labels.pop();
    }
    let mut encoded = Vec::with_capacity(labels.len());
    for label in labels {
        let ascii = if label.is_ascii() {
            label.to_string()
        } else {
            idna::domain_to_ascii(label).ok()?
        };
        if ascii.is_empty() || ascii.len() >= 64 {
            return None;
        }
        encoded.push(ascii);
    }
    let mut result = encoded.join(".");
    if trailing_dot {
        result.push('.');
    }
    Some(result)
}

/// Port of the address-list parser of `email._header_value_parser`.
///
/// Instead of building Python's token tree, every parse function returns the
/// attributes `AddressHeader` later reads (`display_name`, `local_part`,
/// `domain`) and counts defects on the parser. Tokens dropped by Python's
/// `try/except` backtracking lose their defects, so every backtracking site
/// restores the defect counter.
mod address {
    const SPECIALS: &[u8] = b"()<>@,:;.\\\"[]";
    const PHRASE_ENDS: &[u8] = b")<>@,:;\\[]";

    fn first(s: &str) -> Option<u8> {
        s.as_bytes().first().copied()
    }
    fn is_wsp(b: u8) -> bool {
        b == b' ' || b == b'\t'
    }
    fn is_cfws_leader(b: u8) -> bool {
        is_wsp(b) || b == b'('
    }
    fn is_special(b: u8) -> bool {
        SPECIALS.contains(&b)
    }
    fn is_atom_end(b: u8) -> bool {
        is_special(b) || is_wsp(b)
    }
    fn is_phrase_end(b: u8) -> bool {
        PHRASE_ENDS.contains(&b)
    }
    fn starts_with_cfws(s: &str) -> bool {
        first(s).is_some_and(is_cfws_leader)
    }
    /// Python `_non_printable_finder`: `[\x00-\x20\x7F]`.
    fn has_non_printable(text: &str) -> bool {
        text.chars().any(|c| (c as u32) <= 0x20 || c as u32 == 0x7f)
    }

    /// `HeaderParseError`.
    #[derive(Debug)]
    struct ParseError;

    type Parsed<'a, T> = Result<(T, &'a str), ParseError>;

    /// `atom` / `quoted-string` / encoded word, with surrounding CFWS flags.
    #[derive(Debug, Clone)]
    struct Word {
        lead: bool,
        core: String,
        trail: bool,
    }

    impl Word {
        fn value(&self) -> String {
            let mut value = String::new();
            if self.lead {
                value.push(' ');
            }
            value.push_str(&self.core);
            if self.trail {
                value.push(' ');
            }
            value
        }
    }

    #[derive(Debug, Clone)]
    enum PhraseItem {
        Word(Word),
        Dot,
        Cfws,
    }

    fn phrase_display_name(items: &[PhraseItem]) -> String {
        let mut items = items.to_vec();
        match items.first_mut() {
            Some(PhraseItem::Cfws) => {
                items.remove(0);
            }
            Some(PhraseItem::Word(word)) => word.lead = false,
            _ => {}
        }
        match items.last_mut() {
            Some(PhraseItem::Cfws) => {
                items.pop();
            }
            Some(PhraseItem::Word(word)) => word.trail = false,
            _ => {}
        }
        items
            .iter()
            .map(|item| match item {
                PhraseItem::Word(word) => word.value(),
                PhraseItem::Dot => ".".into(),
                PhraseItem::Cfws => " ".into(),
            })
            .collect()
    }

    /// Attributes of one `Mailbox` (or `InvalidMailbox`, all `None`).
    #[derive(Debug, Clone, Default, PartialEq)]
    pub(super) struct MailboxInfo {
        pub display_name: Option<String>,
        pub local_part: Option<String>,
        pub domain: Option<String>,
    }

    impl MailboxInfo {
        /// `headerregistry.Address.addr_spec` of `Address(display_name or '',
        /// local_part or '', domain or '')`.
        pub fn addr_spec(&self) -> String {
            let local = self.local_part.clone().unwrap_or_default();
            let domain = self.domain.clone().unwrap_or_default();
            let needs_quotes = local
                .bytes()
                .any(|b| (is_special(b) && b != b'.') || is_wsp(b));
            let local = if needs_quotes {
                quote_string(&local)
            } else {
                local
            };
            if !domain.is_empty() {
                format!("{local}@{domain}")
            } else if local.is_empty() {
                "<>".into()
            } else {
                local
            }
        }
    }

    fn quote_string(value: &str) -> String {
        format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""))
    }

    #[derive(Debug, Clone)]
    pub(super) enum Address {
        Mailbox(MailboxInfo),
        Group(Vec<MailboxInfo>),
    }

    /// The parsed address list as `AddressHeader` sees it.
    #[derive(Debug, Default)]
    pub(super) struct AddressList {
        pub addresses: Vec<Address>,
        pub defects: usize,
        /// Python would raise a non-`ValueError` exception for this input.
        pub poisoned: bool,
    }

    impl AddressList {
        /// Every mailbox of every address (`address.all_mailboxes`).
        pub fn mailboxes(&self) -> Vec<&MailboxInfo> {
            self.addresses
                .iter()
                .flat_map(|address| match address {
                    Address::Mailbox(info) => std::slice::from_ref(info).iter(),
                    Address::Group(infos) => infos.iter(),
                })
                .collect()
        }

        pub fn has_group(&self) -> bool {
            self.addresses
                .iter()
                .any(|address| matches!(address, Address::Group(_)))
        }
    }

    #[derive(Clone, Copy)]
    struct Mark {
        defects: usize,
        poison: usize,
    }

    #[derive(Default)]
    struct Parser {
        defects: usize,
        poison: usize,
    }

    /// Python `get_address_list(value)` as used by `AddressHeader.parse`.
    pub(super) fn parse_address_list(value: &str) -> AddressList {
        let mut parser = Parser::default();
        let addresses = parser.address_list(value);
        AddressList {
            addresses,
            defects: parser.defects,
            poisoned: parser.poison > 0,
        }
    }

    impl Parser {
        fn mark(&self) -> Mark {
            Mark {
                defects: self.defects,
                poison: self.poison,
            }
        }
        fn reset(&mut self, mark: Mark) {
            self.defects = mark.defects;
            self.poison = mark.poison;
        }
        fn defect(&mut self) {
            self.defects += 1;
        }

        /// `get_fws`: Python strips with `str.lstrip()` (any whitespace).
        fn fws<'a>(&mut self, s: &'a str) -> &'a str {
            s.trim_start()
        }

        /// `_get_ptext_to_endchars`: (unquoted text, rest, had quoted pair).
        fn ptext_to_endchars<'a>(
            &mut self,
            s: &'a str,
            endchars: &[u8],
        ) -> (String, &'a str, bool) {
            let fragment_end = s.find([' ', '\t']).unwrap_or(s.len());
            let fragment = &s[..fragment_end];
            let mut text = String::new();
            let mut escape = false;
            let mut had_qp = false;
            let mut stop = fragment.len();
            for (index, ch) in fragment.char_indices() {
                if ch == '\\' {
                    if escape {
                        escape = false;
                        had_qp = true;
                    } else {
                        escape = true;
                        continue;
                    }
                }
                if escape {
                    escape = false;
                } else if ch.is_ascii() && endchars.contains(&(ch as u8)) {
                    stop = index;
                    break;
                }
                text.push(ch);
            }
            (text, &s[stop..], had_qp)
        }

        /// `_validate_xtext`.
        fn validate_xtext(&mut self, text: &str) {
            if has_non_printable(text) {
                self.defect();
            }
        }

        /// `get_comment` (the leading `(` is present).
        fn comment<'a>(&mut self, s: &'a str) -> &'a str {
            let mut s = &s[1..];
            while let Some(b) = first(s) {
                if b == b')' {
                    return &s[1..];
                }
                s = if is_wsp(b) {
                    self.fws(s)
                } else if b == b'(' {
                    self.comment(s)
                } else {
                    let (text, rest, _) = self.ptext_to_endchars(s, b"()");
                    self.validate_xtext(&text);
                    if rest.len() == s.len() {
                        // Defensive: always make progress.
                        &s[s.chars().next().map_or(1, char::len_utf8)..]
                    } else {
                        rest
                    }
                };
            }
            self.defect(); // end of header inside comment
            s
        }

        /// `get_cfws`.
        fn cfws<'a>(&mut self, mut s: &'a str) -> &'a str {
            while let Some(b) = first(s).filter(|b| is_cfws_leader(*b)) {
                s = if is_wsp(b) {
                    self.fws(s)
                } else {
                    self.comment(s)
                };
            }
            s
        }

        /// `get_qcontent`.
        fn qcontent<'a>(&mut self, s: &'a str) -> (String, &'a str) {
            let (text, rest, _) = self.ptext_to_endchars(s, b"\"");
            self.validate_xtext(&text);
            (text, rest)
        }

        /// `get_atext`.
        fn atext<'a>(&mut self, s: &'a str) -> Parsed<'a, String> {
            let end = s.bytes().position(is_atom_end).unwrap_or(s.len());
            if end == 0 {
                return Err(ParseError);
            }
            let text = s[..end].to_string();
            self.validate_xtext(&text);
            Ok((text, &s[end..]))
        }

        /// `get_encoded_word`: the decoded value (whitespace runs become ' ').
        fn encoded_word<'a>(&mut self, s: &'a str) -> Parsed<'a, String> {
            let after = s.strip_prefix("=?").ok_or(ParseError)?;
            let split = after.find("?=").ok_or(ParseError)?;
            let mut token = after[..split].to_string();
            let mut rest = &after[split + 2..];
            let bytes = rest.as_bytes();
            if bytes.len() > 1
                && bytes[0].is_ascii_hexdigit()
                && bytes[1].is_ascii_hexdigit()
                && token.matches('?').count() < 2
            {
                // The '?' after the CTE was followed by an encoded word escape (=XX).
                match rest.find("?=") {
                    Some(index) => {
                        token = format!("{token}?={}", &rest[..index]);
                        rest = &rest[index + 2..];
                    }
                    None => {
                        token = format!("{token}?={rest}");
                        rest = "";
                    }
                }
            }
            let whitespace_inside = token.split_whitespace().count() > 1;
            let (text, decode_defects) = decode_encoded_word(&token).ok_or(ParseError)?;
            if whitespace_inside {
                self.defect();
            }
            self.defects += decode_defects;
            let mut value = String::new();
            let mut remaining = text.as_str();
            while let Some(b) = first(remaining) {
                if is_wsp(b) {
                    remaining = self.fws(remaining);
                    value.push(' ');
                    continue;
                }
                let end = remaining.find([' ', '\t']).unwrap_or(remaining.len());
                let chunk = &remaining[..end];
                self.validate_xtext(chunk);
                value.push_str(chunk);
                remaining = &remaining[end..];
            }
            if first(rest).is_some_and(|b| !is_wsp(b)) {
                self.defect(); // missing trailing whitespace after encoded-word
            }
            Ok((value, rest))
        }

        /// `get_bare_quoted_string`: the raw content between the quotes.
        fn bare_quoted_string<'a>(&mut self, s: &'a str) -> Parsed<'a, String> {
            if first(s) != Some(b'"') {
                return Err(ParseError);
            }
            let mut s = &s[1..];
            let mut value = String::new();
            if first(s) == Some(b'"') {
                let (text, rest) = self.qcontent(s);
                value.push_str(&text);
                s = rest;
            }
            while let Some(b) = first(s).filter(|b| *b != b'"') {
                if is_wsp(b) {
                    let rest = self.fws(s);
                    value.push_str(&s[..s.len() - rest.len()]);
                    s = rest;
                } else if s.starts_with("=?") {
                    let mark = self.mark();
                    match self.encoded_word(s) {
                        Ok((text, rest)) => {
                            self.defect(); // encoded word inside quoted string
                            value.push_str(&text);
                            s = rest;
                        }
                        Err(_) => {
                            self.reset(mark);
                            let (text, rest) = self.qcontent(s);
                            value.push_str(&text);
                            s = rest;
                        }
                    }
                } else {
                    let (text, rest) = self.qcontent(s);
                    value.push_str(&text);
                    s = if rest.len() == s.len() { &s[1..] } else { rest };
                }
            }
            if s.is_empty() {
                self.defect(); // end of header inside quoted string
                return Ok((value, s));
            }
            Ok((value, &s[1..]))
        }

        /// `get_quoted_string`.
        fn quoted_string<'a>(&mut self, s: &'a str) -> Parsed<'a, Word> {
            let mut s = s;
            let mut lead = false;
            if starts_with_cfws(s) {
                s = self.cfws(s);
                lead = true;
            }
            let (core, rest) = self.bare_quoted_string(s)?;
            s = rest;
            let mut trail = false;
            if starts_with_cfws(s) {
                s = self.cfws(s);
                trail = true;
            }
            Ok((Word { lead, core, trail }, s))
        }

        /// `get_atom`.
        fn atom<'a>(&mut self, s: &'a str) -> Parsed<'a, Word> {
            let mut s = s;
            let mut lead = false;
            if starts_with_cfws(s) {
                s = self.cfws(s);
                lead = true;
            }
            if first(s).is_some_and(is_atom_end) {
                return Err(ParseError);
            }
            let (core, rest) = if s.starts_with("=?") {
                let mark = self.mark();
                match self.encoded_word(s) {
                    Ok(parsed) => parsed,
                    Err(_) => {
                        self.reset(mark);
                        self.atext(s)?
                    }
                }
            } else {
                self.atext(s)?
            };
            s = rest;
            let mut trail = false;
            if starts_with_cfws(s) {
                s = self.cfws(s);
                trail = true;
            }
            Ok((Word { lead, core, trail }, s))
        }

        /// `get_dot_atom_text`.
        fn dot_atom_text<'a>(&mut self, s: &'a str) -> Parsed<'a, String> {
            let mut s = s;
            if first(s).is_none_or(is_atom_end) {
                return Err(ParseError);
            }
            let mut text = String::new();
            let mut ends_with_dot = false;
            while first(s).is_some_and(|b| !is_atom_end(b)) {
                let (atext, rest) = self.atext(s)?;
                text.push_str(&atext);
                ends_with_dot = false;
                s = rest;
                if first(s) == Some(b'.') {
                    text.push('.');
                    ends_with_dot = true;
                    s = &s[1..];
                }
            }
            if ends_with_dot {
                return Err(ParseError);
            }
            Ok((text, s))
        }

        /// `get_dot_atom`.
        fn dot_atom<'a>(&mut self, s: &'a str) -> Parsed<'a, Word> {
            let mut s = s;
            let mut lead = false;
            if starts_with_cfws(s) {
                s = self.cfws(s);
                lead = true;
            }
            let (core, rest) = if s.starts_with("=?") {
                let mark = self.mark();
                match self.encoded_word(s) {
                    Ok(parsed) => parsed,
                    Err(_) => {
                        self.reset(mark);
                        self.dot_atom_text(s)?
                    }
                }
            } else {
                self.dot_atom_text(s)?
            };
            s = rest;
            let mut trail = false;
            if starts_with_cfws(s) {
                s = self.cfws(s);
                trail = true;
            }
            Ok((Word { lead, core, trail }, s))
        }

        /// `get_word`.
        fn word<'a>(&mut self, s: &'a str) -> Parsed<'a, Word> {
            let mut s = s;
            let mut leader = false;
            if starts_with_cfws(s) {
                s = self.cfws(s);
                leader = true;
            }
            let Some(b) = first(s) else {
                return Err(ParseError);
            };
            let (mut word, rest) = if b == b'"' {
                self.quoted_string(s)?
            } else if is_special(b) {
                return Err(ParseError);
            } else {
                self.atom(s)?
            };
            word.lead |= leader;
            Ok((word, rest))
        }

        /// `get_phrase`.
        fn phrase<'a>(&mut self, s: &'a str) -> Parsed<'a, Vec<PhraseItem>> {
            let mut s = s;
            let mut items = Vec::new();
            let mark = self.mark();
            match self.word(s) {
                Ok((word, rest)) => {
                    items.push(PhraseItem::Word(word));
                    s = rest;
                }
                Err(_) => {
                    self.reset(mark);
                    self.defect(); // phrase does not start with word
                }
            }
            while let Some(b) = first(s).filter(|b| !is_phrase_end(*b)) {
                if b == b'.' {
                    items.push(PhraseItem::Dot);
                    self.defect(); // period in 'phrase'
                    s = &s[1..];
                    continue;
                }
                let mark = self.mark();
                match self.word(s) {
                    Ok((word, rest)) => {
                        items.push(PhraseItem::Word(word));
                        s = rest;
                    }
                    Err(error) => {
                        self.reset(mark);
                        if !is_cfws_leader(b) {
                            return Err(error);
                        }
                        s = self.cfws(s);
                        items.push(PhraseItem::Cfws);
                        self.defect(); // comment found without atom
                    }
                }
            }
            Ok((items, s))
        }

        /// `get_local_part`: the `local_part` attribute.
        fn local_part<'a>(&mut self, original: &'a str) -> Parsed<'a, String> {
            let mut s = original;
            if starts_with_cfws(s) {
                s = self.cfws(s);
            }
            let Some(b) = first(s) else {
                return Err(ParseError);
            };
            let mark = self.mark();
            let (mut local_part, rest) = match self.dot_atom(s) {
                Ok((word, rest)) => (word.core, rest),
                Err(_) => {
                    self.reset(mark);
                    match self.word(s) {
                        Ok((word, rest)) => (word.core, rest),
                        Err(error) => {
                            self.reset(mark);
                            if b != b'\\' && is_phrase_end(b) {
                                return Err(error);
                            }
                            (String::new(), s)
                        }
                    }
                }
            };
            s = rest;
            if first(s).is_some_and(|b| b == b'\\' || !is_phrase_end(b)) {
                // Python re-parses `str(local_part) + value`; re-parsing the
                // original text from the same position is equivalent here.
                self.reset(mark);
                let (obs, rest) = self.obs_local_part(original)?;
                self.defect(); // obsolete or invalid local-part
                local_part = obs;
                s = rest;
            }
            if !local_part.is_ascii() {
                self.defect(); // NonASCIILocalPartDefect
            }
            Ok((local_part, s))
        }

        /// `get_obs_local_part`: the joined non-whitespace pieces.
        fn obs_local_part<'a>(&mut self, s: &'a str) -> Parsed<'a, String> {
            #[derive(PartialEq)]
            enum Piece {
                Dot,
                Misplaced,
                Word,
                Cfws,
            }
            let mut s = s;
            let mut pieces: Vec<Piece> = Vec::new();
            let mut text = String::new();
            let mut last_non_ws_was_dot = false;
            let mut local_defects = 0;
            while let Some(b) = first(s).filter(|b| *b == b'\\' || !is_phrase_end(*b)) {
                if b == b'.' {
                    if last_non_ws_was_dot {
                        local_defects += 1;
                    }
                    pieces.push(Piece::Dot);
                    text.push('.');
                    last_non_ws_was_dot = true;
                    s = &s[1..];
                    continue;
                }
                if b == b'\\' {
                    pieces.push(Piece::Misplaced);
                    text.push('\\');
                    s = &s[1..];
                    local_defects += 1;
                    last_non_ws_was_dot = false;
                    continue;
                }
                if pieces.last().is_some_and(|piece| *piece != Piece::Dot) {
                    local_defects += 1; // missing '.' between words
                }
                let mark = self.mark();
                match self.word(s) {
                    Ok((word, rest)) => {
                        last_non_ws_was_dot = false;
                        pieces.push(Piece::Word);
                        text.push_str(&word.core);
                        s = rest;
                    }
                    Err(error) => {
                        self.reset(mark);
                        if !is_cfws_leader(b) {
                            return Err(error);
                        }
                        s = self.cfws(s);
                        pieces.push(Piece::Cfws);
                    }
                }
            }
            if pieces.is_empty() {
                return Err(ParseError);
            }
            let n = pieces.len();
            if pieces[0] == Piece::Dot
                || (pieces[0] == Piece::Cfws && n > 1 && pieces[1] == Piece::Dot)
            {
                local_defects += 1;
            }
            if pieces[n - 1] == Piece::Dot
                || (pieces[n - 1] == Piece::Cfws && n > 1 && pieces[n - 2] == Piece::Dot)
            {
                local_defects += 1;
            }
            self.defects += local_defects;
            Ok((text, s))
        }

        /// `get_domain_literal`: the `domain` attribute (`[...]`).
        fn domain_literal<'a>(&mut self, s: &'a str) -> Parsed<'a, String> {
            let mut s = s;
            if starts_with_cfws(s) {
                s = self.cfws(s);
            }
            if first(s) != Some(b'[') {
                return Err(ParseError);
            }
            s = &s[1..];
            // Python appends a defect *object* to the token list on early end
            // of input, which later raises AttributeError.
            if s.is_empty() {
                self.poison += 1;
                return Ok(("[]".into(), s));
            }
            if first(s).is_some_and(is_wsp) {
                s = self.fws(s);
            }
            let (text, rest, had_qp) = self.ptext_to_endchars(s, b"[]");
            if had_qp {
                self.defect();
            }
            self.validate_xtext(&text);
            s = rest;
            if s.is_empty() {
                self.poison += 1;
                return Ok((format!("[{text}]"), s));
            }
            if first(s).is_some_and(is_wsp) {
                s = self.fws(s);
            }
            if s.is_empty() {
                self.poison += 1;
                return Ok((format!("[{text}]"), s));
            }
            if first(s) != Some(b']') {
                return Err(ParseError);
            }
            s = &s[1..];
            if starts_with_cfws(s) {
                s = self.cfws(s);
            }
            let domain: String = format!("[{text}]").split_whitespace().collect();
            Ok((domain, s))
        }

        /// `get_domain`: the `domain` attribute (whitespace removed).
        fn domain<'a>(&mut self, s: &'a str) -> Parsed<'a, String> {
            let mut s = s;
            if starts_with_cfws(s) {
                s = self.cfws(s);
            }
            if s.is_empty() {
                return Err(ParseError);
            }
            if first(s) == Some(b'[') {
                return self.domain_literal(s);
            }
            let mark = self.mark();
            let (word, rest) = match self.dot_atom(s) {
                Ok(parsed) => parsed,
                Err(_) => {
                    self.reset(mark);
                    self.atom(s)?
                }
            };
            s = rest;
            if first(s) == Some(b'@') {
                return Err(ParseError);
            }
            let mut value = word.value();
            if first(s) == Some(b'.') {
                self.defect(); // domain is not a dot-atom (contains CFWS)
                while first(s) == Some(b'.') {
                    value.push('.');
                    let (atom, rest) = self.atom(&s[1..])?;
                    value.push_str(&atom.value());
                    s = rest;
                }
            }
            Ok((value.split_whitespace().collect(), s))
        }

        /// `get_addr_spec`: (local_part, domain).
        fn addr_spec<'a>(&mut self, s: &'a str) -> Parsed<'a, (String, Option<String>)> {
            let (local_part, s) = self.local_part(s)?;
            if first(s) != Some(b'@') {
                self.defect(); // addr-spec local part with no domain
                return Ok(((local_part, None), s));
            }
            let (domain, s) = self.domain(&s[1..])?;
            Ok(((local_part, Some(domain)), s))
        }

        /// `get_obs_route`.
        fn obs_route<'a>(&mut self, s: &'a str) -> Parsed<'a, ()> {
            let mut s = s;
            while let Some(b) = first(s).filter(|b| *b == b',' || is_cfws_leader(*b)) {
                s = if is_cfws_leader(b) {
                    self.cfws(s)
                } else {
                    &s[1..]
                };
            }
            if first(s) != Some(b'@') {
                return Err(ParseError);
            }
            let (_, rest) = self.domain(&s[1..])?;
            s = rest;
            while first(s) == Some(b',') {
                s = &s[1..];
                if s.is_empty() {
                    break;
                }
                if starts_with_cfws(s) {
                    s = self.cfws(s);
                }
                if s.is_empty() {
                    break;
                }
                if first(s) == Some(b'@') {
                    let (_, rest) = self.domain(&s[1..])?;
                    s = rest;
                }
            }
            if first(s) != Some(b':') {
                return Err(ParseError);
            }
            Ok(((), &s[1..]))
        }

        /// `get_angle_addr`: the inner addr-spec (`None` for `<>`).
        fn angle_addr<'a>(&mut self, s: &'a str) -> Parsed<'a, Option<(String, Option<String>)>> {
            let mut s = s;
            if starts_with_cfws(s) {
                s = self.cfws(s);
            }
            if first(s) != Some(b'<') {
                return Err(ParseError);
            }
            s = &s[1..];
            if first(s) == Some(b'>') {
                self.defect(); // null addr-spec in angle-addr
                return Ok((None, &s[1..]));
            }
            let mark = self.mark();
            let (spec, rest) = match self.addr_spec(s) {
                Ok(parsed) => parsed,
                Err(_) => {
                    self.reset(mark);
                    let (_, rest) = self.obs_route(s)?;
                    self.defect(); // obsolete route specification
                    self.addr_spec(rest)?
                }
            };
            s = rest;
            if first(s) == Some(b'>') {
                s = &s[1..];
            } else {
                self.defect(); // missing trailing '>' on angle-addr
            }
            if starts_with_cfws(s) {
                s = self.cfws(s);
            }
            Ok((Some(spec), s))
        }

        /// `get_display_name`: the `display_name` attribute.
        fn display_name<'a>(&mut self, s: &'a str) -> Parsed<'a, String> {
            let (items, rest) = self.phrase(s)?;
            Ok((phrase_display_name(&items), rest))
        }

        /// `get_name_addr`.
        fn name_addr<'a>(&mut self, s: &'a str) -> Parsed<'a, MailboxInfo> {
            let mut s = s;
            if s.is_empty() {
                return Err(ParseError);
            }
            if starts_with_cfws(s) {
                s = self.cfws(s);
                if s.is_empty() {
                    return Err(ParseError);
                }
            }
            let mut display_name = None;
            if first(s) != Some(b'<') {
                if first(s).is_some_and(is_phrase_end) {
                    return Err(ParseError);
                }
                let (name, rest) = self.display_name(s)?;
                if rest.is_empty() {
                    return Err(ParseError);
                }
                display_name = Some(name);
                s = rest;
            }
            let (spec, rest) = self.angle_addr(s)?;
            let (local_part, domain) = match spec {
                Some((local_part, domain)) => (Some(local_part), domain),
                None => (None, None),
            };
            Ok((
                MailboxInfo {
                    display_name,
                    local_part,
                    domain,
                },
                rest,
            ))
        }

        /// `get_mailbox`.
        fn mailbox<'a>(&mut self, s: &'a str) -> Parsed<'a, MailboxInfo> {
            let mark = self.mark();
            match self.name_addr(s) {
                Ok(parsed) => Ok(parsed),
                Err(_) => {
                    self.reset(mark);
                    let ((local_part, domain), rest) =
                        self.addr_spec(s).inspect_err(|_| self.reset(mark))?;
                    Ok((
                        MailboxInfo {
                            display_name: None,
                            local_part: Some(local_part),
                            domain,
                        },
                        rest,
                    ))
                }
            }
        }

        /// `get_invalid_mailbox`: skip to one of `endchars`.
        fn invalid_mailbox<'a>(&mut self, s: &'a str, endchars: &[u8]) -> &'a str {
            let mut s = s;
            while let Some(b) = first(s).filter(|b| !endchars.contains(b)) {
                let before = s.len();
                if is_phrase_end(b) {
                    s = &s[1..];
                } else {
                    match self.phrase(s) {
                        Ok((_, rest)) => s = rest,
                        Err(_) => {
                            // Python would propagate HeaderParseError.
                            self.poison += 1;
                            return "";
                        }
                    }
                }
                if s.len() == before {
                    s = &s[s.chars().next().map_or(1, char::len_utf8)..];
                }
            }
            s
        }

        /// `get_mailbox_list`: the `all_mailboxes` of the list.
        fn mailbox_list<'a>(&mut self, s: &'a str) -> (Vec<MailboxInfo>, &'a str) {
            let mut s = s;
            let mut mailboxes: Vec<MailboxInfo> = Vec::new();
            let mut last_is_mailbox = false;
            while let Some(b) = first(s).filter(|b| *b != b';') {
                let mark = self.mark();
                match self.mailbox(s) {
                    Ok((info, rest)) => {
                        mailboxes.push(info);
                        last_is_mailbox = true;
                        s = rest;
                    }
                    Err(_) => {
                        self.reset(mark);
                        if is_cfws_leader(b) {
                            s = self.cfws(s);
                            if first(s).is_none_or(|b| b == b',' || b == b';') {
                                last_is_mailbox = false;
                                self.defect(); // empty element in mailbox-list
                            } else {
                                s = self.invalid_mailbox(s, b",;");
                                mailboxes.push(MailboxInfo::default());
                                last_is_mailbox = true;
                                self.defect();
                            }
                        } else if b == b',' {
                            self.defect(); // empty element in mailbox-list
                        } else {
                            s = self.invalid_mailbox(s, b",;");
                            mailboxes.push(MailboxInfo::default());
                            last_is_mailbox = true;
                            self.defect();
                        }
                    }
                }
                if first(s).is_some_and(|b| b != b',' && b != b';') {
                    // Crap after mailbox; treat it as an invalid mailbox.
                    if !last_is_mailbox {
                        self.poison += 1;
                    }
                    s = self.invalid_mailbox(s, b",;");
                    self.defect();
                }
                if first(s) == Some(b',') {
                    last_is_mailbox = false;
                    s = &s[1..];
                }
            }
            (mailboxes, s)
        }

        /// `get_group_list`.
        fn group_list<'a>(&mut self, s: &'a str) -> (Vec<MailboxInfo>, &'a str) {
            let mut s = s;
            if s.is_empty() {
                self.defect();
                return (Vec::new(), s);
            }
            if starts_with_cfws(s) {
                s = self.cfws(s);
                if s.is_empty() {
                    self.defect();
                    return (Vec::new(), s);
                }
                if first(s) == Some(b';') {
                    return (Vec::new(), s);
                }
            }
            let (mailboxes, rest) = self.mailbox_list(s);
            if mailboxes.is_empty() {
                self.defect(); // group-list with empty entries
            }
            (mailboxes, rest)
        }

        /// `get_group`.
        fn group<'a>(&mut self, s: &'a str) -> Parsed<'a, Vec<MailboxInfo>> {
            let (_, s) = self.display_name(s)?;
            if first(s) != Some(b':') {
                return Err(ParseError);
            }
            let s = &s[1..];
            if first(s) == Some(b';') {
                return Ok((Vec::new(), &s[1..]));
            }
            let (mailboxes, s) = self.group_list(s);
            if s.is_empty() {
                self.defect(); // end of header in group
            } else if first(s) != Some(b';') {
                return Err(ParseError);
            }
            let mut s = s.get(1..).unwrap_or("");
            if starts_with_cfws(s) {
                s = self.cfws(s);
            }
            Ok((mailboxes, s))
        }

        /// `get_address`.
        fn address<'a>(&mut self, s: &'a str) -> Parsed<'a, Address> {
            let mark = self.mark();
            match self.group(s) {
                Ok((mailboxes, rest)) => Ok((Address::Group(mailboxes), rest)),
                Err(_) => {
                    self.reset(mark);
                    let (info, rest) = self.mailbox(s)?;
                    Ok((Address::Mailbox(info), rest))
                }
            }
        }

        /// `get_address_list`.
        fn address_list(&mut self, s: &str) -> Vec<Address> {
            let mut s = s;
            let mut addresses = Vec::new();
            while let Some(b) = first(s) {
                let mut appended = false;
                let mark = self.mark();
                match self.address(s) {
                    Ok((address, rest)) => {
                        addresses.push(address);
                        appended = true;
                        s = rest;
                    }
                    Err(_) => {
                        self.reset(mark);
                        if is_cfws_leader(b) {
                            s = self.cfws(s);
                            if first(s).is_none_or(|b| b == b',') {
                                self.defect(); // address-list entry with no content
                            } else {
                                s = self.invalid_mailbox(s, b",");
                                addresses.push(Address::Mailbox(MailboxInfo::default()));
                                appended = true;
                                self.defect();
                            }
                        } else if b == b',' {
                            self.defect(); // empty element in address-list
                        } else {
                            s = self.invalid_mailbox(s, b",");
                            addresses.push(Address::Mailbox(MailboxInfo::default()));
                            appended = true;
                            self.defect();
                        }
                    }
                }
                if first(s).is_some_and(|b| b != b',') {
                    // Crap after address. A group whose token type changes to
                    // invalid-mailbox makes Python raise AttributeError.
                    if !appended || matches!(addresses.last(), Some(Address::Group(_))) {
                        self.poison += 1;
                    }
                    s = self.invalid_mailbox(s, b",");
                    self.defect();
                }
                if !s.is_empty() {
                    s = &s[1..]; // must be a ',' at this point
                }
            }
            addresses
        }
    }

    /// `_encoded_words.decode`: (text, defect count), or `None` when Python
    /// raises (malformed word, unknown CTE, non-ASCII payload).
    fn decode_encoded_word(token: &str) -> Option<(String, usize)> {
        let parts: Vec<&str> = token.split('?').collect();
        let [charset, cte, payload] = parts.as_slice() else {
            return None;
        };
        if !payload.is_ascii() {
            return None;
        }
        let charset = charset.split('*').next().unwrap_or("").to_lowercase();
        let (bytes, mut defects) = match cte.to_lowercase().as_str() {
            "q" => (decode_q(payload), 0),
            "b" => decode_b(payload),
            _ => return None,
        };
        let text = match charset.replace('_', "-").as_str() {
            "utf-8" | "utf8" => match String::from_utf8(bytes.clone()) {
                Ok(text) => text,
                Err(_) => {
                    defects += 1;
                    String::from_utf8_lossy(&bytes).into_owned()
                }
            },
            "us-ascii" | "ascii" | "646" | "unknown-8bit" => {
                if !bytes.is_ascii() {
                    defects += 1;
                }
                String::from_utf8_lossy(&bytes).into_owned()
            }
            // Latin-1 decodes exactly; other charsets are decoded byte-wise
            // (their text only feeds the control-character checks).
            _ => bytes.iter().map(|&b| b as char).collect(),
        };
        Some((text, defects))
    }

    fn decode_q(payload: &str) -> Vec<u8> {
        let bytes = payload.replace('_', " ").into_bytes();
        let mut output = Vec::with_capacity(bytes.len());
        let mut index = 0;
        while index < bytes.len() {
            if bytes[index] == b'='
                && index + 2 < bytes.len()
                && bytes[index + 1].is_ascii_hexdigit()
                && bytes[index + 2].is_ascii_hexdigit()
            {
                let hex = std::str::from_utf8(&bytes[index + 1..index + 3]).unwrap();
                output.push(u8::from_str_radix(hex, 16).unwrap());
                index += 3;
            } else {
                output.push(bytes[index]);
                index += 1;
            }
        }
        output
    }

    fn decode_b(payload: &str) -> (Vec<u8>, usize) {
        use base64::Engine;
        let engine = base64::engine::general_purpose::STANDARD;
        let pad_err = payload.len() % 4;
        let padded = format!(
            "{payload}{}",
            &"==="[..if pad_err == 0 { 0 } else { 4 - pad_err }]
        );
        if let Ok(bytes) = engine.decode(&padded) {
            return (bytes, usize::from(pad_err != 0));
        }
        // Invalid characters or length: Python decodes leniently and records
        // defects, which reject the address anyway.
        let cleaned: String = payload
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || *c == '+' || *c == '/')
            .collect();
        let pad = (4 - cleaned.len() % 4) % 4;
        let bytes = engine
            .decode(format!("{cleaned}{}", "=".repeat(pad)))
            .unwrap_or_else(|_| payload.as_bytes().to_vec());
        (bytes, 1)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn q_and_b_encoded_words_decode() {
            assert_eq!(
                decode_encoded_word("utf-8?q?Ren=C3=A9_X"),
                Some(("René X".into(), 0))
            );
            assert_eq!(
                decode_encoded_word("iso-8859-1?q?Ren=E9"),
                Some(("René".into(), 0))
            );
            assert_eq!(
                decode_encoded_word("utf-8?b?UmVuw6k="),
                Some(("René".into(), 0))
            );
            assert_eq!(
                decode_encoded_word("utf-8?b?UmVuw6k").map(|(_, d)| d),
                Some(1)
            );
            assert_eq!(decode_encoded_word("utf-8?x?abc"), None);
            assert_eq!(decode_encoded_word("bad"), None);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn issues<T: RequestModel + std::fmt::Debug>(body: Value) -> Value {
        T::from_json(&body).unwrap_err().detail()
    }

    #[test]
    fn python_int_parsing() {
        assert_eq!(parse_python_int(" 1_000 "), Some(1000));
        assert_eq!(parse_python_int("+5"), Some(5));
        assert_eq!(parse_python_int("-5"), Some(-5));
        for invalid in ["", "  ", "1__0", "_1", "1_", "0x10", "1e3", "7.0", "abc"] {
            assert_eq!(parse_python_int(invalid), None, "{invalid}");
        }
    }

    #[test]
    fn header_safe_rejects_controls() {
        assert!(header_safe("Ren\u{e9}e, Team"));
        assert!(!header_safe("a\tb"));
        assert!(!header_safe("a\u{7f}"));
        assert!(!header_safe("a\r\nb"));
    }

    #[test]
    fn constants_match_python() {
        assert_eq!(MAX_MESSAGE_BODY_BYTES, 1_048_576);
        assert_eq!(MAX_SEND_FILES, 20);
        assert_eq!(MAX_SEND_FILE_BYTES, 10_485_760);
        assert_eq!(MAX_SEND_FILES_BYTES, 20_971_520);
    }

    // -- FastAPI body handling ---------------------------------------------

    #[test]
    fn body_level_errors_match_fastapi() {
        let missing =
            json!([{"type": "missing", "loc": ["body"], "msg": "Field required", "input": null}]);
        assert_eq!(FlagsIn::from_body(b"").unwrap_err().detail(), missing);
        assert_eq!(
            FlagsIn::from_json(&Value::Null).unwrap_err().detail(),
            missing
        );
        for body in [json!([]), json!("str")] {
            assert_eq!(
                issues::<FlagsIn>(body.clone()),
                json!([{"type": "model_attributes_type", "loc": ["body"],
                        "msg": "Input should be a valid dictionary or object to extract fields from", "input": body}])
            );
        }
        let error = FlagsIn::from_body(b"{bad").unwrap_err();
        assert_eq!(error.status(), 422);
        let detail = error.detail();
        assert_eq!(detail[0]["type"], "json_invalid");
        assert_eq!(detail[0]["loc"], json!(["body", 1]));
        assert_eq!(detail[0]["msg"], "JSON decode error");
        assert_eq!(detail[0]["input"], json!({}));
        // Lone surrogates are a JSON error in Rust (pydantic: string_unicode); still 422.
        let error =
            MailPreferencesIn::from_body(br#"{"messages_per_page":5,"signature":"bad\ud800"}"#)
                .unwrap_err();
        assert_eq!(error.status(), 422);
    }

    // -- FlagsIn: lax coercions ----------------------------------------------

    #[test]
    fn flags_lax_int_and_bool_coercions() {
        let flags = |body: Value| FlagsIn::from_json(&body);
        let base = |uid: Value| json!({"account": "a@b.c", "folder": "INBOX", "uid": uid});
        for (uid, expected) in [
            (json!(true), 1),
            (json!("7"), 7),
            (json!(7.0), 7),
            (json!(" 7 "), 7),
            (json!("7.0"), 7),
            (json!("1_000"), 1000),
            (json!("+5"), 5),
            (json!(1e3), 1000),
        ] {
            assert_eq!(flags(base(uid.clone())).unwrap().uid, expected, "{uid}");
        }
        let int_parsing = "Input should be a valid integer, unable to parse string as an integer";
        for uid in ["7.5", "abc", "0x10", "7.", ".0", "1e3", "  "] {
            let detail = issues::<FlagsIn>(base(json!(uid)));
            assert_eq!(
                detail,
                json!([{"type": "int_parsing", "loc": ["body", "uid"], "msg": int_parsing, "input": uid}])
            );
        }
        assert_eq!(
            issues::<FlagsIn>(base(json!(7.5))),
            json!([{"type": "int_from_float", "loc": ["body", "uid"],
                    "msg": "Input should be a valid integer, got a number with a fractional part", "input": 7.5}])
        );
        assert_eq!(
            issues::<FlagsIn>(base(json!(0))),
            json!([{"type": "greater_than_equal", "loc": ["body", "uid"],
                    "msg": "Input should be greater than or equal to 1", "input": 0, "ctx": {"ge": 1}}])
        );
        assert_eq!(
            issues::<FlagsIn>(base(json!("-5"))),
            json!([{"type": "greater_than_equal", "loc": ["body", "uid"],
                    "msg": "Input should be greater than or equal to 1", "input": "-5", "ctx": {"ge": 1}}])
        );
        assert_eq!(
            issues::<FlagsIn>(base(json!(1e20)))[0]["type"],
            "int_parsing_size"
        );
        assert_eq!(issues::<FlagsIn>(base(json!(null)))[0]["type"], "int_type");

        let with = |seen: Value, flagged: Value| json!({"account": "a@b.c", "folder": "INBOX", "uid": 1, "seen": seen, "flagged": flagged});
        let parsed = flags(with(json!("yes"), json!(1))).unwrap();
        assert_eq!((parsed.seen, parsed.flagged), (Some(true), Some(true)));
        let parsed = flags(with(json!(1.0), json!("OFF"))).unwrap();
        assert_eq!((parsed.seen, parsed.flagged), (Some(true), Some(false)));
        let parsed = flags(with(json!("TRUE"), json!("F"))).unwrap();
        assert_eq!((parsed.seen, parsed.flagged), (Some(true), Some(false)));
        let bool_parsing = "Input should be a valid boolean, unable to interpret input";
        assert_eq!(
            issues::<FlagsIn>(with(json!("maybe"), json!(2))),
            json!([{"type": "bool_parsing", "loc": ["body", "seen"], "msg": bool_parsing, "input": "maybe"},
                   {"type": "bool_parsing", "loc": ["body", "flagged"], "msg": bool_parsing, "input": 2}])
        );
        assert_eq!(
            issues::<FlagsIn>(with(json!(" yes "), json!(0.5))),
            json!([{"type": "bool_parsing", "loc": ["body", "seen"], "msg": bool_parsing, "input": " yes "},
                   {"type": "bool_type", "loc": ["body", "flagged"], "msg": "Input should be a valid boolean", "input": 0.5}])
        );
        assert_eq!(
            issues::<FlagsIn>(with(json!(2.0), json!(0.0)))[0]["type"],
            "bool_parsing"
        );
        assert_eq!(
            issues::<FlagsIn>(with(json!(-1), json!({}))),
            json!([{"type": "bool_parsing", "loc": ["body", "seen"], "msg": bool_parsing, "input": -1},
                   {"type": "bool_type", "loc": ["body", "flagged"], "msg": "Input should be a valid boolean", "input": {}}])
        );
        let parsed = flags(with(json!(null), json!(false))).unwrap();
        assert_eq!((parsed.seen, parsed.flagged), (None, Some(false)));
    }

    #[test]
    fn missing_type_and_length_errors_in_field_order() {
        let body = json!({"account": 5, "folder": "", "extra": 1});
        assert_eq!(
            issues::<FlagsIn>(body.clone()),
            json!([
                {"type": "string_type", "loc": ["body", "account"], "msg": "Input should be a valid string", "input": 5},
                {"type": "string_too_short", "loc": ["body", "folder"], "msg": "String should have at least 1 character", "input": "", "ctx": {"min_length": 1}},
                {"type": "missing", "loc": ["body", "uid"], "msg": "Field required", "input": body},
            ])
        );
    }

    // -- UnlockIn / ServerProfileIn ------------------------------------------

    #[test]
    fn validation_issues_never_echo_passwords() {
        let secret = "Hunter2-Secret";
        // Missing field: the whole body is the input; the password member is
        // redacted in place (key order kept).
        let detail = issues::<UnlockIn>(json!({"password": secret, "extra": [{"password": 1}]}));
        assert_eq!(
            detail,
            json!([{"type": "missing", "loc": ["body", "email"], "msg": "Field required",
                    "input": {"password": "[redacted]", "extra": [{"password": "[redacted]"}]}}])
        );
        let keys: Vec<_> = detail[0]["input"].as_object().unwrap().keys().collect();
        assert_eq!(keys, ["password", "extra"]);
        // Over-long or mistyped password: input redacted, ctx kept.
        let long = format!("{secret}{}", "x".repeat(4096));
        let detail = issues::<UnlockIn>(json!({"email": "a@b.c", "password": long}));
        assert_eq!(detail[0]["loc"], json!(["body", "password"]));
        assert_eq!(detail[0]["input"], json!("[redacted]"));
        assert_eq!(detail[0]["ctx"], json!({"max_length": 4096}));
        let detail = issues::<UnlockIn>(json!({"email": "a@b.c", "password": 5}));
        assert_eq!(detail[0]["input"], json!("[redacted]"));
        // A raw (non-JSON) body echoed at ["body"] that mentions a password.
        let mut raw = json!({"type": "model_attributes_type", "loc": ["body"], "msg": "m",
                             "input": format!("{{\"Password\":\"{secret}\"}}")});
        redact_issue(&mut raw);
        assert_eq!(raw["input"], json!("[redacted]"));
        let mut harmless =
            json!({"type": "model_attributes_type", "loc": ["body"], "msg": "m", "input": "hello"});
        redact_issue(&mut harmless);
        assert_eq!(harmless["input"], json!("hello"));
        // Idempotent; non-issue values are left alone.
        let mut twice = detail[0].clone();
        redact_issue(&mut twice);
        assert_eq!(twice, detail[0]);
        let mut scalar = json!("password");
        redact_issue(&mut scalar);
        assert_eq!(scalar, json!("password"));
    }

    #[test]
    fn unlock_validation() {
        assert_eq!(
            issues::<UnlockIn>(json!({"email": "ab", "password": "", "display_name": "x\u{1}"})),
            json!([
                {"type": "string_too_short", "loc": ["body", "email"], "msg": "String should have at least 3 characters", "input": "ab", "ctx": {"min_length": 3}},
                {"type": "string_too_short", "loc": ["body", "password"], "msg": "String should have at least 1 character", "input": "[redacted]", "ctx": {"min_length": 1}},
                {"type": "value_error", "loc": ["body", "display_name"], "msg": "Value error, Display name must not contain control characters", "input": "x\u{1}", "ctx": {"error": {}}},
            ])
        );
        let unlock = UnlockIn::from_json(&json!({"email": "a@b.c", "password": "p", "incoming_port": "993", "incoming_server": null})).unwrap();
        assert_eq!(unlock.incoming_port, Some(993));
        assert_eq!(unlock.incoming_server, None);
        assert!(!unlock.display_name_set());
        assert!(unlock.fields_set.contains("incoming_server"));
        assert!(!format!("{unlock:?}").contains("\"p\""));
        assert_eq!(
            issues::<UnlockIn>(
                json!({"email": "a@b.c", "password": "p", "incoming_port": 70000, "save_profile": "true"})
            ),
            json!([{"type": "less_than_equal", "loc": ["body", "incoming_port"], "msg": "Input should be less than or equal to 65535", "input": 70000, "ctx": {"le": 65535}}])
        );
        let named = UnlockIn::from_json(&json!({"email": "a@b.c", "password": "p", "display_name": "", "save_profile": "yes", "incoming_mail_protocol": "pop3"})).unwrap();
        assert!(named.display_name_set());
        assert!(named.save_profile);
        assert_eq!(named.incoming_mail_protocol.as_deref(), Some("pop3"));
        let emoji = "\u{1F600}";
        assert!(UnlockIn::from_json(
            &json!({"email": "a@b.c", "password": "p", "display_name": emoji.repeat(200)})
        )
        .is_ok());
        assert_eq!(
            issues::<UnlockIn>(
                json!({"email": "a@b.c", "password": "p", "display_name": emoji.repeat(201)})
            )[0]["msg"],
            "String should have at most 200 characters"
        );
        assert_eq!(
            issues::<UnlockIn>(
                json!({"email": "a@b.c", "password": "p", "incoming_mail_protocol": "smtp"})
            )[0]["msg"],
            "Input should be 'imap' or 'pop3'"
        );
    }

    #[test]
    fn server_profile_defaults_and_errors() {
        let profile =
            ServerProfileIn::from_json(&json!({"incoming_server": "i", "outgoing_server": "s"}))
                .unwrap();
        assert_eq!(profile.incoming_port, 993);
        assert_eq!(profile.incoming_protocol, "SSL/TLS");
        assert_eq!(profile.outgoing_port, 587);
        assert_eq!(profile.outgoing_protocol, "STARTTLS");
        assert_eq!(profile.incoming_mail_protocol, "imap");
        assert_eq!(profile.email_address, "");
        assert_eq!(
            issues::<ServerProfileIn>(
                json!({"incoming_server": "", "outgoing_server": "s", "incoming_port": 0, "email_address": null})
            ),
            json!([
                {"type": "string_type", "loc": ["body", "email_address"], "msg": "Input should be a valid string", "input": null},
                {"type": "string_too_short", "loc": ["body", "incoming_server"], "msg": "String should have at least 1 character", "input": "", "ctx": {"min_length": 1}},
                {"type": "greater_than_equal", "loc": ["body", "incoming_port"], "msg": "Input should be greater than or equal to 1", "input": 0, "ctx": {"ge": 1}},
            ])
        );
    }

    // -- MailPreferencesIn -----------------------------------------------------

    #[test]
    fn mail_preferences_strict_fields_and_extra_forbid() {
        assert_eq!(
            issues::<MailPreferencesIn>(json!({})),
            json!([{"type": "missing", "loc": ["body", "messages_per_page"], "msg": "Field required", "input": {}}])
        );
        for count in [
            json!(true),
            json!("5"),
            json!(5.0),
            json!(null),
            json!([]),
            json!({}),
        ] {
            assert_eq!(
                issues::<MailPreferencesIn>(json!({"messages_per_page": count}))[0]["type"],
                "int_type",
                "{count}"
            );
        }
        assert_eq!(
            issues::<MailPreferencesIn>(json!({"messages_per_page": 0}))[0]["type"],
            "greater_than_equal"
        );
        assert_eq!(
            issues::<MailPreferencesIn>(json!({"messages_per_page": 201})),
            json!([{"type": "less_than_equal", "loc": ["body", "messages_per_page"], "msg": "Input should be less than or equal to 200", "input": 201, "ctx": {"le": 200}}])
        );
        let extra = issues::<MailPreferencesIn>(
            json!({"messages_per_page": 5, "password": "x", "data_directory": "y"}),
        );
        let mut types: Vec<_> = extra
            .as_array()
            .unwrap()
            .iter()
            .map(|issue| issue["loc"][1].as_str().unwrap().to_string())
            .collect();
        types.sort();
        assert_eq!(types, ["data_directory", "password"]);
        assert_eq!(extra[0]["type"], "extra_forbidden");
        assert_eq!(extra[0]["msg"], "Extra inputs are not permitted");
    }

    #[test]
    fn mail_preferences_field_validators() {
        let check = |body: Value, msg: &str| {
            let detail = issues::<MailPreferencesIn>(body);
            assert_eq!(detail[0]["msg"], msg, "{detail}");
        };
        check(
            json!({"messages_per_page": 5, "signature": null}),
            "Input should be a valid string",
        );
        check(
            json!({"messages_per_page": 5, "signature": "bad\u{1}"}),
            "Value error, Signature must be valid Unicode text without control characters",
        );
        check(
            json!({"messages_per_page": 5, "signature": "bad\u{7f}"}),
            "Value error, Signature must be valid Unicode text without control characters",
        );
        check(
            json!({"messages_per_page": 5, "signature": "x".repeat(10001)}),
            "String should have at most 10000 characters",
        );
        check(
            json!({"messages_per_page": 5, "category_expiration_days": null}),
            "Value error, Category expiration must include exactly the five email categories",
        );
        check(
            json!({"messages_per_page": 5, "category_expiration_days": {"marketing": 1}}),
            "Value error, Category expiration must include exactly the five email categories",
        );
        check(
            json!({"messages_per_page": 5, "category_expiration_days": []}),
            "Input should be a valid dictionary",
        );
        check(
            json!({"messages_per_page": 5, "local_ai_model": null}),
            "Value error, Local AI model must be a model name of at most 200 characters",
        );
        check(
            json!({"messages_per_page": 5, "local_ai_model": ""}),
            "Value error, Local AI model must be a model name of at most 200 characters",
        );
        check(
            json!({"messages_per_page": 5, "local_ai_model": 5}),
            "Input should be a valid string",
        );
        check(
            json!({"messages_per_page": 5, "local_ai_model": "x".repeat(201)}),
            "String should have at most 200 characters",
        );
        check(
            json!({"messages_per_page": 5, "local_ai_model": "gpt-oss:20b-cloud"}),
            "Value error, Choose a locally installed model, not a cloud model",
        );
        check(
            json!({"messages_per_page": 5, "local_ai_model": "a..b"}),
            "Value error, Local AI model must be a model identifier",
        );

        let expected = "'marketing', 'transactional', 'updates', 'verification' or 'uncategorized'";
        assert_eq!(
            issues::<MailPreferencesIn>(
                json!({"messages_per_page": 5, "category_expiration_days": {"bogus": 2, "updates": true, "verification": 365001}})
            ),
            json!([
                {"type": "literal_error", "loc": ["body", "category_expiration_days", "bogus", "[key]"], "msg": format!("Input should be {expected}"), "input": "bogus", "ctx": {"expected": expected}},
                {"type": "int_type", "loc": ["body", "category_expiration_days", "updates"], "msg": "Input should be a valid integer", "input": true},
                {"type": "less_than_equal", "loc": ["body", "category_expiration_days", "verification"], "msg": "Input should be less than or equal to 365000", "input": 365001, "ctx": {"le": 365000}},
            ])
        );

        let valid = MailPreferencesIn::from_json(&json!({
            "messages_per_page": 5,
            "category_expiration_days": {"marketing": -3, "transactional": 2, "updates": 3, "verification": 4, "uncategorized": 5},
            "local_ai_model": "llama3:8b",
        })).unwrap();
        assert_eq!(
            valid.category_expiration_days.as_ref().unwrap()["marketing"],
            -1
        );
        let (count, update) = valid.to_update();
        assert_eq!(count, json!(5));
        assert_eq!(update.signature, None);
        assert_eq!(update.local_ai_model, Some(json!("llama3:8b")));
        assert_eq!(
            update.category_expiration_days.unwrap()["marketing"],
            json!(-1)
        );

        let only_count = MailPreferencesIn::from_json(&json!({"messages_per_page": 20})).unwrap();
        assert_eq!(
            only_count.to_update().1,
            crate::settings::MailPreferencesUpdate::default()
        );
        let empty_signature =
            MailPreferencesIn::from_json(&json!({"messages_per_page": 20, "signature": ""}))
                .unwrap();
        assert_eq!(empty_signature.to_update().1.signature, Some(json!("")));
    }

    // -- Retention / classify / sender rules ---------------------------------

    #[test]
    fn message_retention_requires_a_change() {
        let base = json!({"account": "a@b.c", "folder": "INBOX", "uid": 7, "uid_validity": "5"});
        assert_eq!(
            issues::<MessageRetentionIn>(base.clone()),
            json!([{"type": "value_error", "loc": ["body"], "msg": "Value error, Choose a category or expiration to update", "input": base, "ctx": {"error": {}}}])
        );
        let mut with_null = base.clone();
        with_null["category"] = json!(null);
        let parsed = MessageRetentionIn::from_json(&with_null).unwrap();
        assert_eq!(parsed.category, None);
        assert_eq!(
            parsed.changes(),
            json!({"category": null}).as_object().unwrap().clone()
        );

        let mut expiring = base.clone();
        expiring["expiration_days"] = json!(-7);
        let parsed = MessageRetentionIn::from_json(&expiring).unwrap();
        assert_eq!(parsed.expiration_days, Some(-1));
        assert_eq!(
            parsed.changes(),
            json!({"expiration_days": -1}).as_object().unwrap().clone()
        );

        let detail = issues::<MessageRetentionIn>(
            json!({"account": "a@b.c", "folder": "INBOX", "uid": 7, "uid_validity": "5", "expiration_days": 365001, "category": "spam"}),
        );
        assert_eq!(detail[0]["type"], "literal_error");
        assert_eq!(detail[0]["loc"], json!(["body", "category"]));
        assert_eq!(detail[1]["type"], "less_than_equal");
        let detail = issues::<MessageRetentionIn>(
            json!({"account": "a@b.c", "folder": "INBOX", "uid": "7", "uid_validity": "5", "expiration_days": "3"}),
        );
        assert_eq!(detail[0]["loc"], json!(["body", "uid"]));
        assert_eq!(detail[0]["type"], "int_type");
        assert_eq!(detail[1]["loc"], json!(["body", "expiration_days"]));
        assert_eq!(
            issues::<MessageRetentionIn>(
                json!({"account": "a@b.c", "folder": "INBOX", "uid": 7, "uid_validity": "5", "expiration_days": 5.0})
            )[0]["type"],
            "int_type"
        );
        assert_eq!(
            issues::<MessageRetentionIn>(
                json!({"account": "a@b.c", "folder": "INBOX", "uid": 0, "uid_validity": "9999999999"})
            ),
            json!([
                {"type": "greater_than_equal", "loc": ["body", "uid"], "msg": "Input should be greater than or equal to 1", "input": 0, "ctx": {"ge": 1}},
                {"type": "value_error", "loc": ["body", "uid_validity"], "msg": "Value error, UID validity must be a positive 32-bit integer string", "input": "9999999999", "ctx": {"error": {}}},
            ])
        );
    }

    #[test]
    fn classify_and_sender_rule_models() {
        let detail = issues::<MessageClassifyIn>(
            json!({"account": "a@b.c", "folder": "INBOX", "uid": 4294967296u64, "uid_validity": "5", "category": "updates"}),
        );
        assert_eq!(
            detail,
            json!([
                {"type": "less_than_equal", "loc": ["body", "uid"], "msg": "Input should be less than or equal to 4294967295", "input": 4294967296u64, "ctx": {"le": 4294967295u64}},
                {"type": "extra_forbidden", "loc": ["body", "category"], "msg": "Extra inputs are not permitted", "input": "updates"},
            ])
        );
        let base = json!({"account": "a@b.c", "folder": "INBOX", "uid": 7, "uid_validity": "5"});
        assert_eq!(
            issues::<MessageSenderRuleIn>(base.clone()),
            json!([
                {"type": "missing", "loc": ["body", "category"], "msg": "Field required", "input": base},
            ])
        );
        let detail = issues::<MessageSenderRuleIn>(
            json!({"account": "a@b.c", "folder": "INBOX", "uid": 7, "uid_validity": "5", "category": "updates", "expected_category_revision": -1, "x": 1}),
        );
        assert_eq!(
            detail,
            json!([
                {"type": "greater_than_equal", "loc": ["body", "expected_category_revision"], "msg": "Input should be greater than or equal to 0", "input": -1, "ctx": {"ge": 0}},
                {"type": "extra_forbidden", "loc": ["body", "x"], "msg": "Extra inputs are not permitted", "input": 1},
            ])
        );
        let rule = MessageSenderRuleIn::from_json(&json!({"account": "a@b.c", "folder": "INBOX", "uid": 7, "uid_validity": "5", "category": "updates", "expected_category_revision": null})).unwrap();
        assert_eq!(rule.category, "updates");
        assert_eq!(rule.expected_category_revision, None);
        let detail = issues::<MessageClassifyIn>(
            json!({"account": "a@b.c", "folder": "INBOX", "uid": 7, "uid_validity": "0123"}),
        );
        assert_eq!(
            detail,
            json!([{"type": "string_pattern_mismatch", "loc": ["body", "uid_validity"],
            "msg": "String should match pattern '^[1-9][0-9]{0,9}$'", "input": "0123", "ctx": {"pattern": "^[1-9][0-9]{0,9}$"}}])
        );
    }

    // -- DeleteMessagesIn --------------------------------------------------------

    #[test]
    fn delete_messages_validation() {
        let body = |uids: Value| json!({"account": "a@b.c", "folder": "INBOX", "uids": uids});
        let parsed = DeleteMessagesIn::from_json(&body(json!([7, 11, 7]))).unwrap();
        assert_eq!(parsed.uids, [7, 11]);
        assert_eq!(parsed.trash, "");
        let max: Vec<u32> = (1..=500).collect();
        assert_eq!(
            DeleteMessagesIn::from_json(&body(json!(max)))
                .unwrap()
                .uids
                .len(),
            500
        );
        for uids in [
            json!([]),
            json!([0]),
            json!([-1]),
            json!([true]),
            json!([1.5]),
            json!(["7"]),
            json!([4294967296u64]),
            json!((1..=501).collect::<Vec<_>>()),
        ] {
            assert!(
                DeleteMessagesIn::from_json(&body(uids.clone())).is_err(),
                "{uids}"
            );
        }
        assert_eq!(
            issues::<DeleteMessagesIn>(body(json!([]))),
            json!([{"type": "too_short", "loc": ["body", "uids"],
            "msg": "List should have at least 1 item after validation, not 0", "input": [], "ctx": {"field_type": "List", "min_length": 1, "actual_length": 0}}])
        );
        let detail =
            issues::<DeleteMessagesIn>(body(json!([0, -1, true, 1.5, "7", 4294967296u64, 1.0])));
        let summary: Vec<(Value, Value)> = detail
            .as_array()
            .unwrap()
            .iter()
            .map(|i| (i["loc"][2].clone(), i["type"].clone()))
            .collect();
        assert_eq!(
            summary,
            vec![
                (json!(0), json!("greater_than_equal")),
                (json!(1), json!("greater_than_equal")),
                (json!(2), json!("int_type")),
                (json!(3), json!("int_type")),
                (json!(4), json!("int_type")),
                (json!(5), json!("less_than_equal")),
                (json!(6), json!("int_type")),
            ]
        );
        let too_long = issues::<DeleteMessagesIn>(body(json!(vec!["x"; 502])));
        assert_eq!(too_long.as_array().unwrap().len(), 1);
        assert_eq!(
            too_long[0]["msg"],
            "List should have at most 500 items after validation, not 502"
        );
        assert_eq!(
            too_long[0]["ctx"],
            json!({"field_type": "List", "max_length": 500, "actual_length": 502})
        );
        assert_eq!(
            issues::<DeleteMessagesIn>(body(json!("7")))[0]["type"],
            "list_type"
        );
        let mut with_validity = body(json!([7]));
        with_validity["uid_validity"] = json!("4294967296");
        assert_eq!(
            issues::<DeleteMessagesIn>(with_validity.clone())[0]["msg"],
            "Value error, UID validity must be a positive 32-bit integer string"
        );
        with_validity["uid_validity"] = json!(5);
        assert_eq!(
            issues::<DeleteMessagesIn>(with_validity.clone())[0]["type"],
            "string_type"
        );
        with_validity["uid_validity"] = json!(null);
        with_validity["trash"] = json!(null);
        assert_eq!(
            issues::<DeleteMessagesIn>(with_validity)[0]["loc"],
            json!(["body", "trash"])
        );
    }

    // -- Remaining small models ----------------------------------------------

    #[test]
    fn small_models() {
        let image = RemoteImageIn::from_json(
            &json!({"account": "a@b.c", "folder": "INBOX", "uid": 7.0, "url": "x", "retry": 1}),
        )
        .unwrap();
        assert_eq!((image.uid, image.retry), (7, true));
        assert_eq!(
            issues::<RemoteImageIn>(
                json!({"account": "a@b.c", "folder": "INBOX", "uid": "7", "url": "", "retry": "yes", "zzz": 1})
            ),
            json!([{"type": "string_too_short", "loc": ["body", "url"], "msg": "String should have at least 1 character", "input": "", "ctx": {"min_length": 1}}])
        );
        for archive in [json!("true"), json!(1)] {
            assert_eq!(
                issues::<TrashPrepareIn>(
                    json!({"account": "a@b.c", "folder": "INBOX", "archive": archive.clone()})
                ),
                json!([{"type": "bool_type", "loc": ["body", "archive"], "msg": "Input should be a valid boolean", "input": archive}])
            );
        }
        assert!(TrashPrepareIn::from_json(
            &json!({"account": "a@b.c", "folder": "INBOX", "archive": false})
        )
        .is_ok());
        assert_eq!(
            issues::<TrashEmptyIn>(json!({"account": "a@b.c", "folder": "x"}))[0]["type"],
            "extra_forbidden"
        );
        assert_eq!(
            issues::<PasteAuditIn>(json!({"content": ""}))[0]["type"],
            "string_too_short"
        );
        assert_eq!(
            issues::<PasteAuditIn>(json!({"content": 5}))[0]["type"],
            "string_type"
        );
        assert_eq!(
            PasteAuditIn::from_json(&json!({"content": "x", "other": 1}))
                .unwrap()
                .content,
            "x"
        );
    }

    // -- SendIn / SendUploadIn -------------------------------------------------

    #[test]
    fn send_upload_metadata() {
        assert_eq!(
            issues::<SendUploadIn>(json!({"disposition": "inline"})),
            json!([{"type": "value_error", "loc": ["body"],
            "msg": "Value error, Inline images require a valid content ID", "input": {"disposition": "inline"}, "ctx": {"error": {}}}])
        );
        assert!(
            SendUploadIn::from_json(&json!({"disposition": "inline", "content_id": "img1@x"}))
                .unwrap()
                .is_inline()
        );
        assert_eq!(
            issues::<SendUploadIn>(json!({"disposition": "attachment", "content_id": "abc"}))[0]
                ["msg"],
            "Value error, Ordinary attachments cannot have an inline content ID"
        );
        assert_eq!(
            issues::<SendUploadIn>(json!({"disposition": "other"})),
            json!([{"type": "literal_error", "loc": ["body", "disposition"],
            "msg": "Input should be 'attachment' or 'inline'", "input": "other", "ctx": {"expected": "'attachment' or 'inline'"}}])
        );
    }

    #[test]
    fn send_validation() {
        let minimal = SendIn::from_json(&json!({"account": "a@b.c"})).unwrap();
        assert!(minimal.to.is_empty() && minimal.uploads.is_empty() && minimal.subject.is_empty());
        assert_eq!(
            issues::<SendIn>(
                json!({"account": "a@b.c\n", "subject": "x\r", "to": ["bad", 5, "Name <a@b.com>"], "cc": "x"})
            ),
            json!([
                {"type": "value_error", "loc": ["body", "account"], "msg": "Value error, Mail headers cannot contain control characters", "input": "a@b.c\n", "ctx": {"error": {}}},
                {"type": "string_type", "loc": ["body", "to", 1], "msg": "Input should be a valid string", "input": 5},
                {"type": "list_type", "loc": ["body", "cc"], "msg": "Input should be a valid list", "input": "x"},
                {"type": "value_error", "loc": ["body", "subject"], "msg": "Value error, Mail headers cannot contain control characters", "input": "x\r", "ctx": {"error": {}}},
            ])
        );
        assert_eq!(
            issues::<SendIn>(json!({"account": "a@b.c", "to": ["bad", "a@b.com", "x y <z>"]})),
            json!([{"type": "value_error", "loc": ["body", "to"], "msg": "Value error, Each recipient must contain one email address",
                    "input": ["bad", "a@b.com", "x y <z>"], "ctx": {"error": {}}}])
        );
        let body =
            json!({"account": "a@b.c", "to": vec!["a@b.com"; 60], "cc": vec!["c@d.com"; 41]});
        assert_eq!(
            issues::<SendIn>(body.clone()),
            json!([{"type": "value_error", "loc": ["body"],
            "msg": "Value error, Send to no more than 100 recipients", "input": body, "ctx": {"error": {}}}])
        );
        assert_eq!(
            issues::<SendIn>(json!({"account": "a@b.c", "to": vec!["bad"; 101]}))[0]["type"],
            "too_long"
        );
        let big = json!({"account": "a@b.c", "to": ["a@b.com"], "text": "x".repeat(1024 * 1024), "html": "y"});
        assert_eq!(
            issues::<SendIn>(big)[0]["msg"],
            "Value error, Message text and HTML must total no more than 1 MiB"
        );
        let exact = json!({"account": "a@b.c", "to": ["a@b.com"], "text": "x".repeat(1024 * 1024 - 2), "html": "\u{e9}"});
        assert!(SendIn::from_json(&exact).is_ok());
        let duplicate = json!({"account": "a@b.c", "to": ["a@b.com", "a@b.com"], "uploads": [
            {"disposition": "inline", "content_id": "c1"}, {"disposition": "inline", "content_id": "c1"}]});
        assert_eq!(
            issues::<SendIn>(duplicate)[0]["msg"],
            "Value error, Inline image content IDs must be unique"
        );
        assert_eq!(
            issues::<SendIn>(
                json!({"account": "a@b.c", "uploads": [{"disposition": "inline"}, {"disposition": "attachment", "content_id": "c1", "x": 1}]})
            ),
            json!([
                {"type": "value_error", "loc": ["body", "uploads", 0], "msg": "Value error, Inline images require a valid content ID", "input": {"disposition": "inline"}, "ctx": {"error": {}}},
                {"type": "extra_forbidden", "loc": ["body", "uploads", 1, "x"], "msg": "Extra inputs are not permitted", "input": 1},
            ])
        );
        let detail = issues::<SendIn>(json!({"account": "a@b.c", "uploads": ["x", 5, null, {}]}));
        assert_eq!(detail.as_array().unwrap().len(), 3);
        assert_eq!(detail[2]["loc"], json!(["body", "uploads", 2]));
        assert_eq!(detail[0]["type"], "model_attributes_type");
        assert_eq!(
            issues::<SendIn>(
                json!({"account": "a@b.c", "uploads": vec![json!({"disposition": "attachment"}); 21]})
            )[0]["msg"],
            "List should have at most 20 items after validation, not 21"
        );
        assert_eq!(
            issues::<SendIn>(json!({"account": "a@b.c", "to": ["a@b.com"], "text": null}))[0]
                ["loc"],
            json!(["body", "text"])
        );
        assert_eq!(
            issues::<SendIn>(json!({"account": "ab"}))[0]["type"],
            "string_too_short"
        );
    }

    // -- recipient_address (cases evaluated with the Python original) ---------

    #[test]
    fn recipient_address_matches_python() {
        let cases: &[(&str, std::result::Result<&str, &str>)] = &[
            ("a@b.com", Ok("a@b.com")),
            ("Name <a@b.com>", Ok("a@b.com")),
            ("\"Quoted, Name\" <a@b.com>", Ok("a@b.com")),
            ("Ren\u{e9}e <renee@example.com>", Ok("renee@example.com")),
            ("bad", Err(NOT_ONE_ADDRESS)),
            ("", Err(NOT_ONE_ADDRESS)),
            (" ", Err(NOT_ONE_ADDRESS)),
            ("a@b.com, c@d.com", Err(NOT_ONE_ADDRESS)),
            ("a@b.com; c@d.com", Err(NOT_ONE_ADDRESS)),
            ("Group: a@b.com;", Err(NOT_ONE_ADDRESS)),
            ("Group:;", Err(NOT_ONE_ADDRESS)),
            ("<a@b.com>", Ok("a@b.com")),
            ("  a@b.com  ", Ok("a@b.com")),
            ("a@b@c.com", Err(NOT_ONE_ADDRESS)),
            ("\"a@b\"@c.com", Err(INVALID_ADDRESS)),
            ("\"john doe\"@x.com", Err(INVALID_ADDRESS)),
            ("\"john\"@x.com", Ok("john@x.com")),
            ("john.doe@x.com", Ok("john.doe@x.com")),
            ("john..doe@x.com", Err(NOT_ONE_ADDRESS)),
            (".john@x.com", Err(NOT_ONE_ADDRESS)),
            ("john.@x.com", Err(NOT_ONE_ADDRESS)),
            ("a@b.com (Comment)", Ok("a@b.com")),
            ("(Comment) a@b.com", Ok("a@b.com")),
            ("Name (c) <a@b.com>", Ok("a@b.com")),
            ("a@[1.2.3.4]", Ok("a@[1.2.3.4]")),
            ("a@[IPv6:::1]", Ok("a@[IPv6:::1]")),
            ("a@[ipv6:2001:db8::1]", Ok("a@[ipv6:2001:db8::1]")),
            ("a@[300.1.1.1]", Err(INVALID_DOMAIN)),
            ("a@[foo]", Err(INVALID_DOMAIN)),
            ("a@b..com", Err(NOT_ONE_ADDRESS)),
            ("a@-b.com", Err(INVALID_DOMAIN)),
            ("a@b-.com", Err(INVALID_DOMAIN)),
            ("a@b_c.com", Err(INVALID_DOMAIN)),
            ("a@b.com.", Err(NOT_ONE_ADDRESS)),
            ("a@localhost", Ok("a@localhost")),
            ("a@m\u{fc}nchen.de", Ok("a@m\u{fc}nchen.de")),
            ("a@xn--mnchen-3ya.de", Ok("a@xn--mnchen-3ya.de")),
            ("Name <a@b.com", Err(NOT_ONE_ADDRESS)),
            ("Name a@b.com>", Err(NOT_ONE_ADDRESS)),
            ("Name <a@b.com> trailing", Err(NOT_ONE_ADDRESS)),
            ("<a@b.com> <c@d.com>", Err(NOT_ONE_ADDRESS)),
            ("Name <>", Err(NOT_ONE_ADDRESS)),
            ("a b@c.com", Err(NOT_ONE_ADDRESS)),
            ("a\u{8}@c.com", Err(CONTROL_MESSAGE)),
            ("\"a\\\"b\"@c.com", Err(INVALID_ADDRESS)),
            ("a<b@c.com", Err(NOT_ONE_ADDRESS)),
            ("a@b.c", Ok("a@b.c")),
            ("@b.com", Err(NOT_ONE_ADDRESS)),
            ("a@", Err(NOT_ONE_ADDRESS)),
            ("a@b.com\r\nBcc: x@y.com", Err(CONTROL_MESSAGE)),
            ("\"Na\u{1}me\" <a@b.com>", Err(CONTROL_MESSAGE)),
            ("=?utf-8?q?Name?= <a@b.com>", Ok("a@b.com")),
            ("Name: <a@b.com>", Err(NOT_ONE_ADDRESS)),
            (
                "first.last+tag@sub.example.co.uk",
                Ok("first.last+tag@sub.example.co.uk"),
            ),
            ("a@b.com,", Ok("a@b.com")),
            (",a@b.com", Err(NOT_ONE_ADDRESS)),
            ("Name, Other <a@b.com>", Err(NOT_ONE_ADDRESS)),
            ("Mr. Smith <a@b.com>", Err(NOT_ONE_ADDRESS)),
            ("\"unterminated <a@b.com>", Err(NOT_ONE_ADDRESS)),
            ("a@(comment)b.com", Ok("a@b.com")),
            ("a(c)@b.com", Ok("a@b.com")),
            ("Name <a@[1.2.3.4]>", Ok("a@[1.2.3.4]")),
            ("a@1.2.3.4", Ok("a@1.2.3.4")),
            ("a@b.com >", Err(NOT_ONE_ADDRESS)),
            ("<<a@b.com>>", Err(NOT_ONE_ADDRESS)),
            ("Na<me <a@b.com>", Err(NOT_ONE_ADDRESS)),
            ("user%host@example.com", Ok("user%host@example.com")),
            ("user!x@example.com", Ok("user!x@example.com")),
            ("\"\"@example.com", Err(INVALID_ADDRESS)),
            ("a@[]", Err(INVALID_DOMAIN)),
            ("a@[IPv6:1.2.3.4]", Ok("a@[IPv6:1.2.3.4]")),
            ("a@[1.2.3.4%eth0]", Err(INVALID_DOMAIN)),
            ("a@[IPv6:fe80::1%eth0]", Ok("a@[IPv6:fe80::1%eth0]")),
            ("\u{e9}@example.com", Err(NOT_ONE_ADDRESS)),
            ("a@exa mple.com", Err(NOT_ONE_ADDRESS)),
            ("Name <a @b.com>", Ok("a@b.com")),
            ("a@b.com\t", Err(CONTROL_MESSAGE)),
            ("=?utf-8?q?a=0Db?= <a@b.com>", Err(INVALID_ADDRESS)),
            ("=?utf-8?q?Na=01me?= <a@b.com>", Err(NOT_ONE_ADDRESS)),
            ("=?utf-8?q?a?= @b.com", Ok("a@b.com")),
            ("=?utf-8?q?a?=@b.com", Err(NOT_ONE_ADDRESS)),
            ("=?iso-8859-1?q?Ren=E9?= <a@b.com>", Ok("a@b.com")),
            ("=?utf-8?b?UmVuw6k=?= <a@b.com>", Ok("a@b.com")),
            ("=?utf-8?b?UmVuw6k?= <a@b.com>", Err(NOT_ONE_ADDRESS)),
            ("\"Ren=?utf-8?q?x?=\" <a@b.com>", Ok("a@b.com")),
            ("a@b.com (unclosed", Err(NOT_ONE_ADDRESS)),
            ("Name <a@b.com> (c)", Ok("a@b.com")),
            ("<@route:a@b.com>", Err(NOT_ONE_ADDRESS)),
            ("a@b . com", Err(NOT_ONE_ADDRESS)),
            ("a . b@c.com", Err(NOT_ONE_ADDRESS)),
            ("\"a\" . b@c.com", Err(NOT_ONE_ADDRESS)),
            ("a@b.com;", Err(NOT_ONE_ADDRESS)),
            (":a@b.com", Err(NOT_ONE_ADDRESS)),
            ("=?utf-8?q?x?= =?utf-8?q?y?= <a@b.com>", Ok("a@b.com")),
            ("=?gb2312?b?xOO6ww==?= <a@b.com>", Ok("a@b.com")),
            ("=?utf-8?q??= <a@b.com>", Ok("a@b.com")),
            ("=?bad?= <a@b.com>", Ok("a@b.com")),
            ("=?utf-8?x?abc?= <a@b.com>", Ok("a@b.com")),
            ("\"\" <a@b.com>", Ok("a@b.com")),
            ("(c)", Err(NOT_ONE_ADDRESS)),
            ("a@b.com,,", Err(NOT_ONE_ADDRESS)),
            ("\"a b\" <c@d.com>", Ok("c@d.com")),
            ("a@[1.2.3.4] ", Ok("a@[1.2.3.4]")),
            ("a@[ 1.2.3.4 ]", Ok("a@[1.2.3.4]")),
            ("a@[1.2.3.4\\]]", Err(INVALID_DOMAIN)),
            ("x@y.com, ", Err(NOT_ONE_ADDRESS)),
            ("  ,a@b.com", Err(NOT_ONE_ADDRESS)),
            ("a@b.com (x) (y)", Ok("a@b.com")),
            ("a.\"b\"@c.com", Err(NOT_ONE_ADDRESS)),
            ("<a@b.com", Err(NOT_ONE_ADDRESS)),
            ("Name <a@b.com>>", Err(NOT_ONE_ADDRESS)),
            ("a@b.com <c@d.com>", Err(NOT_ONE_ADDRESS)),
            ("Ann <a@b.com>, ", Err(NOT_ONE_ADDRESS)),
            ("\u{a0}a@b.com", Err(NOT_ONE_ADDRESS)),
            ("a@b.com\u{a0}", Ok("a@b.com")),
            ("a@b\u{3002}com", Ok("a@b\u{3002}com")),
            ("a@B\u{dc}CHER.de", Ok("a@B\u{dc}CHER.de")),
            ("a@xn--.com", Err(INVALID_DOMAIN)),
            ("a@_x.com", Err(INVALID_DOMAIN)),
            ("=?utf-8?q?=E2=80=AE?= <a@b.com>", Ok("a@b.com")),
            ("a\\@b.com", Err(NOT_ONE_ADDRESS)),
            ("a@b\\.com", Err(NOT_ONE_ADDRESS)),
            ("\"a\\\"b\" <a@b.com>", Ok("a@b.com")),
            ("Name <a@b.com> x", Err(NOT_ONE_ADDRESS)),
            ("a@b.com x", Err(NOT_ONE_ADDRESS)),
            // Python raises AttributeError for these; the port rejects them.
            ("a@[", Err(INVALID_ADDRESS)),
            ("a@[1.2.3.4", Err(INVALID_ADDRESS)),
            ("G: a@b.com; x", Err(INVALID_ADDRESS)),
            ("G:;x@y.com", Err(INVALID_ADDRESS)),
        ];
        let mut failures = Vec::new();
        for (input, expected) in cases {
            let actual = recipient_address(input);
            let expected = expected.map(str::to_string).map_err(str::to_string);
            if actual != expected {
                failures.push(format!("{input:?}: expected {expected:?}, got {actual:?}"));
            }
        }
        assert!(failures.is_empty(), "{}", failures.join("\n"));
        let long = format!("{}@b.com", "x".repeat(993));
        assert_eq!(recipient_address(&long).unwrap_err(), CONTROL_MESSAGE);
        let long_label = format!("a@{}.com", "a".repeat(64));
        assert_eq!(recipient_address(&long_label).unwrap_err(), INVALID_DOMAIN);
        let long_domain = format!("a@{}.com", vec!["abcdefghi"; 26].join("."));
        assert_eq!(recipient_address(&long_domain).unwrap_err(), INVALID_DOMAIN);
    }
}
