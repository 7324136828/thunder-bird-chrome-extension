//! FastAPI-compatible request extractors.
//!
//! The copied React frontend only looks at `detail`, but tests and MCP clients
//! compare full error bodies, so request parsing reproduces FastAPI/pydantic v2:
//!
//! * [`JsonBody`] / [`JsonObject`] read a JSON request body exactly like
//!   FastAPI's `get_request_handler`: empty or `null` bodies are a 422
//!   `missing` issue at `["body"]`, malformed JSON is a 422 `json_invalid`
//!   issue at `["body", <char position>]`, an undecodable body is a 400
//!   `"There was an error parsing the body"`, and a non-JSON or absent
//!   `Content-Type` is handed to model validation as raw text
//!   (`model_attributes_type`; FastAPI's default `strict_content_type=True`).
//! * [`QueryParams`] parses the query string like Starlette (`parse_qsl`,
//!   blank values kept, repeated keys preserved) and [`QueryValidator`]
//!   applies `Query(...)` constraints (`ge`/`le`/`min_length`/`max_length`/
//!   `Literal`) producing issues at `["query", name]`.
//!
//! These extractors are deliberately generic (they yield `serde_json` values);
//! field-level validation of request models lives in `mail_core::schemas`.
//!
//! # How routes combine them
//!
//! FastAPI resolves a route's dependencies before the route's own parameters:
//! `require_account` (query `account`) runs first and raises the 401
//! `password_required` *before* the remaining query parameters are validated,
//! but when `account` itself is missing its issue is reported together with
//! the other parameter issues. Port such a route like this:
//!
//! ```ignore
//! async fn get_message(
//!     State(state): State<AppState>,
//!     query: QueryParams,
//! ) -> ApiResult<Json<Value>> {
//!     let mut q = query.validator();
//!     // Dependency: require_account(account: str)
//!     if let Some(email) = q.string("account").required() {
//!         // 401 now, exactly like the dependency raising HTTPException.
//!         state.sessions.require(&email)?;
//!     }
//!     // Endpoint parameters, in declaration order.
//!     let folder = q.string("folder").max_length(500).default("INBOX");
//!     let uid = q.integer("uid").ge(1).required();
//!     let mark_seen = q.boolean("mark_seen").default(true);
//!     q.finish()?; // 422 with every collected issue
//!     let uid = uid.expect("validated");
//!     /* ... run_blocking(move || mail_core::imap::fetch_message(...)).await ... */
//! }
//! ```
//!
//! Body routes take `JsonObject(body)` (the 422s above are produced before the
//! handler runs) and then validate the fields with the request-model helpers
//! in `mail_core::schemas`, returning `MailError` / `ApiError` 422s.

use axum::body::Bytes;
use axum::extract::{FromRequest, FromRequestParts, Request};
use axum::http::request::Parts;
use axum::http::{header, HeaderMap, StatusCode};
use serde_json::{json, Map, Value};

use crate::error::ApiError;

/// Python `HTTPException(400, "There was an error parsing the body")`.
pub const BODY_PARSE_ERROR: &str = "There was an error parsing the body";

// ---------------------------------------------------------------------------
// Issue builders (pydantic v2 wording)
// ---------------------------------------------------------------------------

/// `{"type","loc","msg","input"}` plus `ctx` when given.
pub fn issue(type_: &str, loc: Vec<Value>, msg: impl Into<String>, input: Value) -> Value {
    json!({ "type": type_, "loc": loc, "msg": msg.into(), "input": input })
}

/// [`issue`] with a `ctx` object.
pub fn issue_with_ctx(
    type_: &str,
    loc: Vec<Value>,
    msg: impl Into<String>,
    input: Value,
    ctx: Value,
) -> Value {
    let mut value = issue(type_, loc, msg, input);
    value["ctx"] = ctx;
    value
}

/// pydantic `missing`: `"Field required"`, `input` = the parent (or `null`).
pub fn missing_issue(loc: Vec<Value>, input: Value) -> Value {
    issue("missing", loc, "Field required", input)
}

fn plural(count: usize) -> &'static str {
    if count == 1 {
        ""
    } else {
        "s"
    }
}

/// pydantic `string_too_short`.
pub fn string_too_short_issue(loc: Vec<Value>, input: &str, min_length: usize) -> Value {
    issue_with_ctx(
        "string_too_short",
        loc,
        format!(
            "String should have at least {min_length} character{}",
            plural(min_length)
        ),
        Value::from(input),
        json!({ "min_length": min_length }),
    )
}

/// pydantic `string_too_long`.
pub fn string_too_long_issue(loc: Vec<Value>, input: &str, max_length: usize) -> Value {
    issue_with_ctx(
        "string_too_long",
        loc,
        format!(
            "String should have at most {max_length} character{}",
            plural(max_length)
        ),
        Value::from(input),
        json!({ "max_length": max_length }),
    )
}

/// pydantic `literal_error` (`"Input should be 'a', 'b' or 'c'"`).
pub fn literal_issue(loc: Vec<Value>, input: Value, choices: &[&str]) -> Value {
    let quoted: Vec<String> = choices.iter().map(|choice| format!("'{choice}'")).collect();
    let expected = match quoted.split_last() {
        None => String::new(),
        Some((last, [])) => last.clone(),
        Some((last, rest)) => format!("{} or {last}", rest.join(", ")),
    };
    issue_with_ctx(
        "literal_error",
        loc,
        format!("Input should be {expected}"),
        input,
        json!({ "expected": expected }),
    )
}

// ---------------------------------------------------------------------------
// JSON bodies
// ---------------------------------------------------------------------------

/// The request body parsed like FastAPI parses a pydantic-model body.
///
/// Rejections (as [`ApiError`]):
/// * empty body or JSON `null` → 422 `[{"type":"missing","loc":["body"],"msg":"Field required","input":null}]`
/// * malformed JSON → 422 `[{"type":"json_invalid","loc":["body",pos],"msg":"JSON decode error","input":{},"ctx":{"error":...}}]`
/// * non-UTF-8 JSON, unreadable body → 400 `{"detail":"There was an error parsing the body"}`
/// * non-JSON, absent or empty `Content-Type` → 422 `model_attributes_type`
///   with the body text as `input` (FastAPI's `strict_content_type=True`)
///
/// Any other JSON value (object, array, number, ...) is passed through.
#[derive(Debug, Clone, PartialEq)]
pub struct JsonBody(pub Value);

/// Like [`JsonBody`] but additionally requires a JSON object (pydantic's
/// `model_attributes_type` for anything else), which is what every request
/// model in main.py expects.
#[derive(Debug, Clone, PartialEq)]
pub struct JsonObject(pub Map<String, Value>);

impl<S: Send + Sync> FromRequest<S> for JsonBody {
    type Rejection = ApiError;

    async fn from_request(request: Request, state: &S) -> Result<Self, Self::Rejection> {
        let content_type = content_type_of(request.headers());
        let bytes = Bytes::from_request(request, state)
            .await
            .map_err(|rejection| {
                if rejection.status() == StatusCode::PAYLOAD_TOO_LARGE {
                    ApiError::payload_too_large("Request exceeds maximum allowed size")
                } else {
                    ApiError::bad_request(BODY_PARSE_ERROR)
                }
            })?;
        parse_model_body(content_type.as_deref(), &bytes).map(JsonBody)
    }
}

impl<S: Send + Sync> FromRequest<S> for JsonObject {
    type Rejection = ApiError;

    async fn from_request(request: Request, state: &S) -> Result<Self, Self::Rejection> {
        let JsonBody(value) = JsonBody::from_request(request, state).await?;
        match value {
            Value::Object(object) => Ok(JsonObject(object)),
            other => Err(ApiError::validation(vec![model_attributes_issue(other)])),
        }
    }
}

fn content_type_of(headers: &HeaderMap) -> Option<String> {
    headers
        .get(header::CONTENT_TYPE)
        .map(|value| String::from_utf8_lossy(value.as_bytes()).into_owned())
}

fn model_attributes_issue(input: Value) -> Value {
    issue(
        "model_attributes_type",
        vec![json!("body")],
        "Input should be a valid dictionary or object to extract fields from",
        input,
    )
}

/// What FastAPI hands to body validation for these request bytes.
#[derive(Debug, Clone, PartialEq)]
pub enum RawBody {
    /// No body bytes (validated as missing).
    Missing,
    /// Decoded JSON (may be `null`).
    Json(Value),
    /// A non-JSON content type: the raw bytes.
    Bytes(Bytes),
}

/// Python `email.message.Message().get_content_type()` semantics: the part
/// before `;`, lowercased; anything without exactly one `/` is `text/plain`.
fn is_json_content_type(content_type: &str) -> bool {
    let essence = content_type
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    if essence.matches('/').count() != 1 {
        return false;
    }
    let (main, sub) = essence.split_once('/').unwrap_or_default();
    main == "application" && (sub == "json" || sub.ends_with("+json"))
}

/// FastAPI's body decoding (`fastapi.routing.get_request_handler` with the
/// default `strict_content_type=True`): only an `application/json` or
/// `application/*+json` body is decoded; a body without (or with an empty)
/// `Content-Type` is handed to validation as raw bytes, which a model body
/// rejects with `model_attributes_type`. An empty body is always missing.
pub fn decode_body(content_type: Option<&str>, bytes: &Bytes) -> Result<RawBody, ApiError> {
    if bytes.is_empty() {
        return Ok(RawBody::Missing);
    }
    let parse_json = content_type.is_some_and(is_json_content_type);
    if !parse_json {
        return Ok(RawBody::Bytes(bytes.clone()));
    }
    // json.loads(bytes) accepts a UTF-8 BOM; other decode failures are not
    // JSONDecodeError and become FastAPI's generic 400.
    let raw = bytes.strip_prefix(b"\xef\xbb\xbf").unwrap_or(bytes);
    let text = std::str::from_utf8(raw).map_err(|_| ApiError::bad_request(BODY_PARSE_ERROR))?;
    serde_json::from_str::<Value>(text)
        .map(RawBody::Json)
        .map_err(|error| json_invalid(text, &error))
}

/// [`decode_body`] followed by the checks FastAPI applies to a required model
/// body (see [`JsonBody`]).
pub fn parse_model_body(content_type: Option<&str>, bytes: &Bytes) -> Result<Value, ApiError> {
    match decode_body(content_type, bytes)? {
        RawBody::Missing | RawBody::Json(Value::Null) => {
            Err(ApiError::validation(vec![missing_issue(
                vec![json!("body")],
                Value::Null,
            )]))
        }
        RawBody::Json(value) => Ok(value),
        RawBody::Bytes(raw) => Err(ApiError::validation(vec![model_attributes_issue(
            Value::from(String::from_utf8_lossy(&raw).into_owned()),
        )])),
    }
}

/// 422 `json_invalid` with Python's `JSONDecodeError.pos` and message.
fn json_invalid(text: &str, error: &serde_json::Error) -> ApiError {
    let position = char_position(text, error.line(), error.column());
    ApiError::validation(vec![issue_with_ctx(
        "json_invalid",
        vec![json!("body"), json!(position)],
        "JSON decode error",
        json!({}),
        json!({ "error": python_json_message(error) }),
    )])
}

/// Character offset of serde_json's (1-based line, 1-based byte column).
fn char_position(text: &str, line: usize, column: usize) -> usize {
    let mut byte_offset = 0;
    for (index, segment) in text.split('\n').enumerate() {
        if index + 1 == line {
            byte_offset += column.saturating_sub(1).min(segment.len());
            break;
        }
        byte_offset += segment.len() + 1;
    }
    let mut boundary = byte_offset.min(text.len());
    while !text.is_char_boundary(boundary) {
        boundary -= 1;
    }
    text[..boundary].chars().count()
}

/// Best-effort translation of serde_json's message to Python `json` wording.
fn python_json_message(error: &serde_json::Error) -> &'static str {
    let message = error.to_string();
    let message = message
        .rsplit_once(" at line ")
        .map(|(head, _)| head)
        .unwrap_or(&message);
    match message {
        "key must be a string" | "EOF while parsing an object" => {
            "Expecting property name enclosed in double quotes"
        }
        "expected `,` or `}`" | "expected `,` or `]`" | "EOF while parsing a list" => {
            "Expecting ',' delimiter"
        }
        "expected `:`" => "Expecting ':' delimiter",
        "trailing characters" | "trailing comma" => "Extra data",
        "EOF while parsing a string" => "Unterminated string starting at",
        "invalid escape" => "Invalid \\escape",
        "invalid unicode code point" | "lone leading surrogate in hex escape" => {
            "Invalid \\uXXXX escape"
        }
        _ if message.starts_with("control character") => "Invalid control character at",
        _ => "Expecting value",
    }
}

// ---------------------------------------------------------------------------
// Query parameters
// ---------------------------------------------------------------------------

/// The decoded query string (Starlette `parse_qsl(keep_blank_values=True)`):
/// `+` is a space, invalid percent-escapes decode lossily, repeated keys are
/// kept in order. Never rejects.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct QueryParams {
    pairs: Vec<(String, String)>,
}

impl QueryParams {
    /// Parse a raw query string (without the leading `?`).
    pub fn parse(query: &str) -> Self {
        Self {
            pairs: url::form_urlencoded::parse(query.as_bytes())
                .map(|(key, value)| (key.into_owned(), value.into_owned()))
                .collect(),
        }
    }

    /// The value FastAPI uses for a scalar parameter: the **last** occurrence.
    pub fn get(&self, name: &str) -> Option<&str> {
        self.pairs
            .iter()
            .rev()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    }

    /// Every occurrence, in order (for `list[str]` parameters).
    pub fn get_all(&self, name: &str) -> Vec<&str> {
        self.pairs
            .iter()
            .filter(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
            .collect()
    }

    pub fn pairs(&self) -> &[(String, String)] {
        &self.pairs
    }

    /// Start validating parameters against `Query(...)` declarations.
    pub fn validator(&self) -> QueryValidator<'_> {
        QueryValidator::new(self)
    }
}

impl<S: Send + Sync> FromRequestParts<S> for QueryParams {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        Ok(Self::parse(parts.uri.query().unwrap_or_default()))
    }
}

/// Collects FastAPI query-parameter issues in declaration order.
///
/// Typed accessors return `None` (or the default) when a value is missing or
/// invalid and record the issue; call [`QueryValidator::finish`] before using
/// the values. After `finish()` succeeds every `required()` value is `Some`.
#[derive(Debug)]
pub struct QueryValidator<'q> {
    params: &'q QueryParams,
    issues: Vec<Value>,
}

impl<'q> QueryValidator<'q> {
    pub fn new(params: &'q QueryParams) -> Self {
        Self {
            params,
            issues: Vec::new(),
        }
    }

    /// `name: str = Query(...)`.
    pub fn string<'v>(&'v mut self, name: &'static str) -> StrParam<'v, 'q> {
        StrParam {
            validator: self,
            name,
            min_length: None,
            max_length: None,
        }
    }

    /// `name: int = Query(...)`.
    pub fn integer<'v>(&'v mut self, name: &'static str) -> IntParam<'v, 'q> {
        IntParam {
            validator: self,
            name,
            ge: None,
            le: None,
        }
    }

    /// `name: bool = Query(...)`.
    pub fn boolean<'v>(&'v mut self, name: &'static str) -> BoolParam<'v, 'q> {
        BoolParam {
            validator: self,
            name,
        }
    }

    /// `name: Literal[choices...] = Query(...)`.
    pub fn literal<'v>(
        &'v mut self,
        name: &'static str,
        choices: &'static [&'static str],
    ) -> LiteralParam<'v, 'q> {
        LiteralParam {
            validator: self,
            name,
            choices,
        }
    }

    /// `name: list[str] | None = Query(default=None)`: `None` when absent.
    pub fn list(&mut self, name: &'static str) -> Option<Vec<String>> {
        let values = self.params.get_all(name);
        if values.is_empty() {
            None
        } else {
            Some(values.into_iter().map(str::to_string).collect())
        }
    }

    /// Raw last value of a parameter (no validation).
    pub fn raw(&self, name: &str) -> Option<&'q str> {
        self.params.get(name)
    }

    /// Record a custom issue (it is reported in call order).
    pub fn push_issue(&mut self, issue: Value) {
        self.issues.push(issue);
    }

    /// True while no issue has been recorded.
    pub fn is_ok(&self) -> bool {
        self.issues.is_empty()
    }

    pub fn issues(&self) -> &[Value] {
        &self.issues
    }

    pub fn into_issues(self) -> Vec<Value> {
        self.issues
    }

    /// `Ok(())`, or the FastAPI 422 with every recorded issue.
    pub fn finish(self) -> Result<(), ApiError> {
        if self.issues.is_empty() {
            Ok(())
        } else {
            Err(ApiError::validation(self.issues))
        }
    }

    fn loc(name: &str) -> Vec<Value> {
        vec![json!("query"), json!(name)]
    }

    fn missing(&mut self, name: &str) {
        self.issues
            .push(missing_issue(Self::loc(name), Value::Null));
    }
}

/// Builder for a string query parameter.
#[derive(Debug)]
pub struct StrParam<'v, 'q> {
    validator: &'v mut QueryValidator<'q>,
    name: &'static str,
    min_length: Option<usize>,
    max_length: Option<usize>,
}

impl StrParam<'_, '_> {
    /// `min_length=` (counted in Unicode code points, like Python `len`).
    pub fn min_length(mut self, value: usize) -> Self {
        self.min_length = Some(value);
        self
    }

    /// `max_length=` (counted in Unicode code points).
    pub fn max_length(mut self, value: usize) -> Self {
        self.max_length = Some(value);
        self
    }

    fn check(self, value: &str) -> Option<String> {
        let length = value.chars().count();
        let loc = QueryValidator::loc(self.name);
        if let Some(min) = self.min_length.filter(|min| length < *min) {
            self.validator
                .issues
                .push(string_too_short_issue(loc, value, min));
            return None;
        }
        if let Some(max) = self.max_length.filter(|max| length > *max) {
            self.validator
                .issues
                .push(string_too_long_issue(loc, value, max));
            return None;
        }
        Some(value.to_string())
    }

    /// Required parameter (`Query()` with no default).
    pub fn required(self) -> Option<String> {
        match self.validator.params.get(self.name) {
            Some(value) => self.check(value),
            None => {
                let name = self.name;
                self.validator.missing(name);
                None
            }
        }
    }

    /// `str | None = Query(default=None)`.
    pub fn optional(self) -> Option<String> {
        let value = self.validator.params.get(self.name)?;
        self.check(value)
    }

    /// `str = Query(default=...)`; an invalid value yields the default after
    /// recording its issue.
    pub fn default(self, default: &str) -> String {
        match self.validator.params.get(self.name) {
            Some(value) => self.check(value).unwrap_or_else(|| default.to_string()),
            None => default.to_string(),
        }
    }
}

/// Builder for an integer query parameter.
#[derive(Debug)]
pub struct IntParam<'v, 'q> {
    validator: &'v mut QueryValidator<'q>,
    name: &'static str,
    ge: Option<i64>,
    le: Option<i64>,
}

impl IntParam<'_, '_> {
    pub fn ge(mut self, value: i64) -> Self {
        self.ge = Some(value);
        self
    }

    pub fn le(mut self, value: i64) -> Self {
        self.le = Some(value);
        self
    }

    fn check(self, raw: &str) -> Option<i64> {
        let loc = QueryValidator::loc(self.name);
        let Some(number) = parse_lax_int(raw) else {
            self.validator.issues.push(issue(
                "int_parsing",
                loc,
                "Input should be a valid integer, unable to parse string as an integer",
                Value::from(raw),
            ));
            return None;
        };
        if let Some(ge) = self.ge.filter(|ge| number < i128::from(*ge)) {
            self.validator.issues.push(issue_with_ctx(
                "greater_than_equal",
                loc,
                format!("Input should be greater than or equal to {ge}"),
                Value::from(raw),
                json!({ "ge": ge }),
            ));
            return None;
        }
        if let Some(le) = self.le.filter(|le| number > i128::from(*le)) {
            self.validator.issues.push(issue_with_ctx(
                "less_than_equal",
                loc,
                format!("Input should be less than or equal to {le}"),
                Value::from(raw),
                json!({ "le": le }),
            ));
            return None;
        }
        match i64::try_from(number) {
            Ok(value) => Some(value),
            Err(_) => {
                // Python ints are unbounded; this backend caps at i64.
                self.validator.issues.push(issue(
                    "int_parsing",
                    loc,
                    "Input should be a valid integer, unable to parse string as an integer",
                    Value::from(raw),
                ));
                None
            }
        }
    }

    pub fn required(self) -> Option<i64> {
        match self.validator.params.get(self.name) {
            Some(value) => self.check(value),
            None => {
                let name = self.name;
                self.validator.missing(name);
                None
            }
        }
    }

    /// `int | None = Query(default=None, ...)`.
    pub fn optional(self) -> Option<i64> {
        let value = self.validator.params.get(self.name)?;
        self.check(value)
    }

    pub fn default(self, default: i64) -> i64 {
        match self.validator.params.get(self.name) {
            Some(value) => self.check(value).unwrap_or(default),
            None => default,
        }
    }
}

/// pydantic v2 lax `str → int`: surrounding whitespace, an optional sign,
/// `_` between digits, and a `.000` fractional suffix are accepted.
pub fn parse_lax_int(raw: &str) -> Option<i128> {
    let text = raw.trim();
    let text = match text.split_once('.') {
        Some((whole, fraction)) if fraction.chars().all(|c| c == '0') => whole,
        Some(_) => return None,
        None => text,
    };
    let (negative, digits) = match text.as_bytes().first()? {
        b'-' => (true, &text[1..]),
        b'+' => (false, &text[1..]),
        _ => (false, text),
    };
    if digits.is_empty()
        || digits.starts_with('_')
        || digits.ends_with('_')
        || digits.contains("__")
        || !digits.chars().all(|c| c.is_ascii_digit() || c == '_')
    {
        return None;
    }
    let cleaned: String = digits.chars().filter(|c| *c != '_').collect();
    let magnitude: i128 = cleaned.parse().ok()?;
    Some(if negative { -magnitude } else { magnitude })
}

/// Builder for a boolean query parameter.
#[derive(Debug)]
pub struct BoolParam<'v, 'q> {
    validator: &'v mut QueryValidator<'q>,
    name: &'static str,
}

impl BoolParam<'_, '_> {
    fn check(self, raw: &str) -> Option<bool> {
        match parse_lax_bool(raw) {
            Some(value) => Some(value),
            None => {
                self.validator.issues.push(issue(
                    "bool_parsing",
                    QueryValidator::loc(self.name),
                    "Input should be a valid boolean, unable to interpret input",
                    Value::from(raw),
                ));
                None
            }
        }
    }

    pub fn required(self) -> Option<bool> {
        match self.validator.params.get(self.name) {
            Some(value) => self.check(value),
            None => {
                let name = self.name;
                self.validator.missing(name);
                None
            }
        }
    }

    pub fn default(self, default: bool) -> bool {
        match self.validator.params.get(self.name) {
            Some(value) => self.check(value).unwrap_or(default),
            None => default,
        }
    }
}

/// pydantic v2 lax `str → bool`.
pub fn parse_lax_bool(raw: &str) -> Option<bool> {
    match raw.to_lowercase().as_str() {
        "0" | "off" | "f" | "false" | "n" | "no" => Some(false),
        "1" | "on" | "t" | "true" | "y" | "yes" => Some(true),
        _ => None,
    }
}

/// Builder for a `Literal[...]` query parameter.
#[derive(Debug)]
pub struct LiteralParam<'v, 'q> {
    validator: &'v mut QueryValidator<'q>,
    name: &'static str,
    choices: &'static [&'static str],
}

impl LiteralParam<'_, '_> {
    fn check(self, raw: &str) -> Option<&'static str> {
        if let Some(choice) = self.choices.iter().find(|choice| **choice == raw) {
            return Some(choice);
        }
        self.validator.issues.push(literal_issue(
            QueryValidator::loc(self.name),
            Value::from(raw),
            self.choices,
        ));
        None
    }

    pub fn required(self) -> Option<&'static str> {
        match self.validator.params.get(self.name) {
            Some(value) => self.check(value),
            None => {
                let name = self.name;
                self.validator.missing(name);
                None
            }
        }
    }

    /// `Literal[...] | None = Query(default=None)`.
    pub fn optional(self) -> Option<&'static str> {
        let value = self.validator.params.get(self.name)?;
        self.check(value)
    }

    pub fn default(self, default: &'static str) -> &'static str {
        match self.validator.params.get(self.name) {
            Some(value) => self.check(value).unwrap_or(default),
            None => default,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn detail(error: ApiError) -> Value {
        error.detail().clone()
    }

    #[test]
    fn query_params_keep_repeats_blanks_and_last_value() {
        let params = QueryParams::parse(
            "sender_domain=a.example&sender_domain=b.example&query=&folder=One&folder=Two+%C3%A9",
        );
        assert_eq!(params.get_all("sender_domain"), ["a.example", "b.example"]);
        assert_eq!(params.get("query"), Some(""));
        assert_eq!(params.get("folder"), Some("Two é"));
        assert_eq!(params.get("missing"), None);
        assert_eq!(QueryParams::parse("bad=%ZZ%").get("bad"), Some("%ZZ%"));
    }

    #[test]
    fn query_validator_matches_fastapi_messages() {
        let params = QueryParams::parse(
            "folder=xxxxxx&offset=-1&limit=201&read_status=new&category=spam&expired_only=maybe&uid=abc",
        );
        let mut q = params.validator();
        assert_eq!(q.string("account").required(), None);
        assert_eq!(q.string("folder").max_length(5).default("INBOX"), "INBOX");
        assert_eq!(q.integer("offset").ge(0).default(0), 0);
        assert_eq!(q.integer("limit").ge(1).le(200).optional(), None);
        assert_eq!(
            q.literal("read_status", &["all", "unread", "read"])
                .default("all"),
            "all"
        );
        assert_eq!(
            q.literal(
                "category",
                &[
                    "marketing",
                    "transactional",
                    "updates",
                    "verification",
                    "uncategorized"
                ]
            )
            .optional(),
            None
        );
        assert!(!q.boolean("expired_only").default(false));
        assert_eq!(q.integer("uid").ge(1).required(), None);
        assert_eq!(q.list("sender_domain"), None);
        let issues = detail(q.finish().unwrap_err());
        assert_eq!(
            issues,
            json!([
                {"type": "missing", "loc": ["query", "account"], "msg": "Field required", "input": null},
                {"type": "string_too_long", "loc": ["query", "folder"],
                 "msg": "String should have at most 5 characters", "input": "xxxxxx",
                 "ctx": {"max_length": 5}},
                {"type": "greater_than_equal", "loc": ["query", "offset"],
                 "msg": "Input should be greater than or equal to 0", "input": "-1", "ctx": {"ge": 0}},
                {"type": "less_than_equal", "loc": ["query", "limit"],
                 "msg": "Input should be less than or equal to 200", "input": "201", "ctx": {"le": 200}},
                {"type": "literal_error", "loc": ["query", "read_status"],
                 "msg": "Input should be 'all', 'unread' or 'read'", "input": "new",
                 "ctx": {"expected": "'all', 'unread' or 'read'"}},
                {"type": "literal_error", "loc": ["query", "category"],
                 "msg": "Input should be 'marketing', 'transactional', 'updates', 'verification' or 'uncategorized'",
                 "input": "spam",
                 "ctx": {"expected": "'marketing', 'transactional', 'updates', 'verification' or 'uncategorized'"}},
                {"type": "bool_parsing", "loc": ["query", "expired_only"],
                 "msg": "Input should be a valid boolean, unable to interpret input", "input": "maybe"},
                {"type": "int_parsing", "loc": ["query", "uid"],
                 "msg": "Input should be a valid integer, unable to parse string as an integer", "input": "abc"},
            ])
        );
    }

    #[test]
    fn query_validator_accepts_valid_values() {
        let params = QueryParams::parse(
            "account=u%40example.com&uid=+42&mark_seen=False&sender_domain=x&sender_domain=y&sender=ab",
        );
        let mut q = params.validator();
        assert_eq!(
            q.string("account").required().as_deref(),
            Some("u@example.com")
        );
        assert_eq!(q.integer("uid").ge(1).required(), Some(42));
        assert!(!q.boolean("mark_seen").default(true));
        assert_eq!(
            q.list("sender_domain"),
            Some(vec!["x".to_string(), "y".to_string()])
        );
        assert_eq!(q.string("folder").min_length(1).optional(), None);
        assert!(q.is_ok());
        assert_eq!(q.string("sender").min_length(3).optional(), None);
        assert_eq!(
            q.into_issues(),
            vec![
                json!({"type": "string_too_short", "loc": ["query", "sender"],
                "msg": "String should have at least 3 characters", "input": "ab",
                "ctx": {"min_length": 3}})
            ]
        );
    }

    #[test]
    fn singular_length_messages() {
        assert_eq!(
            string_too_short_issue(vec![], "", 1)["msg"],
            "String should have at least 1 character"
        );
        assert_eq!(
            string_too_long_issue(vec![], "ab", 1)["msg"],
            "String should have at most 1 character"
        );
        assert_eq!(
            literal_issue(vec![], json!("x"), &["only"])["msg"],
            "Input should be 'only'"
        );
        assert_eq!(
            literal_issue(vec![], json!("x"), &["a", "b"])["msg"],
            "Input should be 'a' or 'b'"
        );
    }

    #[test]
    fn lax_int_and_bool_parsing() {
        assert_eq!(parse_lax_int(" 12 "), Some(12));
        assert_eq!(parse_lax_int("-3"), Some(-3));
        assert_eq!(parse_lax_int("1_000"), Some(1000));
        assert_eq!(parse_lax_int("5.00"), Some(5));
        for bad in ["", "abc", "1.5", "_1", "1__0", "1_", "+", "0x10", "1e3"] {
            assert_eq!(parse_lax_int(bad), None, "{bad}");
        }
        for (raw, expected) in [
            ("TRUE", true),
            ("yes", true),
            ("1", true),
            ("off", false),
            ("N", false),
        ] {
            assert_eq!(parse_lax_bool(raw), Some(expected), "{raw}");
        }
        assert_eq!(parse_lax_bool("2"), None);
        assert_eq!(parse_lax_bool(""), None);
    }

    #[test]
    fn body_decoding_matches_fastapi() {
        let bytes = |text: &str| Bytes::from(text.to_string());
        let missing =
            json!([{"type": "missing", "loc": ["body"], "msg": "Field required", "input": null}]);
        assert_eq!(
            detail(parse_model_body(None, &bytes("")).unwrap_err()),
            missing
        );
        assert_eq!(
            detail(parse_model_body(Some("application/json"), &bytes("null")).unwrap_err()),
            missing
        );
        assert_eq!(
            parse_model_body(
                Some("application/json; charset=utf-8"),
                &bytes(r#"{"a":1}"#)
            )
            .unwrap(),
            json!({"a": 1})
        );
        assert_eq!(
            parse_model_body(Some("application/merge-patch+json"), &bytes("[1]")).unwrap(),
            json!([1])
        );
        // No (or an empty) content type: not JSON (strict_content_type), the
        // raw text is validated and rejected; an empty body is still missing.
        for content_type in [None, Some("")] {
            assert_eq!(
                detail(parse_model_body(content_type, &bytes(r#"{"a":1}"#)).unwrap_err()),
                json!([{"type": "model_attributes_type", "loc": ["body"],
                        "msg": "Input should be a valid dictionary or object to extract fields from",
                        "input": "{\"a\":1}"}])
            );
            assert_eq!(
                detail(parse_model_body(content_type, &bytes("")).unwrap_err()),
                missing
            );
        }
        // BOM accepted like json.loads(bytes).
        let json = Some("application/json");
        assert_eq!(
            parse_model_body(json, &Bytes::from_static(b"\xef\xbb\xbf{\"x\":true}")).unwrap(),
            json!({"x": true})
        );

        let invalid = parse_model_body(Some("application/json"), &bytes(r#"{"a": }"#)).unwrap_err();
        assert_eq!(invalid.status(), StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(
            detail(invalid),
            json!([{"type": "json_invalid", "loc": ["body", 6], "msg": "JSON decode error",
                    "input": {}, "ctx": {"error": "Expecting value"}}])
        );
        let extra = parse_model_body(json, &bytes("{} x")).unwrap_err();
        assert_eq!(detail(extra)[0]["loc"], json!(["body", 3]));
        let multiline = parse_model_body(json, &bytes("{\n \"é\": ,}")).unwrap_err();
        assert_eq!(detail(multiline)[0]["loc"], json!(["body", 8]));

        let undecodable =
            parse_model_body(json, &Bytes::from_static(b"{\"a\":\"\xff\"}")).unwrap_err();
        assert_eq!(undecodable.status(), StatusCode::BAD_REQUEST);
        assert_eq!(undecodable.body(), json!({"detail": BODY_PARSE_ERROR}));

        let text = parse_model_body(Some("text/plain"), &bytes("hello")).unwrap_err();
        assert_eq!(
            detail(text),
            json!([{"type": "model_attributes_type", "loc": ["body"],
                    "msg": "Input should be a valid dictionary or object to extract fields from",
                    "input": "hello"}])
        );
        // Malformed content types fall back to text/plain like email.message.
        assert!(parse_model_body(Some("application"), &bytes("{}")).is_err());
    }

    #[test]
    fn json_content_type_detection() {
        assert!(is_json_content_type("Application/JSON"));
        assert!(is_json_content_type(
            "application/problem+json; charset=utf-8"
        ));
        assert!(!is_json_content_type("text/json"));
        assert!(!is_json_content_type("multipart/form-data; boundary=x"));
        assert!(!is_json_content_type("application/json/extra"));
    }
}
