//! HTTP error responses (port of the exception handlers in `backend/app/main.py`
//! plus the Starlette/FastAPI defaults the frontend relies on).
//!
//! Every error the backend produces is JSON `{"detail": ...}`:
//!
//! | Source                                         | Status | Body                                   |
//! |------------------------------------------------|--------|----------------------------------------|
//! | [`mail_core::MailError`] (any variant)          | `MailError::status()` | `MailError::body()`     |
//! | unknown path (Starlette `NotFound`)            | 404    | `{"detail":"Not Found"}`               |
//! | known path, wrong method                       | 405    | `{"detail":"Method Not Allowed"}` + `Allow` |
//! | request validation (FastAPI)                   | 422    | `{"detail":[{type,loc,msg,input,ctx?}]}` (passwords redacted) |
//! | request body over the size limit               | 413    | `{"detail":"Request exceeds maximum allowed size"}` |
//! | panic in a handler or blocking task            | 500    | `{"detail":"Internal Server Error"}`   |
//!
//! Deviations:
//!
//! * Starlette answers unhandled exceptions with a plain-text
//!   `Internal Server Error`; this backend keeps it JSON so the frontend's
//!   error parser always finds a `detail`.
//! * 422 issue lists never echo a password: [`ApiError::new`] (and
//!   `mail_core::schemas::ValidationIssue::to_json`) apply
//!   `mail_core::schemas::redact_issue`, replacing it with `"[redacted]"`.
//! * Ordinary JSON responses are serialized by serde_json, so a float such as
//!   `1e16` is written `1e16` where Python's `json` writes `1e+16` (and
//!   `1e-05` vs `1e-5`). Both parse to the same number; only the ASCII
//!   re-encoded 422 bodies ([`python_json_ascii`]) reproduce Python's float
//!   repr byte for byte. A shared response serializer for every route was not
//!   worth the per-response re-encoding cost for values no route returns in
//!   practice.

use std::any::Any;
use std::io;

use axum::body::Body;
use axum::extract::Request;
use axum::http::{header, HeaderMap, HeaderName, HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use mail_core::schemas::redact_issue;
use mail_core::MailError;
use serde_json::{json, Value};

/// Paths whose request-validation errors are serialized like Python's
/// `json.dumps(..., ensure_ascii=True)` (see `settings_validation_error` in main.py).
pub const ASCII_VALIDATION_PATHS: [&str; 2] = ["/api/settings", "/api/accounts/unlock"];

/// Largest non-JSON error body the normalizing middleware reads (its text
/// only becomes the `detail` of a generic error).
const MAX_ERROR_BODY: usize = 1024 * 1024;

/// Result type for route handlers.
pub type ApiResult<T> = Result<T, ApiError>;

/// An HTTP error rendered as `{"detail": detail}` with a status and optional
/// extra headers.
#[derive(Debug, Clone)]
pub struct ApiError {
    status: StatusCode,
    detail: Value,
    /// Boxed so `Result<T, ApiError>` stays small (clippy `result_large_err`).
    headers: Option<Box<HeaderMap>>,
}

impl ApiError {
    /// Python `HTTPException(status_code=status, detail=detail)`.
    ///
    /// A 422 whose detail is a pydantic-style issue list (from
    /// [`ApiError::validation`] or a `MailError` validation error) has its
    /// passwords redacted with [`mail_core::schemas::redact_issue`]
    /// (intentional deviation: FastAPI echoes them as `input`).
    pub fn new(status: StatusCode, detail: impl Into<Value>) -> Self {
        let mut detail = detail.into();
        if status == StatusCode::UNPROCESSABLE_ENTITY {
            if let Value::Array(issues) = &mut detail {
                issues.iter_mut().for_each(redact_issue);
            }
        }
        Self {
            status,
            detail,
            headers: None,
        }
    }

    /// 400 with a string detail.
    pub fn bad_request(detail: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, detail.into())
    }

    /// 403 with a string detail.
    pub fn forbidden(detail: impl Into<String>) -> Self {
        Self::new(StatusCode::FORBIDDEN, detail.into())
    }

    /// Starlette's 404 for unknown paths: `{"detail":"Not Found"}`.
    pub fn not_found() -> Self {
        Self::new(StatusCode::NOT_FOUND, "Not Found")
    }

    /// Starlette's 405: `{"detail":"Method Not Allowed"}`.
    pub fn method_not_allowed() -> Self {
        Self::new(StatusCode::METHOD_NOT_ALLOWED, "Method Not Allowed")
    }

    /// 413 with a string detail.
    pub fn payload_too_large(detail: impl Into<String>) -> Self {
        Self::new(StatusCode::PAYLOAD_TOO_LARGE, detail.into())
    }

    /// 500 `{"detail":"Internal Server Error"}` (never leaks internals).
    pub fn internal() -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, "Internal Server Error")
    }

    /// FastAPI `RequestValidationError`: 422 with a list of pydantic-style
    /// issue objects (`{"type","loc","msg","input","ctx"?}`).
    pub fn validation(issues: Vec<Value>) -> Self {
        Self::new(StatusCode::UNPROCESSABLE_ENTITY, Value::Array(issues))
    }

    /// Add a response header (e.g. `Allow`, `WWW-Authenticate`).
    pub fn with_header(mut self, name: HeaderName, value: HeaderValue) -> Self {
        self.headers
            .get_or_insert_with(Default::default)
            .insert(name, value);
        self
    }

    pub fn status(&self) -> StatusCode {
        self.status
    }

    pub fn detail(&self) -> &Value {
        &self.detail
    }

    /// The full response body: `{"detail": ...}`.
    pub fn body(&self) -> Value {
        json!({ "detail": self.detail })
    }
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.detail {
            Value::String(text) => write!(f, "{} {text}", self.status.as_u16()),
            other => write!(f, "{} {other}", self.status.as_u16()),
        }
    }
}

impl std::error::Error for ApiError {}

impl From<MailError> for ApiError {
    fn from(error: MailError) -> Self {
        let status =
            StatusCode::from_u16(error.status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        Self::new(status, error.detail())
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let mut response = json_response(self.status, &self.body());
        if let Some(headers) = self.headers {
            response.headers_mut().extend(*headers);
        }
        response
    }
}

/// `application/json` response with compact serde_json encoding (Starlette's
/// `JSONResponse` uses compact separators too).
pub fn json_response(status: StatusCode, body: &Value) -> Response {
    let mut response = Response::new(Body::from(body.to_string()));
    *response.status_mut() = status;
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    response
}

/// Router fallback for unknown paths (Starlette's JSON 404).
pub async fn not_found_fallback() -> ApiError {
    ApiError::not_found()
}

// ---------------------------------------------------------------------------
// Blocking work
// ---------------------------------------------------------------------------

/// Run synchronous mail-core work on tokio's blocking pool (FastAPI ran these
/// `def` endpoints in its threadpool).
///
/// The closure's error converts into [`ApiError`] (so `MailError` works
/// directly). A panic inside the closure becomes a JSON 500 and is logged; the
/// server keeps running.
pub async fn run_blocking<T, E, F>(work: F) -> ApiResult<T>
where
    F: FnOnce() -> Result<T, E> + Send + 'static,
    T: Send + 'static,
    E: Into<ApiError> + Send + 'static,
{
    match tokio::task::spawn_blocking(work).await {
        Ok(result) => result.map_err(Into::into),
        Err(error) => Err(join_error(error)),
    }
}

/// Map a [`tokio::task::JoinError`] (panic or cancellation) to a JSON 500.
pub fn join_error(error: tokio::task::JoinError) -> ApiError {
    if error.is_panic() {
        let payload = error.into_panic();
        tracing::error!(
            "blocking task panicked: {}",
            panic_message(payload.as_ref())
        );
    } else {
        tracing::error!("blocking task was cancelled: {error}");
    }
    ApiError::internal()
}

// ---------------------------------------------------------------------------
// Panics
// ---------------------------------------------------------------------------

/// Human-readable text of a panic payload.
pub fn panic_message(payload: &(dyn Any + Send)) -> String {
    payload
        .downcast_ref::<String>()
        .cloned()
        .or_else(|| payload.downcast_ref::<&str>().map(|text| text.to_string()))
        .unwrap_or_else(|| "unknown panic".into())
}

/// `tower_http::catch_panic::CatchPanicLayer::custom` handler: logs the panic
/// and answers JSON 500.
pub fn panic_response(payload: Box<dyn Any + Send + 'static>) -> Response {
    tracing::error!(
        "request handler panicked: {}",
        panic_message(payload.as_ref())
    );
    ApiError::internal().into_response()
}

// ---------------------------------------------------------------------------
// Normalizing middleware
// ---------------------------------------------------------------------------

/// Turn every non-JSON error response (axum's empty 405, extractor
/// rejections, `tower_http` limit responses, ...) into JSON `{"detail": ...}`
/// while keeping its headers (e.g. `Allow`), and re-encode request-validation
/// errors on [`ASCII_VALIDATION_PATHS`] like Python's `ensure_ascii=True`.
pub async fn normalize_error_responses(request: Request, next: Next) -> Response {
    let ascii_path = ASCII_VALIDATION_PATHS.contains(&request.uri().path());
    let response = next.run(request).await;
    let status = response.status();
    if !(status.is_client_error() || status.is_server_error()) {
        return response;
    }
    let is_json = response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.starts_with("application/json"));
    if is_json {
        if ascii_path && status == StatusCode::UNPROCESSABLE_ENTITY {
            return reencode_ascii_validation(response).await;
        }
        return response;
    }

    let (parts, body) = response.into_parts();
    let text = axum::body::to_bytes(body, MAX_ERROR_BODY)
        .await
        .unwrap_or_default();
    let text = String::from_utf8_lossy(&text).trim().to_string();
    let detail = match status {
        StatusCode::NOT_FOUND => "Not Found".to_string(),
        StatusCode::METHOD_NOT_ALLOWED => "Method Not Allowed".to_string(),
        StatusCode::PAYLOAD_TOO_LARGE => "Request exceeds maximum allowed size".to_string(),
        StatusCode::INTERNAL_SERVER_ERROR => "Internal Server Error".to_string(),
        _ if text.is_empty() => status.canonical_reason().unwrap_or("Error").to_string(),
        _ => text,
    };
    let mut normalized = ApiError::new(status, detail).into_response();
    for (name, value) in parts.headers.iter() {
        if name != header::CONTENT_TYPE && name != header::CONTENT_LENGTH {
            normalized.headers_mut().append(name, value.clone());
        }
    }
    normalized
}

/// Re-serialize a 422 whose `detail` is an issue list with Python's default
/// `json.dumps` formatting and `ensure_ascii=True`.
///
/// The body is our own, already in-memory JSON response, so it is read
/// without a cap: its size is bounded by the request body limit (a 422 echoes
/// at most the request), and capping it turned a large 422 into a 500.
async fn reencode_ascii_validation(response: Response) -> Response {
    let (mut parts, body) = response.into_parts();
    let Ok(bytes) = axum::body::to_bytes(body, usize::MAX).await else {
        return ApiError::internal().into_response();
    };
    let value: Value = match serde_json::from_slice(&bytes) {
        Ok(value) => value,
        Err(_) => return Response::from_parts(parts, Body::from(bytes)),
    };
    if !value.get("detail").is_some_and(Value::is_array) {
        return Response::from_parts(parts, Body::from(bytes));
    }
    parts.headers.remove(header::CONTENT_LENGTH);
    Response::from_parts(parts, Body::from(python_json_ascii(&value)))
}

/// Python `json.dumps(value, ensure_ascii=True)`: `", "` / `": "` separators
/// and every non-ASCII character escaped as lowercase `\uXXXX` (UTF-16).
pub fn python_json_ascii(value: &Value) -> String {
    let mut out = Vec::new();
    let mut serializer = serde_json::Serializer::with_formatter(&mut out, PythonAsciiFormatter);
    serde::Serialize::serialize(value, &mut serializer).expect("serializing a Value cannot fail");
    String::from_utf8(out).expect("ASCII output")
}

struct PythonAsciiFormatter;

impl serde_json::ser::Formatter for PythonAsciiFormatter {
    fn begin_array_value<W: ?Sized + io::Write>(
        &mut self,
        writer: &mut W,
        first: bool,
    ) -> io::Result<()> {
        if first {
            Ok(())
        } else {
            writer.write_all(b", ")
        }
    }

    fn begin_object_key<W: ?Sized + io::Write>(
        &mut self,
        writer: &mut W,
        first: bool,
    ) -> io::Result<()> {
        if first {
            Ok(())
        } else {
            writer.write_all(b", ")
        }
    }

    fn begin_object_value<W: ?Sized + io::Write>(&mut self, writer: &mut W) -> io::Result<()> {
        writer.write_all(b": ")
    }

    fn write_f64<W: ?Sized + io::Write>(&mut self, writer: &mut W, value: f64) -> io::Result<()> {
        // Python's float repr: `1e+16`, `1e-05` (serde_json writes `1e16`, `1e-5`).
        writer.write_all(mail_core::settings::python_float_repr(value).as_bytes())
    }

    fn write_string_fragment<W: ?Sized + io::Write>(
        &mut self,
        writer: &mut W,
        fragment: &str,
    ) -> io::Result<()> {
        // Python escapes everything outside printable ASCII (`[^ -~]`), which
        // includes DEL (0x7f); serde_json has already escaped C0 controls.
        for character in fragment.chars() {
            if (' '..='~').contains(&character) {
                writer.write_all(&[character as u8])?;
            } else {
                let mut units = [0u16; 2];
                for unit in character.encode_utf16(&mut units) {
                    write!(writer, "\\u{unit:04x}")?;
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mail_errors_map_to_status_and_detail() {
        let error = ApiError::from(MailError::credential_required(" User@Example.com "));
        assert_eq!(error.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            error.body(),
            json!({"detail": {"error": "password_required", "email": "user@example.com"}})
        );
        let error = ApiError::from(MailError::operation("IMAP down"));
        assert_eq!(error.status(), StatusCode::BAD_GATEWAY);
        assert_eq!(error.body(), json!({"detail": "IMAP down"}));
        assert_eq!(
            ApiError::from(MailError::RetentionConflict("changed".into())).status(),
            StatusCode::CONFLICT
        );
        assert_eq!(
            ApiError::from(MailError::TrashNotFound("gone".into())).status(),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            ApiError::from(MailError::Settings("bad".into())).status(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
        assert_eq!(
            ApiError::from(MailError::validation("Bad value")).body(),
            json!({"detail": "Bad value"})
        );
    }

    #[test]
    fn python_ascii_json_matches_json_dumps() {
        // Keys in sorted order so the test holds with or without serde_json's
        // `preserve_order` feature.
        let text: String = [0x47, 0x72, 0xFC, 0xDF, 0x65, 0x20, 0x1F600]
            .into_iter()
            .map(|code| char::from_u32(code).unwrap())
            .collect();
        let value = json!({"detail": [{"loc": ["body", 1], "msg": text}]});
        let bs = '\\';
        assert_eq!(
            python_json_ascii(&value),
            format!(
                r#"{{"detail": [{{"loc": ["body", 1], "msg": "Gr{bs}u00fc{bs}u00dfe {bs}ud83d{bs}ude00"}}]}}"#
            )
        );
        assert_eq!(python_json_ascii(&json!("a\n\"b")), r#""a\n\"b""#);
        // DEL is escaped by Python's `ensure_ascii`; other controls keep the
        // short escapes or lowercase `\u00XX`.
        assert_eq!(
            python_json_ascii(&json!([1e16, 0.00001, 2.5, 7])),
            "[1e+16, 1e-05, 2.5, 7]"
        );
        assert_eq!(
            python_json_ascii(&json!("x\u{7f}\u{1}\t/")),
            r#""x\u007f\u0001\t/""#
        );
    }

    #[test]
    fn validation_details_redact_passwords() {
        let error = ApiError::validation(vec![
            json!({"type": "missing", "loc": ["body", "email"], "msg": "Field required",
                   "input": {"password": "s3cret"}}),
            json!({"type": "string_too_long", "loc": ["body", "password"], "msg": "m",
                   "input": "s3cret", "ctx": {"max_length": 4096}}),
        ]);
        assert!(
            !error.body().to_string().contains("s3cret"),
            "{}",
            error.body()
        );
        assert_eq!(
            error.detail()[0]["input"],
            json!({"password": "[redacted]"})
        );
        assert_eq!(error.detail()[1]["input"], json!("[redacted]"));
        // Other statuses and string details are untouched.
        let other = ApiError::new(
            StatusCode::BAD_REQUEST,
            json!([{"input": {"password": "x"}}]),
        );
        assert_eq!(other.detail()[0]["input"]["password"], json!("x"));
    }

    #[test]
    fn panic_messages_are_extracted() {
        let owned: Box<dyn Any + Send> = Box::new(String::from("owned"));
        let borrowed: Box<dyn Any + Send> = Box::new("borrowed");
        let other: Box<dyn Any + Send> = Box::new(5u8);
        assert_eq!(panic_message(owned.as_ref()), "owned");
        assert_eq!(panic_message(borrowed.as_ref()), "borrowed");
        assert_eq!(panic_message(other.as_ref()), "unknown panic");
    }

    #[tokio::test]
    async fn run_blocking_maps_errors_and_panics() {
        let ok: ApiResult<u8> = run_blocking(|| Ok::<_, MailError>(7)).await;
        assert_eq!(ok.unwrap(), 7);
        let err = run_blocking(|| Err::<u8, _>(MailError::Send("smtp".into())))
            .await
            .unwrap_err();
        assert_eq!(err.status(), StatusCode::BAD_GATEWAY);
        let panicked = run_blocking(|| -> Result<u8, MailError> { panic!("boom") })
            .await
            .unwrap_err();
        assert_eq!(panicked.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(panicked.body(), json!({"detail": "Internal Server Error"}));
    }
}
