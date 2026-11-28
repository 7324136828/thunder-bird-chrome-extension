//! HTTP client for the local mail-backend API.
//!
//! The routes, query parameters and JSON shapes are the original FastAPI
//! contract from `backend/app/main.py`, which the Rust `mail-backend` keeps
//! unchanged. The MCP server holds no credentials: every call relies on an
//! account session the user already unlocked in the extension.
//!
//! Requests are sent without an `Origin` header (the backend treats such
//! callers as trusted local processes), never through a proxy, and never
//! follow redirects.

use std::net::IpAddr;
use std::time::Duration;

use reqwest::header::{CONTENT_DISPOSITION, CONTENT_LENGTH, CONTENT_TYPE};
use reqwest::{Method, Response};
use serde_json::Value;
use url::{Host, Url};

use crate::error::ToolError;

/// Default backend address (`mail-backend` binds `127.0.0.1:48101`).
pub const DEFAULT_BACKEND_URL: &str = "http://127.0.0.1:48101";
/// Environment variable overriding the backend base URL.
pub const BACKEND_URL_ENV: &str = "MAIL_BACKEND_URL";
/// Set to `1` to allow a backend URL whose host is not a loopback address.
pub const ALLOW_NON_LOOPBACK_ENV: &str = "MAIL_MCP_ALLOW_NON_LOOPBACK";
/// Environment variable overriding the per-request timeout, in seconds.
pub const TIMEOUT_ENV: &str = "MAIL_BACKEND_TIMEOUT_SECS";
/// Default per-request timeout. Local AI classification and sending large
/// attachments can legitimately take minutes.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(300);
/// Largest JSON response body accepted from the backend.
pub const MAX_JSON_RESPONSE_BYTES: usize = 64 * 1024 * 1024;
/// Largest error body read from the backend.
const MAX_ERROR_BODY_BYTES: usize = 1024 * 1024;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Query parameters as ordered `(name, value)` pairs; names may repeat.
pub type Query = Vec<(&'static str, String)>;

/// A binary download, possibly cut short at the caller's size cap.
#[derive(Debug, Clone, PartialEq)]
pub struct Download {
    /// The bytes read (at most the requested cap).
    pub data: Vec<u8>,
    /// `true` when the body was longer than the cap.
    pub truncated: bool,
    /// The `Content-Length` header, when the backend sent one.
    pub content_length: Option<u64>,
    /// The `Content-Type` header.
    pub content_type: Option<String>,
    /// The `Content-Disposition` header.
    pub content_disposition: Option<String>,
}

/// Client for the loopback mail-backend HTTP API.
#[derive(Debug, Clone)]
pub struct BackendClient {
    base: Url,
    http: reqwest::Client,
    timeout: Duration,
}

impl BackendClient {
    /// Create a client for `base_url`.
    ///
    /// Only `http`/`https` URLs without credentials, query or fragment are
    /// accepted, and the host must be a loopback address unless
    /// `allow_non_loopback` is set.
    pub fn new(
        base_url: &str,
        allow_non_loopback: bool,
        timeout: Duration,
    ) -> Result<Self, String> {
        let base = validate_base_url(base_url, allow_non_loopback)?;
        let http = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(timeout)
            .user_agent(concat!("mail-mcp/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|error| format!("Cannot create the HTTP client: {error}"))?;
        Ok(Self {
            base,
            http,
            timeout,
        })
    }

    /// Create a client from `MAIL_BACKEND_URL`, `MAIL_MCP_ALLOW_NON_LOOPBACK`
    /// and `MAIL_BACKEND_TIMEOUT_SECS`.
    pub fn from_env() -> Result<Self, String> {
        let base = std::env::var(BACKEND_URL_ENV)
            .ok()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| DEFAULT_BACKEND_URL.to_string());
        let allow_non_loopback = std::env::var(ALLOW_NON_LOOPBACK_ENV)
            .map(|value| matches!(value.trim(), "1" | "true" | "yes"))
            .unwrap_or(false);
        let timeout = match std::env::var(TIMEOUT_ENV) {
            Ok(value) if !value.trim().is_empty() => {
                let seconds: u64 = value
                    .trim()
                    .parse()
                    .ok()
                    .filter(|seconds| *seconds > 0)
                    .ok_or_else(|| format!("{TIMEOUT_ENV} must be a positive number of seconds"))?;
                Duration::from_secs(seconds)
            }
            _ => DEFAULT_TIMEOUT,
        };
        Self::new(base.trim(), allow_non_loopback, timeout)
    }

    /// The configured base URL.
    pub fn base_url(&self) -> &Url {
        &self.base
    }

    /// Build the URL for `segments` (each percent-encoded as one path
    /// segment) below the base URL, followed by `query`.
    pub fn endpoint(&self, segments: &[&str], query: &[(&str, String)]) -> Url {
        let mut url = self.base.clone();
        {
            // Validated base URLs are always hierarchical (http/https).
            let mut path = url
                .path_segments_mut()
                .expect("http(s) URLs always have path segments");
            path.pop_if_empty();
            path.extend(segments);
        }
        if !query.is_empty() {
            let mut pairs = url.query_pairs_mut();
            for (name, value) in query {
                pairs.append_pair(name, value);
            }
        }
        url
    }

    /// `GET` a JSON endpoint.
    pub async fn get_json(
        &self,
        segments: &[&str],
        query: &[(&str, String)],
    ) -> Result<Value, ToolError> {
        self.json_request(Method::GET, segments, query, None).await
    }

    /// Send a request with an optional JSON body and decode the JSON answer.
    pub async fn json_request(
        &self,
        method: Method,
        segments: &[&str],
        query: &[(&str, String)],
        body: Option<&Value>,
    ) -> Result<Value, ToolError> {
        let mut request = self.http.request(method, self.endpoint(segments, query));
        if let Some(body) = body {
            request = request.json(body);
        }
        let response = request
            .send()
            .await
            .map_err(|error| self.transport_error(error))?;
        self.decode_json(response).await
    }

    /// `POST` a `multipart/form-data` body and decode the JSON answer.
    pub async fn post_multipart(
        &self,
        segments: &[&str],
        form: reqwest::multipart::Form,
    ) -> Result<Value, ToolError> {
        let response = self
            .http
            .post(self.endpoint(segments, &[]))
            .multipart(form)
            .send()
            .await
            .map_err(|error| self.transport_error(error))?;
        self.decode_json(response).await
    }

    /// `GET` a binary endpoint, reading at most `max_bytes` of the body.
    pub async fn get_bytes(
        &self,
        segments: &[&str],
        query: &[(&str, String)],
        max_bytes: usize,
    ) -> Result<Download, ToolError> {
        let response = self
            .http
            .get(self.endpoint(segments, query))
            .send()
            .await
            .map_err(|error| self.transport_error(error))?;
        let response = self.check_status(response).await?;
        // The backend (like Starlette) encodes header values as Latin-1, so
        // e.g. `filename="résumé.pdf"` arrives as raw 0xE9 bytes, which
        // `HeaderValue::to_str` rejects.
        let header = |name| {
            response
                .headers()
                .get(name)
                .map(|value: &reqwest::header::HeaderValue| latin1(value.as_bytes()))
        };
        let content_type = header(CONTENT_TYPE);
        let content_disposition = header(CONTENT_DISPOSITION);
        let content_length = header(CONTENT_LENGTH).and_then(|value| value.parse().ok());
        let (data, truncated) = read_capped(response, max_bytes)
            .await
            .map_err(|error| self.transport_error(error))?;
        Ok(Download {
            data,
            truncated,
            content_length,
            content_type,
            content_disposition,
        })
    }

    async fn decode_json(&self, response: Response) -> Result<Value, ToolError> {
        let response = self.check_status(response).await?;
        let (data, truncated) = read_capped(response, MAX_JSON_RESPONSE_BYTES)
            .await
            .map_err(|error| self.transport_error(error))?;
        if truncated {
            return Err(ToolError::InvalidResponse(format!(
                "the response is larger than {} MiB",
                MAX_JSON_RESPONSE_BYTES / (1024 * 1024)
            )));
        }
        serde_json::from_slice(&data)
            .map_err(|error| ToolError::InvalidResponse(format!("invalid JSON ({error})")))
    }

    /// Turn a non-success response into a [`ToolError`] carrying its `detail`.
    async fn check_status(&self, response: Response) -> Result<Response, ToolError> {
        let status = response.status();
        if status.is_success() {
            return Ok(response);
        }
        let (body, _) = read_capped(response, MAX_ERROR_BODY_BYTES)
            .await
            .unwrap_or_default();
        Err(ToolError::from_status(
            status.as_u16(),
            error_detail(&body, status.canonical_reason()),
        ))
    }

    fn transport_error(&self, error: reqwest::Error) -> ToolError {
        let reason = if error.is_timeout() {
            format!(
                "the request timed out after {} seconds",
                self.timeout.as_secs()
            )
        } else if error.is_connect() {
            "the connection was refused or could not be established".to_string()
        } else {
            error.without_url().to_string()
        };
        ToolError::Unreachable {
            url: self.base.to_string(),
            reason,
        }
    }
}

/// Decode a header value as Latin-1 (every byte is one code point), the
/// encoding Starlette and the Rust backend use for response headers.
pub fn latin1(bytes: &[u8]) -> String {
    bytes.iter().map(|&byte| char::from(byte)).collect()
}

/// Extract the FastAPI `detail` from an error body.
fn error_detail(body: &[u8], reason: Option<&str>) -> Value {
    if let Ok(json) = serde_json::from_slice::<Value>(body) {
        return match json {
            Value::Object(mut object) if object.contains_key("detail") => {
                object.shift_remove("detail").unwrap_or(Value::Null)
            }
            other => other,
        };
    }
    let text = String::from_utf8_lossy(body);
    let text = text.trim();
    if text.is_empty() {
        Value::String(reason.unwrap_or("Request failed").to_string())
    } else {
        Value::String(text.chars().take(2000).collect())
    }
}

async fn read_capped(
    mut response: Response,
    cap: usize,
) -> Result<(Vec<u8>, bool), reqwest::Error> {
    let mut data = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        let room = cap - data.len();
        if chunk.len() > room {
            data.extend_from_slice(&chunk[..room]);
            return Ok((data, true));
        }
        data.extend_from_slice(&chunk);
    }
    Ok((data, false))
}

/// Validate the backend base URL (see [`BackendClient::new`]).
pub fn validate_base_url(value: &str, allow_non_loopback: bool) -> Result<Url, String> {
    let url = Url::parse(value)
        .map_err(|error| format!("{BACKEND_URL_ENV} is not a valid URL ({error})"))?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err(format!("{BACKEND_URL_ENV} must use http or https"));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(format!("{BACKEND_URL_ENV} must not contain credentials"));
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err(format!(
            "{BACKEND_URL_ENV} must not contain a query string or fragment"
        ));
    }
    let loopback = match url.host() {
        Some(Host::Domain(domain)) => domain.eq_ignore_ascii_case("localhost"),
        Some(Host::Ipv4(address)) => IpAddr::V4(address).is_loopback(),
        Some(Host::Ipv6(address)) => IpAddr::V6(address).is_loopback(),
        None => false,
    };
    if !loopback && !allow_non_loopback {
        return Err(format!(
            "{BACKEND_URL_ENV} must point at a loopback address (127.0.0.1, ::1 or \
             localhost); set {ALLOW_NON_LOOPBACK_ENV}=1 to override"
        ));
    }
    Ok(url)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn client(base: &str) -> BackendClient {
        BackendClient::new(base, false, DEFAULT_TIMEOUT).unwrap()
    }

    #[test]
    fn base_url_must_be_loopback_http() {
        assert!(validate_base_url("http://127.0.0.1:48101", false).is_ok());
        assert!(validate_base_url("http://localhost:48101/", false).is_ok());
        assert!(validate_base_url("http://[::1]:48101", false).is_ok());
        assert!(validate_base_url("http://127.0.0.2:1", false).is_ok());
        assert!(validate_base_url("http://example.com", false)
            .unwrap_err()
            .contains("loopback"));
        assert!(validate_base_url("http://example.com", true).is_ok());
        assert!(validate_base_url("ftp://127.0.0.1", false).is_err());
        assert!(validate_base_url("http://user:pw@127.0.0.1", false).is_err());
        assert!(validate_base_url("http://127.0.0.1/?a=b", false).is_err());
        assert!(validate_base_url("not a url", false).is_err());
    }

    #[test]
    fn endpoint_encodes_segments_and_repeated_query_pairs() {
        let backend = client("http://127.0.0.1:48101");
        let url = backend.endpoint(
            &["api", "mail", "trash", "a/b c", "empty"],
            &[
                ("account", "me+x@example.com".into()),
                ("sender_domain", "a.com".into()),
                ("sender_domain", "b.com".into()),
            ],
        );
        assert_eq!(
            url.as_str(),
            "http://127.0.0.1:48101/api/mail/trash/a%2Fb%20c/empty\
             ?account=me%2Bx%40example.com&sender_domain=a.com&sender_domain=b.com"
        );
    }

    #[test]
    fn endpoint_keeps_a_base_path_prefix() {
        let backend = client("http://127.0.0.1:9/prefix/");
        assert_eq!(
            backend.endpoint(&["api", "accounts"], &[]).as_str(),
            "http://127.0.0.1:9/prefix/api/accounts"
        );
    }

    #[test]
    fn error_detail_unwraps_fastapi_bodies() {
        assert_eq!(
            error_detail(br#"{"detail":"Profile not found"}"#, None),
            json!("Profile not found")
        );
        assert_eq!(
            error_detail(
                br#"{"detail":{"error":"password_required","email":"a@b.c"}}"#,
                None
            ),
            json!({"error": "password_required", "email": "a@b.c"})
        );
        assert_eq!(error_detail(br#"{"other":1}"#, None), json!({"other": 1}));
        assert_eq!(error_detail(b"  boom ", None), json!("boom"));
        assert_eq!(error_detail(b"", Some("Bad Gateway")), json!("Bad Gateway"));
    }

    #[test]
    fn header_values_are_latin1() {
        assert_eq!(
            latin1(b"attachment; filename=\"r\xe9sum\xe9.txt\""),
            "attachment; filename=\"résumé.txt\""
        );
        assert_eq!(latin1(b"plain"), "plain");
    }

    #[tokio::test]
    async fn unreachable_backend_is_a_tool_error() {
        // Port 9 (discard) on loopback is essentially never listening.
        let backend =
            BackendClient::new("http://127.0.0.1:9", false, Duration::from_secs(5)).unwrap();
        let error = backend
            .get_json(&["api", "accounts"], &[])
            .await
            .unwrap_err();
        assert!(matches!(error, ToolError::Unreachable { .. }), "{error:?}");
        assert!(error.message().contains("Cannot reach the mail backend"));
    }
}
