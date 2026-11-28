//! Per-route request body size limits (ports of the ASGI middlewares
//! `send_uploads.SendUploadLimitMiddleware`, `signatures.SignatureUploadLimitMiddleware`
//! and `doctor.router.UploadLimitMiddleware`).
//!
//! The Python middlewares capped bodies *before* FastAPI parsed multipart or
//! JSON, both by the declared `Content-Length` and by counting streamed
//! (chunked) bytes. [`RequestSizeLimitLayer`] does the same as a tower layer
//! that the route phase attaches to individual method routes:
//!
//! ```ignore
//! use axum::routing::{post, put};
//! use crate::limits::RequestSizeLimitLayer;
//!
//! Router::new()
//!     .route("/api/mail/send", post(send).layer(RequestSizeLimitLayer::send_json()))
//!     .route("/api/mail/send/files", post(send_files).layer(RequestSizeLimitLayer::send_files()))
//!     .route("/api/mail/signature", get(get_signature)
//!         .put(put_signature.layer(RequestSizeLimitLayer::signature())))
//!     .route("/api/jobs", get(list_jobs)
//!         .post(create_job.layer(RequestSizeLimitLayer::doctor_upload(max_upload_bytes))))
//! ```
//!
//! Behavior per request:
//! 1. (send/signature only) more than one `Content-Length`, or one that is not
//!    a non-negative integer → 400 `{"detail":"Invalid request size"}`;
//!    a declared length above the limit → 413 with the route's message.
//! 2. The body is wrapped so reading more than the limit fails with
//!    `http_body_util::LengthLimitError` (axum's `Bytes`/`Multipart`
//!    extractors turn that into 413) and, whatever the handler then answers,
//!    the response is replaced by 413 with the route's message — like the
//!    Python `HTTPException(413)` raised from inside `receive()`.
//!
//! # Global default limit (intentional deviation)
//!
//! Python had no cap on the other routes: a single request could make the
//! server buffer an arbitrarily large JSON body before validation rejected
//! it. [`default_body_limit`] (installed by [`crate::apply_middleware`])
//! applies the same layer to every route that has no limit of its own:
//!
//! | Routes | Limit |
//! |--------|-------|
//! | `/api/mail/send`, `/api/mail/send/files`, `/api/mail/signature`, `/api/jobs`, `/api/jobs/paste` | their own [`RequestSizeLimitLayer`] (no default) |
//! | `POST /api/audit/eml` (a whole pasted raw message) | [`AUDIT_PASTE_BODY_LIMIT`] (64 MiB) |
//! | every other route (small JSON bodies: unlock, settings, servers, retention, flags, delete, trash, image, classify, Doctor credentials/OAuth, ...) | [`DEFAULT_BODY_LIMIT`] (4 MiB) |
//!
//! An over-limit body is a 413 `{"detail":"Request exceeds maximum allowed
//! size"}`. axum's own `DefaultBodyLimit` stays disabled so these layers are
//! the only body limits.

use std::convert::Infallible;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};

use axum::body::{Body, Bytes};
use axum::extract::Request;
use axum::http::{header, HeaderMap};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use http_body::{Body as HttpBody, Frame, SizeHint};
use http_body_util::{LengthLimitError, Limited};
use tower::{Layer, Service, ServiceExt};

use crate::error::ApiError;

const MIB: u64 = 1024 * 1024;

/// `schemas.MAX_SEND_FILES_BYTES`: combined attachment bytes (20 MiB).
pub const MAX_SEND_FILES_BYTES: u64 = 20 * MIB;
/// `send_uploads.MAX_MESSAGE_JSON_BYTES`: JSON send body / multipart message part (8 MiB).
pub const MAX_MESSAGE_JSON_BYTES: u64 = 8 * MIB;
/// `send_uploads.MAX_SEND_REQUEST_BYTES`: whole multipart send request (30 MiB).
pub const MAX_SEND_REQUEST_BYTES: u64 = 30 * MIB;
/// `signatures.MAX_SIGNATURE_HTML_BYTES` (256 KiB).
pub const MAX_SIGNATURE_HTML_BYTES: u64 = 256 * 1024;
/// `signatures.MAX_SIGNATURE_JSON_BYTES`.
pub const MAX_SIGNATURE_JSON_BYTES: u64 = MAX_SIGNATURE_HTML_BYTES * 6 + 16 * 1024;
/// `signatures.MAX_SIGNATURE_REQUEST_BYTES`.
pub const MAX_SIGNATURE_REQUEST_BYTES: u64 =
    MAX_SEND_FILES_BYTES + MAX_SIGNATURE_JSON_BYTES + 64 * 1024;
/// `DoctorSettings.max_upload_bytes` default (`MAX_UPLOAD_BYTES`, 200 MiB).
pub const DEFAULT_DOCTOR_MAX_UPLOAD_BYTES: u64 = 200 * MIB;
/// Extra allowance the doctor middleware adds for multipart framing (1 MiB).
pub const DOCTOR_UPLOAD_OVERHEAD_BYTES: u64 = MIB;

/// Global default request body cap for routes without their own limit.
///
/// Every JSON model of those routes is tiny (the largest field is the 10 000
/// character settings signature), but the cap stays well above 2 MiB so an
/// over-long field is still answered with the field's 422, as in Python.
pub const DEFAULT_BODY_LIMIT: u64 = 4 * MIB;
/// `POST /api/audit/eml` takes a whole raw message as JSON text; the cap is
/// the largest message the trash archive accepts (`trash::MAX_MESSAGE_BYTES`).
pub const AUDIT_PASTE_BODY_LIMIT: u64 = 64 * MIB;

/// Message of the send and doctor middlewares.
pub const REQUEST_TOO_LARGE: &str = "Request exceeds maximum allowed size";
/// Message of the signature middleware.
pub const SIGNATURE_TOO_LARGE: &str = "Signature request exceeds maximum allowed size";
/// 400 for malformed / repeated `Content-Length`.
pub const INVALID_REQUEST_SIZE: &str = "Invalid request size";

/// Tower layer enforcing one route group's request size limit.
#[derive(Debug, Clone)]
pub struct RequestSizeLimitLayer {
    limit: u64,
    message: &'static str,
    check_declared_length: bool,
}

impl RequestSizeLimitLayer {
    /// A limit of `limit` bytes answering 413 `{"detail": message}`, with the
    /// `Content-Length` pre-check enabled.
    pub fn new(limit: u64, message: &'static str) -> Self {
        Self {
            limit,
            message,
            check_declared_length: true,
        }
    }

    /// Disable the declared `Content-Length` pre-check (stream counting only),
    /// as the doctor middleware did.
    pub fn without_declared_length_check(mut self) -> Self {
        self.check_declared_length = false;
        self
    }

    /// `POST /api/mail/send` (JSON): 8 MiB.
    pub fn send_json() -> Self {
        Self::new(MAX_MESSAGE_JSON_BYTES, REQUEST_TOO_LARGE)
    }

    /// `POST /api/mail/send/files` (multipart): 30 MiB.
    pub fn send_files() -> Self {
        Self::new(MAX_SEND_REQUEST_BYTES, REQUEST_TOO_LARGE)
    }

    /// `PUT /api/mail/signature` (multipart).
    pub fn signature() -> Self {
        Self::new(MAX_SIGNATURE_REQUEST_BYTES, SIGNATURE_TOO_LARGE)
    }

    /// `POST /api/jobs` and `POST /api/jobs/paste`: the doctor's
    /// `max_upload_bytes` plus 1 MiB, counted while streaming only.
    pub fn doctor_upload(max_upload_bytes: u64) -> Self {
        Self::new(
            max_upload_bytes.saturating_add(DOCTOR_UPLOAD_OVERHEAD_BYTES),
            REQUEST_TOO_LARGE,
        )
        .without_declared_length_check()
    }

    /// [`Self::doctor_upload`] with `max_upload_bytes` read like
    /// `DoctorSettings` (`MAX_UPLOAD_BYTES`, default 200 MiB, minimum 1).
    pub fn doctor_upload_from_env() -> Self {
        let configured = mail_core::doctor::env_integer(
            "MAX_UPLOAD_BYTES",
            DEFAULT_DOCTOR_MAX_UPLOAD_BYTES as i64,
            1,
        );
        Self::doctor_upload(u64::try_from(configured).unwrap_or(DEFAULT_DOCTOR_MAX_UPLOAD_BYTES))
    }

    pub fn limit(&self) -> u64 {
        self.limit
    }

    pub fn message(&self) -> &'static str {
        self.message
    }
}

impl<S> Layer<S> for RequestSizeLimitLayer {
    type Service = RequestSizeLimit<S>;

    fn layer(&self, inner: S) -> Self::Service {
        RequestSizeLimit {
            inner,
            config: self.clone(),
        }
    }
}

/// Service produced by [`RequestSizeLimitLayer`].
#[derive(Debug, Clone)]
pub struct RequestSizeLimit<S> {
    inner: S,
    config: RequestSizeLimitLayer,
}

type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send + 'static>>;

impl<S> Service<Request> for RequestSizeLimit<S>
where
    S: Service<Request, Response = Response, Error = Infallible> + Clone + Send + 'static,
    S::Future: Send + 'static,
{
    type Response = Response;
    type Error = Infallible;
    type Future = BoxFuture<Result<Response, Infallible>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: Request) -> Self::Future {
        let config = self.config.clone();
        if config.check_declared_length {
            match declared_length(request.headers()) {
                Err(()) => {
                    let response = ApiError::bad_request(INVALID_REQUEST_SIZE).into_response();
                    return Box::pin(async move { Ok(response) });
                }
                Ok(Some(length)) if length > u128::from(config.limit) => {
                    let response = ApiError::payload_too_large(config.message).into_response();
                    return Box::pin(async move { Ok(response) });
                }
                Ok(_) => {}
            }
        }

        let exceeded = Arc::new(AtomicBool::new(false));
        let limit = usize::try_from(config.limit).unwrap_or(usize::MAX);
        let flag = exceeded.clone();
        let request = request.map(move |body| Body::new(CountingBody::new(body, limit, flag)));

        // Take the service that was driven to readiness; leave a clone behind.
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);
        Box::pin(async move {
            let response = inner.call(request).await?;
            if exceeded.load(Ordering::SeqCst) {
                return Ok(ApiError::payload_too_large(config.message).into_response());
            }
            Ok(response)
        })
    }
}

/// Paths that install their own [`RequestSizeLimitLayer`] and therefore get
/// no default limit.
const OWN_LIMIT_PATHS: [&str; 5] = [
    "/api/mail/send",
    "/api/mail/send/files",
    "/api/mail/signature",
    "/api/jobs",
    "/api/jobs/paste",
];

/// The default body limit for a request path (see the module docs), or
/// `None` when the route enforces its own limit.
pub fn default_limit_for(path: &str) -> Option<u64> {
    if OWN_LIMIT_PATHS.contains(&path) {
        None
    } else if path == "/api/audit/eml" {
        Some(AUDIT_PASTE_BODY_LIMIT)
    } else {
        Some(DEFAULT_BODY_LIMIT)
    }
}

/// Middleware applying [`default_limit_for`] as a [`RequestSizeLimitLayer`]
/// (declared `Content-Length` checked first, streamed bytes counted) to
/// every route without its own limit; over-limit → JSON 413.
pub async fn default_body_limit(request: Request, next: Next) -> Response {
    match default_limit_for(request.uri().path()) {
        None => next.run(request).await,
        Some(limit) => match RequestSizeLimitLayer::new(limit, REQUEST_TOO_LARGE)
            .layer(next)
            .oneshot(request)
            .await
        {
            Ok(response) => response,
            Err(never) => match never {},
        },
    }
}

/// The single declared `Content-Length` (Python `int(value)` rules), `None`
/// when absent, `Err` when repeated, negative or unparsable.
fn declared_length(headers: &HeaderMap) -> Result<Option<u128>, ()> {
    let mut values = headers.get_all(header::CONTENT_LENGTH).iter();
    let Some(first) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(());
    }
    let text = std::str::from_utf8(first.as_bytes()).map_err(|_| ())?;
    if text.contains('.') {
        return Err(());
    }
    match crate::extract::parse_lax_int(text) {
        Some(value) if value >= 0 => Ok(Some(value as u128)),
        _ => Err(()),
    }
}

/// Body wrapper that fails after `limit` bytes and records that it did.
struct CountingBody {
    inner: Limited<Body>,
    exceeded: Arc<AtomicBool>,
}

impl CountingBody {
    fn new(body: Body, limit: usize, exceeded: Arc<AtomicBool>) -> Self {
        Self {
            inner: Limited::new(body, limit),
            exceeded,
        }
    }
}

impl HttpBody for CountingBody {
    type Data = Bytes;
    type Error = Box<dyn std::error::Error + Send + Sync>;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let polled = Pin::new(&mut self.inner).poll_frame(cx);
        if let Poll::Ready(Some(Err(error))) = &polled {
            if error.downcast_ref::<LengthLimitError>().is_some() {
                self.exceeded.store(true, Ordering::SeqCst);
            }
        }
        polled
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    #[test]
    fn limits_match_python_constants() {
        assert_eq!(MAX_SIGNATURE_JSON_BYTES, 1_589_248);
        assert_eq!(MAX_SIGNATURE_REQUEST_BYTES, 20_971_520 + 1_589_248 + 65_536);
        assert_eq!(RequestSizeLimitLayer::send_json().limit(), 8_388_608);
        assert_eq!(RequestSizeLimitLayer::send_files().limit(), 31_457_280);
        assert_eq!(
            RequestSizeLimitLayer::doctor_upload(100).limit(),
            100 + 1_048_576
        );
        assert!(!RequestSizeLimitLayer::doctor_upload(1).check_declared_length);
        assert_eq!(
            RequestSizeLimitLayer::signature().message(),
            SIGNATURE_TOO_LARGE
        );
    }

    #[test]
    fn default_limits_per_path() {
        assert_eq!(
            default_limit_for("/api/accounts/unlock"),
            Some(DEFAULT_BODY_LIMIT)
        );
        assert_eq!(default_limit_for("/api/settings"), Some(4 * 1024 * 1024));
        assert_eq!(
            default_limit_for("/api/audit/eml"),
            Some(AUDIT_PASTE_BODY_LIMIT)
        );
        for own in OWN_LIMIT_PATHS {
            assert_eq!(default_limit_for(own), None, "{own}");
        }
        assert_eq!(
            default_limit_for("/api/jobs/abc/discard"),
            Some(DEFAULT_BODY_LIMIT)
        );
    }

    #[test]
    fn declared_length_parsing() {
        let mut headers = HeaderMap::new();
        assert_eq!(declared_length(&headers), Ok(None));
        headers.insert(header::CONTENT_LENGTH, HeaderValue::from_static(" 12 "));
        assert_eq!(declared_length(&headers), Ok(Some(12)));
        for bad in ["-1", "abc", "1.0", ""] {
            headers.insert(header::CONTENT_LENGTH, HeaderValue::from_static(bad));
            assert_eq!(declared_length(&headers), Err(()), "{bad}");
        }
        headers.insert(header::CONTENT_LENGTH, HeaderValue::from_static("1"));
        headers.append(header::CONTENT_LENGTH, HeaderValue::from_static("1"));
        assert_eq!(declared_length(&headers), Err(()));
    }
}
