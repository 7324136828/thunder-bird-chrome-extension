//! Remote-image privacy proxy (main.py `download_message_image`; logic in
//! `app/mail/image_sources.py` and `app/mail/remote_images.py`).
//!
//! | Method | Path | Params / body | Success | Errors |
//! |--------|------|---------------|---------|--------|
//! | POST   | `/api/mail/message/image` | JSON `RemoteImageIn` `{account: str(3..=320), folder: str(1..=500), uid: int(1..=4294967295), url: str(1..=4096), retry?: bool=false}` | 200 image bytes with the downloaded content type; headers `Cache-Control: no-store`, `X-Content-Type-Options: nosniff`, `Content-Security-Policy: default-src 'none'; sandbox` | 400 `"The image URL is not a supported HTTP or HTTPS address"`, 401 (also when locked during download; cache cleared), 403 `"This image was not found in the selected email"`, 422, 502 `"The remote image could not be downloaded safely"`, 502 IMAP |
//!
//! When the registry has no record for (account, folder, uid) the message is
//! re-fetched with `fetch_raw` (no `\Seen` change) and its HTML re-registered.
//!
//! The browser never contacts the remote server: the backend downloads with
//! disposable headers (no browser cookies, `Authorization` or `Referer` are
//! forwarded) and serves the verified raster bytes with a sandboxing CSP.

use axum::body::Body;
use axum::extract::State;
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::Response;
use axum::routing::post;
use axum::Router;
use mail_core::schemas::{RemoteImageIn, RequestModel};
use mail_core::{image_sources, imap, parsing, remote_images, MailError};

use crate::error::{join_error, run_blocking, ApiError, ApiResult};
use crate::extract::JsonBody;
use crate::state::AppState;

const UNSUPPORTED_URL: &str = "The image URL is not a supported HTTP or HTTPS address";
const NOT_IN_EMAIL: &str = "This image was not found in the selected email";
const DOWNLOAD_FAILED: &str = "The remote image could not be downloaded safely";

pub fn router() -> Router<AppState> {
    Router::new().route("/api/mail/message/image", post(download_message_image))
}

/// `POST /api/mail/message/image`.
async fn download_message_image(
    State(state): State<AppState>,
    JsonBody(body): JsonBody,
) -> ApiResult<Response> {
    let body = RemoteImageIn::from_json(&body)?;
    let account = state.sessions.require(&body.account)?;
    let Some(url) = image_sources::normalize_url(&body.url) else {
        return Err(ApiError::bad_request(UNSUPPORTED_URL));
    };
    let allowed = match state
        .image_sources
        .sources(&account.email, &body.folder, body.uid)
    {
        Some(allowed) => allowed,
        None => {
            // Restored sessions or expired records are verified without
            // marking mail read.
            let registry = state.image_sources.clone();
            let account = account.clone();
            let folder = body.folder.clone();
            let uid = body.uid;
            run_blocking(move || {
                let raw = imap::fetch_raw(&account, &folder, uid)?;
                let (_, html) = parsing::extract_bodies(&parsing::parse_message(&raw));
                registry.register(&account.email, &folder, uid, &html);
                Ok::<_, MailError>(
                    registry
                        .sources(&account.email, &folder, uid)
                        .unwrap_or_default(),
                )
            })
            .await?
        }
    };
    if !allowed.contains(&url) {
        return Err(ApiError::forbidden(NOT_IN_EMAIL));
    }
    let retry = body.retry;
    let downloaded =
        match tokio::task::spawn_blocking(move || remote_images::fetch_image(&url, retry)).await {
            Ok(Ok(downloaded)) => downloaded,
            // Never disclose the upstream detail, URL or cookie values.
            Ok(Err(_)) => return Err(ApiError::new(StatusCode::BAD_GATEWAY, DOWNLOAD_FAILED)),
            Err(error) => return Err(join_error(error)),
        };
    // The account may have been locked while the upstream request was running.
    if !state.sessions.is_current(&account) {
        remote_images::clear_cache();
        return Err(MailError::credential_required(&account.email).into());
    }
    let content_type =
        HeaderValue::from_str(&downloaded.content_type).map_err(|_| ApiError::internal())?;
    let mut response = Response::new(Body::from(downloaded.content));
    let headers = response.headers_mut();
    headers.insert(header::CONTENT_TYPE, content_type);
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static("default-src 'none'; sandbox"),
    );
    Ok(response)
}
