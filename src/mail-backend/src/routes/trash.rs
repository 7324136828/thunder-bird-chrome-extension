//! Prepared Trash-emptying workflow (main.py `prepare_trash`,
//! `download_trash_archive`, `empty_trash`, `discard_trash_operation`; logic
//! in `app/mail/trash.py`, ported as `mail_core::trash`).
//!
//! | Method | Path | Params / body | Success | Errors |
//! |--------|------|---------------|---------|--------|
//! | POST   | `/api/mail/trash/prepare` | JSON `TrashPrepareIn` `{account: str(3..=320), folder: str(1..=500), archive: bool(strict)}` | 200 `{"operation_id", "count", "archive", "filename"}` (if the account was re-locked meanwhile: discard + 401) | 401, 422, 502 `TrashOperationError` |
//! | GET    | `/api/mail/trash/{operation_id}/archive` | acct (query `account`) | 200 ZIP file (`FileResponse`, `application/zip`, `Content-Disposition` attachment filename), `Cache-Control: no-store`, `X-Content-Type-Options: nosniff` | 401, 404 `TrashOperationNotFound`, 502 |
//! | POST   | `/api/mail/trash/{operation_id}/empty` | JSON `TrashEmptyIn` `{account: str(3..=320)}` | 200 `{"deleted": n, "remaining": n}` (retries return the stored result) | 401, 404, 422, 502 |
//! | DELETE | `/api/mail/trash/{operation_id}` | acct | 200 `{"discarded": operation_id}` | 401, 404, 502 |
//!
//! POP3 accounts answer 400 (`pop3::imap_only`) from prepare and empty.
//!
//! # Intentional deviations
//!
//! * The archive response carries Starlette `FileResponse`'s
//!   `content-type`, `content-disposition`, `content-length` and
//!   `last-modified` headers but no `etag` (Starlette's is an MD5 of the
//!   file's mtime and size) and no range support. The file is streamed in
//!   64 KiB chunks like Starlette.
//! * A file that vanished between `archive()` and the response is a JSON
//!   500 (Starlette raised `RuntimeError`, also a 500).

use std::path::Path;

use axum::body::{Body, Bytes};
use axum::extract::{Path as PathParam, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::Response;
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use mail_core::schemas::{RequestModel, TrashEmptyIn, TrashPrepareIn};
use mail_core::MailError;
use percent_encoding::{utf8_percent_encode, AsciiSet, NON_ALPHANUMERIC};
use serde_json::{json, Value};
use tokio::io::AsyncReadExt;

use crate::error::{run_blocking, ApiError, ApiResult};
use crate::extract::{JsonBody, QueryParams};
use crate::routes::mail::require_account;
use crate::state::AppState;

/// Starlette `FileResponse.chunk_size`.
const CHUNK_SIZE: usize = 64 * 1024;

/// `urllib.parse.quote(filename)` keeps `A-Za-z0-9_.-~` and `/`.
const QUOTE_SAFE: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'_')
    .remove(b'.')
    .remove(b'-')
    .remove(b'~')
    .remove(b'/');

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/mail/trash/prepare", post(prepare_trash))
        .route(
            "/api/mail/trash/{operation_id}/archive",
            get(download_trash_archive),
        )
        .route("/api/mail/trash/{operation_id}/empty", post(empty_trash))
        .route(
            "/api/mail/trash/{operation_id}",
            delete(discard_trash_operation),
        )
}

/// `POST /api/mail/trash/prepare`.
async fn prepare_trash(
    State(state): State<AppState>,
    JsonBody(body): JsonBody,
) -> ApiResult<Json<Value>> {
    let body = TrashPrepareIn::from_json(&body)?;
    let account = state.sessions.require(&body.account)?;
    let result = run_blocking(move || {
        let result = state.trash.prepare(&account, &body.folder, body.archive)?;
        if !state.sessions.is_current(&account) {
            let operation_id = result["operation_id"].as_str().unwrap_or_default();
            state.trash.discard(&account, operation_id)?;
            return Err(MailError::credential_required(&account.email));
        }
        Ok(result)
    })
    .await?;
    Ok(Json(result))
}

/// `GET /api/mail/trash/{operation_id}/archive`.
async fn download_trash_archive(
    State(state): State<AppState>,
    PathParam(operation_id): PathParam<String>,
    query: QueryParams,
) -> ApiResult<Response> {
    let mut q = query.validator();
    let account = require_account(&state, &mut q)?;
    q.finish()?;
    let account = account.expect("validated");
    let (path, filename) =
        run_blocking(move || state.trash.archive(&account, &operation_id)).await?;
    file_response(&path, &filename).await
}

/// `POST /api/mail/trash/{operation_id}/empty`.
async fn empty_trash(
    State(state): State<AppState>,
    PathParam(operation_id): PathParam<String>,
    JsonBody(body): JsonBody,
) -> ApiResult<Json<Value>> {
    let body = TrashEmptyIn::from_json(&body)?;
    let account = state.sessions.require(&body.account)?;
    let result = run_blocking(move || state.trash.empty(&account, &operation_id)).await?;
    Ok(Json(result))
}

/// `DELETE /api/mail/trash/{operation_id}`.
async fn discard_trash_operation(
    State(state): State<AppState>,
    PathParam(operation_id): PathParam<String>,
    query: QueryParams,
) -> ApiResult<Json<Value>> {
    let mut q = query.validator();
    let account = require_account(&state, &mut q)?;
    q.finish()?;
    let account = account.expect("validated");
    let id = operation_id.clone();
    run_blocking(move || state.trash.discard(&account, &id)).await?;
    Ok(Json(json!({ "discarded": operation_id })))
}

/// Starlette `FileResponse(path, media_type="application/zip",
/// filename=filename, headers={"Cache-Control": "no-store",
/// "X-Content-Type-Options": "nosniff"})`.
async fn file_response(path: &Path, filename: &str) -> ApiResult<Response> {
    let unavailable = |_| {
        tracing::error!("prepared Trash archive could not be opened");
        ApiError::internal()
    };
    let file = tokio::fs::File::open(path).await.map_err(unavailable)?;
    let metadata = file.metadata().await.map_err(unavailable)?;
    let stream = futures_util::stream::try_unfold(file, |mut file| async move {
        let mut buffer = vec![0u8; CHUNK_SIZE];
        let read = file.read(&mut buffer).await?;
        if read == 0 {
            return Ok::<_, std::io::Error>(None);
        }
        buffer.truncate(read);
        Ok(Some((Bytes::from(buffer), file)))
    });
    let mut response = Response::new(Body::from_stream(stream));
    *response.status_mut() = StatusCode::OK;
    let headers = response.headers_mut();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/zip"),
    );
    headers.insert(header::CONTENT_LENGTH, HeaderValue::from(metadata.len()));
    if let Ok(modified) = metadata.modified() {
        let modified = chrono::DateTime::<chrono::Utc>::from(modified)
            .format("%a, %d %b %Y %H:%M:%S GMT")
            .to_string();
        if let Ok(value) = HeaderValue::from_str(&modified) {
            headers.insert(header::LAST_MODIFIED, value);
        }
    }
    let disposition = content_disposition(filename);
    let value = HeaderValue::from_str(&disposition).map_err(|_| ApiError::internal())?;
    headers.insert(header::CONTENT_DISPOSITION, value);
    Ok(response)
}

/// Starlette's `Content-Disposition` for `FileResponse(filename=...)`.
fn content_disposition(filename: &str) -> String {
    let quoted = utf8_percent_encode(filename, QUOTE_SAFE).to_string();
    if quoted == filename {
        format!("attachment; filename=\"{filename}\"")
    } else {
        format!("attachment; filename*=utf-8''{quoted}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn content_disposition_matches_starlette() {
        assert_eq!(
            content_disposition("trash-20261127-101500.zip"),
            "attachment; filename=\"trash-20261127-101500.zip\""
        );
        assert_eq!(
            content_disposition("tr\u{e4}sh one.zip"),
            "attachment; filename*=utf-8''tr%C3%A4sh%20one.zip"
        );
    }
}
