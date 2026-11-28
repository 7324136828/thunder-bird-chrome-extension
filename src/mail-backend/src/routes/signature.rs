//! Per-account rich signatures (main.py `get_mail_signature`,
//! `update_mail_signature`, `get_mail_signature_image`; logic in
//! `app/mail/signatures.py` → `mail_core::signatures`).
//!
//! All three use the `require_account` dependency: query `account: str`
//! (required) → 401 `{"error":"password_required","email":...}` when locked.
//!
//! | Method | Path | Params / body | Success | Errors |
//! |--------|------|---------------|---------|--------|
//! | GET    | `/api/mail/signature` | query `account` | 200 `{"account", "text", "multipart-path": {cid: path}, "images": [...]}` (`signatures.load_signature`) | 401, 422 (account missing), 500 `SettingsError` |
//! | PUT    | `/api/mail/signature` | query `account`; multipart: exactly one `signature` JSON field `{"text": html, "uploads": [{"content_id"}]}` (<= `MAX_SIGNATURE_JSON_BYTES`) + up to 20 `files` image parts (10 MiB each, 20 MiB total) | 200 signature dict (`save_signature`) | **size layer first**: 400 `"Invalid request size"`, 413 `"Signature request exceeds maximum allowed size"` (`RequestSizeLimitLayer::signature()`); then 401, 400 not multipart / malformed form / unexpected field / count mismatch, 413 file limits, 422 metadata / `ValueError` (string detail), 500 |
//! | GET    | `/api/mail/signature/image` | query `content_id: str(max 100)` (required), `revision: str(max 32)=""`, `account` | 200 image bytes, `Content-Type` = sniffed type, headers `Cache-Control: no-store`, `X-Content-Type-Options: nosniff`, `Content-Security-Policy: default-src 'none'; sandbox` | 401, 400 `Invalid signature image identifier`, 404 `Signature image not found`, 422, 500 |
//!
//! Starlette ran the signature size middleware before the account
//! dependency, so the limit layer wraps the PUT handler (it runs before the
//! extractors). The multipart field is named `signature` as in the Python
//! code (`parse_signature_uploads`).
//!
//! Multipart framing is shared with `routes/send.rs`: Starlette's
//! `"Invalid multipart data."` for unreadable bodies and an empty form for a
//! mixed-case `Multipart/Form-Data; ...` media type (see that module for the
//! preamble / truncated-body deviations).

use axum::extract::{FromRequest, Multipart, Request, State};
use axum::handler::Handler;
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use mail_core::schemas::{MAX_SEND_FILES, MAX_SEND_FILES_BYTES, MAX_SEND_FILE_BYTES};
use mail_core::send_uploads::{validate_files, MessageFile};
use mail_core::signatures::{self, Signature, MAX_SIGNATURE_JSON_BYTES};
use mail_core::MailError;

use crate::error::{run_blocking, ApiError, ApiResult};
use crate::extract::QueryParams;
use crate::limits::{RequestSizeLimitLayer, SIGNATURE_TOO_LARGE};
use crate::routes::mail::require_account;
use crate::routes::send::{
    declares_empty_body, form_type, with_canonical_boundary, FormType, INVALID_MULTIPART,
};
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route(
            "/api/mail/signature",
            get(get_mail_signature)
                .put(update_mail_signature.layer(RequestSizeLimitLayer::signature())),
        )
        .route("/api/mail/signature/image", get(get_mail_signature_image))
}

/// `GET /api/mail/signature`.
async fn get_mail_signature(
    State(state): State<AppState>,
    query: QueryParams,
) -> ApiResult<Json<Signature>> {
    let mut q = query.validator();
    let account = require_account(&state, &mut q)?;
    q.finish()?;
    let email = account.expect("validated").email.clone();
    let signature = run_blocking(move || signatures::load_signature(&email)).await?;
    Ok(Json(signature))
}

/// `PUT /api/mail/signature`.
async fn update_mail_signature(
    State(state): State<AppState>,
    query: QueryParams,
    request: Request,
) -> ApiResult<Json<Signature>> {
    let mut q = query.validator();
    let account = require_account(&state, &mut q)?;
    q.finish()?;
    let email = account.expect("validated").email.clone();
    let (text, images) = parse_signature_uploads(request).await?;
    let signature =
        run_blocking(move || signatures::save_signature(&email, &text, &images)).await?;
    Ok(Json(signature))
}

/// `GET /api/mail/signature/image`.
async fn get_mail_signature_image(
    State(state): State<AppState>,
    query: QueryParams,
) -> ApiResult<Response> {
    let mut q = query.validator();
    let account = require_account(&state, &mut q)?;
    let content_id = q.string("content_id").max_length(100).required();
    let revision = q.string("revision").max_length(32).default("");
    q.finish()?;
    let email = account.expect("validated").email.clone();
    let content_id = content_id.expect("validated");
    let (data, content_type) =
        run_blocking(move || signatures::signature_image(&email, &content_id, &revision)).await?;
    let mut response = data.into_response();
    let headers = response.headers_mut();
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
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

// ---------------------------------------------------------------------------
// signatures.parse_signature_uploads
// ---------------------------------------------------------------------------

/// Starlette's `request.form(max_fields=1)`.
const MAX_FORM_FIELDS: usize = 1;

enum FormItem {
    /// A part without a `filename` parameter (a string field).
    Field(String),
    /// An `UploadFile`.
    File {
        filename: String,
        content_type: String,
        data: Vec<u8>,
    },
}

fn bad_request(detail: impl Into<String>) -> ApiError {
    ApiError::bad_request(detail)
}

fn too_large(detail: &str) -> ApiError {
    ApiError::payload_too_large(detail)
}

/// Starlette `_user_safe_decode`: UTF-8, falling back to Latin-1.
fn user_safe_decode(bytes: &[u8]) -> String {
    match std::str::from_utf8(bytes) {
        Ok(text) => text.to_string(),
        Err(_) => bytes.iter().map(|&b| b as char).collect(),
    }
}

fn latin1(bytes: &[u8]) -> String {
    bytes.iter().map(|&b| b as char).collect()
}

fn multipart_error(error: axum::extract::multipart::MultipartError) -> ApiError {
    if error.status() == StatusCode::PAYLOAD_TOO_LARGE {
        too_large(SIGNATURE_TOO_LARGE)
    } else {
        bad_request(INVALID_MULTIPART)
    }
}

/// `request.form(max_files=20, max_fields=1, max_part_size=MAX_SIGNATURE_JSON_BYTES)`.
async fn read_form(request: Request) -> ApiResult<Vec<(String, FormItem)>> {
    let mut multipart = Multipart::from_request(request, &())
        .await
        .map_err(|_| bad_request(INVALID_MULTIPART))?;
    let mut items = Vec::new();
    let (mut files, mut fields) = (0usize, 0usize);
    while let Some(mut field) = multipart.next_field().await.map_err(multipart_error)? {
        let Some(name) = field.name().map(str::to_string) else {
            return Err(bad_request(
                "The Content-Disposition header field \"name\" must be provided.",
            ));
        };
        match field.file_name().map(str::to_string) {
            Some(filename) => {
                files += 1;
                if files > MAX_SEND_FILES {
                    return Err(bad_request(format!(
                        "Too many files. Maximum number of files is {MAX_SEND_FILES}."
                    )));
                }
                let content_type = field
                    .headers()
                    .get(header::CONTENT_TYPE)
                    .map(|value| latin1(value.as_bytes()))
                    .unwrap_or_default();
                let mut data = Vec::new();
                while let Some(chunk) = field.chunk().await.map_err(multipart_error)? {
                    data.extend_from_slice(&chunk);
                }
                items.push((
                    name,
                    FormItem::File {
                        filename,
                        content_type,
                        data,
                    },
                ));
            }
            None => {
                fields += 1;
                if fields > MAX_FORM_FIELDS {
                    return Err(bad_request(format!(
                        "Too many fields. Maximum number of fields is {MAX_FORM_FIELDS}."
                    )));
                }
                let mut data = Vec::new();
                while let Some(chunk) = field.chunk().await.map_err(multipart_error)? {
                    if data.len() + chunk.len() > MAX_SIGNATURE_JSON_BYTES {
                        return Err(bad_request(format!(
                            "Part exceeded maximum size of {}KB.",
                            MAX_SIGNATURE_JSON_BYTES / 1024
                        )));
                    }
                    data.extend_from_slice(&chunk);
                }
                items.push((name, FormItem::Field(user_safe_decode(&data))));
            }
        }
    }
    Ok(items)
}

/// Python `parse_signature_uploads(request)`: the sanitized HTML and the
/// validated inline images.
async fn parse_signature_uploads(request: Request) -> ApiResult<(String, Vec<MessageFile>)> {
    let content_type = request
        .headers()
        .get(header::CONTENT_TYPE)
        .map(|value| latin1(value.as_bytes()))
        .unwrap_or_default();
    let essence = content_type
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_lowercase();
    if essence != "multipart/form-data" {
        return Err(bad_request("Save signatures using multipart/form-data"));
    }
    let items = match form_type(&content_type) {
        FormType::Empty => Vec::new(),
        FormType::MissingBoundary => return Err(bad_request("Missing boundary in multipart.")),
        FormType::InvalidBoundary => return Err(bad_request(INVALID_MULTIPART)),
        // python-multipart reads an empty body as a form without parts.
        FormType::Multipart(_) if declares_empty_body(&request) => Vec::new(),
        FormType::Multipart(boundary) => {
            read_form(with_canonical_boundary(request, &boundary)?).await?
        }
    };
    if items
        .iter()
        .any(|(name, _)| name != "signature" && name != "files")
    {
        return Err(bad_request("Unexpected signature upload field"));
    }
    let metadata: Vec<&FormItem> = items
        .iter()
        .filter(|(name, _)| name == "signature")
        .map(|(_, item)| item)
        .collect();
    let files: Vec<&FormItem> = items
        .iter()
        .filter(|(name, _)| name == "files")
        .map(|(_, item)| item)
        .collect();
    let metadata = match metadata.as_slice() {
        [FormItem::Field(text)]
            if files
                .iter()
                .all(|file| matches!(file, FormItem::File { .. })) =>
        {
            text
        }
        _ => {
            return Err(bad_request(
                "Provide one JSON signature and its uploaded images",
            ))
        }
    };
    if metadata.len() > MAX_SIGNATURE_JSON_BYTES {
        return Err(too_large("Signature metadata exceeds maximum allowed size"));
    }
    let Some((text, identifiers)) = signatures::parse_signature_metadata(metadata) else {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "Check the signature HTML, size, and image metadata",
        ));
    };
    if files.len() != identifiers.len() {
        return Err(bad_request(
            "Uploaded images must match the signature metadata",
        ));
    }
    let mut images = Vec::with_capacity(files.len());
    let mut total = 0usize;
    for (file, content_id) in files.into_iter().zip(identifiers) {
        let FormItem::File {
            filename,
            content_type,
            data,
        } = file
        else {
            unreachable!("checked above");
        };
        // Starlette knows each UploadFile's size once the form is parsed.
        if data.len() > MAX_SEND_FILE_BYTES {
            return Err(too_large(
                "Each signature image must be no larger than 10 MiB",
            ));
        }
        total += data.len();
        if total > MAX_SEND_FILES_BYTES {
            return Err(too_large(
                "Signature images exceed the 10 MiB per-image or 20 MiB total limit",
            ));
        }
        images.push(MessageFile::inline(
            if filename.is_empty() {
                "image"
            } else {
                filename.as_str()
            },
            if content_type.is_empty() {
                "application/octet-stream"
            } else {
                content_type.as_str()
            },
            data.clone(),
            content_id,
        ));
    }
    let images = validate_files(&text, &images).map_err(MailError::validation)?;
    Ok((text, images))
}
