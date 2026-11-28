//! Sending (main.py `send`, `send_files`; logic in `app/mail/smtp_client.py`
//! and `app/mail/send_uploads.py`).
//!
//! | Method | Path | Params / body | Success | Errors |
//! |--------|------|---------------|---------|--------|
//! | POST   | `/api/mail/send` | JSON `SendIn` `{account: str(3..=320), to/cc/bcc: list[str] (<=100 each, validated addresses), subject: str(<=998)="", text="", html="", in_reply_to: str(<=998)="", references: str(<=2048)="", uploads: list[SendUploadIn](<=20)=[]}`; size layer `RequestSizeLimitLayer::send_json()` (8 MiB) | 200 `{"sent": true, "message_id", "from", "sent_saved": bool, "sent_folder": str|null, "warning"?: str}` | 400 `"Invalid request size"`, 413 `"Request exceeds maximum allowed size"`, 422 `"Use the attachment upload endpoint for messages with files"` (non-empty uploads), 422 `validate_files` ValueError (string), 422 validation, 401 `password_required`, 502 `MailSendError` |
//! | POST   | `/api/mail/send/files` | multipart: exactly one `message` field (JSON `SendIn`, <= 8 MiB) + `files` parts (<= 20, 10 MiB each, 20 MiB total) matching `uploads`; size layer `RequestSizeLimitLayer::send_files()` (30 MiB) | 200 same as `/api/mail/send` | 400 invalid size / malformed multipart, 413 size limits, 422 metadata/file mismatch, 401, 502 `MailSendError` |
//!
//! The sender identity is resolved with main.py `_sender_account` (saved
//! display name > manual name > matching profile; never another mailbox
//! owner's profile name). Delivery success with a failed Sent copy is still
//! 200 with `sent_saved: false` and the warning text; POP3 accounts (no
//! server folders) always report it that way.
//!
//! Like main.py, neither route re-checks the session identity after
//! resolving the account: the send uses the credentials that were current
//! when the request was accepted.
//!
//! Multipart framing follows Starlette's `Request.form()` over
//! python-multipart: a body the parser cannot read is a 400
//! `"Invalid multipart data."`; a `Content-Type` whose media type is not
//! exactly `multipart/form-data` once it carries parameters (python-multipart
//! keeps its case) parses as an empty form, so it is answered like a form
//! without the `message` field.
//!
//! Deviations: python-multipart rejected a preamble before the first
//! boundary and silently dropped a truncated final part; the Rust parser
//! (multer) accepts the RFC 2046 preamble and rejects a truncated body with
//! the same 400 `"Invalid multipart data."`.

use axum::extract::{FromRequest, Multipart, Request, State};
use axum::http::{header, StatusCode};
use axum::routing::post;
use axum::{Json, Router};
use mail_core::schemas::{RequestModel, SendIn};
use mail_core::schemas::{MAX_SEND_FILES, MAX_SEND_FILES_BYTES, MAX_SEND_FILE_BYTES};
use mail_core::send_uploads::{validate_files, MessageFile, MAX_MESSAGE_JSON_BYTES};
use mail_core::smtp::{self, OutgoingMessage};
use mail_core::MailError;
use serde_json::{Map, Value};

use crate::error::{run_blocking, ApiError, ApiResult};
use crate::extract::JsonObject;
use crate::limits::RequestSizeLimitLayer;
use crate::routes::accounts::sender_account;
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route(
            "/api/mail/send",
            post(send).layer(RequestSizeLimitLayer::send_json()),
        )
        .route(
            "/api/mail/send/files",
            post(send_files).layer(RequestSizeLimitLayer::send_files()),
        )
}

fn outgoing(body: SendIn, attachments: Vec<MessageFile>) -> OutgoingMessage {
    OutgoingMessage {
        to: body.to,
        cc: body.cc,
        bcc: body.bcc,
        subject: body.subject,
        text: body.text,
        html: body.html,
        in_reply_to: body.in_reply_to,
        references: body.references,
        attachments,
    }
}

/// `{"sent": True, **result}`.
fn sent_response(result: Map<String, Value>) -> Json<Value> {
    let mut response = Map::new();
    response.insert("sent".into(), Value::Bool(true));
    response.extend(result);
    Json(Value::Object(response))
}

/// Resolve the sender and send on the blocking pool (FastAPI's threadpool).
async fn deliver(
    state: &AppState,
    body: SendIn,
    attachments: Vec<MessageFile>,
) -> ApiResult<Json<Value>> {
    let account = state.sessions.require(&body.account)?;
    let path = state.mail_servers_path.clone();
    let message = outgoing(body, attachments);
    let result = run_blocking(move || {
        let sender = sender_account(&account, &path)?;
        smtp::send_message(&sender, &message)
    })
    .await?;
    Ok(sent_response(result))
}

/// `POST /api/mail/send`.
async fn send(
    State(state): State<AppState>,
    JsonObject(body): JsonObject,
) -> ApiResult<Json<Value>> {
    let body = SendIn::from_json(&Value::Object(body))?;
    if !body.uploads.is_empty() {
        return Err(MailError::validation(
            "Use the attachment upload endpoint for messages with files",
        )
        .into());
    }
    validate_files(&body.html, &[]).map_err(MailError::validation)?;
    deliver(&state, body, Vec::new()).await
}

/// `POST /api/mail/send/files`.
async fn send_files(State(state): State<AppState>, request: Request) -> ApiResult<Json<Value>> {
    let (body, uploads) = parse_send_uploads(request).await?;
    deliver(&state, body, uploads).await
}

// ---------------------------------------------------------------------------
// send_uploads.parse_send_uploads
// ---------------------------------------------------------------------------

/// Starlette's `request.form(max_files=20, max_fields=1, max_part_size=8 MiB)`
/// limit messages (`MultiPartException` → 400).
const MAX_FORM_FIELDS: usize = 1;

/// One parsed form item.
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

fn bad_request(detail: &str) -> ApiError {
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

/// Starlette's `MultiPartException("Invalid multipart data.")` (any
/// python-multipart framing error), answered as a 400.
pub(super) const INVALID_MULTIPART: &str = "Invalid multipart data.";

/// Rewrite the request `Content-Type` to a canonical
/// `multipart/form-data; boundary="..."` carrying the boundary python-multipart
/// found, so the Rust parser accepts every header spelling Starlette accepted
/// (spaces around `=`, parameter-name case, parameter order).
pub(super) fn with_canonical_boundary(mut request: Request, boundary: &str) -> ApiResult<Request> {
    let value = format!(
        "multipart/form-data; boundary=\"{}\"",
        boundary.replace('"', "\\\"")
    );
    let value =
        axum::http::HeaderValue::from_str(&value).map_err(|_| bad_request(INVALID_MULTIPART))?;
    request.headers_mut().insert(header::CONTENT_TYPE, value);
    Ok(request)
}

/// `Content-Length: 0`: no multipart parts at all.
pub(super) fn declares_empty_body(request: &Request) -> bool {
    request
        .headers()
        .get(header::CONTENT_LENGTH)
        .is_some_and(|value| value.as_bytes() == b"0")
}

/// How Starlette's `Request.form()` treats a request `Content-Type`.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum FormType {
    /// `parse_options_header` does not yield exactly `multipart/form-data`:
    /// `request.form()` returns an empty form without reading the body.
    Empty,
    /// No `boundary` parameter: `"Missing boundary in multipart."`.
    MissingBoundary,
    /// A present but empty boundary: python-multipart cannot parse anything.
    InvalidBoundary,
    /// A parseable multipart form with this (unquoted) boundary.
    Multipart(String),
}

/// python-multipart `parse_options_header(value)` as used by Starlette's
/// `_get_form` (media type) and `MultiPartParser.parse` (boundary): without
/// parameters the media type is lowercased; with parameters it keeps its case
/// (stripped), and parameter names are lowercased with `"`-quoted values
/// unquoted. `;` inside a quoted value does not split.
pub(super) fn form_type(content_type: &str) -> FormType {
    if !content_type.contains(';') {
        return if content_type.trim().to_lowercase() == "multipart/form-data" {
            FormType::MissingBoundary
        } else {
            FormType::Empty
        };
    }
    let mut segments = Vec::new();
    let mut current = String::new();
    let mut quoted = false;
    let mut escaped = false;
    for c in content_type.chars() {
        match c {
            ';' if !quoted => segments.push(std::mem::take(&mut current)),
            '"' if !escaped => {
                quoted = !quoted;
                current.push(c);
            }
            _ => current.push(c),
        }
        escaped = c == '\\' && !escaped;
    }
    segments.push(current);
    if segments[0].trim() != "multipart/form-data" {
        return FormType::Empty;
    }
    let mut boundary = None;
    for segment in &segments[1..] {
        let Some((key, value)) = segment.split_once('=') else {
            continue;
        };
        let key = key.trim().to_lowercase();
        if key.contains('*') || key != "boundary" {
            continue;
        }
        let value = value.trim();
        let value = if value.len() >= 2 && value.starts_with('"') && value.ends_with('"') {
            &value[1..value.len() - 1]
        } else {
            value
        };
        boundary = Some(value.to_string());
    }
    match boundary {
        None => FormType::MissingBoundary,
        Some(value) if value.is_empty() => FormType::InvalidBoundary,
        Some(value) => FormType::Multipart(value),
    }
}

fn multipart_error(error: axum::extract::multipart::MultipartError) -> ApiError {
    if error.status() == StatusCode::PAYLOAD_TOO_LARGE {
        too_large(crate::limits::REQUEST_TOO_LARGE)
    } else {
        bad_request(INVALID_MULTIPART)
    }
}

/// Read the form like Starlette's `MultiPartParser`, enforcing its file,
/// field and part-size limits while streaming.
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
                    return Err(bad_request(&format!(
                        "Too many files. Maximum number of files is {MAX_SEND_FILES}."
                    )));
                }
                let content_type = field
                    .headers()
                    .get(header::CONTENT_TYPE)
                    .map(|value| value.as_bytes().iter().map(|&b| b as char).collect())
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
                    return Err(bad_request(&format!(
                        "Too many fields. Maximum number of fields is {MAX_FORM_FIELDS}."
                    )));
                }
                let mut data = Vec::new();
                while let Some(chunk) = field.chunk().await.map_err(multipart_error)? {
                    if data.len() + chunk.len() > MAX_MESSAGE_JSON_BYTES {
                        return Err(bad_request(&format!(
                            "Part exceeded maximum size of {}KB.",
                            MAX_MESSAGE_JSON_BYTES / 1024
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

/// Python `parse_send_uploads(request)`.
async fn parse_send_uploads(request: Request) -> ApiResult<(SendIn, Vec<MessageFile>)> {
    let content_type = request
        .headers()
        .get(header::CONTENT_TYPE)
        .map(|value| {
            value
                .as_bytes()
                .iter()
                .map(|&b| b as char)
                .collect::<String>()
        })
        .unwrap_or_default();
    let essence = content_type
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_lowercase();
    if essence != "multipart/form-data" {
        return Err(bad_request("Send attachments using multipart/form-data"));
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
        .any(|(name, _)| name != "message" && name != "files")
    {
        return Err(bad_request("Unexpected message upload field"));
    }
    let messages: Vec<&FormItem> = items
        .iter()
        .filter(|(name, _)| name == "message")
        .map(|(_, item)| item)
        .collect();
    let files: Vec<&FormItem> = items
        .iter()
        .filter(|(name, _)| name == "files")
        .map(|(_, item)| item)
        .collect();
    let message = match messages.as_slice() {
        [FormItem::Field(text)]
            if files
                .iter()
                .all(|file| matches!(file, FormItem::File { .. })) =>
        {
            text
        }
        _ => {
            return Err(bad_request(
                "Provide one JSON message and its uploaded files",
            ))
        }
    };
    if message.len() > MAX_MESSAGE_JSON_BYTES {
        return Err(too_large("Message metadata exceeds maximum allowed size"));
    }
    // Never echo JSON bodies, attachment contents, or addresses in errors.
    let invalid = || {
        ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "Check the message recipients, headers, size, and attachment metadata",
        )
    };
    let value: Value = serde_json::from_str(message).map_err(|_| invalid())?;
    let body = SendIn::validate(&value).map_err(|_| invalid())?;
    if files.len() != body.uploads.len() {
        return Err(bad_request(
            "Uploaded files must match the message attachment metadata",
        ));
    }
    let mut total = 0usize;
    let mut uploads = Vec::with_capacity(files.len());
    for (file, metadata) in files.into_iter().zip(&body.uploads) {
        let FormItem::File {
            filename,
            content_type,
            data,
        } = file
        else {
            unreachable!("checked above");
        };
        if data.len() > MAX_SEND_FILE_BYTES {
            return Err(too_large("Each attachment must be no larger than 10 MiB"));
        }
        total += data.len();
        if total > MAX_SEND_FILES_BYTES {
            return Err(too_large(
                "Attachments exceed the 10 MiB per-file or 20 MiB total limit",
            ));
        }
        uploads.push(MessageFile {
            filename: if filename.is_empty() {
                "attachment".into()
            } else {
                filename.clone()
            },
            content_type: if content_type.is_empty() {
                "application/octet-stream".into()
            } else {
                content_type.clone()
            },
            data: data.clone(),
            content_id: metadata.content_id.clone(),
            disposition: metadata.disposition.clone(),
        });
    }
    let uploads = validate_files(&body.html, &uploads).map_err(MailError::validation)?;
    Ok((body, uploads))
}
