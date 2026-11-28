//! Mailbox browsing and message operations (main.py `list_folders`,
//! `list_messages`, `get_message`, `get_message_eml`, `get_attachment`,
//! `update_flags`, `delete_message`, `delete_messages`; logic in
//! `app/mail/imap_client.py`, POP3 compatibility in `mail_core::pop3`).
//!
//! "acct" = `require_account` dependency (query `account`, 401 when locked,
//! resolved before the other query parameters). Body routes call
//! `store.require(body.account)` → the same 401 shape. Every IMAP failure is
//! `MailOperationError` → 502 `{"detail": str}`.
//!
//! | Method | Path | Params / body | Success | Errors |
//! |--------|------|---------------|---------|--------|
//! | GET    | `/api/mail/folders` | acct | 200 `{"folders": [...]}` | 401, 422, 502 |
//! | GET    | `/api/mail/messages` | acct; `folder: str(max 500)="INBOX"`, `offset: int(ge 0)=0`, `limit: int(1..=200)|None` (None → preferences `messages_per_page`), `query: str(max 200)=""` (stripped), `read_status: Literal["all","unread","read"]="all"`, `sender_domain: list[str]|None` (repeated key), `category: Literal[marketing,transactional,updates,verification,uncategorized]|None`, `expired_only: bool=false` | 200 `{"total", "offset", "limit", "messages": [summary...]}` newest first | 401, 422 (FastAPI or `ValueError` from `normalize_sender_domains`/filters as string detail), 409 retention conflict, 500 settings, 502 |
//! | GET    | `/api/mail/message` | acct; `folder: str(max 500)="INBOX"`, `uid: int(ge 1)` required, `mark_seen: bool=true` | 200 message view (headers, bodies, attachments, retention metadata...); registers html image sources | 401, 422, 502 |
//! | DELETE | `/api/mail/message` | acct; `folder: str(max 500)="INBOX"`, `uid: int(ge 1)`, `trash: str(max 500)=""`, `uid_validity: str(max 10)|None` | 200 `{"deleted": uid}` | 401, 422 `"UID validity must be a positive 32-bit decimal number"` (string detail) or FastAPI list, 502 |
//! | GET    | `/api/mail/message/eml` | acct; `folder="INBOX"(max 500)`, `uid: int(ge 1)` | 200 raw bytes `message/rfc822`, `Content-Disposition: attachment; filename="message-{uid}.eml"` | 401, 422, 502 |
//! | GET    | `/api/mail/message/attachment` | acct; `folder="INBOX"(max 500)`, `uid: int(ge 1)`, `index: int(ge 0)` | 200 bytes with attachment content type, `Content-Disposition: attachment; filename="{name with ["\\\r\n] → _}"` | 401, 422, 502 |
//! | POST   | `/api/mail/message/flags` | JSON `FlagsIn` `{account: str(3..=320), folder: str(1..=500), uid: int(ge 1), seen?: bool|null, flagged?: bool|null}` | 200 `{"uid", "flags": [...], "seen", "flagged"}` | 401, 422, 502 |
//! | POST   | `/api/mail/messages/delete` | JSON `DeleteMessagesIn` `{account, folder: str(1..=500), uids: list[int(strict,1..=4294967295)] (bounded length), trash: str(<=500)="", uid_validity?: str(strict, ^[1-9][0-9]{0,9}$)|null}` | 200 `{"deleted": [uid...]}` | 401, 422, 502 |
//!
//! POP3 accounts (compatibility level): folders = INBOX only, list/read
//! supported; flags, delete with server trash and folder operations are not.
//!
//! # Intentional deviations
//!
//! * Query/body UIDs above the 32-bit IMAP range (`uid` only has `ge=1` in
//!   main.py) never reach the server: reads answer the 502 `"The server
//!   returned no data for message UID {uid}"`, flag updates answer the 502
//!   `"The server could not update flag …"` (or an empty flag list when no
//!   flag was requested), and deletes answer the 502 `"Select between 1 and
//!   500 valid message UIDs"` exactly like Python's `delete_messages`. Python
//!   sent such UIDs to the server, whose `BAD` reply escaped as a 500.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::Response;
use axum::routing::{get, post};
use axum::{Json, Router};
use mail_core::imap::{self, ListMessagesOptions};
use mail_core::schemas::{DeleteMessagesIn, FlagsIn, RequestModel};
use mail_core::{MailAccount, MailError};
use serde_json::{json, Value};

use crate::error::{run_blocking, ApiError, ApiResult};
use crate::extract::{JsonBody, QueryParams, QueryValidator};
use crate::state::AppState;

/// `Content-Security-Policy` of attachment / `.eml` downloads.
pub const DOWNLOAD_CSP: &str = "default-src 'none'; sandbox";

/// `Literal[...]` of `read_status`.
const READ_STATUSES: &[&str] = &["all", "unread", "read"];
/// `Literal[...]` of the `category` filter.
const CATEGORIES: &[&str] = &[
    "marketing",
    "transactional",
    "updates",
    "verification",
    "uncategorized",
];
/// main.py's 422 for an invalid `uid_validity` query parameter.
pub const UID_VALIDITY_MESSAGE: &str = "UID validity must be a positive 32-bit decimal number";

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/mail/folders", get(list_folders))
        .route("/api/mail/messages", get(list_messages))
        .route("/api/mail/message", get(get_message).delete(delete_message))
        .route("/api/mail/message/eml", get(get_message_eml))
        .route("/api/mail/message/attachment", get(get_attachment))
        .route("/api/mail/message/flags", post(update_flags))
        .route("/api/mail/messages/delete", post(delete_messages))
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

/// The `require_account` dependency: when `account` is present the 401 is
/// raised immediately (before the endpoint's own parameters are validated);
/// a missing `account` is recorded as a 422 issue with the others.
pub(crate) fn require_account(
    state: &AppState,
    q: &mut QueryValidator<'_>,
) -> ApiResult<Option<Arc<MailAccount>>> {
    match q.string("account").required() {
        Some(email) => Ok(Some(state.sessions.require(&email)?)),
        None => Ok(None),
    }
}

/// Body routes: `store.require(body.account)` → 401 `password_required`.
fn require_body_account(state: &AppState, email: &str) -> ApiResult<Arc<MailAccount>> {
    Ok(state.sessions.require(email)?)
}

/// The UID as an IMAP UID (32-bit), when it is one.
fn imap_uid(uid: i64) -> Option<u32> {
    u32::try_from(uid).ok().filter(|uid| *uid >= 1)
}

/// Python `str.strip()` (Unicode whitespace plus the `\x1c`-`\x1f`
/// separators, which `str.isspace` also counts).
fn py_strip(value: &str) -> &str {
    value.trim_matches(|c: char| c.is_whitespace() || ('\x1c'..='\x1f').contains(&c))
}

/// What a read of a UID outside the IMAP range answers (see module docs).
fn no_data(uid: impl std::fmt::Display) -> MailError {
    MailError::operation(format!("The server returned no data for message UID {uid}"))
}

/// Starlette `Response(media_type=...)`: `text/*` types get `; charset=utf-8`.
fn starlette_media_type(media_type: &str) -> String {
    if media_type.starts_with("text/") && !media_type.to_lowercase().contains("charset=") {
        format!("{media_type}; charset=utf-8")
    } else {
        media_type.to_string()
    }
}

/// Starlette encodes header values as latin-1; anything that cannot be
/// encoded (or that the HTTP layer rejects) failed with a 500 in Python.
fn latin1_header(value: &str) -> ApiResult<HeaderValue> {
    let bytes: Option<Vec<u8>> = value
        .chars()
        .map(|character| u8::try_from(u32::from(character)).ok())
        .collect();
    bytes
        .and_then(|bytes| HeaderValue::from_bytes(&bytes).ok())
        .ok_or_else(|| {
            tracing::error!("response header value could not be encoded");
            ApiError::internal()
        })
}

/// `Response(content=..., media_type=..., headers={"Content-Disposition": ...})`.
///
/// Intentional deviation (hardening): downloads also carry
/// `X-Content-Type-Options: nosniff`, `Cache-Control: no-store` and
/// `Content-Security-Policy: default-src 'none'; sandbox`, so an attachment
/// or `.eml` (attacker-controlled bytes and content type) opened directly in
/// a tab can neither be sniffed into HTML nor run script on the backend's
/// origin, and decrypted mail is not kept in the browser cache. Python sent
/// only `Content-Disposition`.
fn download_response(content: Vec<u8>, media_type: &str, disposition: &str) -> ApiResult<Response> {
    let content_type = latin1_header(&starlette_media_type(media_type))?;
    let disposition = latin1_header(disposition)?;
    let length = content.len();
    let mut response = Response::new(Body::from(content));
    *response.status_mut() = StatusCode::OK;
    let headers = response.headers_mut();
    headers.insert(header::CONTENT_DISPOSITION, disposition);
    headers.insert(header::CONTENT_LENGTH, HeaderValue::from(length));
    headers.insert(header::CONTENT_TYPE, content_type);
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(DOWNLOAD_CSP),
    );
    Ok(response)
}

/// main.py `re.sub(r'["\\\r\n]', "_", filename)`.
pub fn sanitize_filename(filename: &str) -> String {
    filename
        .chars()
        .map(|character| match character {
            '"' | '\\' | '\r' | '\n' => '_',
            other => other,
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------------

/// `GET /api/mail/folders`.
async fn list_folders(
    axum::extract::State(state): axum::extract::State<AppState>,
    query: QueryParams,
) -> ApiResult<Json<Value>> {
    let mut q = query.validator();
    let account = require_account(&state, &mut q)?;
    q.finish()?;
    let account = account.expect("validated");
    let folders = run_blocking(move || imap::list_folders(&account)).await?;
    Ok(Json(json!({ "folders": folders })))
}

/// `GET /api/mail/messages`.
async fn list_messages(
    axum::extract::State(state): axum::extract::State<AppState>,
    query: QueryParams,
) -> ApiResult<Json<Value>> {
    let mut q = query.validator();
    let account = require_account(&state, &mut q)?;
    let folder = q.string("folder").max_length(500).default("INBOX");
    let offset = q.integer("offset").ge(0).default(0);
    let limit = q.integer("limit").ge(1).le(200).optional();
    let search = q.string("query").max_length(200).default("");
    let read_status = q.literal("read_status", READ_STATUSES).default("all");
    let sender_domain = q.list("sender_domain");
    let category = q.literal("category", CATEGORIES).optional();
    let expired_only = q.boolean("expired_only").default(false);
    q.finish()?;
    let account = account.expect("validated");

    let sender_domains =
        imap::normalize_sender_domains(sender_domain.as_deref()).map_err(MailError::validation)?;
    let has_unicode_input = sender_domain
        .iter()
        .flatten()
        .any(|domain| !domain.is_ascii());
    let offset = usize::try_from(offset).unwrap_or(usize::MAX);
    let search = py_strip(&search).to_string();

    let result = run_blocking(move || {
        let preferences = mail_core::settings::load_mail_preferences()?;
        let effective_limit = match limit {
            Some(limit) => usize::try_from(limit).unwrap_or(usize::MAX),
            None => preferences.messages_per_page as usize,
        };
        let options = ListMessagesOptions {
            offset,
            limit: effective_limit,
            query: &search,
            read_status,
            sender_domains: &sender_domains,
            has_unicode_input,
            retention_store: Some(&state.retention),
            category_expiration_days: Some(&preferences.category_expiration_days),
            category,
            expired_only,
        };
        imap::list_messages(&account, &folder, &options)
    })
    .await?;
    Ok(Json(result))
}

/// `GET /api/mail/message`: the message view; its HTML image sources are
/// registered for the image proxy.
async fn get_message(
    axum::extract::State(state): axum::extract::State<AppState>,
    query: QueryParams,
) -> ApiResult<Json<Value>> {
    let mut q = query.validator();
    let account = require_account(&state, &mut q)?;
    let folder = q.string("folder").max_length(500).default("INBOX");
    let uid = q.integer("uid").ge(1).required();
    let mark_seen = q.boolean("mark_seen").default(true);
    q.finish()?;
    let account = account.expect("validated");
    let uid = uid.expect("validated");

    let message = run_blocking(move || {
        // main.py evaluated load_mail_preferences() as an argument, i.e.
        // before any mailbox access.
        let preferences = mail_core::settings::load_mail_preferences()?;
        let Some(imap_uid) = imap_uid(uid) else {
            return Err(no_data(uid));
        };
        let message = imap::fetch_message(
            &account,
            &folder,
            imap_uid,
            mark_seen,
            Some(&state.retention),
            Some(&preferences.category_expiration_days),
        )?;
        let html = message
            .get("html_body")
            .and_then(Value::as_str)
            .unwrap_or("");
        state
            .image_sources
            .register(&account.email, &folder, imap_uid, html);
        Ok::<_, MailError>(message)
    })
    .await?;
    Ok(Json(message))
}

/// `GET /api/mail/message/eml`: the raw message as a download.
async fn get_message_eml(
    axum::extract::State(state): axum::extract::State<AppState>,
    query: QueryParams,
) -> ApiResult<Response> {
    let mut q = query.validator();
    let account = require_account(&state, &mut q)?;
    let folder = q.string("folder").max_length(500).default("INBOX");
    let uid = q.integer("uid").ge(1).required();
    q.finish()?;
    let account = account.expect("validated");
    let uid = uid.expect("validated");

    let raw = run_blocking(move || match imap_uid(uid) {
        Some(imap_uid) => imap::fetch_raw(&account, &folder, imap_uid),
        None => Err(no_data(uid)),
    })
    .await?;
    download_response(
        raw,
        "message/rfc822",
        &format!("attachment; filename=\"message-{uid}.eml\""),
    )
}

/// `GET /api/mail/message/attachment`: one attachment as a download.
async fn get_attachment(
    axum::extract::State(state): axum::extract::State<AppState>,
    query: QueryParams,
) -> ApiResult<Response> {
    let mut q = query.validator();
    let account = require_account(&state, &mut q)?;
    let folder = q.string("folder").max_length(500).default("INBOX");
    let uid = q.integer("uid").ge(1).required();
    let index = q.integer("index").ge(0).required();
    q.finish()?;
    let account = account.expect("validated");
    let uid = uid.expect("validated");
    let index = usize::try_from(index.expect("validated")).unwrap_or(usize::MAX);

    let attachment = run_blocking(move || match imap_uid(uid) {
        Some(imap_uid) => imap::fetch_attachment(&account, &folder, imap_uid, index),
        None => Err(no_data(uid)),
    })
    .await?;
    let filename = sanitize_filename(&attachment.filename);
    download_response(
        attachment.content,
        &attachment.content_type,
        &format!("attachment; filename=\"{filename}\""),
    )
}

/// `POST /api/mail/message/flags`.
async fn update_flags(
    axum::extract::State(state): axum::extract::State<AppState>,
    JsonBody(body): JsonBody,
) -> ApiResult<Json<Value>> {
    let body = FlagsIn::from_json(&body)?;
    let account = require_body_account(&state, &body.account)?;
    let result = run_blocking(move || {
        match u32::try_from(body.uid) {
            Ok(uid) => imap::set_flags(&account, &body.folder, uid, body.seen, body.flagged),
            Err(_) if account.is_pop3() => Err(mail_core::pop3::imap_only()),
            // Outside the IMAP UID range: what a server refusing the STORE
            // (or returning no FLAGS) produced in Python.
            Err(_) => {
                for (value, flag) in [(body.seen, "\\Seen"), (body.flagged, "\\Flagged")] {
                    if value.is_some() {
                        return Err(MailError::operation(format!(
                            "The server could not update flag {flag}"
                        )));
                    }
                }
                Ok(json!({"uid": body.uid, "flags": [], "seen": false, "flagged": false}))
            }
        }
    })
    .await?;
    Ok(Json(result))
}

/// `DELETE /api/mail/message`: move to `trash` (or delete permanently).
async fn delete_message(
    axum::extract::State(state): axum::extract::State<AppState>,
    query: QueryParams,
) -> ApiResult<Json<Value>> {
    let mut q = query.validator();
    let account = require_account(&state, &mut q)?;
    let folder = q.string("folder").max_length(500).default("INBOX");
    let uid = q.integer("uid").ge(1).required();
    let trash = q.string("trash").max_length(500).default("");
    let uid_validity = q.string("uid_validity").max_length(10).optional();
    q.finish()?;
    let account = account.expect("validated");
    let uid = uid.expect("validated");

    let expected = match uid_validity {
        Some(value) => match mail_core::retention::normalize_uid_validity(&value) {
            Some(normalized) => Some(normalized),
            None => return Err(MailError::validation(UID_VALIDITY_MESSAGE).into()),
        },
        None => None,
    };
    run_blocking(move || match imap_uid(uid) {
        Some(imap_uid) => {
            imap::delete_message(&account, &folder, imap_uid, &trash, expected.as_deref())
        }
        // UID 0 is rejected exactly like Python rejected out-of-range UIDs
        // ("Select between 1 and 500 valid message UIDs").
        None => {
            imap::delete_messages(&account, &folder, &[0], &trash, expected.as_deref()).map(|_| ())
        }
    })
    .await?;
    Ok(Json(json!({ "deleted": uid })))
}

/// `POST /api/mail/messages/delete`.
async fn delete_messages(
    axum::extract::State(state): axum::extract::State<AppState>,
    JsonBody(body): JsonBody,
) -> ApiResult<Json<Value>> {
    let body = DeleteMessagesIn::from_json(&body)?;
    let account = require_body_account(&state, &body.account)?;
    let deleted = run_blocking(move || {
        imap::delete_messages(
            &account,
            &body.folder,
            &body.uids,
            &body.trash,
            body.uid_validity.as_deref(),
        )
    })
    .await?;
    Ok(Json(json!({ "deleted": deleted })))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filenames_are_sanitized_like_main_py() {
        assert_eq!(sanitize_filename("a\"b\\c\r\nd.pdf"), "a_b_c__d.pdf");
        assert_eq!(sanitize_filename("résumé.pdf"), "résumé.pdf");
    }

    #[test]
    fn media_types_follow_starlette() {
        assert_eq!(
            starlette_media_type("text/plain"),
            "text/plain; charset=utf-8"
        );
        assert_eq!(starlette_media_type("message/rfc822"), "message/rfc822");
        assert_eq!(
            starlette_media_type("text/csv; charset=latin-1"),
            "text/csv; charset=latin-1"
        );
    }

    #[test]
    fn headers_are_latin1_encoded() {
        assert_eq!(
            latin1_header("attachment; filename=\"é.txt\"")
                .unwrap()
                .as_bytes(),
            b"attachment; filename=\"\xe9.txt\""
        );
        assert!(latin1_header("filename=\"\u{65e5}.txt\"").is_err());
        assert!(latin1_header("filename=\"a\u{0}b\"").is_err());
    }

    #[test]
    fn strip_matches_python() {
        assert_eq!(py_strip("\u{1c} \t offers \u{a0}\u{3000}\n"), "offers");
        assert_eq!(py_strip(""), "");
    }

    #[test]
    fn imap_uid_range() {
        assert_eq!(imap_uid(1), Some(1));
        assert_eq!(imap_uid(4_294_967_295), Some(u32::MAX));
        assert_eq!(imap_uid(4_294_967_296), None);
        assert_eq!(imap_uid(0), None);
    }
}
