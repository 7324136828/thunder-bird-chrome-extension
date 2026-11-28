//! Message security audit (main.py `audit_message`, `audit_pasted`; logic in
//! `app/mail/audit.py` → `mail_core::audit`).
//!
//! | Method | Path | Params / body | Success | Errors |
//! |--------|------|---------------|---------|--------|
//! | GET    | `/api/mail/audit` | acct; `folder: str(max 500)="INBOX"`, `uid: int(ge 1)` | 200 audit report (`audit.audit_message(raw, account_email=account.email)`) | 401, 422, 502 |
//! | POST   | `/api/audit/eml` | JSON `PasteAuditIn` `{content: str(min 1)}`; encoded UTF-8 with `replace`; no account | 200 audit report (`audit.audit_message(raw)`) | 422 |
//!
//! # Intentional deviations
//!
//! * A `uid` above the 32-bit IMAP range never reaches the server: the route
//!   answers the 502 `"The server returned no data for message UID {uid}"`
//!   (as `routes/mail.rs` does). Python sent it and the server's `BAD`
//!   escaped as a 500.
//! * Pasted content containing a lone UTF-16 surrogate escape (`"\ud800"`)
//!   is rejected by the JSON decoder (422 `json_invalid`); Python decoded it
//!   and encoded the surrogate as `?`.

use axum::extract::State;
use axum::routing::{get, post};
use axum::{Json, Router};
use mail_core::schemas::{PasteAuditIn, RequestModel};
use mail_core::{audit, imap, MailError};
use serde_json::Value;

use crate::error::{run_blocking, ApiResult};
use crate::extract::{JsonObject, QueryParams};
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/mail/audit", get(audit_message))
        .route("/api/audit/eml", post(audit_pasted))
}

/// `GET /api/mail/audit`.
async fn audit_message(
    State(state): State<AppState>,
    query: QueryParams,
) -> ApiResult<Json<Value>> {
    let mut q = query.validator();
    // Dependency `require_account` (resolved before the other parameters).
    let account = match q.string("account").required() {
        Some(email) => Some(state.sessions.require(&email)?),
        None => None,
    };
    let folder = q.string("folder").max_length(500).default("INBOX");
    let uid = q.integer("uid").ge(1).required();
    q.finish()?;
    let account = account.expect("validated");
    let uid = uid.expect("validated");

    run_blocking(move || {
        let raw = match u32::try_from(uid) {
            Ok(imap_uid) => imap::fetch_raw(&account, &folder, imap_uid)?,
            Err(_) => {
                return Err(MailError::operation(format!(
                    "The server returned no data for message UID {uid}"
                )))
            }
        };
        Ok(Json(audit::audit_message(&raw, Some(&account.email))))
    })
    .await
}

/// `POST /api/audit/eml`: audit pasted message source; no account needed.
async fn audit_pasted(JsonObject(body): JsonObject) -> ApiResult<Json<Value>> {
    let body = PasteAuditIn::from_json(&Value::Object(body))?;
    run_blocking(move || {
        let raw = body.content.into_bytes();
        Ok::<_, MailError>(Json(audit::audit_message(&raw, None)))
    })
    .await
}
