//! Retention: manual category / expiration and sender rules (main.py
//! `update_message_retention`, `create_message_sender_rule`,
//! `list_sender_rules`, `remove_sender_rule`; logic in `app/mail/retention.py`).
//!
//! | Method | Path | Params / body | Success | Errors |
//! |--------|------|---------------|---------|--------|
//! | PUT    | `/api/mail/message/retention` | JSON `MessageRetentionIn` `{account: str(3..=320), folder: str(1..=500), uid: int(strict,1..=4294967295), uid_validity: str(strict,^[1-9][0-9]{0,9}$), category?: EmailCategory|null, expiration_days?: int(strict, <=MAX_EXPIRATION_DAYS)|null}` (only set fields change) | 200 `{"uid", "folder", ...retention metadata}` | 401, 409 `RetentionConflictError` (uid validity changed), 422, 500 `RetentionError`, 502 |
//! | POST   | `/api/mail/message/sender-rule` | JSON `MessageSenderRuleIn` = classify fields + `category: EmailCategory`, `expected_category_revision?: int(strict, ge 0)|null` | 200 `{"uid", "folder", ...metadata, "rule": {...}}` | 401 (also when re-locked mid-operation), 409 `"The email category changed. Refresh the message before saving a sender rule."`, 422 `ValueError` from `prepare_sender_rule` (string detail), 500, 502 |
//! | GET    | `/api/mail/sender-rules` | acct; `folder: str(1..=500)|None` | 200 `{"rules": [...]}` | 401, 422, 500 |
//! | DELETE | `/api/mail/sender-rules` | acct; `sender: str(3..=320)` required, `folder: str(1..=500)` required, `expected_revision: int(ge 1)|None` | 200 `{"deleted": bool}` (absent rule → `false` without contacting IMAP) | 401, 409, 422 (`normalize_sender_address` ValueError → string detail), 500, 502 |

use axum::extract::State;
use axum::routing::{get, post, put};
use axum::{Json, Router};
use mail_core::imap;
use mail_core::retention::{Patch, SaveSenderRuleOptions};
use mail_core::schemas::{MessageRetentionIn, MessageSenderRuleIn, RequestModel};
use mail_core::MailError;
use serde_json::{json, Map, Value};

use crate::error::{run_blocking, ApiResult};
use crate::extract::{JsonBody, QueryParams};
use crate::routes::mail::require_account;
use crate::state::AppState;

/// 409 when the message category moved on before a sender rule was saved.
pub const CATEGORY_CHANGED_MESSAGE: &str =
    "The email category changed. Refresh the message before saving a sender rule.";

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/mail/message/retention", put(update_message_retention))
        .route(
            "/api/mail/message/sender-rule",
            post(create_message_sender_rule),
        )
        .route(
            "/api/mail/sender-rules",
            get(list_sender_rules).delete(remove_sender_rule),
        )
}

fn to_value<T: serde::Serialize>(value: T) -> Value {
    serde_json::to_value(value).unwrap_or(Value::Null)
}

/// `PUT /api/mail/message/retention`: save independent manual overrides.
async fn update_message_retention(
    State(state): State<AppState>,
    JsonBody(body): JsonBody,
) -> ApiResult<Json<Value>> {
    let body = MessageRetentionIn::from_json(&body)?;
    let account = state.sessions.require(&body.account)?;
    // body.model_dump(include={"category", "expiration_days"}, exclude_unset=True)
    let category = match (body.fields_set.contains("category"), &body.category) {
        (false, _) => Patch::Unset,
        (true, None) => Patch::Clear,
        (true, Some(category)) => Patch::Set(category.clone()),
    };
    let expiration_days = match (
        body.fields_set.contains("expiration_days"),
        body.expiration_days,
    ) {
        (false, _) => Patch::Unset,
        (true, None) => Patch::Clear,
        (true, Some(days)) => Patch::Set(days),
    };
    let result = run_blocking(move || {
        let preferences = mail_core::settings::load_mail_preferences()?;
        imap::update_retention(
            &account,
            &body.folder,
            body.uid,
            &state.retention,
            &preferences.category_expiration_days,
            category,
            expiration_days,
            Some(&body.uid_validity),
        )
    })
    .await?;
    Ok(Json(result))
}

/// `POST /api/mail/message/sender-rule`: categorize future mail from the
/// selected message's exact sender.
async fn create_message_sender_rule(
    State(state): State<AppState>,
    JsonBody(body): JsonBody,
) -> ApiResult<Json<Value>> {
    let body = MessageSenderRuleIn::from_json(&body)?;
    let account = state.sessions.require(&body.account)?;
    let result = run_blocking(move || {
        let uid = i64::from(body.uid);
        let inspected = imap::prepare_sender_rule(&account, &body.folder, uid, &body.uid_validity)?;
        let saved = &state.retention;
        let category_revision =
            saved.get_category_revision(&account, &body.folder, uid, &body.uid_validity)?;
        let rule_revision =
            saved.get_sender_rule_revision(&account, &body.folder, &inspected.sender)?;
        let policies = mail_core::settings::load_mail_preferences()?.category_expiration_days;
        let metadata = saved.metadata(
            &account,
            &body.folder,
            uid,
            Some(&body.uid_validity),
            &inspected.headers,
            inspected.received_at.as_deref(),
            Some(&policies),
        )?;
        if metadata.category != body.category
            || body
                .expected_category_revision
                .is_some_and(|expected| expected != category_revision)
        {
            return Err(MailError::RetentionConflict(
                CATEGORY_CHANGED_MESSAGE.to_string(),
            ));
        }
        if !state.sessions.is_current(&account) {
            return Err(MailError::credential_required(&account.email));
        }
        let rule = saved.save_sender_rule(
            &account,
            &body.folder,
            &inspected.sender,
            &body.category,
            &inspected.scope.uid_validity,
            inspected.scope.first_uid,
            SaveSenderRuleOptions {
                created_at: None,
                message_uid: Some(uid),
                expected_category_revision: Some(category_revision),
                expected_sender_rule_revision: Some(rule_revision),
            },
        )?;
        let current = saved.metadata(
            &account,
            &body.folder,
            uid,
            Some(&body.uid_validity),
            &inspected.headers,
            inspected.received_at.as_deref(),
            Some(&policies),
        )?;
        let mut response = Map::new();
        response.insert("uid".into(), json!(body.uid));
        response.insert("folder".into(), json!(body.folder));
        response.extend(current.into_map());
        response.insert("rule".into(), to_value(rule));
        Ok::<_, MailError>(Value::Object(response))
    })
    .await?;
    Ok(Json(result))
}

/// `GET /api/mail/sender-rules`.
async fn list_sender_rules(
    State(state): State<AppState>,
    query: QueryParams,
) -> ApiResult<Json<Value>> {
    let mut q = query.validator();
    let account = require_account(&state, &mut q)?;
    let folder = q.string("folder").min_length(1).max_length(500).optional();
    q.finish()?;
    let account = account.expect("validated");
    let rules = run_blocking(move || {
        state
            .retention
            .list_sender_rules(&account, folder.as_deref())
    })
    .await?;
    Ok(Json(json!({ "rules": to_value(rules) })))
}

/// `DELETE /api/mail/sender-rules`: stop applying a sender rule to future
/// mail; removing an absent rule is idempotent and contacts no server.
async fn remove_sender_rule(
    State(state): State<AppState>,
    query: QueryParams,
) -> ApiResult<Json<Value>> {
    let mut q = query.validator();
    let account = require_account(&state, &mut q)?;
    let sender = q.string("sender").min_length(3).max_length(320).required();
    let folder = q.string("folder").min_length(1).max_length(500).required();
    let expected_revision = q.integer("expected_revision").ge(1).optional();
    q.finish()?;
    let account = account.expect("validated");
    let sender = sender.expect("validated");
    let folder = folder.expect("validated");

    let normalized = mail_core::retention::normalize_sender_address(&sender)?;
    let deleted = run_blocking(move || {
        let saved = &state.retention;
        if saved
            .get_sender_rule(&account, &folder, &normalized)?
            .is_none()
        {
            return Ok(false);
        }
        let scope = imap::prepare_sender_rule_scope(&account, &folder)?;
        if !state.sessions.is_current(&account) {
            return Err(MailError::credential_required(&account.email));
        }
        saved.delete_sender_rule(
            &account,
            &folder,
            &normalized,
            &scope.uid_validity,
            scope.first_uid,
            None,
            expected_revision,
        )
    })
    .await?;
    Ok(Json(json!({ "deleted": deleted })))
}
