//! Local (Ollama) AI classification (main.py `local_classifier_status`,
//! `classify_message`; logic in `app/mail/local_classifier.py` →
//! `mail_core::classifier`).
//!
//! | Method | Path | Params / body | Success | Errors |
//! |--------|------|---------------|---------|--------|
//! | GET    | `/api/mail/classifier/status` | query `model: str(max 200)|None` (None → preferences `local_ai_model`); no account needed | 200 `{"available": bool, "model": str, "installed_models": [str], "error": str|null}` (read-only, never runs inference) | 422, 500 settings |
//! | POST   | `/api/mail/message/classify` | JSON `MessageClassifyIn` `{account: str(3..=320), folder: str(1..=500), uid: int(strict,1..=4294967295), uid_validity: str(strict,^[1-9][0-9]{0,9}$)}` | 200 `{"uid", "folder", ...retention metadata}` (AI category saved) | 401 (also when locked or replaced during inference), 409 retention conflict / mailbox changed, 422, 500, 502 `LocalClassifierError` (incl. `"The local model returned an invalid classification. Try again or choose another model."`), 502 IMAP |
//!
//! `classify_message` reads the message read-only, remembers the category
//! revision, runs inference, then re-checks the session identity, re-reads
//! the message (the mailbox may have changed during inference), re-checks
//! the session again and saves the AI category only if no newer category
//! change happened (`expected_category_revision`).

use axum::extract::State;
use axum::routing::{get, post};
use axum::{Json, Router};
use mail_core::classifier::{self, ClassifierStatus};
use mail_core::imap;
use mail_core::model::EMAIL_CATEGORIES;
use mail_core::schemas::{MessageClassifyIn, RequestModel};
use mail_core::settings::load_mail_preferences;
use mail_core::MailError;
use serde_json::{json, Map, Value};

use crate::error::{run_blocking, ApiResult};
use crate::extract::{JsonBody, QueryParams};
use crate::state::AppState;

/// 502 when the classifier result fails the route's own validation.
pub const INVALID_CLASSIFICATION: &str =
    "The local model returned an invalid classification. Try again or choose another model.";

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/mail/classifier/status", get(local_classifier_status))
        .route("/api/mail/message/classify", post(classify_message))
}

/// `GET /api/mail/classifier/status`.
async fn local_classifier_status(query: QueryParams) -> ApiResult<Json<ClassifierStatus>> {
    let mut q = query.validator();
    let model = q.string("model").max_length(200).optional();
    q.finish()?;
    let status = run_blocking(move || {
        let selected = match model {
            Some(model) => model,
            None => load_mail_preferences()?.local_ai_model,
        };
        Ok::<_, MailError>(classifier::get_status(&selected))
    })
    .await?;
    Ok(Json(status))
}

/// `POST /api/mail/message/classify`.
async fn classify_message(
    State(state): State<AppState>,
    JsonBody(body): JsonBody,
) -> ApiResult<Json<Value>> {
    let body = MessageClassifyIn::from_json(&body)?;
    let account = state.sessions.require(&body.account)?;
    let result = run_blocking(move || {
        let uid = i64::from(body.uid);
        let message = imap::fetch_classification_message(
            &account,
            &body.folder,
            body.uid,
            &body.uid_validity,
        )?;
        let saved = &state.retention;
        let revision =
            saved.get_category_revision(&account, &body.folder, uid, &body.uid_validity)?;
        let model = load_mail_preferences()?.local_ai_model;
        let result = classifier::classify(&model, &message.raw)?;
        let reason_length = result.reason.chars().count();
        let model_length = result.model.chars().count();
        if !EMAIL_CATEGORIES.contains(&result.category.as_str())
            || !(1..=500).contains(&reason_length)
            || !(1..=200).contains(&model_length)
        {
            return Err(MailError::Classifier(INVALID_CLASSIFICATION.to_string()));
        }
        if !state.sessions.is_current(&account) {
            return Err(MailError::credential_required(&account.email));
        }
        // Inference can take long enough for the mailbox or selected message
        // to change. Verify it again without changing read status.
        let current = imap::fetch_classification_message(
            &account,
            &body.folder,
            body.uid,
            &body.uid_validity,
        )?;
        if !state.sessions.is_current(&account) {
            return Err(MailError::credential_required(&account.email));
        }
        let policies = load_mail_preferences()?.category_expiration_days;
        saved.save_ai(
            &account,
            &body.folder,
            uid,
            &body.uid_validity,
            &result.category,
            &result.reason,
            &result.model,
            revision,
        )?;
        let metadata = saved.metadata(
            &account,
            &body.folder,
            uid,
            Some(&body.uid_validity),
            &current.headers,
            current.received_at.as_deref(),
            Some(&policies),
        )?;
        let mut response = Map::new();
        response.insert("uid".into(), json!(body.uid));
        response.insert("folder".into(), json!(body.folder));
        response.extend(metadata.into_map());
        Ok::<_, MailError>(Value::Object(response))
    })
    .await?;
    Ok(Json(result))
}
