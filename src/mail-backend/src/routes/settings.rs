//! Mail preferences (main.py `get_mail_preferences`, `update_mail_preferences`).
//!
//! | Method | Path            | Params / body | Success | Errors |
//! |--------|-----------------|---------------|---------|--------|
//! | GET    | `/api/settings` | — | 200 `MailPreferences` `{messages_per_page, signature, category_expiration_days{category:int}, local_ai_model}` | 500 `SettingsError` |
//! | PUT    | `/api/settings` | JSON `MailPreferencesIn` `{messages_per_page: int(strict,1..=200), signature?: str(strict,max MAX_SIGNATURE_LENGTH)="", category_expiration_days?: {EmailCategory: int(strict, <=MAX_EXPIRATION_DAYS)}|null, local_ai_model?: str(strict,max 200)|null}`; `save_mail_preferences(**model_dump(exclude_unset=True))` | 200 `MailPreferences` | 422 validation (serialized with `ensure_ascii=True`, Python separators — handled by `error::normalize_error_responses`), 500 `SettingsError` |
//!
//! Python: `load_mail_preferences()` / `save_mail_preferences()` →
//! `mail_core::settings::{load_mail_preferences, save_mail_preferences}`;
//! request model `mail_core::schemas::MailPreferencesIn`.
//!
//! Deviation: a JSON body containing a lone UTF-16 surrogate escape
//! (`"\ud800"`) is rejected by the JSON decoder (422 `json_invalid`) instead
//! of by the signature validator (422 `value_error`); both are 422 and nothing
//! is written.

use axum::routing::get;
use axum::{Json, Router};
use mail_core::schemas::{MailPreferencesIn, RequestModel};
use mail_core::settings::{load_mail_preferences, save_mail_preferences, MailPreferences};
use serde_json::Value;

use crate::error::{run_blocking, ApiResult};
use crate::extract::JsonObject;
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new().route(
        "/api/settings",
        get(get_mail_preferences).put(update_mail_preferences),
    )
}

/// `GET /api/settings`: read without creating or rewriting settings.json.
async fn get_mail_preferences() -> ApiResult<Json<MailPreferences>> {
    run_blocking(load_mail_preferences).await.map(Json)
}

/// `PUT /api/settings`: validate `MailPreferencesIn`, then save only the
/// fields the client sent (`exclude_unset=True`).
async fn update_mail_preferences(JsonObject(body): JsonObject) -> ApiResult<Json<MailPreferences>> {
    let body = MailPreferencesIn::from_json(&Value::Object(body))?;
    let (messages_per_page, update) = body.to_update();
    run_blocking(move || save_mail_preferences(&messages_per_page, &update))
        .await
        .map(Json)
}
