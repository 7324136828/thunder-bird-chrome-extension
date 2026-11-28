//! Server profiles in `mail-servers.json` (main.py `list_server_profiles`,
//! `upsert_server_profile`, `delete_server_profile`). No secrets are stored.
//!
//! | Method | Path | Params / body | Success | Errors |
//! |--------|------|---------------|---------|--------|
//! | GET    | `/api/mail/servers` | — | 200 `{"path": str, "servers": {key: profile.to_dict()}, "display_names": {email: name}}`; when display names are unreadable: `"display_names": {}, "display_names_error": str` | 500 profiles unreadable (`MailServersError` → `{"detail": str}`) |
//! | PUT    | `/api/mail/servers/{key}` | path `key` (sanitized by `_profile_key`: `[^0-9A-Za-z_.-]+`→`-`, strip `-.`, lower, max 120); JSON `ServerProfileIn` `{email_address?: str(<=320)="", display_name?: str(<=200)="", incoming_server: str(1..=253), incoming_port?: int(1..=65535)=993, incoming_protocol?: str(<=20)="SSL/TLS", outgoing_server: str(1..=253), outgoing_port?: int=587, outgoing_protocol?: str(<=20)="STARTTLS"}` | **201** `{"key": safe_key, "profile": dict}` | 400 `"Profile key is empty"`, 422 validation, 500 load/save failure |
//! | DELETE | `/api/mail/servers/{key}` | path `key` (exact, not sanitized) | 200 `{"deleted": key}` | 404 `"Profile not found"`, 500 load/save failure |
//!
//! Profiles carry the POP3 extension field `incoming_mail_protocol`
//! (`ServerProfileIn` accepts `"imap"` (default) or `"pop3"`).
//!
//! Deviation: an encoded slash in the key (`%2F`) reaches the handler
//! decoded (`PUT` sanitizes it to `-`); Starlette routed on the decoded path,
//! so such a request answered 404 there.

use axum::extract::{Path as UrlPath, State};
use axum::http::StatusCode;
use axum::routing::{get, put};
use axum::{Json, Router};
use mail_core::schemas::{RequestModel, ServerProfileIn};
use mail_core::servers::{self, ServerProfile};
use mail_core::{display_names, MailError};
use serde_json::{json, Map, Value};

use crate::error::{run_blocking, ApiError, ApiResult};
use crate::extract::JsonObject;
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/mail/servers", get(list_server_profiles))
        .route(
            "/api/mail/servers/{key}",
            put(upsert_server_profile).delete(delete_server_profile),
        )
}

/// `GET /api/mail/servers`.
async fn list_server_profiles(State(state): State<AppState>) -> ApiResult<Json<Value>> {
    let path = state.mail_servers_path.clone();
    run_blocking(move || {
        let profiles = servers::load_profiles(&path)?;
        let listed: Map<String, Value> = profiles
            .iter()
            .map(|(key, profile)| (key.clone(), profile.to_dict()))
            .collect();
        let mut response = Map::new();
        response.insert("path".into(), Value::from(path.to_string_lossy()));
        response.insert("servers".into(), Value::Object(listed));
        match display_names::load_names() {
            Ok(names) => {
                response.insert("display_names".into(), json!(names));
            }
            // Server discovery with an explicit profile file stays available
            // even when the separate user preferences need repair.
            Err(MailError::Settings(message)) => {
                response.insert("display_names".into(), json!({}));
                response.insert("display_names_error".into(), Value::from(message));
            }
            Err(other) => return Err(other),
        }
        Ok(Json(Value::Object(response)))
    })
    .await
}

/// `PUT /api/mail/servers/{key}` (201).
async fn upsert_server_profile(
    State(state): State<AppState>,
    UrlPath(key): UrlPath<String>,
    JsonObject(body): JsonObject,
) -> ApiResult<(StatusCode, Json<Value>)> {
    let body = ServerProfileIn::from_json(&Value::Object(body))?;
    let path = state.mail_servers_path.clone();
    run_blocking(move || {
        let mut profiles = servers::load_profiles(&path)?;
        let safe_key = servers::profile_key(&key)?;
        let profile = ServerProfile::from_input(safe_key.clone(), &body);
        let dict = profile.to_dict();
        profiles.insert(safe_key.clone(), profile);
        servers::save_profiles(&path, &profiles)?;
        Ok::<_, MailError>((
            StatusCode::CREATED,
            Json(json!({ "key": safe_key, "profile": dict })),
        ))
    })
    .await
}

/// `DELETE /api/mail/servers/{key}`.
async fn delete_server_profile(
    State(state): State<AppState>,
    UrlPath(key): UrlPath<String>,
) -> ApiResult<Json<Value>> {
    let path = state.mail_servers_path.clone();
    run_blocking(move || {
        let mut profiles = servers::load_profiles(&path)?;
        if profiles.shift_remove(&key).is_none() {
            return Err(ApiError::new(StatusCode::NOT_FOUND, "Profile not found"));
        }
        servers::save_profiles(&path, &profiles)?;
        Ok(Json(json!({ "deleted": key })))
    })
    .await
}
