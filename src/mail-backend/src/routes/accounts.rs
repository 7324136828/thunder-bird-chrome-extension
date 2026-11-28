//! Unlocked-account sessions (main.py `list_accounts`, `unlock_account`,
//! `lock_account`). Passwords live in `AppState::sessions` only.
//!
//! | Method | Path | Params / body | Success | Errors |
//! |--------|------|---------------|---------|--------|
//! | GET    | `/api/accounts` | — | 200 `{"accounts": [public_dict, ...]}` (each resolved with `_sender_account`: saved display name > manual name > matching profile name) | 500 profiles unreadable (`_load_profiles_or_500`), 500 `SettingsError` (display names) |
//! | POST   | `/api/accounts/unlock` | JSON `UnlockIn` `{email: str(3..=320), password: str(1..=4096), profile_key?: str(<=200)|null, display_name?: str(<=200)="", incoming_server?: str(<=253)|null, incoming_port?: int(1..=65535)|null, incoming_protocol?: str(<=20)|null, outgoing_server?, outgoing_port?, outgoing_protocol?, save_profile?: bool=false}` (+ POP3 port: `incoming_mail_protocol`) | 200 `{"account": public_dict}` | 400 `"Enter a valid email address"` (count('@') != 1), 404 `"Profile not found"` (unknown profile_key), 400 `"No incoming (IMAP) server is configured for this account"`, 401 `{detail: str(error)}` when `verify_login` fails (MailOperationError → 401 here, not 502), 422 validation (`ensure_ascii=True`), 500 profiles unreadable |
//! | DELETE | `/api/accounts/{email}` | path `email` | 200 `{"locked": email.strip().lower()}`; also forgets image sources, clears remote-image cache, forgets trash operations | 404 `"Account is not unlocked"` |
//!
//! Side effects of unlock: `display_names.save_name` when `display_name` was
//! sent, `audit_scheduler.register(email)`, best-effort profile save when
//! `save_profile` and no profile matched (key = `_profile_key(email)`).
//!
//! POP3 extension: `incoming_mail_protocol` is taken from the request, else
//! from the selected/matched profile, else `"imap"`; `verify_login`
//! dispatches to POP3 for such accounts and a profile saved by unlock keeps
//! the protocol.
//!
//! `GET /api/accounts` lists accounts in session-store insertion order
//! (first unlock; a re-unlock keeps the position), like the Python dict.
//!
//! # Intentional deviations
//!
//! * A POP3 unlock without an explicit or profile incoming port defaults to
//!   995 instead of 993 (the extension has no Python counterpart).
//! * A profile whose stored port lies outside 1..=65535 cannot be used to
//!   unlock: the route answers 500 `Internal Server Error` (Python passed the
//!   value to the socket layer, whose `OverflowError` escaped as a 500 too).
//! * A failing `audit_scheduler.register` (SQLite error) answers the generic
//!   500 after the account was unlocked, as the unhandled Python exception did.
//! * `DELETE /api/accounts/a%2Fb@example.org` reaches the handler with the
//!   decoded `/` (404 "Account is not unlocked" unless such a session
//!   exists); Starlette routed on the decoded path and answered 404 Not Found.

use std::path::Path;
use std::sync::Arc;

use axum::extract::{Path as UrlPath, State};
use axum::http::StatusCode;
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use mail_core::schemas::{RequestModel, UnlockIn};
use mail_core::servers::{self, Profiles, ServerProfile};
use mail_core::sessions::{PROTOCOL_IMAP, PROTOCOL_POP3};
use mail_core::{display_names, imap, remote_images, MailAccount, MailError};
use serde_json::{json, Value};

use crate::error::{run_blocking, ApiError, ApiResult};
use crate::extract::JsonObject;
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/accounts", get(list_accounts))
        .route("/api/accounts/unlock", post(unlock_account))
        .route("/api/accounts/{email}", delete(lock_account))
}

/// `_load_profiles_or_500`: `MailServersError` is already a 500 `MailError`.
fn load_profiles_or_500(path: &Path) -> Result<Profiles, MailError> {
    servers::load_profiles(path)
}

/// main.py `_sender_account(account, path)`: resolve profile names at
/// request time, preserving a manually entered name.
///
/// The single shared implementation, used by `GET /api/accounts` and by the
/// send routes (`POST /api/mail/send`, `POST /api/mail/send/files`).
///
/// Errors: `MailError::Settings` (unreadable settings.json display names or
/// mail-servers.json, both HTTP 500 with the error text).
pub fn sender_account(account: &MailAccount, path: &Path) -> Result<MailAccount, MailError> {
    let names = display_names::load_names()?;
    let email = account.email.to_lowercase();
    if let Some(name) = names.get(&email) {
        let mut resolved = account.clone();
        resolved.display_name = name.clone();
        return Ok(resolved);
    }
    if !account.display_name.trim().is_empty() && account.sender_profile_key.is_none() {
        return Ok(account.clone());
    }
    let profiles = load_profiles_or_500(path)?;
    let profile = match account.sender_profile_key.as_deref() {
        // `profiles.get(key) if key else next(...)`: an empty key is falsy.
        Some(key) if !key.is_empty() => profiles.get(key),
        _ => profiles
            .values()
            .find(|item| item.email_address.to_lowercase() == email),
    };
    let Some(profile) = profile else {
        return Ok(account.clone());
    };
    // Provider-domain matching is suitable for server settings, but must not
    // borrow another mailbox owner's identity for an outgoing message.
    if !profile.email_address.is_empty() && profile.email_address.to_lowercase() != email {
        return Ok(account.clone());
    }
    let mut resolved = account.clone();
    resolved.display_name = profile.display_name.clone();
    Ok(resolved)
}

/// `GET /api/accounts`.
async fn list_accounts(State(state): State<AppState>) -> ApiResult<Json<Value>> {
    let path = state.mail_servers_path.clone();
    let accounts = state.sessions.list();
    run_blocking(move || {
        let listed = accounts
            .iter()
            .map(|account| sender_account(account, &path).map(|item| item.public_dict()))
            .collect::<Result<Vec<_>, MailError>>()?;
        Ok::<_, MailError>(Json(json!({ "accounts": listed })))
    })
    .await
}

/// `POST /api/accounts/unlock`.
async fn unlock_account(
    State(state): State<AppState>,
    JsonObject(body): JsonObject,
) -> ApiResult<Json<Value>> {
    let body = UnlockIn::from_json(&Value::Object(body))?;
    run_blocking(move || unlock(&state, body)).await.map(Json)
}

/// Python `pick(given, fallback, default)`.
fn pick<T>(given: Option<T>, fallback: Option<T>, default: T) -> T {
    given.or(fallback).unwrap_or(default)
}

/// A profile port as a socket port (see the module's deviations).
fn profile_port(port: i64) -> Result<u16, ApiError> {
    u16::try_from(port).map_err(|_| {
        tracing::error!("server profile port {port} is outside 0..=65535");
        ApiError::internal()
    })
}

/// The synchronous body of `unlock_account` (FastAPI ran it in its threadpool).
fn unlock(state: &AppState, body: UnlockIn) -> Result<Value, ApiError> {
    let email = body.email.trim().to_string();
    if email.matches('@').count() != 1 {
        return Err(ApiError::bad_request("Enter a valid email address"));
    }
    let lowered = email.to_lowercase();

    let path = state.mail_servers_path.as_path();
    let mut profiles = load_profiles_or_500(path)?;
    let mut profile: Option<ServerProfile> = None;
    if let Some(key) = body.profile_key.as_deref().filter(|key| !key.is_empty()) {
        match profiles.get(key) {
            Some(found) => profile = Some(found.clone()),
            None => {
                return Err(ApiError::new(StatusCode::NOT_FOUND, "Profile not found"));
            }
        }
    }
    if profile.is_none() {
        profile = servers::profile_for_email(&profiles, &email).cloned();
    }
    let profile = profile;

    let profile_name = match &profile {
        Some(found)
            if found.email_address.is_empty() || found.email_address.to_lowercase() == lowered =>
        {
            found.display_name.clone()
        }
        _ => String::new(),
    };
    let requested_name = body
        .display_name_set()
        .then(|| body.display_name.trim().to_string());
    let saved_names = display_names::load_names()?;
    let sender_name = match &requested_name {
        Some(name) => name.clone(),
        None => saved_names
            .get(&lowered)
            .cloned()
            .unwrap_or_else(|| profile_name.clone()),
    };

    let incoming_mail_protocol = pick(
        body.incoming_mail_protocol.clone(),
        profile.as_ref().map(|p| p.incoming_mail_protocol.clone()),
        PROTOCOL_IMAP.to_string(),
    );
    let default_incoming_port = if incoming_mail_protocol.eq_ignore_ascii_case(PROTOCOL_POP3) {
        995
    } else {
        993
    };
    let incoming_port = match (body.incoming_port, &profile) {
        (Some(port), _) => port,
        (None, Some(found)) => profile_port(found.incoming_port)?,
        (None, None) => default_incoming_port,
    };
    let outgoing_port = match (body.outgoing_port, &profile) {
        (Some(port), _) => port,
        (None, Some(found)) => profile_port(found.outgoing_port)?,
        (None, None) => 587,
    };
    let mut account = MailAccount::new(
        email.clone(),
        body.password,
        pick(
            body.incoming_server.clone(),
            profile.as_ref().map(|p| p.incoming_server.clone()),
            String::new(),
        )
        .trim(),
        incoming_port,
        pick(
            body.incoming_protocol.clone(),
            profile.as_ref().map(|p| p.incoming_protocol.clone()),
            "SSL/TLS".to_string(),
        )
        .trim(),
        pick(
            body.outgoing_server.clone(),
            profile.as_ref().map(|p| p.outgoing_server.clone()),
            String::new(),
        )
        .trim(),
        outgoing_port,
        pick(
            body.outgoing_protocol.clone(),
            profile.as_ref().map(|p| p.outgoing_protocol.clone()),
            "STARTTLS".to_string(),
        )
        .trim(),
    );
    account.display_name = sender_name.clone();
    account.sender_profile_key = profile
        .as_ref()
        .filter(|_| sender_name == profile_name)
        .map(|found| found.key.clone());
    account.incoming_mail_protocol = incoming_mail_protocol;

    if account.incoming_server.is_empty() {
        return Err(ApiError::bad_request(
            "No incoming (IMAP) server is configured for this account",
        ));
    }
    match imap::verify_login(&account) {
        Ok(()) => {}
        Err(MailError::Operation(message)) => {
            return Err(ApiError::new(StatusCode::UNAUTHORIZED, message));
        }
        Err(other) => return Err(other.into()),
    }

    if let Some(requested) = &requested_name {
        // Unchanged profile defaults remain live; custom and cleared names
        // persist independently of whether server settings are saved.
        let keep_default = profile.is_some() && !requested.is_empty() && *requested == profile_name;
        display_names::save_name(&email, (!keep_default).then_some(requested.as_str()))?;
    }

    let account: Arc<MailAccount> = state.sessions.unlock(account);
    if let Err(error) = state.audit_scheduler.register(&account.email, None) {
        tracing::error!("could not register the weekly audit schedule: {error}");
        return Err(ApiError::internal());
    }

    if body.save_profile && profile.is_none() {
        let safe_key = servers::profile_key(&email)?;
        let mut saved = ServerProfile::new(
            safe_key.clone(),
            account.incoming_server.clone(),
            i64::from(account.incoming_port),
            account.incoming_protocol.clone(),
            account.outgoing_server.clone(),
            i64::from(account.outgoing_port),
            account.outgoing_protocol.clone(),
        );
        saved.email_address = email.clone();
        saved.display_name = account.display_name.clone();
        saved.incoming_mail_protocol = account.incoming_mail_protocol.to_lowercase();
        profiles.insert(safe_key, saved);
        // Unlocking already succeeded; persistence is best-effort.
        let _ = servers::save_profiles(path, &profiles);
    }

    Ok(json!({ "account": account.public_dict() }))
}

/// `DELETE /api/accounts/{email}`.
async fn lock_account(
    State(state): State<AppState>,
    UrlPath(email): UrlPath<String>,
) -> ApiResult<Json<Value>> {
    run_blocking(move || {
        if !state.sessions.forget(&email) {
            return Err(ApiError::new(
                StatusCode::NOT_FOUND,
                "Account is not unlocked",
            ));
        }
        state.image_sources.forget(&email);
        remote_images::clear_cache();
        state.trash.forget(&email);
        Ok(Json(json!({ "locked": email.trim().to_lowercase() })))
    })
    .await
}
