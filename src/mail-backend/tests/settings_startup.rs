//! Port of the application-level tests of
//! `tests/test_settings.py::SettingsTests` (server-profile file location at
//! start-up), driven through `AppState::initialize` like `main.rs`.
//!
//! Deviation: Python seeded `mail-servers.json` from the repository's copy
//! (`"purelymail" in servers`); the extension build has no project root, so
//! the file starts as `{"servers": {}}` (see
//! `mail_core::settings::initialize_mail_servers`). The tests check the empty
//! seed instead.
//!
//! These tests change process environment variables (`MAIL_SERVERS_PATH`,
//! `DATA_DIRECTORY`). They live in their own test binary and every test holds
//! the process-wide settings scope while doing so, which serializes them.

mod common;

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use axum::body::Body;
use axum::http::{Request, StatusCode};
use common::call_router;
use mail_backend::state::MAIL_SERVERS_PATH_ENV;
use mail_backend::{build_app, AppState};
use mail_core::doctor::DATA_DIRECTORY_ENV;
use mail_core::settings::{
    mail_servers_path, resolve_path, scoped_settings_path, ScopedSettingsPath,
};
use serde_json::{json, Value};

/// Restores an environment variable when dropped.
struct EnvVar {
    name: &'static str,
    previous: Option<OsString>,
}

impl EnvVar {
    fn set(name: &'static str, value: impl AsRef<std::ffi::OsStr>) -> Self {
        let previous = std::env::var_os(name);
        std::env::set_var(name, value);
        Self { name, previous }
    }

    fn unset(name: &'static str) -> Self {
        let previous = std::env::var_os(name);
        std::env::remove_var(name);
        Self { name, previous }
    }
}

impl Drop for EnvVar {
    fn drop(&mut self) {
        match self.previous.take() {
            Some(value) => std::env::set_var(self.name, value),
            None => std::env::remove_var(self.name),
        }
    }
}

/// `SettingsTestCase.setUp`: settings under `<root>/roaming/...`, no
/// `MAIL_SERVERS_PATH`, Doctor data under `<root>/data`.
struct Fixture {
    root: PathBuf,
    settings_path: PathBuf,
    // Field order: environment restored, then the settings scope released,
    // then the directory removed.
    _env: Vec<EnvVar>,
    _settings: ScopedSettingsPath,
    _temporary: tempfile::TempDir,
}

impl Fixture {
    fn new() -> Self {
        let temporary = tempfile::tempdir().unwrap();
        let root = resolve_path(temporary.path()).unwrap();
        let settings_path = root.join("roaming").join("app").join("settings.json");
        let settings = scoped_settings_path(&settings_path);
        let env = vec![
            EnvVar::unset(MAIL_SERVERS_PATH_ENV),
            EnvVar::set(DATA_DIRECTORY_ENV, root.join("data")),
        ];
        Self {
            root,
            settings_path,
            _env: env,
            _settings: settings,
            _temporary: temporary,
        }
    }

    fn write_settings(&self, content: &str) {
        std::fs::create_dir_all(self.settings_path.parent().unwrap()).unwrap();
        std::fs::write(&self.settings_path, content).unwrap();
    }
}

async fn get(state: &AppState, uri: &str) -> common::Resp {
    let request = Request::get(uri)
        .header("host", "127.0.0.1:48101")
        .body(Body::empty())
        .unwrap();
    call_router(build_app(state.clone()), request).await
}

async fn put_json(state: &AppState, uri: &str, body: &Value) -> common::Resp {
    let request = Request::put(uri)
        .header("host", "127.0.0.1:48101")
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    call_router(build_app(state.clone()), request).await
}

fn path_text(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

#[tokio::test]
async fn application_seeds_mail_servers_into_appdata_at_startup() {
    let fixture = Fixture::new();
    let profiles_path = mail_servers_path();
    assert_eq!(
        profiles_path,
        fixture.settings_path.with_file_name("mail-servers.json")
    );
    assert!(!profiles_path.exists());

    let state = AppState::initialize().unwrap();
    let response = get(&state, "/api/mail/servers").await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text());
    let data = response.json();
    assert_eq!(data["path"], path_text(&profiles_path));
    assert!(profiles_path.is_file());
    assert_eq!(data["servers"], json!({}));
    assert_eq!(data["display_names"], json!({}));
    assert!(!std::fs::read_to_string(&profiles_path)
        .unwrap()
        .to_lowercase()
        .contains("password"));
    state.shutdown();
}

#[tokio::test]
async fn mail_servers_env_override_uses_explicit_path() {
    let fixture = Fixture::new();
    let target = fixture.root.join("explicit").join("profiles.json");
    let _override = EnvVar::set(MAIL_SERVERS_PATH_ENV, &target);

    let state = AppState::initialize().unwrap();
    let data = get(&state, "/api/mail/servers").await.json();
    state.shutdown();

    assert_eq!(data["path"], path_text(&target));
    assert_eq!(data["servers"], json!({}));
    assert!(target.is_file());
    assert!(!mail_servers_path().exists());
}

#[tokio::test]
async fn blank_mail_servers_env_falls_back_to_appdata() {
    let _fixture = Fixture::new();
    let _override = EnvVar::set(MAIL_SERVERS_PATH_ENV, "   ");
    let state = AppState::initialize().unwrap();
    let data = get(&state, "/api/mail/servers").await.json();
    state.shutdown();
    assert_eq!(data["path"], path_text(&mail_servers_path()));
}

#[tokio::test]
async fn profiles_persist_in_appdata_after_application_recreation() {
    let _fixture = Fixture::new();
    let state = AppState::initialize().unwrap();
    let response = put_json(
        &state,
        "/api/mail/servers/work",
        &json!({
            "incoming_server": "imap.work.example",
            "outgoing_server": "smtp.work.example",
            "email_address": "me@work.example",
        }),
    )
    .await;
    assert_eq!(response.status, StatusCode::CREATED, "{}", response.text());
    state.shutdown();

    let profiles = mail_servers_path();
    assert!(profiles.is_file());
    let restarted = AppState::initialize().unwrap();
    let data = get(&restarted, "/api/mail/servers").await.json();
    restarted.shutdown();
    assert!(data["servers"].get("work").is_some(), "{data}");
    assert_eq!(data["servers"]["work"]["email_address"], "me@work.example");
}

#[tokio::test]
async fn explicit_profiles_path_does_not_require_valid_settings() {
    let fixture = Fixture::new();
    fixture.write_settings("{invalid}");
    let profiles = fixture.root.join("explicit").join("profiles.json");
    let _override = EnvVar::set(MAIL_SERVERS_PATH_ENV, &profiles);

    let state = AppState::initialize().unwrap();
    let health = get(&state, "/api/health").await.json();
    assert_eq!(health["status"], "ok");
    let response = get(&state, "/api/mail/servers").await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text());
    let data = response.json();
    assert_eq!(data["servers"], json!({}));
    // The broken settings only disable the saved display names.
    assert_eq!(data["display_names"], json!({}));
    assert!(data["display_names_error"]
        .as_str()
        .unwrap()
        .contains("settings.json"));
    state.shutdown();

    assert!(profiles.is_file());
    assert_eq!(std::fs::read(&fixture.settings_path).unwrap(), b"{invalid}");
}

#[tokio::test]
async fn corrupt_profiles_file_is_reported() {
    let fixture = Fixture::new();
    let profiles = fixture.root.join("mail-servers.json");
    std::fs::write(&profiles, "{broken").unwrap();
    let _override = EnvVar::set(MAIL_SERVERS_PATH_ENV, &profiles);

    let state = AppState::initialize().unwrap();
    let response = get(&state, "/api/mail/servers").await;
    state.shutdown();
    let detail = response.assert_json_error(StatusCode::INTERNAL_SERVER_ERROR);
    assert!(
        detail.as_str().unwrap().contains("mail-servers.json"),
        "{detail}"
    );
    assert_eq!(std::fs::read(&profiles).unwrap(), b"{broken");
}
