//! Shared helpers for the `accounts_*`, `servers_*`, `settings_*` and
//! `audit_*` route tests.
//!
//! Python's `ApiTestCase` / `SettingsTestCase` patched the settings location
//! to a temporary directory; [`Harness`] holds a
//! `mail_core::settings::scoped_settings_path` guard for the same purpose
//! (holders are serialized process-wide, so the tests of one binary never
//! share settings even though they run on parallel threads). Never create two
//! harnesses at once in one test: the second would wait for the first guard.

#![allow(dead_code)]

use std::path::{Path, PathBuf};

use axum::body::Body;
use axum::http::{Method, Request};
use axum::Router;
use mail_backend::{build_app, AppState};
use mail_core::settings::{scoped_settings_path, ScopedSettingsPath};
use serde_json::Value;

use crate::common::{call_router, Resp};

pub const HOST: &str = "127.0.0.1:48101";

/// An app over a temporary state directory and settings file.
pub struct Harness {
    pub app: Router,
    pub state: AppState,
    pub root: PathBuf,
    pub settings_path: PathBuf,
    // Declared before `_temporary` so the override is dropped first.
    _settings: ScopedSettingsPath,
    _temporary: tempfile::TempDir,
}

impl Harness {
    /// Empty `{"servers": {}}` profiles.
    pub fn new() -> Self {
        Self::build(None)
    }

    /// `mail-servers.json` written with `profiles` before the app starts.
    pub fn with_profiles(profiles: &Value) -> Self {
        Self::build(Some(profiles))
    }

    fn build(profiles: Option<&Value>) -> Self {
        let temporary = tempfile::tempdir().expect("tempdir");
        let root = mail_core::settings::resolve_path(temporary.path())
            .unwrap_or_else(|_| temporary.path().to_path_buf());
        let settings_path = root.join("settings.json");
        let settings = scoped_settings_path(&settings_path);
        if let Some(profiles) = profiles {
            std::fs::write(root.join("mail-servers.json"), profiles.to_string())
                .expect("write profiles");
        }
        let state = AppState::for_tests(&root);
        Self {
            app: build_app(state.clone()),
            state,
            root,
            settings_path,
            _settings: settings,
            _temporary: temporary,
        }
    }

    pub fn profiles_path(&self) -> PathBuf {
        self.state.mail_servers_path.clone()
    }

    pub fn write_profiles(&self, profiles: &Value) {
        std::fs::write(self.profiles_path(), profiles.to_string()).expect("write profiles");
    }

    pub fn read_profiles(&self) -> Value {
        read_json(&self.profiles_path())
    }

    pub fn write_settings(&self, content: &str) {
        std::fs::write(&self.settings_path, content.as_bytes()).expect("write settings");
    }

    /// A second app over the same files (Python's restarted `TestClient`):
    /// a fresh, empty session store.
    pub fn restarted(&self) -> Client {
        let state = AppState::for_tests(&self.root);
        Client {
            app: build_app(state.clone()),
            state,
        }
    }

    pub fn client(&self) -> Client {
        Client {
            app: self.app.clone(),
            state: self.state.clone(),
        }
    }

    pub async fn get(&self, uri: &str) -> Resp {
        self.client().get(uri).await
    }

    pub async fn delete(&self, uri: &str) -> Resp {
        self.client().delete(uri).await
    }

    pub async fn put_json(&self, uri: &str, body: &Value) -> Resp {
        self.client().put_json(uri, body).await
    }

    pub async fn post_json(&self, uri: &str, body: &Value) -> Resp {
        self.client().post_json(uri, body).await
    }

    pub async fn raw(
        &self,
        method: Method,
        uri: &str,
        content_type: Option<&str>,
        body: impl Into<Vec<u8>>,
    ) -> Resp {
        self.client().raw(method, uri, content_type, body).await
    }
}

/// One app instance (the primary or a restarted one).
#[derive(Clone)]
pub struct Client {
    pub app: Router,
    pub state: AppState,
}

impl Client {
    pub async fn raw(
        &self,
        method: Method,
        uri: &str,
        content_type: Option<&str>,
        body: impl Into<Vec<u8>>,
    ) -> Resp {
        let mut request = Request::builder()
            .method(method)
            .uri(uri)
            .header("host", HOST);
        if let Some(content_type) = content_type {
            request = request.header("content-type", content_type);
        }
        let request = request.body(Body::from(body.into())).expect("request");
        call_router(self.app.clone(), request).await
    }

    pub async fn get(&self, uri: &str) -> Resp {
        self.raw(Method::GET, uri, None, Vec::new()).await
    }

    pub async fn delete(&self, uri: &str) -> Resp {
        self.raw(Method::DELETE, uri, None, Vec::new()).await
    }

    pub async fn put_json(&self, uri: &str, body: &Value) -> Resp {
        self.raw(Method::PUT, uri, Some("application/json"), body.to_string())
            .await
    }

    pub async fn post_json(&self, uri: &str, body: &Value) -> Resp {
        self.raw(
            Method::POST,
            uri,
            Some("application/json"),
            body.to_string(),
        )
        .await
    }
}

pub fn read_json(path: &Path) -> Value {
    serde_json::from_str(&std::fs::read_to_string(path).expect("read file")).expect("valid JSON")
}

/// Python `settings.DEFAULT_CATEGORY_EXPIRATION_DAYS`.
pub fn default_expiration() -> Value {
    serde_json::json!({
        "marketing": 30,
        "transactional": 30,
        "updates": 30,
        "verification": 30,
        "uncategorized": -1,
    })
}

/// `MailPreferencesTests.preferences(count, signature)`.
pub fn preferences(count: u32, signature: &str) -> Value {
    serde_json::json!({
        "messages_per_page": count,
        "signature": signature,
        "category_expiration_days": default_expiration(),
        "local_ai_model": mail_core::model::DEFAULT_LOCAL_AI_MODEL,
    })
}

/// A TCP port on 127.0.0.1 that nothing listens on (bound, then released).
pub fn closed_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    drop(listener);
    port
}
