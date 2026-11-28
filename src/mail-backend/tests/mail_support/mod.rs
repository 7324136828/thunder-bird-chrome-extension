//! Shared helpers for the `mail_*` / `retention_*` route tests: an isolated
//! app (state + settings file), request helpers and fake-IMAP accounts.
//!
//! Python's `ApiTestCase` patched `backend.settings.settings_path` to a
//! temporary `settings.json`; [`Harness`] holds a
//! `mail_core::settings::scoped_settings_path` guard for the same purpose
//! (holders are serialized process-wide, so parallel tests never share it).

#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Method, Request};
use axum::Router;
use mail_backend::{build_app, AppState};
use mail_core::settings::{scoped_settings_path, ScopedSettingsPath};
use mail_core::MailAccount;
use mail_proto::testkit::{FakeImapBuilder, FakeImapServer, FakeMessage};
use serde_json::Value;

use crate::common::{call_router, Resp};

pub const USER: &str = "user@example.com";
pub const PASSWORD: &str = "s3cret-imap-pass";

/// Python `DEFAULT_POLICIES` / `DEFAULT_CATEGORY_EXPIRATION_DAYS`.
pub fn default_policies() -> Value {
    serde_json::json!({
        "marketing": 30,
        "transactional": 30,
        "updates": 30,
        "verification": 30,
        "uncategorized": -1,
    })
}

/// An app over a temporary state directory and settings file.
pub struct Harness {
    pub app: Router,
    pub state: AppState,
    pub root: PathBuf,
    // Declared before `_temporary` so the override is dropped first.
    _settings: ScopedSettingsPath,
    _temporary: tempfile::TempDir,
}

impl Harness {
    pub fn new() -> Self {
        let temporary = tempfile::tempdir().expect("tempdir");
        let root = temporary.path().to_path_buf();
        let settings = scoped_settings_path(root.join("settings.json"));
        let state = AppState::for_tests(&root);
        Self {
            app: build_app(state.clone()),
            state,
            root,
            _settings: settings,
            _temporary: temporary,
        }
    }

    /// A second app over the same files (Python's restarted `TestClient`):
    /// a fresh, empty session store, the same retention database.
    pub fn restarted(&self) -> Client {
        let state = AppState::for_tests(&self.root);
        Client {
            app: build_app(state.clone()),
            state,
        }
    }

    /// The primary app as a [`Client`].
    pub fn client(&self) -> Client {
        Client {
            app: self.app.clone(),
            state: self.state.clone(),
        }
    }

    pub fn settings_path(&self) -> PathBuf {
        self.root.join("settings.json")
    }

    /// Persist mail preferences directly (what `PUT /api/settings` saves).
    pub fn write_preferences(&self, messages_per_page: u32, policies: Option<Value>) {
        let mut values = serde_json::Map::new();
        values.insert("messages_per_page".into(), messages_per_page.into());
        if let Some(policies) = policies {
            values.insert("category_expiration_days".into(), policies);
        }
        std::fs::write(
            self.settings_path(),
            serde_json::to_vec(&Value::Object(values)).unwrap(),
        )
        .unwrap();
    }

    pub fn unlock(&self, account: MailAccount) -> Arc<MailAccount> {
        self.state.sessions.unlock(account)
    }

    pub async fn get(&self, path: &str, params: &[(&str, &str)]) -> Resp {
        self.client().get(path, params).await
    }

    pub async fn delete(&self, path: &str, params: &[(&str, &str)]) -> Resp {
        self.client().delete(path, params).await
    }

    pub async fn post_json(&self, path: &str, body: &Value) -> Resp {
        self.client().post_json(path, body).await
    }

    pub async fn put_json(&self, path: &str, body: &Value) -> Resp {
        self.client().put_json(path, body).await
    }
}

/// One app instance to send requests to.
#[derive(Clone)]
pub struct Client {
    pub app: Router,
    pub state: AppState,
}

impl Client {
    pub fn unlock(&self, account: MailAccount) -> Arc<MailAccount> {
        self.state.sessions.unlock(account)
    }

    pub async fn send(&self, method: Method, uri: &str, body: Option<&Value>) -> Resp {
        let mut builder = Request::builder()
            .method(method)
            .uri(uri)
            .header("host", "127.0.0.1:48101");
        let body = match body {
            Some(value) => {
                builder = builder.header("content-type", "application/json");
                Body::from(serde_json::to_vec(value).unwrap())
            }
            None => Body::empty(),
        };
        call_router(self.app.clone(), builder.body(body).unwrap()).await
    }

    pub async fn get(&self, path: &str, params: &[(&str, &str)]) -> Resp {
        self.send(Method::GET, &with_query(path, params), None)
            .await
    }

    pub async fn delete(&self, path: &str, params: &[(&str, &str)]) -> Resp {
        self.send(Method::DELETE, &with_query(path, params), None)
            .await
    }

    pub async fn post_json(&self, path: &str, body: &Value) -> Resp {
        self.send(Method::POST, path, Some(body)).await
    }

    pub async fn put_json(&self, path: &str, body: &Value) -> Resp {
        self.send(Method::PUT, path, Some(body)).await
    }
}

/// `path?k=v&...` encoded like `requests`/`httpx` `params=`.
pub fn with_query(path: &str, params: &[(&str, &str)]) -> String {
    if params.is_empty() {
        return path.to_string();
    }
    let query = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(params.iter())
        .finish();
    format!("{path}?{query}")
}

/// A fake IMAP server accepting [`USER`] / [`PASSWORD`].
pub fn server() -> FakeImapBuilder {
    FakeImapServer::builder().credentials(USER, PASSWORD)
}

/// An account pointing at the fake server (plain TCP).
pub fn account(server: &FakeImapServer) -> MailAccount {
    account_at(USER, server.port())
}

pub fn account_at(email: &str, port: u16) -> MailAccount {
    MailAccount::new(
        email,
        PASSWORD,
        "127.0.0.1",
        port,
        "none",
        "smtp.example.com",
        587,
        "STARTTLS",
    )
}

/// Python `make_account()`: an account that must never reach a server
/// (port 1 on loopback refuses connections immediately).
pub fn offline_account(email: &str) -> MailAccount {
    account_at(email, 1)
}

/// A message with a fixed UID and INTERNALDATE.
pub fn message(uid: u32, raw: impl Into<Vec<u8>>) -> FakeMessage {
    FakeMessage::new(raw)
        .with_uid(uid)
        .with_internal_date("01-Jan-2020 00:00:00 +0000")
}

/// Every mutating IMAP command the fake server saw (Python's
/// `FakeRetentionMailbox.mutations`: any UID command other than SEARCH and
/// FETCH, plus the non-UID equivalents).
pub fn mutations(server: &FakeImapServer) -> Vec<String> {
    server
        .log()
        .into_iter()
        .filter(|command| {
            matches!(
                command.name.as_str(),
                "STORE"
                    | "UID STORE"
                    | "COPY"
                    | "UID COPY"
                    | "MOVE"
                    | "UID MOVE"
                    | "EXPUNGE"
                    | "UID EXPUNGE"
                    | "APPEND"
                    | "CREATE"
                    | "DELETE"
            )
        })
        .map(|command| command.line)
        .collect()
}

/// Python `assert_read_only`: no mailbox mutation, read-only selections
/// (EXAMINE) and only `BODY.PEEK[...]` fetches.
pub fn assert_read_only(server: &FakeImapServer) {
    assert_eq!(mutations(server), Vec::<String>::new());
    for command in server.log() {
        assert_ne!(
            command.name, "SELECT",
            "read-write selection: {}",
            command.line
        );
        if command.name == "UID FETCH" || command.name == "FETCH" {
            let upper = command.line.to_uppercase();
            assert!(
                !upper.contains("BODY[")
                    && !upper.contains("RFC822 ")
                    && !upper.contains("RFC822)"),
                "non-peek fetch: {}",
                command.line
            );
        }
    }
}

/// `path` exists?
pub fn exists(path: &Path) -> bool {
    path.exists()
}

// ---------------------------------------------------------------------------
// Retention mailboxes (Python `FakeRetentionMailbox` / `SenderRuleMailbox`)
// ---------------------------------------------------------------------------

/// Now, truncated to whole seconds (Python `.replace(microsecond=0)`).
pub fn now_seconds() -> chrono::DateTime<chrono::Utc> {
    use chrono::Timelike;
    chrono::Utc::now().with_nanosecond(0).unwrap()
}

/// IMAP INTERNALDATE text (`strftime("%d-%b-%Y %H:%M:%S %z")`).
pub fn internal_date(at: chrono::DateTime<chrono::Utc>) -> String {
    at.format("%d-%b-%Y %H:%M:%S %z").to_string()
}

/// Python `datetime.isoformat()` of an aware UTC datetime.
pub fn isoformat(at: chrono::DateTime<chrono::Utc>) -> String {
    at.to_rfc3339_opts(chrono::SecondsFormat::AutoSi, false)
}

/// One retention test message: `From` header(s), subject, a `Date` far in
/// the future (only INTERNALDATE may count as the arrival time) and the
/// given INTERNALDATE.
pub fn retention_message(
    uid: u32,
    subject: &str,
    from: &[&str],
    received: chrono::DateTime<chrono::Utc>,
) -> FakeMessage {
    let author: String = from
        .iter()
        .map(|value| format!("From: {value}\r\n"))
        .collect();
    let date = (received + chrono::Duration::days(1000)).to_rfc2822();
    let raw = format!(
        "{author}To: user@example.com\r\nSubject: {subject}\r\nDate: {date}\r\n\
         Message-ID: <retention-{uid}@example.com>\r\n\r\nMessage body."
    );
    FakeMessage::new(raw.into_bytes())
        .with_uid(uid)
        .with_internal_date(&internal_date(received))
}

/// The three-message INBOX of `FakeRetentionMailbox` (UIDVALIDITY 1234,
/// received 60 days ago, UIDNEXT 4) plus a `Trash` folder.
pub fn retention_server(received: chrono::DateTime<chrono::Utc>) -> FakeImapServer {
    let mut builder = server()
        .folder("Trash", &[r"\Trash"])
        .uid_validity("INBOX", Some(1234));
    for (uid, subject) in [
        (1, "Special offer"),
        (2, "Dinner next week"),
        (3, "Order confirmation"),
    ] {
        builder = builder.message_with(
            "INBOX",
            retention_message(uid, subject, &["News <news@example.com>"], received),
        );
    }
    builder.start()
}

/// Change a folder's UIDVALIDITY (a mailbox rebuild).
pub fn set_uid_validity(server: &FakeImapServer, folder: &str, value: u32) {
    server.with_folders(|folders| {
        for item in folders.iter_mut() {
            if item.name.eq_ignore_ascii_case(folder) {
                item.uid_validity = Some(value);
            }
        }
    });
}

/// UIDs of a page response.
pub fn page_uids(page: &Value) -> Vec<u64> {
    page["messages"]
        .as_array()
        .map(|messages| {
            messages
                .iter()
                .filter_map(|message| message["uid"].as_u64())
                .collect()
        })
        .unwrap_or_default()
}

/// `{uid: summary}` of a page response.
pub fn by_uid(page: &Value) -> std::collections::BTreeMap<u64, Value> {
    page["messages"]
        .as_array()
        .map(|messages| {
            messages
                .iter()
                .map(|message| (message["uid"].as_u64().unwrap(), message.clone()))
                .collect()
        })
        .unwrap_or_default()
}
