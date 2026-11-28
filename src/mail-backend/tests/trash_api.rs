//! Port of `tests/test_trash_api.py` (and the observable part of
//! `tests/test_trash_proxy.py`) against `mail_proto::testkit::FakeImapServer`.
//!
//! `test_trash_proxy.py` exercised the packaged frontend's reverse proxy
//! (`backend/packaged.py`), which this port does not have; what remains
//! observable is that the archive route streams a multi-chunk ZIP with its
//! download headers intact (`archive_download_streams_large_zip_with_headers`).

mod common;

use std::io::Read;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use axum::Router;
use mail_backend::AppState;
use mail_core::MailAccount;
use mail_proto::testkit::{Failure, FakeImapServer, FakeMessage, HookAction};
use serde_json::{json, Value};

use common::{call_router, test_app, Resp};

const USER: &str = "user@example.com";
const OTHER: &str = "other@example.com";
const PASSWORD: &str = "trash-api-secret-pass";

fn original(uid: u32) -> Vec<u8> {
    format!("From: sender{uid}@example.com\r\nSubject: Original {uid}\r\n\r\nBody {uid}\r\n")
        .into_bytes()
}

fn account_for(email: &str, port: u16) -> MailAccount {
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

struct Api {
    app: Router,
    state: AppState,
    server: FakeImapServer,
    account: MailAccount,
    _temporary: tempfile::TempDir,
}

impl Api {
    fn new(messages: Vec<(u32, Vec<u8>)>) -> Self {
        let mut builder = FakeImapServer::builder()
            .credentials(USER, PASSWORD)
            .credentials(OTHER, PASSWORD)
            .folder("Trash", &["\\Trash"])
            .uid_validity("Trash", Some(137));
        for (uid, raw) in messages {
            builder = builder.message_with("Trash", FakeMessage::new(raw).with_uid(uid));
        }
        let server = builder.start();
        let (app, state, temporary) = test_app();
        let account = account_for(USER, server.port());
        Self {
            app,
            state,
            server,
            account,
            _temporary: temporary,
        }
    }

    /// `FakeTrashServer(12)`.
    fn twelve() -> Self {
        Self::new((1..=12).map(|uid| (uid, original(uid))).collect())
    }

    fn unlock(&self) -> Arc<MailAccount> {
        self.state.sessions.unlock(self.account.clone())
    }

    async fn send(&self, method: Method, uri: &str, body: Option<&Value>) -> Resp {
        let mut builder = Request::builder()
            .method(method)
            .uri(uri)
            .header("host", "127.0.0.1:48101");
        let body = match body {
            Some(value) => {
                builder = builder.header("content-type", "application/json");
                Body::from(value.to_string())
            }
            None => Body::empty(),
        };
        call_router(self.app.clone(), builder.body(body).unwrap()).await
    }

    async fn prepare_with(&self, archive: Value) -> Resp {
        let body = json!({"account": USER, "folder": "Trash", "archive": archive});
        self.send(Method::POST, "/api/mail/trash/prepare", Some(&body))
            .await
    }

    async fn prepare(&self, archive: bool) -> Resp {
        self.prepare_with(json!(archive)).await
    }

    async fn empty(&self, operation: &str) -> Resp {
        let body = json!({"account": USER});
        self.send(
            Method::POST,
            &format!("/api/mail/trash/{operation}/empty"),
            Some(&body),
        )
        .await
    }

    async fn archive(&self, operation: &str, account: &str) -> Resp {
        let uri = format!(
            "/api/mail/trash/{operation}/archive?account={}",
            account.replace('@', "%40")
        );
        self.send(Method::GET, &uri, None).await
    }

    async fn discard(&self, operation: &str) -> Resp {
        let uri = format!("/api/mail/trash/{operation}?account=user%40example.com");
        self.send(Method::DELETE, &uri, None).await
    }

    fn mutations(&self) -> Vec<String> {
        self.server
            .log()
            .into_iter()
            .filter(|command| command.name == "UID STORE" || command.name == "UID EXPUNGE")
            .map(|command| command.line)
            .collect()
    }

    fn archives(&self) -> Vec<std::path::PathBuf> {
        let directory = self.state.data_directory.join("trash_archives");
        std::fs::read_dir(directory)
            .map(|entries| {
                entries
                    .map(|entry| entry.unwrap().path())
                    .filter(|path| path.extension().is_some_and(|ext| ext == "zip"))
                    .collect()
            })
            .unwrap_or_default()
    }
}

fn zip_entries(bytes: &[u8]) -> Vec<(String, Vec<u8>)> {
    let mut archive = zip::ZipArchive::new(std::io::Cursor::new(bytes.to_vec())).unwrap();
    (0..archive.len())
        .map(|index| {
            let mut entry = archive.by_index(index).unwrap();
            let mut data = Vec::new();
            entry.read_to_end(&mut data).unwrap();
            (entry.name().to_string(), data)
        })
        .collect()
}

fn operation_id(response: &Resp) -> String {
    assert_eq!(response.status, StatusCode::OK, "{}", response.text());
    response.json()["operation_id"]
        .as_str()
        .unwrap()
        .to_string()
}

#[tokio::test]
async fn all_trash_routes_require_unlocked_account() {
    let api = Api::twelve();
    let responses = [
        api.prepare(true).await,
        api.empty("unknown").await,
        api.archive("unknown", USER).await,
        api.discard("unknown").await,
    ];
    for response in responses {
        let detail = response.assert_json_error(StatusCode::UNAUTHORIZED);
        assert_eq!(detail, json!({"error": "password_required", "email": USER}));
    }
    assert_eq!(api.server.connection_count(), 0);
}

#[tokio::test]
async fn archived_zip_delivered_before_empty_preserves_all_original_bytes() {
    let api = Api::twelve();
    api.unlock();
    let prepared = api.prepare(true).await;
    let operation = operation_id(&prepared);
    assert_eq!(prepared.json()["count"], json!(12));
    assert_eq!(prepared.json()["archive"], json!(true));
    assert!(api.mutations().is_empty());
    // Attempting permanent deletion before requesting the backup is rejected.
    let refused = api.empty(&operation).await;
    let detail = refused.assert_json_error(StatusCode::BAD_GATEWAY);
    assert_eq!(
        detail,
        json!("Download and save the Trash archive before permanently deleting the messages.")
    );
    assert!(api.mutations().is_empty());

    let downloaded = api.archive(&operation, USER).await;
    assert_eq!(downloaded.status, StatusCode::OK);
    assert_eq!(downloaded.header("content-type"), Some("application/zip"));
    assert_eq!(downloaded.header("cache-control"), Some("no-store"));
    assert_eq!(downloaded.header("x-content-type-options"), Some("nosniff"));
    let filename = prepared.json()["filename"].as_str().unwrap().to_string();
    assert_eq!(
        downloaded.header("content-disposition"),
        Some(format!("attachment; filename=\"{filename}\"").as_str())
    );
    assert_eq!(
        downloaded.header("content-length"),
        Some(downloaded.body.len().to_string().as_str())
    );
    assert!(downloaded
        .header("last-modified")
        .is_some_and(|value| value.ends_with(" GMT")));
    let entries = zip_entries(&downloaded.body);
    assert_eq!(entries.len(), 12);
    for (name, data) in &entries {
        let uid: u32 = name
            .trim_start_matches("message-")
            .trim_end_matches(".eml")
            .parse()
            .unwrap();
        assert_eq!(data, &original(uid));
    }

    api.server.add_message(
        "Trash",
        FakeMessage::new(b"Subject: New arrival\r\n\r\nRemain in Trash.".to_vec()).with_uid(100),
    );
    let response = api.empty(&operation).await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text());
    assert_eq!(response.json(), json!({"deleted": 12, "remaining": 1}));
    assert_eq!(api.server.uids("Trash"), vec![100]);
    assert_eq!(api.empty(&operation).await.json(), response.json());
    assert_eq!(api.archive(&operation, USER).await.body, downloaded.body);
}

#[tokio::test]
async fn empty_without_archive_removes_entire_snapshot() {
    let api = Api::twelve();
    api.unlock();
    let prepared = api.prepare(false).await;
    let operation = operation_id(&prepared);
    assert_eq!(prepared.json()["filename"], Value::Null);
    assert_eq!(
        api.empty(&operation).await.json(),
        json!({"deleted": 12, "remaining": 0})
    );
    assert!(!api.server.log().iter().any(|c| c.name == "UID FETCH"));
    assert!(api.server.uids("Trash").is_empty());
}

#[tokio::test]
async fn cancel_discards_zip_without_deleting_any_messages() {
    let api = Api::twelve();
    api.unlock();
    let operation = operation_id(&api.prepare(true).await);
    assert_eq!(api.archives().len(), 1);
    let response = api.discard(&operation).await;
    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(response.json(), json!({"discarded": operation}));
    assert!(api.mutations().is_empty());
    assert!(api.archives().is_empty());
    api.empty(&operation)
        .await
        .assert_json_error(StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn other_accounts_and_unknown_operations_do_not_expose_archives_or_delete() {
    let api = Api::twelve();
    api.unlock();
    let operation = operation_id(&api.prepare(true).await);
    api.state
        .sessions
        .unlock(account_for(OTHER, api.server.port()));
    let detail = api
        .archive(&operation, OTHER)
        .await
        .assert_json_error(StatusCode::NOT_FOUND);
    assert_eq!(
        detail,
        json!("This Trash operation has expired or is unavailable. Prepare it again.")
    );
    api.empty("unknown")
        .await
        .assert_json_error(StatusCode::NOT_FOUND);
    assert!(api.mutations().is_empty());
}

#[tokio::test]
async fn account_lock_discards_staged_backup_and_snapshot() {
    let api = Api::twelve();
    api.unlock();
    let operation = operation_id(&api.prepare(true).await);
    let locked = api
        .send(Method::DELETE, "/api/accounts/user%40example.com", None)
        .await;
    assert_eq!(locked.status, StatusCode::OK, "{}", locked.text());
    api.unlock();
    api.empty(&operation)
        .await
        .assert_json_error(StatusCode::NOT_FOUND);
    assert!(api.mutations().is_empty());
    assert!(api.archives().is_empty());
}

#[tokio::test]
async fn forgetting_the_account_discards_staged_backup_and_snapshot() {
    // The trash side of `lock_account`, independent of the accounts route.
    let api = Api::twelve();
    api.unlock();
    let operation = operation_id(&api.prepare(true).await);
    assert!(api.state.sessions.forget(USER));
    api.state.trash.forget(USER);
    api.unlock();
    api.empty(&operation)
        .await
        .assert_json_error(StatusCode::NOT_FOUND);
    assert!(api.mutations().is_empty());
    assert!(api.archives().is_empty());
}

#[tokio::test]
async fn prepare_rejects_non_trash_and_invalid_request_without_deletion() {
    let api = Api::twelve();
    api.unlock();
    let body = json!({"account": USER, "folder": "INBOX", "archive": true});
    let response = api
        .send(Method::POST, "/api/mail/trash/prepare", Some(&body))
        .await;
    let detail = response.assert_json_error(StatusCode::BAD_GATEWAY);
    assert_eq!(
        detail,
        json!("Emptying is only available for the server's verified Trash folder. No messages were deleted.")
    );
    for value in [json!("true"), json!(1), Value::Null] {
        let response = api.prepare_with(value.clone()).await;
        let detail = response.assert_json_error(StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(detail[0]["loc"], json!(["body", "archive"]), "{value}");
    }
    assert!(api.mutations().is_empty());
}

#[tokio::test]
async fn request_validation_runs_before_the_session_check() {
    let api = Api::twelve();
    // Locked account, invalid bodies: FastAPI answers 422 first.
    let body = json!({"account": USER, "folder": "Trash", "archive": true, "extra": 1});
    let response = api
        .send(Method::POST, "/api/mail/trash/prepare", Some(&body))
        .await;
    let detail = response.assert_json_error(StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(detail[0]["type"], json!("extra_forbidden"));
    let response = api
        .send(
            Method::POST,
            "/api/mail/trash/unknown/empty",
            Some(&json!({"account": "x"})),
        )
        .await;
    let detail = response.assert_json_error(StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(detail[0]["loc"], json!(["body", "account"]));
    let response = api
        .send(Method::DELETE, "/api/mail/trash/unknown", None)
        .await;
    let detail = response.assert_json_error(StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(detail[0]["loc"], json!(["query", "account"]));
    assert_eq!(api.server.connection_count(), 0);
}

#[tokio::test]
async fn partial_server_failure_keeps_download_and_same_snapshot_retry() {
    let api = Api::twelve();
    api.unlock();
    let operation = operation_id(&api.prepare(true).await);
    assert_eq!(api.archive(&operation, USER).await.status, StatusCode::OK);
    api.server.fail_next("UID EXPUNGE", Failure::no());
    let response = api.empty(&operation).await;
    let detail = response.assert_json_error(StatusCode::BAD_GATEWAY);
    assert!(detail.as_str().unwrap().contains("partially"), "{detail}");
    assert_eq!(api.archive(&operation, USER).await.status, StatusCode::OK);
    assert_eq!(
        api.empty(&operation).await.json(),
        json!({"deleted": 12, "remaining": 0})
    );
}

#[tokio::test]
async fn relock_during_prepare_discards_operation_and_answers_401() {
    let api = Api::twelve();
    api.unlock();
    let sessions = api.state.sessions.clone();
    let replacement = api.account.clone();
    // Another unlock replaces the session while the snapshot is being taken.
    api.server.set_hook(move |request| {
        if request.command == "EXAMINE" {
            let mut account = replacement.clone();
            account.unlocked_at += 1.0;
            sessions.unlock(account);
        }
        HookAction::Continue
    });
    let response = api.prepare(true).await;
    let detail = response.assert_json_error(StatusCode::UNAUTHORIZED);
    assert_eq!(detail, json!({"error": "password_required", "email": USER}));
    assert_eq!(api.state.trash.operation_count(), 0);
    assert!(api.archives().is_empty());
    assert!(api.mutations().is_empty());
}

#[tokio::test]
async fn archive_download_streams_large_zip_with_headers() {
    // Pseudo-random bodies so the ZIP spans several 64 KiB chunks.
    let mut seed = 0x2545_f491_u32;
    let messages = (1..=8)
        .map(|uid| {
            let body: String = (0..30_000)
                .map(|_| {
                    seed ^= seed << 13;
                    seed ^= seed >> 17;
                    seed ^= seed << 5;
                    char::from(b'!' + (seed % 90) as u8)
                })
                .collect::<Vec<char>>()
                .chunks(76)
                .map(|line| line.iter().collect::<String>() + "\r\n")
                .collect();
            (
                uid,
                format!("Subject: Large {uid}\r\n\r\n{body}").into_bytes(),
            )
        })
        .collect::<Vec<_>>();
    let expected: Vec<(String, Vec<u8>)> = messages
        .iter()
        .map(|(uid, raw)| (format!("message-{uid}.eml"), raw.clone()))
        .collect();
    let api = Api::new(messages);
    api.unlock();
    let operation = operation_id(&api.prepare(true).await);
    let downloaded = api.archive(&operation, USER).await;
    assert_eq!(downloaded.status, StatusCode::OK);
    assert!(
        downloaded.body.len() > 3 * 64 * 1024,
        "{}",
        downloaded.body.len()
    );
    assert!(downloaded.body.starts_with(b"PK\x03\x04"));
    let on_disk = std::fs::read(&api.archives()[0]).unwrap();
    assert_eq!(downloaded.body, on_disk);
    assert_eq!(
        downloaded.header("content-length"),
        Some(on_disk.len().to_string().as_str())
    );
    assert_eq!(zip_entries(&downloaded.body), expected);
}

#[tokio::test]
async fn pop3_accounts_cannot_prepare() {
    let api = Api::twelve();
    let mut account = api.account.clone();
    account.incoming_mail_protocol = "pop3".into();
    api.state.sessions.unlock(account);
    let response = api.prepare(false).await;
    response.assert_json_error(StatusCode::BAD_REQUEST);
    assert_eq!(api.server.connection_count(), 0);
}
