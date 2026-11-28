//! Classifier routes: port of `LocalClassifierSettingsApiTests` (status
//! part) and `LocalClassifierMailApiTests`
//! (tests/test_local_classifier_api.py).
//!
//! The Python tests patched `local_classifier.classify` / `get_status`; here
//! the real classifier talks to a loopback fake Ollama (shared with
//! mail-core's tests) and the real IMAP code to the fake IMAP server.
//! "During inference" side effects run inside the fake's `/api/chat`
//! handler. Consequences:
//! * the route's own result check (`"The local model returned an invalid
//!   classification..."`) cannot be reached through a real classifier, which
//!   already rejects unknown categories; the invalid-category test asserts
//!   the classifier's 502 message instead;
//! * the settings-route tests of `LocalClassifierSettingsApiTests`
//!   (`/api/settings` model persistence) belong to the settings routes.

#[path = "../../mail-core/tests/classifier_support/mod.rs"]
mod classifier_support;
mod common;
mod mail_support;

use std::sync::Arc;

use axum::http::StatusCode;
use classifier_support::{chat_answer, local_show, tag, FakeOllama, Recorded, Reply};
use mail_core::classifier::scoped_ollama_url;
use mail_core::retention::Patch;
use mail_core::MailAccount;
use mail_proto::testkit::FakeImapServer;
use mail_support::*;
use serde_json::{json, Value};

const MODEL: &str = "llama3.2:latest";

fn identity(email: &str) -> Value {
    json!({"account": email, "folder": "INBOX", "uid": 1, "uid_validity": "1234"})
}

fn merge(base: &Value, extra: Value) -> Value {
    let mut merged = base.as_object().unwrap().clone();
    for (key, value) in extra.as_object().unwrap() {
        merged.insert(key.clone(), value.clone());
    }
    Value::Object(merged)
}

/// A fake Ollama with `models` installed whose `/api/chat` handler runs
/// `during` (inference side effects) and then answers `answer`.
fn ollama(models: &[&str], answer: Value, during: impl Fn() + Send + Sync + 'static) -> FakeOllama {
    let tags: Vec<Value> = models.iter().map(|name| tag(name)).collect();
    FakeOllama::start(move |request: &Recorded| match request.path.as_str() {
        "/api/tags" => Reply::ok(json!({"models": tags.clone()})),
        "/api/show" => Reply::ok(local_show()),
        "/api/chat" => {
            during();
            Reply::ok(answer.clone())
        }
        other => panic!("unexpected request to {other}"),
    })
}

fn result(category: &str) -> Value {
    chat_answer(category, "A service notification", MODEL)
}

struct Fixture {
    harness: Harness,
    server: Arc<FakeImapServer>,
    account: MailAccount,
}

impl Fixture {
    fn new() -> Self {
        let harness = Harness::new();
        let server = Arc::new(retention_server(now_seconds() - chrono::Duration::days(60)));
        let account = mail_support::account(&server);
        Fixture {
            harness,
            server,
            account,
        }
    }

    fn unlock(&self) {
        self.harness.unlock(self.account.clone());
    }

    async fn classify(&self, body: &Value) -> common::Resp {
        self.harness
            .post_json("/api/mail/message/classify", body)
            .await
    }

    async fn detail(&self, client: &Client) -> Value {
        let response = client
            .get(
                "/api/mail/message",
                &[
                    ("account", &self.account.email),
                    ("folder", "INBOX"),
                    ("uid", "1"),
                    ("mark_seen", "false"),
                ],
            )
            .await;
        assert_eq!(response.status, StatusCode::OK, "{}", response.text());
        response.json()
    }

    async fn seed(&self) -> Value {
        self.harness
            .state
            .retention
            .update(
                &self.account,
                "INBOX",
                1,
                "1234",
                Patch::Set("transactional".into()),
                Patch::Set(-1),
            )
            .unwrap();
        self.detail(&self.harness.client()).await
    }
}

#[tokio::test]
async fn status_is_read_only_and_does_not_require_mailbox_credentials() {
    let f = Fixture::new();
    std::fs::write(
        f.harness.settings_path(),
        r#"{"messages_per_page": 5, "local_ai_model": "qwen3:4b"}"#,
    )
    .unwrap();
    let original = std::fs::read(f.harness.settings_path()).unwrap();
    let fake = ollama(&["qwen3:4b"], result("updates"), || {});
    let _url = scoped_ollama_url(fake.url());
    let response = f.harness.get("/api/mail/classifier/status", &[]).await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text());
    assert_eq!(
        response.json(),
        json!({"available": true, "model": "qwen3:4b", "installed_models": ["qwen3:4b"], "error": null})
    );
    assert_eq!(fake.paths(), ["/api/tags", "/api/show"]);
    assert_eq!(f.server.connection_count(), 0);
    assert_eq!(std::fs::read(f.harness.settings_path()).unwrap(), original);

    let response = f
        .harness
        .get("/api/mail/classifier/status", &[("model", "gemma3:4b")])
        .await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text());
    assert_eq!(
        response.json(),
        json!({"available": false, "model": "gemma3:4b", "installed_models": ["qwen3:4b"],
               "error": "Model 'gemma3:4b' is not installed locally. Choose an installed model in Settings."})
    );
    assert_eq!(std::fs::read(f.harness.settings_path()).unwrap(), original);

    let long = "x".repeat(201);
    let response = f
        .harness
        .get("/api/mail/classifier/status", &[("model", &long)])
        .await;
    let detail = response.assert_json_error(StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(detail[0]["loc"], json!(["query", "model"]));
    assert_eq!(detail[0]["type"], "string_too_long");
}

#[tokio::test]
async fn status_reports_unreachable_ollama_and_invalid_saved_settings() {
    let f = Fixture::new();
    let _url = scoped_ollama_url(classifier_support::closed_url());
    let response = f.harness.get("/api/mail/classifier/status", &[]).await;
    assert_eq!(
        response.json(),
        json!({"available": false, "model": MODEL, "installed_models": [],
               "error": "Cannot reach local Ollama at 127.0.0.1:11434. Start Ollama and try again."})
    );
    std::fs::write(f.harness.settings_path(), r#"{"messages_per_page": false}"#).unwrap();
    let response = f.harness.get("/api/mail/classifier/status", &[]).await;
    assert_eq!(response.status, StatusCode::INTERNAL_SERVER_ERROR);
}

#[tokio::test]
async fn requires_an_unlocked_account_before_imap_or_inference() {
    let f = Fixture::new();
    let fake = ollama(&[MODEL], result("updates"), || {});
    let _url = scoped_ollama_url(fake.url());
    let response = f.classify(&identity(&f.account.email)).await;
    let detail = response.assert_json_error(StatusCode::UNAUTHORIZED);
    assert_eq!(detail["error"], "password_required");
    assert_eq!(f.server.connection_count(), 0);
    assert!(fake.requests().is_empty());
}

#[tokio::test]
async fn validates_message_identity_before_accessing_mail_or_inference() {
    let f = Fixture::new();
    f.unlock();
    let fake = ollama(&[MODEL], result("updates"), || {});
    let _url = scoped_ollama_url(fake.url());
    let base = identity(&f.account.email);
    let mut invalid: Vec<Value> = [
        json!(0),
        json!(-1),
        json!(true),
        json!("1"),
        json!(1.5),
        json!(4294967296u64),
    ]
    .into_iter()
    .map(|value| merge(&base, json!({"uid": value})))
    .collect();
    invalid.extend(
        [
            json!(null),
            json!(""),
            json!("0"),
            json!("-1"),
            json!("4294967296"),
            json!(1234),
        ]
        .into_iter()
        .map(|value| merge(&base, json!({"uid_validity": value}))),
    );
    let mut missing = base.as_object().unwrap().clone();
    missing.remove("uid_validity");
    invalid.push(Value::Object(missing));
    invalid.push(merge(&base, json!({"category": "updates"})));
    for body in invalid {
        let response = f.classify(&body).await;
        assert_eq!(
            response.status,
            StatusCode::UNPROCESSABLE_ENTITY,
            "{body}: {}",
            response.text()
        );
    }
    assert_eq!(f.server.connection_count(), 0);
    assert!(fake.requests().is_empty());
}

#[tokio::test]
async fn success_replaces_category_preserves_expiration_and_survives_restart() {
    let f = Fixture::new();
    f.unlock();
    std::fs::write(
        f.harness.settings_path(),
        r#"{"messages_per_page": 5, "local_ai_model": "qwen3:4b"}"#,
    )
    .unwrap();
    f.seed().await;
    let fake = ollama(
        &["qwen3:4b"],
        chat_answer("verification", "A service notification", "qwen3:4b"),
        || {},
    );
    let _url = scoped_ollama_url(fake.url());
    let response = f.classify(&identity(&f.account.email)).await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text());
    let actual = response.json();
    assert_eq!(actual["uid"], 1);
    assert_eq!(actual["folder"], "INBOX");
    assert_eq!(actual["category"], "verification");
    assert_eq!(actual["category_source"], "ai");
    assert_eq!(actual["category_reason"], "A service notification");
    assert_eq!(actual["category_model"], "qwen3:4b");
    assert_eq!(actual["expiration_days"], -1);
    assert_eq!(actual["expiration_source"], "manual");
    assert_eq!(actual["expires_at"], -1);
    assert_eq!(actual["expired"], false);
    assert_eq!(fake.paths(), ["/api/tags", "/api/show", "/api/chat"]);
    let chat = fake.requests().pop().unwrap().json();
    assert_eq!(chat["model"], "qwen3:4b");
    let user = chat["messages"][1]["content"].as_str().unwrap();
    assert!(user.contains("Special offer"), "{user}");
    assert!(user.contains("Message body."), "{user}");
    assert!(!user.contains(PASSWORD));
    let detail = f.detail(&f.harness.client()).await;
    assert_eq!(detail["category_source"], "ai");

    let restarted = f.harness.restarted();
    restarted.unlock(f.account.clone());
    let persisted = f.detail(&restarted).await;
    for field in [
        "category",
        "category_source",
        "category_reason",
        "expiration_days",
        "expiration_source",
        "expires_at",
    ] {
        assert_eq!(persisted[field], actual[field], "{field}");
    }
    let reset = restarted
        .put_json(
            "/api/mail/message/retention",
            &merge(&identity(&f.account.email), json!({"category": null})),
        )
        .await;
    assert_eq!(reset.status, StatusCode::OK, "{}", reset.text());
    assert_eq!(reset.json()["category"], "marketing");
    assert_eq!(reset.json()["category_source"], "automatic");
    assert_eq!(reset.json()["expiration_days"], -1);
    assert_read_only(&f.server);
}

#[tokio::test]
async fn ai_category_uses_current_category_retention_policy() {
    let f = Fixture::new();
    f.unlock();
    f.harness
        .write_preferences(5, Some(merge(&default_policies(), json!({"updates": 90}))));
    let fake = ollama(&[MODEL], result("updates"), || {});
    let _url = scoped_ollama_url(fake.url());
    let response = f.classify(&identity(&f.account.email)).await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text());
    assert_eq!(response.json()["expiration_days"], 90);
    assert_eq!(response.json()["expiration_source"], "category");
    assert_eq!(response.json()["expired"], false);
    assert_read_only(&f.server);
}

#[tokio::test]
async fn classifier_failure_preserves_manual_metadata() {
    let f = Fixture::new();
    f.unlock();
    let before = f.seed().await;
    let _url = scoped_ollama_url(classifier_support::closed_url());
    let response = f.classify(&identity(&f.account.email)).await;
    let detail = response.assert_json_error(StatusCode::BAD_GATEWAY);
    assert!(detail.as_str().unwrap().contains("Ollama"), "{detail}");
    assert_eq!(f.detail(&f.harness.client()).await, before);
    assert_read_only(&f.server);
}

#[tokio::test]
async fn invalid_inference_category_is_rejected_without_changing_metadata() {
    let f = Fixture::new();
    f.unlock();
    let before = f.seed().await;
    let fake = ollama(&[MODEL], result("delete_everything"), || {});
    let _url = scoped_ollama_url(fake.url());
    let response = f.classify(&identity(&f.account.email)).await;
    assert_eq!(
        response.assert_json_error(StatusCode::BAD_GATEWAY),
        "Local AI returned an invalid category or incomplete answer. The email was left unchanged."
    );
    assert_eq!(f.detail(&f.harness.client()).await, before);
    assert_read_only(&f.server);
}

#[tokio::test]
async fn stale_uid_epoch_is_rejected_before_inference() {
    let f = Fixture::new();
    f.unlock();
    set_uid_validity(&f.server, "INBOX", 5678);
    let fake = ollama(&[MODEL], result("updates"), || {});
    let _url = scoped_ollama_url(fake.url());
    let response = f.classify(&identity(&f.account.email)).await;
    assert_eq!(response.status, StatusCode::CONFLICT, "{}", response.text());
    assert!(fake.requests().is_empty());
    assert_read_only(&f.server);
}

#[tokio::test]
async fn uid_epoch_changed_during_inference_does_not_store_a_category() {
    let f = Fixture::new();
    f.unlock();
    let before = f.seed().await;
    let server = f.server.clone();
    let fake = ollama(&[MODEL], result("updates"), move || {
        set_uid_validity(&server, "INBOX", 5678);
    });
    let _url = scoped_ollama_url(fake.url());
    let response = f.classify(&identity(&f.account.email)).await;
    assert_eq!(response.status, StatusCode::CONFLICT, "{}", response.text());
    set_uid_validity(&f.server, "INBOX", 1234);
    assert_eq!(f.detail(&f.harness.client()).await, before);
    assert_read_only(&f.server);
}

#[tokio::test]
async fn message_vanished_during_inference_does_not_store_a_category() {
    let f = Fixture::new();
    f.unlock();
    let before = f.seed().await;
    let removed = Arc::new(std::sync::Mutex::new(None));
    let (server, slot) = (f.server.clone(), removed.clone());
    let fake = ollama(&[MODEL], result("updates"), move || {
        server.with_folders(|folders| {
            let inbox = folders
                .iter_mut()
                .find(|folder| folder.name == "INBOX")
                .unwrap();
            let index = inbox.messages.iter().position(|m| m.uid == 1).unwrap();
            *slot.lock().unwrap() = Some(inbox.messages.remove(index));
        });
    });
    let _url = scoped_ollama_url(fake.url());
    let response = f.classify(&identity(&f.account.email)).await;
    assert!(
        [
            StatusCode::NOT_FOUND,
            StatusCode::CONFLICT,
            StatusCode::BAD_GATEWAY
        ]
        .contains(&response.status),
        "{}",
        response.text()
    );
    let message = removed.lock().unwrap().take().unwrap();
    f.server.with_folders(|folders| {
        let inbox = folders
            .iter_mut()
            .find(|folder| folder.name == "INBOX")
            .unwrap();
        inbox.messages.insert(0, message);
    });
    assert_eq!(f.detail(&f.harness.client()).await, before);
    assert_read_only(&f.server);
}

#[tokio::test]
async fn lock_during_inference_discards_the_result() {
    let f = Fixture::new();
    f.unlock();
    let before = f.seed().await;
    let (state, email) = (f.harness.state.clone(), f.account.email.clone());
    let fake = ollama(&[MODEL], result("updates"), move || {
        state.sessions.forget(&email);
    });
    let _url = scoped_ollama_url(fake.url());
    let response = f.classify(&identity(&f.account.email)).await;
    assert_eq!(
        response.assert_json_error(StatusCode::UNAUTHORIZED),
        json!({"error": "password_required", "email": USER})
    );
    f.unlock();
    assert_eq!(f.detail(&f.harness.client()).await, before);
    assert_read_only(&f.server);
}

#[tokio::test]
async fn replaced_account_session_during_inference_discards_the_result() {
    let f = Fixture::new();
    f.unlock();
    let before = f.seed().await;
    let state = f.harness.state.clone();
    let mut replacement = f.account.clone();
    replacement.password = "different-password".into();
    let fake = ollama(&[MODEL], result("updates"), move || {
        state.sessions.unlock(replacement.clone());
    });
    let _url = scoped_ollama_url(fake.url());
    let response = f.classify(&identity(&f.account.email)).await;
    assert_eq!(
        response.status,
        StatusCode::UNAUTHORIZED,
        "{}",
        response.text()
    );
    f.unlock();
    assert_eq!(f.detail(&f.harness.client()).await, before);
    assert_read_only(&f.server);
}

#[tokio::test]
async fn manual_category_change_during_inference_is_not_overwritten() {
    let f = Fixture::new();
    f.unlock();
    f.seed().await;
    let (state, account) = (f.harness.state.clone(), f.account.clone());
    let fake = ollama(&[MODEL], result("updates"), move || {
        state
            .retention
            .update(
                &account,
                "INBOX",
                1,
                "1234",
                Patch::Set("verification".into()),
                Patch::Unset,
            )
            .unwrap();
    });
    let _url = scoped_ollama_url(fake.url());
    let response = f.classify(&identity(&f.account.email)).await;
    assert_eq!(response.status, StatusCode::CONFLICT, "{}", response.text());
    let actual = f.detail(&f.harness.client()).await;
    assert_eq!(actual["category"], "verification");
    assert_eq!(actual["category_source"], "manual");
    assert_eq!(actual["expiration_days"], -1);
    assert_read_only(&f.server);
}

#[tokio::test]
async fn category_change_and_restore_during_inference_is_detected() {
    let f = Fixture::new();
    f.unlock();
    let before = f.seed().await;
    let (state, account) = (f.harness.state.clone(), f.account.clone());
    let fake = ollama(&[MODEL], result("updates"), move || {
        for category in ["verification", "transactional"] {
            state
                .retention
                .update(
                    &account,
                    "INBOX",
                    1,
                    "1234",
                    Patch::Set(category.into()),
                    Patch::Unset,
                )
                .unwrap();
        }
    });
    let _url = scoped_ollama_url(fake.url());
    let response = f.classify(&identity(&f.account.email)).await;
    assert_eq!(response.status, StatusCode::CONFLICT, "{}", response.text());
    assert_eq!(f.detail(&f.harness.client()).await, before);
    assert_read_only(&f.server);
}

#[tokio::test]
async fn expiration_edit_during_inference_is_preserved_without_category_conflict() {
    let f = Fixture::new();
    f.unlock();
    f.seed().await;
    let (state, account) = (f.harness.state.clone(), f.account.clone());
    let fake = ollama(&[MODEL], result("updates"), move || {
        state
            .retention
            .update(&account, "INBOX", 1, "1234", Patch::Unset, Patch::Set(45))
            .unwrap();
    });
    let _url = scoped_ollama_url(fake.url());
    let response = f.classify(&identity(&f.account.email)).await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text());
    let body = response.json();
    assert_eq!(body["category"], "updates");
    assert_eq!(body["category_source"], "ai");
    assert_eq!(body["expiration_days"], 45);
    assert_eq!(body["expiration_source"], "manual");
    assert_read_only(&f.server);
}

#[tokio::test]
async fn category_policy_changed_during_inference_is_applied_to_new_result() {
    let f = Fixture::new();
    f.unlock();
    let fake = ollama(&[MODEL], result("updates"), move || {
        let update = mail_core::settings::MailPreferencesUpdate {
            category_expiration_days: Some(merge(&default_policies(), json!({"updates": 90}))),
            ..Default::default()
        };
        mail_core::settings::save_mail_preferences(&json!(5), &update).unwrap();
    });
    let _url = scoped_ollama_url(fake.url());
    let response = f.classify(&identity(&f.account.email)).await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text());
    assert_eq!(response.json()["category"], "updates");
    assert_eq!(response.json()["expiration_days"], 90);
    assert_eq!(response.json()["expiration_source"], "category");
    assert_read_only(&f.server);
}

#[tokio::test]
async fn settings_read_failure_after_inference_does_not_store_a_category() {
    let f = Fixture::new();
    f.unlock();
    f.harness.write_preferences(5, None);
    let path = f.harness.settings_path();
    let before = f.seed().await;
    let original = std::fs::read(&path).unwrap();
    let broken = path.clone();
    let fake = ollama(&[MODEL], result("updates"), move || {
        std::fs::write(&broken, r#"{"messages_per_page": false}"#).unwrap();
    });
    let _url = scoped_ollama_url(fake.url());
    let response = f.classify(&identity(&f.account.email)).await;
    assert_eq!(
        response.status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "{}",
        response.text()
    );
    std::fs::write(&path, original).unwrap();
    assert_eq!(f.detail(&f.harness.client()).await, before);
    assert_read_only(&f.server);
}
