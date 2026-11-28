//! Port of `tests/test_sender_display_name.py` (`SenderDisplayNameTests`).
//!
//! Python patched `imap_client.verify_login`, `smtp_client._connect` and
//! `imap_client.save_sent_copy`; here unlock signs in to a fake IMAP server,
//! messages go to a fake SMTP server (the sender name is read from the
//! delivered message) and the Sent copy is appended to the fake IMAP server.
//! Besides the send paths, the resolved name is also checked through
//! `GET /api/accounts`, which uses the same `_sender_account` resolution.
//!
//! `test_failed_save_does_not_unlock_or_report_success` patched
//! `settings._write_json` to raise; the port makes the settings directory
//! impossible to create (its parent is a file) instead.

mod accounts_support;
mod common;

use accounts_support::{Client, Harness};
use axum::http::{Method, StatusCode};
use mail_core::MailAccount;
use mail_parser::MessageParser;
use mail_proto::testkit::{FakeImapServer, FakeSmtpServer};
use serde_json::{json, Value};

const USER: &str = "user@example.com";
const PASSWORD: &str = "s3cret";
const BOUNDARY: &str = "display-name-boundary-41b7";

struct Fixture {
    harness: Harness,
    imap: FakeImapServer,
    smtp: FakeSmtpServer,
}

impl Fixture {
    fn new() -> Self {
        // The upper-case login is the restart test's `email.upper()` unlock
        // (Python patched `verify_login`; the fake servers compare exactly).
        let imap = FakeImapServer::builder()
            .credentials(USER, PASSWORD)
            .credentials(&USER.to_uppercase(), PASSWORD)
            .folder("Sent", &["\\Sent"])
            .start();
        let smtp = FakeSmtpServer::builder()
            .credentials(USER, PASSWORD)
            .credentials(&USER.to_uppercase(), PASSWORD)
            .start();
        let harness = Harness::new();
        let fixture = Self {
            harness,
            imap,
            smtp,
        };
        fixture.write_profile("", None);
        fixture
    }

    fn account(&self) -> MailAccount {
        MailAccount::new(
            USER,
            PASSWORD,
            "127.0.0.1",
            self.imap.port(),
            "none",
            "127.0.0.1",
            self.smtp.port(),
            "none",
        )
    }

    fn write_profile(&self, name: &str, email: Option<&str>) {
        self.harness.write_profiles(&json!({"servers": {"sender": {
            "email_address": email.unwrap_or(USER), "display_name": name,
            "incoming_server": "127.0.0.1", "incoming_port": self.imap.port(),
            "incoming_protocol": "none",
            "outgoing_server": "127.0.0.1", "outgoing_port": self.smtp.port(),
            "outgoing_protocol": "none",
        }}}));
    }

    async fn unlock_on(&self, client: &Client, changes: Value) {
        let mut body = json!({"email": USER, "password": PASSWORD, "profile_key": "sender"});
        for (key, value) in changes.as_object().unwrap() {
            body[key] = value.clone();
        }
        let response = client.post_json("/api/accounts/unlock", &body).await;
        assert_eq!(response.status, StatusCode::OK, "{}", response.text());
    }

    async fn unlock(&self, changes: Value) {
        self.unlock_on(&self.harness.client(), changes).await;
    }

    fn send_body() -> Value {
        json!({"account": USER, "to": ["recipient@example.net"], "subject": "Hello", "text": "Body"})
    }

    async fn send_on(&self, client: &Client, with_files: bool) -> Value {
        let response = if with_files {
            let mut body = Self::send_body();
            body["uploads"] = json!([{"disposition": "attachment", "content_id": ""}]);
            let form = format!(
                "--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"message\"\r\n\
                 Content-Type: application/json\r\n\r\n{body}\r\n\
                 --{BOUNDARY}\r\nContent-Disposition: form-data; name=\"files\"; filename=\"hello.txt\"\r\n\
                 Content-Type: text/plain\r\n\r\nAttachment\r\n--{BOUNDARY}--\r\n"
            );
            client
                .raw(
                    Method::POST,
                    "/api/mail/send/files",
                    Some(&format!("multipart/form-data; boundary={BOUNDARY}")),
                    form,
                )
                .await
        } else {
            client.post_json("/api/mail/send", &Self::send_body()).await
        };
        assert_eq!(response.status, StatusCode::OK, "{}", response.text());
        response.json()
    }

    async fn send(&self, with_files: bool) -> Value {
        self.send_on(&self.harness.client(), with_files).await
    }

    /// Python `assert_sender`: the delivered message and the Sent copy carry
    /// `name` (an empty name means a bare address) and the envelope sender
    /// is the account address.
    fn assert_sender(&self, name: &str) {
        let delivered = self.smtp.messages();
        let last = delivered.last().expect("a delivered message");
        assert_eq!(last.mail_from, USER);
        let mut copies = vec![last.data.clone()];
        let sent = self.imap.uids("Sent");
        if let Some(uid) = sent.last() {
            copies.push(self.imap.message("Sent", *uid).unwrap().raw);
        }
        assert_eq!(copies.len(), 2, "a Sent copy was saved");
        for raw in copies {
            let message = MessageParser::default().parse(&raw).unwrap();
            let address = message.from().and_then(|list| list.first()).unwrap();
            assert_eq!(address.address(), Some(USER));
            assert_eq!(address.name().unwrap_or(""), name);
        }
    }

    async fn listed_name(&self, client: &Client) -> Value {
        client.get("/api/accounts").await.json()["accounts"][0]["display_name"].clone()
    }
}

#[tokio::test]
async fn profile_changes_after_unlock_reach_both_send_paths_and_saved_copy() {
    let f = Fixture::new();
    f.unlock(json!({})).await;
    for (with_files, name) in [(false, "Example Sender"), (true, "Ren\u{e9}e, Team")] {
        f.write_profile(name, None);
        let result = f.send(with_files).await;
        assert_eq!(result["sent"], true);
        f.assert_sender(name);
        assert_eq!(f.listed_name(&f.harness.client()).await, name);
    }
    f.write_profile("", None);
    f.send(false).await;
    f.assert_sender("");
}

#[tokio::test]
async fn explicit_name_override_is_preserved() {
    let f = Fixture::new();
    f.write_profile("Profile Name", None);
    f.unlock(json!({"display_name": "My Custom Name"})).await;
    f.write_profile("Updated Profile Name", None);
    f.send(false).await;
    f.assert_sender("My Custom Name");
}

#[tokio::test]
async fn selected_profile_name_is_refreshed_when_connection_form_supplies_it() {
    let f = Fixture::new();
    f.write_profile("Original Name", None);
    f.unlock(json!({"display_name": "Original Name"})).await;
    f.write_profile("Updated Name", None);
    f.send(false).await;
    f.assert_sender("Updated Name");
    // The unchanged default was not saved as an override.
    assert!(!f.harness.settings_path.exists());
}

#[tokio::test]
async fn unnamed_session_uses_exact_profile_match() {
    let f = Fixture::new();
    f.harness.state.sessions.unlock(f.account());
    f.write_profile("Example Sender", Some(&USER.to_uppercase()));
    f.send(false).await;
    f.assert_sender("Example Sender");
}

#[tokio::test]
async fn another_account_on_same_provider_cannot_supply_the_sender_name() {
    let f = Fixture::new();
    f.harness.state.sessions.unlock(f.account());
    f.write_profile("Another Person", Some("someone@example.com"));
    f.send(false).await;
    f.assert_sender("");
    assert_eq!(f.listed_name(&f.harness.client()).await, "");
}

#[tokio::test]
async fn manual_named_account_does_not_require_a_profile() {
    let f = Fixture::new();
    let mut account = f.account();
    account.display_name = "Manual Sender".into();
    f.harness.state.sessions.unlock(account);
    f.harness.write_profiles(&json!({"servers": {}}));
    f.send(true).await;
    f.assert_sender("Manual Sender");
    // Not even a broken profile file is read for a manually named account.
    std::fs::write(f.harness.profiles_path(), "{broken").unwrap();
    assert_eq!(f.listed_name(&f.harness.client()).await, "Manual Sender");
}

#[tokio::test]
async fn profile_header_injection_is_rejected_before_smtp_connection() {
    let f = Fixture::new();
    f.unlock(json!({})).await;
    f.write_profile("Name\r\nBcc: hidden@example.com", None);
    let response = f
        .harness
        .post_json("/api/mail/send", &Fixture::send_body())
        .await;
    response.assert_json_error(StatusCode::BAD_GATEWAY);
    assert_eq!(f.smtp.connection_count(), 0);
}

#[tokio::test]
async fn custom_name_survives_restart_without_saving_server_profile() {
    let f = Fixture::new();
    f.write_profile("Profile Default", None);
    let original_profile = std::fs::read(f.harness.profiles_path()).unwrap();
    f.unlock(json!({"display_name": "Persistent Sender", "save_profile": false}))
        .await;
    assert_eq!(
        std::fs::read(f.harness.profiles_path()).unwrap(),
        original_profile
    );
    let profiles = f.harness.get("/api/mail/servers").await.json();
    assert_eq!(profiles["display_names"][USER], "Persistent Sender");

    let restarted = f.harness.restarted();
    assert_eq!(
        restarted.get("/api/accounts").await.json()["accounts"],
        json!([])
    );
    let response = restarted
        .post_json(
            "/api/accounts/unlock",
            &json!({"email": USER.to_uppercase(), "password": PASSWORD}),
        )
        .await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text());
    assert_eq!(
        response.json()["account"]["display_name"],
        "Persistent Sender"
    );
    assert_eq!(f.listed_name(&restarted).await, "Persistent Sender");
    let result = f.send_on(&restarted, false).await;
    assert_eq!(result["sent"], true);
    let delivered = f.smtp.messages();
    let message = MessageParser::default()
        .parse(&delivered.last().unwrap().data)
        .unwrap();
    assert_eq!(
        message.from().and_then(|list| list.first()).unwrap().name(),
        Some("Persistent Sender")
    );
}

#[tokio::test]
async fn explicit_clear_survives_password_only_unlock_and_sending() {
    let f = Fixture::new();
    f.write_profile("Profile Default", None);
    f.unlock(json!({"display_name": ""})).await;
    assert_eq!(
        f.harness.get("/api/mail/servers").await.json()["display_names"],
        json!({USER: ""})
    );
    f.harness.state.sessions.clear();
    // Password-only requests omit the name; they must not restore the default.
    f.unlock(json!({})).await;
    assert_eq!(f.listed_name(&f.harness.client()).await, "");
    f.send(true).await;
    f.assert_sender("");
}

#[tokio::test]
async fn explicit_empty_name_remains_empty_after_an_unnamed_profile_gets_a_default() {
    let f = Fixture::new();
    f.unlock(json!({"display_name": ""})).await;
    f.write_profile("New Profile Default", None);
    f.harness.state.sessions.clear();
    f.unlock(json!({})).await;
    f.send(false).await;
    f.assert_sender("");
}

#[tokio::test]
async fn manual_accounts_persist_names_without_creating_a_provider_profile() {
    let f = Fixture::new();
    f.harness.write_profiles(&json!({"servers": {}}));
    let imap = FakeImapServer::builder()
        .credentials("one@example.com", "ephemeral-secret")
        .credentials("two@example.com", "ephemeral-secret")
        .start();
    for (address, name) in [
        ("one@example.com", "First Sender"),
        ("two@example.com", "Second Sender"),
    ] {
        let response = f
            .harness
            .post_json(
                "/api/accounts/unlock",
                &json!({
                    "email": address, "password": "ephemeral-secret", "display_name": name,
                    "incoming_server": "127.0.0.1", "incoming_port": imap.port(),
                    "incoming_protocol": "none", "outgoing_server": "smtp.example.com",
                }),
            )
            .await;
        assert_eq!(response.status, StatusCode::OK, "{}", response.text());
    }
    let profiles = f.harness.get("/api/mail/servers").await.json();
    assert_eq!(profiles["servers"], json!({}));
    assert_eq!(
        profiles["display_names"],
        json!({"one@example.com": "First Sender", "two@example.com": "Second Sender"})
    );
    let settings = std::fs::read_to_string(&f.harness.settings_path).unwrap();
    assert!(!settings.contains("ephemeral-secret"));
}

#[tokio::test]
async fn save_preserves_signatures_and_other_settings() {
    let f = Fixture::new();
    let original = json!({
        "messages_per_page": 37,
        "emails_signatures": {USER: {"text": "<p>Signature</p>", "multipart-path": {}}},
        "data_directory": "retained-data",
    });
    f.harness.write_settings(&original.to_string());
    f.unlock(json!({"display_name": "Persistent Sender", "save_profile": true}))
        .await;
    let saved: Value =
        serde_json::from_str(&std::fs::read_to_string(&f.harness.settings_path).unwrap()).unwrap();
    for (key, value) in original.as_object().unwrap() {
        assert_eq!(&saved[key], value, "{key}");
    }
    assert_eq!(
        saved["email_display_names"],
        json!({USER: "Persistent Sender"})
    );
    assert!(!saved.to_string().contains(PASSWORD));
}

#[tokio::test]
async fn failed_save_does_not_unlock_or_report_success() {
    let f = Fixture::new();
    // settings.json would live below a regular file: it can never be written.
    let blocker = f.harness.root.join("blocker");
    std::fs::write(&blocker, "not a directory").unwrap();
    // The harness holds the serializing settings scope, so the override can
    // be swapped directly; dropping the scope restores the previous one.
    mail_core::settings::set_settings_path_override(Some(blocker.join("settings.json")));
    let response = f
        .harness
        .post_json(
            "/api/accounts/unlock",
            &json!({"email": USER, "password": PASSWORD, "profile_key": "sender",
                    "display_name": "Persistent Sender"}),
        )
        .await;
    let detail = response.assert_json_error(StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(
        detail,
        "Could not save the display name. Reconnect to try again."
    );
    assert!(!response.text().contains(PASSWORD));
    assert_eq!(
        f.harness.get("/api/accounts").await.json()["accounts"],
        json!([])
    );
    assert_eq!(
        f.harness.get("/api/mail/servers").await.json()["display_names"],
        json!({})
    );
}

#[tokio::test]
async fn failed_login_does_not_change_the_saved_name() {
    let f = Fixture::new();
    f.unlock(json!({"display_name": "Original Saved Name"}))
        .await;
    let original_settings = std::fs::read(&f.harness.settings_path).unwrap();
    let response = f
        .harness
        .post_json(
            "/api/accounts/unlock",
            &json!({"email": USER, "password": "incorrect", "display_name": "Wrong Name"}),
        )
        .await;
    response.assert_json_error(StatusCode::UNAUTHORIZED);
    assert_eq!(
        std::fs::read(&f.harness.settings_path).unwrap(),
        original_settings
    );
}

#[tokio::test]
async fn invalid_name_unicode_returns_validation_error_without_unlocking() {
    let f = Fixture::new();
    let connections = f.imap.connection_count();
    let response = f
        .harness
        .raw(
            Method::POST,
            "/api/accounts/unlock",
            Some("application/json"),
            r#"{"email": "user@example.com", "password": "memory-only", "display_name": "\ud800"}"#,
        )
        .await;
    assert_eq!(
        response.status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "{}",
        response.text()
    );
    assert!(response.text().is_ascii());
    assert!(!response.text().contains("memory-only"));
    assert_eq!(f.imap.connection_count(), connections);
    assert_eq!(
        f.harness.get("/api/accounts").await.json()["accounts"],
        json!([])
    );
}
