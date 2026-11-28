//! Port of the session tests of `tests/test_mail.py::MailApiTests`
//! (`test_unlock_verifies_imap_then_caches_password`,
//! `test_unlock_rejects_invalid_email_and_bad_credentials`) and the remaining
//! `unlock_account` / `lock_account` / `list_accounts` behaviors of main.py,
//! plus the POP3 unlock extension.
//!
//! Python patched `imap_client.verify_login`; here unlock really signs in to
//! a fake IMAP (or POP3) server from `mail_proto::testkit`.

mod accounts_support;
mod common;

use accounts_support::{closed_port, read_json, Harness};
use axum::http::{Method, StatusCode};
use mail_core::MailAccount;
use mail_proto::testkit::{FakeImapServer, FakePop3Server};
use serde_json::{json, Value};

const USER: &str = "y@example.org";
const PASSWORD: &str = "pw-memory-only";

fn imap_server() -> FakeImapServer {
    FakeImapServer::builder()
        .credentials(USER, PASSWORD)
        .start()
}

fn provider_profiles(port: u16) -> Value {
    json!({
        "servers": {
            "provider": {
                "incoming_server": "127.0.0.1",
                "incoming_port": port,
                "incoming_protocol": "none",
                "outgoing_server": "smtp.provider.example",
                "outgoing_port": 587,
                "outgoing_protocol": "STARTTLS",
                "email_address": USER,
            }
        }
    })
}

fn manual_unlock(email: &str, password: &str, port: u16) -> Value {
    json!({
        "email": email, "password": password,
        "incoming_server": "127.0.0.1", "incoming_port": port, "incoming_protocol": "none",
    })
}

#[tokio::test]
async fn unlock_verifies_imap_then_caches_password() {
    let server = imap_server();
    let harness = Harness::with_profiles(&provider_profiles(server.port()));
    let response = harness
        .post_json(
            "/api/accounts/unlock",
            &json!({"email": USER, "password": PASSWORD, "profile_key": "provider"}),
        )
        .await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text());
    let account = response.json()["account"].clone();
    assert_eq!(account["email"], USER);
    assert_eq!(account["incoming_server"], "127.0.0.1");
    assert_eq!(account["incoming_port"], server.port());
    assert_eq!(account["incoming_protocol"], "none");
    assert_eq!(account["outgoing_server"], "smtp.provider.example");
    assert_eq!(account["incoming_mail_protocol"], "imap");
    assert!(!response.text().contains("password"));
    assert!(!response.text().contains(PASSWORD));
    assert!(server.command_names().iter().any(|name| name == "LOGIN"));
    assert_eq!(harness.state.sessions.get(USER).unwrap().password, PASSWORD);

    let accounts = harness.get("/api/accounts").await.json();
    assert_eq!(accounts["accounts"][0]["email"], USER);
    assert!(!accounts.to_string().contains(PASSWORD));

    let response = harness.delete("/api/accounts/Y%40Example.org").await;
    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(response.json(), json!({"locked": USER}));
    assert_eq!(
        harness.get("/api/accounts").await.json()["accounts"],
        json!([])
    );
    let response = harness.delete("/api/accounts/y%40example.org").await;
    assert_eq!(
        response.assert_json_error(StatusCode::NOT_FOUND),
        "Account is not unlocked"
    );
}

#[tokio::test]
async fn unlock_rejects_invalid_email_and_bad_credentials() {
    let server = imap_server();
    let harness = Harness::new();
    for email in ["not-an-email", "a@b@c", "  @@  "] {
        let response = harness
            .post_json(
                "/api/accounts/unlock",
                &json!({"email": email, "password": "x"}),
            )
            .await;
        assert_eq!(
            response.assert_json_error(StatusCode::BAD_REQUEST),
            "Enter a valid email address"
        );
    }
    let response = harness
        .post_json(
            "/api/accounts/unlock",
            &manual_unlock(USER, "wrong", server.port()),
        )
        .await;
    assert_eq!(
        response.assert_json_error(StatusCode::UNAUTHORIZED),
        "Mailbox sign-in failed. Check the password or use an app password."
    );
    assert!(harness.state.sessions.list().is_empty());
    assert!(!response.text().contains("wrong"));
}

#[tokio::test]
async fn unreachable_server_is_a_401_with_the_connection_error() {
    let harness = Harness::new();
    let port = closed_port();
    let response = harness
        .post_json(
            "/api/accounts/unlock",
            &manual_unlock("a@example.org", "x", port),
        )
        .await;
    let detail = response.assert_json_error(StatusCode::UNAUTHORIZED);
    assert!(
        detail
            .as_str()
            .unwrap()
            .starts_with(&format!("Could not connect to 127.0.0.1:{port}")),
        "{detail}"
    );
    assert!(harness.state.sessions.list().is_empty());
}

#[tokio::test]
async fn unknown_profile_and_missing_server_are_rejected_before_connecting() {
    let server = imap_server();
    let harness = Harness::with_profiles(&provider_profiles(server.port()));
    let response = harness
        .post_json(
            "/api/accounts/unlock",
            &json!({"email": USER, "password": PASSWORD, "profile_key": "missing"}),
        )
        .await;
    assert_eq!(
        response.assert_json_error(StatusCode::NOT_FOUND),
        "Profile not found"
    );
    // No profile matches this domain and no server was given.
    let response = harness
        .post_json(
            "/api/accounts/unlock",
            &json!({"email": "a@unrelated.test", "password": "x", "incoming_server": "   "}),
        )
        .await;
    assert_eq!(
        response.assert_json_error(StatusCode::BAD_REQUEST),
        "No incoming (IMAP) server is configured for this account"
    );
    assert_eq!(server.connection_count(), 0);
}

#[tokio::test]
async fn empty_profile_key_falls_back_to_the_email_match_and_overrides_win() {
    let server = imap_server();
    let harness = Harness::with_profiles(&provider_profiles(closed_port()));
    let response = harness
        .post_json(
            "/api/accounts/unlock",
            &json!({
                "email": format!("  {USER} "), "password": PASSWORD, "profile_key": "",
                "incoming_port": server.port(), "outgoing_server": "  smtp.override.example ",
                "outgoing_port": 2525, "outgoing_protocol": " SSL/TLS ",
            }),
        )
        .await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text());
    let account = response.json()["account"].clone();
    assert_eq!(account["email"], USER);
    assert_eq!(account["incoming_server"], "127.0.0.1");
    assert_eq!(account["incoming_port"], server.port());
    assert_eq!(account["outgoing_server"], "smtp.override.example");
    assert_eq!(account["outgoing_port"], 2525);
    assert_eq!(account["outgoing_protocol"], "SSL/TLS");
}

#[tokio::test]
async fn validation_errors_are_ascii_encoded_and_never_connect() {
    let server = imap_server();
    let harness = Harness::new();
    let response = harness
        .post_json(
            "/api/accounts/unlock",
            &json!({"email": USER, "password": "memory-only", "display_name": "Zo\u{eb}\r\nBcc: x"}),
        )
        .await;
    assert_eq!(response.status, StatusCode::UNPROCESSABLE_ENTITY);
    let text = response.text();
    assert!(text.is_ascii(), "{text}");
    assert!(text.starts_with(r#"{"detail": [{"#), "{text}");
    let detail = response.json()["detail"].clone();
    assert_eq!(detail[0]["loc"], json!(["body", "display_name"]));
    assert_eq!(
        detail[0]["msg"],
        "Value error, Display name must not contain control characters"
    );

    let response = harness
        .post_json(
            "/api/accounts/unlock",
            &json!({"email": "ab", "password": "", "incoming_port": 70000, "save_profile": "maybe"}),
        )
        .await;
    let detail = response.assert_json_error(StatusCode::UNPROCESSABLE_ENTITY);
    let types: Vec<&str> = detail
        .as_array()
        .unwrap()
        .iter()
        .map(|issue| issue["type"].as_str().unwrap())
        .collect();
    assert_eq!(
        types,
        [
            "string_too_short",
            "string_too_short",
            "less_than_equal",
            "bool_parsing"
        ]
    );

    let response = harness
        .raw(
            Method::POST,
            "/api/accounts/unlock",
            Some("application/json"),
            "",
        )
        .await;
    assert_eq!(
        response.json(),
        json!({"detail": [{"type": "missing", "loc": ["body"], "msg": "Field required", "input": null}]})
    );
    assert_eq!(server.connection_count(), 0);
    assert!(harness.state.sessions.list().is_empty());
}

#[tokio::test]
async fn save_profile_creates_a_profile_only_when_none_matched() {
    let server = imap_server();
    let harness = Harness::new();
    let mut body = manual_unlock(USER, PASSWORD, server.port());
    body["save_profile"] = json!(true);
    body["display_name"] = json!(" Example Sender ");
    body["outgoing_server"] = json!("smtp.example.org");
    let response = harness.post_json("/api/accounts/unlock", &body).await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text());
    assert_eq!(response.json()["account"]["display_name"], "Example Sender");
    let profiles = harness.read_profiles();
    assert_eq!(
        profiles["servers"]["y-example.org"],
        json!({
            "incoming_server": "127.0.0.1",
            "incoming_port": server.port(),
            "incoming_protocol": "none",
            "outgoing_server": "smtp.example.org",
            "outgoing_port": 587,
            "outgoing_protocol": "STARTTLS",
            "email_address": USER,
            "display_name": "Example Sender",
            "incoming_mail_protocol": "imap",
        })
    );
    assert!(!profiles.to_string().contains(PASSWORD));
    let settings = std::fs::read_to_string(&harness.settings_path).unwrap();
    assert!(!settings.contains(PASSWORD));

    // The profile now matches: a second save does not add another one.
    let before = std::fs::read(harness.profiles_path()).unwrap();
    let response = harness.post_json("/api/accounts/unlock", &body).await;
    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(std::fs::read(harness.profiles_path()).unwrap(), before);
}

#[tokio::test]
async fn unlock_registers_the_weekly_audit_and_relock_replaces_the_session() {
    let server = imap_server();
    let harness = Harness::new();
    let body = manual_unlock(USER, PASSWORD, server.port());
    harness.post_json("/api/accounts/unlock", &body).await;
    let first = harness.state.sessions.get(USER).unwrap();
    let rows = harness.state.audit_scheduler.rows().unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].email, USER);

    let response = harness.post_json("/api/accounts/unlock", &body).await;
    assert_eq!(response.status, StatusCode::OK);
    assert!(!harness.state.sessions.is_current(&first));
    assert_eq!(harness.state.audit_scheduler.rows().unwrap().len(), 1);
    assert_eq!(harness.state.sessions.list().len(), 1);
}

#[tokio::test]
async fn lock_forgets_the_session_and_image_sources() {
    let harness = Harness::new();
    let account = MailAccount::new(
        USER,
        PASSWORD,
        "127.0.0.1",
        1,
        "none",
        "127.0.0.1",
        1,
        "none",
    );
    harness.state.sessions.unlock(account);
    harness.state.image_sources.register(
        USER,
        "INBOX",
        7,
        r#"<img src="https://images.example.org/a.png">"#,
    );
    assert!(harness
        .state
        .image_sources
        .sources(USER, "INBOX", 7)
        .is_some());
    let response = harness.delete("/api/accounts/%20Y%40example.org%20").await;
    assert_eq!(response.json(), json!({"locked": USER}));
    assert!(harness
        .state
        .image_sources
        .sources(USER, "INBOX", 7)
        .is_none());
    assert!(harness.state.sessions.get(USER).is_none());
}

#[tokio::test]
async fn accounts_list_resolves_display_names_and_reports_broken_files() {
    let harness = Harness::new();
    let mut account = MailAccount::new(
        USER,
        PASSWORD,
        "127.0.0.1",
        1,
        "none",
        "127.0.0.1",
        1,
        "none",
    );
    account.display_name = "Manual Name".into();
    harness.state.sessions.unlock(account);
    let listed = harness.get("/api/accounts").await.json();
    assert_eq!(listed["accounts"][0]["display_name"], "Manual Name");
    assert!(listed["accounts"][0].get("password").is_none());

    harness.write_settings(&json!({"email_display_names": {USER: "Saved Name"}}).to_string());
    let listed = harness.get("/api/accounts").await.json();
    assert_eq!(listed["accounts"][0]["display_name"], "Saved Name");

    harness.write_settings("{broken");
    let response = harness.get("/api/accounts").await;
    response.assert_json_error(StatusCode::INTERNAL_SERVER_ERROR);
}

#[tokio::test]
async fn accounts_list_reports_unreadable_profiles_when_needed() {
    let harness = Harness::new();
    let mut account = MailAccount::new(
        USER,
        PASSWORD,
        "127.0.0.1",
        1,
        "none",
        "127.0.0.1",
        1,
        "none",
    );
    account.sender_profile_key = Some("provider".into());
    harness.state.sessions.unlock(account);
    std::fs::write(harness.profiles_path(), "{broken").unwrap();
    let response = harness.get("/api/accounts").await;
    let detail = response.assert_json_error(StatusCode::INTERNAL_SERVER_ERROR);
    assert!(detail.as_str().unwrap().contains("mail-servers.json"));
}

#[tokio::test]
async fn unlock_with_unreadable_profiles_is_a_500() {
    let harness = Harness::new();
    std::fs::write(harness.profiles_path(), "{broken").unwrap();
    let response = harness
        .post_json("/api/accounts/unlock", &manual_unlock(USER, PASSWORD, 1))
        .await;
    let detail = response.assert_json_error(StatusCode::INTERNAL_SERVER_ERROR);
    assert!(detail.as_str().unwrap().contains("mail-servers.json"));
    assert!(!response.text().contains(PASSWORD));
}

// ---------------------------------------------------------------------------
// POP3 extension
// ---------------------------------------------------------------------------

fn pop3_server() -> FakePop3Server {
    FakePop3Server::builder()
        .credentials(USER, PASSWORD)
        .message(b"Subject: hi\r\n\r\nbody\r\n".to_vec())
        .start()
}

#[tokio::test]
async fn pop3_unlock_signs_in_with_pop3() {
    let server = pop3_server();
    let harness = Harness::new();
    let mut body = manual_unlock(USER, PASSWORD, server.port());
    body["incoming_mail_protocol"] = json!("pop3");
    body["save_profile"] = json!(true);
    let response = harness.post_json("/api/accounts/unlock", &body).await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text());
    assert_eq!(response.json()["account"]["incoming_mail_protocol"], "pop3");
    assert!(harness.state.sessions.get(USER).unwrap().is_pop3());
    assert!(server.command_names().iter().any(|name| name == "PASS"));
    let profiles = read_json(&harness.profiles_path());
    assert_eq!(
        profiles["servers"]["y-example.org"]["incoming_mail_protocol"],
        "pop3"
    );

    harness.state.sessions.clear();
    body["password"] = json!("wrong");
    let response = harness.post_json("/api/accounts/unlock", &body).await;
    response.assert_json_error(StatusCode::UNAUTHORIZED);
    assert!(harness.state.sessions.list().is_empty());
}

#[tokio::test]
async fn pop3_profile_selects_pop3_unless_the_request_overrides_it() {
    let server = pop3_server();
    let harness = Harness::with_profiles(&json!({"servers": {"pop": {
        "incoming_server": "127.0.0.1", "incoming_port": server.port(), "incoming_protocol": "none",
        "outgoing_server": "smtp.example.org", "email_address": USER,
        "incoming_mail_protocol": "pop3",
    }}}));
    let response = harness
        .post_json(
            "/api/accounts/unlock",
            &json!({"email": USER, "password": PASSWORD, "profile_key": "pop"}),
        )
        .await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text());
    assert_eq!(response.json()["account"]["incoming_mail_protocol"], "pop3");

    // Asking for IMAP against the POP3-only fake server fails to sign in.
    let response = harness
        .post_json(
            "/api/accounts/unlock",
            &json!({"email": USER, "password": PASSWORD, "profile_key": "pop",
                    "incoming_mail_protocol": "imap"}),
        )
        .await;
    response.assert_json_error(StatusCode::UNAUTHORIZED);

    let response = harness
        .post_json(
            "/api/accounts/unlock",
            &json!({"email": USER, "password": PASSWORD, "incoming_mail_protocol": "smtp"}),
        )
        .await;
    response.assert_json_error(StatusCode::UNPROCESSABLE_ENTITY);
}
