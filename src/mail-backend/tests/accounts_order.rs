//! Ordering parity with the Python dicts behind `/api/accounts`,
//! `/api/mail/servers`, `/api/accounts/unlock` and `/api/settings`, plus the
//! `ensure_ascii=True` encoding of unlock validation errors.

mod accounts_support;
mod common;

use accounts_support::{closed_port, Harness};
use axum::http::StatusCode;
use mail_core::MailAccount;
use mail_proto::testkit::FakeImapServer;
use serde_json::{json, Value};

fn keys(value: &Value) -> Vec<String> {
    value.as_object().expect("object").keys().cloned().collect()
}

fn account(email: &str) -> MailAccount {
    MailAccount::new(
        email,
        "secret-in-memory",
        "imap.example.com",
        993,
        "SSL/TLS",
        "smtp.example.com",
        587,
        "STARTTLS",
    )
}

#[tokio::test]
async fn accounts_are_listed_in_session_insertion_order() {
    let harness = Harness::new();
    for email in ["c@example.com", "a@example.com", "b@example.com"] {
        harness.state.sessions.unlock(account(email));
    }
    // Re-unlocking keeps the first position (Python dict assignment);
    // locking and unlocking again moves the account to the end.
    harness.state.sessions.unlock(account("c@example.com"));
    assert_eq!(
        harness.delete("/api/accounts/a%40example.com").await.status,
        StatusCode::OK
    );
    harness.state.sessions.unlock(account("a@example.com"));

    let response = harness.get("/api/accounts").await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text());
    let listed: Vec<String> = response.json()["accounts"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| item["email"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(listed, ["c@example.com", "b@example.com", "a@example.com"]);
    assert!(!response.text().contains("secret-in-memory"));
}

#[tokio::test]
async fn server_profiles_keep_file_order_through_list_upsert_and_delete() {
    let harness = Harness::new();
    std::fs::write(
        harness.profiles_path(),
        r#"{"servers": {
            "zeta": {"incoming_server": "imap.zeta.example", "outgoing_server": "smtp.zeta.example"},
            "alpha": {"incoming_server": "imap.alpha.example", "outgoing_server": "smtp.alpha.example"},
            "mid": {"incoming_server": "imap.mid.example", "outgoing_server": "smtp.mid.example"}
        }}"#,
    )
    .unwrap();
    let listed = harness.get("/api/mail/servers").await.json();
    assert_eq!(keys(&listed), ["path", "servers", "display_names"]);
    assert_eq!(keys(&listed["servers"]), ["zeta", "alpha", "mid"]);
    assert_eq!(
        keys(&listed["servers"]["zeta"]),
        [
            "incoming_server",
            "incoming_port",
            "incoming_protocol",
            "outgoing_server",
            "outgoing_port",
            "outgoing_protocol",
            "email_address",
            "display_name",
            "incoming_mail_protocol",
        ]
    );

    // Replacing keeps the position, a new key is appended.
    let body =
        json!({"incoming_server": "imap.new.example", "outgoing_server": "smtp.new.example"});
    let response = harness.put_json("/api/mail/servers/alpha", &body).await;
    assert_eq!(response.status, StatusCode::CREATED, "{}", response.text());
    assert_eq!(keys(&response.json()), ["key", "profile"]);
    let response = harness.put_json("/api/mail/servers/Beta", &body).await;
    assert_eq!(response.json()["key"], "beta");
    assert_eq!(
        keys(&harness.read_profiles()["servers"]),
        ["zeta", "alpha", "mid", "beta"]
    );

    // Deleting keeps the order of the remaining profiles.
    let response = harness.delete("/api/mail/servers/zeta").await;
    assert_eq!(response.json(), json!({"deleted": "zeta"}));
    assert_eq!(
        keys(&harness.get("/api/mail/servers").await.json()["servers"]),
        ["alpha", "mid", "beta"]
    );
}

#[tokio::test]
async fn unlock_uses_the_first_matching_profile_in_file_order() {
    let user = "owner@example.org";
    let password = "pw-memory-only";
    let server = FakeImapServer::builder()
        .credentials(user, password)
        .start();
    // Both profiles match the address's domain; Python picked the first one
    // in file order ("zz-first"), not the alphabetically first ("aa-second",
    // whose server is closed).
    let profiles = format!(
        r#"{{"servers": {{
            "zz-first": {{"incoming_server": "127.0.0.1", "incoming_port": {port},
                          "incoming_protocol": "none", "outgoing_server": "smtp.example.org",
                          "email_address": "{user}", "display_name": "First Profile"}},
            "aa-second": {{"incoming_server": "127.0.0.1", "incoming_port": {closed},
                           "incoming_protocol": "none", "outgoing_server": "smtp.example.org",
                           "email_address": "{user}", "display_name": "Second Profile"}}
        }}}}"#,
        port = server.port(),
        closed = closed_port(),
    );
    let harness = Harness::new();
    std::fs::write(harness.profiles_path(), profiles).unwrap();
    let response = harness
        .post_json(
            "/api/accounts/unlock",
            &json!({"email": user, "password": password}),
        )
        .await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text());
    let account = response.json()["account"].clone();
    assert_eq!(account["incoming_port"], server.port());
    assert_eq!(account["display_name"], "First Profile");
    assert_eq!(
        keys(&account),
        [
            "email",
            "display_name",
            "incoming_server",
            "incoming_port",
            "incoming_protocol",
            "outgoing_server",
            "outgoing_port",
            "outgoing_protocol",
            "incoming_mail_protocol",
            "unlocked_at",
        ]
    );
    // `_sender_account` resolves the same profile when listing.
    let listed = harness.get("/api/accounts").await.json();
    assert_eq!(listed["accounts"][0]["display_name"], "First Profile");
}

#[tokio::test]
async fn unlock_validation_errors_escape_del_like_python_ensure_ascii() {
    let harness = Harness::new();
    let response = harness
        .post_json(
            "/api/accounts/unlock",
            &json!({"email": "u@example.com", "password": "x", "display_name": "Bad\u{7f}Name é"}),
        )
        .await;
    assert_eq!(response.status, StatusCode::UNPROCESSABLE_ENTITY);
    let text = response.text();
    let bs = '\\';
    let expected = format!(r#""input": "Bad{bs}u007fName {bs}u00e9""#);
    assert!(text.contains(&expected), "{text}");
    assert!(text.is_ascii(), "{text}");
    let issue = &response.json()["detail"][0];
    assert_eq!(keys(issue), ["type", "loc", "msg", "input", "ctx"]);
    assert_eq!(issue["loc"], json!(["body", "display_name"]));
}

#[tokio::test]
async fn settings_response_lists_categories_in_email_categories_order() {
    let harness = Harness::new();
    let order = [
        "marketing",
        "transactional",
        "updates",
        "verification",
        "uncategorized",
    ];
    let response = harness.get("/api/settings").await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text());
    let body = response.json();
    assert_eq!(
        keys(&body),
        [
            "messages_per_page",
            "signature",
            "category_expiration_days",
            "local_ai_model"
        ]
    );
    assert_eq!(keys(&body["category_expiration_days"]), order);

    let response = harness
        .put_json(
            "/api/settings",
            &json!({"messages_per_page": 7, "category_expiration_days": {
                "uncategorized": 1, "verification": 2, "updates": 3, "transactional": 4, "marketing": 5,
            }}),
        )
        .await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text());
    assert_eq!(keys(&response.json()["category_expiration_days"]), order);
    let stored: Value =
        serde_json::from_str(&std::fs::read_to_string(&harness.settings_path).unwrap()).unwrap();
    assert_eq!(keys(&stored["category_expiration_days"]), order);
}
