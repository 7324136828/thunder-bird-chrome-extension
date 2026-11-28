//! Port of the server-profile tests of `tests/test_mail.py::MailApiTests`
//! (`test_servers_endpoint_lists_profiles_from_file`,
//! `test_profile_can_be_added_and_removed_without_passwords`) plus the
//! remaining `list/upsert/delete_server_profile` behaviors of main.py.
//!
//! The Python fixture used a real provider name/address; the port uses
//! example.org.

mod accounts_support;
mod common;

use accounts_support::Harness;
use axum::http::{Method, StatusCode};
use serde_json::{json, Value};

fn provider_profiles() -> Value {
    json!({
        "servers": {
            "provider": {
                "incoming_server": "imap.provider.example",
                "incoming_port": 993,
                "incoming_protocol": "SSL/TLS",
                "outgoing_server": "smtp.provider.example",
                "outgoing_port": 587,
                "outgoing_protocol": "STARTTLS",
                "email_address": "y@example.org",
            }
        }
    })
}

fn work_profile() -> Value {
    json!({
        "incoming_server": "imap.work.example",
        "outgoing_server": "smtp.work.example",
        "email_address": "me@work.example",
    })
}

#[tokio::test]
async fn servers_endpoint_lists_profiles_from_file() {
    let harness = Harness::with_profiles(&provider_profiles());
    let response = harness.get("/api/mail/servers").await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text());
    let data = response.json();
    assert_eq!(
        data["path"],
        harness.profiles_path().to_string_lossy().as_ref()
    );
    assert_eq!(
        data["servers"]["provider"],
        json!({
            "incoming_server": "imap.provider.example",
            "incoming_port": 993,
            "incoming_protocol": "SSL/TLS",
            "outgoing_server": "smtp.provider.example",
            "outgoing_port": 587,
            "outgoing_protocol": "STARTTLS",
            "email_address": "y@example.org",
            "display_name": "",
            "incoming_mail_protocol": "imap",
        })
    );
    assert_eq!(data["display_names"], json!({}));
    assert!(data.get("display_names_error").is_none());
}

#[tokio::test]
async fn profile_can_be_added_and_removed_without_passwords() {
    let harness = Harness::with_profiles(&provider_profiles());
    let response = harness
        .put_json("/api/mail/servers/work", &work_profile())
        .await;
    assert_eq!(response.status, StatusCode::CREATED, "{}", response.text());
    assert_eq!(
        response.json(),
        json!({
            "key": "work",
            "profile": {
                "incoming_server": "imap.work.example",
                "incoming_port": 993,
                "incoming_protocol": "SSL/TLS",
                "outgoing_server": "smtp.work.example",
                "outgoing_port": 587,
                "outgoing_protocol": "STARTTLS",
                "email_address": "me@work.example",
                "display_name": "",
                "incoming_mail_protocol": "imap",
            }
        })
    );
    let on_disk = harness.read_profiles();
    assert!(on_disk["servers"].get("work").is_some());
    assert!(on_disk["servers"].get("provider").is_some());
    assert!(!on_disk.to_string().contains("password"));

    let response = harness.delete("/api/mail/servers/work").await;
    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(response.json(), json!({"deleted": "work"}));
    let response = harness.delete("/api/mail/servers/work").await;
    assert_eq!(
        response.assert_json_error(StatusCode::NOT_FOUND),
        "Profile not found"
    );
    assert!(harness.read_profiles()["servers"].get("work").is_none());
}

#[tokio::test]
async fn profile_keys_are_sanitized_on_save_but_not_on_delete() {
    let harness = Harness::new();
    let response = harness
        .put_json("/api/mail/servers/.My%20Work!!%20Box-", &work_profile())
        .await;
    assert_eq!(response.status, StatusCode::CREATED, "{}", response.text());
    assert_eq!(response.json()["key"], "my-work-box");

    // Deleting uses the exact key.
    let response = harness.delete("/api/mail/servers/My%20Work!!%20Box").await;
    response.assert_json_error(StatusCode::NOT_FOUND);
    let response = harness.delete("/api/mail/servers/my-work-box").await;
    assert_eq!(response.json(), json!({"deleted": "my-work-box"}));

    let long = "K".repeat(130);
    let response = harness
        .put_json(&format!("/api/mail/servers/{long}"), &work_profile())
        .await;
    assert_eq!(response.status, StatusCode::CREATED);
    assert_eq!(response.json()["key"], "k".repeat(120));

    let response = harness
        .put_json("/api/mail/servers/%2D%2E%21", &work_profile())
        .await;
    assert_eq!(
        response.assert_json_error(StatusCode::BAD_REQUEST),
        "Profile key is empty"
    );
}

#[tokio::test]
async fn invalid_bodies_are_rejected_before_the_key_is_checked() {
    let harness = Harness::new();
    let before = std::fs::read(harness.profiles_path()).unwrap();
    let response = harness
        .put_json(
            "/api/mail/servers/%21%21",
            &json!({"outgoing_server": "smtp.work.example", "incoming_port": 0}),
        )
        .await;
    let detail = response.assert_json_error(StatusCode::UNPROCESSABLE_ENTITY);
    let locations: Vec<Value> = detail
        .as_array()
        .unwrap()
        .iter()
        .map(|issue| issue["loc"].clone())
        .collect();
    assert_eq!(
        locations,
        vec![
            json!(["body", "incoming_server"]),
            json!(["body", "incoming_port"])
        ]
    );
    assert_eq!(detail[0]["type"], "missing");
    // Not an ASCII-encoded path: compact JSON.
    assert!(response.text().starts_with(r#"{"detail":[{"#));

    let response = harness
        .put_json(
            "/api/mail/servers/work",
            &json!({"incoming_server": "imap.work.example", "outgoing_server": "smtp.work.example",
                    "incoming_mail_protocol": "smtp"}),
        )
        .await;
    response.assert_json_error(StatusCode::UNPROCESSABLE_ENTITY);
    let response = harness
        .raw(
            Method::PUT,
            "/api/mail/servers/work",
            Some("application/json"),
            "",
        )
        .await;
    response.assert_json_error(StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(std::fs::read(harness.profiles_path()).unwrap(), before);
}

#[tokio::test]
async fn pop3_profiles_keep_their_protocol() {
    let harness = Harness::new();
    let response = harness
        .put_json(
            "/api/mail/servers/pop",
            &json!({
                "incoming_server": "pop.example.org", "incoming_port": 995,
                "outgoing_server": "smtp.example.org", "incoming_mail_protocol": "pop3",
                "display_name": "Example Sender",
            }),
        )
        .await;
    assert_eq!(response.status, StatusCode::CREATED, "{}", response.text());
    let listed = harness.get("/api/mail/servers").await.json();
    assert_eq!(listed["servers"]["pop"]["incoming_mail_protocol"], "pop3");
    assert_eq!(listed["servers"]["pop"]["incoming_port"], 995);
    assert_eq!(listed["servers"]["pop"]["display_name"], "Example Sender");
}

#[tokio::test]
async fn display_names_are_listed_and_unreadable_names_are_reported() {
    let harness = Harness::new();
    harness.write_settings(r#"{"email_display_names": {" Me@Example.org ": "Example Sender"}}"#);
    let data = harness.get("/api/mail/servers").await.json();
    assert_eq!(
        data["display_names"],
        json!({"me@example.org": "Example Sender"})
    );

    harness.write_settings(r#"{"email_display_names": ["not", "a", "map"]}"#);
    let response = harness.get("/api/mail/servers").await;
    assert_eq!(response.status, StatusCode::OK);
    let data = response.json();
    assert_eq!(data["display_names"], json!({}));
    assert_eq!(
        data["display_names_error"],
        "Invalid email_display_names in settings"
    );
    assert_eq!(data["servers"], json!({}));
}

#[tokio::test]
async fn corrupt_profiles_answer_500_on_every_route() {
    let harness = Harness::new();
    std::fs::write(harness.profiles_path(), "{broken").unwrap();
    for response in [
        harness.get("/api/mail/servers").await,
        harness
            .put_json("/api/mail/servers/work", &work_profile())
            .await,
        harness.delete("/api/mail/servers/work").await,
    ] {
        let detail = response.assert_json_error(StatusCode::INTERNAL_SERVER_ERROR);
        assert!(
            detail.as_str().unwrap().contains("mail-servers.json"),
            "{detail}"
        );
    }
    assert_eq!(std::fs::read(harness.profiles_path()).unwrap(), b"{broken");

    std::fs::write(harness.profiles_path(), r#"{"servers": []}"#).unwrap();
    let response = harness.get("/api/mail/servers").await;
    let detail = response.assert_json_error(StatusCode::INTERNAL_SERVER_ERROR);
    assert!(detail
        .as_str()
        .unwrap()
        .contains("'servers' must be an object"));
}
