//! End-to-end: Inbox Doctor audit of an account unlocked through the API
//! (`doctorApi.account` → poll `doctorApi.job` → files / zip / discard),
//! against a fake IMAP server.

mod e2e_support;

use axum::http::{Method, StatusCode};
use e2e_support::*;
use mail_proto::testkit::FakeImapServer;
use serde_json::json;

fn newsletter(index: usize) -> String {
    format!(
        "From: Shop News <news@shop.example.com>\r\nTo: {USER}\r\n\
         Subject: Offer number {index}\r\nDate: {}\r\nMessage-ID: <offer-{index}@shop.example.com>\r\n\
         List-Unsubscribe: <https://shop.example.com/u/{index}>\r\nMIME-Version: 1.0\r\n\
         Content-Type: text/plain; charset=utf-8\r\n\r\nSale {index}: visit https://shop.example.com/sale\r\n",
        rfc2822_days_ago(0)
    )
}

#[tokio::test]
async fn unlocked_imap_account_audit_runs_to_completion() {
    let mut builder = FakeImapServer::builder().credentials(USER, PASSWORD);
    for index in 0..3 {
        builder = builder.message_with(
            "INBOX",
            fake_message(10 + index as u32, &newsletter(index), 0, &[]),
        );
    }
    builder = builder.message_with(
        "INBOX",
        fake_message(
            20,
            &plain_message("Bob <bob@example.net>", "Hi", "Hello", 0, "hi"),
            0,
            &[],
        ),
    );
    let imap = builder.start();
    let app = E2e::new();

    let unlocked = app
        .unlock(json!({
            "email": USER, "password": PASSWORD, "incoming_server": "127.0.0.1",
            "incoming_port": imap.port(), "incoming_protocol": "NONE",
            "outgoing_server": "127.0.0.1", "outgoing_port": 2525, "outgoing_protocol": "NONE",
        }))
        .await;
    unlocked.ok();

    let response = app
        .post_json(
            "/api/mail/jobs/account",
            &json!({"account": "USER@example.com", "days": 7}),
        )
        .await;
    assert_eq!(response.status, StatusCode::CREATED, "{}", response.text());
    let created = response.json();
    assert_eq!(created["source_kind"], "mailbox");
    assert_eq!(created["account_email"], USER);
    assert_eq!(created["days"], 7);
    for key in [
        "id",
        "filename",
        "file_size",
        "status",
        "progress",
        "stage",
        "log",
        "error_message",
        "created_at",
        "completed_at",
        "output_files",
        "source_kind",
        "account_email",
        "days",
        "downloaded_messages",
        "total_messages",
        "snapshot_available",
        "snapshot_at",
    ] {
        assert!(created.get(key).is_some(), "{key} missing: {created}");
    }
    let id = created["id"].as_str().unwrap().to_string();

    let job = app.wait_job(&id).await;
    assert_eq!(job["status"], "completed", "{}", job["log"]);
    assert_eq!(job["downloaded_messages"], 4, "{job}");
    assert_eq!(job["total_messages"], 4, "{job}");
    assert_eq!(job["progress"], 100, "{job}");
    assert!(!job.to_string().contains(PASSWORD));
    // The audit only examined INBOX read-only.
    let commands = imap.commands();
    assert!(
        commands.iter().any(|c| c.starts_with("EXAMINE")),
        "{commands:?}"
    );
    assert!(
        !commands.iter().any(|c| c.starts_with("SELECT")),
        "{commands:?}"
    );
    assert!(!commands
        .iter()
        .any(|c| c.contains("STORE") || c.contains("EXPUNGE")));
    assert!(imap.flags("INBOX", 10).unwrap().is_empty());

    let jobs = app.get("/api/jobs", &[]).await.ok();
    assert!(jobs
        .as_array()
        .unwrap()
        .iter()
        .any(|item| item["id"] == id.as_str()));

    let files = app.get(&format!("/api/jobs/{id}/files"), &[]).await.ok();
    let files: Vec<String> = files["files"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f.as_str().unwrap().to_string())
        .collect();
    assert!(!files.is_empty());
    for file in files.iter().take(5) {
        let encoded: Vec<String> = file
            .split('/')
            .map(|segment| {
                percent_encoding::utf8_percent_encode(segment, percent_encoding::NON_ALPHANUMERIC)
                    .to_string()
            })
            .collect();
        let response = app
            .get(&format!("/api/jobs/{id}/files/{}", encoded.join("/")), &[])
            .await;
        assert_eq!(
            response.status,
            StatusCode::OK,
            "{file}: {}",
            response.text()
        );
        assert_eq!(response.header("x-content-type-options"), Some("nosniff"));
    }
    let traversal = app
        .get(
            &format!("/api/jobs/{id}/files/..%2F..%2Fsettings.json"),
            &[],
        )
        .await;
    assert!(
        traversal.status == StatusCode::NOT_FOUND || traversal.status == StatusCode::BAD_REQUEST,
        "{}",
        traversal.text()
    );

    let zip = app.get(&format!("/api/jobs/{id}/download-zip"), &[]).await;
    assert_eq!(zip.status, StatusCode::OK, "{}", zip.text());
    assert_eq!(zip.header("content-type"), Some("application/zip"));
    let entries = zip_entries(&zip.body);
    assert!(!entries.is_empty());
    assert!(entries
        .values()
        .all(|bytes| !contains(bytes, PASSWORD.as_bytes())));

    let snapshot = app
        .get(&format!("/api/jobs/{id}/snapshot-files"), &[])
        .await
        .ok();
    assert!(snapshot["files"].as_array().is_some_and(|f| !f.is_empty()));

    let discarded = app
        .send(
            E2e::builder(Method::POST, &format!("/api/jobs/{id}/discard"))
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .ok();
    assert_eq!(discarded["status"], "discarded");
    let again = app
        .send(
            E2e::builder(Method::POST, &format!("/api/jobs/{id}/discard"))
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(
        again.error(StatusCode::BAD_REQUEST),
        "Job was already discarded"
    );

    assert!(app.any_file_contains(PASSWORD).is_none());

    // After lock the account audit needs the password again.
    app.delete(&format!("/api/accounts/{USER}"), &[]).await.ok();
    app.post_json(
        "/api/mail/jobs/account",
        &json!({"account": USER, "days": 7}),
    )
    .await
    .assert_locked(USER);
}
