//! Security audit: password lifetime. The mailbox password must live only in
//! the in-memory session store: never in a response, a file under the data /
//! settings folders, a doctor job record or log, and never after a restart.

mod common;
mod mail_support;

use std::path::Path;
use std::time::{Duration, Instant};

use axum::http::StatusCode;
use mail_support::{server, Harness, PASSWORD, USER};
use serde_json::json;

const MESSAGE: &str = "From: Sender <sender@example.com>\r\nTo: user@example.com\r\n\
Subject: Audit\r\nDate: Mon, 13 Oct 2026 09:59:40 +0000\r\nMessage-ID: <audit@example.com>\r\n\
\r\nHello.\r\n";

/// Every file below `root` whose bytes contain `needle` (UTF-8 or UTF-16LE).
fn files_containing(root: &Path, needle: &str) -> Vec<String> {
    let utf16: Vec<u8> = needle.encode_utf16().flat_map(u16::to_le_bytes).collect();
    let mut hits = Vec::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        let Ok(entries) = std::fs::read_dir(&directory) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                pending.push(path);
            } else if let Ok(bytes) = std::fs::read(&path) {
                let contains = |pattern: &[u8]| bytes.windows(pattern.len()).any(|w| w == pattern);
                if contains(needle.as_bytes()) || contains(&utf16) {
                    hits.push(path.display().to_string());
                }
            }
        }
    }
    hits
}

#[tokio::test]
async fn password_never_reaches_disk_responses_or_a_restarted_backend() {
    let imap = server()
        .uid_validity("INBOX", Some(7))
        .message_with("INBOX", mail_support::message(1, MESSAGE))
        .start();
    let h = Harness::new();

    // A failed unlock does not echo the attempted password.
    let wrong = h
        .post_json(
            "/api/accounts/unlock",
            &json!({
                "email": USER, "password": "Wrong-Audit-Pass-9",
                "incoming_server": "127.0.0.1", "incoming_port": imap.port(),
                "incoming_protocol": "none",
            }),
        )
        .await;
    assert_eq!(wrong.status, StatusCode::UNAUTHORIZED, "{}", wrong.text());
    assert!(
        !wrong.text().contains("Wrong-Audit-Pass-9"),
        "{}",
        wrong.text()
    );

    let unlocked = h
        .post_json(
            "/api/accounts/unlock",
            &json!({
                "email": USER, "password": PASSWORD, "display_name": "Audit User",
                "incoming_server": "127.0.0.1", "incoming_port": imap.port(),
                "incoming_protocol": "none", "outgoing_server": "127.0.0.1",
                "outgoing_port": 1, "outgoing_protocol": "none", "save_profile": true,
            }),
        )
        .await;
    assert_eq!(unlocked.status, StatusCode::OK, "{}", unlocked.text());
    let mut transcript = vec![unlocked.text()];
    for (path, params) in [
        ("/api/accounts", vec![]),
        ("/api/mail/servers", vec![]),
        ("/api/settings", vec![]),
        ("/api/mail/folders", vec![("account", USER)]),
        ("/api/mail/messages", vec![("account", USER)]),
        (
            "/api/mail/message",
            vec![("account", USER), ("uid", "1"), ("mark_seen", "false")],
        ),
        ("/api/mail/signature", vec![("account", USER)]),
    ] {
        let response = h.get(path, &params).await;
        transcript.push(response.text());
    }

    // An Inbox Doctor audit of the unlocked account (worker thread, SQLite
    // job record, job log, report files).
    let job = h
        .post_json(
            "/api/mail/jobs/account",
            &json!({"account": USER, "days": 30}),
        )
        .await;
    assert_eq!(job.status, StatusCode::CREATED, "{}", job.text());
    let id = job.json()["id"].as_str().unwrap().to_string();
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let status = h.get(&format!("/api/jobs/{id}"), &[]).await;
        transcript.push(status.text());
        let state = status.json()["status"].as_str().unwrap_or("").to_string();
        if !matches!(state.as_str(), "queued" | "in_progress" | "pending") {
            assert!(
                matches!(state.as_str(), "completed" | "healthy"),
                "the doctor job did not download the mailbox: {}",
                status.text()
            );
            break;
        }
        assert!(Instant::now() < deadline, "doctor job did not finish");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    for text in &transcript {
        assert!(
            !text.contains(PASSWORD),
            "a response leaked the password: {text}"
        );
    }
    assert_eq!(
        files_containing(&h.root, PASSWORD),
        Vec::<String>::new(),
        "the password was written to disk"
    );

    // Restart: a new backend over the same files has no unlocked account.
    let restarted = h.restarted();
    let accounts = restarted.get("/api/accounts", &[]).await;
    assert_eq!(accounts.json()["accounts"], json!([]));
    let folders = restarted
        .get("/api/mail/folders", &[("account", USER)])
        .await;
    assert_eq!(folders.status, StatusCode::UNAUTHORIZED);

    // Lock: the session is gone and mail routes demand the password again.
    let locked = h.delete(&format!("/api/accounts/{USER}"), &[]).await;
    assert_eq!(locked.status, StatusCode::OK);
    assert!(h.state.sessions.get(USER).is_none());
    let after = h.get("/api/mail/folders", &[("account", USER)]).await;
    assert_eq!(after.status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        after.json()["detail"],
        json!({"error": "password_required", "email": USER})
    );
}

#[tokio::test]
async fn shutdown_locks_every_account() {
    let h = Harness::new();
    h.unlock(mail_support::offline_account(USER));
    h.unlock(mail_support::offline_account("other@example.com"));
    h.state.shutdown();
    assert!(h.state.sessions.list().is_empty());
    assert_eq!(
        h.get("/api/accounts", &[]).await.json()["accounts"],
        json!([])
    );
}
