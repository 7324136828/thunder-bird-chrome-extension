//! Mailbox routes of routes/mail.rs: port of `MailApiTests` (tests/test_mail.py)
//! and `MailPaginationApiTests` (tests/test_mail_pagination.py).
//!
//! The Python tests patched `imap_client.*` and asserted the call arguments.
//! Here the real mail-core IMAP code talks to `mail_proto::testkit`'s fake
//! IMAP server, so the same contracts are checked through what reaches the
//! server (command log, mailbox state) and the HTTP responses.

mod common;
mod mail_support;

use axum::http::StatusCode;
use mail_proto::testkit::{Failure, FakeImapServer};
use mail_support::*;
use serde_json::{json, Value};

const SAMPLE_EML: &[u8] = b"From: \"Bank Support <support@bank.example>\" <forged@evil.example>\r
To: <user@example.com>\r
Subject: Urgent: verify your account\r
Date: Mon, 13 Oct 2026 09:59:40 +0000\r
Message-ID: <deadbeef@evil.example>\r
MIME-Version: 1.0\r
Content-Type: multipart/mixed; boundary=\"BOUND\"\r
\r
--BOUND\r
Content-Type: text/plain; charset=\"utf-8\"\r
\r
Click http://185.10.20.30/login to verify.\r
\r
--BOUND\r
Content-Type: text/html; charset=\"utf-8\"\r
\r
<p>Hello <img src=\"https://images.example.org/logo.png\"></p>\r
\r
--BOUND\r
Content-Type: application/octet-stream; name=\"invoice.pdf.exe\"\r
Content-Disposition: attachment; filename=\"in\\\"voice.pdf.exe\"\r
Content-Transfer-Encoding: base64\r
\r
TVo=\r
\r
--BOUND\r
Content-Type: text/plain; name=\"notes.txt\"\r
Content-Disposition: attachment; filename=\"notes.txt\"\r
\r
plain notes\r
--BOUND--\r
";

fn simple(uid: u32, from: &str, subject: &str) -> Vec<u8> {
    let _ = uid;
    format!("From: {from}\r\nTo: user@example.com\r\nSubject: {subject}\r\n\r\nBody\r\n")
        .into_bytes()
}

fn numbered_server(count: u32) -> FakeImapServer {
    let mut builder = server();
    for uid in 1..=count {
        builder = builder.message_with(
            "INBOX",
            message(uid, simple(uid, "user@example.com", &uid.to_string())),
        );
    }
    builder.start()
}

fn search_lines(server: &FakeImapServer) -> Vec<String> {
    server
        .log()
        .into_iter()
        .filter(|command| command.name == "UID SEARCH")
        .map(|command| command.line)
        .collect()
}

// ---------------------------------------------------------------------------
// Authentication (test_mail_endpoints_require_unlocked_account, ...)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn mail_endpoints_require_unlocked_account() {
    let harness = Harness::new();
    for (path, params) in [
        ("/api/mail/folders", vec![("account", "a@b.c")]),
        (
            "/api/mail/messages",
            vec![("account", "a@b.c"), ("folder", "INBOX")],
        ),
        (
            "/api/mail/message",
            vec![("account", "a@b.c"), ("folder", "INBOX"), ("uid", "1")],
        ),
        (
            "/api/mail/message/eml",
            vec![("account", "a@b.c"), ("uid", "1")],
        ),
        (
            "/api/mail/message/attachment",
            vec![("account", "a@b.c"), ("uid", "1"), ("index", "0")],
        ),
    ] {
        let response = harness.get(path, &params).await;
        let detail = response.assert_json_error(StatusCode::UNAUTHORIZED);
        assert_eq!(
            detail,
            json!({"error": "password_required", "email": "a@b.c"}),
            "{path}"
        );
    }
    let response = harness
        .delete("/api/mail/message", &[("account", " A@B.C "), ("uid", "1")])
        .await;
    assert_eq!(
        response.assert_json_error(StatusCode::UNAUTHORIZED),
        json!({"error": "password_required", "email": "a@b.c"})
    );
    let response = harness
        .post_json(
            "/api/mail/message/flags",
            &json!({"account": "a@b.c", "folder": "INBOX", "uid": 1, "seen": true}),
        )
        .await;
    assert_eq!(
        response.assert_json_error(StatusCode::UNAUTHORIZED),
        json!({"error": "password_required", "email": "a@b.c"})
    );
}

#[tokio::test]
async fn locked_account_answers_401_before_other_query_validation() {
    // require_account is a dependency: it runs before the endpoint's own
    // query parameters are validated.
    let harness = Harness::new();
    let response = harness
        .get(
            "/api/mail/messages",
            &[("account", "a@b.c"), ("limit", "0"), ("offset", "-1")],
        )
        .await;
    response.assert_json_error(StatusCode::UNAUTHORIZED);
    let response = harness
        .get("/api/mail/message", &[("account", "a@b.c")])
        .await;
    response.assert_json_error(StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn missing_account_is_reported_with_the_other_query_issues() {
    let harness = Harness::new();
    let response = harness
        .get("/api/mail/message", &[("uid", "0"), ("mark_seen", "maybe")])
        .await;
    let detail = response.assert_json_error(StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(
        detail,
        json!([
            {"type": "missing", "loc": ["query", "account"], "msg": "Field required", "input": null},
            {"type": "greater_than_equal", "loc": ["query", "uid"],
             "msg": "Input should be greater than or equal to 1", "input": "0", "ctx": {"ge": 1}},
            {"type": "bool_parsing", "loc": ["query", "mark_seen"],
             "msg": "Input should be a valid boolean, unable to interpret input", "input": "maybe"},
        ])
    );
    let response = harness.get("/api/mail/folders", &[]).await;
    assert_eq!(
        response.assert_json_error(StatusCode::UNPROCESSABLE_ENTITY),
        json!([{"type": "missing", "loc": ["query", "account"], "msg": "Field required", "input": null}])
    );
}

#[tokio::test]
async fn unlocked_account_query_validation_matches_fastapi() {
    let harness = Harness::new();
    let account = harness.unlock(offline_account(USER));
    let long_folder = "x".repeat(501);
    let response = harness
        .get(
            "/api/mail/message/attachment",
            &[
                ("account", &account.email),
                ("folder", &long_folder),
                ("index", "-1"),
            ],
        )
        .await;
    let detail = response.assert_json_error(StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(detail[0]["type"], "string_too_long");
    assert_eq!(detail[0]["loc"], json!(["query", "folder"]));
    assert_eq!(
        detail[1],
        json!({"type": "missing", "loc": ["query", "uid"], "msg": "Field required", "input": null})
    );
    assert_eq!(detail[2]["type"], "greater_than_equal");
    assert_eq!(detail[2]["loc"], json!(["query", "index"]));
    assert_eq!(detail.as_array().unwrap().len(), 3);
}

// ---------------------------------------------------------------------------
// Folders, messages, message, eml, attachment
// ---------------------------------------------------------------------------

#[tokio::test]
async fn folders_messages_and_reader_use_cached_credentials() {
    let server = server()
        .folder("Trash", &["\\Trash"])
        .message_with("INBOX", message(7, simple(7, "x@example.org", "Hi")))
        .start();
    let harness = Harness::new();
    let account = harness.unlock(account(&server));

    let response = harness
        .get("/api/mail/folders", &[("account", &account.email)])
        .await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text());
    let folders = response.json()["folders"].clone();
    assert_eq!(folders[0]["name"], "INBOX");
    assert!(folders
        .as_array()
        .unwrap()
        .iter()
        .any(|folder| folder["name"] == "Trash"));

    let response = harness
        .get(
            "/api/mail/messages",
            &[
                ("account", &account.email),
                ("folder", "INBOX"),
                ("limit", "10"),
            ],
        )
        .await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text());
    let page = response.json();
    assert_eq!(page["messages"][0]["uid"], 7);
    assert_eq!(page["limit"], 10);
    assert_eq!(page["total"], 1);
}

#[tokio::test]
async fn reader_returns_message_view_marks_seen_and_registers_image_sources() {
    let server = server()
        .message_with("INBOX", message(7, SAMPLE_EML.to_vec()))
        .start();
    let harness = Harness::new();
    let account = harness.unlock(account(&server));

    let response = harness
        .get(
            "/api/mail/message",
            &[
                ("account", &account.email),
                ("uid", "7"),
                ("mark_seen", "false"),
            ],
        )
        .await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text());
    let view = response.json();
    assert_eq!(view["uid"], 7);
    assert_eq!(view["folder"], "INBOX");
    assert_eq!(view["subject"], "Urgent: verify your account");
    assert_eq!(view["seen"], false);
    assert!(view["html_body"]
        .as_str()
        .unwrap()
        .contains("images.example.org"));
    for key in ["category", "expiration_days", "expires_at", "uid_validity"] {
        assert!(view.get(key).is_some(), "{key} missing");
    }
    assert!(!server
        .flags("INBOX", 7)
        .unwrap()
        .iter()
        .any(|f| f == "\\Seen"));
    // The route registers the rendered HTML for the image proxy. (The
    // registry itself is ported separately; once it is, the URL appears.)
    let _ = harness
        .state
        .image_sources
        .sources(&account.email, "INBOX", 7);

    let response = harness
        .get(
            "/api/mail/message",
            &[("account", &account.email), ("uid", "7")],
        )
        .await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text());
    assert_eq!(response.json()["seen"], true);
    assert!(server
        .flags("INBOX", 7)
        .unwrap()
        .iter()
        .any(|f| f == "\\Seen"));
}

#[tokio::test]
async fn reader_registers_image_sources_for_the_proxy() {
    let server = server()
        .message_with("INBOX", message(7, SAMPLE_EML.to_vec()))
        .start();
    let harness = Harness::new();
    let account = harness.unlock(account(&server));
    let response = harness
        .get(
            "/api/mail/message",
            &[("account", &account.email), ("uid", "7")],
        )
        .await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text());
    let sources = harness
        .state
        .image_sources
        .sources(&account.email, "INBOX", 7)
        .expect("message registered");
    assert!(sources.contains("https://images.example.org/logo.png"));
}

#[tokio::test]
async fn eml_download_returns_raw_bytes_with_attachment_disposition() {
    let server = server()
        .message_with("INBOX", message(7, SAMPLE_EML.to_vec()))
        .start();
    let harness = Harness::new();
    let account = harness.unlock(account(&server));
    let response = harness
        .get(
            "/api/mail/message/eml",
            &[("account", &account.email), ("uid", "7")],
        )
        .await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text());
    assert_eq!(response.header("content-type"), Some("message/rfc822"));
    assert_eq!(
        response.header("content-disposition"),
        Some("attachment; filename=\"message-7.eml\"")
    );
    assert_download_hardening(&response);
    assert_eq!(response.body, server.message("INBOX", 7).unwrap().raw);
}

/// Downloads carry nosniff / no-store / a sandboxing CSP (hardening beyond
/// Python, see `routes::mail::download_response`).
fn assert_download_hardening(response: &common::Resp) {
    assert_eq!(response.header("x-content-type-options"), Some("nosniff"));
    assert_eq!(response.header("cache-control"), Some("no-store"));
    assert_eq!(
        response.header("content-security-policy"),
        Some("default-src 'none'; sandbox")
    );
}

#[tokio::test]
async fn attachment_download_sanitizes_filename_and_keeps_content_type() {
    let server = server()
        .message_with("INBOX", message(7, SAMPLE_EML.to_vec()))
        .start();
    let harness = Harness::new();
    let account = harness.unlock(account(&server));
    let response = harness
        .get(
            "/api/mail/message/attachment",
            &[("account", &account.email), ("uid", "7"), ("index", "0")],
        )
        .await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text());
    assert_eq!(
        response.header("content-type"),
        Some("application/octet-stream")
    );
    let disposition = response.header("content-disposition").unwrap();
    assert!(
        disposition.starts_with("attachment; filename=\""),
        "{disposition}"
    );
    assert!(!disposition["attachment; filename=\"".len()..disposition.len() - 1].contains('"'));
    assert_eq!(response.body, b"MZ");
    assert_download_hardening(&response);

    let response = harness
        .get(
            "/api/mail/message/attachment",
            &[("account", &account.email), ("uid", "7"), ("index", "1")],
        )
        .await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text());
    // Starlette adds the default charset to text/* media types.
    assert_eq!(
        response.header("content-type"),
        Some("text/plain; charset=utf-8")
    );
    assert_eq!(
        response.header("content-disposition"),
        Some("attachment; filename=\"notes.txt\"")
    );

    let response = harness
        .get(
            "/api/mail/message/attachment",
            &[("account", &account.email), ("uid", "7"), ("index", "5")],
        )
        .await;
    assert_eq!(
        response.assert_json_error(StatusCode::BAD_GATEWAY),
        json!("Attachment 5 was not found on message UID 7")
    );
}

#[tokio::test]
async fn missing_message_and_out_of_range_uid_are_upstream_errors() {
    let server = server().start();
    let harness = Harness::new();
    let account = harness.unlock(account(&server));
    let response = harness
        .get(
            "/api/mail/message",
            &[("account", &account.email), ("uid", "4294967296")],
        )
        .await;
    assert_eq!(
        response.assert_json_error(StatusCode::BAD_GATEWAY),
        json!("The server returned no data for message UID 4294967296")
    );
    let response = harness
        .get(
            "/api/mail/message/eml",
            &[("account", &account.email), ("uid", "9")],
        )
        .await;
    response.assert_json_error(StatusCode::BAD_GATEWAY);
}

// ---------------------------------------------------------------------------
// Flags
// ---------------------------------------------------------------------------

#[tokio::test]
async fn flags_update_returns_server_flags() {
    let server = server()
        .message_with("INBOX", message(7, simple(7, "x@example.org", "Hi")))
        .start();
    let harness = Harness::new();
    let account = harness.unlock(account(&server));
    let response = harness
        .post_json(
            "/api/mail/message/flags",
            &json!({"account": account.email, "folder": "INBOX", "uid": 7, "seen": true, "flagged": true}),
        )
        .await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text());
    let body = response.json();
    assert_eq!(body["uid"], 7);
    assert_eq!(body["seen"], true);
    assert_eq!(body["flagged"], true);
    let flags = server.flags("INBOX", 7).unwrap();
    assert!(flags.iter().any(|f| f == "\\Seen") && flags.iter().any(|f| f == "\\Flagged"));

    let response = harness
        .post_json(
            "/api/mail/message/flags",
            &json!({"account": account.email, "folder": "INBOX", "uid": 7, "seen": false}),
        )
        .await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text());
    assert_eq!(response.json()["seen"], false);
    assert_eq!(response.json()["flagged"], true);
}

#[tokio::test]
async fn flags_body_is_validated_before_the_account_is_required() {
    // Body models validate before the route runs; the 401 comes afterwards.
    let harness = Harness::new();
    let response = harness
        .post_json(
            "/api/mail/message/flags",
            &json!({"account": "a@b.c", "folder": "", "uid": 0}),
        )
        .await;
    let detail = response.assert_json_error(StatusCode::UNPROCESSABLE_ENTITY);
    let locs: Vec<Value> = detail
        .as_array()
        .unwrap()
        .iter()
        .map(|issue| issue["loc"].clone())
        .collect();
    assert_eq!(
        locs,
        vec![json!(["body", "folder"]), json!(["body", "uid"])]
    );
    let response = harness
        .post_json("/api/mail/message/flags", &Value::Null)
        .await;
    assert_eq!(
        response.assert_json_error(StatusCode::UNPROCESSABLE_ENTITY),
        json!([{"type": "missing", "loc": ["body"], "msg": "Field required", "input": null}])
    );
}

#[tokio::test]
async fn pop3_accounts_cannot_change_flags_or_delete() {
    let harness = Harness::new();
    let mut pop3 = offline_account(USER);
    pop3.incoming_mail_protocol = "pop3".into();
    let account = harness.unlock(pop3);
    let response = harness
        .post_json(
            "/api/mail/message/flags",
            &json!({"account": account.email, "folder": "INBOX", "uid": 1, "seen": true}),
        )
        .await;
    response.assert_json_error(StatusCode::BAD_REQUEST);
    let response = harness
        .delete(
            "/api/mail/message",
            &[("account", &account.email), ("uid", "1")],
        )
        .await;
    response.assert_json_error(StatusCode::BAD_REQUEST);
    let response = harness
        .post_json(
            "/api/mail/messages/delete",
            &json!({"account": account.email, "folder": "INBOX", "uids": [1]}),
        )
        .await;
    response.assert_json_error(StatusCode::BAD_REQUEST);
}

// ---------------------------------------------------------------------------
// Bulk delete (MailApiTests.test_bulk_delete_*)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn bulk_delete_requires_unlocked_account() {
    let harness = Harness::new();
    let response = harness
        .post_json(
            "/api/mail/messages/delete",
            &json!({"account": "a@b.c", "folder": "INBOX", "uids": [7, 11], "trash": "Trash"}),
        )
        .await;
    assert_eq!(
        response.assert_json_error(StatusCode::UNAUTHORIZED),
        json!({"error": "password_required", "email": "a@b.c"})
    );
}

#[tokio::test]
async fn bulk_delete_passes_deduplicated_uids_and_returns_server_success() {
    let server = server()
        .folder("Deleted Items", &["\\Trash"])
        .message_with("INBOX", message(7, simple(7, "x@example.org", "a")))
        .message_with("INBOX", message(9, simple(9, "x@example.org", "keep")))
        .message_with("INBOX", message(11, simple(11, "x@example.org", "b")))
        .start();
    let harness = Harness::new();
    let account = harness.unlock(account(&server));
    let response = harness
        .post_json(
            "/api/mail/messages/delete",
            &json!({"account": account.email, "folder": "INBOX", "uids": [7, 11, 7],
                    "trash": "Deleted Items"}),
        )
        .await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text());
    assert_eq!(response.json(), json!({"deleted": [7, 11]}));
    assert_eq!(server.uids("INBOX"), vec![9]);
    assert_eq!(server.uids("Deleted Items").len(), 2);
    let moves: Vec<String> = server
        .log()
        .into_iter()
        .filter(|command| command.name == "UID MOVE")
        .map(|command| command.line)
        .collect();
    assert_eq!(moves.len(), 1);
    assert!(moves[0].contains("7,11"), "{moves:?}");
}

#[tokio::test]
async fn bulk_delete_supports_default_permanent_mode() {
    let server = server()
        .folder("Trash", &["\\Trash"])
        .message_with("Trash", message(7, simple(7, "x@example.org", "a")))
        .start();
    let harness = Harness::new();
    let account = harness.unlock(account(&server));
    let response = harness
        .post_json(
            "/api/mail/messages/delete",
            &json!({"account": account.email, "folder": "Trash", "uids": [7]}),
        )
        .await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text());
    assert_eq!(response.json(), json!({"deleted": [7]}));
    assert!(server.uids("Trash").is_empty());
}

#[tokio::test]
async fn bulk_delete_validates_uid_bounds_and_batch_size_before_server_operation() {
    let server = server().start();
    let harness = Harness::new();
    let account = harness.unlock(account(&server));
    let too_many: Vec<u32> = (1..=501).collect();
    for uids in [
        json!([]),
        json!([0]),
        json!([-1]),
        json!([true]),
        json!([1.5]),
        json!(["7"]),
        json!([4_294_967_296u64]),
        json!(too_many),
    ] {
        let response = harness
            .post_json(
                "/api/mail/messages/delete",
                &json!({"account": account.email, "folder": "INBOX", "uids": uids}),
            )
            .await;
        response.assert_json_error(StatusCode::UNPROCESSABLE_ENTITY);
    }
    assert_eq!(server.connection_count(), 0);
}

#[tokio::test]
async fn bulk_delete_accepts_maximum_batch() {
    let mut builder = server().folder("Trash", &["\\Trash"]);
    for uid in 1..=500u32 {
        builder = builder.message_with("INBOX", message(uid, simple(uid, "x@example.org", "m")));
    }
    let server = builder.start();
    let harness = Harness::new();
    let account = harness.unlock(account(&server));
    let uids: Vec<u32> = (1..=500).collect();
    let response = harness
        .post_json(
            "/api/mail/messages/delete",
            &json!({"account": account.email, "folder": "INBOX", "uids": uids, "trash": "Trash"}),
        )
        .await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text());
    assert_eq!(response.json(), json!({"deleted": uids}));
}

#[tokio::test]
async fn bulk_delete_server_failure_returns_error_without_success_payload() {
    let server = server()
        .capabilities(&["IMAP4rev1", "UIDPLUS"])
        .message_with("INBOX", message(7, simple(7, "x@example.org", "a")))
        .message_with("INBOX", message(11, simple(11, "x@example.org", "b")))
        .start();
    server.fail_next("UID EXPUNGE", Failure::No("rejected".into()));
    let harness = Harness::new();
    let account = harness.unlock(account(&server));
    let response = harness
        .post_json(
            "/api/mail/messages/delete",
            &json!({"account": account.email, "folder": "INBOX", "uids": [7, 11]}),
        )
        .await;
    assert_eq!(
        response.status,
        StatusCode::BAD_GATEWAY,
        "{}",
        response.text()
    );
    let body = response.json();
    assert_eq!(body.as_object().unwrap().len(), 1);
    assert!(body["detail"].is_string());
}

#[tokio::test]
async fn bulk_delete_without_safe_delete_support_is_refused() {
    let server = server()
        .capabilities(&["IMAP4rev1"])
        .message_with("INBOX", message(7, simple(7, "x@example.org", "a")))
        .start();
    let harness = Harness::new();
    let account = harness.unlock(account(&server));
    let response = harness
        .post_json(
            "/api/mail/messages/delete",
            &json!({"account": account.email, "folder": "INBOX", "uids": [7]}),
        )
        .await;
    let detail = response.assert_json_error(StatusCode::BAD_GATEWAY);
    assert!(
        detail.as_str().unwrap().contains("MOVE or UIDPLUS"),
        "{detail}"
    );
    assert_eq!(server.uids("INBOX"), vec![7]);
}

// ---------------------------------------------------------------------------
// Single delete
// ---------------------------------------------------------------------------

#[tokio::test]
async fn single_delete_moves_to_trash_and_returns_uid() {
    let server = server()
        .folder("Trash", &["\\Trash"])
        .message_with("INBOX", message(7, simple(7, "x@example.org", "a")))
        .start();
    let harness = Harness::new();
    let account = harness.unlock(account(&server));
    let response = harness
        .delete(
            "/api/mail/message",
            &[
                ("account", &account.email),
                ("uid", "7"),
                ("trash", "Trash"),
            ],
        )
        .await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text());
    assert_eq!(response.json(), json!({"deleted": 7}));
    assert!(server.uids("INBOX").is_empty());
    assert_eq!(server.uids("Trash").len(), 1);
}

#[tokio::test]
async fn single_delete_validates_uid_validity() {
    let server = server().start();
    let harness = Harness::new();
    let account = harness.unlock(account(&server));
    for value in ["0", "-1", "abc", "4294967296", ""] {
        let response = harness
            .delete(
                "/api/mail/message",
                &[
                    ("account", &account.email),
                    ("uid", "7"),
                    ("uid_validity", value),
                ],
            )
            .await;
        assert_eq!(
            response.assert_json_error(StatusCode::UNPROCESSABLE_ENTITY),
            json!("UID validity must be a positive 32-bit decimal number"),
            "{value}"
        );
    }
    let response = harness
        .delete(
            "/api/mail/message",
            &[
                ("account", &account.email),
                ("uid", "7"),
                ("uid_validity", "12345678901"),
            ],
        )
        .await;
    let detail = response.assert_json_error(StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(detail[0]["type"], "string_too_long");
    assert_eq!(server.connection_count(), 0);
}

#[tokio::test]
async fn single_delete_with_stale_epoch_is_a_conflict() {
    let server = server()
        .uid_validity("INBOX", Some(5678))
        .message_with("INBOX", message(7, simple(7, "x@example.org", "a")))
        .start();
    let harness = Harness::new();
    let account = harness.unlock(account(&server));
    let response = harness
        .delete(
            "/api/mail/message",
            &[
                ("account", &account.email),
                ("uid", "7"),
                ("uid_validity", "1234"),
            ],
        )
        .await;
    response.assert_json_error(StatusCode::CONFLICT);
    assert_eq!(server.uids("INBOX"), vec![7]);

    let response = harness
        .delete(
            "/api/mail/message",
            &[("account", &account.email), ("uid", "4294967296")],
        )
        .await;
    assert_eq!(
        response.assert_json_error(StatusCode::BAD_GATEWAY),
        json!("Select between 1 and 500 valid message UIDs")
    );
}

// ---------------------------------------------------------------------------
// MailPaginationApiTests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn omitted_limit_uses_default_then_saved_preference() {
    let server = numbered_server(20);
    let harness = Harness::new();
    let account = harness.unlock(account(&server));
    let response = harness
        .get("/api/mail/messages", &[("account", &account.email)])
        .await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text());
    assert_eq!(response.json()["limit"], 5);
    assert_eq!(response.json()["messages"].as_array().unwrap().len(), 5);

    harness.write_preferences(17, None);
    let response = harness
        .get("/api/mail/messages", &[("account", &account.email)])
        .await;
    assert_eq!(response.json()["limit"], 17);
    assert_eq!(response.json()["messages"].as_array().unwrap().len(), 17);

    let response = harness
        .get(
            "/api/mail/messages",
            &[("account", &account.email), ("limit", "2")],
        )
        .await;
    assert_eq!(response.json()["limit"], 2);
    assert_eq!(
        response.json()["messages"]
            .as_array()
            .unwrap()
            .iter()
            .map(|message| message["uid"].as_u64().unwrap())
            .collect::<Vec<_>>(),
        vec![20, 19]
    );
}

#[tokio::test]
async fn unreadable_preferences_are_a_settings_error() {
    let server = numbered_server(1);
    let harness = Harness::new();
    let account = harness.unlock(account(&server));
    std::fs::write(harness.settings_path(), b"{not json").unwrap();
    let response = harness
        .get("/api/mail/messages", &[("account", &account.email)])
        .await;
    response.assert_json_error(StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(server.connection_count(), 0);
}

#[tokio::test]
async fn repeated_domain_query_parameters_are_normalized() {
    let server = numbered_server(3);
    let harness = Harness::new();
    let account = harness.unlock(account(&server));
    let response = harness
        .get(
            "/api/mail/messages",
            &[
                ("account", &account.email),
                ("sender_domain", "EXAMPLE.COM."),
                ("sender_domain", "other.test"),
                ("sender_domain", "example.com"),
                ("query", "  offers  "),
                ("offset", "10"),
                ("limit", "5"),
            ],
        )
        .await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text());
    let page = response.json();
    assert_eq!(page["offset"], 10);
    assert_eq!(page["limit"], 5);
    let searches = search_lines(&server);
    assert_eq!(searches.len(), 1, "{searches:?}");
    assert!(
        searches[0].ends_with(r#"TEXT "offers" OR FROM "example.com" FROM "other.test""#),
        "{searches:?}"
    );
}

#[tokio::test]
async fn invalid_domain_page_size_or_offset_never_reaches_mail_server() {
    let server = numbered_server(1);
    let harness = Harness::new();
    let account = harness.unlock(account(&server));
    for (name, value) in [
        ("sender_domain", "example.com\" ALL"),
        ("limit", "0"),
        ("limit", "201"),
        ("offset", "-1"),
    ] {
        let response = harness
            .get(
                "/api/mail/messages",
                &[("account", &account.email), (name, value)],
            )
            .await;
        response.assert_json_error(StatusCode::UNPROCESSABLE_ENTITY);
    }
    // normalize_sender_domains' ValueError is a string detail.
    let response = harness
        .get(
            "/api/mail/messages",
            &[
                ("account", &account.email),
                ("sender_domain", "user@example.com"),
            ],
        )
        .await;
    assert!(response
        .assert_json_error(StatusCode::UNPROCESSABLE_ENTITY)
        .is_string());
    assert_eq!(server.connection_count(), 0);
}

#[tokio::test]
async fn read_status_filters_are_forwarded_and_all_keeps_the_default() {
    let server = numbered_server(3);
    let harness = Harness::new();
    let account = harness.unlock(account(&server));
    for (read_status, criterion) in [("all", ""), ("unread", " UNSEEN"), ("read", " SEEN")] {
        server.clear_log();
        let response = harness
            .get(
                "/api/mail/messages",
                &[
                    ("account", &account.email),
                    ("read_status", read_status),
                    ("query", "offers"),
                    ("sender_domain", "EXAMPLE.COM"),
                    ("offset", "5"),
                ],
            )
            .await;
        assert_eq!(response.status, StatusCode::OK, "{}", response.text());
        assert_eq!(response.json()["limit"], 5);
        let searches = search_lines(&server);
        assert!(
            searches[0].ends_with(&format!(r#"TEXT "offers"{criterion} FROM "example.com""#)),
            "{read_status}: {searches:?}"
        );
    }
}

#[tokio::test]
async fn invalid_read_status_or_category_never_reaches_mail_server() {
    let server = numbered_server(1);
    let harness = Harness::new();
    let account = harness.unlock(account(&server));
    for read_status in ["", "READ", "seen", "unread ALL"] {
        let response = harness
            .get(
                "/api/mail/messages",
                &[("account", &account.email), ("read_status", read_status)],
            )
            .await;
        let detail = response.assert_json_error(StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(detail[0]["type"], "literal_error");
    }
    for category in ["", "Marketing", "other", "marketing,updates"] {
        let response = harness
            .get(
                "/api/mail/messages",
                &[("account", &account.email), ("category", category)],
            )
            .await;
        response.assert_json_error(StatusCode::UNPROCESSABLE_ENTITY);
    }
    assert_eq!(server.connection_count(), 0);
}

#[tokio::test]
async fn unicode_original_is_preserved_when_api_passes_normalized_domains() {
    let server = server()
        .message_with(
            "INBOX",
            message(
                1,
                "From: user@fa\u{00df}.de\r\nSubject: offers\r\n\r\nx\r\n"
                    .as_bytes()
                    .to_vec(),
            ),
        )
        .message_with(
            "INBOX",
            message(
                2,
                b"From: user@fass.de\r\nSubject: offers\r\n\r\nx\r\n".to_vec(),
            ),
        )
        .message_with(
            "INBOX",
            message(
                3,
                b"From: user@other.de\r\nSubject: hello\r\n\r\nx\r\n".to_vec(),
            ),
        )
        .start();
    let harness = Harness::new();
    let account = harness.unlock(account(&server));
    let response = harness
        .get(
            "/api/mail/messages",
            &[
                ("account", &account.email),
                ("sender_domain", "fa\u{00df}.de"),
                ("query", "offers"),
            ],
        )
        .await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text());
    let page = response.json();
    assert_eq!(page["total"], 2);
    let uids: Vec<u64> = page["messages"]
        .as_array()
        .unwrap()
        .iter()
        .map(|message| message["uid"].as_u64().unwrap())
        .collect();
    assert_eq!(uids, vec![2, 1]);
    // has_unicode_input keeps the server search to the text query only.
    assert_eq!(
        search_lines(&server),
        vec![r#"UID SEARCH TEXT "offers""#.to_string()]
    );
}
