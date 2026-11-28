//! End-to-end edge cases around the IMAP flow: stale identities, trash
//! operation lifetimes across re-unlock / discard, restart persistence, TLS
//! refusal (no plaintext fallback), Sent-copy creation and failures, SMTP
//! failures, and the error texts the extension shows.

mod e2e_support;

use axum::http::{Method, StatusCode};
use e2e_support::*;
use mail_proto::testkit::{Failure, FakeImapServer, FakeSmtpServer, TlsMode};
use serde_json::{json, Value};

const SENT_WARNING: &str = "Message sent, but a copy could not be saved in Sent. \
                            Do not resend the message; check your Sent folder or mail server settings.";

fn inbox_server() -> mail_proto::testkit::FakeImapBuilder {
    FakeImapServer::builder()
        .credentials(USER, PASSWORD)
        .uid_validity("INBOX", Some(1234))
        .message_with(
            "INBOX",
            fake_message(
                1,
                &plain_message("Bob <bob@example.net>", "One", "1", 3, "one"),
                3,
                &[],
            ),
        )
        .message_with("INBOX", fake_message(2, &attachment_message(2), 2, &[]))
}

fn unlock_body(imap_port: u16, smtp_port: u16) -> Value {
    json!({
        "email": USER, "password": PASSWORD, "incoming_server": "127.0.0.1",
        "incoming_port": imap_port, "incoming_protocol": "NONE",
        "outgoing_server": "127.0.0.1", "outgoing_port": smtp_port, "outgoing_protocol": "NONE",
    })
}

fn send_body() -> Value {
    json!({"account": USER, "to": ["friend@example.net"], "cc": [], "bcc": ["hidden@example.org"],
           "subject": "Edge", "text": "Body", "html": "", "in_reply_to": "", "references": ""})
}

#[tokio::test]
async fn stale_identities_and_missing_items_report_the_python_errors() {
    let imap = inbox_server().folder("Trash", &["\\Trash"]).start();
    let app = E2e::new();
    app.unlock(unlock_body(imap.port(), 2525)).await.ok();

    let stale = app
        .delete(
            "/api/mail/message",
            &[
                ("account", USER),
                ("folder", "INBOX"),
                ("uid", "1"),
                ("trash", "Trash"),
                ("uid_validity", "999"),
            ],
        )
        .await;
    assert_eq!(
        stale.error(StatusCode::CONFLICT),
        "The mailbox changed. Refresh the folder before deleting messages."
    );
    assert_eq!(imap.uids("INBOX"), [1, 2]);
    let invalid = app
        .delete(
            "/api/mail/message",
            &[
                ("account", USER),
                ("folder", "INBOX"),
                ("uid", "1"),
                ("uid_validity", "0"),
            ],
        )
        .await;
    assert_eq!(
        invalid.error(StatusCode::UNPROCESSABLE_ENTITY),
        "UID validity must be a positive 32-bit decimal number"
    );

    let missing = app
        .get(
            "/api/mail/message/attachment",
            &[
                ("account", USER),
                ("folder", "INBOX"),
                ("uid", "2"),
                ("index", "5"),
            ],
        )
        .await;
    assert_eq!(
        missing.error(StatusCode::BAD_GATEWAY),
        "Attachment 5 was not found on message UID 2"
    );
    let gone = app
        .get(
            "/api/mail/message",
            &[("account", USER), ("folder", "INBOX"), ("uid", "99")],
        )
        .await;
    assert_eq!(
        gone.error(StatusCode::BAD_GATEWAY),
        "The server returned no data for message UID 99"
    );
    let folder = app
        .get(
            "/api/mail/messages",
            &[("account", USER), ("folder", "Nope")],
        )
        .await;
    assert_eq!(
        folder.error(StatusCode::BAD_GATEWAY),
        "The server would not open folder 'Nope'"
    );
    let limit = app
        .get(
            "/api/mail/messages",
            &[("account", USER), ("folder", "INBOX"), ("limit", "0")],
        )
        .await;
    let issues = limit.error(StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(issues[0]["loc"], json!(["query", "limit"]));
    let classify = app
        .post_json(
            "/api/mail/message/classify",
            &json!({"account": USER, "folder": "INBOX", "uid": 1, "uid_validity": "999"}),
        )
        .await;
    assert!(classify.error(StatusCode::CONFLICT).is_string());
    let rule = app
        .post_json(
            "/api/mail/message/sender-rule",
            &json!({"account": USER, "folder": "INBOX", "uid": 1, "uid_validity": "999",
                    "category": "uncategorized"}),
        )
        .await;
    assert!(rule.error(StatusCode::CONFLICT).is_string());
}

#[tokio::test]
async fn trash_operations_end_with_discard_and_with_a_new_unlock() {
    let imap = inbox_server()
        .folder("Trash", &["\\Trash"])
        .message_with(
            "Trash",
            fake_message(
                7,
                &plain_message("Old <old@example.net>", "Old", "x", 50, "old"),
                50,
                &[],
            ),
        )
        .start();
    let app = E2e::new();
    app.unlock(unlock_body(imap.port(), 2525)).await.ok();

    // Only the verified server Trash can be emptied.
    let inbox = app
        .post_json(
            "/api/mail/trash/prepare",
            &json!({"account": USER, "folder": "INBOX", "archive": false}),
        )
        .await;
    assert_eq!(
        inbox.error(StatusCode::BAD_GATEWAY),
        "Emptying is only available for the server's verified Trash folder. No messages were deleted."
    );

    // discard → the operation is gone.
    let prepared = app
        .post_json(
            "/api/mail/trash/prepare",
            &json!({"account": USER, "folder": "Trash", "archive": true}),
        )
        .await
        .ok();
    let id = prepared["operation_id"].as_str().unwrap().to_string();
    assert_eq!(walk(&app.trash_archive_dir()).len(), 1);
    let discarded = app
        .delete(&format!("/api/mail/trash/{id}"), &[("account", USER)])
        .await
        .ok();
    assert_eq!(discarded, json!({"discarded": id}));
    assert!(walk(&app.trash_archive_dir()).is_empty());
    let after = app
        .post_json(
            &format!("/api/mail/trash/{id}/empty"),
            &json!({"account": USER}),
        )
        .await;
    assert_eq!(
        after.error(StatusCode::NOT_FOUND),
        "This Trash operation has expired or is unavailable. Prepare it again."
    );

    // An operation belongs to one unlock: unlocking again (new session)
    // invalidates it.
    let prepared = app
        .post_json(
            "/api/mail/trash/prepare",
            &json!({"account": USER, "folder": "Trash", "archive": false}),
        )
        .await
        .ok();
    assert_eq!(prepared["filename"], Value::Null);
    let id = prepared["operation_id"].as_str().unwrap().to_string();
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    app.unlock(unlock_body(imap.port(), 2525)).await.ok();
    let stale = app
        .post_json(
            &format!("/api/mail/trash/{id}/empty"),
            &json!({"account": USER}),
        )
        .await;
    assert_eq!(
        stale.error(StatusCode::NOT_FOUND),
        "This Trash operation has expired or is unavailable. Prepare it again."
    );
    assert_eq!(imap.uids("Trash"), [7]);

    // Without an archive, emptying needs no download.
    let prepared = app
        .post_json(
            "/api/mail/trash/prepare",
            &json!({"account": USER, "folder": "Trash", "archive": false}),
        )
        .await
        .ok();
    let id = prepared["operation_id"].as_str().unwrap();
    let no_archive = app
        .get(
            &format!("/api/mail/trash/{id}/archive"),
            &[("account", USER)],
        )
        .await;
    assert_eq!(
        no_archive.error(StatusCode::BAD_GATEWAY),
        "No archive is available for this Trash operation."
    );
    let emptied = app
        .post_json(
            &format!("/api/mail/trash/{id}/empty"),
            &json!({"account": USER}),
        )
        .await
        .ok();
    assert_eq!(emptied, json!({"deleted": 1, "remaining": 0}));
    assert!(imap.uids("Trash").is_empty());
    assert_eq!(imap.uids("INBOX"), [1, 2]);
}

#[tokio::test]
async fn restart_forgets_sessions_but_keeps_retention_choices() {
    let imap = inbox_server().start();
    let mut app = E2e::new();
    app.unlock(unlock_body(imap.port(), 2525)).await.ok();
    app.put_json(
        "/api/mail/message/retention",
        &json!({"account": USER, "folder": "INBOX", "uid": 1, "uid_validity": "1234",
                "category": "transactional", "expiration_days": 90}),
    )
    .await
    .ok();

    app.restart();
    assert_eq!(
        app.get("/api/accounts", &[]).await.ok(),
        json!({"accounts": []})
    );
    app.get(
        "/api/mail/messages",
        &[("account", USER), ("folder", "INBOX")],
    )
    .await
    .assert_locked(USER);

    app.unlock(unlock_body(imap.port(), 2525)).await.ok();
    let page = app
        .get(
            "/api/mail/messages",
            &[("account", USER), ("folder", "INBOX"), ("limit", "10")],
        )
        .await
        .ok();
    let summary = &by_uid(&page)[&1];
    assert_eq!(summary["category"], "transactional");
    assert_eq!(summary["category_source"], "manual");
    assert_eq!(summary["expiration_days"], 90);
    assert_eq!(summary["expiration_source"], "manual");
}

#[tokio::test]
async fn tls_servers_with_untrusted_certificates_are_refused_without_fallback() {
    let app = E2e::new();
    // STARTTLS offered with a self-signed certificate: the unlock fails; the
    // password is never sent in clear text.
    let starttls = inbox_server().tls(TlsMode::StartTls).start();
    let mut body = unlock_body(starttls.port(), 2525);
    body["incoming_protocol"] = json!("STARTTLS");
    let refused = app.unlock(body).await;
    assert!(refused.error(StatusCode::UNAUTHORIZED).is_string());
    assert!(!starttls.log().iter().any(|command| command.name == "LOGIN"));
    // A plain server that does not offer STARTTLS is not used either.
    let plain = inbox_server().start();
    let mut body = unlock_body(plain.port(), 2525);
    body["incoming_protocol"] = json!("STARTTLS");
    let refused = app.unlock(body).await;
    assert!(refused.error(StatusCode::UNAUTHORIZED).is_string());
    assert!(!plain.log().iter().any(|command| command.name == "LOGIN"));
    // Implicit TLS with an untrusted certificate.
    let implicit = inbox_server().tls(TlsMode::Implicit).start();
    let mut body = unlock_body(implicit.port(), 2525);
    body["incoming_protocol"] = json!("SSL/TLS");
    let refused = app.unlock(body).await;
    assert!(refused.error(StatusCode::UNAUTHORIZED).is_string());
    assert!(app.state.sessions.list().is_empty());
}

#[tokio::test]
async fn sent_copy_is_created_when_missing_and_failures_are_warnings() {
    // No Sent folder: "Sent" is created and the copy appended (with Bcc).
    let imap = inbox_server().start();
    let smtp = FakeSmtpServer::builder()
        .credentials(USER, PASSWORD)
        .start();
    let app = E2e::new();
    app.unlock(unlock_body(imap.port(), smtp.port())).await.ok();
    let sent = app.post_json("/api/mail/send", &send_body()).await.ok();
    assert_eq!(sent["sent_saved"], true, "{sent}");
    assert_eq!(sent["sent_folder"], "Sent");
    let folder = imap.folder("Sent").expect("Sent created");
    assert_eq!(folder.messages.len(), 1);
    let copy = &folder.messages[0].raw;
    assert!(
        contains(copy, b"hidden@example.org"),
        "Bcc kept in the private copy"
    );
    assert!(!contains(&smtp.messages()[0].data, b"hidden@example.org"));

    // Sending the same Message-ID again is not duplicated... (a new send has
    // a new Message-ID, so a second copy is expected).
    app.post_json("/api/mail/send", &send_body()).await.ok();
    assert_eq!(imap.folder("Sent").unwrap().messages.len(), 2);

    // APPEND refused: delivered, warning, no resend invitation.
    imap.fail_next("APPEND", Failure::no());
    let sent = app.post_json("/api/mail/send", &send_body()).await.ok();
    assert_eq!(sent["sent"], true);
    assert_eq!(sent["sent_saved"], false);
    assert_eq!(sent["sent_folder"], "Sent");
    assert_eq!(sent["warning"], SENT_WARNING);
    assert_eq!(
        keys(&sent),
        [
            "sent",
            "message_id",
            "from",
            "sent_saved",
            "sent_folder",
            "warning"
        ]
    );
    assert_eq!(smtp.messages().len(), 3);
}

#[tokio::test]
async fn smtp_failures_are_502_with_the_python_texts() {
    let imap = inbox_server().start();
    let app = E2e::new();

    let failing = FakeSmtpServer::builder()
        .credentials(USER, PASSWORD)
        .fail_auth(true)
        .start();
    app.unlock(unlock_body(imap.port(), failing.port()))
        .await
        .ok();
    let response = app.post_json("/api/mail/send", &send_body()).await;
    assert_eq!(
        response.error(StatusCode::BAD_GATEWAY),
        "SMTP sign-in failed. Check the password or use an app password."
    );
    assert!(!response.text().contains(PASSWORD));

    let rejecting = FakeSmtpServer::builder()
        .credentials(USER, PASSWORD)
        .reject_recipient("hidden@example.org")
        .start();
    app.unlock(unlock_body(imap.port(), rejecting.port()))
        .await
        .ok();
    let response = app.post_json("/api/mail/send", &send_body()).await;
    assert_eq!(
        response.error(StatusCode::BAD_GATEWAY),
        "Some recipients were rejected. Other recipients may already have received the message."
    );

    // Nothing listening.
    let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = closed.local_addr().unwrap().port();
    drop(closed);
    app.unlock(unlock_body(imap.port(), port)).await.ok();
    let response = app.post_json("/api/mail/send", &send_body()).await;
    assert_eq!(
        response.error(StatusCode::BAD_GATEWAY),
        "Could not connect securely to the outgoing mail server."
    );
}

#[tokio::test]
async fn send_validation_errors_match_the_extension_contract() {
    let imap = inbox_server().start();
    let smtp = FakeSmtpServer::builder()
        .credentials(USER, PASSWORD)
        .start();
    let app = E2e::new();
    app.unlock(unlock_body(imap.port(), smtp.port())).await.ok();

    let mut body = send_body();
    body["uploads"] = json!([{"content_id": "", "disposition": "attachment"}]);
    let response = app.post_json("/api/mail/send", &body).await;
    assert_eq!(
        response.error(StatusCode::UNPROCESSABLE_ENTITY),
        "Use the attachment upload endpoint for messages with files"
    );

    let message = json!({"account": USER, "to": ["friend@example.net"], "subject": "x",
                         "text": "y", "html": "<p>no image</p>",
                         "uploads": [{"content_id": "logo", "disposition": "inline"}]});
    let response = app
        .multipart(
            Method::POST,
            "/api/mail/send/files",
            &[
                form_field("message", &message.to_string()),
                form_file("files", "logo.png", "image/png", &png()),
            ],
        )
        .await;
    assert_eq!(
        response.error(StatusCode::UNPROCESSABLE_ENTITY),
        "Every inline image must have a matching cid reference in the HTML message"
    );
    let message = json!({"account": USER, "to": ["friend@example.net"], "subject": "x",
                         "text": "y", "html": "<img src=\"cid:logo\">",
                         "uploads": [{"content_id": "logo", "disposition": "inline"}]});
    let response = app
        .multipart(
            Method::POST,
            "/api/mail/send/files",
            &[
                form_field("message", &message.to_string()),
                form_file("files", "logo.png", "image/png", b"not an image"),
            ],
        )
        .await;
    assert_eq!(
        response.error(StatusCode::UNPROCESSABLE_ENTITY),
        "Inline images must be valid PNG, JPEG, GIF, WebP, or BMP images"
    );
    let bad_recipient = app
        .post_json(
            "/api/mail/send",
            &json!({"account": USER, "to": ["not an address"], "subject": "x"}),
        )
        .await;
    let issues = bad_recipient.error(StatusCode::UNPROCESSABLE_ENTITY);
    assert!(issues.is_array(), "{issues}");
    assert!(smtp.messages().is_empty());
}

#[tokio::test]
async fn deleting_inside_trash_expunges_and_bulk_uids_are_deduplicated() {
    let imap = inbox_server()
        .folder("Trash", &[r"\Trash"])
        .message_with(
            "Trash",
            fake_message(
                4,
                &plain_message("Old <old@example.net>", "Old", "x", 9, "o4"),
                9,
                &[],
            ),
        )
        .start();
    let app = E2e::new();
    app.unlock(unlock_body(imap.port(), 2525)).await.ok();

    let deleted = app
        .delete(
            "/api/mail/message",
            &[
                ("account", USER),
                ("folder", "Trash"),
                ("uid", "4"),
                ("trash", "Trash"),
            ],
        )
        .await
        .ok();
    assert_eq!(deleted, json!({"deleted": 4}));
    assert!(imap.uids("Trash").is_empty());
    let names = imap.command_names();
    assert!(names.iter().any(|name| name == "UID EXPUNGE"), "{names:?}");
    assert!(!names.iter().any(|name| name == "EXPUNGE"), "{names:?}");

    let deleted = app
        .post_json(
            "/api/mail/messages/delete",
            &json!({"account": USER, "folder": "INBOX", "uids": [2, 2, 1], "trash": "Trash"}),
        )
        .await
        .ok();
    assert_eq!(deleted, json!({"deleted": [2, 1]}));
    assert_eq!(imap.uids("Trash").len(), 2);
    let strict = app
        .post_json(
            "/api/mail/messages/delete",
            &json!({"account": USER, "folder": "INBOX", "uids": [1], "uid_validity": 1234}),
        )
        .await;
    let issues = strict.error(StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(
        issues[0]["loc"],
        json!(["body", "uid_validity"]),
        "{issues}"
    );
}

#[tokio::test]
async fn two_accounts_are_isolated_and_locking_one_keeps_the_other() {
    const OTHER: &str = "second@example.org";
    const OTHER_PASSWORD: &str = "Second-Pass-5521";
    let first = inbox_server().folder("Trash", &[r"\Trash"]).start();
    let second = FakeImapServer::builder()
        .credentials(OTHER, OTHER_PASSWORD)
        .folder("Trash", &[r"\Trash"])
        .message_with(
            "INBOX",
            fake_message(9, &html_message("http://127.0.0.1:9/x.png", 1), 1, &[]),
        )
        .start();
    let app = E2e::new();
    app.unlock(unlock_body(first.port(), 2525)).await.ok();
    let mut body = unlock_body(second.port(), 2525);
    body["email"] = json!(OTHER);
    body["password"] = json!(OTHER_PASSWORD);
    app.unlock(body).await.ok();

    let accounts = app.get("/api/accounts", &[]).await.ok();
    let emails: Vec<&str> = accounts["accounts"]
        .as_array()
        .unwrap()
        .iter()
        .map(|account| account["email"].as_str().unwrap())
        .collect();
    assert_eq!(emails, [USER, OTHER]);

    app.get(
        "/api/mail/message",
        &[
            ("account", OTHER),
            ("folder", "INBOX"),
            ("uid", "9"),
            ("mark_seen", "false"),
        ],
    )
    .await
    .ok();
    let prepared = app
        .post_json(
            "/api/mail/trash/prepare",
            &json!({"account": OTHER, "folder": "Trash", "archive": false}),
        )
        .await
        .ok();
    let id = prepared["operation_id"].as_str().unwrap().to_string();
    // Another account cannot use (or even see) that operation.
    let foreign = app
        .post_json(
            &format!("/api/mail/trash/{id}/empty"),
            &json!({"account": USER}),
        )
        .await;
    assert_eq!(foreign.status, StatusCode::NOT_FOUND, "{}", foreign.text());

    app.delete(&format!("/api/accounts/{USER}"), &[]).await.ok();
    let accounts = app.get("/api/accounts", &[]).await.ok();
    assert_eq!(accounts["accounts"].as_array().unwrap().len(), 1);
    assert_eq!(accounts["accounts"][0]["email"], OTHER);
    assert!(app.state.image_sources.sources(OTHER, "INBOX", 9).is_some());
    let emptied = app
        .post_json(
            &format!("/api/mail/trash/{id}/empty"),
            &json!({"account": OTHER}),
        )
        .await
        .ok();
    assert_eq!(emptied, json!({"deleted": 0, "remaining": 0}));
    app.get("/api/mail/folders", &[("account", OTHER)])
        .await
        .ok();
    app.get("/api/mail/folders", &[("account", USER)])
        .await
        .assert_locked(USER);
}
