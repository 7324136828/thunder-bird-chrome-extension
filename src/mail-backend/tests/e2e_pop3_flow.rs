//! End-to-end: a POP3 account (compatibility mode) through the extension's
//! call sequence: unlock, folders = INBOX, list, read, attachment, eml,
//! IMAP-only operations → 400, retention/audit still work, send works
//! (without a Sent copy), the maildrop is never modified, lock → 401.

mod e2e_support;

use axum::http::{Method, StatusCode};
use e2e_support::*;
use mail_proto::testkit::{FakePop3Server, FakeSmtpServer};
use serde_json::json;

const IMAP_ONLY: &str =
    "This operation requires an IMAP account. POP3 accounts can only list and read the INBOX.";

fn pop3_server() -> FakePop3Server {
    FakePop3Server::builder()
        .credentials(USER, PASSWORD)
        .message_with_uid(
            plain_message(
                "Bob <bob@example.net>",
                "First pop message",
                "Hello over POP3.",
                3,
                "pop1",
            )
            .into_bytes(),
            "uidl-a",
        )
        .message_with_uid(attachment_message(2).into_bytes(), "uidl-b")
        .message_with_uid(
            html_message("http://127.0.0.1:9/pop.png", 1).into_bytes(),
            "uidl-c",
        )
        .start()
}

#[tokio::test]
async fn pop3_account_compatibility_flow() {
    let pop = pop3_server();
    let smtp = FakeSmtpServer::builder()
        .credentials(USER, PASSWORD)
        .start();
    let app = E2e::new();

    // A POP3 profile (the extension's profile form keeps the field).
    let response = app
        .put_json(
            "/api/mail/servers/pop",
            &json!({
                "incoming_server": "127.0.0.1", "incoming_port": pop.port(),
                "incoming_protocol": "NONE", "outgoing_server": "127.0.0.1",
                "outgoing_port": smtp.port(), "outgoing_protocol": "NONE",
                "email_address": USER, "display_name": "Pop User",
                "incoming_mail_protocol": "pop3",
            }),
        )
        .await;
    assert_eq!(response.status, StatusCode::CREATED, "{}", response.text());
    assert_eq!(response.json()["profile"]["incoming_mail_protocol"], "pop3");

    let wrong = app
        .unlock(json!({"email": USER, "password": "nope", "profile_key": "pop"}))
        .await;
    assert!(wrong.error(StatusCode::UNAUTHORIZED).is_string());

    let unlocked = app
        .unlock(json!({"email": USER, "password": PASSWORD, "profile_key": "pop"}))
        .await
        .ok();
    assert_eq!(unlocked["account"]["incoming_mail_protocol"], "pop3");
    assert_eq!(unlocked["account"]["display_name"], "Pop User");

    let folders = app
        .get("/api/mail/folders", &[("account", USER)])
        .await
        .ok();
    assert_eq!(
        folders,
        json!({"folders": [{"name": "INBOX", "delimiter": "", "flags": [],
                            "special": "inbox", "selectable": true}]})
    );

    let page = app
        .get(
            "/api/mail/messages",
            &[
                ("account", USER),
                ("folder", "INBOX"),
                ("offset", "0"),
                ("limit", "2"),
                ("query", ""),
            ],
        )
        .await
        .ok();
    assert_eq!(page["total"], 3);
    assert_eq!(page_uids(&page), [3, 2]);
    assert_eq!(keys(&page), ["total", "offset", "limit", "messages"]);
    for message in page["messages"].as_array().unwrap() {
        assert_eq!(message["seen"], false);
        assert_eq!(message["flags"], json!([]));
        assert!(message["uid_validity"].is_string(), "{message}");
    }
    let rest = app
        .get(
            "/api/mail/messages",
            &[
                ("account", USER),
                ("folder", "INBOX"),
                ("offset", "2"),
                ("limit", "2"),
                ("query", ""),
            ],
        )
        .await
        .ok();
    assert_eq!(page_uids(&rest), [1]);
    let searched = app
        .get(
            "/api/mail/messages",
            &[
                ("account", USER),
                ("folder", "INBOX"),
                ("offset", "0"),
                ("limit", "20"),
                ("query", "notes"),
            ],
        )
        .await
        .ok();
    assert_eq!(page_uids(&searched), [2], "{searched}");
    let domain = app
        .get(
            "/api/mail/messages",
            &[
                ("account", USER),
                ("folder", "INBOX"),
                ("offset", "0"),
                ("limit", "20"),
                ("query", ""),
                ("sender_domain", "example.net"),
            ],
        )
        .await
        .ok();
    assert_eq!(page_uids(&domain), [1], "{domain}");
    let read = app
        .get(
            "/api/mail/messages",
            &[
                ("account", USER),
                ("folder", "INBOX"),
                ("offset", "0"),
                ("limit", "20"),
                ("query", ""),
                ("read_status", "read"),
            ],
        )
        .await
        .ok();
    assert_eq!(read["total"], 0);
    let other = app
        .get(
            "/api/mail/messages",
            &[("account", USER), ("folder", "Sent")],
        )
        .await;
    assert!(other.error(StatusCode::BAD_GATEWAY).is_string());

    // Read (mark_seen is a no-op), attachment, eml, image registration.
    let message = app
        .get(
            "/api/mail/message",
            &[
                ("account", USER),
                ("folder", "INBOX"),
                ("uid", "2"),
                ("mark_seen", "true"),
            ],
        )
        .await
        .ok();
    assert_eq!(message["subject"], "Project notes");
    assert_eq!(message["seen"], false);
    assert_eq!(message["attachments"][0]["filename"], "report.pdf");
    let attachment = app
        .get(
            "/api/mail/message/attachment",
            &[
                ("account", USER),
                ("folder", "INBOX"),
                ("uid", "2"),
                ("index", "0"),
            ],
        )
        .await;
    assert_eq!(attachment.status, StatusCode::OK, "{}", attachment.text());
    assert_eq!(attachment.body, PDF_BYTES);
    let eml = app
        .get(
            "/api/mail/message/eml",
            &[("account", USER), ("folder", "INBOX"), ("uid", "1")],
        )
        .await;
    assert_eq!(eml.status, StatusCode::OK);
    assert_eq!(eml.body, pop.messages()[0]);
    let html = app
        .get(
            "/api/mail/message",
            &[
                ("account", USER),
                ("folder", "INBOX"),
                ("uid", "3"),
                ("mark_seen", "true"),
            ],
        )
        .await
        .ok();
    let validity = html["uid_validity"].as_str().unwrap().to_string();
    assert!(app
        .state
        .image_sources
        .sources(USER, "INBOX", 3)
        .is_some_and(|sources| sources.contains("http://127.0.0.1:9/pop.png")));
    let audit = app
        .get(
            "/api/mail/audit",
            &[("account", USER), ("folder", "INBOX"), ("uid", "1")],
        )
        .await
        .ok();
    assert_eq!(audit["subject"], "First pop message");

    // Retention overrides work with the synthetic UID validity.
    let retention = app
        .put_json(
            "/api/mail/message/retention",
            &json!({"account": USER, "folder": "INBOX", "uid": 3, "uid_validity": validity,
                    "category": "marketing"}),
        )
        .await
        .ok();
    assert_eq!(retention["category"], "marketing");
    assert_eq!(retention["category_source"], "manual");

    // IMAP-only operations → 400.
    let flags = app
        .post_json(
            "/api/mail/message/flags",
            &json!({"account": USER, "folder": "INBOX", "uid": 1, "seen": true}),
        )
        .await;
    assert_eq!(flags.error(StatusCode::BAD_REQUEST), IMAP_ONLY);
    let delete = app
        .delete(
            "/api/mail/message",
            &[
                ("account", USER),
                ("folder", "INBOX"),
                ("uid", "1"),
                ("trash", "Trash"),
            ],
        )
        .await;
    assert_eq!(delete.error(StatusCode::BAD_REQUEST), IMAP_ONLY);
    let bulk = app
        .post_json(
            "/api/mail/messages/delete",
            &json!({"account": USER, "folder": "INBOX", "uids": [1, 2], "trash": ""}),
        )
        .await;
    assert_eq!(bulk.error(StatusCode::BAD_REQUEST), IMAP_ONLY);
    let prepare = app
        .post_json(
            "/api/mail/trash/prepare",
            &json!({"account": USER, "folder": "Trash", "archive": true}),
        )
        .await;
    assert_eq!(prepare.error(StatusCode::BAD_REQUEST), IMAP_ONLY);
    let doctor = app
        .post_json(
            "/api/mail/jobs/account",
            &json!({"account": USER, "days": 7}),
        )
        .await;
    assert!(doctor.error(StatusCode::BAD_REQUEST).is_string());

    // Sending works; there is no server Sent folder.
    let sent = app
        .post_json(
            "/api/mail/send",
            &json!({"account": USER, "to": ["friend@example.net"], "cc": [], "bcc": [],
                    "subject": "From POP", "text": "Hi", "html": "",
                    "in_reply_to": "", "references": ""}),
        )
        .await
        .ok();
    assert_eq!(sent["sent"], true);
    assert_eq!(sent["from"], "Pop User <user@example.com>");
    assert_eq!(sent["sent_saved"], false);
    assert!(sent["warning"].is_string(), "{sent}");
    assert_eq!(smtp.messages().len(), 1);
    let files = app
        .multipart(
            Method::POST,
            "/api/mail/send/files",
            &[
                form_field(
                    "message",
                    &json!({"account": USER, "to": ["friend@example.net"], "subject": "File",
                            "text": "x", "uploads": [{"content_id": "", "disposition": "attachment"}]})
                    .to_string(),
                ),
                form_file("files", "a.txt", "text/plain", b"attached"),
            ],
        )
        .await
        .ok();
    assert_eq!(files["sent"], true);
    assert_eq!(smtp.messages().len(), 2);

    // The maildrop is read-only.
    let names = pop.command_names();
    assert!(!names.iter().any(|name| name == "DELE"), "{names:?}");
    assert_eq!(pop.messages().len(), 3);
    assert!(!pop.commands().iter().any(|line| line.contains(PASSWORD)));

    // Lock → 401.
    let locked = app.delete(&format!("/api/accounts/{USER}"), &[]).await.ok();
    assert_eq!(locked, json!({"locked": USER}));
    app.get("/api/mail/folders", &[("account", USER)])
        .await
        .assert_locked(USER);
    app.get(
        "/api/mail/messages",
        &[("account", USER), ("folder", "INBOX")],
    )
    .await
    .assert_locked(USER);
    assert!(app.any_file_contains(PASSWORD).is_none());
}

/// The extension's connect form sends no `incoming_mail_protocol`; a POP3
/// unlock can also name it explicitly (MCP / API clients).
#[tokio::test]
async fn pop3_unlock_with_explicit_protocol_and_manual_servers() {
    let pop = pop3_server();
    let app = E2e::new();
    let unlocked = app
        .unlock(json!({
            "email": USER, "password": PASSWORD,
            "incoming_server": "127.0.0.1", "incoming_port": pop.port(),
            "incoming_protocol": "NONE", "outgoing_server": "127.0.0.1",
            "outgoing_port": 2525, "outgoing_protocol": "NONE",
            "incoming_mail_protocol": "pop3", "save_profile": true,
        }))
        .await
        .ok();
    assert_eq!(unlocked["account"]["incoming_mail_protocol"], "pop3");
    let servers = app.get("/api/mail/servers", &[]).await.ok();
    let saved = &servers["servers"]["user-example.com"];
    assert_eq!(saved["incoming_mail_protocol"], "pop3", "{servers}");
    assert_eq!(saved["incoming_port"], pop.port());
    let profile_text = std::fs::read_to_string(&app.state.mail_servers_path).unwrap();
    assert!(!profile_text.contains(PASSWORD));

    // Same server through IMAP fails to sign in (no silent protocol switch).
    // (One harness at a time: the settings override is process-serialized.)
    drop(app);
    let app2 = E2e::new();
    let imap = app2
        .unlock(json!({
            "email": USER, "password": PASSWORD,
            "incoming_server": "127.0.0.1", "incoming_port": pop.port(),
            "incoming_protocol": "NONE", "outgoing_server": "127.0.0.1",
        }))
        .await;
    assert!(imap.error(StatusCode::UNAUTHORIZED).is_string());
}
