//! End-to-end: the extension's complete IMAP call sequence against the
//! real router, fake IMAP + SMTP servers and a fake Ollama.
//!
//! save profile → unlock → accounts → folders → messages (pagination,
//! query, read status, sender domain, category, expired-only) → message
//! (mark_seen, image source registration) → eml / attachment → flags →
//! retention → classify → sender rules → send (JSON + multipart) → delete to
//! Trash → trash prepare(archive) → archive download → empty → lock (state
//! forgotten, then 401 everywhere).

mod e2e_support;

use std::collections::BTreeSet;

use axum::http::{Method, StatusCode};
use e2e_support::*;
use mail_core::classifier::scoped_ollama_url;
use mail_parser::{MessageParser, MimeHeaders};
use mail_proto::testkit::{FakeImapServer, FakeSmtpServer};
use serde_json::{json, Value};

const IMAGE_URL: &str = "http://127.0.0.1:9/banner.png";
const MODEL: &str = "llama3.2:latest";

struct Servers {
    imap: FakeImapServer,
    smtp: FakeSmtpServer,
}

/// INBOX (UIDVALIDITY 1234):
/// 1 verification, 400 days, seen · 2 attachment (alice@example.org), seen
/// 3 HTML newsletter, unseen · 4 bob@example.net "Lunch tomorrow?", unseen
/// 5 invoice, seen · 6 team@example.org status, unseen.
/// Trash: 2 old messages. Sent: empty.
fn servers() -> Servers {
    let imap = FakeImapServer::builder()
        .credentials(USER, PASSWORD)
        .folder("Sent", &["\\Sent"])
        .folder("Trash", &["\\Trash"])
        .uid_validity("INBOX", Some(1234))
        .message_with(
            "INBOX",
            fake_message(
                1,
                &plain_message(
                    "Accounts <no-reply@accounts.example.com>",
                    "Your verification code",
                    "Your code is 123456.",
                    400,
                    "verify",
                ),
                400,
                &["\\Seen"],
            ),
        )
        .message_with(
            "INBOX",
            fake_message(2, &attachment_message(10), 10, &["\\Seen"]),
        )
        .message_with(
            "INBOX",
            fake_message(3, &html_message(IMAGE_URL, 60), 60, &[]),
        )
        .message_with(
            "INBOX",
            fake_message(
                4,
                &plain_message(
                    "Bob <bob@example.net>",
                    "Lunch tomorrow?",
                    "Shall we meet at noon?",
                    2,
                    "lunch",
                ),
                2,
                &[],
            ),
        )
        .message_with(
            "INBOX",
            fake_message(
                5,
                &plain_message(
                    "Store <billing@store.example.com>",
                    "Invoice 2026-11",
                    "Your invoice is attached to your account.",
                    5,
                    "invoice",
                ),
                5,
                &["\\Seen"],
            ),
        )
        .message_with(
            "INBOX",
            fake_message(
                6,
                &plain_message(
                    "Team <team@example.org>",
                    "Weekly status update",
                    "All green.",
                    1,
                    "status",
                ),
                1,
                &[],
            ),
        )
        .message_with(
            "Trash",
            fake_message(
                1,
                &plain_message("Old <old@example.net>", "Old thing", "Bye.", 90, "old1"),
                90,
                &["\\Seen"],
            ),
        )
        .message_with(
            "Trash",
            fake_message(
                2,
                &plain_message("Old <old@example.net>", "Older thing", "Bye.", 95, "old2"),
                95,
                &["\\Seen"],
            ),
        )
        .start();
    let smtp = FakeSmtpServer::builder()
        .credentials(USER, PASSWORD)
        .start();
    Servers { imap, smtp }
}

fn profile(servers: &Servers) -> Value {
    json!({
        "incoming_server": "127.0.0.1",
        "incoming_port": servers.imap.port(),
        "incoming_protocol": "NONE",
        "outgoing_server": "127.0.0.1",
        "outgoing_port": servers.smtp.port(),
        "outgoing_protocol": "NONE",
        "email_address": USER,
        "display_name": "Example User",
    })
}

/// `api.messages(...)` with the frontend's parameter layout.
async fn messages(app: &E2e, extra: &[(&str, &str)]) -> Value {
    let mut params = vec![("account", USER), ("folder", "INBOX")];
    params.extend_from_slice(extra);
    app.get("/api/mail/messages", &params).await.ok()
}

async fn all_messages(app: &E2e) -> Value {
    messages(app, &[("offset", "0"), ("limit", "200"), ("query", "")]).await
}

#[tokio::test]
async fn imap_account_full_frontend_flow() {
    let servers = servers();
    let app = E2e::new();

    // -- health, settings, profiles ------------------------------------------
    let health = app.get("/api/health", &[]).await;
    assert_eq!(health.ok(), json!({"status": "ok"}));
    assert_eq!(health.header("access-control-allow-origin"), Some(ORIGIN));

    let settings = app.get("/api/settings", &[]).await.ok();
    assert_eq!(settings["messages_per_page"], 5, "{settings}");
    assert_eq!(settings["local_ai_model"], MODEL, "{settings}");
    // SettingsModal.save(): page size only.
    let saved = app
        .put_json("/api/settings", &json!({"messages_per_page": 2}))
        .await
        .ok();
    assert_eq!(saved["messages_per_page"], 2, "{saved}");

    let listed = app.get("/api/mail/servers", &[]).await.ok();
    assert_eq!(listed["servers"], json!({}));
    assert_eq!(listed["display_names"], json!({}));
    assert_eq!(keys(&listed), ["path", "servers", "display_names"]);

    let response = app
        .put_json("/api/mail/servers/Work%20Mail", &profile(&servers))
        .await;
    assert_eq!(response.status, StatusCode::CREATED, "{}", response.text());
    let created = response.json();
    assert_eq!(created["key"], "work-mail");
    assert_eq!(created["profile"]["incoming_port"], servers.imap.port());
    let listed = app.get("/api/mail/servers", &[]).await.ok();
    assert!(listed["servers"]["work-mail"].is_object(), "{listed}");

    // -- unlock --------------------------------------------------------------
    let wrong = app
        .unlock(json!({
            "email": USER, "password": "wrong-password", "profile_key": "work-mail",
            "display_name": "Example User", "save_profile": false,
        }))
        .await;
    let detail = wrong.error(StatusCode::UNAUTHORIZED);
    assert!(detail.is_string(), "{detail}");
    assert!(!wrong.text().contains("wrong-password"));
    assert!(app.state.sessions.list().is_empty());

    let unlocked = app
        .unlock(json!({
            "email": USER, "password": PASSWORD, "profile_key": "work-mail",
            "display_name": "Example User",
            "incoming_server": "127.0.0.1", "incoming_port": servers.imap.port(),
            "incoming_protocol": "NONE", "outgoing_server": "127.0.0.1",
            "outgoing_port": servers.smtp.port(), "outgoing_protocol": "NONE",
            "save_profile": false,
        }))
        .await;
    let account = unlocked.ok()["account"].clone();
    assert!(!unlocked.text().contains(PASSWORD));
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
    assert_eq!(account["email"], USER);
    assert_eq!(account["display_name"], "Example User");
    assert_eq!(account["incoming_mail_protocol"], "imap");

    let accounts = app.get("/api/accounts", &[]).await.ok();
    assert_eq!(accounts["accounts"].as_array().unwrap().len(), 1);
    assert_eq!(accounts["accounts"][0]["display_name"], "Example User");

    // -- folders -------------------------------------------------------------
    let folders = app
        .get("/api/mail/folders", &[("account", USER)])
        .await
        .ok();
    let folders = folders["folders"].as_array().unwrap().clone();
    let names: Vec<&str> = folders
        .iter()
        .map(|f| f["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["INBOX", "Sent", "Trash"], "{folders:?}");
    for folder in &folders {
        assert_eq!(
            keys(folder),
            ["name", "delimiter", "flags", "special", "selectable"]
        );
    }
    let specials: Vec<&str> = folders
        .iter()
        .map(|f| f["special"].as_str().unwrap())
        .collect();
    assert_eq!(specials, ["inbox", "sent", "trash"]);

    // -- messages: default page size from settings, pagination ----------------
    let default_page = messages(&app, &[]).await;
    assert_eq!(default_page["total"], 6);
    assert_eq!(default_page["limit"], 2);
    assert_eq!(page_uids(&default_page), [6, 5]);
    assert_eq!(
        keys(&default_page),
        ["total", "offset", "limit", "messages"]
    );
    let summary = &default_page["messages"][0];
    assert_eq!(
        keys(summary)[..11],
        [
            "uid",
            "flags",
            "seen",
            "flagged",
            "answered",
            "size",
            "internal_date",
            "subject",
            "from",
            "to",
            "date"
        ]
    );
    for key in [
        "category",
        "category_source",
        "expiration_days",
        "expires_at",
        "expired",
        "received_at",
        "uid_validity",
        "sender_rule",
    ] {
        assert!(summary.get(key).is_some(), "{key} missing from {summary}");
    }
    assert_eq!(summary["uid_validity"], "1234");

    let mut paged = Vec::new();
    for offset in ["0", "2", "4", "6"] {
        let page = messages(&app, &[("offset", offset), ("limit", "2"), ("query", "")]).await;
        assert_eq!(page["total"], 6);
        assert_eq!(page["offset"], offset.parse::<u64>().unwrap());
        paged.extend(page_uids(&page));
    }
    assert_eq!(paged, [6, 5, 4, 3, 2, 1]);

    // query
    let found = messages(
        &app,
        &[("offset", "0"), ("limit", "2"), ("query", "  Lunch  ")],
    )
    .await;
    assert_eq!(page_uids(&found), [4], "{found}");
    assert_eq!(found["total"], 1);

    // read status
    let unread = messages(
        &app,
        &[
            ("offset", "0"),
            ("limit", "50"),
            ("query", ""),
            ("read_status", "unread"),
        ],
    )
    .await;
    assert_eq!(page_uids(&unread), [6, 4, 3]);
    let read = messages(
        &app,
        &[
            ("offset", "0"),
            ("limit", "50"),
            ("query", ""),
            ("read_status", "read"),
        ],
    )
    .await;
    assert_eq!(page_uids(&read), [5, 2, 1]);

    // sender domains (repeated key)
    let domains = messages(
        &app,
        &[
            ("offset", "0"),
            ("limit", "50"),
            ("query", ""),
            ("sender_domain", "example.org"),
        ],
    )
    .await;
    assert_eq!(page_uids(&domains), [6, 2], "{domains}");
    let domains = messages(
        &app,
        &[
            ("offset", "0"),
            ("limit", "50"),
            ("query", ""),
            ("sender_domain", "example.net"),
            ("sender_domain", "EXAMPLE.ORG"),
        ],
    )
    .await;
    assert_eq!(page_uids(&domains), [6, 4, 2], "{domains}");

    // category filter == the categories reported by the full listing
    let full = all_messages(&app).await;
    let summaries = by_uid(&full);
    let categories: BTreeSet<String> = summaries
        .values()
        .map(|s| s["category"].as_str().unwrap().to_string())
        .collect();
    assert!(categories.len() >= 2, "{categories:?}");
    for category in &categories {
        let filtered = messages(
            &app,
            &[
                ("offset", "0"),
                ("limit", "50"),
                ("query", ""),
                ("category", category),
            ],
        )
        .await;
        let expected: Vec<u64> = summaries
            .iter()
            .rev()
            .filter(|(_, s)| s["category"] == category.as_str())
            .map(|(uid, _)| *uid)
            .collect();
        assert_eq!(page_uids(&filtered), expected, "category {category}");
        assert_eq!(filtered["total"], expected.len());
    }
    // A page of a filtered result keeps the filtered total.
    if let Some(category) = categories.iter().find(|c| {
        summaries
            .values()
            .filter(|s| s["category"] == c.as_str())
            .count()
            >= 2
    }) {
        let filtered = messages(
            &app,
            &[
                ("offset", "1"),
                ("limit", "1"),
                ("query", ""),
                ("category", category),
            ],
        )
        .await;
        assert_eq!(page_uids(&filtered).len(), 1);
        assert!(filtered["total"].as_u64().unwrap() >= 2);
    }

    // -- message: mark_seen + image source registration ----------------------
    assert!(app.state.image_sources.sources(USER, "INBOX", 3).is_none());
    let opened = app
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
    assert_eq!(opened["uid"], 3);
    assert_eq!(opened["folder"], "INBOX");
    assert_eq!(opened["seen"], true);
    assert_eq!(opened["subject"], "Weekly deals");
    assert_eq!(opened["from_addr"], "news@shop.example.com");
    assert_eq!(opened["uid_validity"], "1234");
    assert!(opened["html_body"].as_str().unwrap().contains(IMAGE_URL));
    assert_eq!(
        keys(&opened)[..11],
        [
            "subject",
            "from_name",
            "from_addr",
            "to",
            "cc",
            "date",
            "message_id",
            "text_body",
            "html_body",
            "attachments",
            "snippet"
        ]
    );
    assert!(servers
        .imap
        .flags("INBOX", 3)
        .unwrap()
        .contains(&"\\Seen".to_string()));
    let sources = app.state.image_sources.sources(USER, "INBOX", 3).unwrap();
    assert!(sources.contains(IMAGE_URL), "{sources:?}");

    // mark_seen=false leaves the server flags alone.
    let peeked = app
        .get(
            "/api/mail/message",
            &[
                ("account", USER),
                ("folder", "INBOX"),
                ("uid", "4"),
                ("mark_seen", "false"),
            ],
        )
        .await
        .ok();
    assert_eq!(peeked["seen"], false);
    assert!(!servers
        .imap
        .flags("INBOX", 4)
        .unwrap()
        .contains(&"\\Seen".to_string()));

    // Image proxy: only registered sources; loopback targets are refused.
    let unknown = app
        .post_json(
            "/api/mail/message/image",
            &json!({"account": USER, "folder": "INBOX", "uid": 3,
                    "url": "http://127.0.0.1:9/other.png", "retry": false}),
        )
        .await;
    assert_eq!(
        unknown.error(StatusCode::FORBIDDEN),
        "This image was not found in the selected email"
    );
    let blocked = app
        .post_json(
            "/api/mail/message/image",
            &json!({"account": USER, "folder": "INBOX", "uid": 3,
                    "url": IMAGE_URL, "retry": false}),
        )
        .await;
    assert_eq!(
        blocked.error(StatusCode::BAD_GATEWAY),
        "The remote image could not be downloaded safely"
    );

    // -- eml + attachment downloads ------------------------------------------
    let eml = app
        .get(
            "/api/mail/message/eml",
            &[("account", USER), ("folder", "INBOX"), ("uid", "2")],
        )
        .await;
    assert_eq!(eml.status, StatusCode::OK);
    assert_eq!(eml.header("content-type"), Some("message/rfc822"));
    assert_eq!(
        eml.header("content-disposition"),
        Some("attachment; filename=\"message-2.eml\"")
    );
    assert_eq!(eml.header("access-control-allow-origin"), Some(ORIGIN));
    assert!(eml
        .header("access-control-expose-headers")
        .is_some_and(|value| value.to_lowercase().contains("content-disposition")));
    assert_eq!(eml.body, servers.imap.message("INBOX", 2).unwrap().raw);

    let detail = app
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
    assert_eq!(
        detail["attachments"],
        json!([{"index": 0, "filename": "report.pdf", "content_type": "application/pdf",
                "size": PDF_BYTES.len()}])
    );
    assert_eq!(detail["cc"], "Carol <carol@example.org>");
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
    assert_eq!(attachment.header("content-type"), Some("application/pdf"));
    assert_eq!(
        attachment.header("content-disposition"),
        Some("attachment; filename=\"report.pdf\"")
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
        missing.status,
        StatusCode::BAD_GATEWAY,
        "{}",
        missing.text()
    );

    // -- flags ---------------------------------------------------------------
    let flagged = app
        .post_json(
            "/api/mail/message/flags",
            &json!({"account": USER, "folder": "INBOX", "uid": 4, "flagged": true}),
        )
        .await
        .ok();
    assert_eq!(keys(&flagged), ["uid", "flags", "seen", "flagged"]);
    assert_eq!(flagged["uid"], 4);
    assert_eq!(flagged["flagged"], true);
    assert_eq!(flagged["seen"], false);
    assert!(servers
        .imap
        .flags("INBOX", 4)
        .unwrap()
        .contains(&"\\Flagged".to_string()));
    let seen = app
        .post_json(
            "/api/mail/message/flags",
            &json!({"account": USER, "folder": "INBOX", "uid": 4, "seen": true}),
        )
        .await
        .ok();
    assert_eq!(
        (seen["seen"].clone(), seen["flagged"].clone()),
        (json!(true), json!(true))
    );
    let unseen = app
        .post_json(
            "/api/mail/message/flags",
            &json!({"account": USER, "folder": "INBOX", "uid": 4, "seen": false}),
        )
        .await
        .ok();
    assert_eq!(unseen["seen"], false);
    assert!(!servers
        .imap
        .flags("INBOX", 4)
        .unwrap()
        .contains(&"\\Seen".to_string()));

    // -- retention PUT -------------------------------------------------------
    // The 60-day-old newsletter expires after a manual 1-day expiration.
    let updated = app
        .put_json(
            "/api/mail/message/retention",
            &json!({"account": USER, "folder": "INBOX", "uid": 3, "uid_validity": "1234",
                    "expiration_days": 1}),
        )
        .await
        .ok();
    assert_eq!(updated["uid"], 3);
    assert_eq!(updated["folder"], "INBOX");
    assert_eq!(updated["expiration_days"], 1);
    assert_eq!(updated["expiration_source"], "manual");
    assert_eq!(updated["expired"], true);
    let categorized = app
        .put_json(
            "/api/mail/message/retention",
            &json!({"account": USER, "folder": "INBOX", "uid": 5, "uid_validity": "1234",
                    "category": "transactional"}),
        )
        .await
        .ok();
    assert_eq!(categorized["category"], "transactional");
    assert_eq!(categorized["category_source"], "manual");
    // Stale identity → 409.
    let stale = app
        .put_json(
            "/api/mail/message/retention",
            &json!({"account": USER, "folder": "INBOX", "uid": 5, "uid_validity": "999",
                    "category": "updates"}),
        )
        .await;
    assert!(stale.error(StatusCode::CONFLICT).is_string());

    // expired_only == the summaries reporting expired.
    let full = all_messages(&app).await;
    let expected: Vec<u64> = by_uid(&full)
        .iter()
        .rev()
        .filter(|(_, s)| s["expired"] == true)
        .map(|(uid, _)| *uid)
        .collect();
    assert!(expected.contains(&3), "{full}");
    let expired = messages(
        &app,
        &[
            ("offset", "0"),
            ("limit", "50"),
            ("query", ""),
            ("expired_only", "true"),
        ],
    )
    .await;
    assert_eq!(page_uids(&expired), expected);
    let expired_unread = messages(
        &app,
        &[
            ("offset", "0"),
            ("limit", "50"),
            ("query", ""),
            ("read_status", "read"),
            ("expired_only", "true"),
        ],
    )
    .await;
    // Message 3 was marked seen above.
    assert!(page_uids(&expired_unread).contains(&3));

    // -- local AI classification ---------------------------------------------
    let ollama = FakeOllama::with_model(MODEL, "updates", "A team status report");
    {
        let _url = scoped_ollama_url(ollama.url());
        let status = app.get("/api/mail/classifier/status", &[]).await.ok();
        assert_eq!(
            status,
            json!({"available": true, "model": MODEL, "installed_models": [MODEL], "error": null})
        );
        let classified = app
            .post_json(
                "/api/mail/message/classify",
                &json!({"account": USER, "folder": "INBOX", "uid": 6, "uid_validity": "1234"}),
            )
            .await
            .ok();
        assert_eq!(classified["uid"], 6);
        assert_eq!(classified["folder"], "INBOX");
        assert_eq!(classified["category"], "updates");
        assert_eq!(classified["category_source"], "ai");
        assert_eq!(classified["category_reason"], "A team status report");
        assert_eq!(classified["category_model"], MODEL);
        assert!(ollama.paths().contains(&"/api/chat".to_string()));
        // Classification never marks the message read.
        assert!(!servers
            .imap
            .flags("INBOX", 6)
            .unwrap()
            .contains(&"\\Seen".to_string()));
    }

    // -- sender rules --------------------------------------------------------
    let created = app
        .post_json(
            "/api/mail/message/sender-rule",
            &json!({"account": USER, "folder": "INBOX", "uid": 6, "uid_validity": "1234",
                    "category": "updates"}),
        )
        .await
        .ok();
    let rule = created["rule"].clone();
    assert_eq!(rule["sender"], "team@example.org", "{created}");
    assert_eq!(rule["category"], "updates");
    assert_eq!(rule["uid_validity"], "1234");
    assert_eq!(rule["first_uid"], 7);
    assert_eq!(created["uid"], 6);
    let mismatched = app
        .post_json(
            "/api/mail/message/sender-rule",
            &json!({"account": USER, "folder": "INBOX", "uid": 4, "uid_validity": "1234",
                    "category": "marketing"}),
        )
        .await;
    assert_eq!(
        mismatched.error(StatusCode::CONFLICT),
        "The email category changed. Refresh the message before saving a sender rule."
    );
    let rules = app
        .get(
            "/api/mail/sender-rules",
            &[("account", USER), ("folder", "INBOX")],
        )
        .await
        .ok();
    assert_eq!(rules["rules"].as_array().unwrap().len(), 1, "{rules}");
    assert_eq!(rules["rules"][0]["sender"], "team@example.org");
    let revision = rules["rules"][0]["revision"].as_u64().unwrap().to_string();
    let deleted = app
        .delete(
            "/api/mail/sender-rules",
            &[
                ("account", USER),
                ("folder", "INBOX"),
                ("sender", "team@example.org"),
                ("expected_revision", &revision),
            ],
        )
        .await
        .ok();
    assert_eq!(deleted, json!({"deleted": true}));
    let rules = app
        .get(
            "/api/mail/sender-rules",
            &[("account", USER), ("folder", "INBOX")],
        )
        .await
        .ok();
    assert_eq!(rules, json!({"rules": []}));
    let again = app
        .delete(
            "/api/mail/sender-rules",
            &[
                ("account", USER),
                ("folder", "INBOX"),
                ("sender", "team@example.org"),
            ],
        )
        .await
        .ok();
    assert_eq!(again, json!({"deleted": false}));

    // -- send: JSON ----------------------------------------------------------
    let sent = app
        .post_json(
            "/api/mail/send",
            &json!({
                "account": USER, "to": ["Friend <friend@example.net>"], "cc": [],
                "bcc": ["hidden@example.org"], "subject": "Hello from e2e",
                "text": "Plain body", "html": "<p>Plain <b>body</b></p>",
                "in_reply_to": "", "references": "",
            }),
        )
        .await
        .ok();
    assert_eq!(sent["sent"], true, "{sent}");
    assert_eq!(sent["from"], "Example User <user@example.com>", "{sent}");
    assert_eq!(sent["sent_saved"], true, "{sent}");
    assert_eq!(sent["sent_folder"], "Sent", "{sent}");
    assert_eq!(keys(&sent)[..3], ["sent", "message_id", "from"]);
    let delivered = servers.smtp.messages();
    assert_eq!(delivered.len(), 1);
    let mail = &delivered[0];
    assert_eq!(mail.mail_from, USER);
    let mut recipients = mail.rcpt_to.clone();
    recipients.sort();
    assert_eq!(recipients, ["friend@example.net", "hidden@example.org"]);
    assert_eq!(mail.authenticated_user.as_deref(), Some(USER));
    assert!(!contains(&mail.data, b"hidden@example.org"), "Bcc leaked");
    let parsed = MessageParser::default().parse(&mail.data).unwrap();
    assert_eq!(parsed.subject(), Some("Hello from e2e"));
    let message_id = sent["message_id"].as_str().unwrap().to_string();
    let sent_copy = servers.imap.folder("Sent").unwrap();
    assert_eq!(sent_copy.messages.len(), 1);
    assert!(contains(
        &sent_copy.messages[0].raw,
        message_id.trim_matches(|c| c == '<' || c == '>').as_bytes()
    ));
    assert!(sent_copy.messages[0].has_flag("\\Seen"));

    // -- send: multipart with inline image + attachment ----------------------
    let logo = png();
    let message = json!({
        "account": USER, "to": ["friend@example.net"], "cc": ["carol@example.org"], "bcc": [],
        "subject": "Files from e2e", "text": "See attached",
        "html": "<p>Logo:</p><img src=\"cid:logo-1\">",
        "in_reply_to": "<lunch@example.com>", "references": "<lunch@example.com>",
        "uploads": [
            {"content_id": "logo-1", "disposition": "inline"},
            {"content_id": "", "disposition": "attachment"},
        ],
    });
    let response = app
        .multipart(
            Method::POST,
            "/api/mail/send/files",
            &[
                form_field("message", &message.to_string()),
                form_file("files", "logo.png", "image/png", &logo),
                form_file("files", "notes.txt", "text/plain", b"remember the milk\n"),
            ],
        )
        .await;
    let sent = response.ok();
    assert_eq!(sent["sent"], true);
    assert_eq!(sent["sent_saved"], true, "{sent}");
    let delivered = servers.smtp.messages();
    assert_eq!(delivered.len(), 2);
    let parsed = MessageParser::default().parse(&delivered[1].data).unwrap();
    assert_eq!(parsed.subject(), Some("Files from e2e"));
    assert_eq!(parsed.in_reply_to().as_text(), Some("lunch@example.com"));
    let parts: Vec<_> = parsed.attachments().collect();
    assert_eq!(
        parts.len(),
        2,
        "{}",
        String::from_utf8_lossy(&delivered[1].data)
    );
    let inline = parts
        .iter()
        .find(|part| part.content_id() == Some("logo-1"))
        .expect("inline image part");
    assert_eq!(inline.contents(), logo.as_slice());
    assert_eq!(
        inline.content_disposition().map(|d| d.ctype()),
        Some("inline")
    );
    let notes = parts
        .iter()
        .find(|part| part.attachment_name() == Some("notes.txt"))
        .expect("attachment part");
    assert_eq!(notes.contents(), b"remember the milk\n");
    assert_eq!(servers.imap.folder("Sent").unwrap().messages.len(), 2);

    // -- delete to Trash -----------------------------------------------------
    let deleted = app
        .delete(
            "/api/mail/message",
            &[
                ("account", USER),
                ("folder", "INBOX"),
                ("uid", "4"),
                ("trash", "Trash"),
                ("uid_validity", "1234"),
            ],
        )
        .await
        .ok();
    assert_eq!(deleted, json!({"deleted": 4}));
    let deleted = app
        .post_json(
            "/api/mail/messages/delete",
            &json!({"account": USER, "folder": "INBOX", "uids": [6, 5], "trash": "Trash",
                    "uid_validity": "1234"}),
        )
        .await
        .ok();
    assert_eq!(deleted, json!({"deleted": [6, 5]}));
    assert_eq!(servers.imap.uids("INBOX"), [1, 2, 3]);
    let trash_uids = servers.imap.uids("Trash");
    assert_eq!(trash_uids.len(), 5, "{trash_uids:?}");
    let page = messages(&app, &[("offset", "0"), ("limit", "50"), ("query", "")]).await;
    assert_eq!(page["total"], 3);

    // -- trash: prepare(archive) → download → empty --------------------------
    let prepared = app
        .post_json(
            "/api/mail/trash/prepare",
            &json!({"account": USER, "folder": "Trash", "archive": true}),
        )
        .await
        .ok();
    assert_eq!(
        keys(&prepared),
        ["operation_id", "count", "archive", "filename"]
    );
    assert_eq!(prepared["count"], 5);
    assert_eq!(prepared["archive"], true);
    let filename = prepared["filename"].as_str().unwrap().to_string();
    assert!(
        filename.starts_with("trash-") && filename.ends_with(".zip") && filename.len() == 25,
        "{filename}"
    );
    let operation = prepared["operation_id"].as_str().unwrap().to_string();

    // The archive must be downloaded before the permanent deletion.
    let early = app
        .post_json(
            &format!("/api/mail/trash/{operation}/empty"),
            &json!({"account": USER}),
        )
        .await;
    assert_eq!(
        early.error(StatusCode::BAD_GATEWAY),
        "Download and save the Trash archive before permanently deleting the messages."
    );
    assert_eq!(servers.imap.uids("Trash").len(), 5);

    let archive = app
        .get(
            &format!("/api/mail/trash/{operation}/archive"),
            &[("account", USER)],
        )
        .await;
    assert_eq!(archive.status, StatusCode::OK, "{}", archive.text());
    assert_eq!(archive.header("content-type"), Some("application/zip"));
    assert_eq!(archive.header("cache-control"), Some("no-store"));
    assert_eq!(archive.header("x-content-type-options"), Some("nosniff"));
    assert_eq!(
        archive.header("content-disposition"),
        Some(format!("attachment; filename=\"{filename}\"").as_str())
    );
    let entries = zip_entries(&archive.body);
    let trash = servers.imap.folder("Trash").unwrap();
    let expected: BTreeSet<String> = trash
        .uids()
        .iter()
        .map(|uid| format!("message-{uid}.eml"))
        .collect();
    assert_eq!(entries.keys().cloned().collect::<BTreeSet<_>>(), expected);
    for uid in trash.uids() {
        assert_eq!(
            entries[&format!("message-{uid}.eml")],
            trash.message(uid).unwrap().raw,
            "archived bytes of UID {uid}"
        );
    }

    let emptied = app
        .post_json(
            &format!("/api/mail/trash/{operation}/empty"),
            &json!({"account": USER}),
        )
        .await
        .ok();
    assert_eq!(emptied, json!({"deleted": 5, "remaining": 0}));
    assert!(servers.imap.uids("Trash").is_empty());
    // Retrying returns the stored result without touching the server again.
    let retried = app
        .post_json(
            &format!("/api/mail/trash/{operation}/empty"),
            &json!({"account": USER}),
        )
        .await
        .ok();
    assert_eq!(retried, emptied);
    // INBOX untouched.
    assert_eq!(servers.imap.uids("INBOX"), [1, 2, 3]);

    // A second prepared operation stays pending until the lock below.
    let pending = app
        .post_json(
            "/api/mail/trash/prepare",
            &json!({"account": USER, "folder": "Trash", "archive": true}),
        )
        .await
        .ok();
    assert_eq!(pending["count"], 0);
    let pending_id = pending["operation_id"].as_str().unwrap().to_string();

    // -- lock: every trace of the session is forgotten -----------------------
    let locked = app
        .delete(&format!("/api/accounts/{}", "User%40Example.com"), &[])
        .await
        .ok();
    assert_eq!(locked, json!({"locked": USER}));
    assert!(app.state.sessions.list().is_empty());
    assert!(app.state.image_sources.sources(USER, "INBOX", 3).is_none());
    let leftovers: Vec<_> = walk(&app.trash_archive_dir())
        .into_iter()
        .filter(|path| path.extension().is_some_and(|ext| ext == "zip"))
        .collect();
    assert!(leftovers.is_empty(), "{leftovers:?}");
    assert_eq!(
        app.get("/api/accounts", &[]).await.ok(),
        json!({"accounts": []})
    );
    let again = app.delete(&format!("/api/accounts/{USER}"), &[]).await;
    assert_eq!(
        again.error(StatusCode::NOT_FOUND),
        "Account is not unlocked"
    );
    assert!(
        app.any_file_contains(PASSWORD).is_none(),
        "password persisted in {:?}",
        app.any_file_contains(PASSWORD)
    );

    assert_everything_locked(&app, &operation, &pending_id).await;
}

/// Every account-bound route answers the 401 `password_required` shape.
async fn assert_everything_locked(app: &E2e, operation: &str, pending: &str) {
    let account = [("account", USER)];
    let message = [("account", USER), ("folder", "INBOX"), ("uid", "1")];
    for (path, params) in [
        ("/api/mail/folders", &account[..]),
        ("/api/mail/messages", &account[..]),
        ("/api/mail/message", &message[..]),
        ("/api/mail/message/eml", &message[..]),
        ("/api/mail/audit", &message[..]),
        ("/api/mail/sender-rules", &account[..]),
        ("/api/mail/signature", &account[..]),
    ] {
        app.get(path, params).await.assert_locked(USER);
    }
    app.get(
        "/api/mail/message/attachment",
        &[
            ("account", USER),
            ("folder", "INBOX"),
            ("uid", "1"),
            ("index", "0"),
        ],
    )
    .await
    .assert_locked(USER);
    app.get(&format!("/api/mail/trash/{operation}/archive"), &account)
        .await
        .assert_locked(USER);
    app.delete(&format!("/api/mail/trash/{pending}"), &account)
        .await
        .assert_locked(USER);
    app.delete("/api/mail/message", &message)
        .await
        .assert_locked(USER);
    app.delete(
        "/api/mail/sender-rules",
        &[
            ("account", USER),
            ("folder", "INBOX"),
            ("sender", "team@example.org"),
        ],
    )
    .await
    .assert_locked(USER);
    let identity = json!({"account": USER, "folder": "INBOX", "uid": 1, "uid_validity": "1234"});
    for (path, body) in [
        (
            "/api/mail/message/flags",
            json!({"account": USER, "folder": "INBOX", "uid": 1, "seen": true}),
        ),
        (
            "/api/mail/messages/delete",
            json!({"account": USER, "folder": "INBOX", "uids": [1], "trash": "Trash"}),
        ),
        ("/api/mail/message/classify", identity.clone()),
        (
            "/api/mail/message/sender-rule",
            json!({"account": USER, "folder": "INBOX", "uid": 1, "uid_validity": "1234",
                   "category": "updates"}),
        ),
        (
            "/api/mail/message/image",
            json!({"account": USER, "folder": "INBOX", "uid": 3, "url": IMAGE_URL}),
        ),
        (
            "/api/mail/trash/prepare",
            json!({"account": USER, "folder": "Trash", "archive": false}),
        ),
        (
            &format!("/api/mail/trash/{operation}/empty"),
            json!({"account": USER}),
        ),
        (
            "/api/mail/send",
            json!({"account": USER, "to": ["friend@example.net"], "subject": "x", "text": "y"}),
        ),
        (
            "/api/mail/jobs/account",
            json!({"account": USER, "days": 7}),
        ),
    ] {
        app.post_json(path, &body).await.assert_locked(USER);
    }
    app.put_json(
        "/api/mail/message/retention",
        &json!({"account": USER, "folder": "INBOX", "uid": 1, "uid_validity": "1234",
                "category": "updates"}),
    )
    .await
    .assert_locked(USER);
    let message = json!({"account": USER, "to": ["friend@example.net"], "subject": "x",
                         "text": "y", "uploads": [{"content_id": "", "disposition": "attachment"}]});
    app.multipart(
        Method::POST,
        "/api/mail/send/files",
        &[
            form_field("message", &message.to_string()),
            form_file("files", "a.txt", "text/plain", b"a"),
        ],
    )
    .await
    .assert_locked(USER);
}
