//! End-to-end follow-ups of the IMAP flow: sender rules applied to mail that
//! arrives later, image-source re-registration after a re-unlock without
//! marking mail read, read-only downloads, per-account signatures
//! (`api.saveSignature` / `api.signature` / `api.signatureImage`),
//! retention reset, an unreachable Ollama, and paging past the end.

mod e2e_support;

use axum::http::{Method, StatusCode};
use e2e_support::*;
use mail_core::classifier::scoped_ollama_url;
use mail_proto::testkit::FakeImapServer;
use serde_json::{json, Value};

const IMAGE_URL: &str = "http://127.0.0.1:9/banner.png";

fn imap() -> FakeImapServer {
    FakeImapServer::builder()
        .credentials(USER, PASSWORD)
        .uid_validity("INBOX", Some(1234))
        .message_with(
            "INBOX",
            fake_message(
                1,
                &plain_message("Team <team@example.org>", "Status one", "a", 3, "s1"),
                3,
                &[],
            ),
        )
        .message_with(
            "INBOX",
            fake_message(2, &html_message(IMAGE_URL, 2), 2, &[]),
        )
        .message_with("INBOX", fake_message(3, &attachment_message(1), 1, &[]))
        .start()
}

fn unlock_body(port: u16) -> Value {
    json!({
        "email": USER, "password": PASSWORD, "incoming_server": "127.0.0.1",
        "incoming_port": port, "incoming_protocol": "NONE",
        "outgoing_server": "127.0.0.1", "outgoing_port": 2525, "outgoing_protocol": "NONE",
    })
}

async fn list(app: &E2e) -> Value {
    app.get(
        "/api/mail/messages",
        &[
            ("account", USER),
            ("folder", "INBOX"),
            ("offset", "0"),
            ("limit", "50"),
            ("query", ""),
        ],
    )
    .await
    .ok()
}

#[tokio::test]
async fn sender_rules_categorize_mail_that_arrives_later() {
    let server = imap();
    let app = E2e::new();
    app.unlock(unlock_body(server.port())).await.ok();

    let before = by_uid(&list(&app).await);
    let current = before[&1]["category"].as_str().unwrap().to_string();
    let target = if current == "updates" {
        "marketing"
    } else {
        "updates"
    };
    // The frontend first sets the category manually, then saves the rule.
    app.put_json(
        "/api/mail/message/retention",
        &json!({"account": USER, "folder": "INBOX", "uid": 1, "uid_validity": "1234",
                "category": target}),
    )
    .await
    .ok();
    let created = app
        .post_json(
            "/api/mail/message/sender-rule",
            &json!({"account": USER, "folder": "INBOX", "uid": 1, "uid_validity": "1234",
                    "category": target}),
        )
        .await
        .ok();
    assert_eq!(created["rule"]["first_uid"], 4, "{created}");
    assert_eq!(created["category"], target);
    let created_keys = keys(&created);
    assert_eq!(created_keys[..2], ["uid", "folder"]);
    assert_eq!(created_keys.last().unwrap(), "rule");
    assert_eq!(created_keys.len(), 14, "{created_keys:?}");
    assert_eq!(
        keys(&created["rule"]),
        // retention.py: `SELECT folder, sender, category, uid_validity,
        // first_uid, created_at, revision` / the same dict from save.
        [
            "folder",
            "sender",
            "category",
            "uid_validity",
            "first_uid",
            "created_at",
            "revision"
        ]
    );

    // New mail from the same sender (UID ≥ first_uid) follows the rule.
    server.add_message(
        "INBOX",
        fake_message(
            0,
            &plain_message("Team <TEAM@example.org>", "Status two", "b", 0, "s2"),
            0,
            &[],
        ),
    );
    let after = by_uid(&list(&app).await);
    let arrived = &after[&4];
    assert_eq!(arrived["category"], target, "{arrived}");
    assert_eq!(arrived["category_source"], "sender_rule", "{arrived}");
    assert_eq!(arrived["sender_rule"]["sender"], "team@example.org");
    assert_eq!(
        arrived["category_reason"],
        "Saved sender rule for team@example.org assigned this category"
    );
    assert_eq!(
        keys(arrived)[11..],
        [
            "category",
            "category_source",
            "category_reason",
            "category_model",
            "expiration_days",
            "expiration_source",
            "expires_at",
            "expired",
            "received_at",
            "uid_validity",
            "sender_rule",
        ]
    );
    // The rule keeps the manual choice of the message it was created from.
    assert_eq!(after[&1]["category_source"], "manual");
    assert_eq!(after[&1]["category_reason"], "Category selected manually");
    // Older mail from other senders is unaffected.
    assert_eq!(after[&3]["category"], before[&3]["category"]);
    let filtered = app
        .get(
            "/api/mail/messages",
            &[
                ("account", USER),
                ("folder", "INBOX"),
                ("offset", "0"),
                ("limit", "50"),
                ("query", ""),
                ("category", target),
            ],
        )
        .await
        .ok();
    assert!(page_uids(&filtered).contains(&4), "{filtered}");

    // Deleting the rule stops it for future mail.
    let deleted = app
        .delete(
            "/api/mail/sender-rules",
            &[
                ("account", USER),
                ("folder", "INBOX"),
                ("sender", "Team@Example.org"),
            ],
        )
        .await
        .ok();
    assert_eq!(deleted, json!({"deleted": true}));
    server.add_message(
        "INBOX",
        fake_message(
            0,
            &plain_message("Team <team@example.org>", "Hello", "c", 0, "s3"),
            0,
            &[],
        ),
    );
    let last = by_uid(&list(&app).await);
    assert_ne!(last[&5]["category_source"], "sender_rule", "{}", last[&5]);
}

#[tokio::test]
async fn image_sources_are_re_registered_after_a_new_unlock_without_marking_read() {
    let server = imap();
    let app = E2e::new();
    app.unlock(unlock_body(server.port())).await.ok();
    app.get(
        "/api/mail/message",
        &[
            ("account", USER),
            ("folder", "INBOX"),
            ("uid", "2"),
            ("mark_seen", "false"),
        ],
    )
    .await
    .ok();
    assert!(app.state.image_sources.sources(USER, "INBOX", 2).is_some());

    app.delete(&format!("/api/accounts/{USER}"), &[]).await.ok();
    assert!(app.state.image_sources.sources(USER, "INBOX", 2).is_none());
    app.unlock(unlock_body(server.port())).await.ok();

    // The proxy reads the message itself (peek) to authorize the image; a
    // loopback image target is still refused as unsafe.
    let image = app
        .post_json(
            "/api/mail/message/image",
            &json!({"account": USER, "folder": "INBOX", "uid": 2, "url": IMAGE_URL}),
        )
        .await;
    assert_eq!(
        image.error(StatusCode::BAD_GATEWAY),
        "The remote image could not be downloaded safely"
    );
    assert!(app.state.image_sources.sources(USER, "INBOX", 2).is_some());
    assert!(server.flags("INBOX", 2).unwrap().is_empty());
    // An image of another message is not authorized by this one.
    let other = app
        .post_json(
            "/api/mail/message/image",
            &json!({"account": USER, "folder": "INBOX", "uid": 1, "url": IMAGE_URL}),
        )
        .await;
    assert_eq!(
        other.error(StatusCode::FORBIDDEN),
        "This image was not found in the selected email"
    );
    let unsupported = app
        .post_json(
            "/api/mail/message/image",
            &json!({"account": USER, "folder": "INBOX", "uid": 2, "url": "javascript:alert(1)"}),
        )
        .await;
    assert_eq!(
        unsupported.error(StatusCode::BAD_REQUEST),
        "The image URL is not a supported HTTP or HTTPS address"
    );
}

#[tokio::test]
async fn downloads_and_audits_never_mark_mail_read() {
    let server = imap();
    let app = E2e::new();
    app.unlock(unlock_body(server.port())).await.ok();
    let params = [("account", USER), ("folder", "INBOX"), ("uid", "3")];
    let eml = app.get("/api/mail/message/eml", &params).await;
    assert_eq!(eml.status, StatusCode::OK);
    let attachment = app
        .get(
            "/api/mail/message/attachment",
            &[
                ("account", USER),
                ("folder", "INBOX"),
                ("uid", "3"),
                ("index", "0"),
            ],
        )
        .await;
    assert_eq!(attachment.status, StatusCode::OK);
    let audit = app.get("/api/mail/audit", &params).await.ok();
    assert_eq!(audit["subject"], "Project notes");
    assert_eq!(audit["account"], USER);
    assert_eq!(audit["attachments"][0]["filename"], "report.pdf");
    let pasted = app
        .post_json(
            "/api/audit/eml",
            &json!({"content": String::from_utf8(eml.body.clone()).unwrap()}),
        )
        .await
        .ok();
    assert_eq!(pasted["subject"], "Project notes");
    assert_eq!(pasted["account"], "");
    assert!(server.flags("INBOX", 3).unwrap().is_empty());
    for command in server.log() {
        assert_ne!(command.name, "SELECT", "{}", command.line);
        assert!(!command.name.contains("STORE"), "{}", command.line);
    }
}

#[tokio::test]
async fn per_account_signature_round_trip() {
    let server = imap();
    let app = E2e::new();
    app.unlock(unlock_body(server.port())).await.ok();

    let empty = app
        .get("/api/mail/signature", &[("account", USER)])
        .await
        .ok();
    assert_eq!(empty["account"], USER);
    assert_eq!(empty["text"], "");
    assert_eq!(empty["images"], json!([]));

    let logo = png();
    let saved = app
        .multipart(
            Method::PUT,
            &with_query("/api/mail/signature", &[("account", USER)]),
            &[
                form_field(
                    "signature",
                    &json!({"text": "<p>Regards</p><img src=\"cid:sig-logo\">",
                            "uploads": [{"content_id": "sig-logo"}]})
                    .to_string(),
                ),
                form_file("files", "logo.png", "image/png", &logo),
            ],
        )
        .await
        .ok();
    assert_eq!(
        keys(&saved),
        ["account", "text", "multipart-path", "images"]
    );
    assert!(saved["text"].as_str().unwrap().contains("cid:sig-logo"));
    let image = &saved["images"][0];
    assert_eq!(image["content_id"], "sig-logo");
    assert_eq!(image["content_type"], "image/png");
    let url = image["url"].as_str().unwrap();
    assert!(url.starts_with("/api/mail/signature/image?"), "{url}");

    let fetched = app
        .send(
            E2e::builder(Method::GET, url)
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(fetched.status, StatusCode::OK, "{}", fetched.text());
    assert_eq!(fetched.body, logo);
    assert_eq!(fetched.header("content-type"), Some("image/png"));
    assert_eq!(fetched.header("cache-control"), Some("no-store"));
    assert_eq!(
        fetched.header("content-security-policy"),
        Some("default-src 'none'; sandbox")
    );

    let loaded = app
        .get("/api/mail/signature", &[("account", USER)])
        .await
        .ok();
    assert_eq!(loaded, saved);

    // Locked accounts cannot read or change signatures.
    app.delete(&format!("/api/accounts/{USER}"), &[]).await.ok();
    app.get("/api/mail/signature", &[("account", USER)])
        .await
        .assert_locked(USER);
    let response = app
        .send(
            E2e::builder(Method::GET, url)
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await;
    response.assert_locked(USER);
}

#[tokio::test]
async fn retention_reset_paging_past_the_end_and_unreachable_ollama() {
    let server = imap();
    let app = E2e::new();
    app.unlock(unlock_body(server.port())).await.ok();
    let automatic = by_uid(&list(&app).await)[&3].clone();

    let manual = app
        .put_json(
            "/api/mail/message/retention",
            &json!({"account": USER, "folder": "INBOX", "uid": 3, "uid_validity": "1234",
                    "category": "verification", "expiration_days": -1}),
        )
        .await
        .ok();
    assert_eq!(manual["category_source"], "manual");
    assert_eq!(manual["expires_at"], -1);
    let reset = app
        .put_json(
            "/api/mail/message/retention",
            &json!({"account": USER, "folder": "INBOX", "uid": 3, "uid_validity": "1234",
                    "category": null, "expiration_days": null}),
        )
        .await
        .ok();
    assert_eq!(reset["category"], automatic["category"]);
    assert_eq!(reset["category_source"], automatic["category_source"]);
    assert_eq!(reset["expiration_source"], "category");
    let nothing = app
        .put_json(
            "/api/mail/message/retention",
            &json!({"account": USER, "folder": "INBOX", "uid": 3, "uid_validity": "1234"}),
        )
        .await;
    assert_eq!(nothing.status, StatusCode::UNPROCESSABLE_ENTITY);

    let past = app
        .get(
            "/api/mail/messages",
            &[
                ("account", USER),
                ("folder", "INBOX"),
                ("offset", "10"),
                ("limit", "5"),
                ("query", ""),
            ],
        )
        .await
        .ok();
    assert_eq!(
        past,
        json!({"total": 3, "offset": 10, "limit": 5, "messages": []})
    );

    // Ollama not running: status reports it, classification is a 502.
    let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://127.0.0.1:{}", closed.local_addr().unwrap().port());
    drop(closed);
    let _url = scoped_ollama_url(url);
    let status = app
        .get("/api/mail/classifier/status", &[("model", "qwen3:4b")])
        .await
        .ok();
    assert_eq!(status["available"], false);
    assert_eq!(status["model"], "qwen3:4b");
    assert_eq!(status["installed_models"], json!([]));
    let message = status["error"].as_str().unwrap().to_string();
    assert!(message.contains("Ollama"), "{message}");
    let classify = app
        .post_json(
            "/api/mail/message/classify",
            &json!({"account": USER, "folder": "INBOX", "uid": 3, "uid_validity": "1234"}),
        )
        .await;
    assert_eq!(classify.error(StatusCode::BAD_GATEWAY), message.as_str());
    assert!(server.flags("INBOX", 3).unwrap().is_empty());
}

/// Summary and reader values exactly as `imap_client.py` renders them:
/// ISO dates with offsets, decoded encoded-words, lower-cased addresses,
/// `date` falling back to INTERNALDATE, `size` = RFC822.SIZE.
#[tokio::test]
async fn summary_and_reader_values_match_python_rendering() {
    let encoded = "From: =?utf-8?b?w4lsb2lzZQ==?= <Eloise@Example.ORG>\r\n\
                   To: =?utf-8?q?J=C3=BCrgen?= <jurgen@example.com>, plain@example.net\r\n\
                   Subject: =?utf-8?q?Caf=C3=A9_menu?=\r\n\
                   Date: Tue, 24 Nov 2026 09:30:00 -0500\r\n\
                   Message-ID: <  cafe@example.com  >\r\n\
                   Content-Type: text/plain; charset=utf-8\r\n\r\n\
                   Soup   of\r\n the day.\r\n";
    let undated = "From: x@example.net\r\nSubject: No date\r\n\r\nbody\r\n";
    let server = FakeImapServer::builder()
        .credentials(USER, PASSWORD)
        .uid_validity("INBOX", Some(77))
        .message_with(
            "INBOX",
            mail_proto::testkit::FakeMessage::new(encoded.as_bytes().to_vec())
                .with_uid(5)
                .with_internal_date("24-Nov-2026 14:31:05 +0000"),
        )
        .message_with(
            "INBOX",
            mail_proto::testkit::FakeMessage::new(undated.as_bytes().to_vec())
                .with_uid(6)
                .with_internal_date("02-Jan-2026 03:04:05 +0100"),
        )
        .start();
    let app = E2e::new();
    app.unlock(unlock_body(server.port())).await.ok();
    let page = by_uid(&list(&app).await);

    let summary = &page[&5];
    assert_eq!(summary["subject"], "Café menu");
    assert_eq!(summary["from"], "Éloise <eloise@example.org>");
    assert_eq!(
        summary["to"],
        "Jürgen <jurgen@example.com>, plain@example.net"
    );
    assert_eq!(summary["date"], "2026-11-24T09:30:00-05:00");
    assert_eq!(summary["internal_date"], "2026-11-24T14:31:05+00:00");
    assert_eq!(summary["received_at"], "2026-11-24T14:31:05+00:00");
    assert_eq!(summary["size"], encoded.len());
    assert_eq!(summary["uid_validity"], "77");
    assert_eq!(summary["flags"], json!([]));
    assert_eq!(summary["answered"], false);
    let days = summary["expiration_days"].as_i64().unwrap();
    if days >= 0 {
        let expected = (chrono::DateTime::parse_from_rfc3339("2026-11-24T14:31:05+00:00").unwrap()
            + chrono::Duration::days(days))
        .to_rfc3339();
        assert_eq!(summary["expires_at"], expected.as_str(), "{summary}");
    } else {
        assert_eq!(summary["expires_at"], -1);
    }

    let undated_summary = &page[&6];
    assert_eq!(undated_summary["date"], "2026-01-02T03:04:05+01:00");
    assert_eq!(
        undated_summary["internal_date"],
        "2026-01-02T03:04:05+01:00"
    );
    assert_eq!(undated_summary["to"], "");

    let reader = app
        .get(
            "/api/mail/message",
            &[
                ("account", USER),
                ("folder", "INBOX"),
                ("uid", "5"),
                ("mark_seen", "false"),
            ],
        )
        .await
        .ok();
    assert_eq!(reader["from_name"], "Éloise");
    assert_eq!(reader["from_addr"], "eloise@example.org");
    assert_eq!(reader["cc"], "");
    // policy.default folds the msg-id: Python yields "<  cafe@example.com>".
    assert_eq!(reader["message_id"], "<  cafe@example.com>");
    assert_eq!(reader["snippet"], "Soup of the day.");
    assert_eq!(reader["html_body"], "");
    assert_eq!(reader["attachments"], json!([]));
    let undated_reader = app
        .get(
            "/api/mail/message",
            &[
                ("account", USER),
                ("folder", "INBOX"),
                ("uid", "6"),
                ("mark_seen", "false"),
            ],
        )
        .await
        .ok();
    assert_eq!(undated_reader["date"], json!(null));
    assert_eq!(undated_reader["message_id"], "");
}
