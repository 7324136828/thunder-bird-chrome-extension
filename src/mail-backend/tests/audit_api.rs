//! Port of the audit route tests of `tests/test_mail.py::MailApiTests`
//! (`test_mail_endpoints_require_unlocked_account` for the audit URL, the
//! audit part of `test_folders_messages_and_audit_use_cached_credentials`,
//! `test_audit_paste_needs_no_account`) plus the parameter validation of
//! `GET /api/mail/audit` and `POST /api/audit/eml`.
//!
//! Python patched `imap_client.fetch_raw`; here the message is fetched from
//! a fake IMAP server.

mod accounts_support;
mod common;

use accounts_support::Harness;
use axum::http::{Method, StatusCode};
use mail_core::MailAccount;
use mail_proto::testkit::{FakeImapServer, FakeMessage};
use serde_json::{json, Value};

const USER: &str = "a@example.org";
const PASSWORD: &str = "pw-audit";

const SAMPLE_EML: &[u8] = br#"Return-Path: <bounce@bounces.example>
Received: from mail.evil.example (mail.evil.example [10.0.0.1])
        by mx.example.com with ESMTPS id abc123
        for <user@example.com>; Mon, 13 Oct 2026 10:00:05 +0000
Received: from phishing.host (phishing.host [10.0.0.2])
        by mail.evil.example with SMTP id def456;
        Mon, 13 Oct 2026 09:59:50 +0000
Authentication-Results: mx.example.com;
        spf=fail smtp.mailfrom=evil.example;
        dkim=none;
        dmarc=fail header.from=bank.example
From: "Bank Support <support@bank.example>" <forged@evil.example>
Reply-To: <helpdesk@other.example>
To: <user@example.com>
Subject: Urgent: verify your account
Date: Mon, 13 Oct 2026 09:59:40 +0000
Message-ID: <deadbeef@evil.example>
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="BOUND"

--BOUND
Content-Type: text/plain; charset="utf-8"

Click http://185.10.20.30/login to verify.
Also see https://bank.example/secure and https://xn--bnk-xua.example/.

--BOUND
Content-Type: text/html; charset="utf-8"

<a href="http://185.10.20.30/login">https://bank.example</a>

--BOUND
Content-Type: application/octet-stream; name="invoice.pdf.exe"
Content-Disposition: attachment; filename="invoice.pdf.exe"
Content-Transfer-Encoding: base64

TVo=

--BOUND--
"#;

fn unlock(harness: &Harness, server: &FakeImapServer) {
    harness.state.sessions.unlock(MailAccount::new(
        USER,
        PASSWORD,
        "127.0.0.1",
        server.port(),
        "none",
        "smtp.example.org",
        587,
        "STARTTLS",
    ));
}

fn locations(detail: &Value) -> Vec<Value> {
    detail
        .as_array()
        .unwrap()
        .iter()
        .map(|issue| issue["loc"].clone())
        .collect()
}

#[tokio::test]
async fn audit_requires_unlocked_account() {
    let harness = Harness::new();
    let response = harness
        .get("/api/mail/audit?account=a%40b.c&folder=INBOX&uid=1")
        .await;
    let detail = response.assert_json_error(StatusCode::UNAUTHORIZED);
    assert_eq!(
        detail,
        json!({"error": "password_required", "email": "a@b.c"})
    );
    // The dependency answers before the other parameters are validated.
    let response = harness
        .get("/api/mail/audit?account=%20A%40B.c%20&uid=0")
        .await;
    assert_eq!(
        response.assert_json_error(StatusCode::UNAUTHORIZED),
        json!({"error": "password_required", "email": "a@b.c"})
    );
}

#[tokio::test]
async fn audit_uses_cached_credentials() {
    let server = FakeImapServer::builder()
        .credentials(USER, PASSWORD)
        .message_with("INBOX", FakeMessage::new(SAMPLE_EML.to_vec()).with_uid(7))
        .start();
    let harness = Harness::new();
    unlock(&harness, &server);
    let response = harness
        .get("/api/mail/audit?account=a%40example.org&folder=INBOX&uid=7")
        .await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text());
    let report = response.json();
    assert_eq!(report["verdict"], "high");
    assert_eq!(report["account"], USER);
    assert!(!response.text().contains(PASSWORD));
    // Folder defaults to INBOX.
    let report = harness
        .get("/api/mail/audit?account=a%40example.org&uid=7")
        .await
        .json();
    assert_eq!(report["verdict"], "high");
    assert!(server.command_names().iter().any(|name| name == "LOGIN"));
}

#[tokio::test]
async fn audit_reports_server_failures_as_502() {
    let server = FakeImapServer::builder()
        .credentials(USER, PASSWORD)
        .start();
    let harness = Harness::new();
    unlock(&harness, &server);
    let response = harness
        .get("/api/mail/audit?account=a%40example.org&uid=99")
        .await;
    response.assert_json_error(StatusCode::BAD_GATEWAY);

    let response = harness
        .get("/api/mail/audit?account=a%40example.org&uid=4294967296")
        .await;
    assert_eq!(
        response.assert_json_error(StatusCode::BAD_GATEWAY),
        "The server returned no data for message UID 4294967296"
    );
}

#[tokio::test]
async fn audit_validates_query_parameters() {
    let server = FakeImapServer::builder()
        .credentials(USER, PASSWORD)
        .start();
    let harness = Harness::new();
    unlock(&harness, &server);

    let response = harness.get("/api/mail/audit").await;
    let detail = response.assert_json_error(StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(
        locations(&detail),
        vec![json!(["query", "account"]), json!(["query", "uid"])]
    );

    let folder = "f".repeat(501);
    let response = harness
        .get(&format!(
            "/api/mail/audit?account=a%40example.org&folder={folder}&uid=0"
        ))
        .await;
    let detail = response.assert_json_error(StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(
        locations(&detail),
        vec![json!(["query", "folder"]), json!(["query", "uid"])]
    );
    assert_eq!(detail[0]["type"], "string_too_long");
    assert_eq!(detail[1]["type"], "greater_than_equal");

    let response = harness
        .get("/api/mail/audit?account=a%40example.org&uid=seven")
        .await;
    let detail = response.assert_json_error(StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(detail[0]["type"], "int_parsing");
    assert_eq!(server.connection_count(), 0);
}

#[tokio::test]
async fn audit_paste_needs_no_account() {
    let harness = Harness::new();
    let response = harness
        .post_json(
            "/api/audit/eml",
            &json!({"content": String::from_utf8(SAMPLE_EML.to_vec()).unwrap()}),
        )
        .await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text());
    let report = response.json();
    assert_eq!(report["verdict"], "high");
    assert_eq!(report["account"], "");
}

#[tokio::test]
async fn audit_paste_validates_the_body() {
    let harness = Harness::new();
    let response = harness
        .post_json("/api/audit/eml", &json!({"content": ""}))
        .await;
    let detail = response.assert_json_error(StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(detail[0]["type"], "string_too_short");
    assert_eq!(detail[0]["loc"], json!(["body", "content"]));

    let response = harness.post_json("/api/audit/eml", &json!({})).await;
    let detail = response.assert_json_error(StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(detail[0]["type"], "missing");

    let response = harness
        .raw(Method::POST, "/api/audit/eml", Some("application/json"), "")
        .await;
    assert_eq!(
        response.json(),
        json!({"detail": [{"type": "missing", "loc": ["body"], "msg": "Field required", "input": null}]})
    );

    let response = harness
        .post_json("/api/audit/eml", &json!({"content": 5}))
        .await;
    let detail = response.assert_json_error(StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(detail[0]["type"], "string_type");

    // Any non-empty text is audited, even if it is not a message.
    let response = harness
        .post_json("/api/audit/eml", &json!({"content": "x"}))
        .await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text());
}
