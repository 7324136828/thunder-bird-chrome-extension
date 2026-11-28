//! Connection, single-message, flag and attachment behavior of
//! `imap_client.py` (connect, verify_login, _select, fetch_raw,
//! fetch_message, set_flags, fetch_attachment) against the fake server.

mod imap_support;

use imap_support::{account, account_at, lines_named, mail_commands, message, server, PASSWORD};
use mail_core::error::MailError;
use mail_core::imap;
use mail_proto::testkit::{Failure, FakeImapServer, TlsMode};
use serde_json::json;

const MULTIPART: &str = "From: \"Sender Name\" <Sender@Example.com>\r\n\
To: user@example.com\r\n\
Subject: Report\r\n\
Date: Mon, 13 Oct 2026 09:59:40 +0000\r\n\
Message-ID: <report@example.com>\r\n\
MIME-Version: 1.0\r\n\
Content-Type: multipart/mixed; boundary=\"BOUND\"\r\n\
\r\n\
--BOUND\r\n\
Content-Type: text/plain; charset=\"utf-8\"\r\n\
\r\n\
Hello there.\r\n\
--BOUND\r\n\
Content-Type: text/csv; name=\"data.csv\"\r\n\
Content-Disposition: attachment; filename=\"data.csv\"\r\n\
Content-Transfer-Encoding: base64\r\n\
\r\n\
YSxiCjEsMgo=\r\n\
--BOUND--\r\n";

fn mailbox() -> FakeImapServer {
    server()
        .uid_validity("INBOX", Some(77))
        .message_with("INBOX", message(5, MULTIPART))
        .message_with(
            "INBOX",
            message(6, "Subject: flagged\r\n\r\nx\r\n").with_flags(&["\\Flagged"]),
        )
        .start()
}

#[test]
fn verify_login_examines_inbox_and_logs_out() {
    let server = mailbox();
    imap::verify_login(&account(&server)).unwrap();
    assert_eq!(mail_commands(&server), ["EXAMINE INBOX"]);
    assert_eq!(server.logout_count(), 1);
    // Credentials never reach the command log.
    assert!(server
        .commands()
        .iter()
        .all(|line| !line.contains(PASSWORD)));
}

#[test]
fn verify_login_reports_bad_credentials_and_unopenable_inbox() {
    let server = mailbox();
    let mut wrong = account(&server);
    wrong.password = "definitely-wrong".into();
    let error = imap::verify_login(&wrong).unwrap_err();
    assert!(matches!(error, MailError::Operation(ref m)
        if m == "Mailbox sign-in failed. Check the password or use an app password."));
    assert!(!error.to_string().contains("definitely-wrong"));
    assert_eq!(error.status(), 502);

    server.fail_next("EXAMINE", Failure::no());
    let error = imap::verify_login(&account(&server)).unwrap_err();
    assert_eq!(
        error.to_string(),
        "The server would not open the INBOX folder"
    );
}

#[test]
fn unreachable_server_reports_connection_target() {
    let error = imap::verify_login(&account_at(1)).unwrap_err();
    let message = error.to_string();
    assert!(
        message.starts_with("Could not connect to 127.0.0.1:1: "),
        "{message}"
    );
    assert!(!message.contains(PASSWORD));
}

#[test]
fn starttls_is_required_when_configured() {
    // The fake plain server does not offer STARTTLS: imaplib raised
    // "TLS not supported by server" which connect() reported.
    let server = mailbox();
    let mut starttls = account(&server);
    starttls.incoming_protocol = "STARTTLS".into();
    let error = imap::verify_login(&starttls).unwrap_err();
    let message = error.to_string();
    assert!(message.starts_with(&format!(
        "Could not connect to 127.0.0.1:{}: ",
        server.port()
    )));
    assert!(message.contains("TLS not supported by server"), "{message}");
}

#[test]
fn tls_certificate_is_verified_against_the_system_store() {
    // The testkit certificate is self-signed, so a real client must refuse it.
    let server = server().tls(TlsMode::Implicit).start();
    let mut ssl = account(&server);
    ssl.incoming_protocol = "SSL/TLS".into();
    let error = imap::verify_login(&ssl).unwrap_err();
    assert!(error
        .to_string()
        .starts_with("Could not connect to 127.0.0.1:"));
}

#[test]
fn select_returns_exists_and_names_missing_folders() {
    let server = mailbox();
    let mut conn = imap::connect(&account(&server)).unwrap();
    assert_eq!(imap::select(&mut conn, "INBOX", true).unwrap(), 2);
    let error = imap::select(&mut conn, "Nope", false).unwrap_err();
    assert_eq!(error.to_string(), "The server would not open folder 'Nope'");
    imap::logout(conn);
    assert_eq!(server.logout_count(), 1);
}

#[test]
fn fetch_raw_returns_exact_bytes_without_marking_seen() {
    let server = mailbox();
    let raw = imap::fetch_raw(&account(&server), "INBOX", 5).unwrap();
    assert_eq!(raw, MULTIPART.as_bytes());
    assert!(server.flags("INBOX", 5).unwrap().is_empty());
    assert_eq!(
        mail_commands(&server),
        [
            "EXAMINE \"INBOX\"",
            "UID FETCH 5 (UID FLAGS INTERNALDATE BODY.PEEK[])"
        ]
    );
    let error = imap::fetch_raw(&account(&server), "INBOX", 9).unwrap_err();
    assert_eq!(
        error.to_string(),
        "The server returned no data for message UID 9"
    );
    server.fail_next("UID FETCH", Failure::no());
    let error = imap::fetch_raw(&account(&server), "INBOX", 5).unwrap_err();
    assert_eq!(
        error.to_string(),
        "The server could not fetch message UID 5"
    );
    assert_eq!(server.logout_count(), 3);
}

#[test]
fn fetch_message_without_mark_seen_examines_read_only() {
    let server = mailbox();
    let view = imap::fetch_message(&account(&server), "INBOX", 5, false, None, None).unwrap();
    assert!(lines_named(&server, "SELECT").is_empty());
    assert!(lines_named(&server, "UID STORE").is_empty());
    assert!(server.flags("INBOX", 5).unwrap().is_empty());
    assert_eq!(view["uid"], 5);
    assert_eq!(view["folder"], "INBOX");
    assert_eq!(view["flags"], json!([]));
    assert_eq!(view["seen"], false);
    assert_eq!(view["flagged"], false);
    assert_eq!(view["subject"], "Report");
    assert_eq!(view["from_name"], "Sender Name");
    assert_eq!(view["from_addr"], "sender@example.com");
    assert_eq!(view["message_id"], "<report@example.com>");
    assert_eq!(view["date"], "2026-10-13T09:59:40+00:00");
    assert_eq!(view["uid_validity"], "77");
    assert_eq!(view["received_at"], "2020-01-01T00:00:00+00:00");
    assert_eq!(view["category"], "uncategorized");
    assert_eq!(view["sender_rule"], json!(null));
    assert!(view["text_body"].as_str().unwrap().contains("Hello there."));
    assert_eq!(view["attachments"][0]["filename"], "data.csv");
}

#[test]
fn fetch_message_with_mark_seen_stores_seen_once() {
    let server = mailbox();
    let view = imap::fetch_message(&account(&server), "INBOX", 5, true, None, None).unwrap();
    assert_eq!(view["flags"], json!(["\\Seen"]));
    assert_eq!(view["seen"], true);
    assert_eq!(server.flags("INBOX", 5).unwrap(), ["\\Seen"]);
    assert_eq!(
        mail_commands(&server),
        [
            "SELECT \"INBOX\"",
            "UID FETCH 5 (UID FLAGS INTERNALDATE BODY.PEEK[])",
            "UID STORE 5 +FLAGS (\\Seen)",
        ]
    );
    server.clear_log();
    imap::fetch_message(&account(&server), "INBOX", 5, true, None, None).unwrap();
    assert!(lines_named(&server, "UID STORE").is_empty());
}

#[test]
fn set_flags_updates_and_reports_server_flags() {
    let server = mailbox();
    let result = imap::set_flags(&account(&server), "INBOX", 5, Some(true), Some(true)).unwrap();
    assert_eq!(
        result,
        json!({"uid": 5, "flags": ["\\Seen", "\\Flagged"], "seen": true, "flagged": true})
    );
    assert_eq!(
        mail_commands(&server),
        [
            "SELECT \"INBOX\"",
            "UID STORE 5 +FLAGS (\\Seen)",
            "UID STORE 5 +FLAGS (\\Flagged)",
            "UID FETCH 5 (FLAGS)",
        ]
    );
    let result = imap::set_flags(&account(&server), "INBOX", 6, None, Some(false)).unwrap();
    assert_eq!(
        result,
        json!({"uid": 6, "flags": [], "seen": false, "flagged": false})
    );
    assert_eq!(server.logout_count(), 2);
}

#[test]
fn set_flags_reports_the_flag_the_server_refused() {
    let server = mailbox();
    server.fail_next("UID STORE", Failure::no());
    let error = imap::set_flags(&account(&server), "INBOX", 5, Some(true), None).unwrap_err();
    assert_eq!(error.to_string(), "The server could not update flag \\Seen");
    assert_eq!(error.status(), 502);
    assert_eq!(server.logout_count(), 1);
}

#[test]
fn fetch_attachment_returns_decoded_payload_or_python_message() {
    let server = mailbox();
    let attachment = imap::fetch_attachment(&account(&server), "INBOX", 5, 0).unwrap();
    assert_eq!(attachment.filename, "data.csv");
    assert_eq!(attachment.content_type, "text/csv");
    assert_eq!(attachment.content, b"a,b\n1,2\n");
    let error = imap::fetch_attachment(&account(&server), "INBOX", 5, 3).unwrap_err();
    assert!(matches!(error, MailError::Operation(ref m)
        if m == "Attachment 3 was not found on message UID 5"));
    assert_eq!(server.logout_count(), 2);
    assert!(server.flags("INBOX", 5).unwrap().is_empty());
}

#[test]
fn normalize_sender_domains_is_public() {
    let values = vec!["Example.COM.".to_string(), "example.com".to_string()];
    assert_eq!(
        imap::normalize_sender_domains(Some(&values)).unwrap(),
        ["example.com"]
    );
    assert_eq!(
        imap::normalize_sender_domains(None).unwrap(),
        Vec::<String>::new()
    );
    assert_eq!(
        imap::normalize_sender_domains(Some(&["a@b.example".to_string()])).unwrap_err(),
        "Enter a valid sender domain without an email address or URL"
    );
}
