//! POP3 result dicts use the same keys, in the same order, as the IMAP
//! (`imap_client.py`) dicts: folder dicts, list summaries, the message view
//! and the `update_retention` result.

use mail_core::imap::{self, ListMessagesOptions};
use mail_core::model::default_category_expiration_days;
use mail_core::pop3;
use mail_core::retention::{Patch, RetentionStore};
use mail_core::sessions::{MailAccount, PROTOCOL_POP3};
use mail_proto::testkit::{FakeImapServer, FakePop3Server};
use serde_json::Value;

const EMAIL: &str = "user@example.com";
const PASSWORD: &str = "pop-secret-123";
const RAW: &str =
    "Received: from mx.example.com by mail.example.com; Mon, 13 Oct 2026 10:00:00 +0000\r\n\
From: Sender <sender@example.com>\r\n\
To: user@example.com\r\n\
Subject: Hello\r\n\
Date: Mon, 13 Oct 2026 09:59:40 +0000\r\n\
\r\n\
Body\r\n";

fn pop3_account(server: &FakePop3Server) -> MailAccount {
    let mut account = MailAccount::new(
        EMAIL,
        PASSWORD,
        server.host(),
        server.port(),
        "none",
        "smtp.example.com",
        587,
        "starttls",
    );
    account.incoming_mail_protocol = PROTOCOL_POP3.into();
    account
}

fn imap_account(server: &FakeImapServer) -> MailAccount {
    MailAccount::new(
        EMAIL,
        PASSWORD,
        "127.0.0.1",
        server.port(),
        "none",
        "smtp.example.com",
        587,
        "starttls",
    )
}

fn servers() -> (FakePop3Server, FakeImapServer) {
    let pop = FakePop3Server::builder()
        .credentials(EMAIL, PASSWORD)
        .message(RAW.as_bytes().to_vec())
        .start();
    let imap = FakeImapServer::builder()
        .credentials(EMAIL, PASSWORD)
        .uid_validity("INBOX", Some(5))
        .message_with(
            "INBOX",
            mail_proto::testkit::FakeMessage::new(RAW.as_bytes().to_vec())
                .with_uid(1)
                .with_internal_date("13-Oct-2026 10:00:00 +0000"),
        )
        .start();
    (pop, imap)
}

fn keys(value: &Value) -> Vec<String> {
    value.as_object().expect("object").keys().cloned().collect()
}

#[test]
fn folder_dicts_match_imap_keys() {
    let (pop, imap) = servers();
    let pop_folders = imap::list_folders(&pop3_account(&pop)).unwrap();
    let imap_folders = imap::list_folders(&imap_account(&imap)).unwrap();
    assert_eq!(keys(&pop_folders[0]), keys(&imap_folders[0]));
    assert_eq!(pop_folders[0]["name"], "INBOX");
    assert_eq!(pop_folders[0]["special"], "inbox");
}

#[test]
fn summaries_and_views_match_imap_keys() {
    let (pop, imap) = servers();
    let options = ListMessagesOptions::default();
    let pop_page = imap::list_messages(&pop3_account(&pop), "INBOX", &options).unwrap();
    let imap_page = imap::list_messages(&imap_account(&imap), "INBOX", &options).unwrap();
    assert_eq!(keys(&pop_page), keys(&imap_page));
    assert_eq!(
        keys(&pop_page["messages"][0]),
        keys(&imap_page["messages"][0])
    );

    let pop_view = imap::fetch_message(&pop3_account(&pop), "INBOX", 1, false, None, None).unwrap();
    let imap_view =
        imap::fetch_message(&imap_account(&imap), "INBOX", 1, false, None, None).unwrap();
    assert_eq!(keys(&pop_view), keys(&imap_view));
}

#[test]
fn update_retention_result_matches_imap_keys() {
    let (pop, imap) = servers();
    let dir = tempfile::tempdir().unwrap();
    let store = RetentionStore::new(dir.path());
    let policies = default_category_expiration_days();
    let pop_epoch = pop3::prepare_sender_rule_scope(&pop3_account(&pop), "INBOX")
        .unwrap()
        .uid_validity;
    let pop_result = imap::update_retention(
        &pop3_account(&pop),
        "INBOX",
        1,
        &store,
        &policies,
        Patch::Set("updates".into()),
        Patch::Unset,
        Some(&pop_epoch),
    )
    .unwrap();
    let imap_result = imap::update_retention(
        &imap_account(&imap),
        "INBOX",
        1,
        &store,
        &policies,
        Patch::Set("updates".into()),
        Patch::Unset,
        Some("5"),
    )
    .unwrap();
    assert_eq!(keys(&pop_result), keys(&imap_result));
    assert_eq!(pop_result["category"], "updates");
    assert_eq!(pop_result["uid_validity"], Value::String(pop_epoch));
}
