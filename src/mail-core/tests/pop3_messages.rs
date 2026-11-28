//! POP3 compatibility mode: reading messages, attachments, retention edits,
//! classification guards and sender rules against the fake POP3 server.
//! Mirrors the IMAP expectations of `tests/test_retention.py`
//! (`RetentionImapTests`) and `tests/test_sender_rules.py`
//! (`SenderRuleImapTests`) with the synthetic POP3 epoch.

use std::collections::BTreeSet;

use mail_core::imap::ListMessagesOptions;
use mail_core::model::default_category_expiration_days;
use mail_core::pop3;
use mail_core::retention::{Patch, RetentionStore, SaveSenderRuleOptions};
use mail_core::sessions::{MailAccount, PROTOCOL_POP3};
use mail_core::MailError;
use mail_proto::testkit::{Failure, FakePop3Server};
use serde_json::{json, Value};

const EMAIL: &str = "user@example.com";
const PASSWORD: &str = "pop-secret-123";

fn account(server: &FakePop3Server) -> MailAccount {
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

fn server_with(messages: &[Vec<u8>]) -> FakePop3Server {
    messages
        .iter()
        .fold(
            FakePop3Server::builder().credentials(EMAIL, PASSWORD),
            |builder, raw| builder.message(raw.clone()),
        )
        .start()
}

fn count(server: &FakePop3Server, name: &str) -> usize {
    server
        .command_names()
        .iter()
        .filter(|c| c.as_str() == name)
        .count()
}

fn epoch(server: &FakePop3Server) -> String {
    pop3::prepare_sender_rule_scope(&account(server), "INBOX")
        .unwrap()
        .uid_validity
}

fn conflict(error: MailError) -> String {
    match error {
        MailError::RetentionConflict(message) => message,
        other => panic!("expected a retention conflict, got {other:?}"),
    }
}

fn operation(error: MailError) -> String {
    match error {
        MailError::Operation(message) => message,
        other => panic!("expected an operation error, got {other:?}"),
    }
}

fn uids(page: &Value) -> Vec<u64> {
    page["messages"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m["uid"].as_u64().unwrap())
        .collect()
}

const INVOICE: &[u8] =
    b"Received: from mx.example.org by pop.example.com; 14 Oct 2099 00:00:00 +0000\r\n\
From: Billing <billing@example.org>\r\nTo: user@example.com\r\nSubject: Invoice\r\n\
Date: Tue, 1 Jan 2000 00:00:00 +0000\r\nMessage-ID: <invoice-1@example.org>\r\n\
List-Unsubscribe: <https://example.org/u>\r\nPrecedence: bulk\r\n\r\nVerification code in body\r\n";

const WITH_ATTACHMENT: &[u8] = b"From: a@example.com\r\nSubject: files\r\nMIME-Version: 1.0\r\n\
Content-Type: multipart/mixed; boundary=\"b1\"\r\n\r\n--b1\r\nContent-Type: text/plain\r\n\r\n\
See attached\r\n--b1\r\nContent-Type: text/plain; name=\"notes.txt\"\r\n\
Content-Disposition: attachment; filename=\"notes.txt\"\r\n\r\nattachment text\r\n--b1--\r\n";

// ---------------------------------------------------------------------------
// fetch_message / fetch_raw / fetch_attachment
// ---------------------------------------------------------------------------

#[test]
fn fetch_message_returns_the_imap_view_shape_without_marking_seen() {
    let server = server_with(&[INVOICE.to_vec()]);
    let view = pop3::fetch_message(&account(&server), "INBOX", 1, true, None, None).unwrap();
    let keys: BTreeSet<&str> = view
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    let expected: BTreeSet<&str> = [
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
        "snippet",
        "uid",
        "folder",
        "flags",
        "seen",
        "flagged",
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
    .into_iter()
    .collect();
    assert_eq!(keys, expected);
    assert_eq!(view["uid"], 1);
    assert_eq!(view["folder"], "INBOX");
    assert_eq!(view["flags"], json!([]));
    assert_eq!(view["seen"], false);
    assert_eq!(view["flagged"], false);
    assert_eq!(view["subject"], "Invoice");
    assert_eq!(view["from_addr"], "billing@example.org");
    assert_eq!(view["message_id"], "<invoice-1@example.org>");
    assert_eq!(view["text_body"], "Verification code in body\r\n");
    assert_eq!(view["category"], "transactional");
    assert_eq!(view["received_at"], "2099-10-14T00:00:00+00:00");
    assert_eq!(view["expired"], false);
    assert_eq!(view["uid_validity"].as_str().unwrap(), epoch(&server));
    // mark_seen is a no-op: nothing but reads were sent.
    let names = server.command_names();
    assert!(names
        .iter()
        .all(|n| ["USER", "PASS", "LIST", "UIDL", "RETR", "QUIT", "TOP"].contains(&n.as_str())));
}

#[test]
fn list_and_detail_use_the_same_headers_and_arrival_time() {
    let dir = tempfile::tempdir().unwrap();
    let store = RetentionStore::new(dir.path());
    let server = server_with(&[INVOICE.to_vec()]);
    let account = account(&server);
    let page = pop3::list_messages(
        &account,
        "INBOX",
        &ListMessagesOptions {
            retention_store: Some(&store),
            ..Default::default()
        },
    )
    .unwrap();
    let summary = &page["messages"][0];
    let detail = pop3::fetch_message(&account, "INBOX", 1, false, Some(&store), None).unwrap();
    for field in [
        "category",
        "category_source",
        "category_reason",
        "expiration_days",
        "expires_at",
        "expired",
        "received_at",
        "uid_validity",
        "sender_rule",
    ] {
        assert_eq!(summary[field], detail[field], "{field}");
    }
    assert_eq!(detail["category"], "transactional");
}

#[test]
fn fetch_message_unknown_number_and_refused_retr() {
    let server = server_with(&[INVOICE.to_vec()]);
    let error = pop3::fetch_message(&account(&server), "INBOX", 9, false, None, None).unwrap_err();
    assert_eq!(
        operation(error),
        "The server returned no data for message UID 9"
    );
    assert_eq!(count(&server, "RETR"), 0);
    server.fail_next("RETR", Failure::no());
    let error = pop3::fetch_message(&account(&server), "INBOX", 1, false, None, None).unwrap_err();
    assert_eq!(operation(error), "The server could not fetch message UID 1");
    let error = pop3::fetch_message(&account(&server), "Trash", 1, false, None, None).unwrap_err();
    assert_eq!(operation(error), "The server would not open folder 'Trash'");
}

#[test]
fn fetch_raw_returns_the_message_bytes() {
    let server = server_with(&[INVOICE.to_vec(), WITH_ATTACHMENT.to_vec()]);
    let raw = pop3::fetch_raw(&account(&server), "INBOX", 2).unwrap();
    assert_eq!(raw, server.messages()[1]);
    let error = pop3::fetch_raw(&account(&server), "INBOX", 3).unwrap_err();
    assert_eq!(
        operation(error),
        "The server returned no data for message UID 3"
    );
}

#[test]
fn fetch_attachment_returns_payload_or_imap_error() {
    let server = server_with(&[WITH_ATTACHMENT.to_vec()]);
    let attachment = pop3::fetch_attachment(&account(&server), "INBOX", 1, 0).unwrap();
    assert_eq!(attachment.filename, "notes.txt");
    assert_eq!(attachment.content_type, "text/plain");
    assert_eq!(attachment.content, b"attachment text");
    let error = pop3::fetch_attachment(&account(&server), "INBOX", 1, 1).unwrap_err();
    assert_eq!(
        operation(error),
        "Attachment 1 was not found on message UID 1"
    );
    let view = pop3::fetch_message(&account(&server), "INBOX", 1, false, None, None).unwrap();
    assert_eq!(
        view["attachments"],
        json!([{"index": 0, "filename": "notes.txt", "content_type": "text/plain", "size": 15}])
    );
}

// ---------------------------------------------------------------------------
// update_retention
// ---------------------------------------------------------------------------

#[test]
fn update_retention_rejects_missing_or_stale_epoch_without_mutation() {
    let dir = tempfile::tempdir().unwrap();
    let store = RetentionStore::new(dir.path());
    let server = server_with(&[b"From: a@example.com\r\nSubject: Invoice\r\n\r\nx\r\n".to_vec()]);
    let policies = default_category_expiration_days();
    let error = pop3::update_retention(
        &account(&server),
        "INBOX",
        1,
        &store,
        &policies,
        Patch::Set("marketing".into()),
        Patch::Unset,
        None,
    )
    .unwrap_err();
    assert_eq!(
        conflict(error),
        "Message identity is unavailable. Refresh the folder before editing retention."
    );
    assert_eq!(server.connection_count(), 0);
    let current = epoch(&server);
    let stale = if current == "100" { "101" } else { "100" };
    let error = pop3::update_retention(
        &account(&server),
        "INBOX",
        1,
        &store,
        &policies,
        Patch::Set("marketing".into()),
        Patch::Unset,
        Some(stale),
    )
    .unwrap_err();
    assert_eq!(error.status(), 409);
    assert_eq!(
        conflict(error),
        "The mailbox changed. Refresh the folder before editing retention."
    );
    assert!(!store.path().exists());
    assert_eq!(count(&server, "TOP"), 0);
}

#[test]
fn update_retention_reads_headers_only_and_preserves_independent_choices() {
    let dir = tempfile::tempdir().unwrap();
    let store = RetentionStore::new(dir.path());
    let server = server_with(&[b"From: a@example.com\r\nSubject: Invoice\r\n\r\nx\r\n".to_vec()]);
    let policies = default_category_expiration_days();
    let current = epoch(&server);
    pop3::update_retention(
        &account(&server),
        "INBOX",
        1,
        &store,
        &policies,
        Patch::Unset,
        Patch::Set(-1),
        Some(&current),
    )
    .unwrap();
    let view = pop3::update_retention(
        &account(&server),
        "INBOX",
        1,
        &store,
        &policies,
        Patch::Set("marketing".into()),
        Patch::Unset,
        Some(&current),
    )
    .unwrap();
    assert_eq!(view["category"], "marketing");
    assert_eq!(view["category_source"], "manual");
    assert_eq!(view["expires_at"], -1);
    assert_eq!(view["expiration_source"], "manual");
    assert_eq!(view["uid"], 1);
    assert_eq!(view["folder"], "INBOX");
    assert_eq!(view["uid_validity"], current.as_str());
    assert_eq!(view["seen"], false);
    assert_eq!(count(&server, "RETR"), 0);
    assert!(count(&server, "TOP") >= 1);

    // The listing shows the saved choice for the same epoch.
    let page = pop3::list_messages(
        &account(&server),
        "INBOX",
        &ListMessagesOptions {
            retention_store: Some(&store),
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(page["messages"][0]["category"], "marketing");

    // A new arrival changes the synthetic epoch, so the saved per-message
    // choice no longer applies and stale edits are rejected (documented).
    server.add_message(b"From: b@example.com\r\nSubject: hello\r\n\r\nx\r\n".to_vec());
    let page = pop3::list_messages(
        &account(&server),
        "INBOX",
        &ListMessagesOptions {
            retention_store: Some(&store),
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(page["messages"][1]["category_source"], "automatic");
    let error = pop3::update_retention(
        &account(&server),
        "INBOX",
        1,
        &store,
        &policies,
        Patch::Clear,
        Patch::Unset,
        Some(&current),
    )
    .unwrap_err();
    assert_eq!(error.status(), 409);
}

#[test]
fn update_retention_missing_message_and_invalid_category() {
    let dir = tempfile::tempdir().unwrap();
    let store = RetentionStore::new(dir.path());
    let server = server_with(&[b"From: a@example.com\r\nSubject: Invoice\r\n\r\nx\r\n".to_vec()]);
    let policies = default_category_expiration_days();
    let current = epoch(&server);
    let error = pop3::update_retention(
        &account(&server),
        "INBOX",
        2,
        &store,
        &policies,
        Patch::Set("marketing".into()),
        Patch::Unset,
        Some(&current),
    )
    .unwrap_err();
    assert_eq!(operation(error), "Message UID 2 is no longer available");
    assert!(!store.path().exists());
    let error = pop3::update_retention(
        &account(&server),
        "INBOX",
        1,
        &store,
        &policies,
        Patch::Set("custom".into()),
        Patch::Unset,
        Some(&current),
    )
    .unwrap_err();
    assert_eq!(error.status(), 422);
    assert_eq!(
        error.body(),
        json!({"detail": "Choose a valid email category"})
    );
}

#[test]
fn category_and_expired_filters_apply_before_count_and_page() {
    let dir = tempfile::tempdir().unwrap();
    let store = RetentionStore::new(dir.path());
    let messages: Vec<Vec<u8>> = (1..=9)
        .map(|n| {
            let subject = if n % 2 == 1 { "Newsletter" } else { "Invoice" };
            format!(
                "From: a@example.com\r\nSubject: {subject}\r\nDate: Wed, 1 Jan 2020 00:00:00 +0000\r\n\r\nx\r\n"
            )
            .into_bytes()
        })
        .collect();
    let server = server_with(&messages);
    let account = account(&server);
    let current = epoch(&server);
    store
        .update(
            &account,
            "INBOX",
            9,
            &current,
            Patch::Set("transactional".into()),
            Patch::Unset,
        )
        .unwrap();
    store
        .update(&account, "INBOX", 7, &current, Patch::Unset, Patch::Set(-1))
        .unwrap();
    let page = pop3::list_messages(
        &account,
        "INBOX",
        &ListMessagesOptions {
            category: Some("marketing"),
            expired_only: true,
            offset: 1,
            limit: 2,
            retention_store: Some(&store),
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(page["total"], 3);
    assert_eq!(uids(&page), [3, 1]);
    assert!(page["messages"]
        .as_array()
        .unwrap()
        .iter()
        .all(|m| m["category"] == "marketing" && m["expired"] == true));
    // Every candidate's headers were read once; no message bodies.
    assert_eq!(count(&server, "TOP"), 9);
    assert_eq!(count(&server, "RETR"), 0);
}

// ---------------------------------------------------------------------------
// Classification
// ---------------------------------------------------------------------------

#[test]
fn classification_message_guards_identity_and_epoch() {
    let server = server_with(&[INVOICE.to_vec()]);
    for (uid, expected) in [(1, "abc"), (1, "0"), (0, "99")] {
        let error = pop3::fetch_classification_message(&account(&server), "INBOX", uid, expected)
            .unwrap_err();
        assert_eq!(
            conflict(error),
            "Message identity is unavailable. Refresh the folder before classifying."
        );
    }
    assert_eq!(server.connection_count(), 0);
    let current = epoch(&server);
    let stale = if current == "100" { "101" } else { "100" };
    let error =
        pop3::fetch_classification_message(&account(&server), "INBOX", 1, stale).unwrap_err();
    assert_eq!(
        conflict(error),
        "The mailbox changed. Refresh the folder before classifying."
    );
    assert_eq!(count(&server, "RETR"), 0);

    let message =
        pop3::fetch_classification_message(&account(&server), "INBOX", 1, &current).unwrap();
    assert_eq!(message.raw, server.messages()[0]);
    assert_eq!(message.uid_validity, current);
    assert_eq!(
        message.received_at.as_deref(),
        Some("2099-10-14T00:00:00+00:00")
    );
    assert_eq!(message.headers.get("Subject").as_deref(), Some("Invoice"));
    let error =
        pop3::fetch_classification_message(&account(&server), "INBOX", 2, &current).unwrap_err();
    assert_eq!(
        operation(error),
        "The server returned no data for message UID 2"
    );
}

// ---------------------------------------------------------------------------
// Sender rules
// ---------------------------------------------------------------------------

const PERSON: &[u8] =
    b"Received: from mx.example.org by pop.example.com; Tue, 14 Oct 2025 12:00:00 +0000\r\n\
From: Person <PERSON@example.com>\r\nSubject: Invoice\r\n\r\nbody\r\n";

#[test]
fn prepare_sender_rule_uses_message_count_and_headers_only() {
    let server = server_with(&[
        PERSON.to_vec(),
        b"From: other@example.com\r\n\r\nx\r\n".to_vec(),
    ]);
    let current = epoch(&server);
    let prepared = pop3::prepare_sender_rule(&account(&server), "INBOX", 1, &current).unwrap();
    assert_eq!(prepared.sender, "person@example.com");
    assert_eq!(prepared.scope.first_uid, 3);
    assert_eq!(prepared.scope.uid_validity, current);
    assert_eq!(
        prepared.received_at.as_deref(),
        Some("2025-10-14T12:00:00+00:00")
    );
    assert_eq!(count(&server, "RETR"), 0);
    assert_eq!(
        server.commands().iter().filter(|c| *c == "TOP 1 0").count(),
        1
    );
}

#[test]
fn prepare_sender_rule_scope_reads_no_messages() {
    let server = server_with(&[PERSON.to_vec(), PERSON.to_vec(), PERSON.to_vec()]);
    let scope = pop3::prepare_sender_rule_scope(&account(&server), "INBOX").unwrap();
    assert_eq!(scope.first_uid, 4);
    assert_eq!(count(&server, "TOP") + count(&server, "RETR"), 0);
    let empty = server_with(&[]);
    assert_eq!(
        pop3::prepare_sender_rule_scope(&account(&empty), "INBOX")
            .unwrap()
            .first_uid,
        1
    );
    let error = pop3::prepare_sender_rule_scope(&account(&server), "Junk").unwrap_err();
    assert_eq!(operation(error), "The server would not open folder 'Junk'");
}

#[test]
fn prepare_sender_rule_rejects_stale_missing_and_ambiguous_messages() {
    let server = server_with(&[
        PERSON.to_vec(),
        b"From: one@example.com, two@example.com\r\n\r\nx\r\n".to_vec(),
    ]);
    for (uid, expected) in [(1, "abc"), (0, "99"), (4_294_967_296, "99")] {
        let error =
            pop3::prepare_sender_rule(&account(&server), "INBOX", uid, expected).unwrap_err();
        assert_eq!(
            conflict(error),
            "Message identity is unavailable. Refresh before saving a sender rule."
        );
    }
    let current = epoch(&server);
    let stale = if current == "100" { "101" } else { "100" };
    let error = pop3::prepare_sender_rule(&account(&server), "INBOX", 1, stale).unwrap_err();
    assert_eq!(
        conflict(error),
        "The mailbox changed. Refresh before saving a sender rule."
    );
    assert_eq!(count(&server, "TOP"), 0);
    let error = pop3::prepare_sender_rule(&account(&server), "INBOX", 2, &current).unwrap_err();
    assert_eq!(error.status(), 422);
    assert_eq!(
        error.body(),
        json!({"detail": "Sender rules require exactly one valid From email address"})
    );
    let error = pop3::prepare_sender_rule(&account(&server), "INBOX", 3, &current).unwrap_err();
    assert_eq!(operation(error), "Message UID 3 is no longer available");
    server.fail_next("TOP", Failure::Disconnect);
    let error = pop3::prepare_sender_rule(&account(&server), "INBOX", 1, &current).unwrap_err();
    assert_eq!(operation(error), "The server could not fetch message UID 1");
}

#[test]
fn sender_rules_apply_to_later_arrivals_in_list_and_detail() {
    let dir = tempfile::tempdir().unwrap();
    let store = RetentionStore::new(dir.path());
    let old = b"Received: from mx by pop; Wed, 1 Jan 2025 00:00:00 +0000\r\n\
From: person@example.com\r\nSubject: Invoice\r\n\r\nx\r\n";
    let server = server_with(&[old.to_vec(), old.to_vec()]);
    let account = account(&server);
    let prepared = pop3::prepare_sender_rule(&account, "INBOX", 2, &epoch(&server)).unwrap();
    let rule = store
        .save_sender_rule(
            &account,
            "INBOX",
            &prepared.sender,
            "marketing",
            &prepared.scope.uid_validity,
            prepared.scope.first_uid,
            SaveSenderRuleOptions {
                created_at: Some("2025-06-01T00:00:00+00:00"),
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(rule.first_uid, 3);

    // Same epoch: existing messages are below first_uid and keep their category.
    let options = ListMessagesOptions {
        retention_store: Some(&store),
        ..Default::default()
    };
    let page = pop3::list_messages(&account, "INBOX", &options).unwrap();
    assert!(page["messages"]
        .as_array()
        .unwrap()
        .iter()
        .all(|m| m["category"] == "transactional" && m["category_source"] == "automatic"));

    // A later arrival changes the epoch; the rule then applies by arrival time.
    server.add_message(
        b"Received: from mx by pop; Tue, 1 Jul 2025 00:00:00 +0000\r\n\
From: Person <person@example.com>\r\nSubject: Invoice\r\n\r\nx\r\n"
            .to_vec(),
    );
    let page = pop3::list_messages(&account, "INBOX", &options).unwrap();
    assert_eq!(uids(&page), [3, 2, 1]);
    let newest = &page["messages"][0];
    assert_eq!(newest["category"], "marketing");
    assert_eq!(newest["category_source"], "sender_rule");
    assert_eq!(
        newest["category_reason"],
        "Saved sender rule for person@example.com assigned this category"
    );
    assert_eq!(page["messages"][1]["category_source"], "automatic");
    let detail = pop3::fetch_message(&account, "INBOX", 3, false, Some(&store), None).unwrap();
    for field in [
        "category",
        "category_source",
        "category_reason",
        "sender_rule",
        "expiration_days",
        "expires_at",
    ] {
        assert_eq!(newest[field], detail[field], "{field}");
    }
    let filtered = pop3::list_messages(
        &account,
        "INBOX",
        &ListMessagesOptions {
            category: Some("marketing"),
            retention_store: Some(&store),
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(uids(&filtered), [3]);
}
