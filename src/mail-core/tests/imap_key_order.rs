//! JSON key order of the IMAP result dicts. serde_json keeps insertion order
//! (`preserve_order`), so the dicts must be built in the same order as the
//! Python dict literals of `imap_client.py` (`_fetch_summaries`,
//! `fetch_message`'s `view.update(...)`, `set_flags`, `update_retention`).

mod imap_support;

use imap_support::{account, message, server};
use mail_core::imap::{self, ListMessagesOptions};
use mail_core::retention::{Patch, RetentionStore};
use serde_json::Value;

const RAW: &str = "From: Sender <sender@example.com>\r\n\
To: user@example.com\r\n\
Subject: Hello\r\n\
Date: Mon, 13 Oct 2026 09:59:40 +0000\r\n\
\r\n\
Body\r\n";

/// `_fetch_summaries` dict keys before `**metadata`.
const SUMMARY_KEYS: [&str; 11] = [
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
    "date",
];

/// `retention_metadata` keys (the `**metadata` tail).
const METADATA_KEYS: [&str; 11] = [
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
];

fn keys(value: &Value) -> Vec<&str> {
    value
        .as_object()
        .expect("object")
        .keys()
        .map(String::as_str)
        .collect()
}

fn assert_metadata_tail(keys: &[&str], from: usize) {
    // Only the keys retention_metadata produces, in its order; check the
    // known prefix so later additions to the metadata do not break this test.
    let tail = &keys[from..];
    let expected: Vec<&str> = METADATA_KEYS
        .iter()
        .copied()
        .filter(|key| tail.contains(key))
        .collect();
    let actual: Vec<&str> = tail
        .iter()
        .copied()
        .filter(|key| METADATA_KEYS.contains(key))
        .collect();
    assert_eq!(actual, expected);
    assert!(tail.starts_with(&["category"]), "{tail:?}");
}

#[test]
fn list_summaries_follow_python_key_order() {
    let server = server()
        .uid_validity("INBOX", Some(9))
        .message_with("INBOX", message(3, RAW).with_flags(&["\\Seen"]))
        .start();
    let result =
        imap::list_messages(&account(&server), "INBOX", &ListMessagesOptions::default()).unwrap();
    assert_eq!(keys(&result), ["total", "offset", "limit", "messages"]);
    let summary = &result["messages"][0];
    let names = keys(summary);
    assert_eq!(&names[..SUMMARY_KEYS.len()], SUMMARY_KEYS);
    assert_metadata_tail(&names, SUMMARY_KEYS.len());
}

#[test]
fn message_view_follows_python_key_order() {
    let server = server()
        .uid_validity("INBOX", Some(9))
        .message_with("INBOX", message(3, RAW))
        .start();
    let view = imap::fetch_message(&account(&server), "INBOX", 3, false, None, None).unwrap();
    let names = keys(&view);
    let header_keys = [
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
    ];
    assert_eq!(&names[..header_keys.len()], header_keys);
    let rest = &names[header_keys.len()..];
    assert_eq!(&rest[..5], ["uid", "folder", "flags", "seen", "flagged"]);
    assert_metadata_tail(&names, header_keys.len() + 5);
}

#[test]
fn set_flags_result_follows_python_key_order() {
    let server = server()
        .uid_validity("INBOX", Some(9))
        .message_with("INBOX", message(3, RAW))
        .start();
    let result = imap::set_flags(&account(&server), "INBOX", 3, Some(true), None).unwrap();
    assert_eq!(keys(&result), ["uid", "flags", "seen", "flagged"]);
}

#[test]
fn update_retention_result_follows_python_key_order() {
    let server = server()
        .uid_validity("INBOX", Some(9))
        .message_with("INBOX", message(3, RAW))
        .start();
    let dir = tempfile::tempdir().unwrap();
    let store = RetentionStore::new(dir.path());
    let policies = mail_core::model::default_category_expiration_days();
    let result = imap::update_retention(
        &account(&server),
        "INBOX",
        3,
        &store,
        &policies,
        Patch::Set("marketing".to_string()),
        Patch::Unset,
        Some("9"),
    )
    .unwrap();
    let names = keys(&result);
    // {"uid", "folder", **summary}: the summary's "uid" keeps position 0.
    assert_eq!(names[0], "uid");
    assert_eq!(names[1], "folder");
    assert_eq!(&names[2..SUMMARY_KEYS.len() + 1], &SUMMARY_KEYS[1..]);
    assert_eq!(result["category"], "marketing");
}
