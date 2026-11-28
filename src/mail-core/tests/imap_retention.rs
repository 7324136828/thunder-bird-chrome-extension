//! Port of the IMAP integration tests of tests/test_retention.py
//! (`RetentionImapTests`) and tests/test_sender_rules.py
//! (`SenderRuleImapTests`) against the fake IMAP server.
//!
//! The Python tests also spied on `RetentionStore.get_many` /
//! `get_sender_rules_for_folder` call counts; those internals have no Rust
//! analogue, so the observable results (totals, pages, batches) are checked.

mod imap_support;

use std::collections::BTreeMap;

use imap_support::{account, fetch_items, fetch_sets, lines_named, mail_commands, message, server};
use mail_core::error::MailError;
use mail_core::imap::{self, ListMessagesOptions};
use mail_core::model::default_category_expiration_days;
use mail_core::retention::{Patch, RetentionStore, SaveSenderRuleOptions};
use mail_proto::imap::Status;
use mail_proto::testkit::{FakeImapServer, HookAction};
use serde_json::json;

const CREATED: &str = "2026-10-14T12:00:00+00:00";

fn policies() -> BTreeMap<String, i64> {
    default_category_expiration_days()
}

fn store() -> (tempfile::TempDir, RetentionStore) {
    let directory = tempfile::tempdir().unwrap();
    let store = RetentionStore::new(directory.path());
    (directory, store)
}

fn epoch_server(epoch: Option<u32>, messages: &[(u32, &str)]) -> FakeImapServer {
    let mut builder = server().uid_validity("INBOX", epoch);
    for (uid, raw) in messages {
        builder = builder.message_with("INBOX", message(*uid, raw.as_bytes().to_vec()));
    }
    builder.start()
}

fn conflict_message(error: MailError) -> String {
    match error {
        MailError::RetentionConflict(message) => message,
        other => panic!("expected RetentionConflictError, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// RetentionImapTests
// ---------------------------------------------------------------------------

#[test]
fn filters_apply_before_count_and_page_in_bounded_peek_batches() {
    let mut builder = server().uid_validity("INBOX", Some(99));
    for uid in 1..=451u32 {
        let subject = if uid % 2 == 1 {
            "Newsletter"
        } else {
            "Invoice"
        };
        builder = builder.message_with(
            "INBOX",
            message(uid, format!("Subject: {subject}\r\n\r\n").into_bytes()),
        );
    }
    let server = builder.start();
    let (_directory, store) = store();
    let account = account(&server);
    store
        .update(
            &account,
            "INBOX",
            449,
            "99",
            Patch::Set("transactional".into()),
            Patch::Unset,
        )
        .unwrap();
    store
        .update(&account, "INBOX", 451, "99", Patch::Unset, Patch::Set(-1))
        .unwrap();
    let result = imap::list_messages(
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
    assert_eq!(result["total"], 224);
    let uids: Vec<u64> = result["messages"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m["uid"].as_u64().unwrap())
        .collect();
    assert_eq!(uids, [445, 443]);
    let sizes: Vec<usize> = fetch_sets(&server)
        .iter()
        .map(|set| set.split(',').count())
        .collect();
    assert_eq!(sizes, [200, 200, 51]);
    assert!(fetch_items(&server).iter().all(
        |items| items.contains("BODY.PEEK[HEADER.FIELDS") && items.contains("LIST-UNSUBSCRIBE")
    ));
    assert_eq!(mail_commands(&server)[0], "EXAMINE \"INBOX\"");
    assert!(lines_named(&server, "UID STORE").is_empty());
    let first = &result["messages"][0];
    assert_eq!(first["category"], "marketing");
    assert_eq!(first["expired"], true);
    assert_eq!(first["uid_validity"], "99");
}

#[test]
fn list_and_detail_use_same_headers_and_internaldate() {
    let raw = "Subject: Invoice\r\nDate: Tue, 1 Jan 2000 00:00:00 +0000\r\nList-Unsubscribe: <https://example.com>\r\nPrecedence: bulk\r\n\r\nVerification code in body";
    let server = server()
        .uid_validity("INBOX", Some(99))
        .message_with(
            "INBOX",
            message(42, raw).with_internal_date("14-Oct-2099 00:00:00 +0000"),
        )
        .start();
    let (_directory, store) = store();
    let account = account(&server);
    let page = imap::list_messages(
        &account,
        "INBOX",
        &ListMessagesOptions {
            retention_store: Some(&store),
            ..Default::default()
        },
    )
    .unwrap();
    let summary = &page["messages"][0];
    let detail = imap::fetch_message(&account, "INBOX", 42, false, Some(&store), None).unwrap();
    for field in [
        "category",
        "category_source",
        "category_reason",
        "expiration_days",
        "expires_at",
        "expired",
        "received_at",
        "uid_validity",
    ] {
        assert_eq!(summary[field], detail[field], "{field}");
    }
    assert_eq!(detail["category"], "transactional");
    assert_eq!(detail["expired"], false);
    assert_eq!(detail["received_at"], "2099-10-14T00:00:00+00:00");
    assert_eq!(detail["uid_validity"], "99");
    // Python omitted INTERNALDATE; the fake always sends one, so send an
    // unparsable value instead: the expiry is unknown and never "expired".
    server.with_folders(|folders| {
        let inbox = folders.iter_mut().find(|f| f.name == "INBOX").unwrap();
        inbox.messages[0].internal_date = "not a date".into();
    });
    let detail = imap::fetch_message(&account, "INBOX", 42, false, None, None).unwrap();
    assert_eq!(detail["expires_at"], json!(null));
    assert_eq!(detail["expired"], false);
    assert_eq!(detail["received_at"], json!(null));
}

#[test]
fn missing_epoch_rejects_filters_and_stale_edit_without_mutation() {
    for epoch in [None, Some(100)] {
        let server = epoch_server(epoch, &[(42, "Subject: Invoice\r\n\r\n")]);
        let (_directory, store) = store();
        let account = account(&server);
        let error = imap::update_retention(
            &account,
            "INBOX",
            42,
            &store,
            &policies(),
            Patch::Set("marketing".into()),
            Patch::Unset,
            Some("99"),
        )
        .unwrap_err();
        assert_eq!(
            conflict_message(error),
            "The mailbox changed. Refresh the folder before editing retention."
        );
        if epoch.is_none() {
            let error = imap::list_messages(
                &account,
                "INBOX",
                &ListMessagesOptions {
                    expired_only: true,
                    ..Default::default()
                },
            )
            .unwrap_err();
            assert_eq!(
                conflict_message(error),
                "Mailbox identity is unavailable. Refresh the folder before filtering retention."
            );
        }
        assert!(!store.path().exists());
        assert!(!mail_commands(&server)
            .iter()
            .any(|c| c.starts_with("UID FETCH") || c.starts_with("UID STORE")));
    }
}

#[test]
fn update_requires_a_known_expected_epoch_before_connecting() {
    let server = epoch_server(Some(99), &[(42, "Subject: Invoice\r\n\r\n")]);
    let (_directory, store) = store();
    for expected in [None, Some("abc"), Some("0")] {
        let error = imap::update_retention(
            &account(&server),
            "INBOX",
            42,
            &store,
            &policies(),
            Patch::Set("marketing".into()),
            Patch::Unset,
            expected,
        )
        .unwrap_err();
        assert_eq!(
            conflict_message(error),
            "Message identity is unavailable. Refresh the folder before editing retention."
        );
    }
    assert_eq!(server.connection_count(), 0);
}

#[test]
fn update_reads_headers_only_and_preserves_independent_choices() {
    let server = epoch_server(Some(99), &[(42, "Subject: Invoice\r\n\r\n")]);
    let (_directory, store) = store();
    let account = account(&server);
    imap::update_retention(
        &account,
        "INBOX",
        42,
        &store,
        &policies(),
        Patch::Unset,
        Patch::Set(-1),
        Some("99"),
    )
    .unwrap();
    let view = imap::update_retention(
        &account,
        "INBOX",
        42,
        &store,
        &policies(),
        Patch::Set("marketing".into()),
        Patch::Unset,
        Some("99"),
    )
    .unwrap();
    assert_eq!(
        (&view["category"], &view["expires_at"]),
        (&json!("marketing"), &json!(-1))
    );
    assert_eq!(view["uid"], 42);
    assert_eq!(view["folder"], "INBOX");
    assert_eq!(view["category_source"], "manual");
    assert_eq!(view["expiration_source"], "manual");
    assert!(lines_named(&server, "SELECT").is_empty());
    assert_eq!(lines_named(&server, "EXAMINE").len(), 2);
    assert!(fetch_items(&server)
        .iter()
        .all(|items| items.contains("BODY.PEEK[HEADER.FIELDS")));
    assert!(lines_named(&server, "UID STORE").is_empty());
}

#[test]
fn update_of_a_vanished_message_saves_nothing() {
    let server = epoch_server(Some(99), &[(42, "Subject: Invoice\r\n\r\n")]);
    let (_directory, store) = store();
    let error = imap::update_retention(
        &account(&server),
        "INBOX",
        43,
        &store,
        &policies(),
        Patch::Set("marketing".into()),
        Patch::Unset,
        Some("99"),
    )
    .unwrap_err();
    assert!(
        matches!(error, MailError::Operation(ref m) if m == "Message UID 43 is no longer available")
    );
    assert!(store
        .get(&account(&server), "INBOX", 43, Some("99"))
        .unwrap()
        .is_none());
}

// ---------------------------------------------------------------------------
// SenderRuleImapTests
// ---------------------------------------------------------------------------

#[test]
fn prepare_uses_entire_folder_uidnext_and_peek_headers_only() {
    let server = server()
        .uid_validity("INBOX", Some(99))
        .message_with(
            "INBOX",
            message(
                42,
                "From: Person <PERSON@example.com>\r\nSubject: Invoice\r\n\r\n",
            )
            .with_internal_date("14-Oct-2026 12:00:00 +0000"),
        )
        .message_with("INBOX", message(99, "From: other@example.com\r\n\r\n"))
        .start();
    let prepared = imap::prepare_sender_rule(&account(&server), "INBOX", 42, "99").unwrap();
    assert_eq!(
        (
            prepared.sender.as_str(),
            prepared.scope.first_uid,
            prepared.scope.uid_validity.as_str()
        ),
        ("person@example.com", 100, "99")
    );
    assert_eq!(prepared.received_at.as_deref(), Some(CREATED));
    assert_eq!(prepared.headers.get("Subject").as_deref(), Some("Invoice"));
    assert_eq!(mail_commands(&server)[0], "EXAMINE \"INBOX\"");
    assert!(fetch_items(&server)
        .iter()
        .all(|items| items.contains("BODY.PEEK[HEADER.FIELDS")));
    assert!(lines_named(&server, "UID STORE").is_empty());
    assert!(lines_named(&server, "UID SEARCH").contains(&"UID SEARCH ALL".to_string()));
    assert_eq!(server.logout_count(), 1);
}

/// A server whose EXAMINE omits `[UIDNEXT]`; UID SEARCH / UID FETCH are
/// answered by the hook too because the hooked EXAMINE selects nothing.
fn server_without_uidnext() -> FakeImapServer {
    server()
        .hook(|request| match request.command.as_str() {
            "EXAMINE" => HookAction::Respond {
                untagged: vec![
                    b"* FLAGS (\\Seen)".to_vec(),
                    b"* 2 EXISTS".to_vec(),
                    b"* OK [UIDVALIDITY 99] UIDs valid".to_vec(),
                ],
                status: Status::Ok,
                text: "[READ-ONLY] EXAMINE completed".into(),
            },
            "UID SEARCH" => HookAction::Respond {
                untagged: vec![b"* SEARCH 42 901".to_vec()],
                status: Status::Ok,
                text: "SEARCH completed".into(),
            },
            "UID FETCH" => {
                let header = b"From: person@example.com\r\n\r\n";
                let mut line = format!(
                    "* 1 FETCH (UID 42 INTERNALDATE \"14-Oct-2026 12:00:00 +0000\" BODY[HEADER.FIELDS (FROM)] {{{}}}\r\n",
                    header.len()
                )
                .into_bytes();
                line.extend_from_slice(header);
                line.push(b')');
                HookAction::Respond {
                    untagged: vec![line],
                    status: Status::Ok,
                    text: "FETCH completed".into(),
                }
            }
            _ => HookAction::Continue,
        })
        .start()
}

#[test]
fn missing_uidnext_scans_all_uids_and_scope_does_not_fetch_bodies() {
    let server = server_without_uidnext();
    let result = imap::prepare_sender_rule(&account(&server), "INBOX", 42, "99").unwrap();
    assert_eq!(result.scope.first_uid, 902);
    assert_eq!(result.sender, "person@example.com");
    assert!(lines_named(&server, "UID SEARCH").contains(&"UID SEARCH ALL".to_string()));
    server.clear_log();
    let scope = imap::prepare_sender_rule_scope(&account(&server), "INBOX").unwrap();
    assert_eq!(scope.uid_validity, "99");
    assert_eq!(scope.first_uid, 902);
    assert!(lines_named(&server, "UID FETCH").is_empty());
}

#[test]
fn stale_epoch_and_missing_or_ambiguous_message_reject_before_storage() {
    for epoch in [None, Some(100)] {
        let server = epoch_server(epoch, &[(42, "From: person@example.com\r\n\r\n")]);
        let error = imap::prepare_sender_rule(&account(&server), "INBOX", 42, "99").unwrap_err();
        let message = conflict_message(error);
        if epoch.is_none() {
            assert_eq!(
                message,
                "Mailbox identity is unavailable. Refresh before editing sender rules."
            );
        } else {
            assert_eq!(
                message,
                "The mailbox changed. Refresh before saving a sender rule."
            );
        }
        assert!(lines_named(&server, "UID FETCH").is_empty());
    }
    let server = epoch_server(
        Some(99),
        &[(42, "From: one@example.com, two@example.com\r\n\r\n")],
    );
    let error = imap::prepare_sender_rule(&account(&server), "INBOX", 42, "99").unwrap_err();
    assert_eq!(error.status(), 422);
    assert_eq!(
        error.to_string(),
        "Sender rules require exactly one valid From email address"
    );
    let error = imap::prepare_sender_rule(&account(&server), "INBOX", 43, "99").unwrap_err();
    assert!(
        matches!(error, MailError::Operation(ref m) if m == "Message UID 43 is no longer available")
    );
}

#[test]
fn invalid_message_identity_is_rejected_before_connecting() {
    let server = epoch_server(Some(99), &[(42, "From: person@example.com\r\n\r\n")]);
    for (uid, epoch) in [
        (0, "99"),
        (-1, "99"),
        (4_294_967_296, "99"),
        (42, "x"),
        (42, ""),
    ] {
        let error = imap::prepare_sender_rule(&account(&server), "INBOX", uid, epoch).unwrap_err();
        assert_eq!(
            conflict_message(error),
            "Message identity is unavailable. Refresh before saving a sender rule."
        );
    }
    assert_eq!(server.connection_count(), 0);
}

#[test]
fn stale_uidnext_cannot_reclassify_existing_uninspected_mail() {
    let server = epoch_server(
        Some(99),
        &[
            (1, "From: person@example.com\r\n\r\n"),
            (2, "From: person@example.com\r\n\r\n"),
            (3, "From: person@example.com\r\n\r\n"),
        ],
    );
    server.with_folders(|folders| {
        folders
            .iter_mut()
            .find(|f| f.name == "INBOX")
            .unwrap()
            .uid_next = 2;
    });
    let prepared = imap::prepare_sender_rule(&account(&server), "INBOX", 1, "99").unwrap();
    assert_eq!(prepared.scope.first_uid, 4);
    // The fake cannot store UID 4294967295 (its UIDNEXT would overflow), so
    // the SEARCH answer is injected.
    server.set_hook(|request| {
        if request.command == "UID SEARCH" {
            HookAction::Respond {
                untagged: vec![b"* SEARCH 1 2 3 4294967295".to_vec()],
                status: Status::Ok,
                text: "SEARCH completed".into(),
            }
        } else {
            HookAction::Continue
        }
    });
    let error = imap::prepare_sender_rule_scope(&account(&server), "INBOX").unwrap_err();
    assert_eq!(
        conflict_message(error),
        "The mailbox UID sequence is exhausted. Refresh before editing sender rules."
    );
}

#[test]
fn unparsable_search_results_never_produce_a_scope() {
    let server = epoch_server(Some(99), &[(1, "From: person@example.com\r\n\r\n")]);
    server.set_hook(|request| {
        if request.command == "UID SEARCH" {
            HookAction::Respond {
                untagged: vec![b"* SEARCH 1 0".to_vec()],
                status: Status::Ok,
                text: "SEARCH completed".into(),
            }
        } else {
            HookAction::Continue
        }
    });
    let error = imap::prepare_sender_rule_scope(&account(&server), "INBOX").unwrap_err();
    assert_eq!(
        conflict_message(error),
        "Future message identity is unavailable. Refresh before editing sender rules."
    );
}

#[test]
fn rules_apply_before_filters_and_pagination() {
    let (_directory, store) = store();
    let mut builder = server().uid_validity("INBOX", Some(99));
    for uid in 1..=450u32 {
        builder = builder.message_with(
            "INBOX",
            message(uid, "From: person@example.com\r\nSubject: Invoice\r\n\r\n"),
        );
    }
    let server = builder.start();
    let account = account(&server);
    store
        .save_sender_rule(
            &account,
            "INBOX",
            "person@example.com",
            "marketing",
            "99",
            400,
            SaveSenderRuleOptions {
                created_at: Some(CREATED),
                ..Default::default()
            },
        )
        .unwrap();
    let page = imap::list_messages(
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
    let detail = imap::fetch_message(&account, "INBOX", 449, false, Some(&store), None).unwrap();
    assert_eq!(page["total"], 51);
    let uids: Vec<u64> = page["messages"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m["uid"].as_u64().unwrap())
        .collect();
    assert_eq!(uids, [449, 448]);
    assert_eq!(page["messages"][0]["category_source"], "sender_rule");
    for field in [
        "category",
        "category_source",
        "category_reason",
        "sender_rule",
        "expiration_days",
        "expires_at",
    ] {
        assert_eq!(page["messages"][0][field], detail[field], "{field}");
    }
    assert_eq!(
        detail["category_reason"],
        "Saved sender rule for person@example.com assigned this category"
    );
}

#[test]
fn classification_message_is_guarded_by_the_epoch_and_leaves_flags() {
    let server = epoch_server(
        Some(99),
        &[(
            42,
            "From: person@example.com\r\nSubject: Hi\r\n\r\nBody\r\n",
        )],
    );
    let message =
        imap::fetch_classification_message(&account(&server), "INBOX", 42, "099").unwrap();
    assert_eq!(message.uid_validity, "99");
    assert!(message.raw.ends_with(b"Body\r\n"));
    assert_eq!(message.headers.get("Subject").as_deref(), Some("Hi"));
    assert_eq!(
        message.received_at.as_deref(),
        Some("2020-01-01T00:00:00+00:00")
    );
    assert!(server.flags("INBOX", 42).unwrap().is_empty());
    assert!(lines_named(&server, "SELECT").is_empty());

    let error =
        imap::fetch_classification_message(&account(&server), "INBOX", 42, "100").unwrap_err();
    assert_eq!(
        conflict_message(error),
        "The mailbox changed. Refresh the folder before classifying."
    );
    let connections = server.connection_count();
    for (uid, epoch) in [(0, "99"), (42, "nope")] {
        let error =
            imap::fetch_classification_message(&account(&server), "INBOX", uid, epoch).unwrap_err();
        assert_eq!(
            conflict_message(error),
            "Message identity is unavailable. Refresh the folder before classifying."
        );
    }
    assert_eq!(server.connection_count(), connections);
}

#[test]
fn hooked_select_counts_are_consistent() {
    // Sanity check for the hook-based servers above: every operation opens
    // exactly one connection and logs out.
    let server = server_without_uidnext();
    for _ in 0..2 {
        imap::prepare_sender_rule_scope(&account(&server), "INBOX").unwrap();
    }
    assert_eq!(server.connection_count(), 2);
    assert_eq!(server.logout_count(), 2);
}
