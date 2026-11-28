//! Port of `BulkDeletionTests` (tests/test_mail.py) and the delete guard of
//! `RetentionImapTests` (tests/test_retention.py) against the fake IMAP
//! server instead of a patched `connect`.

mod imap_support;

use imap_support::{account, account_at, mail_commands, message, pop3_account, server};
use mail_core::error::MailError;
use mail_core::imap;
use mail_proto::testkit::{Failure, FakeImapServer};

fn deletion_server(capabilities: &[&str]) -> FakeImapServer {
    server()
        .capabilities(capabilities)
        // No CAPABILITY round trips besides the one delete_messages sends.
        .greeting_capabilities(true)
        .login_capability_code(true)
        .folder("Trash", &["\\Trash"])
        .message_with("INBOX", message(7, "Subject: seven\r\n\r\nbody\r\n"))
        .message_with(
            "INBOX",
            message(11, "Subject: eleven\r\n\r\nbody\r\n").with_flags(&["\\Seen"]),
        )
        .message_with(
            "INBOX",
            message(99, "Subject: unrelated\r\n\r\nbody\r\n").with_flags(&["\\Deleted"]),
        )
        .start()
}

fn delete(server: &FakeImapServer, uids: &[u32], trash: &str) -> mail_core::Result<Vec<u32>> {
    let result = imap::delete_messages(&account(server), "INBOX", uids, trash, None);
    assert_eq!(server.connection_count(), 1);
    result
}

fn trash_subjects(server: &FakeImapServer) -> Vec<String> {
    let mut subjects: Vec<String> = server
        .folder("Trash")
        .map(|f| f.messages)
        .unwrap_or_default()
        .iter()
        .map(|m| {
            String::from_utf8_lossy(&m.raw)
                .lines()
                .next()
                .unwrap_or_default()
                .to_string()
        })
        .collect();
    subjects.sort();
    subjects
}

fn operation_message(error: MailError) -> String {
    match error {
        MailError::Operation(message) => message,
        other => panic!("expected MailOperationError, got {other:?}"),
    }
}

#[test]
fn move_removes_selected_messages_from_server_and_deduplicates() {
    let server = deletion_server(&["IMAP4rev1", "move"]);
    let result = delete(&server, &[11, 7, 11], "Trash").unwrap();
    assert_eq!(result, vec![11, 7]);
    assert_eq!(
        trash_subjects(&server),
        ["Subject: eleven", "Subject: seven"]
    );
    assert_eq!(server.uids("INBOX"), vec![99]);
    assert!(server.message("INBOX", 99).unwrap().has_flag("\\Deleted"));
    assert_eq!(
        mail_commands(&server),
        ["SELECT \"INBOX\"", "UID MOVE 11,7 \"Trash\""]
    );
    assert_eq!(server.logout_count(), 1);
}

#[test]
fn uidplus_fallback_keeps_unrelated_deleted_messages_on_server() {
    let server = deletion_server(&["IMAP4rev1", "UIDPLUS"]);
    let result = delete(&server, &[7, 11], "Trash").unwrap();
    assert_eq!(result, vec![7, 11]);
    assert_eq!(trash_subjects(&server).len(), 2);
    assert_eq!(server.uids("INBOX"), vec![99]);
    assert_eq!(
        mail_commands(&server),
        [
            "SELECT \"INBOX\"",
            "UID COPY 7,11 \"Trash\"",
            "UID STORE 7,11 +FLAGS.SILENT (\\Deleted)",
            "UID EXPUNGE 7,11",
        ]
    );
    assert_eq!(server.logout_count(), 1);
}

#[test]
fn permanent_deletion_also_targets_only_selected_messages() {
    for trash in ["", "INBOX"] {
        let server = deletion_server(&["IMAP4rev1", "UIDPLUS"]);
        delete(&server, &[7, 11], trash).unwrap();
        assert!(trash_subjects(&server).is_empty(), "trash={trash:?}");
        assert_eq!(server.uids("INBOX"), vec![99]);
        assert!(!mail_commands(&server)
            .iter()
            .any(|c| c.starts_with("UID COPY")));
    }
}

#[test]
fn rev2_includes_move_and_uid_expunge() {
    for trash in ["Trash", ""] {
        let server = deletion_server(&["IMAP4rev2"]);
        delete(&server, &[7, 11], trash).unwrap();
        assert_eq!(server.uids("INBOX"), vec![99], "trash={trash:?}");
    }
}

#[test]
fn unsupported_server_fails_before_mutating_messages() {
    for (capabilities, trash) in [
        (&["IMAP4rev1"][..], "Trash"),
        (&["IMAP4rev1", "MOVE"][..], ""),
    ] {
        let server = deletion_server(capabilities);
        let message = operation_message(delete(&server, &[7, 11], trash).unwrap_err());
        assert!(message.contains("MOVE or UIDPLUS"), "{message}");
        assert_eq!(server.uids("INBOX"), vec![7, 11, 99]);
        assert!(trash_subjects(&server).is_empty());
        assert!(mail_commands(&server).is_empty());
        assert_eq!(server.logout_count(), 1);
    }
}

#[test]
fn capability_or_folder_rejection_fails_without_deleting() {
    for command in ["CAPABILITY", "SELECT"] {
        let server = deletion_server(&["IMAP4rev1", "MOVE", "UIDPLUS"]);
        server.fail_next(command, Failure::no());
        let error = delete(&server, &[7, 11], "Trash").unwrap_err();
        let message = operation_message(error);
        if command == "CAPABILITY" {
            assert_eq!(message, "The server could not report its mail capabilities");
        } else {
            assert_eq!(message, "The server would not open folder 'INBOX'");
        }
        assert_eq!(server.uids("INBOX"), vec![7, 11, 99]);
        assert!(trash_subjects(&server).is_empty());
        assert_eq!(server.logout_count(), 1);
    }
}

#[test]
fn rejected_copy_store_or_uid_expunge_never_reports_success() {
    for (command, failure) in [
        ("UID COPY", Failure::no()),
        ("UID STORE", Failure::bad()),
        ("UID EXPUNGE", Failure::no()),
    ] {
        let server = deletion_server(&["IMAP4rev1", "UIDPLUS"]);
        server.fail_next(command, failure);
        let message = operation_message(delete(&server, &[7, 11], "Trash").unwrap_err());
        assert_eq!(server.uids("INBOX"), vec![7, 11, 99]);
        assert!(server.message("INBOX", 99).unwrap().has_flag("\\Deleted"));
        assert!(mail_commands(&server).last().unwrap().starts_with(command));
        assert_eq!(server.logout_count(), 1);
        if command == "UID COPY" {
            assert!(trash_subjects(&server).is_empty());
            assert!(!message.contains("were copied"), "{message}");
            assert_eq!(
                message,
                "The server could not copy the selected messages to 'Trash'"
            );
        } else {
            assert_eq!(trash_subjects(&server).len(), 2);
            assert!(message.contains("were copied to 'Trash'"), "{message}");
            assert!(message.contains("Check Trash before retrying"), "{message}");
        }
    }
}

#[test]
fn partial_move_error_is_not_retried_with_copy_or_expunge() {
    let server = deletion_server(&["IMAP4rev1", "MOVE", "UIDPLUS"]);
    server.fail_next("UID MOVE", Failure::No("only one message moved".into()));
    let message = operation_message(delete(&server, &[7, 11], "Trash").unwrap_err());
    assert_eq!(
        message,
        "The server could not move all selected messages to 'Trash'. Refresh the folder before retrying."
    );
    let names: Vec<String> = mail_commands(&server)
        .iter()
        .map(|c| c.split(' ').take(2).collect::<Vec<_>>().join(" "))
        .collect();
    assert_eq!(names, ["SELECT \"INBOX\"", "UID MOVE"]);
    assert_eq!(server.logout_count(), 1);
}

#[test]
fn protocol_and_network_errors_are_safe_api_errors() {
    for failure in [Failure::Bad("BAD command".into()), Failure::Disconnect] {
        let disconnect = failure == Failure::Disconnect;
        let server = deletion_server(&["IMAP4rev1", "MOVE", "UIDPLUS"]);
        server.fail_next("UID MOVE", failure);
        let message = operation_message(delete(&server, &[7, 11], "Trash").unwrap_err());
        assert_eq!(
            message,
            "The server connection failed while deleting messages. Refresh the folder before retrying."
        );
        if !disconnect {
            assert_eq!(server.logout_count(), 1);
        }
    }
}

#[test]
fn post_copy_connection_errors_warn_to_check_trash_before_retrying() {
    for command in ["UID STORE", "UID EXPUNGE"] {
        for failure in [Failure::Bad("BAD command".into()), Failure::Disconnect] {
            let disconnect = failure == Failure::Disconnect;
            let server = deletion_server(&["IMAP4rev1", "UIDPLUS"]);
            server.fail_next(command, failure);
            let message = operation_message(delete(&server, &[7, 11], "Trash").unwrap_err());
            assert_eq!(trash_subjects(&server).len(), 2);
            assert_eq!(server.uids("INBOX"), vec![7, 11, 99]);
            assert_eq!(
                message,
                "The messages were copied to 'Trash', but removing them from the original \
                 folder failed. Check Trash before retrying."
            );
            if !disconnect {
                assert_eq!(server.logout_count(), 1);
            }
        }
    }
}

#[test]
fn invalid_uids_are_rejected_before_connecting() {
    // Python also rejected negatives, bools, strings and values above
    // 2**32-1; `&[u32]` makes those unrepresentable.
    let server = deletion_server(&["IMAP4rev1", "MOVE", "UIDPLUS"]);
    let too_many: Vec<u32> = (1..=501).collect();
    for uids in [&[][..], &[0][..], &[7, 0][..], &too_many[..]] {
        let error = imap::delete_messages(&account(&server), "INBOX", uids, "", None).unwrap_err();
        assert_eq!(
            operation_message(error),
            "Select between 1 and 500 valid message UIDs"
        );
    }
    assert_eq!(server.connection_count(), 0);
}

#[test]
fn maximum_batch_is_accepted() {
    let server = deletion_server(&["IMAP4rev1", "MOVE", "UIDPLUS"]);
    let uids: Vec<u32> = [7, 11].into_iter().chain(1000..1498).collect();
    let result = imap::delete_messages(&account(&server), "INBOX", &uids, "Trash", None).unwrap();
    assert_eq!(result.len(), 500);
    assert_eq!(server.uids("INBOX"), vec![99]);
}

#[test]
fn single_message_delete_keeps_public_behavior() {
    let server = deletion_server(&["IMAP4rev1", "MOVE", "UIDPLUS"]);
    imap::delete_message(&account(&server), "INBOX", 7, "Trash", None).unwrap();
    assert_eq!(trash_subjects(&server), ["Subject: seven"]);
    assert_eq!(server.uids("INBOX"), vec![11, 99]);
    assert_eq!(server.logout_count(), 1);
}

#[test]
fn delete_guard_checks_epoch_before_any_mutation() {
    for epoch in [None, Some(100)] {
        let server = server()
            .uid_validity("INBOX", epoch)
            .folder("Trash", &["\\Trash"])
            .message_with("INBOX", message(42, "Subject: Invoice\r\n\r\n"))
            .start();
        let error = imap::delete_messages(&account(&server), "INBOX", &[42], "Trash", Some("99"))
            .unwrap_err();
        assert!(
            matches!(error, MailError::RetentionConflict(ref m)
            if m == "The mailbox changed. Refresh the folder before deleting messages."),
            "{error:?}"
        );
        assert!(!mail_commands(&server)
            .iter()
            .any(|c| c.starts_with("UID MOVE")
                || c.starts_with("UID COPY")
                || c.starts_with("UID STORE")
                || c.starts_with("UID EXPUNGE")));
        assert_eq!(server.logout_count(), 1);
    }
    let server = server()
        .uid_validity("INBOX", Some(99))
        .folder("Trash", &["\\Trash"])
        .message_with("INBOX", message(42, "Subject: Invoice\r\n\r\n"))
        .start();
    let result =
        imap::delete_messages(&account(&server), "INBOX", &[42], "Trash", Some("99")).unwrap();
    assert_eq!(result, vec![42]);
    assert!(mail_commands(&server).contains(&"UID MOVE 42 \"Trash\"".to_string()));
}

#[test]
fn malformed_expected_epoch_is_rejected_before_connecting() {
    let account = account_at(1);
    let error = imap::delete_messages(&account, "INBOX", &[42], "Trash", Some("abc")).unwrap_err();
    assert!(matches!(error, MailError::RetentionConflict(ref m)
        if m == "Message identity is unavailable. Refresh the folder before deleting."));
    assert_eq!(error.status(), 409);
}

#[test]
fn connection_failures_are_operation_errors() {
    let server = deletion_server(&["IMAP4rev1", "MOVE", "UIDPLUS"]);
    let mut wrong = account(&server);
    wrong.password = "wrong-password".into();
    let error = imap::delete_messages(&wrong, "INBOX", &[7], "Trash", None).unwrap_err();
    let message = operation_message(error);
    assert_eq!(
        message,
        "Mailbox sign-in failed. Check the password or use an app password."
    );
    assert!(!message.contains("wrong-password"));
    assert_eq!(server.uids("INBOX"), vec![7, 11, 99]);
}

#[test]
fn pop3_accounts_cannot_delete_server_messages() {
    let account = pop3_account();
    for error in [
        imap::delete_messages(&account, "INBOX", &[1], "Trash", None).unwrap_err(),
        imap::delete_message(&account, "INBOX", 1, "", None).unwrap_err(),
        imap::set_flags(&account, "INBOX", 1, Some(true), None).unwrap_err(),
    ] {
        assert_eq!(error.status(), 400);
        assert_eq!(error.to_string(), mail_core::pop3::IMAP_ONLY_MESSAGE);
    }
}
