//! Port of `tests/test_trash.py` against `mail_proto::testkit::FakeImapServer`.
//!
//! The Python `FakeTrashServer` was a patched `imaplib` connection; here the
//! fake server speaks real IMAP, so deletion is observable across
//! connections and retries. Python tests that patched module constants use
//! `TrashLimits`; tests that patched `_check_deadline` use a short
//! `operation_timeout` with a server hook that stalls the relevant command;
//! the `ZipFile.testzip` patch is replaced by a unit test in `trash.rs`.

use std::collections::HashMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use mail_core::error::MailError;
use mail_core::sessions::MailAccount;
use mail_core::trash::{TrashLimits, TrashOperations};
use mail_proto::imap::Status;
use mail_proto::testkit::{Failure, FakeImapServer, FakeMessage, HookAction};
use serde_json::{json, Value};

const USER: &str = "user@example.com";
const OTHER: &str = "other@example.com";
const PASSWORD: &str = "trash-test-secret-pass";

fn original(uid: u32) -> Vec<u8> {
    format!("From: sender{uid}@example.com\r\nSubject: Original {uid}\r\n\r\nBody {uid}\r\n")
        .into_bytes()
}

fn account_for(email: &str, port: u16) -> MailAccount {
    MailAccount::new(
        email,
        PASSWORD,
        "127.0.0.1",
        port,
        "none",
        "smtp.example.com",
        587,
        "STARTTLS",
    )
}

struct Fixture {
    server: FakeImapServer,
    operations: TrashOperations,
    account: MailAccount,
    directory: PathBuf,
    _temporary: tempfile::TempDir,
}

impl Fixture {
    fn new(count: u32) -> Self {
        Self::with(count, TrashLimits::default(), |builder| builder)
    }

    fn with(
        count: u32,
        limits: TrashLimits,
        configure: impl FnOnce(
            mail_proto::testkit::FakeImapBuilder,
        ) -> mail_proto::testkit::FakeImapBuilder,
    ) -> Self {
        let mut builder = FakeImapServer::builder()
            .credentials(USER, PASSWORD)
            .credentials(OTHER, PASSWORD)
            .folder("Trash", &["\\Trash"])
            .uid_validity("Trash", Some(137));
        for uid in 1..=count {
            builder = builder.message_with("Trash", FakeMessage::new(original(uid)).with_uid(uid));
        }
        let server = configure(builder).start();
        let temporary = tempfile::tempdir().unwrap();
        let directory = temporary.path().join("trash_archives");
        let operations = TrashOperations::with_limits(&directory, limits);
        let account = account_for(USER, server.port());
        Self {
            server,
            operations,
            account,
            directory,
            _temporary: temporary,
        }
    }

    fn prepare(&self, archive: bool) -> Result<Value, MailError> {
        self.operations.prepare(&self.account, "Trash", archive)
    }

    fn download(&self, operation: &Value) -> (PathBuf, String) {
        self.operations
            .archive(&self.account, id(operation))
            .unwrap()
    }

    fn empty(&self, operation: &Value) -> Result<Value, MailError> {
        self.operations.empty(&self.account, id(operation))
    }

    /// `server.mutations`: every `UID STORE` / `UID EXPUNGE` line.
    fn mutations(&self) -> Vec<String> {
        self.server
            .log()
            .into_iter()
            .filter(|command| command.name == "UID STORE" || command.name == "UID EXPUNGE")
            .map(|command| command.line)
            .collect()
    }

    fn uids(&self) -> Vec<u32> {
        self.server.uids("Trash")
    }

    fn files(&self) -> Vec<PathBuf> {
        files(&self.directory)
    }

    fn remove_message(&self, uid: u32) {
        self.server.with_folders(|folders| {
            let trash = folders.iter_mut().find(|f| f.name == "Trash").unwrap();
            trash.messages.retain(|message| message.uid != uid);
        });
    }

    fn set_validity(&self, validity: Option<u32>) {
        self.server.with_folders(|folders| {
            folders
                .iter_mut()
                .find(|f| f.name == "Trash")
                .unwrap()
                .uid_validity = validity;
        });
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.operations.close();
    }
}

fn files(directory: &Path) -> Vec<PathBuf> {
    match std::fs::read_dir(directory) {
        Ok(entries) => entries.map(|entry| entry.unwrap().path()).collect(),
        Err(_) => Vec::new(),
    }
}

fn id(operation: &Value) -> &str {
    operation["operation_id"].as_str().unwrap()
}

fn operation_error(result: Result<impl std::fmt::Debug, MailError>) -> String {
    match result {
        Err(MailError::Operation(message)) => message,
        other => panic!("expected TrashOperationError, got {other:?}"),
    }
}

fn is_not_found<T: std::fmt::Debug>(result: Result<T, MailError>) -> bool {
    matches!(result, Err(MailError::TrashNotFound(_)))
}

fn read_zip(path: &Path) -> HashMap<String, Vec<u8>> {
    let mut archive = zip::ZipArchive::new(std::fs::File::open(path).unwrap()).unwrap();
    let mut entries = HashMap::new();
    for index in 0..archive.len() {
        let mut entry = archive.by_index(index).unwrap();
        let mut data = Vec::new();
        entry.read_to_end(&mut data).unwrap();
        entries.insert(entry.name().to_string(), data);
    }
    entries
}

/// UID of a `UID FETCH <uid> ...` command line.
fn fetched_uid(line: &str) -> Option<u32> {
    line.split_whitespace().nth(2)?.parse().ok()
}

#[test]
fn archive_contains_every_original_rfc822_message_and_prepare_is_read_only() {
    let fixture = Fixture::new(12);
    let operation = fixture.prepare(true).unwrap();
    assert_eq!(operation["count"], json!(12));
    assert_eq!(operation["archive"], json!(true));
    assert!(fixture.mutations().is_empty());
    let log = fixture.server.log();
    let examine = log.iter().position(|c| c.name == "EXAMINE").unwrap();
    assert_eq!(log[examine].line, "EXAMINE \"Trash\"");
    assert_eq!(log[examine - 1].name, "LIST");
    assert_eq!(log[examine - 2].name, "CAPABILITY");
    assert!(!log.iter().any(|c| c.name == "SELECT"));

    let (path, filename) = fixture.download(&operation);
    assert_eq!(json!(filename), operation["filename"]);
    assert!(filename.starts_with("trash-") && filename.ends_with(".zip"));
    assert_eq!(filename.len(), "trash-20260101-000000.zip".len());
    let entries = read_zip(&path);
    assert_eq!(entries.len(), 12);
    for uid in 1..=12 {
        assert_eq!(entries[&format!("message-{uid}.eml")], original(uid));
    }
    let body_fetches: Vec<String> = fixture
        .server
        .log()
        .into_iter()
        .filter(|c| c.name == "UID FETCH" && c.line.contains("BODY"))
        .map(|c| c.line)
        .collect();
    assert_eq!(body_fetches.len(), 12);
    assert!(body_fetches
        .iter()
        .all(|line| line.ends_with(" (UID BODY.PEEK[])")));
    let text = operation.to_string();
    assert!(!text.contains(PASSWORD));
    assert!(!text.contains(&fixture.directory.display().to_string()));
    assert_eq!(id(&operation).len(), 43);
    // Every connection was logged out.
    assert_eq!(
        fixture.server.logout_count(),
        fixture.server.connection_count()
    );
}

#[test]
fn archive_and_empty_removes_snapshot_only_and_retry_is_idempotent() {
    let fixture = Fixture::new(3);
    let operation = fixture.prepare(true).unwrap();
    let (path, _) = fixture.download(&operation);
    // New mail, already marked deleted by another mail client.
    fixture.server.add_message(
        "Trash",
        FakeMessage::new(b"New mail\r\n".to_vec())
            .with_uid(10)
            .with_flags(&["\\Deleted"]),
    );
    assert_eq!(
        fixture.empty(&operation).unwrap(),
        json!({"deleted": 3, "remaining": 1})
    );
    assert_eq!(fixture.uids(), vec![10]);
    assert!(path.is_file());
    let calls = fixture.server.log().len();
    assert_eq!(
        fixture.empty(&operation).unwrap(),
        json!({"deleted": 3, "remaining": 1})
    );
    assert_eq!(fixture.server.log().len(), calls);
    assert_eq!(
        fixture.mutations(),
        vec![
            "UID STORE 1,2,3 +FLAGS.SILENT (\\Deleted)".to_string(),
            "UID EXPUNGE 1,2,3".to_string(),
        ]
    );
}

#[test]
fn direct_empty_does_not_fetch_bodies_or_create_archive() {
    let fixture = Fixture::new(3);
    let operation = fixture.prepare(false).unwrap();
    assert_eq!(operation["filename"], Value::Null);
    assert!(fixture.files().is_empty());
    assert_eq!(
        fixture.empty(&operation).unwrap(),
        json!({"deleted": 3, "remaining": 0})
    );
    assert!(!fixture.server.log().iter().any(|c| c.name == "UID FETCH"));
}

#[test]
fn empty_archive_requires_download_first() {
    let fixture = Fixture::new(3);
    let operation = fixture.prepare(true).unwrap();
    let message = operation_error(fixture.empty(&operation));
    assert!(message.contains("Download and save"), "{message}");
    assert!(fixture.mutations().is_empty());
}

#[test]
fn different_account_or_reunlock_cannot_access_archive_or_empty() {
    let fixture = Fixture::new(3);
    let operation = fixture.prepare(true).unwrap();
    let someone = account_for("someone@example.com", fixture.server.port());
    let mut reunlocked = fixture.account.clone();
    reunlocked.unlocked_at += 1.0;
    for account in [&someone, &reunlocked] {
        let id = id(&operation);
        assert!(is_not_found(fixture.operations.archive(account, id)));
        assert!(is_not_found(fixture.operations.empty(account, id)));
        assert!(is_not_found(fixture.operations.discard(account, id)));
    }
    assert!(fixture.mutations().is_empty());
}

#[test]
fn inbox_and_unadvertised_folder_cannot_be_emptied() {
    let fixture = Fixture::with(3, TrashLimits::default(), |builder| {
        builder.folder("Other", &[])
    });
    for folder in ["INBOX", "Other", "trash"] {
        let message = operation_error(fixture.operations.prepare(&fixture.account, folder, false));
        assert!(message.contains("verified Trash"), "{message}");
        assert!(message.ends_with(" No messages were deleted."), "{message}");
    }
    let names = fixture.server.command_names();
    assert!(!names.iter().any(|n| n == "SELECT" || n == "EXAMINE"));
    assert!(fixture.mutations().is_empty());
}

#[test]
fn noselect_trash_is_rejected() {
    let fixture = Fixture::new(3);
    fixture
        .server
        .add_folder("Trash", &["\\Trash", "\\Noselect"]);
    let message = operation_error(fixture.prepare(false));
    assert!(message.contains("verified Trash"), "{message}");
    assert!(fixture.mutations().is_empty());
}

#[test]
fn trash_special_folder_is_reverified_before_deletion() {
    let fixture = Fixture::new(3);
    let operation = fixture.prepare(false).unwrap();
    fixture.server.add_folder("Trash", &[]);
    let message = operation_error(fixture.empty(&operation));
    assert_eq!(
        message,
        "Emptying is only available for the server's verified Trash folder."
    );
    assert!(fixture.mutations().is_empty());
}

#[test]
fn quoted_folder_and_nil_delimiter_are_verified_and_quoted_safely() {
    let fixture = Fixture::with(0, TrashLimits::default(), |builder| {
        builder
            .delimiter(None)
            .folder("Trash", &[])
            .folder("Trash \"quoted\"", &["\\Trash"])
            .message_with(
                "Trash \"quoted\"",
                FakeMessage::new(original(1)).with_uid(1),
            )
    });
    let operation = fixture
        .operations
        .prepare(&fixture.account, "Trash \"quoted\"", false)
        .unwrap();
    assert_eq!(
        fixture.empty(&operation).unwrap(),
        json!({"deleted": 1, "remaining": 0})
    );
    let selects: Vec<String> = fixture
        .server
        .log()
        .into_iter()
        .filter(|c| c.name == "EXAMINE" || c.name == "SELECT")
        .map(|c| c.line)
        .collect();
    assert_eq!(selects[0], "EXAMINE \"Trash \\\"quoted\\\"\"");
    assert_eq!(selects[1], "SELECT \"Trash \\\"quoted\\\"\"");
}

#[test]
fn literal_folder_names_are_verified() {
    let fixture = Fixture::with(2, TrashLimits::default(), |builder| {
        builder.literal_names(true)
    });
    let operation = fixture.prepare(false).unwrap();
    assert_eq!(operation["count"], json!(2));
}

#[test]
fn control_character_and_unsupported_folder_names_fail_before_connect() {
    let fixture = Fixture::new(3);
    let long = "x".repeat(501);
    for folder in ["Trash\r\nINBOX", "Tr\u{e4}sh", "", long.as_str()] {
        let message = operation_error(fixture.operations.prepare(&fixture.account, folder, false));
        assert_eq!(
            message,
            "This Trash folder name is not supported for safe deletion."
        );
    }
    assert_eq!(fixture.server.connection_count(), 0);
}

#[test]
fn uidplus_required_before_preparation_and_again_before_commit() {
    let fixture = Fixture::new(3);
    fixture.server.set_capabilities(&["IMAP4rev1", "MOVE"]);
    let message = operation_error(fixture.prepare(true));
    assert_eq!(
        message,
        "This server cannot safely empty Trash: UIDPLUS or IMAP4rev2 is required. No messages were deleted."
    );
    assert!(fixture.files().is_empty());
    fixture.server.set_capabilities(&["IMAP4rev1", "UIDPLUS"]);
    let operation = fixture.prepare(false).unwrap();
    fixture.server.set_capabilities(&["IMAP4rev1"]);
    let message = operation_error(fixture.empty(&operation));
    assert_eq!(
        message,
        "This server cannot safely empty Trash: UIDPLUS or IMAP4rev2 is required."
    );
    assert!(fixture.mutations().is_empty());
}

#[test]
fn imap4rev2_supports_uid_expunge_without_uidplus_token() {
    let fixture = Fixture::new(3);
    fixture.server.set_capabilities(&["IMAP4rev2"]);
    let operation = fixture.prepare(false).unwrap();
    assert_eq!(fixture.empty(&operation).unwrap()["deleted"], json!(3));
}

#[test]
fn changed_uidvalidity_never_deletes_reused_uids() {
    let fixture = Fixture::new(3);
    let operation = fixture.prepare(false).unwrap();
    fixture.set_validity(Some(138));
    fixture.server.add_message(
        "Trash",
        FakeMessage::new(b"Replacement message\r\n".to_vec()).with_uid(1),
    );
    let message = operation_error(fixture.empty(&operation));
    assert!(message.contains("mailbox identity"), "{message}");
    assert!(fixture.mutations().is_empty());
    assert!(fixture.uids().contains(&1));
}

#[test]
fn missing_uidvalidity_rejects_prepare_and_commit() {
    let fixture = Fixture::new(3);
    let operation = fixture.prepare(false).unwrap();
    fixture.set_validity(None);
    let message = operation_error(fixture.empty(&operation));
    assert_eq!(
        message,
        "The server did not identify this Trash mailbox safely."
    );
    let message = operation_error(fixture.prepare(false));
    assert_eq!(
        message,
        "The server did not identify this Trash mailbox safely. No messages were deleted."
    );
    assert!(fixture.mutations().is_empty());
}

#[test]
fn empty_snapshot_never_deletes_subsequent_arrivals() {
    let fixture = Fixture::new(0);
    let operation = fixture.prepare(false).unwrap();
    assert_eq!(operation["count"], json!(0));
    fixture
        .server
        .add_message("Trash", FakeMessage::new(b"New\r\n".to_vec()).with_uid(7));
    assert_eq!(
        fixture.empty(&operation).unwrap(),
        json!({"deleted": 0, "remaining": 1})
    );
    assert!(fixture.mutations().is_empty());
}

#[test]
fn vanished_snapshot_uids_are_safe_to_retry() {
    let fixture = Fixture::new(3);
    let operation = fixture.prepare(false).unwrap();
    fixture.remove_message(2);
    assert_eq!(
        fixture.empty(&operation).unwrap(),
        json!({"deleted": 3, "remaining": 0})
    );
    assert_eq!(
        fixture.mutations()[0],
        "UID STORE 1,3 +FLAGS.SILENT (\\Deleted)"
    );
}

#[test]
fn store_failure_retains_archive_and_retry_keeps_new_arrivals() {
    let fixture = Fixture::new(3);
    let operation = fixture.prepare(true).unwrap();
    let (path, _) = fixture.download(&operation);
    fixture.server.fail_next("UID STORE", Failure::no());
    let message = operation_error(fixture.empty(&operation));
    assert_eq!(
        message,
        "Trash could only be partially emptied. Some messages may have been permanently deleted. \
         Keep the downloaded archive and retry this same operation to finish safely."
    );
    assert!(path.is_file());
    assert_eq!(fixture.uids().len(), 3);
    fixture
        .server
        .add_message("Trash", FakeMessage::new(b"New\r\n".to_vec()).with_uid(11));
    assert_eq!(
        fixture.empty(&operation).unwrap(),
        json!({"deleted": 3, "remaining": 1})
    );
    assert_eq!(fixture.uids(), vec![11]);
}

#[test]
fn partial_failure_without_archive_uses_short_message() {
    let fixture = Fixture::new(3);
    let operation = fixture.prepare(false).unwrap();
    fixture.server.fail_next("UID EXPUNGE", Failure::no());
    let message = operation_error(fixture.empty(&operation));
    assert_eq!(
        message,
        "Trash could only be partially emptied. Some messages may have been permanently deleted. \
         Retry this same operation to finish safely."
    );
    assert_eq!(
        fixture.empty(&operation).unwrap(),
        json!({"deleted": 3, "remaining": 0})
    );
}

#[test]
fn partial_batch_failure_retries_same_snapshot_and_leaves_newcomers() {
    let limits = TrashLimits {
        uid_batch_size: 2,
        ..TrashLimits::default()
    };
    let fixture = Fixture::with(3, limits, |builder| builder);
    let operation = fixture.prepare(true).unwrap();
    fixture.download(&operation);
    let expunges = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&expunges);
    fixture.server.set_hook(move |request| {
        if request.command == "UID EXPUNGE" && counter.fetch_add(1, Ordering::SeqCst) == 1 {
            return HookAction::Respond {
                untagged: Vec::new(),
                status: Status::No,
                text: "failed".into(),
            };
        }
        HookAction::Continue
    });
    let message = operation_error(fixture.empty(&operation));
    assert!(message.contains("partially emptied"), "{message}");
    assert_eq!(fixture.uids(), vec![3]);
    fixture
        .server
        .add_message("Trash", FakeMessage::new(b"New\r\n".to_vec()).with_uid(12));
    assert_eq!(
        fixture.empty(&operation).unwrap(),
        json!({"deleted": 3, "remaining": 1})
    );
    assert_eq!(fixture.uids(), vec![12]);
    for line in fixture.mutations() {
        let set = line.split_whitespace().nth(2).unwrap();
        assert!(set.split(',').count() <= 2, "{line}");
    }
}

#[test]
fn more_than_five_hundred_messages_are_emptied_in_bounded_uid_batches() {
    let fixture = Fixture::with(0, TrashLimits::default(), |mut builder| {
        for uid in 1..=507 {
            builder = builder.message_with(
                "Trash",
                FakeMessage::new(b"Original\r\n".to_vec()).with_uid(uid),
            );
        }
        builder
    });
    let operation = fixture.prepare(false).unwrap();
    fixture.server.add_message(
        "Trash",
        FakeMessage::new(b"New arrival\r\n".to_vec()).with_uid(600),
    );
    assert_eq!(
        fixture.empty(&operation).unwrap(),
        json!({"deleted": 507, "remaining": 1})
    );
    let stores: Vec<usize> = fixture
        .mutations()
        .iter()
        .filter(|line| line.starts_with("UID STORE"))
        .map(|line| line.split_whitespace().nth(2).unwrap().split(',').count())
        .collect();
    assert_eq!(stores, vec![500, 7]);
    assert_eq!(fixture.uids(), vec![600]);
}

#[test]
fn concurrent_commit_performs_mutations_only_once() {
    let fixture = Arc::new(Fixture::new(3));
    let operation = fixture.prepare(false).unwrap();
    let threads: Vec<_> = (0..2)
        .map(|_| {
            let fixture = Arc::clone(&fixture);
            let operation = operation.clone();
            thread::spawn(move || fixture.empty(&operation))
        })
        .collect();
    let results: Vec<Value> = threads
        .into_iter()
        .map(|thread| thread.join().unwrap().unwrap())
        .collect();
    assert_eq!(results, vec![json!({"deleted": 3, "remaining": 0}); 2]);
    assert_eq!(fixture.mutations().len(), 2);
}

#[test]
fn archive_fetch_failure_never_deletes_or_leaves_partial_zip() {
    let fixture = Fixture::new(3);
    let fetches = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&fetches);
    // failures["fetch"] = ["OK", "OK", "NO"]: sizes, message 1, then message 2 fails.
    fixture.server.set_hook(move |request| {
        if request.command == "UID FETCH" && counter.fetch_add(1, Ordering::SeqCst) == 2 {
            return HookAction::Respond {
                untagged: Vec::new(),
                status: Status::No,
                text: "failed".into(),
            };
        }
        HookAction::Continue
    });
    let message = operation_error(fixture.prepare(true));
    assert_eq!(
        message,
        "A Trash message could not be archived. No messages were deleted."
    );
    assert!(fixture.mutations().is_empty());
    assert!(fixture.files().is_empty());
    assert_eq!(fixture.operations.operation_count(), 0);
}

#[test]
fn missing_or_mismatched_raw_message_never_registers_archive() {
    let fixture = Fixture::new(3);
    for setting in ["wrong_body_uid", "truncated_body"] {
        fixture.server.set_hook(move |request| {
            if request.command != "UID FETCH" || !request.line.contains("BODY.PEEK[]") {
                return HookAction::Continue;
            }
            let uid = fetched_uid(&request.line).unwrap();
            let mut raw = original(uid);
            let reported = if setting == "wrong_body_uid" {
                uid + 1
            } else {
                uid
            };
            if setting == "truncated_body" {
                raw.pop();
            }
            let mut line =
                format!("* 1 FETCH (UID {reported} BODY[] {{{}}}\r\n", raw.len()).into_bytes();
            line.extend_from_slice(&raw);
            line.push(b')');
            HookAction::Respond {
                untagged: vec![line],
                status: Status::Ok,
                text: "FETCH completed".into(),
            }
        });
        let message = operation_error(fixture.prepare(true));
        assert!(
            message.contains("completely archived"),
            "{setting}: {message}"
        );
    }
    // fetch_missing = {2}: the size listing omits UID 2.
    fixture.server.set_hook(|request| {
        if request.command != "UID FETCH" || !request.line.contains("RFC822.SIZE") {
            return HookAction::Continue;
        }
        let untagged = [1u32, 3]
            .iter()
            .map(|uid| {
                format!(
                    "* {uid} FETCH (UID {uid} RFC822.SIZE {})",
                    original(*uid).len()
                )
                .into_bytes()
            })
            .collect();
        HookAction::Respond {
            untagged,
            status: Status::Ok,
            text: "FETCH completed".into(),
        }
    });
    let message = operation_error(fixture.prepare(true));
    assert_eq!(
        message,
        "Trash changed while preparing the archive. No messages were deleted; retry."
    );
    assert!(fixture.mutations().is_empty());
    assert!(fixture.files().is_empty());
    assert_eq!(fixture.operations.operation_count(), 0);
}

#[test]
fn resource_limits_fail_before_delete() {
    let fixture = Fixture::new(3);
    let defaults = TrashLimits::default();
    let variants = [
        TrashLimits {
            max_messages: 1,
            ..defaults.clone()
        },
        TrashLimits {
            max_message_bytes: 1,
            ..defaults.clone()
        },
        TrashLimits {
            max_source_bytes: 1,
            ..defaults.clone()
        },
        TrashLimits {
            max_archive_bytes: 1,
            ..defaults.clone()
        },
        TrashLimits {
            max_spool_bytes: 1,
            ..defaults.clone()
        },
    ];
    for limits in variants {
        let operations = TrashOperations::with_limits(&fixture.directory, limits.clone());
        let message = operation_error(operations.prepare(&fixture.account, "Trash", true));
        assert!(
            message.contains("No messages were deleted"),
            "{limits:?}: {message}"
        );
        assert_eq!(operations.operation_count(), 0);
        operations.close();
    }
    assert!(fixture.mutations().is_empty());
    assert!(fixture.files().is_empty());
}

#[test]
fn archive_space_estimate_rejects_before_writing() {
    // Smaller than the estimate (sizes + 512 per message + 1024).
    let limits = TrashLimits {
        max_archive_bytes: 2_000,
        ..TrashLimits::default()
    };
    let fixture = Fixture::with(0, limits, |mut builder| {
        for uid in 1..=3u32 {
            // Incompressible-ish bodies so the archive really grows.
            let body: String = (0..400u32)
                .map(|i| char::from(b'a' + ((i * 7 + uid * 13) % 26) as u8))
                .collect();
            builder = builder.message_with(
                "Trash",
                FakeMessage::new(format!("Subject: {uid}\r\n\r\n{body}\r\n").into_bytes())
                    .with_uid(uid),
            );
        }
        builder
    });
    let message = operation_error(fixture.prepare(true));
    assert_eq!(
        message,
        "There is not enough archive space for Trash. No messages were deleted."
    );
    assert!(fixture.files().is_empty());
    assert!(!fixture
        .server
        .log()
        .iter()
        .any(|c| c.line.contains("BODY.PEEK")));
}

#[test]
fn max_operations_bound_is_enforced() {
    let limits = TrashLimits {
        max_operations: 2,
        ..TrashLimits::default()
    };
    let fixture = Fixture::with(1, limits, |builder| builder);
    let first = fixture.prepare(false).unwrap();
    fixture.prepare(false).unwrap();
    let message = operation_error(fixture.prepare(false));
    assert_eq!(
        message,
        "Finish or discard an existing Trash operation before preparing another."
    );
    fixture
        .operations
        .discard(&fixture.account, id(&first))
        .unwrap();
    fixture.prepare(false).unwrap();
}

#[test]
fn expired_operation_releases_file_and_cannot_be_used() {
    let limits = TrashLimits {
        operation_ttl: Duration::from_millis(1500),
        ..TrashLimits::default()
    };
    let fixture = Fixture::with(3, limits, |builder| builder);
    let operation = fixture.prepare(true).unwrap();
    let (path, _) = fixture.download(&operation);
    thread::sleep(Duration::from_millis(1700));
    assert!(is_not_found(fixture.empty(&operation)));
    fixture.operations.cleanup();
    assert!(!path.exists());
    assert_eq!(fixture.operations.operation_count(), 0);
    assert!(fixture.mutations().is_empty());
}

#[test]
fn cleanup_removes_stale_unregistered_archive_files_only() {
    let limits = TrashLimits {
        operation_ttl: Duration::from_millis(1500),
        ..TrashLimits::default()
    };
    let fixture = Fixture::with(1, limits, |builder| builder);
    let leftover = fixture.directory.join("trash-crashed.zip");
    let unrelated = fixture.directory.join("keep.txt");
    std::fs::write(&leftover, b"PK").unwrap();
    std::fs::write(&unrelated, b"x").unwrap();
    fixture.operations.cleanup();
    assert!(leftover.exists(), "fresh files survive");
    thread::sleep(Duration::from_millis(1700));
    fixture.operations.cleanup();
    assert!(!leftover.exists());
    assert!(unrelated.exists());
}

#[test]
fn lock_account_discards_only_its_operations_and_files() {
    let fixture = Fixture::new(3);
    let operation = fixture.prepare(true).unwrap();
    let (path, _) = fixture.download(&operation);
    let other = account_for(OTHER, fixture.server.port());
    let other_operation = fixture.operations.prepare(&other, "Trash", true).unwrap();
    let (other_path, _) = fixture
        .operations
        .archive(&other, id(&other_operation))
        .unwrap();
    fixture.operations.forget("USER@example.com");
    assert!(!path.exists());
    assert!(other_path.exists());
    assert!(is_not_found(fixture.empty(&operation)));
}

#[test]
fn discard_and_shutdown_release_archives() {
    let fixture = Fixture::new(3);
    let first = fixture.prepare(true).unwrap();
    let second = fixture.prepare(true).unwrap();
    let (first_path, _) = fixture.download(&first);
    let (second_path, _) = fixture.download(&second);
    fixture
        .operations
        .discard(&fixture.account, id(&first))
        .unwrap();
    assert!(!first_path.exists());
    fixture.operations.close();
    assert!(!second_path.exists());
    assert!(is_not_found(fixture.empty(&second)));
    let message = operation_error(fixture.prepare(false));
    assert_eq!(message, "Trash operations are unavailable.");
}

#[test]
fn connection_failure_is_safe_error_with_no_files_or_deletion() {
    // A refused connection is a MailOperationError, passed through verbatim.
    let fixture = Fixture::new(3);
    let closed_port = {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.local_addr().unwrap().port()
    };
    let unreachable = account_for(USER, closed_port);
    let message = operation_error(fixture.operations.prepare(&unreachable, "Trash", true));
    assert!(
        message.starts_with(&format!("Could not connect to 127.0.0.1:{closed_port}")),
        "{message}"
    );
    assert!(!message.contains(PASSWORD));
    // A protocol error (imaplib raised IMAP4.error) never leaks server text.
    fixture
        .server
        .fail_next("LIST", Failure::Bad("secret server detail".into()));
    let message = operation_error(fixture.prepare(true));
    assert_eq!(
        message,
        "Trash could not be prepared. No messages were deleted."
    );
    assert!(fixture.files().is_empty());
}

#[test]
fn wrong_password_is_reported_without_the_password() {
    let fixture = Fixture::new(3);
    let mut account = fixture.account.clone();
    account.password = "wrong-password-value".into();
    let message = operation_error(fixture.operations.prepare(&account, "Trash", false));
    assert_eq!(
        message,
        "Mailbox sign-in failed. Check the password or use an app password."
    );
}

#[test]
fn commit_protocol_error_before_mutation_reports_nothing_deleted() {
    let fixture = Fixture::new(3);
    let operation = fixture.prepare(false).unwrap();
    fixture.server.fail_next("SELECT", Failure::bad());
    assert_eq!(
        operation_error(fixture.empty(&operation)),
        "The server could not empty Trash. No messages were deleted."
    );
    fixture.server.fail_next("SELECT", Failure::no());
    assert_eq!(
        operation_error(fixture.empty(&operation)),
        "The server could not empty Trash. No messages were deleted."
    );
    assert!(fixture.mutations().is_empty());
    assert_eq!(fixture.empty(&operation).unwrap()["deleted"], json!(3));
}

#[test]
fn prepare_select_refusal_is_reported_verbatim() {
    let fixture = Fixture::new(3);
    fixture.server.fail_next("EXAMINE", Failure::no());
    assert_eq!(
        operation_error(fixture.prepare(false)),
        "The server would not open folder 'Trash'"
    );
}

#[test]
fn prepare_deadline_fails_read_only_without_leaving_archive() {
    let limits = TrashLimits {
        operation_timeout: Duration::from_millis(1000),
        ..TrashLimits::default()
    };
    let fixture = Fixture::with(3, limits, |builder| builder);
    fixture.server.set_hook(|request| {
        if request.command == "UID FETCH" && request.line.contains("BODY.PEEK[]") {
            thread::sleep(Duration::from_millis(1200));
        }
        HookAction::Continue
    });
    let message = operation_error(fixture.prepare(true));
    assert_eq!(
        message,
        "The Trash operation timed out. No messages were deleted."
    );
    assert!(fixture.mutations().is_empty());
    assert!(fixture.files().is_empty());
}

#[test]
fn commit_deadline_after_store_preserves_retry_snapshot_and_archive() {
    let limits = TrashLimits {
        operation_timeout: Duration::from_millis(1000),
        ..TrashLimits::default()
    };
    let fixture = Fixture::with(3, limits, |builder| builder);
    let operation = fixture.prepare(true).unwrap();
    let (path, _) = fixture.download(&operation);
    fixture.server.set_hook(|request| {
        if request.command == "UID STORE" {
            thread::sleep(Duration::from_millis(1200));
        }
        HookAction::Continue
    });
    let message = operation_error(fixture.empty(&operation));
    assert!(message.contains("partially emptied"), "{message}");
    fixture.server.clear_hook();
    assert!(path.exists());
    assert_eq!(fixture.uids().len(), 3);
    fixture.server.add_message(
        "Trash",
        FakeMessage::new(b"New arrival\r\n".to_vec()).with_uid(9),
    );
    assert_eq!(
        fixture.empty(&operation).unwrap(),
        json!({"deleted": 3, "remaining": 1})
    );
    assert_eq!(fixture.uids(), vec![9]);
}

#[test]
fn pop3_accounts_are_imap_only() {
    let fixture = Fixture::new(3);
    let mut account = fixture.account.clone();
    account.incoming_mail_protocol = "pop3".into();
    let error = fixture
        .operations
        .prepare(&account, "Trash", false)
        .unwrap_err();
    assert_eq!(error.status(), 400);
    let error = fixture.operations.empty(&account, "unknown").unwrap_err();
    assert_eq!(error.status(), 400);
    assert_eq!(fixture.server.connection_count(), 0);
}

#[test]
fn archive_without_zip_is_unavailable() {
    let fixture = Fixture::new(3);
    let operation = fixture.prepare(false).unwrap();
    assert_eq!(
        operation_error(fixture.operations.archive(&fixture.account, id(&operation))),
        "No archive is available for this Trash operation."
    );
}
