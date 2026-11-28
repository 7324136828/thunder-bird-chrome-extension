//! Protocol tests for inbox ingestion (ports of `backend/tests/test_doctor_mailbox.py`
//! `DoctorMailboxDownloadTests` and `test_doctor_schedule_download.py`).
//! Every IMAP connection goes to the in-process fake server from
//! `mail_proto::testkit`.

use chrono::NaiveDate;
use mail_doctor::mailbox_download::{
    download_inbox, DownloadError, DownloadHooks, DownloadOptions, MailboxAuth,
};
use mail_proto::imap::Status;
use mail_proto::testkit::{test_connector, Failure, TlsMode};
use mail_proto::testkit::{FakeImapBuilder, FakeImapServer, FakeMessage, HookAction};
use std::cell::RefCell;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

const USER: &str = "user@example.com";
const PASSWORD: &str = "memory-only-password";
const RAW_EMAIL: &[u8] = b"From: Alice <alice@example.org>\r\n\
To: user@example.com\r\n\
Subject: Keep this unread\r\n\
Date: Tue, 13 Oct 2026 09:00:00 +0000\r\n\r\n\
Mailbox audit preview.\r\n";
const RECENT: &str = "13-Oct-2026 09:00:00 +0000";

fn recent_server() -> FakeImapBuilder {
    FakeImapServer::builder()
        .credentials(USER, PASSWORD)
        .message_with(
            "INBOX",
            FakeMessage::new(RAW_EMAIL)
                .with_uid(41)
                .with_internal_date(RECENT),
        )
        .message_with(
            "INBOX",
            FakeMessage::new(RAW_EMAIL)
                .with_uid(42)
                .with_internal_date(RECENT),
        )
}

fn password_auth(port: u16) -> MailboxAuth {
    let mut auth = MailboxAuth::default();
    auth.password = Some(PASSWORD.into());
    auth.imap_server = Some("127.0.0.1".into());
    auth.imap_port = Some(port);
    auth.use_ssl = Some(false);
    auth
}

/// Recorded callback activity of one download.
#[derive(Default)]
struct Calls {
    progress: Vec<(usize, usize)>,
    batches: Vec<(usize, usize)>,
    logs: Vec<String>,
}

fn now() -> chrono::NaiveDateTime {
    NaiveDate::from_ymd_opt(2026, 10, 13)
        .unwrap()
        .and_hms_opt(12, 0, 0)
        .unwrap()
}

fn run(
    output: &Path,
    auth: &MailboxAuth,
    configure: impl FnOnce(&mut DownloadOptions<'_>),
    cancel: Option<Arc<AtomicBool>>,
) -> (Result<(usize, usize), DownloadError>, Calls) {
    let calls = RefCell::new(Calls::default());
    let mut options = DownloadOptions::new(USER, output, 7, auth);
    options.now = Some(now());
    options.pause = std::time::Duration::ZERO;
    options.tls_connector = Some(test_connector());
    configure(&mut options);
    let result = {
        let mut hooks = DownloadHooks {
            progress: Box::new(|done, total| {
                calls.borrow_mut().progress.push((done, total));
                Ok(())
            }),
            log: Box::new(|message| calls.borrow_mut().logs.push(message.to_string())),
            should_cancel: Box::new(move || {
                cancel
                    .as_ref()
                    .is_some_and(|flag| flag.load(Ordering::SeqCst))
            }),
            on_batch: Box::new(|done, total| {
                calls.borrow_mut().batches.push((done, total));
                Ok(())
            }),
        };
        download_inbox(&options, &mut hooks)
    };
    (result, calls.into_inner())
}

fn files(directory: &Path, suffix: &str) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(directory)
        .map(|entries| {
            entries
                .flatten()
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .filter(|name| name.ends_with(suffix) || name.contains(suffix))
                .collect()
        })
        .unwrap_or_default();
    names.sort();
    names
}

fn output_dir() -> (tempfile::TempDir, PathBuf) {
    let temporary = tempfile::tempdir().unwrap();
    let output = temporary.path().join("inputs");
    (temporary, output)
}

fn body_fetches(server: &FakeImapServer) -> Vec<String> {
    server
        .commands()
        .into_iter()
        .filter(|line| line.contains("BODY.PEEK[]"))
        .collect()
}

#[test]
fn recent_window_uses_readonly_inbox_and_peek_without_changing_flags() {
    let server = recent_server().start();
    let (_temporary, output) = output_dir();
    let auth = password_auth(server.port());
    let (result, calls) = run(&output, &auth, |_| {}, None);
    assert_eq!(result.unwrap(), (2, 2));
    let commands = server.commands();
    assert!(
        commands.iter().any(|c| c.starts_with("EXAMINE")),
        "{commands:?}"
    );
    assert!(!commands
        .iter()
        .any(|c| c.starts_with("SELECT") || c.contains("STORE")));
    assert!(
        commands.iter().any(|c| c == "UID SEARCH SINCE 06-Oct-2026"),
        "{commands:?}"
    );
    assert_eq!(
        body_fetches(&server),
        ["UID FETCH 41 (BODY.PEEK[])", "UID FETCH 42 (BODY.PEEK[])"]
    );
    assert_eq!(calls.progress, [(0, 2), (1, 2), (2, 2)]);
    assert_eq!(calls.batches, [(1, 2), (2, 2)]);
    assert_eq!(files(&output, ".eml"), ["41.eml", "42.eml"]);
    assert_eq!(std::fs::read(output.join("41.eml")).unwrap(), RAW_EMAIL);
    assert!(!calls.logs.join("\n").contains(PASSWORD));
    assert!(!server
        .flags("INBOX", 41)
        .unwrap()
        .iter()
        .any(|f| f == "\\Seen"));
    assert_eq!(server.logout_count(), 1);
}

#[test]
fn explicit_account_protocol_overrides_port_and_legacy_ssl_choice() {
    // SSL/TLS wins over a legacy use_ssl=false on a non-993 port.
    let server = recent_server().tls(TlsMode::Implicit).start();
    let (_temporary, output) = output_dir();
    let mut auth = password_auth(server.port());
    auth.incoming_protocol = Some("SSL/TLS".into());
    auth.use_ssl = Some(false);
    assert_eq!(run(&output, &auth, |_| {}, None).0.unwrap(), (2, 2));

    // STARTTLS upgrades before LOGIN even when use_ssl=true.
    let server = recent_server().tls(TlsMode::StartTls).start();
    let (_temporary, output) = output_dir();
    let mut auth = password_auth(server.port());
    auth.incoming_protocol = Some("STARTTLS".into());
    auth.use_ssl = Some(true);
    assert_eq!(run(&output, &auth, |_| {}, None).0.unwrap(), (2, 2));
    let names = server.command_names();
    let starttls = names
        .iter()
        .position(|n| n == "STARTTLS")
        .expect("STARTTLS sent");
    let login = names.iter().position(|n| n == "LOGIN").expect("LOGIN sent");
    assert!(starttls < login, "{names:?}");

    // NONE stays plain despite use_ssl=true.
    let server = recent_server().start();
    let (_temporary, output) = output_dir();
    let mut auth = password_auth(server.port());
    auth.incoming_protocol = Some("NONE".into());
    auth.use_ssl = Some(true);
    assert_eq!(run(&output, &auth, |_| {}, None).0.unwrap(), (2, 2));
    assert!(!server.command_names().iter().any(|n| n == "STARTTLS"));
}

#[test]
fn unsupported_protocol_is_rejected_before_connecting() {
    let server = recent_server().start();
    let (_temporary, output) = output_dir();
    let mut auth = password_auth(server.port());
    auth.incoming_protocol = Some("TLS".into());
    let error = run(&output, &auth, |_| {}, None).0.unwrap_err();
    assert_eq!(error.to_string(), "Unsupported incoming security protocol");
    assert_eq!(server.connection_count(), 0);
}

#[test]
fn empty_date_window_returns_zero_and_does_not_fetch_messages() {
    let server = FakeImapServer::builder()
        .credentials(USER, PASSWORD)
        .message_with(
            "INBOX",
            FakeMessage::new(RAW_EMAIL)
                .with_uid(41)
                .with_internal_date("01-Jan-2026 09:00:00 +0000"),
        )
        .start();
    let (_temporary, output) = output_dir();
    let auth = password_auth(server.port());
    let (result, calls) = run(&output, &auth, |options| options.days = 3, None);
    assert_eq!(result.unwrap(), (0, 0));
    assert!(server
        .commands()
        .iter()
        .any(|c| c == "UID SEARCH SINCE 10-Oct-2026"));
    assert!(body_fetches(&server).is_empty());
    assert_eq!(calls.progress, [(0, 0)]);
    assert!(calls.batches.is_empty());
    assert!(files(&output, ".eml").is_empty());
    assert_eq!(server.logout_count(), 1);
}

#[test]
fn missing_fetch_payload_is_skipped_and_only_saved_messages_are_counted() {
    let server = recent_server().start();
    server.set_hook(|request| {
        if request.line == "UID FETCH 41 (BODY.PEEK[])" {
            HookAction::Respond {
                untagged: vec![b"* 1 FETCH (UID 41)".to_vec()],
                status: Status::Ok,
                text: "FETCH completed".into(),
            }
        } else {
            HookAction::Continue
        }
    });
    let (_temporary, output) = output_dir();
    let auth = password_auth(server.port());
    let (result, calls) = run(&output, &auth, |_| {}, None);
    assert_eq!(result.unwrap(), (1, 2));
    assert!(!output.join("41.eml").exists());
    assert_eq!(std::fs::read(output.join("42.eml")).unwrap(), RAW_EMAIL);
    assert_eq!(calls.progress, [(0, 2), (1, 2)]);
    assert_eq!(calls.batches, [(1, 2)]);
    assert!(calls.logs.iter().any(|line| line.contains("41")));
}

#[test]
fn oauth_authenticates_without_password_or_token_files() {
    let token = "memory-only-oauth-token";
    let server = FakeImapServer::builder()
        .oauth_token(USER, token)
        .message_with(
            "INBOX",
            FakeMessage::new(RAW_EMAIL)
                .with_uid(41)
                .with_internal_date(RECENT),
        )
        .message_with(
            "INBOX",
            FakeMessage::new(RAW_EMAIL)
                .with_uid(42)
                .with_internal_date(RECENT),
        )
        .start();
    let (_temporary, output) = output_dir();
    let mut auth = MailboxAuth::access_token(token);
    auth.imap_server = Some("127.0.0.1".into());
    auth.imap_port = Some(server.port());
    auth.use_ssl = Some(false);
    let (result, calls) = run(&output, &auth, |_| {}, None);
    assert_eq!(result.unwrap(), (2, 2));
    let names = server.command_names();
    assert!(!names.iter().any(|n| n == "LOGIN"));
    assert!(names.iter().any(|n| n == "AUTHENTICATE"));
    assert!(!calls.logs.join("\n").contains(token));
    for name in files(&output, ".eml") {
        let bytes = std::fs::read(output.join(name)).unwrap();
        assert!(!String::from_utf8_lossy(&bytes).contains(token));
    }
    assert_eq!(server.logout_count(), 1);
}

#[test]
fn cancellation_before_connect_does_not_open_a_network_connection() {
    let server = recent_server().start();
    let (_temporary, output) = output_dir();
    let auth = password_auth(server.port());
    let (result, _) = run(
        &output,
        &auth,
        |_| {},
        Some(Arc::new(AtomicBool::new(true))),
    );
    assert!(matches!(result, Err(DownloadError::Cancelled(_))));
    assert_eq!(server.connection_count(), 0);
    assert!(files(&output, ".eml").is_empty());
}

#[test]
fn cancellation_after_fetch_does_not_publish_that_message() {
    let server = recent_server().start();
    let cancelled = Arc::new(AtomicBool::new(false));
    let flag = cancelled.clone();
    server.set_hook(move |request| {
        if request.command == "UID FETCH" {
            flag.store(true, Ordering::SeqCst);
        }
        HookAction::Continue
    });
    let (_temporary, output) = output_dir();
    let auth = password_auth(server.port());
    let (result, _) = run(&output, &auth, |_| {}, Some(cancelled));
    assert!(matches!(result, Err(DownloadError::Cancelled(_))));
    assert!(files(&output, ".eml").is_empty());
    assert_eq!(body_fetches(&server).len(), 1);
    assert_eq!(server.logout_count(), 1);
}

#[test]
fn failed_login_is_sanitized_and_connection_is_closed() {
    let server = FakeImapServer::builder()
        .credentials(USER, "a-different-password")
        .start();
    let (_temporary, output) = output_dir();
    let auth = password_auth(server.port());
    let error = run(&output, &auth, |_| {}, None).0.unwrap_err();
    assert_eq!(
        error.to_string(),
        "Mailbox sign-in failed. Check provider permissions or use an app password."
    );
    assert!(!error.to_string().contains(PASSWORD));
    let names = server.command_names();
    assert!(!names.iter().any(|n| n == "EXAMINE" || n.starts_with("UID")));
    assert_eq!(server.logout_count(), 1);
}

#[test]
fn missing_authentication_is_reported() {
    let server = recent_server().start();
    let (_temporary, output) = output_dir();
    let mut auth = password_auth(server.port());
    auth.password = None;
    let error = run(&output, &auth, |_| {}, None).0.unwrap_err();
    assert_eq!(error.to_string(), "No mailbox authentication was supplied");
}

#[test]
fn failed_search_closes_connection_without_fetching() {
    let server = recent_server().start();
    server.fail_next("UID SEARCH", Failure::No("Search not allowed".into()));
    let (_temporary, output) = output_dir();
    let auth = password_auth(server.port());
    let error = run(&output, &auth, |_| {}, None).0.unwrap_err();
    assert_eq!(
        error.to_string(),
        "The server could not search the requested date range"
    );
    assert!(!server.command_names().iter().any(|n| n == "UID FETCH"));
    assert!(files(&output, ".eml").is_empty());
    assert_eq!(server.logout_count(), 1);
}

#[test]
fn starttls_failure_closes_connection_without_sending_credentials() {
    // The plain server does not advertise STARTTLS.
    let server = recent_server().start();
    let (_temporary, output) = output_dir();
    let mut auth = password_auth(server.port());
    auth.incoming_protocol = Some("STARTTLS".into());
    let error = run(&output, &auth, |_| {}, None).0.unwrap_err();
    assert_eq!(
        error.to_string(),
        "The server could not establish IMAP STARTTLS"
    );
    let names = server.command_names();
    assert!(!names
        .iter()
        .any(|n| n == "LOGIN" || n == "AUTHENTICATE" || n == "EXAMINE"));
}

#[test]
fn connection_failure_names_the_server() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    let (_temporary, output) = output_dir();
    let auth = password_auth(port);
    let error = run(&output, &auth, |_| {}, None).0.unwrap_err();
    assert!(
        error.to_string().starts_with(&format!(
            "Could not connect to IMAP server 127.0.0.1:{port}: "
        )),
        "{error}"
    );
}

#[test]
fn message_limit_rejects_window_before_fetching_any_message() {
    let server = recent_server().start();
    let (_temporary, output) = output_dir();
    let auth = password_auth(server.port());
    let error = run(&output, &auth, |options| options.max_messages = 1, None)
        .0
        .unwrap_err();
    assert_eq!(
        error.to_string(),
        "The mailbox exceeds the maximum audit message count; choose fewer days"
    );
    assert!(body_fetches(&server).is_empty());
    assert!(files(&output, ".eml").is_empty());
    assert_eq!(server.logout_count(), 1);
}

#[test]
fn byte_limit_counts_all_messages_without_publishing_overflow() {
    let server = recent_server().start();
    let (_temporary, output) = output_dir();
    let auth = password_auth(server.port());
    let (result, calls) = run(
        &output,
        &auth,
        |options| options.max_bytes = RAW_EMAIL.len() as u64,
        None,
    );
    assert_eq!(
        result.unwrap_err().to_string(),
        "The mailbox download exceeds the maximum allowed size; choose fewer days"
    );
    assert_eq!(std::fs::read(output.join("41.eml")).unwrap(), RAW_EMAIL);
    assert!(!output.join("42.eml").exists());
    assert!(files(&output, ".part").is_empty());
    assert_eq!(calls.progress, [(0, 2), (1, 2)]);
    assert_eq!(server.logout_count(), 1);
}

#[test]
fn already_downloaded_messages_are_reused_and_counted() {
    let server = recent_server().start();
    let (_temporary, output) = output_dir();
    std::fs::create_dir_all(&output).unwrap();
    std::fs::write(output.join("41.eml"), RAW_EMAIL).unwrap();
    let auth = password_auth(server.port());
    assert_eq!(run(&output, &auth, |_| {}, None).0.unwrap(), (2, 2));
    assert_eq!(body_fetches(&server), ["UID FETCH 42 (BODY.PEEK[])"]);
}

// ---------------------------------------------------------------------------
// Exact received-date windows (test_doctor_schedule_download.py)
// ---------------------------------------------------------------------------

const OLD_RAW: &[u8] =
    b"From: Sender <sender@example.com>\r\nSubject: Old sender date\r\nDate: Tue, 1 Jan 2000 00:00:00 +0000\r\n\r\nMessage";
const WINDOW_START: &str = "2026-10-10T22:00:00+00:00";
const WINDOW_END: &str = "2026-10-17T22:00:00+00:00";

fn window_server() -> FakeImapServer {
    let mut builder = FakeImapServer::builder().credentials(USER, PASSWORD);
    for (uid, date) in [
        (1, "10-Oct-2026 21:59:59 +0000"), // Before the inclusive start.
        (2, "11-Oct-2026 12:00:00 +1400"), // Exactly 10 October 22:00 UTC.
        (3, "17-Oct-2026 07:59:59 -1400"), // One second before the end.
        (4, "17-Oct-2026 18:00:00 -0400"), // Exclusive end.
    ] {
        builder = builder.message_with(
            "INBOX",
            FakeMessage::new(OLD_RAW)
                .with_uid(uid)
                .with_internal_date(date),
        );
    }
    builder.start()
}

fn with_window(options: &mut DownloadOptions<'_>) {
    options.window_start = Some(WINDOW_START);
    options.window_end = Some(WINDOW_END);
}

#[test]
fn boundaries_use_internaldate_and_only_exact_window_bodies_are_downloaded() {
    let server = window_server();
    let (_temporary, output) = output_dir();
    let auth = password_auth(server.port());
    let (result, calls) = run(
        &output,
        &auth,
        |options| {
            with_window(options);
            options.max_messages = 2;
        },
        None,
    );
    assert_eq!(result.unwrap(), (2, 2));
    assert_eq!(files(&output, ".eml"), ["2.eml", "3.eml"]);
    let uid_commands: Vec<String> = server
        .commands()
        .into_iter()
        .filter(|c| c.starts_with("UID"))
        .collect();
    assert_eq!(
        uid_commands,
        [
            "UID SEARCH SINCE 09-Oct-2026 BEFORE 19-Oct-2026",
            "UID FETCH 1 (INTERNALDATE)",
            "UID FETCH 2 (INTERNALDATE)",
            "UID FETCH 3 (INTERNALDATE)",
            "UID FETCH 4 (INTERNALDATE)",
            "UID FETCH 2 (BODY.PEEK[])",
            "UID FETCH 3 (BODY.PEEK[])",
        ]
    );
    assert_eq!(calls.progress, [(0, 2), (1, 2), (2, 2)]);
    assert_eq!(
        calls.logs[0],
        "Found 2 INBOX messages in [2026-10-10T22:00:00+00:00, 2026-10-17T22:00:00+00:00)"
    );
    assert!(server.commands().iter().any(|c| c.starts_with("EXAMINE")));
    assert_eq!(server.logout_count(), 1);
}

#[test]
fn selected_window_limit_is_enforced_before_any_raw_message_download() {
    let server = window_server();
    let (_temporary, output) = output_dir();
    let auth = password_auth(server.port());
    let error = run(
        &output,
        &auth,
        |options| {
            with_window(options);
            options.max_messages = 1;
        },
        None,
    )
    .0
    .unwrap_err();
    assert!(error.to_string().contains("maximum audit message count"));
    assert!(body_fetches(&server).is_empty());
    assert!(files(&output, ".eml").is_empty());
}

#[test]
fn invalid_received_date_fails_instead_of_silently_losing_weekly_data() {
    let server = window_server();
    server.set_hook(|request| {
        if request.line == "UID FETCH 1 (INTERNALDATE)" {
            HookAction::Respond {
                untagged: vec![b"* 1 FETCH (UID 1 INTERNALDATE \"not a received date\")".to_vec()],
                status: Status::Ok,
                text: "FETCH completed".into(),
            }
        } else {
            HookAction::Continue
        }
    });
    let (_temporary, output) = output_dir();
    let auth = password_auth(server.port());
    let error = run(&output, &auth, with_window, None).0.unwrap_err();
    assert!(error.to_string().contains("valid received date"), "{error}");
    assert!(files(&output, ".eml").is_empty());
    assert_eq!(server.logout_count(), 1);
}

#[test]
fn invalid_or_partial_windows_fail_before_connect() {
    let server = window_server();
    let auth = password_auth(server.port());
    let cases: [(Option<&str>, Option<&str>); 5] = [
        (None, Some(WINDOW_END)),
        (Some(WINDOW_START), None),
        (Some("2026-10-18T22:00:00+00:00"), Some(WINDOW_END)),
        (Some("2026-10-10T22:00:00"), Some(WINDOW_END)),
        (Some(WINDOW_START), Some("invalid")),
    ];
    for (start, end) in cases {
        let (_temporary, output) = output_dir();
        let result = run(
            &output,
            &auth,
            |options| {
                options.window_start = start;
                options.window_end = end;
            },
            None,
        )
        .0;
        assert!(
            matches!(result, Err(DownloadError::Failed(_))),
            "{start:?} {end:?}"
        );
    }
    assert_eq!(server.connection_count(), 0);
}

#[test]
fn cancellation_during_metadata_fetch_prevents_raw_downloads() {
    let server = window_server();
    let cancelled = Arc::new(AtomicBool::new(false));
    let flag = cancelled.clone();
    server.set_hook(move |request| {
        if request.command == "UID FETCH" {
            flag.store(true, Ordering::SeqCst);
        }
        HookAction::Continue
    });
    let (_temporary, output) = output_dir();
    let auth = password_auth(server.port());
    let (result, _) = run(&output, &auth, with_window, Some(cancelled));
    assert!(matches!(result, Err(DownloadError::Cancelled(_))));
    assert!(files(&output, ".eml").is_empty());
    assert!(body_fetches(&server).is_empty());
    assert_eq!(server.logout_count(), 1);
}
