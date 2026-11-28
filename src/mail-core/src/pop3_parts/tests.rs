//! Unit tests for the POP3 internals and the TLS modes (the fake servers'
//! self-signed certificate is trusted through `session::TEST_CONNECTOR`).

use mail_proto::testkit::{test_connector, FakePop3Server, TlsMode};

use super::session::{self, header_block, synthetic_uid_validity, TEST_CONNECTOR};
use super::*;
use crate::sessions::PROTOCOL_POP3;

const EMAIL: &str = "user@example.com";
const PASSWORD: &str = "tls-secret";

fn account(server: &FakePop3Server, protocol: &str) -> MailAccount {
    let mut account = MailAccount::new(
        EMAIL,
        PASSWORD,
        server.host(),
        server.port(),
        protocol,
        "smtp.example.com",
        587,
        "starttls",
    );
    account.incoming_mail_protocol = PROTOCOL_POP3.into();
    account
}

fn with_test_tls<T>(run: impl FnOnce() -> T) -> T {
    TEST_CONNECTOR.with(|cell| *cell.borrow_mut() = Some(test_connector()));
    let result = run();
    TEST_CONNECTOR.with(|cell| *cell.borrow_mut() = None);
    result
}

#[test]
fn implicit_tls_lists_messages() {
    let server = FakePop3Server::builder()
        .credentials(EMAIL, PASSWORD)
        .tls(TlsMode::Implicit)
        .message(b"From: a@example.com\r\nSubject: secure\r\n\r\nx\r\n".to_vec())
        .start();
    let page = with_test_tls(|| {
        list_messages(
            &account(&server, "ssl"),
            "INBOX",
            &ListMessagesOptions::default(),
        )
    })
    .unwrap();
    assert_eq!(page["total"], 1);
    assert_eq!(page["messages"][0]["subject"], "secure");
}

#[test]
fn stls_upgrades_before_login() {
    let server = FakePop3Server::builder()
        .credentials(EMAIL, PASSWORD)
        .tls(TlsMode::StartTls)
        .message(b"From: a@example.com\r\nSubject: upgraded\r\n\r\nx\r\n".to_vec())
        .start();
    with_test_tls(|| verify_login(&account(&server, "starttls"))).unwrap();
    let names = server.command_names();
    assert_eq!(names.first().map(String::as_str), Some("STLS"));
    assert_eq!(names[1], "USER");
}

#[test]
fn untrusted_certificate_is_a_connection_error() {
    let server = FakePop3Server::builder()
        .credentials(EMAIL, PASSWORD)
        .tls(TlsMode::Implicit)
        .start();
    // Default trust store: the self-signed test certificate is rejected.
    let error = session::connect(&account(&server, "ssl"), None)
        .err()
        .expect("untrusted certificate");
    let message = error.to_string();
    assert!(
        message.starts_with(&format!(
            "Could not connect to 127.0.0.1:{}: ",
            server.port()
        )),
        "{message}"
    );
    assert!(!message.contains(PASSWORD));
}

#[test]
fn synthetic_epoch_is_stable_positive_and_input_sensitive() {
    let a = synthetic_uid_validity("uidl", ["1 abc", "2 def"]);
    assert_eq!(
        a,
        synthetic_uid_validity("uidl", vec!["1 abc".to_string(), "2 def".to_string()])
    );
    assert_ne!(a, synthetic_uid_validity("uidl", ["1 abc"]));
    assert_ne!(a, synthetic_uid_validity("list", ["1 abc", "2 def"]));
    let empty = synthetic_uid_validity("uidl", Vec::<String>::new());
    for value in [&a, &empty] {
        let number: u64 = value.parse().unwrap();
        assert!((1..=4_294_967_295).contains(&number));
        assert_eq!(
            crate::retention::normalize_uid_validity(value).as_deref(),
            Some(value.as_str())
        );
    }
    // Pinned so the epoch never silently changes between releases (which
    // would discard saved retention choices for every POP3 message).
    assert_eq!(a, "876418143");
}

#[test]
fn header_block_cuts_at_the_first_empty_line() {
    assert_eq!(
        header_block(b"A: 1\r\nB: 2\r\n\r\nbody\r\n\r\nmore"),
        b"A: 1\r\nB: 2\r\n\r\n"
    );
    assert_eq!(header_block(b"A: 1\n\nbody"), b"A: 1\n\n");
    assert_eq!(header_block(b"A: 1\r\n"), b"A: 1\r\n");
}

#[test]
fn received_at_prefers_topmost_parseable_received_header() {
    let message = parsing::parse_message(
        b"Received: from a by b; garbage\r\nReceived: from c by d; Mon, 6 Jan 2025 10:00:00 -0500\r\n\
Received: from e by f; Sun, 5 Jan 2025 10:00:00 +0000\r\nDate: Sat, 4 Jan 2025 00:00:00 +0000\r\n\r\n",
    );
    assert_eq!(
        received_at(&message).as_deref(),
        Some("2025-01-06T10:00:00-05:00")
    );
    let message = parsing::parse_message(
        b"Received: from a by b\r\nDate: Sat, 4 Jan 2025 00:00:00 +0000\r\n\r\n",
    );
    assert_eq!(
        received_at(&message).as_deref(),
        Some("2025-01-04T00:00:00+00:00")
    );
    assert_eq!(
        received_at(&parsing::parse_message(b"Subject: x\r\n\r\n")),
        None
    );
}

#[test]
fn sender_domain_normalization_matches_python() {
    use super::domains::{normalize_sender_domain, normalize_sender_domains};
    assert_eq!(
        normalize_sender_domain(" EXAMPLE.com. ").unwrap(),
        "example.com"
    );
    assert_eq!(
        normalize_sender_domain("b\u{fc}cher.example").unwrap(),
        "xn--bcher-kva.example"
    );
    assert_eq!(normalize_sender_domain("fa\u{df}.de").unwrap(), "fass.de");
    assert_eq!(
        normalize_sender_domain(&"a".repeat(254)).unwrap_err(),
        "Sender domains must be non-empty domain names up to 253 characters"
    );
    assert_eq!(
        normalize_sender_domain("a..com").unwrap_err(),
        "Enter a valid sender domain"
    );
    assert_eq!(
        normalize_sender_domain("-bad.example").unwrap_err(),
        "Enter a valid sender domain without an email address or URL"
    );
    assert_eq!(
        normalize_sender_domains(&[
            "Example.com".into(),
            "example.com.".into(),
            "other.test".into()
        ])
        .unwrap(),
        ["example.com", "other.test"]
    );
}
