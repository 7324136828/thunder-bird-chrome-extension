//! Real TLS negotiation (implicit and STARTTLS/STLS) against the fakes,
//! using the bundled self-signed test certificate.

use super::TIMEOUT;
use crate::imap::ImapConnection;
use crate::pop3::Pop3Connection;
use crate::testkit::{test_connector, FakeImapServer, FakePop3Server, TlsMode};
use crate::{ProtoError, Security};

#[test]
fn imap_starttls_upgrades_and_refreshes_capabilities() {
    let server = FakeImapServer::builder()
        .credentials("u", "p")
        .tls(TlsMode::StartTls)
        .start();
    let mut conn = ImapConnection::connect_with_tls(
        server.host(),
        server.port(),
        Security::StartTls,
        TIMEOUT,
        test_connector(),
    )
    .expect("STARTTLS connect");
    assert!(conn.is_tls());
    assert!(
        !conn.has_capability("STARTTLS"),
        "capabilities refreshed after TLS"
    );
    conn.login("u", "p").unwrap();
    conn.examine("INBOX").unwrap();
    assert_eq!(
        server.command_names(),
        vec![
            "CAPABILITY",
            "STARTTLS",
            "CAPABILITY",
            "LOGIN",
            "CAPABILITY",
            "EXAMINE"
        ]
    );
    // A second STARTTLS is refused locally.
    assert!(matches!(
        conn.starttls().unwrap_err(),
        ProtoError::Protocol(_)
    ));
}

#[test]
fn imap_explicit_starttls_after_plain_connect() {
    // mailbox_download.py: IMAP4(...) then conn.starttls().
    let server = FakeImapServer::builder()
        .credentials("u", "p")
        .tls(TlsMode::StartTls)
        .start();
    let mut conn = ImapConnection::connect_with_tls(
        server.host(),
        server.port(),
        Security::None,
        TIMEOUT,
        test_connector(),
    )
    .unwrap();
    assert!(conn.has_capability("STARTTLS"));
    conn.starttls().unwrap();
    assert!(conn.is_tls());
    conn.login("u", "p").unwrap();
}

#[test]
fn imap_implicit_tls() {
    let server = FakeImapServer::builder()
        .credentials("u", "p")
        .tls(TlsMode::Implicit)
        .start();
    let mut conn = ImapConnection::connect_with_tls(
        server.host(),
        server.port(),
        Security::Ssl,
        TIMEOUT,
        test_connector(),
    )
    .unwrap();
    assert!(conn.is_tls());
    conn.login("u", "p").unwrap();
    conn.logout().unwrap();
}

#[test]
fn imap_default_trust_store_rejects_self_signed_certificate() {
    let server = FakeImapServer::builder().tls(TlsMode::Implicit).start();
    let error =
        ImapConnection::connect(server.host(), server.port(), Security::Ssl, TIMEOUT).unwrap_err();
    assert!(matches!(error, ProtoError::Tls(_)), "{error:?}");
}

#[test]
fn imap_ssl_against_plain_server_fails() {
    let server = FakeImapServer::builder().start();
    let error = ImapConnection::connect_with_tls(
        server.host(),
        server.port(),
        Security::Ssl,
        std::time::Duration::from_secs(3),
        test_connector(),
    )
    .unwrap_err();
    assert!(
        matches!(
            error,
            ProtoError::Tls(_) | ProtoError::Timeout | ProtoError::Io(_)
        ),
        "{error:?}"
    );
}

#[test]
fn pop3_stls_and_implicit_tls() {
    let server = FakePop3Server::builder()
        .credentials("u", "p")
        .message(b"Subject: a\r\n\r\nx\r\n".to_vec())
        .tls(TlsMode::StartTls)
        .start();
    let mut conn = Pop3Connection::connect_with_tls(
        server.host(),
        server.port(),
        Security::StartTls,
        TIMEOUT,
        test_connector(),
    )
    .unwrap();
    assert!(conn.is_tls());
    assert!(!conn.capa().unwrap().contains(&"STLS".to_string()));
    conn.login("u", "p").unwrap();
    assert_eq!(conn.stat().unwrap().0, 1);

    let server = FakePop3Server::builder()
        .credentials("u", "p")
        .tls(TlsMode::Implicit)
        .start();
    let mut conn = Pop3Connection::connect_with_tls(
        server.host(),
        server.port(),
        Security::Ssl,
        TIMEOUT,
        test_connector(),
    )
    .unwrap();
    conn.login("u", "p").unwrap();
    conn.quit().unwrap();
}
