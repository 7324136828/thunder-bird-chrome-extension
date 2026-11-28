//! Uses the testkit exactly as another crate would (public API only).
//! Run with `cargo test -p mail-proto --features testkit`.
#![cfg(feature = "testkit")]

use mail_proto::imap::{Arg, ImapConnection};
use mail_proto::pop3::Pop3Connection;
use mail_proto::testkit::{Failure, FakeImapServer, FakeMessage, FakePop3Server, FakeSmtpServer};
use mail_proto::{ProtoError, Security, DEFAULT_TIMEOUT};

#[test]
fn imap_delete_flow_like_imap_client_delete_messages() {
    let server = FakeImapServer::builder()
        .credentials("user@example.com", "pw")
        .folder("Trash", &["\\Trash"])
        .uid_validity("INBOX", Some(42))
        .message_with(
            "INBOX",
            FakeMessage::new(b"Subject: a\r\n\r\nx\r\n".to_vec()).with_uid(7),
        )
        .message("INBOX", b"Subject: b\r\n\r\ny\r\n".to_vec())
        .start();
    let mut conn = ImapConnection::connect(
        server.host(),
        server.port(),
        Security::None,
        DEFAULT_TIMEOUT,
    )
    .unwrap();
    conn.login("user@example.com", "pw").unwrap();
    let capabilities = conn.capability().unwrap();
    assert!(capabilities.contains(&"MOVE".to_string()));
    let info = conn.select("INBOX", false).unwrap();
    assert_eq!(info.uid_validity, Some(42));
    assert_eq!(
        conn.uid_search(None, &[Arg::atom("ALL")]).unwrap(),
        vec![7, 8]
    );
    conn.uid_move("7", "Trash").unwrap();
    conn.logout().unwrap();
    assert_eq!(server.uids("INBOX"), vec![8]);
    assert_eq!(server.uids("Trash"), vec![1]);
    assert_eq!(
        server.command_names(),
        vec![
            "CAPABILITY",
            "LOGIN",
            "CAPABILITY",
            "CAPABILITY",
            "SELECT",
            "UID SEARCH",
            "UID MOVE",
            "LOGOUT"
        ]
    );
}

#[test]
fn pop3_and_smtp_are_reachable() {
    let pop3 = FakePop3Server::builder()
        .credentials("u", "p")
        .message(b"Subject: x\r\n\r\nbody\r\n".to_vec())
        .start();
    pop3.fail_next("PASS", Failure::no());
    let mut conn =
        Pop3Connection::connect(pop3.host(), pop3.port(), Security::None, DEFAULT_TIMEOUT).unwrap();
    assert!(matches!(conn.login("u", "p"), Err(ProtoError::No(_))));
    conn.login("u", "p").unwrap();
    assert_eq!(
        conn.retr(1).unwrap(),
        b"Subject: x\r\n\r\nbody\r\n".to_vec()
    );

    let smtp = FakeSmtpServer::builder().start();
    assert!(smtp.messages().is_empty());
    assert!(smtp.port() > 0);
}
