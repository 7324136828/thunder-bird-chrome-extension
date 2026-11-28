//! `Pop3Connection` <-> `FakePop3Server` round trips.

use super::TIMEOUT;
use crate::pop3::{Pop3Connection, Pop3ListEntry, Pop3UidlEntry};
use crate::testkit::{Failure, FakePop3Server};
use crate::{ProtoError, Security};

const FIRST: &[u8] = b"From: a@example.com\r\nSubject: one\r\n\r\nline 1\r\n.leading dot\r\n..two dots\r\nline 4\r\n";
const SECOND: &[u8] = b"From: b@example.com\nSubject: two\n\nbody only LF\n";

fn server() -> FakePop3Server {
    FakePop3Server::builder()
        .credentials("user@example.com", "secret")
        .message_with_uid(FIRST.to_vec(), "AAA111")
        .message(SECOND.to_vec())
        .start()
}

fn login(server: &FakePop3Server) -> Pop3Connection {
    let mut conn =
        Pop3Connection::connect(server.host(), server.port(), Security::None, TIMEOUT).unwrap();
    conn.login("user@example.com", "secret").unwrap();
    conn
}

#[test]
fn greeting_and_capa() {
    let server = server();
    let mut conn =
        Pop3Connection::connect(server.host(), server.port(), Security::None, TIMEOUT).unwrap();
    assert!(conn.greeting().starts_with("Fake POP3 server ready"));
    assert_eq!(conn.capa().unwrap(), vec!["USER", "UIDL", "TOP"]);
}

#[test]
fn stat_list_uidl() {
    let server = server();
    let mut conn = login(&server);
    let second_crlf = b"From: b@example.com\r\nSubject: two\r\n\r\nbody only LF\r\n";
    assert_eq!(
        conn.stat().unwrap(),
        (2, (FIRST.len() + second_crlf.len()) as u64)
    );
    assert_eq!(
        conn.list().unwrap(),
        vec![
            Pop3ListEntry {
                number: 1,
                size: FIRST.len() as u64
            },
            Pop3ListEntry {
                number: 2,
                size: second_crlf.len() as u64
            },
        ]
    );
    assert_eq!(conn.list_one(2).unwrap().size, second_crlf.len() as u64);
    assert_eq!(
        conn.uidl().unwrap(),
        vec![
            Pop3UidlEntry {
                number: 1,
                uid: "AAA111".into()
            },
            Pop3UidlEntry {
                number: 2,
                uid: "uid-1".into()
            },
        ]
    );
    assert_eq!(conn.uidl_one(1).unwrap().uid, "AAA111");
    assert!(conn.list_one(9).unwrap_err().is_no());
}

#[test]
fn retr_unstuffs_dots_and_top_limits_body() {
    let server = server();
    let mut conn = login(&server);
    assert_eq!(conn.retr(1).unwrap(), FIRST.to_vec());
    assert_eq!(
        conn.retr(2).unwrap(),
        b"From: b@example.com\r\nSubject: two\r\n\r\nbody only LF\r\n".to_vec()
    );
    assert_eq!(
        conn.top(1, 2).unwrap(),
        b"From: a@example.com\r\nSubject: one\r\n\r\nline 1\r\n.leading dot\r\n".to_vec()
    );
    assert_eq!(
        conn.top(1, 0).unwrap(),
        b"From: a@example.com\r\nSubject: one\r\n\r\n".to_vec()
    );
    assert!(conn.retr(3).unwrap_err().is_no());
}

#[test]
fn dele_rset_and_quit_commit() {
    let server = server();
    let mut conn = login(&server);
    conn.dele(1).unwrap();
    assert_eq!(conn.stat().unwrap().0, 1);
    assert!(conn.retr(1).unwrap_err().is_no());
    conn.rset().unwrap();
    assert_eq!(conn.stat().unwrap().0, 2);
    conn.dele(2).unwrap();
    conn.noop().unwrap();
    conn.quit().unwrap();
    assert_eq!(server.uids(), vec!["AAA111"]);
    assert!(matches!(conn.noop().unwrap_err(), ProtoError::Closed(_)));

    // Dropping without QUIT never deletes.
    let mut conn = login(&server);
    conn.dele(1).unwrap();
    drop(conn);
    std::thread::sleep(std::time::Duration::from_millis(100));
    assert_eq!(server.uids(), vec!["AAA111"]);
}

#[test]
fn bad_password_is_no_and_redacted() {
    let server = server();
    let mut conn =
        Pop3Connection::connect(server.host(), server.port(), Security::None, TIMEOUT).unwrap();
    let error = conn.login("user@example.com", "nope-secret").unwrap_err();
    assert!(error.is_no());
    assert!(!error.to_string().contains("nope-secret"));
    assert!(server.commands().contains(&"PASS ****".to_string()));
    assert!(server.commands().iter().all(|c| !c.contains("nope-secret")));
    // Commands before login fail.
    assert!(conn.stat().unwrap_err().is_no());
}

#[test]
fn failure_injection_and_stls_absent() {
    let server = server();
    server.fail_next("RETR", Failure::No("temporarily unavailable".into()));
    let mut conn = login(&server);
    let error = conn.retr(1).unwrap_err();
    assert!(matches!(error, ProtoError::No(ref t) if t == "temporarily unavailable"));
    assert_eq!(conn.retr(1).unwrap(), FIRST.to_vec());
    server.fail_next("STAT", Failure::Disconnect);
    assert!(matches!(conn.stat().unwrap_err(), ProtoError::Closed(_)));

    let error = Pop3Connection::connect(server.host(), server.port(), Security::StartTls, TIMEOUT)
        .unwrap_err();
    assert!(error.is_no());
}

#[test]
fn command_arguments_cannot_inject_lines() {
    let server = server();
    let mut conn =
        Pop3Connection::connect(server.host(), server.port(), Security::None, TIMEOUT).unwrap();
    let error = conn.user("x\r\nQUIT").unwrap_err();
    assert!(matches!(error, ProtoError::Encoding(_)));
}

#[test]
fn max_response_size() {
    let server = server();
    let mut conn = login(&server);
    conn.set_max_response_size(16);
    assert!(matches!(conn.retr(1).unwrap_err(), ProtoError::Protocol(_)));
}
