//! `ImapConnection` <-> `FakeImapServer` round trips.

use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::thread;
use std::time::Duration;

use super::TIMEOUT;
use crate::imap::{Arg, ImapConnection, Status};
use crate::testkit::{Failure, FakeImapServer, FakeMessage, HookAction};
use crate::{ProtoError, Security};

const USER: &str = "user@example.com";
const PASSWORD: &str = "app-password";

fn raw(from: &str, subject: &str, body: &str) -> Vec<u8> {
    format!(
        "From: {from}\r\nTo: me@example.com\r\nSubject: {subject}\r\nMessage-ID: <{subject}@example.com>\r\n\r\n{body}\r\n"
    )
    .into_bytes()
}

fn mailbox() -> FakeImapServer {
    FakeImapServer::builder()
        .credentials(USER, PASSWORD)
        .folder("Sent", &["\\Sent"])
        .folder("Trash", &["\\Trash", "\\HasNoChildren"])
        .folder("Archive/2025", &[])
        .uid_validity("INBOX", Some(137))
        .message_with(
            "INBOX",
            FakeMessage::new(raw("alice@shop.example", "Sale", "Big discounts"))
                .with_internal_date("01-Mar-2026 10:00:00 +0000"),
        )
        .message_with(
            "INBOX",
            FakeMessage::new(raw("bob@news.example", "Weekly news", "Read me"))
                .with_flags(&["\\Seen"])
                .with_internal_date("15-Mar-2026 08:30:00 +0000"),
        )
        .message_with(
            "INBOX",
            FakeMessage::new(raw("carol@bank.example", "Your código", "Ünïcode body"))
                .with_flags(&["\\Flagged"])
                .with_internal_date("20-Mar-2026 23:59:59 +0000"),
        )
        .start()
}

fn connect(server: &FakeImapServer) -> ImapConnection {
    ImapConnection::connect(server.host(), server.port(), Security::None, TIMEOUT).expect("connect")
}

fn login(server: &FakeImapServer) -> ImapConnection {
    let mut conn = connect(server);
    conn.login(USER, PASSWORD).expect("login");
    conn
}

#[test]
fn connect_reads_greeting_and_capabilities() {
    let server = mailbox();
    let conn = connect(&server);
    assert_eq!(conn.greeting(), "Fake IMAP4rev1 server ready");
    assert!(conn.has_capability("imap4rev1"));
    assert!(conn.has_capability("UIDPLUS"));
    assert!(!conn.is_tls());
    assert_eq!(server.command_names(), vec!["CAPABILITY"]);
}

#[test]
fn greeting_capability_code_skips_capability_command() {
    let server = FakeImapServer::builder()
        .credentials(USER, PASSWORD)
        .greeting_capabilities(true)
        .login_capability_code(true)
        .start();
    let mut conn = connect(&server);
    assert!(conn.has_capability("MOVE"));
    conn.login(USER, PASSWORD).unwrap();
    assert_eq!(server.command_names(), vec!["LOGIN"]);
}

#[test]
fn capabilities_refresh_after_login() {
    let server = FakeImapServer::builder()
        .credentials(USER, PASSWORD)
        .pre_auth_capabilities(&["IMAP4rev1", "AUTH=PLAIN"])
        .capabilities(&["IMAP4rev1", "MOVE", "UIDPLUS"])
        .start();
    let mut conn = connect(&server);
    assert!(!conn.has_capability("MOVE"));
    conn.login(USER, PASSWORD).unwrap();
    assert!(conn.has_capability("MOVE"));
    assert!(!conn.has_capability("AUTH=PLAIN"));
    assert_eq!(
        server.command_names(),
        vec!["CAPABILITY", "LOGIN", "CAPABILITY"]
    );
    // An explicit refresh, as save_sent_copy / delete_messages do.
    assert_eq!(
        conn.capability().unwrap(),
        vec!["IMAP4REV1", "MOVE", "UIDPLUS"]
    );
}

#[test]
fn login_failure_is_no_and_never_leaks_password() {
    let server = mailbox();
    let mut conn = connect(&server);
    let error = conn.login(USER, "wrong-secret").unwrap_err();
    assert!(matches!(error, ProtoError::No(ref text) if text.contains("AUTHENTICATIONFAILED")));
    assert!(!error.to_string().contains("wrong-secret"));
    assert!(server
        .commands()
        .iter()
        .all(|line| !line.contains("wrong-secret")));
    assert!(server.commands().contains(&format!("LOGIN {USER} ****")));
    // The connection stays usable after NO.
    conn.login(USER, PASSWORD).unwrap();
}

#[test]
fn login_with_special_and_non_ascii_passwords() {
    for password in ["p\"a\\ss word", "pässwörd", "密码"] {
        let server = FakeImapServer::builder()
            .credentials(USER, password)
            .start();
        let mut conn = connect(&server);
        conn.login(USER, password).unwrap();
        conn.logout().unwrap();
        assert_eq!(server.logout_count(), 1);
    }
}

#[test]
fn authenticate_xoauth2_and_plain() {
    let server = FakeImapServer::builder()
        .credentials(USER, PASSWORD)
        .oauth_token(USER, "ya29.token")
        .start();
    let mut conn = connect(&server);
    conn.authenticate_xoauth2(USER, "ya29.token").unwrap();
    conn.examine("INBOX").unwrap();

    let mut conn = connect(&server);
    let error = conn.authenticate_xoauth2(USER, "expired").unwrap_err();
    assert!(error.is_no(), "{error:?}");
    assert!(!error.to_string().contains("expired"));
    // Still usable: plain password login on the same connection.
    let mut challenge_count = 0;
    conn.authenticate("PLAIN", |_| {
        challenge_count += 1;
        Some(format!("\0{USER}\0{PASSWORD}").into_bytes())
    })
    .unwrap();
    assert_eq!(challenge_count, 1);

    let mut conn = connect(&server);
    let error = conn.authenticate("PLAIN", |_| None).unwrap_err();
    assert!(error.is_bad());
}

#[test]
fn select_and_examine_report_mailbox_state() {
    let server = mailbox();
    let mut conn = login(&server);
    let info = conn.select("INBOX", false).unwrap();
    assert_eq!(info.exists, 3);
    assert_eq!(info.uid_validity, Some(137));
    assert_eq!(info.uid_validity_raw.as_deref(), Some("137"));
    assert_eq!(info.uid_next, Some(4));
    assert!(!info.read_only);
    assert!(info.flags.contains(&"\\Seen".to_string()));
    assert!(info.permanent_flags.unwrap().contains(&"\\*".to_string()));

    let info = conn.select("Trash", true).unwrap();
    assert!(info.read_only);
    assert_eq!(info.exists, 0);
    assert!(info.permanent_flags.is_none());
    assert!(server.commands().contains(&"EXAMINE \"Trash\"".to_string()));

    let error = conn.select("Missing", true).unwrap_err();
    assert!(error.is_no());
}

#[test]
fn select_without_uidvalidity() {
    let server = FakeImapServer::builder()
        .credentials(USER, PASSWORD)
        .uid_validity("INBOX", None)
        .start();
    let mut conn = login(&server);
    let info = conn.examine("INBOX").unwrap();
    assert_eq!(info.uid_validity, None);
    assert_eq!(info.uid_validity_raw, None);
}

#[test]
fn uid_search_criteria() {
    let server = mailbox();
    let mut conn = login(&server);
    conn.examine("INBOX").unwrap();
    let search =
        |conn: &mut ImapConnection, criteria: &[Arg]| conn.uid_search(None, criteria).unwrap();
    assert_eq!(search(&mut conn, &["ALL".into()]), vec![1, 2, 3]);
    assert_eq!(search(&mut conn, &["UNSEEN".into()]), vec![1, 3]);
    assert_eq!(search(&mut conn, &["SEEN".into()]), vec![2]);
    assert_eq!(search(&mut conn, &["FLAGGED".into()]), vec![3]);
    assert_eq!(
        search(&mut conn, &["FROM".into(), Arg::quoted("shop.example")]),
        vec![1]
    );
    // imap_client._search_uids: OR chains for several sender domains.
    assert_eq!(
        search(
            &mut conn,
            &[
                "OR".into(),
                "FROM".into(),
                Arg::quoted("shop.example"),
                "FROM".into(),
                Arg::quoted("bank.example"),
            ]
        ),
        vec![1, 3]
    );
    assert_eq!(
        search(
            &mut conn,
            &["TEXT".into(), Arg::quoted("read me"), "SEEN".into()]
        ),
        vec![2]
    );
    assert_eq!(
        search(&mut conn, &["NOT".into(), "SEEN".into()]),
        vec![1, 3]
    );
    assert_eq!(
        search(&mut conn, &["SUBJECT".into(), Arg::quoted("weekly")]),
        vec![2]
    );
    assert_eq!(search(&mut conn, &["UID".into(), "2:*".into()]), vec![2, 3]);
    assert_eq!(search(&mut conn, &["(".into(), ")".into()]).len(), 3);
    // save_sent_copy: HEADER Message-ID "<id>"
    assert_eq!(
        search(
            &mut conn,
            &[
                "HEADER".into(),
                "Message-ID".into(),
                Arg::quoted("<Sale@example.com>")
            ]
        ),
        vec![1]
    );
    // mailbox_download: SINCE / BEFORE
    assert_eq!(
        search(&mut conn, &["SINCE".into(), "10-Mar-2026".into()]),
        vec![2, 3]
    );
    assert_eq!(
        search(
            &mut conn,
            &[
                "SINCE".into(),
                "10-Mar-2026".into(),
                "BEFORE".into(),
                "20-Mar-2026".into()
            ]
        ),
        vec![2]
    );
    assert_eq!(
        search(&mut conn, &["SUBJECT".into(), Arg::quoted("nothing")]),
        Vec::<u32>::new()
    );
    // Non-ASCII text needs CHARSET UTF-8 and is sent as a literal.
    assert_eq!(
        conn.uid_search(Some("UTF-8"), &["BODY".into(), Arg::astring("ünïcode")])
            .unwrap(),
        vec![3]
    );
    let error = conn
        .uid_search(Some("KOI8-R"), &["ALL".into()])
        .unwrap_err();
    assert!(matches!(error, ProtoError::No(ref text) if text.contains("BADCHARSET")));
    let error = conn.uid_search(None, &["BOGUS".into()]).unwrap_err();
    assert!(error.is_bad());
}

#[test]
fn non_ascii_atom_requires_utf8_mode() {
    let server = mailbox();
    let mut conn = login(&server);
    conn.examine("INBOX").unwrap();
    let error = conn
        .uid_search(None, &["TEXT".into(), Arg::quoted("código")])
        .unwrap_err();
    assert!(matches!(error, ProtoError::Encoding(_)));
    let error = conn.select("Entwürfe", true).unwrap_err();
    assert!(matches!(error, ProtoError::Encoding(_)));
    let error = conn
        .command("NOOP", &[Arg::atom("a\r\nA2 LOGOUT")])
        .unwrap_err();
    assert!(matches!(error, ProtoError::Encoding(_)));
    // Nothing was sent for rejected arguments.
    assert_eq!(server.command_names().last().unwrap(), "EXAMINE");
}

#[test]
fn fetch_summaries_keep_messages_unread() {
    let server = mailbox();
    let mut conn = login(&server);
    conn.select("INBOX", false).unwrap();
    let fetches = conn
        .uid_fetch(
            "1:3",
            "(UID FLAGS INTERNALDATE RFC822.SIZE BODY.PEEK[HEADER.FIELDS (FROM TO SUBJECT)])",
        )
        .unwrap();
    assert_eq!(fetches.len(), 3);
    let first = &fetches[0];
    assert_eq!(first.uid(), Some(1));
    assert_eq!(first.flags().unwrap(), Vec::<String>::new());
    assert_eq!(
        first.internal_date().as_deref(),
        Some("01-Mar-2026 10:00:00 +0000")
    );
    let raw_len = server.message("INBOX", 1).unwrap().raw.len() as u64;
    assert_eq!(first.rfc822_size(), Some(raw_len));
    assert_eq!(
        first.body("HEADER.FIELDS (FROM TO SUBJECT)").unwrap(),
        b"From: alice@shop.example\r\nTo: me@example.com\r\nSubject: Sale\r\n\r\n"
    );
    assert_eq!(fetches[2].flags().unwrap(), vec!["\\Flagged"]);
    assert!(server.flags("INBOX", 1).unwrap().is_empty());

    // trash._sizes / mailbox_download: (UID RFC822.SIZE), (INTERNALDATE)
    let sizes = conn.uid_fetch("2", "(UID RFC822.SIZE)").unwrap();
    assert_eq!(sizes[0].uid(), Some(2));
    let dates = conn.uid_fetch("3", "(INTERNALDATE)").unwrap();
    assert_eq!(dates[0].uid(), Some(3), "UID FETCH always includes UID");
    assert_eq!(
        dates[0].internal_date().as_deref(),
        Some("20-Mar-2026 23:59:59 +0000")
    );
    // Unknown UIDs produce no data.
    assert!(conn.uid_fetch("99", "(UID FLAGS)").unwrap().is_empty());
}

#[test]
fn body_fetch_sets_seen_only_when_read_write_and_not_peek() {
    let server = mailbox();
    let mut conn = login(&server);
    conn.examine("INBOX").unwrap();
    let fetched = conn.uid_fetch("1", "(UID BODY[])").unwrap();
    assert_eq!(
        fetched[0].body(""),
        Some(server.message("INBOX", 1).unwrap().raw.as_slice())
    );
    assert!(
        server.flags("INBOX", 1).unwrap().is_empty(),
        "EXAMINE never sets \\Seen"
    );

    conn.select("INBOX", false).unwrap();
    let peek = conn
        .uid_fetch("1", "(UID FLAGS INTERNALDATE BODY.PEEK[])")
        .unwrap();
    assert!(peek[0].body("").is_some());
    assert!(server.flags("INBOX", 1).unwrap().is_empty());

    let fetched = conn.uid_fetch("1", "(BODY[TEXT])").unwrap();
    assert_eq!(fetched[0].body("TEXT"), Some(&b"Big discounts\r\n"[..]));
    assert!(
        fetched[0].has_flag("\\Seen"),
        "FLAGS reported after implicit \\Seen"
    );
    assert_eq!(server.flags("INBOX", 1).unwrap(), vec!["\\Seen"]);

    let rfc822 = conn.uid_fetch("3", "RFC822").unwrap();
    assert!(rfc822[0].first_body().unwrap().starts_with(b"From: carol"));
    assert!(server.message("INBOX", 3).unwrap().has_flag("\\Seen"));

    let partial = conn.uid_fetch("2", "(BODY.PEEK[]<0.4>)").unwrap();
    assert_eq!(partial[0].body(""), Some(&b"From"[..]));
    let header = conn
        .uid_fetch("2", "(BODY.PEEK[HEADER.FIELDS.NOT (TO FROM MESSAGE-ID)])")
        .unwrap();
    assert_eq!(
        header[0].body("HEADER.FIELDS.NOT (TO FROM MESSAGE-ID)"),
        Some(&b"Subject: Weekly news\r\n\r\n"[..])
    );
    // Sequence-number FETCH.
    let by_seq = conn.fetch("2:3", "(UID)").unwrap();
    assert_eq!(
        by_seq.iter().map(|f| (f.seq, f.uid())).collect::<Vec<_>>(),
        vec![(2, Some(2)), (3, Some(3))]
    );
}

#[test]
fn store_flags() {
    let server = mailbox();
    let mut conn = login(&server);
    conn.select("INBOX", false).unwrap();
    let updated = conn.uid_store("1", "+FLAGS", "(\\Seen \\Flagged)").unwrap();
    assert_eq!(updated.len(), 1);
    assert_eq!(updated[0].uid(), Some(1));
    assert_eq!(updated[0].flags().unwrap(), vec!["\\Seen", "\\Flagged"]);
    let updated = conn.uid_store("1", "-FLAGS", "(\\Seen)").unwrap();
    assert_eq!(updated[0].flags().unwrap(), vec!["\\Flagged"]);
    let silent = conn
        .uid_store("1,3", "+FLAGS.SILENT", "(\\Deleted)")
        .unwrap();
    assert!(silent.is_empty());
    assert!(server.message("INBOX", 3).unwrap().has_flag("\\Deleted"));

    conn.examine("INBOX").unwrap();
    assert!(conn
        .uid_store("1", "+FLAGS", "(\\Seen)")
        .unwrap_err()
        .is_no());
}

#[test]
fn move_to_trash_returns_copyuid() {
    let server = mailbox();
    let mut conn = login(&server);
    conn.select("INBOX", false).unwrap();
    let copy = conn.uid_move("1,3", "Trash").unwrap().expect("COPYUID");
    assert_eq!(copy.pairs().unwrap(), vec![(1, 1), (3, 2)]);
    assert_eq!(server.uids("INBOX"), vec![2]);
    assert_eq!(server.uids("Trash"), vec![1, 2]);
    assert_eq!(
        server.message("Trash", 2).unwrap().raw,
        raw("carol@bank.example", "Your código", "Ünïcode body")
    );
    let error = conn.uid_move("2", "Nowhere").unwrap_err();
    assert!(matches!(error, ProtoError::No(ref text) if text.contains("TRYCREATE")));
}

#[test]
fn move_requires_capability() {
    let server = FakeImapServer::builder()
        .credentials(USER, PASSWORD)
        .capabilities(&["IMAP4rev1", "UIDPLUS"])
        .folder("Trash", &["\\Trash"])
        .message("INBOX", raw("a@b.c", "x", "y"))
        .start();
    let mut conn = login(&server);
    assert!(!conn.has_capability("MOVE"));
    conn.select("INBOX", false).unwrap();
    assert!(conn.uid_move("1", "Trash").unwrap_err().is_bad());
}

#[test]
fn copy_store_and_uid_expunge_only_touch_selected_uids() {
    let server = mailbox();
    server.with_folders(|folders| folders[0].messages[1].flags.push("\\Deleted".into()));
    let mut conn = login(&server);
    conn.select("INBOX", false).unwrap();
    let copy = conn.uid_copy("1", "Trash").unwrap().unwrap();
    assert_eq!(copy.source, "1");
    conn.uid_store("1", "+FLAGS.SILENT", "(\\Deleted)").unwrap();
    let expunged = conn.uid_expunge("1").unwrap();
    assert_eq!(expunged, vec![1]);
    // UID 2 was marked \Deleted by "another client" and must survive.
    assert_eq!(server.uids("INBOX"), vec![2, 3]);
    assert_eq!(server.uids("Trash"), vec![1]);
    // Mailbox-wide EXPUNGE removes it.
    assert_eq!(conn.expunge().unwrap(), vec![1]);
    assert_eq!(server.uids("INBOX"), vec![3]);
}

#[test]
fn uid_expunge_requires_uidplus() {
    let server = FakeImapServer::builder()
        .credentials(USER, PASSWORD)
        .capabilities(&["IMAP4rev1", "MOVE"])
        .message("INBOX", raw("a@b.c", "x", "y"))
        .start();
    let mut conn = login(&server);
    conn.select("INBOX", false).unwrap();
    assert!(conn.uid_expunge("1").unwrap_err().is_bad());
}

#[test]
fn append_with_flags_date_and_crlf_normalization() {
    let server = mailbox();
    let mut conn = login(&server);
    let message = b"From: me@example.com\nSubject: sent\n\nhello\n";
    let appended = conn
        .append(
            "Sent",
            Some("\\Seen"),
            Some("05-Apr-2026 12:00:00 +0200"),
            message,
        )
        .unwrap()
        .expect("APPENDUID");
    assert_eq!(appended.uids, "1");
    let stored = server.message("Sent", 1).unwrap();
    assert_eq!(stored.flags, vec!["\\Seen"]);
    assert_eq!(stored.internal_date, "05-Apr-2026 12:00:00 +0200");
    assert_eq!(
        stored.raw,
        b"From: me@example.com\r\nSubject: sent\r\n\r\nhello\r\n".to_vec()
    );
    let line = server
        .commands()
        .into_iter()
        .find(|l| l.starts_with("APPEND"))
        .unwrap();
    assert!(
        line.starts_with("APPEND \"Sent\" (\\Seen) \"05-Apr-2026 12:00:00 +0200\" {"),
        "{line}"
    );

    // imap_client.save_sent_copy: append(folder, "(\\Seen)", None, raw)
    conn.append("Sent", Some("(\\Seen)"), None, b"Subject: two\r\n\r\nx\r\n")
        .unwrap();
    assert_eq!(server.uids("Sent"), vec![1, 2]);

    let error = conn.append("Missing", None, None, b"x").unwrap_err();
    assert!(matches!(error, ProtoError::No(ref text) if text.contains("TRYCREATE")));
}

#[test]
fn append_after_enable_utf8_uses_literal8() {
    let server = mailbox();
    let mut conn = login(&server);
    let enabled = conn.enable("UTF8=ACCEPT").unwrap();
    assert_eq!(enabled, vec!["UTF8=ACCEPT"]);
    assert!(conn.utf8_enabled());
    let message = "From: me@example.com\r\nTo: empfänger@bücher.example\r\n\r\nGrüße\r\n";
    conn.append("Sent", Some("(\\Seen)"), None, message.as_bytes())
        .unwrap();
    assert_eq!(server.message("Sent", 1).unwrap().raw, message.as_bytes());
    let line = server
        .commands()
        .into_iter()
        .find(|l| l.starts_with("APPEND"))
        .unwrap();
    assert!(line.contains("UTF8 (~{"), "{line}");
    // UTF-8 mailbox names are allowed now.
    conn.create("Entwürfe").unwrap();
    conn.select("Entwürfe", true).unwrap();
    assert!(server.folder("Entwürfe").is_some());
}

#[test]
fn enable_requires_capability() {
    let server = FakeImapServer::builder()
        .credentials(USER, PASSWORD)
        .capabilities(&["IMAP4rev1"])
        .start();
    let mut conn = login(&server);
    let error = conn.enable("UTF8=ACCEPT").unwrap_err();
    assert!(
        matches!(error, ProtoError::Protocol(ref text) if text == "Server does not support ENABLE")
    );
    assert!(!server.command_names().contains(&"ENABLE".to_string()));
}

#[test]
fn rev2_allows_utf8_arguments_without_enable() {
    let server = FakeImapServer::builder()
        .credentials(USER, PASSWORD)
        .capabilities(&["IMAP4rev2"])
        .start();
    let mut conn = login(&server);
    conn.create("Gesendete Elemente/Привет").unwrap();
    assert!(server.folder("Gesendete Elemente/Привет").is_some());
}

#[test]
fn create_list_and_special_use() {
    let server = mailbox();
    let mut conn = login(&server);
    conn.create("My \"Box\"").unwrap();
    let error = conn.create("Sent").unwrap_err();
    assert!(matches!(error, ProtoError::No(ref text) if text.contains("ALREADYEXISTS")));
    let folders = conn.list("", "*").unwrap();
    let names: Vec<&str> = folders.iter().map(|f| f.name.as_str()).collect();
    assert_eq!(
        names,
        vec!["INBOX", "Sent", "Trash", "Archive/2025", "My \"Box\""]
    );
    let trash = folders.iter().find(|f| f.name == "Trash").unwrap();
    assert!(trash.has_attribute("\\Trash"));
    assert_eq!(trash.delimiter.as_deref(), Some("/"));
    assert!(server.commands().contains(&"LIST \"\" \"*\"".to_string()));

    let top = conn.list("", "%").unwrap();
    assert!(top.iter().all(|f| f.name != "Archive/2025"));
    let archive = conn.list("Archive/", "%").unwrap();
    assert_eq!(archive.len(), 1);
    assert_eq!(conn.list("", "inbox").unwrap()[0].name, "INBOX");

    let special = conn.list_special_use().unwrap();
    assert!(special
        .iter()
        .any(|f| f.name == "Sent" && f.has_attribute("\\Sent")));
    assert!(server
        .commands()
        .contains(&"LIST \"\" \"*\" RETURN (SPECIAL-USE)".to_string()));
}

#[test]
fn special_use_only_on_request_and_capability() {
    let server = FakeImapServer::builder()
        .credentials(USER, PASSWORD)
        .special_use_in_plain_list(false)
        .folder("Sent", &["\\Sent"])
        .start();
    let mut conn = login(&server);
    let plain = conn.list("", "*").unwrap();
    assert!(!plain.iter().any(|f| f.has_attribute("\\Sent")));
    let special = conn.list_special_use().unwrap();
    assert!(special.iter().any(|f| f.has_attribute("\\Sent")));

    let server = FakeImapServer::builder()
        .credentials(USER, PASSWORD)
        .capabilities(&["IMAP4rev1"])
        .start();
    let mut conn = login(&server);
    assert!(conn.list_special_use().unwrap_err().is_bad());
    assert_eq!(conn.list("", "*").unwrap().len(), 1);
}

#[test]
fn literal_mailbox_names() {
    let server = FakeImapServer::builder()
        .credentials(USER, PASSWORD)
        .literal_names(true)
        .delimiter(None)
        .folder("Entw&APw-rfe", &["\\Drafts"])
        .start();
    let mut conn = login(&server);
    let folders = conn.list("", "*").unwrap();
    assert!(folders
        .iter()
        .all(|f| f.name_was_literal && f.delimiter.is_none()));
    let drafts = folders
        .iter()
        .find(|f| f.has_attribute("\\Drafts"))
        .unwrap();
    assert_eq!(drafts.name, "Entw&APw-rfe");
    assert_eq!(drafts.decoded_name(), "Entwürfe");
}

#[test]
fn status_command() {
    let server = mailbox();
    let mut conn = login(&server);
    let status = conn
        .status("INBOX", "(MESSAGES UNSEEN UIDNEXT UIDVALIDITY)")
        .unwrap();
    assert_eq!(
        status,
        vec![
            ("MESSAGES".to_string(), 3),
            ("UNSEEN".to_string(), 2),
            ("UIDNEXT".to_string(), 4),
            ("UIDVALIDITY".to_string(), 137),
        ]
    );
}

#[test]
fn generic_command_returns_status_without_error() {
    let server = mailbox();
    let mut conn = login(&server);
    let response = conn.command("SELECT", &[Arg::quoted("Missing")]).unwrap();
    assert_eq!(response.status, Status::No);
    assert!(!response.is_ok());
    let response = conn.command("FROBNICATE", &[]).unwrap();
    assert_eq!(response.status, Status::Bad);
    let response = conn.uid("search", &["ALL".into()]).unwrap();
    assert_eq!(
        response.status,
        Status::Bad,
        "SEARCH without a selected mailbox"
    );
    conn.examine("INBOX").unwrap();
    let response = conn.uid("search", &["ALL".into()]).unwrap();
    assert_eq!(response.search_results().unwrap(), vec![1, 2, 3]);
    conn.noop().unwrap();
    conn.close().unwrap();
}

#[test]
fn logout_closes_connection() {
    let server = mailbox();
    let mut conn = login(&server);
    conn.logout().unwrap();
    assert_eq!(server.logout_count(), 1);
    assert!(matches!(conn.noop().unwrap_err(), ProtoError::Closed(_)));
    conn.logout().unwrap();
}

#[test]
fn failure_injection() {
    let server = mailbox();
    server.fail_next("UID MOVE", Failure::No("only one message moved".into()));
    server.fail_next("SELECT", Failure::Bad("bad select".into()));
    let mut conn = login(&server);
    assert!(conn.select("INBOX", false).unwrap_err().is_bad());
    conn.select("INBOX", false).unwrap();
    let error = conn.uid_move("1", "Trash").unwrap_err();
    assert!(matches!(error, ProtoError::No(ref text) if text == "only one message moved"));
    assert_eq!(
        server.uids("INBOX"),
        vec![1, 2, 3],
        "the failed MOVE did nothing"
    );
    conn.uid_move("1", "Trash").unwrap();

    server.fail_next("UID FETCH", Failure::Disconnect);
    let error = conn.uid_fetch("2", "(UID)").unwrap_err();
    assert!(matches!(error, ProtoError::Closed(_)), "{error:?}");
    assert!(matches!(conn.noop().unwrap_err(), ProtoError::Closed(_)));

    server.fail_next("LOGIN", Failure::no());
    let mut conn = connect(&server);
    assert!(conn.login(USER, PASSWORD).unwrap_err().is_no());
}

#[test]
fn hook_can_inject_custom_and_unsolicited_responses() {
    let server = mailbox();
    server.set_hook(|request| {
        if request.command == "UID FETCH" && request.line.contains("BODY.PEEK[]") {
            let mut fetch = b"* 1 FETCH (UID 99 BODY[] {5}\r\nhello)".to_vec();
            fetch.extend_from_slice(b"");
            HookAction::Respond {
                untagged: vec![
                    b"* 4 EXISTS".to_vec(),
                    fetch,
                    b"* 2 FETCH (FLAGS (\\Seen))".to_vec(),
                ],
                status: Status::Ok,
                text: "FETCH completed".into(),
            }
        } else {
            HookAction::Continue
        }
    });
    let mut conn = login(&server);
    conn.examine("INBOX").unwrap();
    let fetches = conn.uid_fetch("1", "(UID BODY.PEEK[])").unwrap();
    assert_eq!(fetches.len(), 2);
    assert_eq!(fetches[0].uid(), Some(99));
    assert_eq!(fetches[0].body(""), Some(&b"hello"[..]));
    assert_eq!(fetches[1].uid(), None);
    server.clear_hook();
    assert_eq!(conn.uid_fetch("1", "(UID)").unwrap()[0].uid(), Some(1));
}

#[test]
fn large_and_binary_literals_round_trip() {
    let mut body = Vec::new();
    while body.len() < 3 * 1024 * 1024 {
        body.extend_from_slice(b"0123456789 {12}\r\n.)\r\n* 9 FETCH x\r\n");
    }
    let mut message = b"Subject: big\r\n\r\n".to_vec();
    message.extend_from_slice(&body);
    let server = FakeImapServer::builder()
        .credentials(USER, PASSWORD)
        .message("INBOX", message.clone())
        .start();
    let mut conn = login(&server);
    conn.examine("INBOX").unwrap();
    let fetched = conn.uid_fetch("1", "(UID BODY.PEEK[])").unwrap();
    assert_eq!(fetched[0].body("").unwrap(), message.as_slice());

    conn.set_max_literal_size(1024);
    let error = conn.uid_fetch("1", "(UID BODY.PEEK[])").unwrap_err();
    assert!(matches!(error, ProtoError::Protocol(_)), "{error:?}");
}

#[test]
fn append_large_message() {
    let server = mailbox();
    let mut conn = login(&server);
    let mut message = b"Subject: big\r\n\r\n".to_vec();
    message.resize(2 * 1024 * 1024, b'x');
    message.extend_from_slice(b"\r\n");
    conn.append("Sent", None, None, &message).unwrap();
    assert_eq!(server.message("Sent", 1).unwrap().raw, message);
}

#[test]
fn starttls_not_advertised_fails_before_sending() {
    let server = mailbox();
    let error = ImapConnection::connect(server.host(), server.port(), Security::StartTls, TIMEOUT)
        .unwrap_err();
    assert!(
        matches!(error, ProtoError::Protocol(ref text) if text == "TLS not supported by server")
    );
    assert_eq!(server.command_names(), vec!["CAPABILITY"]);
}

/// A scripted raw server: sends `script` lines in order after reading one
/// client line for each `None` entry.
fn scripted_server(script: Vec<Option<&'static [u8]>>) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        let mut reader = BufReader::new(stream.try_clone().unwrap());
        let mut writer = stream;
        for step in script {
            match step {
                Some(data) => {
                    let _ = writer.write_all(data);
                }
                None => {
                    let mut line = String::new();
                    if reader.read_line(&mut line).unwrap_or(0) == 0 {
                        return;
                    }
                }
            }
        }
        thread::sleep(Duration::from_millis(200));
    });
    port
}

#[test]
fn bye_greeting_is_refused() {
    let port = scripted_server(vec![Some(b"* BYE Too many connections\r\n")]);
    let error = ImapConnection::connect("127.0.0.1", port, Security::None, TIMEOUT).unwrap_err();
    assert!(
        matches!(error, ProtoError::Protocol(ref text) if text.contains("Too many connections"))
    );
}

#[test]
fn starttls_rejects_data_injected_before_handshake() {
    let port = scripted_server(vec![
        Some(b"* OK [CAPABILITY IMAP4rev1 STARTTLS] ready\r\n"),
        None,
        Some(b"A0001 OK Begin TLS\r\n* OK [CAPABILITY IMAP4rev1 AUTH=PLAIN] injected\r\n"),
    ]);
    let error =
        ImapConnection::connect("127.0.0.1", port, Security::StartTls, TIMEOUT).unwrap_err();
    assert!(
        matches!(error, ProtoError::Protocol(ref text) if text.contains("before the TLS handshake")),
        "{error:?}"
    );
}

#[test]
fn starttls_refused_by_server() {
    let port = scripted_server(vec![
        Some(b"* OK [CAPABILITY IMAP4rev1 STARTTLS] ready\r\n"),
        None,
        Some(b"A0001 NO TLS unavailable\r\n"),
    ]);
    let error =
        ImapConnection::connect("127.0.0.1", port, Security::StartTls, TIMEOUT).unwrap_err();
    assert!(error.is_no(), "{error:?}");
}

#[test]
fn unexpected_tag_and_eof_are_errors() {
    let port = scripted_server(vec![
        Some(b"* OK [CAPABILITY IMAP4rev1] ready\r\n"),
        None,
        Some(b"Z9999 OK wrong tag\r\n"),
    ]);
    let mut conn = ImapConnection::connect("127.0.0.1", port, Security::None, TIMEOUT).unwrap();
    assert!(matches!(conn.noop().unwrap_err(), ProtoError::Protocol(_)));

    let port = scripted_server(vec![Some(b"* OK [CAPABILITY IMAP4rev1] ready\r\n"), None]);
    let mut conn = ImapConnection::connect("127.0.0.1", port, Security::None, TIMEOUT).unwrap();
    assert!(matches!(conn.noop().unwrap_err(), ProtoError::Closed(_)));
}

#[test]
fn read_timeout() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let handle = thread::spawn(move || {
        let (_stream, _) = listener.accept().unwrap();
        thread::sleep(Duration::from_millis(1500));
    });
    let error = ImapConnection::connect(
        "127.0.0.1",
        port,
        Security::None,
        Duration::from_millis(300),
    )
    .unwrap_err();
    assert!(error.is_timeout(), "{error:?}");
    handle.join().unwrap();
}

#[test]
fn connection_refused_is_io_error() {
    let port = {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.local_addr().unwrap().port()
    };
    let error = ImapConnection::connect("127.0.0.1", port, Security::None, TIMEOUT).unwrap_err();
    assert!(
        matches!(error, ProtoError::Io(_) | ProtoError::Timeout),
        "{error:?}"
    );
}

#[test]
fn security_parsing() {
    assert_eq!(Security::parse("ssl"), Some(Security::Ssl));
    assert_eq!(Security::parse("SSL/TLS"), Some(Security::Ssl));
    assert_eq!(Security::parse("STARTTLS"), Some(Security::StartTls));
    assert_eq!(Security::parse("none"), Some(Security::None));
    assert_eq!(Security::parse("NONE"), Some(Security::None));
    assert_eq!(Security::parse("tls1.3"), None);
    assert_eq!("starttls".parse::<Security>().unwrap().as_str(), "starttls");
}
