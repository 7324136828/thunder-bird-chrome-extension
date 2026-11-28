//! Security audit: protocol command / header injection through user input.
//!
//! Folder names, search queries, recipients, subjects, reply headers,
//! display names and attachment metadata all come from the extension (or the
//! MCP server, i.e. possibly from an LLM reading attacker-written mail). None
//! of them may smuggle an extra IMAP command, POP3 command or RFC 5322
//! header onto the wire.

use mail_core::imap::{self, ListMessagesOptions};
use mail_core::send_uploads::MessageFile;
use mail_core::sessions::MailAccount;
use mail_core::smtp::{self, OutgoingMessage};
use mail_proto::testkit::{FakeImapServer, FakeMessage, FakePop3Server, FakeSmtpServer};

const USER: &str = "user@example.com";
const PASSWORD: &str = "audit-Pa55word";

fn imap_server() -> FakeImapServer {
    FakeImapServer::builder()
        .credentials(USER, PASSWORD)
        .folder("Sent", &["\\Sent"])
        .folder("Victim", &[])
        .message_with(
            "INBOX",
            FakeMessage::new(b"Subject: hi\r\nFrom: a@example.com\r\n\r\nbody\r\n".to_vec())
                .with_uid(1)
                .with_internal_date("01-Jan-2020 00:00:00 +0000"),
        )
        .start()
}

fn account(imap_port: u16, smtp_port: u16) -> MailAccount {
    MailAccount::new(
        USER,
        PASSWORD,
        "127.0.0.1",
        imap_port,
        "none",
        "127.0.0.1",
        smtp_port,
        "none",
    )
}

/// Commands other than the session boilerplate.
fn injected(server: &FakeImapServer) -> Vec<String> {
    server
        .log()
        .into_iter()
        .filter(|command| {
            matches!(
                command.name.as_str(),
                "DELETE" | "RENAME" | "EXPUNGE" | "UID EXPUNGE" | "STORE" | "UID STORE" | "APPEND"
            )
        })
        .map(|command| command.line)
        .collect()
}

#[test]
fn imap_folder_names_cannot_inject_commands() {
    let server = imap_server();
    let account = account(server.port(), 1);
    for folder in [
        "INBOX\r\nA999 DELETE Victim",
        "INBOX\" \r\nA999 DELETE \"Victim",
        "INBOX\nA999 DELETE Victim",
        "INBOX\0A999 DELETE Victim",
    ] {
        let result = imap::list_messages(&account, folder, &ListMessagesOptions::default());
        assert!(result.is_err(), "{folder:?} was accepted");
        assert!(imap::list_messages(&account, "INBOX", &ListMessagesOptions::default()).is_ok());
        let result = imap::fetch_message(&account, folder, 1, false, None, None);
        assert!(result.is_err(), "{folder:?} was accepted");
    }
    assert_eq!(injected(&server), Vec::<String>::new());
    assert!(server.folder("Victim").is_some(), "the folder was deleted");
    // Quotes and backslashes are escaped inside the quoted mailbox name.
    let _ = imap::list_messages(
        &account,
        "Vic\"tim\\\" DELETE \"Victim",
        &ListMessagesOptions::default(),
    );
    assert_eq!(injected(&server), Vec::<String>::new());
    assert!(server.folder("Victim").is_some());
}

#[test]
fn imap_search_query_cannot_inject_commands() {
    let server = imap_server();
    let account = account(server.port(), 1);
    for query in [
        "x\r\nA999 DELETE Victim",
        "x\" ALL\r\nA999 DELETE \"Victim",
        "x\\\" OR ALL \\\"",
    ] {
        let options = ListMessagesOptions {
            query,
            ..Default::default()
        };
        let _ = imap::list_messages(&account, "INBOX", &options);
    }
    assert_eq!(injected(&server), Vec::<String>::new());
    assert!(server.folder("Victim").is_some(), "the folder was deleted");
    // The search criterion stays a single quoted string.
    for line in server.commands() {
        if line.to_uppercase().contains("SEARCH") {
            assert!(!line.contains('\r') && !line.contains('\n'), "{line:?}");
        }
    }
}

#[test]
fn pop3_credentials_cannot_inject_commands() {
    let server = FakePop3Server::builder()
        .credentials(USER, PASSWORD)
        .message(b"Subject: keep me\r\n\r\nbody\r\n".to_vec())
        .start();
    for (email, password) in [
        ("user@example.com\r\nDELE 1", PASSWORD),
        (USER, "audit-Pa55word\r\nDELE 1"),
    ] {
        let mut account = MailAccount::new(
            email,
            password,
            "127.0.0.1",
            server.port(),
            "none",
            "127.0.0.1",
            1,
            "none",
        );
        account.incoming_mail_protocol = "pop3".into();
        assert!(imap::verify_login(&account).is_err());
    }
    assert!(
        server
            .commands()
            .iter()
            .all(|line| !line.to_uppercase().starts_with("DELE")),
        "{:?}",
        server.commands()
    );
    // Positive control: the clean credentials sign in.
    let mut good = MailAccount::new(
        USER,
        PASSWORD,
        "127.0.0.1",
        server.port(),
        "none",
        "127.0.0.1",
        1,
        "none",
    );
    good.incoming_mail_protocol = "pop3".into();
    imap::verify_login(&good).expect("clean POP3 login");
    assert_eq!(server.messages().len(), 1, "a message was deleted");
}

fn send(
    smtp_server: &FakeSmtpServer,
    imap: &FakeImapServer,
    change: impl FnOnce(&mut OutgoingMessage, &mut MailAccount),
) -> mail_core::Result<serde_json::Map<String, serde_json::Value>> {
    let mut account = account(imap.port(), smtp_server.port());
    let mut message = OutgoingMessage {
        to: vec!["Recipient <to@example.com>".into()],
        subject: "Hello".into(),
        text: "Body".into(),
        ..Default::default()
    };
    change(&mut message, &mut account);
    smtp::send_message(&account, &message)
}

#[test]
fn smtp_headers_cannot_be_injected() {
    let smtp_server = FakeSmtpServer::builder()
        .credentials(USER, PASSWORD)
        .start();
    let imap = imap_server();
    let evil = "\r\nBcc: attacker@example.net";
    type Change = Box<dyn Fn(&mut OutgoingMessage, &mut MailAccount)>;
    let cases: Vec<(&str, Change)> = vec![
        (
            "subject",
            Box::new(move |m, _| m.subject = format!("Hi{evil}")),
        ),
        (
            "subject-lf",
            Box::new(|m, _| m.subject = "Hi\nBcc: attacker@example.net".into()),
        ),
        (
            "to",
            Box::new(move |m, _| m.to = vec![format!("to@example.com{evil}")]),
        ),
        (
            "cc",
            Box::new(move |m, _| m.cc = vec![format!("Name{evil} <cc@example.com>")]),
        ),
        (
            "in_reply_to",
            Box::new(move |m, _| m.in_reply_to = format!("<a@example.com>{evil}")),
        ),
        (
            "references",
            Box::new(move |m, _| {
                m.in_reply_to = "<a@example.com>".into();
                m.references = format!("<a@example.com>{evil}");
            }),
        ),
        (
            "display_name",
            Box::new(move |_, a| a.display_name = format!("Me{evil}")),
        ),
        (
            "attachment filename",
            Box::new(move |m, _| {
                m.attachments = vec![MessageFile::attachment(
                    format!("a.txt{evil}"),
                    "text/plain",
                    b"x".to_vec(),
                )]
            }),
        ),
        (
            "attachment content type",
            Box::new(move |m, _| {
                m.attachments = vec![MessageFile::attachment(
                    "a.txt",
                    format!("text/plain{evil}"),
                    b"x".to_vec(),
                )]
            }),
        ),
    ];
    for (name, change) in cases {
        let result = send(&smtp_server, &imap, |m, a| change(m, a));
        assert!(result.is_err(), "{name}: header injection was accepted");
    }
    assert!(
        smtp_server.messages().is_empty(),
        "a message with an injected header was delivered"
    );
    assert!(smtp_server
        .commands()
        .iter()
        .all(|line| !line.contains("attacker@example.net")));
    // Positive control: the same setup delivers a clean message.
    send(&smtp_server, &imap, |_, _| {}).expect("a clean message is sent");
    assert_eq!(smtp_server.messages().len(), 1);
}

#[test]
fn smtp_password_never_appears_in_errors() {
    let smtp_server = FakeSmtpServer::builder()
        .credentials(USER, "a-different-password")
        .start();
    let imap = imap_server();
    let error = send(&smtp_server, &imap, |_, _| {}).unwrap_err();
    let text = format!("{error} {error:?}");
    assert!(!text.contains(PASSWORD), "{text}");
}
