//! `smtplib.send_message` flattens ASCII-envelope messages with
//! `BytesGenerator(bytesmsg)` (no policy → `mangle_from_=True`), so body
//! lines starting with `From ` go out as `>From `; the SMTPUTF8 path and the
//! Sent copy (`as_bytes`, `mangle_from_=False`) keep them unchanged.

use mail_core::sessions::MailAccount;
use mail_core::smtp::{self, OutgoingMessage};
use mail_proto::testkit::{FakeImapServer, FakeSmtpServer};

const USER: &str = "user@example.com";
const PASSWORD: &str = "s3cret-mangle-pass";

fn send(to: &str) -> (String, String) {
    let smtp = FakeSmtpServer::builder()
        .credentials(USER, PASSWORD)
        .start();
    let imap = FakeImapServer::builder()
        .folder("Sent", &["\\Sent"])
        .credentials(USER, PASSWORD)
        .start();
    let account = MailAccount::new(
        USER,
        PASSWORD,
        "127.0.0.1",
        imap.port(),
        "none",
        "127.0.0.1",
        smtp.port(),
        "none",
    );
    let result = smtp::send_message(
        &account,
        &OutgoingMessage {
            to: vec![to.into()],
            subject: "Mangle".into(),
            text: "From me\n>From you\nnot From here".into(),
            html: "<p>x</p>\nFrom html".into(),
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(result["sent_saved"], true, "{result:?}");
    let wire = String::from_utf8(smtp.messages().last().unwrap().data.clone()).unwrap();
    let saved = imap
        .folder("Sent")
        .and_then(|folder| folder.messages.last().cloned())
        .unwrap()
        .raw;
    (wire, String::from_utf8(saved).unwrap())
}

#[test]
fn ascii_envelopes_mangle_from_lines_on_the_wire_only() {
    let (wire, saved) = send("to@example.com");
    assert!(
        wire.contains("\r\n>From me\r\n>From you\r\nnot From here\r\n"),
        "{wire}"
    );
    assert!(wire.contains("\r\n>From html\r\n"), "{wire}");
    assert!(
        saved.contains("\r\nFrom me\r\n>From you\r\nnot From here\r\n"),
        "{saved}"
    );
    assert!(saved.contains("\r\nFrom html\r\n"), "{saved}");
    let rendered = smtp::render_message(
        &MailAccount::new(USER, "", "127.0.0.1", 1, "none", "127.0.0.1", 1, "none"),
        &OutgoingMessage {
            to: vec!["to@example.com".into()],
            text: "From me".into(),
            ..Default::default()
        },
    )
    .unwrap();
    assert!(String::from_utf8(rendered)
        .unwrap()
        .ends_with("\r\n>From me\r\n"));
}

#[test]
fn smtputf8_envelopes_keep_from_lines() {
    let (wire, saved) = send("user@b\u{fc}cher.example");
    assert!(wire.contains("\r\nFrom me\r\n>From you\r\n"), "{wire}");
    assert!(saved.contains("\r\nFrom me\r\n>From you\r\n"), "{saved}");
}
