//! Port of `tests/test_smtp.py` (`SmtpMessageTests`) against the fake SMTP
//! and IMAP servers instead of mocking `_connect` / `save_sent_copy`.
//!
//! Python inspected the `EmailMessage` passed to the mocked
//! `smtp.send_message`; here the bytes the fake SMTP server received are
//! parsed with `mail-parser`, and the Sent copy is the message the fake IMAP
//! server stored. Where Python patched internals (`email.utils.getaddresses`
//! without `strict`), the observable behavior is tested instead.

use mail_core::error::MailError;
use mail_core::schemas::recipient_address;
use mail_core::send_uploads::MessageFile;
use mail_core::sessions::MailAccount;
use mail_core::smtp::{self, OutgoingMessage, SendOptions};
use mail_parser::{MessageParser, MessagePart, MimeHeaders, PartType};
use mail_proto::testkit::{
    test_connector, Failure, FakeImapBuilder, FakeImapServer, FakeSmtpBuilder, FakeSmtpServer,
    TlsMode,
};
use serde_json::{Map, Value};

const USER: &str = "user@example.com";
const PASSWORD: &str = "s3cret-smtp-pass";

fn png_chunk(kind: &[u8], data: &[u8]) -> Vec<u8> {
    let mut chunk = (data.len() as u32).to_be_bytes().to_vec();
    chunk.extend_from_slice(kind);
    chunk.extend_from_slice(data);
    let mut hasher = crc32fast::Hasher::new();
    hasher.update(kind);
    hasher.update(data);
    chunk.extend_from_slice(&hasher.finalize().to_be_bytes());
    chunk
}

/// The 1x1 PNG of `tests/test_remote_images.py`.
fn png() -> Vec<u8> {
    let mut data = b"\x89PNG\r\n\x1a\n".to_vec();
    data.extend(png_chunk(b"IHDR", &[0, 0, 0, 1, 0, 0, 0, 1, 8, 6, 0, 0, 0]));
    data.extend(png_chunk(
        b"IDAT",
        b"x\x9cc\xf8\xcf\xc0\xf0\x1f\x00\x05\x00\x01\xff",
    ));
    data.extend(png_chunk(b"IEND", b""));
    data
}

struct Servers {
    smtp: FakeSmtpServer,
    imap: FakeImapServer,
}

impl Servers {
    fn start() -> Self {
        Self::with(
            FakeSmtpServer::builder(),
            FakeImapServer::builder().folder("Sent", &["\\Sent"]),
        )
    }

    fn with(smtp: FakeSmtpBuilder, imap: FakeImapBuilder) -> Self {
        Self {
            smtp: smtp.credentials(USER, PASSWORD).start(),
            imap: imap.credentials(USER, PASSWORD).start(),
        }
    }

    fn account(&self) -> MailAccount {
        MailAccount::new(
            USER,
            PASSWORD,
            "127.0.0.1",
            self.imap.port(),
            "none",
            "127.0.0.1",
            self.smtp.port(),
            "none",
        )
    }

    /// `make_account()` + `send(**changes)` with the Python test defaults.
    fn send(
        &self,
        change: impl FnOnce(&mut OutgoingMessage),
    ) -> mail_core::Result<Map<String, Value>> {
        self.send_as(&self.account(), change)
    }

    fn send_as(
        &self,
        account: &MailAccount,
        change: impl FnOnce(&mut OutgoingMessage),
    ) -> mail_core::Result<Map<String, Value>> {
        let mut message = OutgoingMessage {
            to: vec!["Recipient <to@example.com>".into()],
            subject: "Reply".into(),
            text: "Plain reply".into(),
            ..Default::default()
        };
        change(&mut message);
        smtp::send_message(account, &message)
    }

    /// Raw bytes of the last message the SMTP server accepted.
    fn wire(&self) -> Vec<u8> {
        self.smtp
            .messages()
            .last()
            .expect("a delivered message")
            .data
            .clone()
    }

    /// Raw bytes of the Sent copy stored in `folder`.
    fn saved(&self, folder: &str) -> Vec<u8> {
        self.imap
            .folder(folder)
            .and_then(|folder| folder.messages.last().cloned())
            .expect("a saved copy")
            .raw
    }
}

fn parse(raw: &[u8]) -> mail_parser::Message<'_> {
    MessageParser::default()
        .parse(raw)
        .expect("parsable message")
}

fn content_type(part: &MessagePart<'_>) -> String {
    let ct = part.content_type().expect("content type");
    format!("{}/{}", ct.ctype(), ct.subtype().unwrap_or_default()).to_ascii_lowercase()
}

fn children<'a>(
    message: &'a mail_parser::Message<'a>,
    part: &MessagePart<'_>,
) -> Vec<&'a MessagePart<'a>> {
    match &part.body {
        PartType::Multipart(ids) => ids
            .iter()
            .map(|id| message.part(*id).expect("child"))
            .collect(),
        _ => Vec::new(),
    }
}

fn header<'a>(message: &'a mail_parser::Message<'a>, name: &'a str) -> Option<&'a str> {
    message.header_raw(name).map(str::trim)
}

fn disposition(part: &MessagePart<'_>) -> String {
    part.content_disposition()
        .map(|d| d.ctype().to_ascii_lowercase())
        .unwrap_or_default()
}

fn send_error(result: mail_core::Result<Map<String, Value>>) -> String {
    match result {
        Err(MailError::Send(message)) => message,
        other => panic!("expected MailSendError, got {other:?}"),
    }
}

#[test]
fn rich_reply_mime_keeps_alternatives_related_images_and_attachments() {
    let servers = Servers::start();
    let binary = b"%PDF-1.7\x00\xff\r\noriginal file bytes".to_vec();
    let result = servers
        .send(|m| {
            m.cc = vec!["cc@example.com".into()];
            m.bcc = vec!["hidden@example.com".into()];
            m.html = r#"<p>Rich <strong>reply</strong><img src="cid:photo@draft"></p>"#.into();
            m.in_reply_to = "<original@example.com>".into();
            m.references = "<ancestor@example.com> <original@example.com>".into();
            m.attachments = vec![
                MessageFile::inline("photo.png", "image/png", png(), "photo@draft"),
                MessageFile::attachment("documents/report.pdf", "application/pdf", binary.clone()),
            ];
        })
        .unwrap();

    let wire = servers.wire();
    let message = parse(&wire);
    let root = message.root_part();
    assert_eq!(content_type(root), "multipart/mixed");
    let top = children(&message, root);
    assert_eq!(top.len(), 2);
    let (alternative, document) = (top[0], top[1]);
    assert_eq!(content_type(alternative), "multipart/alternative");
    let alternatives = children(&message, alternative);
    assert_eq!(alternatives.len(), 2);
    let (text, related) = (alternatives[0], alternatives[1]);
    assert_eq!(text.text_contents().unwrap().trim(), "Plain reply");
    assert_eq!(content_type(related), "multipart/related");
    let related_parts = children(&message, related);
    assert_eq!(related_parts.len(), 2);
    let (html, image) = (related_parts[0], related_parts[1]);
    assert!(html
        .text_contents()
        .unwrap()
        .contains(r#"<img src="cid:photo@draft">"#));
    assert_eq!(image.content_id(), Some("photo@draft"));
    assert!(String::from_utf8_lossy(&wire).contains("Content-ID: <photo@draft>\r\n"));
    assert_eq!(disposition(image), "inline");
    assert_eq!(image.contents(), png().as_slice());
    assert_eq!(disposition(document), "attachment");
    assert_eq!(document.attachment_name(), Some("report.pdf"));
    assert_eq!(document.contents(), binary.as_slice());
    assert_eq!(
        header(&message, "In-Reply-To"),
        Some("<original@example.com>")
    );
    assert_eq!(
        header(&message, "References"),
        Some("<ancestor@example.com> <original@example.com>")
    );
    assert_eq!(
        header(&message, "Message-ID"),
        result["message_id"].as_str()
    );
    assert_eq!(header(&message, "Bcc"), None);

    let delivered = servers.smtp.messages();
    assert_eq!(delivered.len(), 1);
    assert_eq!(delivered[0].mail_from, "user@example.com");
    assert_eq!(
        delivered[0].rcpt_to,
        ["to@example.com", "cc@example.com", "hidden@example.com"]
    );
    assert_eq!(delivered[0].authenticated_user.as_deref(), Some(USER));

    let saved_raw = servers.saved("Sent");
    let saved = parse(&saved_raw);
    assert_eq!(header(&saved, "Bcc"), Some("hidden@example.com"));
    for name in [
        "From",
        "To",
        "Cc",
        "Subject",
        "Date",
        "Message-ID",
        "In-Reply-To",
        "References",
    ] {
        assert_eq!(header(&saved, name), header(&message, name), "{name}");
    }
    assert_eq!(content_type(saved.root_part()), content_type(root));
    let saved_parts = &saved.parts;
    let saved_document = saved_parts
        .iter()
        .find(|part| part.attachment_name() == Some("report.pdf"))
        .unwrap();
    assert_eq!(saved_document.contents(), binary.as_slice());
    let saved_image = saved_parts
        .iter()
        .find(|part| part.content_id() == Some("photo@draft"))
        .unwrap();
    assert_eq!(saved_image.contents(), png().as_slice());
    assert_eq!(result["sent_saved"], Value::Bool(true));
    assert_eq!(result["sent_folder"], "Sent");
    assert!(!result.contains_key("warning"));
    assert_eq!(result["from"], "user@example.com");
    // smtp.quit() was called exactly once.
    assert_eq!(
        servers
            .smtp
            .command_names()
            .iter()
            .filter(|name| *name == "QUIT")
            .count(),
        1
    );
}

#[test]
fn mime_structure_and_header_order_match_email_message() {
    let servers = Servers::start();
    servers
        .send(|m| {
            m.html = r#"<p>Hi<img src="cid:photo@draft"></p>"#.into();
            m.attachments = vec![
                MessageFile::inline("photo.png", "image/png", png(), "photo@draft"),
                MessageFile::attachment("a.txt", "text/plain", b"data".to_vec()),
            ];
        })
        .unwrap();
    let wire = String::from_utf8(servers.wire()).unwrap();
    let names: Vec<&str> = wire
        .split("\r\n\r\n")
        .next()
        .unwrap()
        .split("\r\n")
        .filter(|line| !line.starts_with(' '))
        .map(|line| line.split(':').next().unwrap())
        .collect();
    assert_eq!(
        names,
        [
            "From",
            "To",
            "Subject",
            "Date",
            "Message-ID",
            "MIME-Version",
            "Content-Type"
        ]
    );
    // The first alternative keeps only the moved Content-* headers; the
    // html part (an EmailMessage) carries MIME-Version, then multipart/related.
    assert!(wire.contains(
        "Content-Type: text/plain; charset=\"utf-8\"\r\nContent-Transfer-Encoding: 7bit\r\n\r\nPlain reply\r\n"
    ));
    assert!(wire.contains(
        "MIME-Version: 1.0\r\nContent-Type: multipart/related;\r\n boundary=\"==============="
    ));
    assert!(wire.contains(
        "Content-Type: text/html; charset=\"utf-8\"\r\nContent-Transfer-Encoding: 7bit\r\n\r\n<p>Hi<img src=\"cid:photo@draft\"></p>\r\n"
    ));
    assert!(wire.contains(
        "Content-Type: image/png\r\nContent-Transfer-Encoding: base64\r\nContent-Disposition: inline; filename=\"photo.png\"\r\nContent-ID: <photo@draft>\r\nMIME-Version: 1.0\r\n\r\n"
    ));
    assert!(wire.contains(
        "Content-Type: text/plain\r\nContent-Transfer-Encoding: base64\r\nContent-Disposition: attachment; filename=\"a.txt\"\r\nMIME-Version: 1.0\r\n\r\nZGF0YQ==\r\n"
    ));
    assert!(wire.ends_with("==--\r\n"));
    // MAIL FROM carries smtplib's size= option.
    let mail = servers
        .smtp
        .commands()
        .into_iter()
        .find(|line| line.starts_with("mail "))
        .unwrap();
    assert_eq!(
        mail,
        format!("mail from:<user@example.com> size={}", wire.len())
    );
}

#[test]
fn legacy_plain_message_and_bcc_only_envelope_work() {
    let servers = Servers::start();
    servers
        .send(|m| {
            m.to = Vec::new();
            m.bcc = vec!["hidden@example.com".into()];
        })
        .unwrap();
    let wire = servers.wire();
    let message = parse(&wire);
    assert_eq!(content_type(message.root_part()), "text/plain");
    assert_eq!(header(&message, "To"), None);
    assert_eq!(header(&message, "Bcc"), None);
    assert_eq!(servers.smtp.messages()[0].rcpt_to, ["hidden@example.com"]);
    let saved_raw = servers.saved("Sent");
    let saved = parse(&saved_raw);
    assert_eq!(header(&saved, "Bcc"), Some("hidden@example.com"));
    assert_eq!(saved.body_text(0).unwrap().trim(), "Plain reply");
}

#[test]
fn sent_copy_uses_rfc_line_endings_and_discovered_folder() {
    let servers = Servers::with(
        FakeSmtpServer::builder(),
        FakeImapServer::builder()
            .delimiter(Some("."))
            .folder("INBOX.Sent Items", &["\\Sent"]),
    );
    let result = servers
        .send(|m| {
            m.subject = "Unicode subject caf\u{e9}".into();
            m.text = "Line one\nLine two".into();
        })
        .unwrap();
    let raw = servers.saved("INBOX.Sent Items");
    let without_crlf: Vec<u8> = String::from_utf8_lossy(&raw)
        .replace("\r\n", "")
        .into_bytes();
    assert!(!without_crlf.contains(&b'\n'));
    let saved = parse(&raw);
    assert_eq!(saved.subject(), Some("Unicode subject caf\u{e9}"));
    // The default policy encodes the non-ASCII word only.
    assert!(String::from_utf8_lossy(&raw)
        .contains("Subject: Unicode subject =?utf-8?q?caf=C3=A9?=\r\n"));
    assert!(String::from_utf8_lossy(&raw).contains("Line one\r\nLine two\r\n"));
    assert_eq!(result["sent_folder"], "INBOX.Sent Items");
    assert_eq!(result["sent_saved"], Value::Bool(true));
}

#[test]
fn international_recipient_domains_remain_valid_utf8_addresses_in_sent_copy() {
    for header_name in ["To", "Cc", "Bcc"] {
        let servers = Servers::start();
        let address = "recipient@b\u{fc}cher.example";
        let result = servers
            .send(|m| {
                let list = vec![address.to_string()];
                match header_name {
                    "To" => m.to = list,
                    "Cc" => m.cc = list,
                    _ => m.bcc = list,
                }
            })
            .unwrap();
        let raw = servers.saved("Sent");
        let text = String::from_utf8(raw.clone()).unwrap();
        assert!(
            text.contains(&format!("{header_name}: {address}\r\n")),
            "{text}"
        );
        let saved = parse(&raw);
        let parsed = saved
            .header(header_name)
            .and_then(|value| value.as_address())
            .and_then(|addresses| addresses.first())
            .and_then(|addr| addr.address())
            .map(str::to_string);
        assert_eq!(parsed.as_deref(), Some(address), "{header_name}");
        assert_eq!(result["sent_saved"], Value::Bool(true));
        let delivered = &servers.smtp.messages()[0];
        assert!(delivered.rcpt_to.iter().any(|rcpt| rcpt == address));
        assert!(delivered.mail_parameters.iter().any(|p| p == "SMTPUTF8"));
        assert!(delivered
            .mail_parameters
            .iter()
            .any(|p| p == "BODY=8BITMIME"));
        assert_eq!(header(&parse(&servers.wire()), "Bcc"), None);
    }
}

#[test]
fn sent_copy_failure_keeps_delivery_success_and_warns_against_resending() {
    // SentCopyError("Sent Items"): the folder was found but APPEND failed.
    let failing_append = Servers::with(
        FakeSmtpServer::builder(),
        FakeImapServer::builder().folder("Sent Items", &["\\Sent"]),
    );
    failing_append
        .imap
        .fail_next("APPEND", Failure::No("private server response".into()));
    // SentCopyError(): the IMAP server cannot be reached at all.
    let unreachable = Servers::start();
    // OSError: the connection drops before the folder is known.
    let dropped = Servers::start();
    dropped.imap.fail_next("LIST", Failure::Disconnect);

    let unreachable_account = {
        let mut account = unreachable.account();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        account.incoming_port = listener.local_addr().unwrap().port();
        drop(listener);
        account
    };
    for (servers, account, folder) in [
        (
            &failing_append,
            failing_append.account(),
            Some("Sent Items"),
        ),
        (&unreachable, unreachable_account, None),
        (&dropped, dropped.account(), None),
    ] {
        let result = servers.send_as(&account, |_| {}).unwrap();
        assert_eq!(result["sent_saved"], Value::Bool(false));
        assert_eq!(result["sent_folder"].as_str(), folder);
        assert!(result["message_id"]
            .as_str()
            .is_some_and(|id| !id.is_empty()));
        assert_eq!(result["from"], "user@example.com");
        let warning = result["warning"].as_str().unwrap();
        assert!(warning.contains("Message sent"));
        assert!(warning.contains("Do not resend"));
        assert!(!warning.contains("private"));
        assert_eq!(servers.smtp.messages().len(), 1);
    }
}

#[test]
fn pop3_accounts_skip_the_sent_copy_and_report_it() {
    let servers = Servers::start();
    let mut account = servers.account();
    account.incoming_mail_protocol = "pop3".into();
    let result = servers.send_as(&account, |_| {}).unwrap();
    assert_eq!(servers.smtp.messages().len(), 1);
    assert_eq!(servers.imap.connection_count(), 0);
    assert_eq!(result["sent_saved"], Value::Bool(false));
    assert_eq!(result["sent_folder"], Value::Null);
    assert_eq!(result["warning"], smtp::SENT_COPY_WARNING);
}

#[test]
fn eml_and_multipart_uploads_remain_byte_exact_opaque_attachments() {
    let servers = Servers::start();
    let original_mail = b"From: support@example.com\r\nTo: user@example.com\r\n\
Subject: Original account request\r\nMIME-Version: 1.0\r\n\
Content-Type: text/plain; charset=utf-8\r\n\r\nOriginal message body.\r\n"
        .to_vec();
    let original_multipart = b"Content-Type: multipart/mixed; boundary=original\r\n\r\n\
--original\r\nContent-Type: text/plain\r\n\r\nOriginal content\r\n--original--\r\n"
        .to_vec();
    servers
        .send(|m| {
            m.attachments = vec![
                MessageFile::attachment("original.eml", "message/rfc822", original_mail.clone()),
                MessageFile::attachment(
                    "original.mime",
                    "multipart/mixed",
                    original_multipart.clone(),
                ),
            ];
        })
        .unwrap();
    let wire = servers.wire();
    let message = parse(&wire);
    let attachments: Vec<_> = message.attachments().collect();
    assert_eq!(attachments.len(), 2);
    for (attachment, (filename, original)) in attachments.iter().zip([
        ("original.eml", &original_mail),
        ("original.mime", &original_multipart),
    ]) {
        assert_eq!(content_type(attachment), "application/octet-stream");
        assert_eq!(attachment.attachment_name(), Some(filename));
        assert_eq!(disposition(attachment), "attachment");
        assert!(!attachment.is_multipart());
        assert_eq!(attachment.contents(), original.as_slice());
    }
    let restored = parse(attachments[0].contents());
    assert_eq!(restored.subject(), Some("Original account request"));
    assert_eq!(
        restored
            .from()
            .and_then(|a| a.first())
            .and_then(|a| a.address()),
        Some("support@example.com")
    );
    assert_eq!(restored.body_text(0).unwrap(), "Original message body.\r\n");
}

#[test]
fn recipient_header_injection_and_invalid_inline_files_fail_before_connecting() {
    let servers = Servers::start();
    type Change = Box<dyn Fn(&mut OutgoingMessage)>;
    let cases: Vec<Change> = vec![
        Box::new(|m| m.to = vec!["recipient@example.com\r\nBcc: attacker@example.com".into()]),
        Box::new(|m| m.to = vec!["invalid".into()]),
        Box::new(|m| m.to = vec!["one@example.com, two@example.com".into()]),
        Box::new(|m| m.subject = "Reply\nInjected: header".into()),
        // Python's "Invalid Unicode \ud800" cannot be a Rust string; JSON
        // bodies with lone surrogates are rejected by the route parser.
        Box::new(|m| m.references = "<id>\0".into()),
        Box::new(|m| m.html = r#"<img src="cid:missing">"#.into()),
        Box::new(|m| {
            m.attachments = vec![MessageFile::attachment(
                "unsafe\r\nfile.txt",
                "text/plain",
                b"data".to_vec(),
            )]
        }),
        Box::new(|m| {
            m.html = r#"<img src="cid:image">"#.into();
            m.attachments = vec![MessageFile::inline(
                "image.png",
                "image/png",
                b"<svg/>".to_vec(),
                "image",
            )];
        }),
    ];
    for change in cases {
        assert_eq!(send_error(servers.send(change)), smtp::INVALID_MESSAGE);
    }
    assert_eq!(
        send_error(servers.send(|m| m.to.clear())),
        smtp::NO_RECIPIENTS
    );
    assert_eq!(servers.smtp.connection_count(), 0);
    assert_eq!(servers.imap.connection_count(), 0);
}

#[test]
fn sender_controls_fail_before_connecting() {
    let servers = Servers::start();
    let mut account = servers.account();
    account.display_name = "Name\r\nBcc: hidden@example.com".into();
    assert_eq!(
        send_error(servers.send_as(&account, |m| {
            m.to = vec!["to@example.com".into()];
            m.subject = "Hi".into();
            m.text = "Body".into();
        })),
        smtp::INVALID_MESSAGE
    );
    assert_eq!(servers.smtp.connection_count(), 0);
    assert_eq!(servers.imap.connection_count(), 0);
}

#[test]
fn address_validation_rejects_ambiguous_addresses() {
    assert_eq!(
        recipient_address("Support <support@example.com>").unwrap(),
        "support@example.com"
    );
    for invalid in [
        "missing-domain",
        "a@@b",
        "one@example.com, two@example.com",
        "a@b..c",
        "a@-b.com",
        "a@b/c",
    ] {
        assert!(recipient_address(invalid).is_err(), "{invalid}");
    }
}

#[test]
fn smtp_failure_is_safe_and_closes_connection() {
    let servers = Servers::start();
    servers.smtp.fail_next(
        "DATA",
        Failure::Code(554, "private content and recipient".into()),
    );
    let error = send_error(servers.send(|_| {}));
    assert!(error.contains("could not send"));
    assert!(!error.contains("private"));
    assert!(servers
        .smtp
        .command_names()
        .iter()
        .any(|name| name == "QUIT"));
    assert_eq!(servers.imap.connection_count(), 0);
}

#[test]
fn partial_recipient_refusal_is_not_silent_success() {
    let servers = Servers::with(
        FakeSmtpServer::builder().reject_recipient("to@example.com"),
        FakeImapServer::builder().folder("Sent", &["\\Sent"]),
    );
    let error = send_error(servers.send(|m| m.cc = vec!["cc@example.com".into()]));
    assert!(error.contains("may already have received"));
    // The accepted recipient did receive it.
    assert_eq!(servers.smtp.messages()[0].rcpt_to, ["cc@example.com"]);
    assert!(servers
        .smtp
        .command_names()
        .iter()
        .any(|name| name == "QUIT"));
    assert_eq!(servers.imap.connection_count(), 0);

    // Every recipient refused: SMTPRecipientsRefused ("could not send").
    let servers = Servers::with(
        FakeSmtpServer::builder().reject_recipient("to@example.com"),
        FakeImapServer::builder(),
    );
    assert_eq!(send_error(servers.send(|_| {})), smtp::SEND_FAILED);
    assert!(servers.smtp.messages().is_empty());
    assert!(servers
        .smtp
        .command_names()
        .iter()
        .any(|name| name == "RSET"));
}

#[test]
fn connection_and_sign_in_failures_use_their_own_messages() {
    let servers = Servers::start();
    let mut account = servers.account();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    account.outgoing_port = listener.local_addr().unwrap().port();
    drop(listener);
    assert_eq!(
        send_error(servers.send_as(&account, |_| {})),
        smtp::CONNECT_FAILED
    );

    let mut wrong = servers.account();
    wrong.password = "wrong-password".into();
    let error = send_error(servers.send_as(&wrong, |_| {}));
    assert_eq!(error, smtp::SIGN_IN_FAILED);
    assert!(!error.contains("wrong-password"));
    assert!(servers
        .smtp
        .command_names()
        .iter()
        .any(|name| name == "QUIT"));
    assert!(servers.smtp.messages().is_empty());

    // No AUTH extension: "SMTP AUTH extension not supported by server."
    let no_auth = Servers::with(
        FakeSmtpServer::builder().extensions(&["SIZE 1000000", "8BITMIME"]),
        FakeImapServer::builder(),
    );
    assert_eq!(send_error(no_auth.send(|_| {})), smtp::SIGN_IN_FAILED);
    // Passwords never reach the command log.
    assert!(!servers
        .smtp
        .commands()
        .iter()
        .any(|line| line.contains(PASSWORD)));
}

#[test]
fn starttls_and_implicit_tls_are_supported() {
    for (mode, protocol) in [
        (TlsMode::StartTls, "STARTTLS"),
        (TlsMode::Implicit, "SSL/TLS"),
    ] {
        let servers = Servers::with(
            FakeSmtpServer::builder().tls(mode),
            FakeImapServer::builder().folder("Sent", &["\\Sent"]),
        );
        let mut account = servers.account();
        account.outgoing_protocol = protocol.into();
        let options = SendOptions {
            tls_connector: Some(test_connector()),
        };
        let message = OutgoingMessage {
            to: vec!["to@example.com".into()],
            subject: "TLS".into(),
            text: "Body".into(),
            ..Default::default()
        };
        let result = smtp::send_message_with(&account, &message, &options).unwrap();
        assert_eq!(result["sent_saved"], Value::Bool(true));
        let delivered = servers.smtp.messages();
        assert!(delivered[0].tls, "{protocol}");
        if mode == TlsMode::StartTls {
            let names = servers.smtp.command_names();
            assert_eq!(&names[..3], ["EHLO", "STARTTLS", "EHLO"]);
        }
    }
    // Without a trusted certificate the connection is refused.
    let servers = Servers::with(
        FakeSmtpServer::builder().tls(TlsMode::StartTls),
        FakeImapServer::builder(),
    );
    let mut account = servers.account();
    account.outgoing_protocol = "STARTTLS".into();
    assert_eq!(
        send_error(servers.send_as(&account, |_| {})),
        smtp::CONNECT_FAILED
    );
    assert!(servers.smtp.messages().is_empty());
}

#[test]
fn starttls_is_required_when_configured() {
    // A STARTTLS account never falls back to plaintext AUTH.
    let servers = Servers::start();
    let mut account = servers.account();
    account.outgoing_protocol = "STARTTLS".into();
    let options = SendOptions {
        tls_connector: Some(test_connector()),
    };
    let message = OutgoingMessage {
        to: vec!["to@example.com".into()],
        ..Default::default()
    };
    assert_eq!(
        send_error(smtp::send_message_with(&account, &message, &options)),
        smtp::CONNECT_FAILED
    );
    assert!(!servers
        .smtp
        .command_names()
        .iter()
        .any(|name| name == "AUTH"));
}

#[test]
fn display_names_duplicates_and_long_html_are_encoded_like_python() {
    let servers = Servers::start();
    let mut account = servers.account();
    account.display_name = "Ren\u{e9} Dupont".into();
    let long_html = format!("<p>{}</p>", "word ".repeat(40));
    let result = servers
        .send_as(&account, |m| {
            m.to = vec![
                "Jos\u{e9} P\u{e9}rez <to@example.com>".into(),
                "to@example.com".into(),
            ];
            m.cc = vec!["TO@example.com".into()];
            m.html = long_html.clone();
        })
        .unwrap();
    assert_eq!(
        result["from"],
        "=?utf-8?q?Ren=C3=A9_Dupont?= <user@example.com>"
    );
    let wire = servers.wire();
    let text = String::from_utf8(wire.clone()).unwrap();
    assert!(text.is_ascii() || text.contains("Plain reply"));
    for line in text.split("\r\n") {
        assert!(line.len() <= 78 || line.starts_with("Content-"), "{line}");
    }
    let message = parse(&wire);
    let from = message.from().and_then(|a| a.first()).unwrap();
    assert_eq!(from.name(), Some("Ren\u{e9} Dupont"));
    let to = message.to().and_then(|a| a.as_list()).unwrap();
    assert_eq!(to[0].name(), Some("Jos\u{e9} P\u{e9}rez"));
    assert_eq!(to[0].address(), Some("to@example.com"));
    assert!(text.contains("Content-Transfer-Encoding: quoted-printable"));
    assert_eq!(message.body_html(0).unwrap().trim_end(), long_html);
    // dict.fromkeys keeps the first spelling of exact duplicates only.
    assert_eq!(
        servers.smtp.messages()[0].rcpt_to,
        ["to@example.com", "TO@example.com"]
    );
}

#[test]
fn rendered_message_has_no_bcc_and_dot_lines_are_stuffed() {
    let servers = Servers::start();
    servers
        .send(|m| {
            m.text = "line\n.\n.hidden".into();
            m.bcc = vec!["hidden@example.com".into()];
        })
        .unwrap();
    let wire = String::from_utf8(servers.wire()).unwrap();
    assert!(wire.contains("line\r\n.\r\n.hidden\r\n"));
    let rendered = smtp::render_message(
        &servers.account(),
        &OutgoingMessage {
            to: vec!["to@example.com".into()],
            bcc: vec!["hidden@example.com".into()],
            ..Default::default()
        },
    )
    .unwrap();
    assert!(!String::from_utf8_lossy(&rendered).contains("hidden@example.com"));
}
