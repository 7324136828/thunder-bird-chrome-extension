//! SMTP sending against an unlocked [`MailAccount`] (port of
//! `app/mail/smtp_client.py`).
//!
//! The same cached credential that unlocked IMAP authenticates the outgoing
//! connection; it is never persisted, logged or returned to the client.
//!
//! # Implementation choice: hand-written client instead of `lettre`
//!
//! `lettre` cannot reproduce `smtplib`'s observable behavior that
//! `send_message` depends on:
//! * a partially refused envelope must still deliver to the accepted
//!   recipients and then report "Some recipients were rejected..." (lettre
//!   aborts the transaction on the first refused `RCPT`);
//! * connect, sign-in and delivery failures map to three different user
//!   messages (lettre's transport hides the phases);
//! * envelope addresses are whatever `recipient_address` accepted (quoted
//!   local parts, domain literals, IDN), which `lettre::Address` rejects;
//! * `smtplib`'s `size=`, `SMTPUTF8`/`BODY=8BITMIME` and `RSET` rules.
//!
//! The message itself is built by a port of `EmailMessage`
//! (`smtp_parts/mime.rs`) and the protocol by a port of `smtplib`
//! (`smtp_parts/client.rs`), both over `native-tls` like the rest of the
//! crate.
//!
//! # Deviations from Python
//! * `login` offers PLAIN and LOGIN only (smtplib tried CRAM-MD5 first when
//!   advertised and fell back to PLAIN/LOGIN after a rejection).
//! * The EHLO name is the local socket address literal (`[192.0.2.1]`)
//!   instead of `socket.getfqdn()`.
//! * Where Python crashed with an uncaught `UnicodeEncodeError` (HTTP 500) —
//!   a non-ASCII account address together with a display name
//!   (`formataddr`), or non-ASCII credentials — the port answers the
//!   corresponding `MailSendError` (validation / sign-in message).
//! * MIME structure, part headers, transfer encodings, bodies, boundaries
//!   format and RFC 2231 filename parameters are byte-identical to CPython
//!   3.14's `EmailMessage` output (differentially checked). Header folding
//!   differs only in how RFC 2047 encoded words are chunked; every header
//!   decodes to the same text:
//!   - over-long single tokens in `Message-ID`, `Content-ID`, `In-Reply-To`
//!     and `References` are never turned into encoded words (CPython 3.14
//!     agrees; older versions encoded the unstructured ones, breaking
//!     `cid:` references);
//!   - user-typed encoded words in `Subject` are passed through instead of
//!     being decoded and re-encoded;
//!   - Python re-encodes everything from the first non-ASCII word of a line
//!     through the last one as a single encoded word (`Re: =?utf-8?b?...?=
//!     with`), the port encodes each run of non-ASCII words separately
//!     (`Re: =?utf-8?q?caf=C3=A9?= au lait and =?utf-8?q?...?=`), so long
//!     non-ASCII subjects split into encoded words at different points;
//!   - a non-ASCII display name (`From`/`To`/`Cc`/`Bcc`) is one encoded
//!     phrase (`=?utf-8?q?Ren=C3=A9_Dupont?=`) where Python encodes word by
//!     word (`=?utf-8?q?Ren=C3=A9?= Dupont`);
//!   - an address item is never split between its display name and
//!     `<addr>`, so a single very long `From`/`To` item can exceed 78
//!     characters on one line (always far below the 998 limit).

use std::time::Duration;

use native_tls::TlsConnector;
use serde_json::{json, Map, Value};

use crate::error::{MailError, Result};
use crate::imap;
use crate::schemas::{header_safe, recipient_address, RequestModel, SendIn};
use crate::send_uploads::{validate_files, MessageFile};
use crate::sessions::MailAccount;

#[path = "smtp_parts/client.rs"]
mod client;
#[path = "smtp_parts/mime.rs"]
mod mime;

use client::SmtpClient;
use mime::{Header, HeaderValue, Part};

/// `timeout=30` of the SMTP connection.
pub const SMTP_TIMEOUT: Duration = Duration::from_secs(30);

pub const NO_RECIPIENTS: &str = "Add at least one recipient";
pub const INVALID_MESSAGE: &str = "Check the message recipients, headers, size, and attachments.";
pub const CONNECT_FAILED: &str = "Could not connect securely to the outgoing mail server.";
pub const SIGN_IN_FAILED: &str = "SMTP sign-in failed. Check the password or use an app password.";
pub const RECIPIENTS_REJECTED: &str =
    "Some recipients were rejected. Other recipients may already have received the message.";
pub const SEND_FAILED: &str = "The outgoing mail server could not send the message.";
/// Delivery succeeded but the Sent copy failed (or the account is POP3).
pub const SENT_COPY_WARNING: &str = "Message sent, but a copy could not be saved in Sent. \
Do not resend the message; check your Sent folder or mail server settings.";

/// Keyword arguments of `send_message` (Python defaults via `Default`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OutgoingMessage {
    pub to: Vec<String>,
    pub cc: Vec<String>,
    pub bcc: Vec<String>,
    pub subject: String,
    pub text: String,
    pub html: String,
    pub in_reply_to: String,
    pub references: String,
    pub attachments: Vec<MessageFile>,
}

/// Transport options. `Default` is production behavior (system trust
/// store with hostname verification, like `ssl.create_default_context()`).
#[derive(Clone, Default)]
pub struct SendOptions {
    /// TLS connector for `ssl`/`starttls` servers (tests pass one trusting
    /// the testkit certificate).
    pub tls_connector: Option<TlsConnector>,
}

fn send_error(message: &str) -> MailError {
    MailError::Send(message.to_string())
}

/// A validated message ready to deliver.
struct Prepared {
    root: Part,
    envelope_from: String,
    envelope_to: Vec<String>,
    message_id: String,
    from_header: String,
}

/// `make_msgid(domain=...)`: `<time*100.pid.random64@domain>`.
fn make_msgid(domain: &str) -> String {
    let timeval = (crate::sessions::now_epoch() * 100.0) as i64;
    let bytes = *uuid::Uuid::new_v4().as_bytes();
    let random = u64::from_le_bytes(bytes[..8].try_into().expect("8 bytes"));
    format!("<{timeval}.{}.{random}@{domain}>", std::process::id())
}

/// `formatdate(localtime=True)`.
fn format_date() -> String {
    chrono::Local::now()
        .format("%a, %d %b %Y %H:%M:%S %z")
        .to_string()
}

/// Validation and MIME construction (everything before `_connect`).
fn prepare(account: &MailAccount, message: &OutgoingMessage) -> Result<Prepared> {
    if message.to.is_empty() && message.cc.is_empty() && message.bcc.is_empty() {
        return Err(send_error(NO_RECIPIENTS));
    }
    let invalid = || send_error(INVALID_MESSAGE);
    let model = json!({
        "account": account.email,
        "to": message.to,
        "cc": message.cc,
        "bcc": message.bcc,
        "subject": message.subject,
        "text": message.text,
        "html": message.html,
        "in_reply_to": message.in_reply_to,
        "references": message.references,
    });
    SendIn::validate(&model).map_err(|_| invalid())?;
    let envelope_from = recipient_address(&account.email).map_err(|_| invalid())?;
    if !header_safe(&account.display_name) {
        return Err(invalid());
    }
    let uploads = validate_files(&message.html, &message.attachments).map_err(|_| invalid())?;
    let mut envelope_to: Vec<String> = Vec::new();
    for value in message.to.iter().chain(&message.cc).chain(&message.bcc) {
        let address = recipient_address(value).map_err(|_| invalid())?;
        if !envelope_to.contains(&address) {
            envelope_to.push(address);
        }
    }

    let from_header =
        mime::formataddr(&account.display_name, &account.email).map_err(|_| invalid())?;
    let domain = account.email.rsplit('@').next().unwrap_or_default();
    let message_id = make_msgid(domain);

    let mut root = Part::default();
    let headers = &mut root.headers;
    headers.push(Header::new(
        "From",
        HeaderValue::Addresses(vec![mime::from_item(
            &account.display_name,
            &account.email,
            &from_header,
        )]),
    ));
    if !message.to.is_empty() {
        headers.push(Header::new(
            "To",
            HeaderValue::Addresses(message.to.clone()),
        ));
    }
    if !message.cc.is_empty() {
        headers.push(Header::new(
            "Cc",
            HeaderValue::Addresses(message.cc.clone()),
        ));
    }
    headers.push(Header::new(
        "Subject",
        HeaderValue::Unstructured(message.subject.clone()),
    ));
    headers.push(Header::new("Date", HeaderValue::Raw(format_date())));
    headers.push(Header::new(
        "Message-ID",
        HeaderValue::Raw(message_id.clone()),
    ));
    if !message.in_reply_to.is_empty() {
        headers.push(Header::new(
            "In-Reply-To",
            HeaderValue::Raw(message.in_reply_to.clone()),
        ));
        let references = if message.references.is_empty() {
            &message.in_reply_to
        } else {
            &message.references
        };
        headers.push(Header::new(
            "References",
            HeaderValue::Raw(references.clone()),
        ));
    }

    // msg.set_content(text or "")
    let text_part = mime::text_part(&message.text, "plain");
    root.headers.extend(text_part.headers);
    root.body = text_part.body;

    if !message.html.is_empty() {
        root.add_multipart("alternative", mime::text_part(&message.html, "html"));
        let html_part = root.last_child_mut().expect("alternative html part");
        for upload in uploads
            .iter()
            .filter(|upload| upload.disposition == "inline")
        {
            let (maintype, subtype) = upload
                .content_type
                .split_once('/')
                .expect("validated content type");
            let cid = format!("<{}>", upload.content_id);
            html_part.add_multipart(
                "related",
                mime::bytes_part(
                    &upload.data,
                    maintype,
                    subtype,
                    "inline",
                    &upload.filename,
                    Some(&cid),
                ),
            );
        }
    }
    for upload in uploads
        .iter()
        .filter(|upload| upload.disposition == "attachment")
    {
        let (mut maintype, mut subtype) = upload
            .content_type
            .split_once('/')
            .expect("validated content type");
        // Uploaded .eml and multipart files are opaque downloads. Encoding
        // their bytes as message/rfc822 or multipart/* would make receiving
        // clients parse a MIME container instead of preserving the file.
        if maintype == "message" || maintype == "multipart" {
            (maintype, subtype) = ("application", "octet-stream");
        }
        root.add_multipart(
            "mixed",
            mime::bytes_part(
                &upload.data,
                maintype,
                subtype,
                "attachment",
                &upload.filename,
                None,
            ),
        );
    }

    Ok(Prepared {
        root,
        envelope_from,
        envelope_to,
        message_id,
        from_header,
    })
}

fn tls_connector(options: &SendOptions) -> std::result::Result<TlsConnector, client::ClientError> {
    match &options.tls_connector {
        Some(connector) => Ok(connector.clone()),
        None => {
            TlsConnector::new().map_err(|error| client::ClientError(format!("TLS setup: {error}")))
        }
    }
}

/// `_connect(account)`: connect (ssl / starttls / none) and sign in.
fn connect(account: &MailAccount, options: &SendOptions) -> Result<SmtpClient> {
    let host = account.outgoing_server.as_str();
    let port = account.outgoing_port;
    let security = account.smtp_security();
    let connected = (|| {
        if security == "ssl" {
            let connector = tls_connector(options)?;
            SmtpClient::connect(host, port, SMTP_TIMEOUT, Some(&connector))
        } else {
            let mut smtp = SmtpClient::connect(host, port, SMTP_TIMEOUT, None)?;
            smtp.ehlo()?;
            if security == "starttls" {
                let connector = tls_connector(options)?;
                smtp.starttls(&connector)?;
                smtp.ehlo()?;
            }
            Ok(smtp)
        }
    })();
    let mut smtp = connected.map_err(|_| send_error(CONNECT_FAILED))?;
    if smtp.login(&account.email, &account.password).is_err() {
        let _ = smtp.quit();
        return Err(send_error(SIGN_IN_FAILED));
    }
    Ok(smtp)
}

/// Python `send_message(account, to=..., cc=..., ...)`.
///
/// Returns the result dict: `{"message_id", "from", "sent_saved",
/// "sent_folder", "warning"?}`. Errors are `MailError::Send` with the
/// user-safe messages above (HTTP 502).
pub fn send_message(
    account: &MailAccount,
    message: &OutgoingMessage,
) -> Result<Map<String, Value>> {
    send_message_with(account, message, &SendOptions::default())
}

/// [`send_message`] with explicit transport options.
pub fn send_message_with(
    account: &MailAccount,
    message: &OutgoingMessage,
    options: &SendOptions,
) -> Result<Map<String, Value>> {
    let prepared = prepare(account, message)?;
    // smtplib's SMTPUTF8 serialization: an international envelope writes the
    // headers as raw UTF-8 instead of encoded words.
    let utf8 = !prepared.envelope_from.is_ascii()
        || prepared
            .envelope_to
            .iter()
            .any(|address| !address.is_ascii());
    // smtplib.send_message never transmits a Bcc header; its ASCII path
    // mangles body lines starting with "From " (see `Part::to_bytes_with`).
    let wire = prepared.root.to_bytes_with(utf8, !utf8);

    let mut smtp = connect(account, options)?;
    let delivered = smtp.send_message(&prepared.envelope_from, &prepared.envelope_to, &wire);
    let _ = smtp.quit();
    match delivered {
        Ok(refused) if !refused.is_empty() => return Err(send_error(RECIPIENTS_REJECTED)),
        Ok(_) => {}
        Err(_) => return Err(send_error(SEND_FAILED)),
    }

    let mut result = Map::new();
    result.insert(
        "message_id".into(),
        Value::from(prepared.message_id.clone()),
    );
    result.insert("from".into(), Value::from(prepared.from_header.clone()));
    // Keep blind recipients in the sender's private copy only.
    let saved = if account.is_pop3() {
        // POP3 has no server folders: report it like a failed Sent copy.
        Err(None)
    } else {
        let mut sent_message = prepared.root.clone();
        if !message.bcc.is_empty() {
            sent_message.headers.push(Header::new(
                "Bcc",
                HeaderValue::Addresses(message.bcc.clone()),
            ));
        }
        let raw = sent_message.to_bytes(utf8);
        imap::save_sent_copy(account, &raw, &prepared.message_id).map_err(|error| match error {
            MailError::SentCopy { folder, .. } => folder,
            _ => None,
        })
    };
    match saved {
        Ok(folder) => {
            result.insert("sent_saved".into(), Value::Bool(true));
            result.insert("sent_folder".into(), Value::from(folder));
        }
        Err(folder) => {
            // Delivery has succeeded. A mailbox/serialization failure must
            // never invite a resend or turn this into a failed response.
            result.insert("sent_saved".into(), Value::Bool(false));
            result.insert(
                "sent_folder".into(),
                folder.map_or(Value::Null, Value::from),
            );
            result.insert("warning".into(), Value::from(SENT_COPY_WARNING));
        }
    }
    Ok(result)
}

/// Build the message exactly as it would be transmitted (no `Bcc` header),
/// without connecting. For tests and diagnostics; the `Message-ID`, `Date`
/// and boundaries differ between calls.
pub fn render_message(account: &MailAccount, message: &OutgoingMessage) -> Result<Vec<u8>> {
    let prepared = prepare(account, message)?;
    let utf8 = !prepared.envelope_from.is_ascii()
        || prepared
            .envelope_to
            .iter()
            .any(|address| !address.is_ascii());
    Ok(prepared.root.to_bytes_with(utf8, !utf8))
}
