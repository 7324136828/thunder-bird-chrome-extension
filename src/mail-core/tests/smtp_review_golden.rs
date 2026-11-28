//! Byte-level MIME parity with CPython 3.14's `EmailMessage`.
//!
//! `smtp_review_golden/cases.json` holds `send_message` inputs and the exact
//! bytes `smtplib.send_message` transmitted for them (built from the
//! `smtp_client.send_message` construction code under Python 3.14.9), with
//! `Date`, `Message-ID` and boundaries normalized. `expected: null` marks
//! inputs Python's `SendIn`/`recipient_address` validation rejects. Cases
//! whose only difference is RFC 2047 encoded-word chunking (documented in
//! `smtp.rs`) are not included.

use base64::Engine;
use mail_core::send_uploads::MessageFile;
use mail_core::sessions::MailAccount;
use mail_core::smtp::{self, OutgoingMessage};
use serde_json::Value;

const CASES: &str = include_str!("smtp_review_golden/cases.json");

fn strings(value: &Value) -> Vec<String> {
    value
        .as_array()
        .unwrap()
        .iter()
        .map(|item| item.as_str().unwrap().to_string())
        .collect()
}

fn text(value: &Value, key: &str) -> String {
    value[key].as_str().unwrap().to_string()
}

/// Replace the `Date` / `Message-ID` values and number the boundaries in
/// order of appearance (`B0`, `B1`, ...), like the Python side.
fn normalize(raw: &[u8]) -> String {
    let mut lines: Vec<String> = Vec::new();
    for line in String::from_utf8(raw.to_vec()).unwrap().split("\r\n") {
        if line.starts_with("Date:") {
            lines.push("Date: X".into());
        } else if line.starts_with("Message-ID:") {
            lines.push("Message-ID: X".into());
        } else {
            lines.push(line.to_string());
        }
    }
    let mut text = lines.join("\r\n");
    let mut seen: Vec<String> = Vec::new();
    let mut search = 0;
    while let Some(offset) = text[search..].find("===============") {
        let start = search + offset;
        let candidate = text.get(start..start + 36);
        match candidate {
            Some(token)
                if token[15..34].bytes().all(|b| b.is_ascii_digit()) && token.ends_with("==") =>
            {
                if !seen.iter().any(|known| known == token) {
                    seen.push(token.to_string());
                }
                search = start + 36;
            }
            _ => search = start + 15,
        }
    }
    for (index, token) in seen.iter().enumerate() {
        text = text.replace(token.as_str(), &format!("B{index}"));
    }
    text
}

#[test]
fn rendered_messages_match_python_bytes() {
    let cases: Vec<Value> = serde_json::from_str(CASES).unwrap();
    assert!(cases.len() > 50);
    for case in cases {
        let name = text(&case, "name");
        let mut account = MailAccount::new(
            text(&case, "email"),
            "unused",
            "127.0.0.1",
            1,
            "none",
            "127.0.0.1",
            1,
            "none",
        );
        account.display_name = text(&case, "display_name");
        let attachments = case["attachments"]
            .as_array()
            .unwrap()
            .iter()
            .map(|item| MessageFile {
                filename: text(item, "filename"),
                content_type: text(item, "content_type"),
                data: base64::engine::general_purpose::STANDARD
                    .decode(item["data"].as_str().unwrap())
                    .unwrap(),
                content_id: text(item, "content_id"),
                disposition: text(item, "disposition"),
            })
            .collect();
        let message = OutgoingMessage {
            to: strings(&case["to"]),
            cc: strings(&case["cc"]),
            bcc: strings(&case["bcc"]),
            subject: text(&case, "subject"),
            text: text(&case, "text"),
            html: text(&case, "html"),
            in_reply_to: text(&case, "in_reply_to"),
            references: text(&case, "references"),
            attachments,
        };
        let rendered = smtp::render_message(&account, &message);
        match case["expected"].as_str() {
            None => assert!(rendered.is_err(), "{name}: Python rejected this message"),
            Some(expected) => {
                let rendered =
                    rendered.unwrap_or_else(|error| panic!("{name}: unexpected {error}"));
                assert_eq!(normalize(&rendered), expected, "{name}");
            }
        }
    }
}
