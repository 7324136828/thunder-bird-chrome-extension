//! Stage 1 - extract structured records from .eml / .mbox inputs
//! (port of `services/stages/eml_extract.py`).
//!
//! Scans the job's `inputs/` directory for `.eml` files (including ones
//! unpacked from uploaded `.zip` archives) and `.mbox` mailboxes, then writes
//! one JSON record per message to `work/messages.jsonl`.
//!
//! `.eml` files are parsed like `BytesParser(policy=policy.default)`, mbox
//! messages like `mailbox.mbox` (which uses the `compat32` policy), so header
//! decoding differs between the two exactly as it does in Python.

use std::cmp::Ordering;
use std::fs;
use std::io::Write;
use std::path::{Component, Path, PathBuf};
use std::sync::OnceLock;

use regex::Regex;
use serde::Deserialize;

use super::py_addr::{getaddresses, parse_date_iso, parseaddr};
use super::py_email::{split_mbox, Message, Policy};
use super::py_header::{
    decode_replace, has_surrogates, legacy_decode, lookup_codec, modern_unstructured, py_split,
    py_strip, replace_surrogates, sanitize, unfold,
};
use super::py_hvp::{address_header_str, message_id_header_str};
use super::pyjson::Json;
use super::{json_error, value_error, LogFn};
use crate::cancellation::{check_cancel, message_limit};
use crate::pipeline::PipelineError;

/// One line of `messages.jsonl` / `messages_grouped.jsonl`.
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(default)]
pub struct MessageRecord {
    pub source_file: String,
    pub mbox_index: Option<u64>,
    pub message_id: String,
    pub subject: String,
    pub from_name: String,
    pub from_addr: String,
    pub from_domain: String,
    pub to: String,
    pub date: Option<String>,
    pub list_unsubscribe: String,
    pub list_unsubscribe_post: bool,
    pub size_bytes: i64,
    pub has_attachments: bool,
    pub snippet: String,
    /// Added by the `rebrand` stage.
    pub sender_domain: Option<String>,
    /// Added by the `rebrand` stage.
    pub sender_group: Option<String>,
}

impl MessageRecord {
    /// The record as an ordered JSON object (Python dict insertion order).
    pub fn to_json(&self) -> Json {
        let mut pairs = vec![
            ("source_file", Json::str(&self.source_file)),
            (
                "mbox_index",
                self.mbox_index.map_or(Json::Null, |i| Json::Int(i as i64)),
            ),
            ("message_id", Json::str(&self.message_id)),
            ("subject", Json::str(&self.subject)),
            ("from_name", Json::str(&self.from_name)),
            ("from_addr", Json::str(&self.from_addr)),
            ("from_domain", Json::str(&self.from_domain)),
            ("to", Json::str(&self.to)),
            ("date", Json::opt_str(self.date.as_deref())),
            ("list_unsubscribe", Json::str(&self.list_unsubscribe)),
            (
                "list_unsubscribe_post",
                Json::Bool(self.list_unsubscribe_post),
            ),
            ("size_bytes", Json::Int(self.size_bytes)),
            ("has_attachments", Json::Bool(self.has_attachments)),
            ("snippet", Json::str(&self.snippet)),
        ];
        if let Some(domain) = &self.sender_domain {
            pairs.push(("sender_domain", Json::str(domain)));
        }
        if let Some(group) = &self.sender_group {
            pairs.push(("sender_group", Json::str(group)));
        }
        Json::object(pairs)
    }

    /// `json.loads(line)` for a JSONL record line.
    pub fn from_json_line(line: &str) -> Result<Self, PipelineError> {
        serde_json::from_str(line).map_err(json_error)
    }
}

/// Read every non-blank line of a JSONL file (`json.loads(line.strip())`).
pub(crate) fn read_records(path: &Path) -> Result<Vec<MessageRecord>, PipelineError> {
    let text = fs::read_to_string(path)?;
    let mut records = Vec::new();
    for line in text.split_inclusive('\n') {
        check_cancel()?;
        let line = py_strip(line);
        if !line.is_empty() {
            records.push(MessageRecord::from_json_line(line)?);
        }
    }
    Ok(records)
}

/// Python `sorted(root.rglob(pattern))`: matching files *and* directories,
/// ordered component-wise like `PurePosixPath` comparison.
pub(crate) fn rglob_sorted(root: &Path, matches: impl Fn(&str) -> bool) -> Vec<PathBuf> {
    fn walk(dir: &Path, matches: &dyn Fn(&str) -> bool, out: &mut Vec<PathBuf>) {
        let Ok(entries) = fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().into_owned();
            if matches(&name) {
                out.push(path.clone());
            }
            if entry.file_type().is_ok_and(|kind| kind.is_dir()) {
                walk(&path, matches, out);
            }
        }
    }
    let mut out = Vec::new();
    walk(root, &matches, &mut out);
    out.sort_by(|a, b| compare_paths(a, b));
    out
}

fn compare_paths(a: &Path, b: &Path) -> Ordering {
    let parts = |p: &Path| -> Vec<String> {
        p.components()
            .filter_map(|c| match c {
                Component::Normal(part) => Some(part.to_string_lossy().into_owned()),
                _ => None,
            })
            .collect()
    };
    parts(a).cmp(&parts(b))
}

/// `Path.name` as text.
pub(crate) fn file_name(path: &Path) -> String {
    path.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default()
}

fn unsub_url() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?s)<([^>]+)>").expect("valid regex"))
}

/// `eml_extract._unsubscribe_link`.
fn unsubscribe_link(raw: &str) -> String {
    if raw.is_empty() {
        return String::new();
    }
    match unsub_url().captures(raw) {
        Some(caps) => caps[1].to_owned(),
        None => py_strip(raw).to_owned(),
    }
}

/// `eml_extract._first_address`.
fn first_address(value: &str) -> String {
    if value.is_empty() {
        return String::new();
    }
    getaddresses(value)
        .into_iter()
        .next()
        .map(|(_, addr)| addr)
        .unwrap_or_default()
}

/// `parseaddr(str(msg["From"]))` under `policy.default`: the modern header
/// re-renders the address list from its parse tree (see [`address_header_str`])
/// before the legacy `parseaddr` sees it.
fn modern_from(value: &str) -> (String, String) {
    parseaddr(&address_header_str(value))
}

/// The header fields of one record, decoded per policy.
struct Headers {
    from_name: String,
    from_addr: String,
    subject: String,
    message_id: String,
    to: String,
    date: Option<String>,
    list_unsubscribe: String,
    list_unsubscribe_post: bool,
}

fn modern_headers(msg: &Message) -> Headers {
    let get = |name: &str| msg.raw_header(0, name);
    let plain = |name: &str| get(name).map(|raw| sanitize(&unfold(raw)));
    let (from_name, from_addr) = modern_from(&get("From").map(unfold).unwrap_or_default());
    Headers {
        from_name: legacy_decode(&from_name),
        from_addr,
        subject: get("Subject")
            .map(|raw| legacy_decode(&modern_unstructured(raw)))
            .unwrap_or_default(),
        message_id: get("Message-ID")
            .map(|raw| py_strip(&message_id_header_str(&unfold(raw))).to_owned())
            .unwrap_or_default(),
        to: first_address(
            &get("To")
                .map(|raw| address_header_str(&unfold(raw)))
                .unwrap_or_default(),
        ),
        date: plain("Date").and_then(|value| parse_date_iso(&value)),
        list_unsubscribe: unsubscribe_link(
            &get("List-Unsubscribe")
                .map(modern_unstructured)
                .unwrap_or_default(),
        ),
        list_unsubscribe_post: get("List-Unsubscribe-Post")
            .is_some_and(|raw| !modern_unstructured(raw).is_empty()),
    }
}

/// compat32: raw values keep their folding; values with raw 8-bit bytes are
/// `Header(..., charset=UNKNOWN8BIT)` objects whose text replaces each byte
/// with U+FFFD and which `parseaddr` / `_parse_date` reject.
fn compat32_headers(msg: &Message) -> Headers {
    let get = |name: &str| msg.raw_header(0, name);
    let text = |name: &str| get(name).map(replace_surrogates);
    let from_raw = get("From").unwrap_or("");
    let (from_name, from_addr) = if has_surrogates(from_raw) {
        (String::new(), String::new())
    } else {
        parseaddr(from_raw)
    };
    Headers {
        from_name: legacy_decode(&from_name),
        from_addr,
        subject: get("Subject")
            .map(|raw| {
                if has_surrogates(raw) {
                    replace_surrogates(raw)
                } else {
                    legacy_decode(raw)
                }
            })
            .unwrap_or_default(),
        message_id: py_strip(&text("Message-ID").unwrap_or_default()).to_owned(),
        to: first_address(&text("To").unwrap_or_default()),
        date: get("Date")
            .filter(|raw| !has_surrogates(raw))
            .and_then(parse_date_iso),
        list_unsubscribe: unsubscribe_link(&text("List-Unsubscribe").unwrap_or_default()),
        list_unsubscribe_post: get("List-Unsubscribe-Post")
            .is_some_and(|raw| has_surrogates(raw) || !raw.is_empty()),
    }
}

/// `eml_extract._snippet` (any exception, including cancellation, yields "").
fn snippet(msg: &Message, limit: usize) -> String {
    for part in msg.walk() {
        if check_cancel().is_err() {
            return String::new();
        }
        if msg.maintype(part) == "multipart" || msg.content_type(part) != "text/plain" {
            continue;
        }
        if msg.header_raises(part, "content-disposition") {
            return String::new();
        }
        if msg.content_disposition(part).as_deref() == Some("attachment") {
            continue;
        }
        let payload = match msg.decoded_payload(part) {
            Err(()) => return String::new(),
            Ok(Some(bytes)) => bytes,
            Ok(None) => msg
                .raw_payload_text(part)
                .chars()
                .map(|c| {
                    if has_surrogates(&c.to_string()) {
                        '?'
                    } else {
                        c
                    }
                })
                .collect::<String>()
                .into_bytes(),
        };
        let charset = msg
            .content_charset(part)
            .filter(|cs| !cs.is_empty())
            .unwrap_or_else(|| "utf-8".to_owned());
        if payload.is_empty() {
            // `b"".decode(charset)` returns "" without looking the codec up,
            // so an unknown charset on an empty part does not end the search.
            continue;
        }
        let Some(codec) = lookup_codec(&charset) else {
            return String::new();
        };
        let text = py_split(&decode_replace(&payload, codec)).join(" ");
        if !text.is_empty() {
            return text.chars().take(limit).collect();
        }
    }
    String::new()
}

/// `eml_extract._has_attachments` (any exception yields `False`).
fn has_attachments(msg: &Message) -> bool {
    for part in msg.walk() {
        if check_cancel().is_err() {
            return false;
        }
        if msg.header_raises(part, "content-disposition") {
            return false;
        }
        if msg.content_disposition(part).as_deref() == Some("attachment")
            || msg.filename(part).is_some_and(|name| !name.is_empty())
        {
            return true;
        }
    }
    false
}

/// `eml_extract._record`.
fn record(msg: &Message, source_file: &str, size: i64, mbox_index: Option<u64>) -> MessageRecord {
    let headers = match msg.policy() {
        Policy::Default => modern_headers(msg),
        Policy::Compat32 => compat32_headers(msg),
    };
    let from_addr = headers.from_addr.to_lowercase();
    let from_domain = match from_addr.rsplit_once('@') {
        Some((_, domain)) => domain.to_owned(),
        None => String::new(),
    };
    MessageRecord {
        source_file: source_file.to_owned(),
        mbox_index,
        message_id: headers.message_id,
        subject: headers.subject,
        from_name: headers.from_name,
        from_addr,
        from_domain,
        to: headers.to,
        date: headers.date,
        list_unsubscribe: headers.list_unsubscribe,
        list_unsubscribe_post: headers.list_unsubscribe_post,
        size_bytes: size,
        has_attachments: has_attachments(msg),
        snippet: snippet(msg, 300),
        sender_domain: None,
        sender_group: None,
    }
}

/// Parse a single `.eml` byte string into a record (helper for tests and callers).
pub fn record_from_eml(data: &[u8], source_file: &str, size: i64) -> MessageRecord {
    record(
        &Message::parse(data, Policy::Default),
        source_file,
        size,
        None,
    )
}

fn check_limit(records: &[MessageRecord]) -> Result<(), PipelineError> {
    if records.len() > message_limit() {
        return Err(value_error(
            "The audit exceeds the maximum allowed message count",
        ));
    }
    Ok(())
}

/// Parse every message under `inputs_dir` into a JSONL file. Returns the count.
pub fn run(
    inputs_dir: &Path,
    out_path: &Path,
    log: &mut LogFn<'_>,
) -> Result<usize, PipelineError> {
    let mut records: Vec<MessageRecord> = Vec::new();

    for eml in rglob_sorted(inputs_dir, |name| name.ends_with(".eml")) {
        check_cancel()?;
        let data = match fs::read(&eml) {
            Ok(data) => data,
            Err(_) => {
                log(format!("Skipping unparseable file: {}", file_name(&eml)))?;
                continue;
            }
        };
        let msg = Message::parse(&data, Policy::Default);
        if msg.parse_raised() {
            log(format!("Skipping unparseable file: {}", file_name(&eml)))?;
            continue;
        }
        let size = fs::metadata(&eml).map(|m| m.len() as i64).unwrap_or(0);
        records.push(record(&msg, &file_name(&eml), size, None));
        check_limit(&records)?;
    }

    for mbox_path in rglob_sorted(inputs_dir, |name| name.ends_with(".mbox")) {
        check_cancel()?;
        let data = match fs::read(&mbox_path) {
            Ok(data) => data,
            Err(error) => {
                log(format!(
                    "Skipping unreadable mailbox {}: {}",
                    file_name(&mbox_path),
                    error
                ))?;
                continue;
            }
        };
        let name = file_name(&mbox_path);
        for (index, raw) in split_mbox(&data).into_iter().enumerate() {
            check_cancel()?;
            let msg = Message::parse(raw, Policy::Compat32);
            let size = msg.as_bytes_len().unwrap_or(0) as i64;
            records.push(record(&msg, &name, size, Some(index as u64)));
            check_limit(&records)?;
        }
    }

    if let Some(parent) = out_path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut output = std::io::BufWriter::new(fs::File::create(out_path)?);
    for rec in &records {
        check_cancel()?;
        output.write_all(rec.to_json().dumps().as_bytes())?;
        output.write_all(b"\n")?;
    }
    output.flush()?;
    Ok(records.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_parts_with_unknown_charsets_are_skipped() {
        // CPython: the first part decodes b"" (no codec lookup), the second
        // one supplies the snippet.
        let raw = b"From: a@b.example\nContent-Type: multipart/alternative; boundary=zz\n\n--zz\nContent-Type: text/plain; charset=unknown-charset-x decode this\n--zz\nContent-Type: text/plain\n\nsecond part never closes\n";
        let rec = record_from_eml(raw, "m.eml", raw.len() as i64);
        assert_eq!(rec.snippet, "second part never closes");
    }

    #[test]
    fn sample_message_record() {
        let raw = b"From: Newsletter Bot <news@mail.example.com>\nTo: user@test.local\nSubject: Weekly digest 3\nDate: Mon, 05 Aug 2024 10:03:00 +0000\nMessage-ID: <msg3@mail.example.com>\nList-Unsubscribe: <https://mail.example.com/unsub?token=3>\nMIME-Version: 1.0\nContent-Type: text/plain; charset=\"utf-8\"\n\nHello, here is your weekly digest number 3.\n";
        let rec = record_from_eml(raw, "news_3.eml", raw.len() as i64);
        assert_eq!(rec.from_name, "Newsletter Bot");
        assert_eq!(rec.from_addr, "news@mail.example.com");
        assert_eq!(rec.from_domain, "mail.example.com");
        assert_eq!(rec.date.as_deref(), Some("2024-08-05T10:03:00+00:00"));
        assert_eq!(
            rec.list_unsubscribe,
            "https://mail.example.com/unsub?token=3"
        );
        assert_eq!(rec.snippet, "Hello, here is your weekly digest number 3.");
        assert!(!rec.has_attachments);
    }

    #[test]
    fn modern_from_drops_comments_and_decodes_phrases() {
        assert_eq!(
            modern_from("user@example.com (Real Name)"),
            (String::new(), "user@example.com".into())
        );
        assert_eq!(
            modern_from("Bob (work) <bob@x.com>"),
            ("Bob".into(), "bob@x.com".into())
        );
        assert_eq!(
            modern_from("=?utf-8?q?Caf=C3=A9_Shop?= <o@x.com>"),
            ("Café Shop".into(), "o@x.com".into())
        );
        assert_eq!(
            modern_from("=?utf-8?b?w4FsdmFybw==?= =?utf-8?b?IEfDs21leg==?= <ag@x.com>"),
            ("Álvaro Gómez".into(), "ag@x.com".into())
        );
    }

    #[test]
    fn unsubscribe_link_prefers_angle_brackets() {
        assert_eq!(unsubscribe_link("<mailto:a@b>, <https://x>"), "mailto:a@b");
        assert_eq!(unsubscribe_link("  https://plain  "), "https://plain");
        assert_eq!(unsubscribe_link(""), "");
    }

    #[test]
    fn record_json_key_order_matches_python() {
        let rec = MessageRecord {
            sender_group: Some("g".into()),
            sender_domain: Some("d".into()),
            ..Default::default()
        };
        let line = rec.to_json().dumps();
        assert!(
            line.starts_with("{\"source_file\": \"\", \"mbox_index\": null, \"message_id\": \"\"")
        );
        assert!(
            line.ends_with("\"snippet\": \"\", \"sender_domain\": \"d\", \"sender_group\": \"g\"}")
        );
        assert_eq!(MessageRecord::from_json_line(&line).unwrap(), rec);
    }
}
