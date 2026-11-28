//! Local classification and durable overrides, scoped to an IMAP mailbox
//! epoch (port of `backend/app/mail/retention.py`).
//!
//! * [`classify_headers`] assigns exactly one category from the Subject and
//!   list headers (never the body).
//! * [`retention_metadata`] combines the automatic category, a saved manual or
//!   AI choice, the applicable sender rule and the category lifetimes into the
//!   `category*`/`expiration*` fields shown for every message.
//! * [`RetentionStore`] persists manual/AI choices and sender rules in
//!   `<data_directory>/mail/retention.sqlite3` using the same tables, columns
//!   and migrations as the Python store, so existing databases stay readable.
//!
//! Python's `RetentionConflictError` maps to [`MailError::RetentionConflict`]
//! (409), `RetentionError` to [`MailError::Retention`] (500) and `ValueError`
//! to [`MailError::validation`] (422).

use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::{LazyLock, Mutex};
use std::time::Duration;

use chrono::{DateTime, Datelike, NaiveDate, NaiveDateTime, NaiveTime, Utc};
use regex::Regex;
use rusqlite::types::Value as SqlValue;
use rusqlite::{params, params_from_iter, Connection, OptionalExtension, TransactionBehavior};
use serde::{Serialize, Serializer};
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::error::{MailError, Result};
use crate::model::{
    default_category_expiration_days, is_category, normalize_expiration_days,
    validate_category_expiration_days,
};
use crate::parsing::{self, is_py_space, py_strip, ParsedMessage, PyDateTime};
use crate::sessions::MailAccount;

// ---------------------------------------------------------------------------
// Classification
// ---------------------------------------------------------------------------

// Subject phrases are intentionally more specific than broad terms such as
// "code", "account", or "order". Classification uses no body or network model.
static VERIFICATION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r"(?i)\b(?:verification(?: code)?|verify (?:your |the )?(?:email|account|identity)|",
        r"confirm (?:your |the )?email|one[ -]time (?:password|code)|otp|",
        r"(?:security|authentication|login|sign[ -]?in) code|",
        r"(?:reset (?:your )?password|password reset))\b",
    ))
    .unwrap()
});
static TRANSACTIONAL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r"(?i)\b(?:receipt|invoice|payment (?:received|confirmed|successful|confirmation|failed)|",
        r"order (?:confirmation|confirmed|shipped|delivered|receipt)|",
        r"(?:shipping|shipment|delivery|booking|reservation|purchase) confirmation|",
        r"refund (?:issued|processed|confirmation)|transaction (?:receipt|confirmation))\b",
    ))
    .unwrap()
});
static MARKETING: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r"(?i)\b(?:newsletter|special offer|limited[ -]time offer|sale|discount|coupon|",
        r"promo(?:tional)?|exclusive (?:offer|deal)|save \d+%|\d+% off)\b",
    ))
    .unwrap()
});
static UPDATES: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r"(?i)\b(?:weekly digest|daily digest|notification|status update|product update|",
        r"service update|security alert|activity alert|new (?:message|comment|follower)|",
        r"(?:terms|privacy policy) update)\b",
    ))
    .unwrap()
});

/// `classify_headers(headers)`: `(category, reason)`. Weak or unknown
/// evidence stays uncategorized.
pub fn classify_headers(headers: &ParsedMessage) -> (&'static str, &'static str) {
    let subject = parsing::decode_value(headers.get("Subject").as_deref());
    let rules: [(&Regex, &str, &str); 3] = [
        (
            &VERIFICATION,
            "verification",
            "Subject contains a verification or account access phrase",
        ),
        (
            &TRANSACTIONAL,
            "transactional",
            "Subject contains a receipt, order, or payment phrase",
        ),
        (
            &MARKETING,
            "marketing",
            "Subject contains a newsletter or promotional phrase",
        ),
    ];
    for (pattern, category, reason) in rules {
        if pattern.is_match(&subject) {
            return (category, reason);
        }
    }
    let unsubscribe = headers
        .get("List-Unsubscribe")
        .is_some_and(|v| !v.is_empty());
    let precedence = headers.get("Precedence").unwrap_or_default();
    if unsubscribe && py_strip(&precedence).to_lowercase() == "bulk" {
        return ("marketing", "Bulk mailing includes an unsubscribe header");
    }
    if UPDATES.is_match(&subject) {
        return (
            "updates",
            "Subject contains an update or notification phrase",
        );
    }
    if headers.get("List-Id").is_some_and(|v| !v.is_empty()) {
        return ("updates", "Message belongs to a mailing list");
    }
    (
        "uncategorized",
        "No strong category signal in the message headers",
    )
}

// ---------------------------------------------------------------------------
// Identity helpers
// ---------------------------------------------------------------------------

const MAX_UID: i64 = 4_294_967_295;

/// `normalize_uid_validity(value)` for text: 1-10 ASCII digits (surrounding
/// whitespace allowed) in `1..=4294967295`, canonicalised without zeros.
pub fn normalize_uid_validity(value: &str) -> Option<String> {
    let text = py_strip(value);
    if text.is_empty() || text.len() > 10 || !text.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let number: i64 = text.parse().ok()?;
    (1..=MAX_UID).contains(&number).then(|| number.to_string())
}

/// `normalize_uid_validity(value)` for bytes (must be ASCII).
pub fn normalize_uid_validity_bytes(value: &[u8]) -> Option<String> {
    if !value.is_ascii() {
        return None;
    }
    normalize_uid_validity(std::str::from_utf8(value).ok()?)
}

/// [`normalize_uid_validity`] for an optional value (`None` stays `None`).
fn normalize_epoch(value: Option<&str>) -> Option<String> {
    value.and_then(normalize_uid_validity)
}

fn valid_uid(uid: i64) -> bool {
    (1..=MAX_UID).contains(&uid)
}

/// `json.dumps(text)` (ensure_ascii=True).
fn python_json_string(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('"');
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 || (c as u32) > 0x7e => {
                let mut units = [0u16; 2];
                for unit in c.encode_utf16(&mut units) {
                    out.push_str(&format!("\\u{unit:04x}"));
                }
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// `_mailbox_identity(account, folder)`: a stable hash of the connection
/// (email, server, port, security) and the folder with INBOX canonicalised.
pub fn mailbox_identity(account: &MailAccount, folder: &str) -> (String, String) {
    let connection = format!(
        "[{},{},{},{}]",
        python_json_string(&py_strip(&account.email).to_lowercase()),
        python_json_string(&account.incoming_server.trim_end_matches('.').to_lowercase()),
        account.incoming_port,
        python_json_string(&account.imap_security()),
    );
    let account_key = hex::encode(Sha256::digest(connection.as_bytes()));
    let folder = if folder.to_uppercase() == "INBOX" {
        "INBOX".to_string()
    } else {
        folder.to_string()
    };
    (account_key, folder)
}

/// `_identity(account, folder, uid, uid_validity)`.
fn message_identity(
    account: &MailAccount,
    folder: &str,
    uid: Option<i64>,
    uid_validity: Option<&str>,
) -> Result<(String, String, String, i64)> {
    let epoch = normalize_epoch(uid_validity);
    match (epoch, uid) {
        (Some(epoch), Some(uid)) if valid_uid(uid) => {
            let (account_key, folder) = mailbox_identity(account, folder);
            Ok((account_key, folder, epoch, uid))
        }
        _ => Err(MailError::RetentionConflict(
            "Message identity is unavailable. Refresh the folder before editing retention.".into(),
        )),
    }
}

// ---------------------------------------------------------------------------
// Sender addresses (schemas.recipient_address + retention helpers)
// ---------------------------------------------------------------------------

const MESSAGE_CONTROL: &str = "Recipients must be valid email addresses without control characters";
const MESSAGE_ONE: &str = "Each recipient must contain one email address";
const MESSAGE_ADDRESS: &str = "Enter a valid recipient email address";
const MESSAGE_DOMAIN: &str = "Enter a valid recipient email domain";

/// `schemas.header_safe`.
fn header_safe(value: &str) -> bool {
    !value.chars().any(|c| (c as u32) < 32 || c as u32 == 127)
}

/// `headerregistry` specials plus folding whitespace (`ATOM_ENDS`).
fn is_atom_end(c: char) -> bool {
    "()<>@,:;.\"[] \t".contains(c)
}

/// One mailbox accepted by the strict parser.
struct StrictMailbox {
    display_name: String,
    local_part: String,
    domain: String,
}

/// A strict, defect-free RFC 5322 single-mailbox parser reproducing what
/// `HeaderRegistry()("To", value)` accepts without registering defects.
struct StrictParser {
    chars: Vec<char>,
    pos: usize,
}

type Defect = ();

impl StrictParser {
    fn peek(&self) -> Option<char> {
        self.chars.get(self.pos).copied()
    }

    fn at_end(&self) -> bool {
        self.pos >= self.chars.len()
    }

    /// Optional CFWS; unterminated comments are defects.
    fn cfws(&mut self) -> std::result::Result<(), Defect> {
        while let Some(c) = self.peek() {
            if c == ' ' || c == '\t' {
                self.pos += 1;
            } else if c == '(' {
                self.comment()?;
            } else {
                break;
            }
        }
        Ok(())
    }

    fn comment(&mut self) -> std::result::Result<(), Defect> {
        self.pos += 1;
        let mut depth = 1;
        while let Some(c) = self.peek() {
            self.pos += 1;
            match c {
                '\\' => self.pos += 1,
                '(' => depth += 1,
                ')' => {
                    depth -= 1;
                    if depth == 0 {
                        return Ok(());
                    }
                }
                _ => {}
            }
        }
        Err(())
    }

    /// Quoted string content (quoted pairs unescaped).
    fn quoted_string(&mut self) -> std::result::Result<String, Defect> {
        self.pos += 1;
        let mut out = String::new();
        while let Some(c) = self.peek() {
            self.pos += 1;
            match c {
                '"' => return Ok(out),
                '\\' => {
                    let escaped = self.peek().ok_or(())?;
                    self.pos += 1;
                    out.push(escaped);
                }
                c => out.push(c),
            }
        }
        Err(())
    }

    fn atext(&mut self) -> String {
        let start = self.pos;
        while self.peek().is_some_and(|c| !is_atom_end(c)) {
            self.pos += 1;
        }
        self.chars[start..self.pos].iter().collect()
    }

    /// `dot-atom-text`: atoms separated by single dots.
    fn dot_atom_text(&mut self) -> std::result::Result<String, Defect> {
        let mut out = self.atext();
        if out.is_empty() {
            return Err(());
        }
        while self.peek() == Some('.') {
            self.pos += 1;
            let atom = self.atext();
            if atom.is_empty() {
                return Err(());
            }
            out.push('.');
            out.push_str(&atom);
        }
        Ok(out)
    }

    /// `addr-spec` with CFWS around its parts. Returns (local, quoted?, domain).
    fn addr_spec(&mut self) -> std::result::Result<(String, String), Defect> {
        self.cfws()?;
        let local = if self.peek() == Some('"') {
            self.quoted_string()?
        } else {
            let local = self.dot_atom_text()?;
            if !local.is_ascii() {
                // NonASCIILocalPartDefect.
                return Err(());
            }
            local
        };
        if !local.is_ascii() {
            return Err(());
        }
        self.cfws()?;
        if self.peek() != Some('@') {
            return Err(());
        }
        self.pos += 1;
        self.cfws()?;
        let domain = if self.peek() == Some('[') {
            let start = self.pos;
            self.pos += 1;
            loop {
                match self.peek() {
                    None | Some('[') | Some('\\') => return Err(()),
                    Some(']') => {
                        self.pos += 1;
                        break;
                    }
                    Some(_) => self.pos += 1,
                }
            }
            self.chars[start..self.pos].iter().collect()
        } else {
            self.dot_atom_text()?
        };
        self.cfws()?;
        Ok((local, domain))
    }

    /// Display-name words up to `<`; periods and other specials are defects.
    fn phrase(&mut self) -> std::result::Result<Vec<String>, Defect> {
        let mut words = Vec::new();
        loop {
            self.cfws()?;
            match self.peek() {
                Some('<') | None => return Ok(words),
                Some('"') => {
                    let text = self.quoted_string()?;
                    words.push(parsing::decode_unstructured(&text));
                }
                Some(c) if is_atom_end(c) => return Err(()),
                Some(_) => {
                    let atom = self.atext();
                    words.push(parsing::decode_unstructured(&atom));
                }
            }
        }
    }

    fn has_angle_bracket(&self) -> bool {
        let mut quoted = false;
        let mut depth = 0;
        let mut escaped = false;
        for &c in &self.chars {
            if escaped {
                escaped = false;
                continue;
            }
            match c {
                '\\' => escaped = true,
                '"' if depth == 0 => quoted = !quoted,
                '(' if !quoted => depth += 1,
                ')' if !quoted && depth > 0 => depth -= 1,
                '<' if !quoted && depth == 0 => return true,
                _ => {}
            }
        }
        false
    }

    fn mailbox(&mut self) -> std::result::Result<StrictMailbox, Defect> {
        if self.has_angle_bracket() {
            let words = self.phrase()?;
            if self.peek() != Some('<') {
                return Err(());
            }
            self.pos += 1;
            let (local_part, domain) = self.addr_spec()?;
            if self.peek() != Some('>') {
                return Err(());
            }
            self.pos += 1;
            self.cfws()?;
            Ok(StrictMailbox {
                display_name: words.join(" "),
                local_part,
                domain,
            })
        } else {
            let (local_part, domain) = self.addr_spec()?;
            Ok(StrictMailbox {
                display_name: String::new(),
                local_part,
                domain,
            })
        }
    }

    /// Exactly one mailbox, optionally followed by one trailing comma.
    fn single_mailbox(value: &str) -> std::result::Result<StrictMailbox, Defect> {
        let mut parser = StrictParser {
            chars: value.chars().collect(),
            pos: 0,
        };
        let mailbox = parser.mailbox()?;
        if parser.peek() == Some(',') {
            parser.pos += 1;
            parser.cfws()?;
        }
        if !parser.at_end() {
            return Err(());
        }
        Ok(mailbox)
    }
}

/// `headerregistry.Address.addr_spec`: quote the local part when needed.
fn addr_spec(local_part: &str, domain: &str) -> String {
    let needs_quotes = local_part.chars().any(|c| c != '.' && is_atom_end(c));
    let local = if needs_quotes {
        format!(
            "\"{}\"",
            local_part.replace('\\', "\\\\").replace('"', "\\\"")
        )
    } else {
        local_part.to_string()
    };
    format!("{local}@{domain}")
}

/// Python's `str.encode("idna")` (IDNA 2003): ASCII names pass through with
/// label length checks; other names are mapped per label (transitional
/// mapping, then punycode).
fn python_idna_encode(domain: &str) -> std::result::Result<String, ()> {
    if domain.is_empty() {
        return Ok(String::new());
    }
    if domain.is_ascii() {
        let labels: Vec<&str> = domain.split('.').collect();
        let (last, rest) = labels.split_last().ok_or(())?;
        if rest
            .iter()
            .any(|label| label.is_empty() || label.len() >= 64)
            || last.len() >= 64
        {
            return Err(());
        }
        return Ok(domain.to_string());
    }
    let mut labels: Vec<&str> = domain
        .split(['.', '\u{3002}', '\u{ff0e}', '\u{ff61}'])
        .collect();
    let trailing_dot = if labels.last().is_some_and(|l| l.is_empty()) {
        labels.pop();
        "."
    } else {
        ""
    };
    let mut encoded = Vec::with_capacity(labels.len());
    for label in labels {
        let ascii = if label.is_ascii() {
            label.to_string()
        } else {
            let mapped: String = label
                .chars()
                .flat_map(|c| match c {
                    'ß' | 'ẞ' => vec!['s', 's'],
                    'ς' => vec!['σ'],
                    '\u{200c}' | '\u{200d}' => vec![],
                    c => vec![c],
                })
                .collect();
            idna::domain_to_ascii(&mapped).map_err(|_| ())?
        };
        if ascii.is_empty() || ascii.len() >= 64 || ascii.contains('.') {
            return Err(());
        }
        encoded.push(ascii);
    }
    Ok(encoded.join(".") + trailing_dot)
}

static DOMAIN_LABEL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$").unwrap());

/// Port of `schemas.recipient_address`: validate exactly one mailbox (an
/// optional display name is allowed) and return its addr-spec.
pub(crate) fn recipient_address(value: &str) -> Result<String> {
    if !header_safe(value) || value.chars().count() > 998 {
        return Err(MailError::validation(MESSAGE_CONTROL));
    }
    let mailbox =
        StrictParser::single_mailbox(value).map_err(|_| MailError::validation(MESSAGE_ONE))?;
    if !header_safe(&mailbox.display_name) {
        // A decoded control character is a NonPrintableDefect in Python.
        return Err(MailError::validation(MESSAGE_ONE));
    }
    let address = addr_spec(&mailbox.local_part, &mailbox.domain);
    if address.matches('@').count() != 1 || address.chars().any(is_py_space) {
        return Err(MailError::validation(MESSAGE_ADDRESS));
    }
    let (local, domain) = address.rsplit_once('@').unwrap_or(("", ""));
    if local.is_empty() || domain.is_empty() || address.chars().any(|c| "<>,;\\".contains(c)) {
        return Err(MailError::validation(MESSAGE_ADDRESS));
    }
    let domain_ok = if domain.starts_with('[') && domain.ends_with(']') {
        let inner = &domain[1..domain.len() - 1];
        let inner = if inner
            .get(..5)
            .is_some_and(|p| p.eq_ignore_ascii_case("ipv6:"))
        {
            &inner[5..]
        } else {
            inner
        };
        inner.parse::<IpAddr>().is_ok()
    } else {
        match python_idna_encode(domain) {
            Ok(normalized) => {
                normalized.len() <= 253
                    && normalized
                        .split('.')
                        .all(|label| DOMAIN_LABEL.is_match(label))
            }
            Err(()) => false,
        }
    };
    if !domain_ok {
        return Err(MailError::validation(MESSAGE_DOMAIN));
    }
    Ok(address)
}

/// `normalize_sender_address(value)`: one validated mailbox, lowercased, with
/// an IDNA-encoded domain - never a display name or bare domain.
pub fn normalize_sender_address(value: &str) -> Result<String> {
    let address = recipient_address(py_strip(value))?;
    let (local, domain) = address.rsplit_once('@').unwrap_or(("", ""));
    let domain = if domain.starts_with('[') {
        domain.to_string()
    } else {
        python_idna_encode(domain).map_err(|_| MailError::validation(MESSAGE_DOMAIN))?
    };
    Ok(format!(
        "{}@{}",
        local.to_lowercase(),
        domain.to_lowercase()
    ))
}

static FOLDED_LINE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\r?\n[ \t]+").unwrap());

/// `sender_address(headers)`: exactly one RFC From author, normalised;
/// invalid or ambiguous messages cannot match a sender rule.
pub fn sender_address(headers: &ParsedMessage) -> Option<String> {
    let mut from = headers
        .raw_headers()
        .iter()
        .filter(|h| h.name.eq_ignore_ascii_case("from"));
    let first = from.next()?;
    if from.next().is_some() {
        return None;
    }
    // RFC 6532 UTF-8 is legal; anything else is rejected strictly.
    let original = std::str::from_utf8(&first.value).ok()?;
    let unfolded = FOLDED_LINE.replace_all(original, " ");
    normalize_sender_address(&unfolded).ok()
}

// ---------------------------------------------------------------------------
// Dates
// ---------------------------------------------------------------------------

/// Parse `HH[:?MM[:?SS[{.,}fff[fff]]]]` (`_parse_hh_mm_ss_ff`).
fn parse_hh_mm_ss_ff(text: &str) -> Option<[u32; 4]> {
    let bytes = text.as_bytes();
    let mut comps = [0u32; 4];
    let mut pos = 0;
    let mut has_sep = false;
    for (comp, slot) in comps.iter_mut().enumerate().take(3) {
        let digits = text.get(pos..pos + 2)?;
        if !digits.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        *slot = digits.parse().ok()?;
        pos += 2;
        let next = bytes.get(pos).copied();
        if comp == 0 {
            has_sep = next == Some(b':');
        }
        if next.is_none() || comp >= 2 {
            break;
        }
        if has_sep && next != Some(b':') {
            return None;
        }
        if has_sep {
            pos += 1;
        }
    }
    if pos < bytes.len() {
        if bytes[pos] != b'.' && bytes[pos] != b',' {
            return None;
        }
        pos += 1;
        let fraction = &text[pos..];
        if fraction.is_empty() || !fraction.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        let used = &fraction[..fraction.len().min(6)];
        let mut micros: u32 = used.parse().ok()?;
        for _ in used.len()..6 {
            micros *= 10;
        }
        comps[3] = micros;
    }
    Some(comps)
}

/// `datetime.fromisoformat(value)` for calendar dates (week dates are not
/// supported): the naive value plus the UTC offset in seconds, if any.
fn python_fromisoformat(value: &str) -> Option<(NaiveDateTime, Option<i64>)> {
    if value.len() < 7 || !value.is_char_boundary(4) {
        return None;
    }
    let bytes = value.as_bytes();
    let (date_len, has_dash) = if bytes[4] == b'-' {
        (10, true)
    } else {
        (8, false)
    };
    if bytes.get(4 + usize::from(has_dash)) == Some(&b'W') || value.len() < date_len {
        return None;
    }
    let date_text = value.get(..date_len).filter(|text| text.is_ascii())?;
    let digits = |s: &str| s.bytes().all(|b| b.is_ascii_digit());
    let (year, month, day) = if has_dash {
        if &date_text[7..8] != "-" {
            return None;
        }
        (&date_text[0..4], &date_text[5..7], &date_text[8..10])
    } else {
        (&date_text[0..4], &date_text[4..6], &date_text[6..8])
    };
    if !(digits(year) && digits(month) && digits(day)) {
        return None;
    }
    let date = NaiveDate::from_ymd_opt(year.parse().ok()?, month.parse().ok()?, day.parse().ok()?)?;
    let rest = &value[date_len..];
    if rest.is_empty() {
        return Some((date.and_time(NaiveTime::MIN), None));
    }
    // Any single character separates the date and the time.
    let separator = rest.chars().next()?;
    let time_text = &rest[separator.len_utf8()..];
    if time_text.len() < 2 {
        return None;
    }
    let tz_pos = time_text.find(['-', '+', 'Z']);
    let clock = &time_text[..tz_pos.unwrap_or(time_text.len())];
    let [hour, minute, second, micros] = parse_hh_mm_ss_ff(clock)?;
    let time = NaiveTime::from_hms_micro_opt(hour, minute, second, micros)?;
    let offset = match tz_pos {
        None => None,
        Some(pos) if pos + 1 == time_text.len() && time_text.ends_with('Z') => Some(0),
        Some(pos) => {
            let tz = &time_text[pos + 1..];
            if matches!(tz.len(), 0 | 1 | 3) {
                return None;
            }
            let [h, m, s, _] = parse_hh_mm_ss_ff(tz)?;
            let sign = if time_text.as_bytes()[pos] == b'-' {
                -1
            } else {
                1
            };
            let seconds = i64::from(h) * 3600 + i64::from(m) * 60 + i64::from(s);
            if seconds >= 86_400 {
                return None;
            }
            Some(sign * seconds)
        }
    };
    Some((date.and_time(time), offset))
}

/// `_received_datetime(value)`: an aware ISO timestamp converted to UTC;
/// naive, malformed or out-of-range values give `None`.
pub fn parse_received_datetime(value: Option<&str>) -> Option<NaiveDateTime> {
    let value = value.filter(|v| !v.is_empty())?;
    let (naive, offset) = python_fromisoformat(value)?;
    let utc = naive - chrono::Duration::seconds(offset?);
    (1..=9999).contains(&utc.year()).then_some(utc)
}

/// `datetime.isoformat()` of a UTC instant.
fn utc_isoformat(value: NaiveDateTime) -> String {
    PyDateTime {
        naive: value,
        offset_seconds: Some(0),
    }
    .isoformat()
}

// ---------------------------------------------------------------------------
// Metadata
// ---------------------------------------------------------------------------

/// A saved sender rule (or one immutable rule event). Rules always have a
/// category; removal events store `None`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SenderRule {
    pub folder: String,
    pub sender: String,
    pub category: Option<String>,
    pub uid_validity: String,
    pub first_uid: i64,
    pub created_at: String,
    pub revision: i64,
}

/// Saved manual/AI choices for one message (a `message_retention` row).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize)]
pub struct RetentionOverride {
    pub uid: i64,
    pub category: Option<String>,
    pub expiration_days: Option<i64>,
    pub category_source: Option<String>,
    pub category_reason: Option<String>,
    pub category_model: Option<String>,
}

/// `expires_at`: an ISO timestamp, `-1` for never, or `null` when unknown.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExpiresAt {
    At(String),
    Never,
    Unknown,
}

impl Serialize for ExpiresAt {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        match self {
            Self::At(text) => serializer.serialize_str(text),
            Self::Never => serializer.serialize_i64(-1),
            Self::Unknown => serializer.serialize_none(),
        }
    }
}

/// The retention fields of a message (`retention_metadata` result).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RetentionMetadata {
    pub category: String,
    pub category_source: String,
    pub category_reason: String,
    pub category_model: Option<String>,
    pub expiration_days: i64,
    pub expiration_source: String,
    pub expires_at: ExpiresAt,
    pub expired: bool,
    pub received_at: Option<String>,
    pub uid_validity: Option<String>,
    pub sender_rule: Option<SenderRule>,
}

impl RetentionMetadata {
    /// The metadata as a JSON object, ready to merge into a message summary.
    pub fn into_map(self) -> serde_json::Map<String, serde_json::Value> {
        match serde_json::to_value(self) {
            Ok(serde_json::Value::Object(map)) => map,
            _ => serde_json::Map::new(),
        }
    }
}

/// Keyword arguments of `retention_metadata`.
#[derive(Debug, Clone, Copy, Default)]
pub struct MetadataOptions<'a> {
    pub overrides: Option<&'a RetentionOverride>,
    pub uid_validity: Option<&'a str>,
    pub now: Option<DateTime<Utc>>,
    pub sender_rule: Option<&'a SenderRule>,
    pub uid: Option<i64>,
    /// `None` means "derive from `sender_rule`" (Python's default).
    pub sender_rule_events: Option<&'a [SenderRule]>,
}

/// `_sender_rule_applies`.
fn sender_rule_applies(
    rule: &SenderRule,
    uid: Option<i64>,
    uid_validity: Option<&str>,
    received_at: Option<&str>,
) -> bool {
    let Some(epoch) = normalize_epoch(uid_validity) else {
        return false;
    };
    if epoch == rule.uid_validity {
        return uid.is_some_and(|uid| uid >= rule.first_uid);
    }
    // UID sequences cannot be compared across mailbox rebuilds. INTERNALDATE
    // keeps pre-rule mail unchanged even when it is assigned a new UID.
    let received = parse_received_datetime(received_at);
    let created = parse_received_datetime(Some(&rule.created_at));
    matches!((received, created), (Some(r), Some(c)) if r >= c)
}

/// Validate a policy map (Python `validate_category_expiration_days`).
fn effective_policies(policies: Option<&BTreeMap<String, i64>>) -> Result<BTreeMap<String, i64>> {
    let policies = policies
        .cloned()
        .unwrap_or_else(default_category_expiration_days);
    validate_category_expiration_days(&json!(policies)).map_err(MailError::validation)
}

/// `retention_metadata(headers, received_at, policies, ...)`.
pub fn retention_metadata(
    headers: &ParsedMessage,
    received_at: Option<&str>,
    policies: Option<&BTreeMap<String, i64>>,
    options: &MetadataOptions<'_>,
) -> Result<RetentionMetadata> {
    let policies = effective_policies(policies)?;
    let (automatic_category, reason) = classify_headers(headers);
    let empty = RetentionOverride::default();
    let overrides = options.overrides.unwrap_or(&empty);
    let saved_category = overrides.category.as_deref().filter(|c| is_category(c));
    // Only a rule for the actual single From author can enter the precedence
    // chain, even if a caller provides a preloaded rule map.
    let sender = sender_address(headers);
    let sender_rule = options
        .sender_rule
        .filter(|rule| Some(rule.sender.as_str()) == sender.as_deref());
    let derived;
    let events: &[SenderRule] = match options.sender_rule_events {
        Some(events) => events,
        None => {
            derived = sender_rule.cloned().into_iter().collect::<Vec<_>>();
            &derived
        }
    };
    let mut applied_rule: Option<&SenderRule> = None;
    for event in events {
        let eligible = Some(event.sender.as_str()) == sender.as_deref()
            && sender_rule_applies(event, options.uid, options.uid_validity, received_at);
        // max(): the first event with the highest revision wins.
        if eligible && applied_rule.is_none_or(|best| event.revision > best.revision) {
            applied_rule = Some(event);
        }
    }
    let rule_category = applied_rule
        .and_then(|rule| rule.category.as_deref())
        .filter(|c| is_category(c));
    let (category, source) = match (saved_category, rule_category) {
        (Some(saved), _) => {
            let source = if overrides.category_source.as_deref() == Some("ai") {
                "ai"
            } else {
                "manual"
            };
            (saved.to_string(), source)
        }
        (None, Some(rule)) => (rule.to_string(), "sender_rule"),
        (None, None) => (automatic_category.to_string(), "automatic"),
    };
    let manual_expiration = overrides.expiration_days;
    let days = match manual_expiration {
        None => policies.get(&category).copied().unwrap_or(-1),
        Some(value) => normalize_expiration_days(&json!(value)).map_err(MailError::validation)?,
    };
    let received = parse_received_datetime(received_at);
    let mut expires_at = if days < 0 {
        ExpiresAt::Never
    } else {
        ExpiresAt::Unknown
    };
    let mut expired = false;
    if days >= 0 {
        if let Some(received) = received {
            let expires =
                chrono::Duration::try_days(days).and_then(|d| received.checked_add_signed(d));
            match expires.filter(|e| e.year() <= 9999) {
                Some(expires) => {
                    expires_at = ExpiresAt::At(utc_isoformat(expires));
                    let current = options.now.unwrap_or_else(Utc::now).naive_utc();
                    expired = expires <= current;
                }
                // Malformed/extreme server dates must never make a message
                // eligible for cleanup merely because the expiry overflows.
                None => expires_at = ExpiresAt::Unknown,
            }
        }
    }
    let category_reason = match source {
        "ai" => {
            let text = overrides
                .category_reason
                .as_deref()
                .filter(|r| !r.is_empty())
                .unwrap_or("Classified by local AI");
            parsing::truncate_chars(text, 500)
        }
        "manual" => "Category selected manually".to_string(),
        "sender_rule" => format!(
            "Saved sender rule for {} assigned this category",
            applied_rule.map(|rule| rule.sender.as_str()).unwrap_or("")
        ),
        _ => reason.to_string(),
    };
    Ok(RetentionMetadata {
        category_model: if source == "ai" {
            overrides.category_model.clone()
        } else {
            None
        },
        category,
        category_source: source.to_string(),
        category_reason,
        expiration_days: days,
        expiration_source: if manual_expiration.is_some() {
            "manual"
        } else {
            "category"
        }
        .into(),
        expires_at,
        expired,
        received_at: received.map(utc_isoformat),
        uid_validity: normalize_epoch(options.uid_validity),
        sender_rule: sender_rule.cloned(),
    })
}

// ---------------------------------------------------------------------------
// Store
// ---------------------------------------------------------------------------

/// Python's `UNSET` sentinel for [`RetentionStore::update`]: leave the field
/// alone, reset it (`None`), or set a value.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum Patch<T> {
    #[default]
    Unset,
    Clear,
    Set(T),
}

impl<T> Patch<T> {
    fn is_unset(&self) -> bool {
        matches!(self, Self::Unset)
    }
}

/// Optional arguments of [`RetentionStore::save_sender_rule`].
#[derive(Debug, Clone, Copy, Default)]
pub struct SaveSenderRuleOptions<'a> {
    pub created_at: Option<&'a str>,
    pub message_uid: Option<i64>,
    pub expected_category_revision: Option<i64>,
    pub expected_sender_rule_revision: Option<i64>,
}

/// Internal error: either a database/filesystem failure (wrapped into the
/// operation's `RetentionError` message) or an error to propagate unchanged.
enum Failure {
    Storage,
    Mail(MailError),
}

impl From<rusqlite::Error> for Failure {
    fn from(_: rusqlite::Error) -> Self {
        Self::Storage
    }
}

impl From<std::io::Error> for Failure {
    fn from(_: std::io::Error) -> Self {
        Self::Storage
    }
}

impl From<MailError> for Failure {
    fn from(error: MailError) -> Self {
        Self::Mail(error)
    }
}

fn wrap<T>(message: &str, result: std::result::Result<T, Failure>) -> Result<T> {
    result.map_err(|failure| match failure {
        Failure::Storage => MailError::Retention(message.to_string()),
        Failure::Mail(error) => error,
    })
}

const RULE_COLUMNS: &str =
    "folder, sender, category, uid_validity, first_uid, created_at, revision";

fn rule_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<SenderRule> {
    Ok(SenderRule {
        folder: row.get(0)?,
        sender: row.get(1)?,
        category: row.get(2)?,
        uid_validity: row.get(3)?,
        first_uid: row.get(4)?,
        created_at: row.get(5)?,
        revision: row.get(6)?,
    })
}

/// `settings.validate_local_ai_model`.
fn validate_local_ai_model(value: &str) -> Result<String> {
    static PATTERN: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,199}$").unwrap());
    static CLOUD: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"(?i)(?:^|[-:/])cloud(?:$|[-:/])").unwrap());
    if !PATTERN.is_match(value) {
        return Err(MailError::validation(
            "Local AI model must be a model name of at most 200 characters",
        ));
    }
    if CLOUD.is_match(value) {
        return Err(MailError::validation(
            "Choose a locally installed model, not a cloud model",
        ));
    }
    if value.contains("://") || value.contains("..") || value.starts_with('/') {
        return Err(MailError::validation(
            "Local AI model must be a model identifier",
        ));
    }
    Ok(value.to_string())
}

/// Persist explicit manual and AI choices within a mailbox UID epoch
/// (`RetentionStore`). Connections are opened per operation; the schema is
/// created/migrated once per store under a lock.
#[derive(Debug)]
pub struct RetentionStore {
    path: PathBuf,
    schema_initialized: Mutex<bool>,
}

impl RetentionStore {
    /// Store at `<data_directory>/mail/retention.sqlite3`. The directory must
    /// already be resolved (`doctor::config::data_directory`); nothing is
    /// created until the first write.
    pub fn new(data_directory: impl AsRef<Path>) -> Self {
        Self {
            path: data_directory
                .as_ref()
                .join("mail")
                .join("retention.sqlite3"),
            schema_initialized: Mutex::new(false),
        }
    }

    /// The SQLite database path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Connections are scoped to individual operations.
    pub fn close(&self) {}

    fn exists(&self) -> bool {
        self.path.exists()
    }

    fn connect(&self) -> std::result::Result<Connection, Failure> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut connection = Connection::open(&self.path)?;
        connection.busy_timeout(Duration::from_secs(15))?;
        // One transaction migrates existing databases; BEGIN IMMEDIATE also
        // coordinates separate store instances.
        let mut initialized = self
            .schema_initialized
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if !*initialized {
            let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            tx.execute_batch(
                "CREATE TABLE IF NOT EXISTS message_retention (
                    account_key TEXT NOT NULL, folder TEXT NOT NULL,
                    uid_validity TEXT NOT NULL, uid INTEGER NOT NULL,
                    category TEXT, expiration_days INTEGER,
                    category_source TEXT, category_reason TEXT, category_model TEXT,
                    category_revision INTEGER NOT NULL DEFAULT 0,
                    PRIMARY KEY (account_key, folder, uid_validity, uid)
                );
                CREATE TABLE IF NOT EXISTS sender_category_rule_events (
                    account_key TEXT NOT NULL, folder TEXT NOT NULL,
                    sender TEXT NOT NULL, category TEXT,
                    uid_validity TEXT NOT NULL, first_uid INTEGER NOT NULL,
                    created_at TEXT NOT NULL, revision INTEGER NOT NULL,
                    PRIMARY KEY (account_key, folder, sender, revision)
                );",
            )?;
            let columns: Vec<String> = {
                let mut statement = tx.prepare("PRAGMA table_info(message_retention)")?;
                let names = statement.query_map([], |row| row.get::<_, String>("name"))?;
                names.collect::<rusqlite::Result<_>>()?
            };
            for (name, definition) in [
                ("category_source", "TEXT"),
                ("category_reason", "TEXT"),
                ("category_model", "TEXT"),
                ("category_revision", "INTEGER NOT NULL DEFAULT 0"),
            ] {
                if !columns.iter().any(|column| column == name) {
                    tx.execute_batch(&format!(
                        "ALTER TABLE message_retention ADD COLUMN {name} {definition}"
                    ))?;
                }
            }
            tx.execute_batch(
                "UPDATE message_retention SET category_source='manual'
                    WHERE category IS NOT NULL AND category_source IS NULL;
                CREATE TABLE IF NOT EXISTS sender_category_rules (
                    account_key TEXT NOT NULL, folder TEXT NOT NULL,
                    sender TEXT NOT NULL, category TEXT NOT NULL,
                    uid_validity TEXT NOT NULL, first_uid INTEGER NOT NULL,
                    created_at TEXT NOT NULL, revision INTEGER NOT NULL DEFAULT 1,
                    PRIMARY KEY (account_key, folder, sender)
                );
                INSERT OR IGNORE INTO sender_category_rule_events
                    SELECT account_key, folder, sender, category, uid_validity, first_uid,
                           created_at, revision
                    FROM sender_category_rules;",
            )?;
            tx.commit()?;
            *initialized = true;
        }
        drop(initialized);
        Ok(connection)
    }

    /// `get(account, folder, uid, uid_validity)`: saved choices or `None`.
    pub fn get(
        &self,
        account: &MailAccount,
        folder: &str,
        uid: i64,
        uid_validity: Option<&str>,
    ) -> Result<Option<RetentionOverride>> {
        Ok(self
            .get_many(account, folder, &[uid], uid_validity)?
            .remove(&uid))
    }

    /// `get_many`: read a bounded header batch's overrides with one
    /// connection. Rows that only hold a revision tombstone are skipped.
    pub fn get_many(
        &self,
        account: &MailAccount,
        folder: &str,
        uids: &[i64],
        uid_validity: Option<&str>,
    ) -> Result<HashMap<i64, RetentionOverride>> {
        if uids.is_empty() || normalize_epoch(uid_validity).is_none() || !self.exists() {
            return Ok(HashMap::new());
        }
        let (account_key, folder, epoch, _) =
            message_identity(account, folder, Some(uids[0]), uid_validity)?;
        if uids.iter().any(|uid| !valid_uid(*uid)) {
            return Err(MailError::RetentionConflict(
                "Message identity is unavailable. Refresh the folder.".into(),
            ));
        }
        wrap(
            "Cannot read saved email retention choices",
            (|| {
                let connection = self.connect()?;
                let mut result = HashMap::new();
                for batch in uids.chunks(200) {
                    let placeholders = vec!["?"; batch.len()].join(",");
                    let sql = format!(
                        "SELECT uid, category, expiration_days, category_source, category_reason, \
                     category_model FROM message_retention WHERE account_key=? AND folder=? \
                     AND uid_validity=? AND uid IN ({placeholders}) \
                     AND (category IS NOT NULL OR expiration_days IS NOT NULL)"
                    );
                    let mut values: Vec<SqlValue> = vec![
                        account_key.clone().into(),
                        folder.clone().into(),
                        epoch.clone().into(),
                    ];
                    values.extend(batch.iter().map(|uid| SqlValue::Integer(*uid)));
                    let mut statement = connection.prepare(&sql)?;
                    let rows = statement.query_map(params_from_iter(values), |row| {
                        Ok(RetentionOverride {
                            uid: row.get(0)?,
                            category: row.get(1)?,
                            expiration_days: row.get(2)?,
                            category_source: row.get(3)?,
                            category_reason: row.get(4)?,
                            category_model: row.get(5)?,
                        })
                    })?;
                    for row in rows {
                        let row = row?;
                        result.insert(row.uid, row);
                    }
                }
                Ok(result)
            })(),
        )
    }

    /// `metadata(...)`: retention fields of one message using the saved
    /// overrides and the From author's sender rule history.
    #[allow(clippy::too_many_arguments)]
    pub fn metadata(
        &self,
        account: &MailAccount,
        folder: &str,
        uid: i64,
        uid_validity: Option<&str>,
        headers: &ParsedMessage,
        received_at: Option<&str>,
        policies: Option<&BTreeMap<String, i64>>,
    ) -> Result<RetentionMetadata> {
        let sender = sender_address(headers);
        let overrides = self.get(account, folder, uid, uid_validity)?;
        let (rule, events) = match &sender {
            Some(sender) => (
                self.get_sender_rule(account, folder, sender)?,
                self.get_sender_rule_events(account, folder, sender)?,
            ),
            None => (None, Vec::new()),
        };
        retention_metadata(
            headers,
            received_at,
            policies,
            &MetadataOptions {
                overrides: overrides.as_ref(),
                uid_validity,
                now: None,
                sender_rule: rule.as_ref(),
                uid: Some(uid),
                sender_rule_events: Some(&events),
            },
        )
    }

    /// `get_sender_rules_for_folder`: rules keyed by sender, one connection
    /// for an entire IMAP list scan.
    pub fn get_sender_rules_for_folder(
        &self,
        account: &MailAccount,
        folder: &str,
    ) -> Result<HashMap<String, SenderRule>> {
        Ok(self
            .list_sender_rules(account, Some(folder))?
            .into_iter()
            .map(|rule| (rule.sender.clone(), rule))
            .collect())
    }

    /// `get_sender_rule_events_for_folder`: immutable boundaries (including
    /// removals and edits) grouped by sender, ordered by revision.
    pub fn get_sender_rule_events_for_folder(
        &self,
        account: &MailAccount,
        folder: &str,
    ) -> Result<HashMap<String, Vec<SenderRule>>> {
        if !self.exists() {
            return Ok(HashMap::new());
        }
        let (account_key, folder) = mailbox_identity(account, folder);
        wrap(
            "Cannot read saved sender category history",
            (|| {
                let connection = self.connect()?;
                let mut statement = connection.prepare(&format!(
                    "SELECT {RULE_COLUMNS} FROM sender_category_rule_events \
                 WHERE account_key=? AND folder=? ORDER BY revision"
                ))?;
                let rows = statement.query_map(params![account_key, folder], rule_from_row)?;
                let mut result: HashMap<String, Vec<SenderRule>> = HashMap::new();
                for row in rows {
                    let row = row?;
                    result.entry(row.sender.clone()).or_default().push(row);
                }
                Ok(result)
            })(),
        )
    }

    /// `get_sender_rule_events(account, folder, sender)`.
    pub fn get_sender_rule_events(
        &self,
        account: &MailAccount,
        folder: &str,
        sender: &str,
    ) -> Result<Vec<SenderRule>> {
        let normalized = normalize_sender_address(sender)?;
        if !self.exists() {
            return Ok(Vec::new());
        }
        let (account_key, folder) = mailbox_identity(account, folder);
        wrap(
            "Cannot read saved sender category history",
            (|| {
                let connection = self.connect()?;
                let mut statement = connection.prepare(&format!(
                    "SELECT {RULE_COLUMNS} FROM sender_category_rule_events \
                 WHERE account_key=? AND folder=? AND sender=? ORDER BY revision"
                ))?;
                let rows =
                    statement.query_map(params![account_key, folder, normalized], rule_from_row)?;
                Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
            })(),
        )
    }

    /// `get_sender_rule_revision`: the latest event revision, 0 if none.
    pub fn get_sender_rule_revision(
        &self,
        account: &MailAccount,
        folder: &str,
        sender: &str,
    ) -> Result<i64> {
        Ok(self
            .get_sender_rule_events(account, folder, sender)?
            .last()
            .map(|event| event.revision)
            .unwrap_or(0))
    }

    /// `get_sender_rule(account, folder, sender)`.
    pub fn get_sender_rule(
        &self,
        account: &MailAccount,
        folder: &str,
        sender: &str,
    ) -> Result<Option<SenderRule>> {
        let normalized = normalize_sender_address(sender)?;
        if !self.exists() {
            return Ok(None);
        }
        let (account_key, folder) = mailbox_identity(account, folder);
        wrap(
            "Cannot read saved sender category rules",
            (|| {
                let connection = self.connect()?;
                let rule = connection
                    .query_row(
                        &format!(
                            "SELECT {RULE_COLUMNS} FROM sender_category_rules \
                         WHERE account_key=? AND folder=? AND sender=?"
                        ),
                        params![account_key, folder, normalized],
                        rule_from_row,
                    )
                    .optional()?;
                Ok(rule)
            })(),
        )
    }

    /// `list_sender_rules(account, folder=None)`: every rule of the account,
    /// or of one folder, ordered by folder and sender.
    pub fn list_sender_rules(
        &self,
        account: &MailAccount,
        folder: Option<&str>,
    ) -> Result<Vec<SenderRule>> {
        if !self.exists() {
            return Ok(Vec::new());
        }
        let (account_key, normalized_folder) =
            mailbox_identity(account, folder.filter(|f| !f.is_empty()).unwrap_or("INBOX"));
        wrap(
            "Cannot read saved sender category rules",
            (|| {
                let connection = self.connect()?;
                let mut query =
                    format!("SELECT {RULE_COLUMNS} FROM sender_category_rules WHERE account_key=?");
                let mut values: Vec<SqlValue> = vec![account_key.into()];
                if folder.is_some() {
                    query.push_str(" AND folder=?");
                    values.push(normalized_folder.into());
                }
                query.push_str(" ORDER BY folder, sender");
                let mut statement = connection.prepare(&query)?;
                let rows = statement.query_map(params_from_iter(values), rule_from_row)?;
                Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
            })(),
        )
    }

    /// `save_sender_rule`: create or replace the rule for future mail from
    /// `sender` (UIDs >= `first_uid` in epoch `uid_validity`) and append an
    /// immutable rule event. Optional revision checks give 409 conflicts.
    #[allow(clippy::too_many_arguments)]
    pub fn save_sender_rule(
        &self,
        account: &MailAccount,
        folder: &str,
        sender: &str,
        category: &str,
        uid_validity: &str,
        first_uid: i64,
        options: SaveSenderRuleOptions<'_>,
    ) -> Result<SenderRule> {
        let (account_key, folder_key) = mailbox_identity(account, folder);
        let normalized = normalize_sender_address(sender)?;
        let epoch = match normalize_uid_validity(uid_validity) {
            Some(epoch) if valid_uid(first_uid) => epoch,
            _ => {
                return Err(MailError::RetentionConflict(
                    "Future message identity is unavailable. Refresh the folder before saving \
                     a sender rule."
                        .into(),
                ))
            }
        };
        if !is_category(category) {
            return Err(MailError::validation("Choose a valid email category"));
        }
        let created = match options.created_at {
            None => Utc::now().naive_utc(),
            Some(text) => parse_received_datetime(Some(text)).ok_or_else(|| {
                MailError::validation("A valid sender rule creation time is required")
            })?,
        };
        if let Some(expected) = options.expected_category_revision {
            message_identity(account, folder, options.message_uid, Some(&epoch))?;
            if expected < 0 {
                return Err(MailError::validation(
                    "A valid category revision is required",
                ));
            }
        }
        if options.expected_sender_rule_revision.is_some_and(|r| r < 0) {
            return Err(MailError::validation(
                "A valid sender rule revision is required",
            ));
        }
        let created_at = utc_isoformat(created);
        wrap(
            "Cannot save sender category rule",
            (|| {
                let mut connection = self.connect()?;
                let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
                if let Some(expected) = options.expected_category_revision {
                    let current: Option<i64> = tx
                        .query_row(
                            "SELECT category_revision FROM message_retention \
                         WHERE account_key=? AND folder=? AND uid_validity=? AND uid=?",
                            params![account_key, folder_key, epoch, options.message_uid],
                            |row| row.get(0),
                        )
                        .optional()?;
                    if current.unwrap_or(0) != expected {
                        return Err(MailError::RetentionConflict(
                            "The email category changed. Review the current category before \
                         saving a sender rule."
                                .into(),
                        )
                        .into());
                    }
                }
                let revision: i64 = tx
                    .query_row(
                        "SELECT MAX(revision) AS revision FROM sender_category_rule_events \
                     WHERE account_key=? AND folder=? AND sender=?",
                        params![account_key, folder_key, normalized],
                        |row| row.get::<_, Option<i64>>(0),
                    )?
                    .unwrap_or(0);
                if options
                    .expected_sender_rule_revision
                    .is_some_and(|r| r != revision)
                {
                    return Err(MailError::RetentionConflict(
                    "The sender category rule changed. Refresh the email before saving it again."
                        .into(),
                )
                .into());
                }
                tx.execute(
                    "INSERT INTO sender_category_rules (account_key, folder, sender, category, \
                 uid_validity, first_uid, created_at, revision) VALUES (?, ?, ?, ?, ?, ?, ?, ?) \
                 ON CONFLICT(account_key,folder,sender) DO UPDATE SET \
                 category=excluded.category, uid_validity=excluded.uid_validity, \
                 first_uid=excluded.first_uid, created_at=excluded.created_at, \
                 revision=excluded.revision",
                    params![
                        account_key,
                        folder_key,
                        normalized,
                        category,
                        epoch,
                        first_uid,
                        created_at,
                        revision + 1
                    ],
                )?;
                tx.execute(
                    "INSERT INTO sender_category_rule_events (account_key, folder, sender, \
                     category, uid_validity, first_uid, created_at, revision) \
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    params![
                        account_key,
                        folder_key,
                        normalized,
                        category,
                        epoch,
                        first_uid,
                        created_at,
                        revision + 1
                    ],
                )?;
                tx.commit()?;
                Ok(SenderRule {
                    folder: folder_key.clone(),
                    sender: normalized.clone(),
                    category: Some(category.to_string()),
                    uid_validity: epoch.clone(),
                    first_uid,
                    created_at: created_at.clone(),
                    revision: revision + 1,
                })
            })(),
        )
    }

    /// `delete_sender_rule`: remove the rule for future mail (from
    /// `first_uid`), recording a removal event. `Ok(false)` if none existed.
    #[allow(clippy::too_many_arguments)]
    pub fn delete_sender_rule(
        &self,
        account: &MailAccount,
        folder: &str,
        sender: &str,
        uid_validity: &str,
        first_uid: i64,
        created_at: Option<&str>,
        expected_sender_rule_revision: Option<i64>,
    ) -> Result<bool> {
        let normalized = normalize_sender_address(sender)?;
        let epoch =
            match normalize_uid_validity(uid_validity) {
                Some(epoch) if valid_uid(first_uid) => epoch,
                _ => return Err(MailError::RetentionConflict(
                    "Future message identity is unavailable. Refresh the folder before removing \
                     a sender rule."
                        .into(),
                )),
            };
        let created = match created_at {
            None => Utc::now().naive_utc(),
            Some(text) => parse_received_datetime(Some(text)).ok_or_else(|| {
                MailError::validation("A valid sender rule creation time is required")
            })?,
        };
        if !self.exists() {
            return Ok(false);
        }
        let (account_key, folder_key) = mailbox_identity(account, folder);
        let created_at = utc_isoformat(created);
        wrap(
            "Cannot remove sender category rule",
            (|| {
                let mut connection = self.connect()?;
                let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
                let revision: i64 = tx
                    .query_row(
                        "SELECT MAX(revision) AS revision FROM sender_category_rule_events \
                     WHERE account_key=? AND folder=? AND sender=?",
                        params![account_key, folder_key, normalized],
                        |row| row.get::<_, Option<i64>>(0),
                    )?
                    .unwrap_or(0);
                if expected_sender_rule_revision.is_some_and(|r| r != revision) {
                    return Err(MailError::RetentionConflict(
                        "The sender category rule changed. Refresh before removing it.".into(),
                    )
                    .into());
                }
                let removed = tx.execute(
                "DELETE FROM sender_category_rules WHERE account_key=? AND folder=? AND sender=?",
                params![account_key, folder_key, normalized],
            )? > 0;
                if removed {
                    tx.execute(
                        "INSERT INTO sender_category_rule_events (account_key, folder, sender, \
                     category, uid_validity, first_uid, created_at, revision) \
                     VALUES (?, ?, ?, NULL, ?, ?, ?, ?)",
                        params![
                            account_key,
                            folder_key,
                            normalized,
                            epoch,
                            first_uid,
                            created_at,
                            revision + 1
                        ],
                    )?;
                }
                tx.commit()?;
                Ok(removed)
            })(),
        )
    }

    /// `update(..., category=UNSET, expiration_days=UNSET)`: manual category
    /// and/or lifetime override. [`Patch::Clear`] resets a value; changing
    /// the category bumps the category revision (a tombstone row is kept).
    pub fn update(
        &self,
        account: &MailAccount,
        folder: &str,
        uid: i64,
        uid_validity: &str,
        category: Patch<String>,
        expiration_days: Patch<i64>,
    ) -> Result<()> {
        let identity = message_identity(account, folder, Some(uid), Some(uid_validity))?;
        if let Patch::Set(value) = &category {
            if !is_category(value) {
                return Err(MailError::validation("Choose a valid email category"));
            }
        }
        let expiration_days = match expiration_days {
            Patch::Set(value) => {
                Patch::Set(normalize_expiration_days(&json!(value)).map_err(MailError::validation)?)
            }
            other => other,
        };
        if category.is_unset() && expiration_days.is_unset() {
            return Err(MailError::validation(
                "Choose a category or expiration to update",
            ));
        }
        wrap(
            "Cannot save email retention choices",
            (|| {
                let mut connection = self.connect()?;
                // Read and update under the same writer transaction so two
                // independent category/lifetime edits cannot discard each other.
                let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
                let previous = read_choice(&tx, &identity)?.unwrap_or_default();
                let chosen_category = match &category {
                    Patch::Unset => previous.category.clone(),
                    Patch::Clear => None,
                    Patch::Set(value) => Some(value.clone()),
                };
                let chosen_days = match expiration_days {
                    Patch::Unset => previous.expiration_days,
                    Patch::Clear => None,
                    Patch::Set(value) => Some(value),
                };
                let (source, reason, model) = match &category {
                    Patch::Unset => (previous.source, previous.reason, previous.model),
                    Patch::Clear => (None, None, None),
                    Patch::Set(_) => (Some("manual".to_string()), None, None),
                };
                let revision = previous.revision + i64::from(!category.is_unset());
                write_choice(
                    &tx,
                    &identity,
                    &Choice {
                        category: chosen_category,
                        expiration_days: chosen_days,
                        source,
                        reason,
                        model,
                        revision,
                    },
                )?;
                tx.commit()?;
                Ok(())
            })(),
        )
    }

    /// `get_category_revision`: 0 when no choice was ever saved.
    pub fn get_category_revision(
        &self,
        account: &MailAccount,
        folder: &str,
        uid: i64,
        uid_validity: &str,
    ) -> Result<i64> {
        let identity = message_identity(account, folder, Some(uid), Some(uid_validity))?;
        if !self.exists() {
            return Ok(0);
        }
        wrap(
            "Cannot read saved email category",
            (|| {
                let connection = self.connect()?;
                Ok(read_choice(&connection, &identity)?
                    .map(|c| c.revision)
                    .unwrap_or(0))
            })(),
        )
    }

    /// `save_ai`: apply a model result unless a newer category choice was
    /// made meanwhile (revision mismatch → 409).
    #[allow(clippy::too_many_arguments)]
    pub fn save_ai(
        &self,
        account: &MailAccount,
        folder: &str,
        uid: i64,
        uid_validity: &str,
        category: &str,
        reason: &str,
        model: &str,
        expected_category_revision: i64,
    ) -> Result<()> {
        let identity = message_identity(account, folder, Some(uid), Some(uid_validity))?;
        if !is_category(category) {
            return Err(MailError::validation("Choose a valid email category"));
        }
        if py_strip(reason).is_empty() || reason.chars().count() > 500 {
            return Err(MailError::validation(
                "A short classification reason is required",
            ));
        }
        let model = validate_local_ai_model(model)?;
        if expected_category_revision < 0 {
            return Err(MailError::validation(
                "A valid category revision is required",
            ));
        }
        wrap(
            "Cannot save local AI classification",
            (|| {
                let mut connection = self.connect()?;
                let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
                let row = read_choice(&tx, &identity)?;
                let current = row.as_ref().map(|c| c.revision).unwrap_or(0);
                if current != expected_category_revision {
                    return Err(MailError::RetentionConflict(
                        "The email category changed while AI was running. Review the current \
                     category and try again."
                            .into(),
                    )
                    .into());
                }
                write_choice(
                    &tx,
                    &identity,
                    &Choice {
                        category: Some(category.to_string()),
                        expiration_days: row.and_then(|c| c.expiration_days),
                        source: Some("ai".into()),
                        reason: Some(py_strip(reason).to_string()),
                        model: Some(model.clone()),
                        revision: current + 1,
                    },
                )?;
                tx.commit()?;
                Ok(())
            })(),
        )
    }
}

/// One `message_retention` row's choice columns.
#[derive(Debug, Default)]
struct Choice {
    category: Option<String>,
    expiration_days: Option<i64>,
    source: Option<String>,
    reason: Option<String>,
    model: Option<String>,
    revision: i64,
}

fn read_choice(
    connection: &Connection,
    identity: &(String, String, String, i64),
) -> rusqlite::Result<Option<Choice>> {
    connection
        .query_row(
            "SELECT category, expiration_days, category_source, category_reason, category_model, \
             category_revision FROM message_retention \
             WHERE account_key=? AND folder=? AND uid_validity=? AND uid=?",
            params![identity.0, identity.1, identity.2, identity.3],
            |row| {
                Ok(Choice {
                    category: row.get(0)?,
                    expiration_days: row.get(1)?,
                    source: row.get(2)?,
                    reason: row.get(3)?,
                    model: row.get(4)?,
                    revision: row.get(5)?,
                })
            },
        )
        .optional()
}

/// `_write_choice`: upsert, keeping a revision tombstone when the last
/// override is reset so an older AI inference cannot overwrite it.
fn write_choice(
    connection: &Connection,
    identity: &(String, String, String, i64),
    choice: &Choice,
) -> rusqlite::Result<()> {
    connection.execute(
        "INSERT INTO message_retention (account_key, folder, uid_validity, uid, category, \
         expiration_days, category_source, category_reason, category_model, category_revision) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) \
         ON CONFLICT(account_key,folder,uid_validity,uid) DO UPDATE SET \
         category=excluded.category, expiration_days=excluded.expiration_days, \
         category_source=excluded.category_source, category_reason=excluded.category_reason, \
         category_model=excluded.category_model, category_revision=excluded.category_revision",
        params![
            identity.0,
            identity.1,
            identity.2,
            identity.3,
            choice.category,
            choice.expiration_days,
            choice.source,
            choice.reason,
            choice.model,
            choice.revision
        ],
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use serde_json::Value;
    use std::sync::{Arc, Barrier};

    const CREATED: &str = "2026-10-14T12:00:00+00:00";
    const OLD: Option<&str> = Some("2020-01-01T00:00:00+00:00");

    fn make_account() -> MailAccount {
        MailAccount::new(
            "user@example.com",
            "s3cret",
            "imap.example.com",
            993,
            "SSL/TLS",
            "smtp.example.com",
            587,
            "STARTTLS",
        )
    }

    fn headers(subject: &str, extra: &str) -> ParsedMessage {
        parsing::parse_message(
            format!("From: person@example.com\r\nSubject: {subject}\r\n{extra}\r\n").as_bytes(),
        )
    }

    fn message(sender: &str) -> ParsedMessage {
        parsing::parse_message(format!("From: {sender}\r\nSubject: Invoice\r\n\r\n").as_bytes())
    }

    fn plain(subject: &str, received: Option<&str>) -> RetentionMetadata {
        retention_metadata(
            &headers(subject, ""),
            received,
            None,
            &MetadataOptions::default(),
        )
        .unwrap()
    }

    fn with_account(base: &MailAccount, change: impl FnOnce(&mut MailAccount)) -> MailAccount {
        let mut account = base.clone();
        change(&mut account);
        account
    }

    // --- test_retention.py::ClassifierTests ----------------------------------

    #[test]
    fn specific_signals_and_conservative_fallback() {
        for (subject, expected) in [
            ("Your verification code", "verification"),
            ("Reset your password", "verification"),
            ("Invoice #123", "transactional"),
            ("Your order confirmation", "transactional"),
            ("Exclusive offer: 20% off", "marketing"),
            ("Weekly newsletter", "marketing"),
            ("Product update", "updates"),
            ("New comment on your post", "updates"),
            ("Can you review this code?", "uncategorized"),
            ("Please order the tasks", "uncategorized"),
            ("Hello", "uncategorized"),
        ] {
            let (category, reason) = classify_headers(&headers(subject, ""));
            assert_eq!(category, expected, "{subject}");
            assert!(!reason.is_empty());
        }
    }

    #[test]
    fn precedence_and_subscription_hints() {
        let subscription = "List-Unsubscribe: <https://example.com/unsubscribe>\r\n\
                            Precedence: bulk\r\nList-Id: updates.example.com\r\n";
        for (subject, extra, expected) in [
            (
                "Verification code and invoice sale",
                subscription,
                "verification",
            ),
            (
                "Order confirmation with discount",
                subscription,
                "transactional",
            ),
            ("Product update sale", subscription, "marketing"),
            ("Product update", subscription, "marketing"),
            ("Hello", subscription, "marketing"),
            ("Hello", "List-Id: developers.example.com\r\n", "updates"),
            (
                "Hello",
                "List-Unsubscribe: <https://example.com>\r\n",
                "uncategorized",
            ),
        ] {
            assert_eq!(
                classify_headers(&headers(subject, extra)).0,
                expected,
                "{subject}"
            );
        }
    }

    #[test]
    fn body_content_does_not_change_category() {
        let message = parsing::parse_message(
            b"Subject: Hello\r\n\r\nVerification code invoice discount newsletter",
        );
        assert_eq!(classify_headers(&message).0, "uncategorized");
    }

    // --- test_retention.py::RetentionMetadataTests ---------------------------

    #[test]
    fn defaults_and_never_sentinel() {
        for (category, subject) in [
            ("verification", "Verification code"),
            ("transactional", "Invoice"),
            ("marketing", "Newsletter"),
            ("updates", "Product update"),
            ("uncategorized", "Hello"),
        ] {
            let view = plain(subject, OLD);
            assert_eq!(view.category, category);
            let never = category == "uncategorized";
            assert_eq!(view.expiration_days, if never { -1 } else { 30 });
            assert_eq!(view.expired, !never);
            if never {
                assert_eq!(view.expires_at, ExpiresAt::Never);
                assert_eq!(serde_json::to_value(&view).unwrap()["expires_at"], -1);
            }
        }
    }

    #[test]
    fn receipt_time_timezone_boundary_and_manual_lifetime() {
        let now = Utc.with_ymd_and_hms(2026, 10, 1, 0, 0, 0).unwrap();
        let options = MetadataOptions {
            now: Some(now),
            ..Default::default()
        };
        let view = retention_metadata(
            &headers("Invoice", ""),
            Some("2026-09-01T02:00:00+02:00"),
            None,
            &options,
        )
        .unwrap();
        assert_eq!(
            view.received_at.as_deref(),
            Some("2026-09-01T00:00:00+00:00")
        );
        assert_eq!(
            view.expires_at,
            ExpiresAt::At("2026-10-01T00:00:00+00:00".into())
        );
        assert!(view.expired);
        let overrides = RetentionOverride {
            expiration_days: Some(0),
            ..Default::default()
        };
        let manual = retention_metadata(
            &headers("Hello", ""),
            Some("2026-09-01T00:00:00+00:00"),
            None,
            &MetadataOptions {
                overrides: Some(&overrides),
                ..options
            },
        )
        .unwrap();
        assert!(manual.expired);
        assert_eq!(manual.expiration_source, "manual");
        let overrides = RetentionOverride {
            expiration_days: Some(-19),
            ..Default::default()
        };
        let never = retention_metadata(
            &headers("Invoice", ""),
            None,
            None,
            &MetadataOptions {
                overrides: Some(&overrides),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(
            (never.expiration_days, never.expires_at, never.expired),
            (-1, ExpiresAt::Never, false)
        );
    }

    #[test]
    fn unavailable_or_extreme_received_date_fails_closed() {
        for date in [
            None,
            Some("bad"),
            Some("2020-01-01T00:00:00"),
            Some("9999-12-31T00:00:00+00:00"),
        ] {
            let view = retention_metadata(
                &headers("Invoice", "Date: Tue, 1 Jan 2000 00:00:00 +0000\r\n"),
                date,
                None,
                &MetadataOptions::default(),
            )
            .unwrap();
            assert_eq!(view.expires_at, ExpiresAt::Unknown, "{date:?}");
            assert!(!view.expired);
            assert_eq!(
                serde_json::to_value(&view).unwrap()["expires_at"],
                Value::Null
            );
        }
    }

    #[test]
    fn invalid_policies_are_validation_errors() {
        let mut policies = default_category_expiration_days();
        policies.insert("other".into(), 3);
        let error = retention_metadata(
            &headers("Hello", ""),
            None,
            Some(&policies),
            &MetadataOptions::default(),
        )
        .unwrap_err();
        assert_eq!(error.status(), 422);
    }

    #[test]
    fn fromisoformat_variants() {
        let parse = |v| parse_received_datetime(Some(v)).map(utc_isoformat);
        assert_eq!(
            parse("2026-10-14T12:00:00Z").as_deref(),
            Some("2026-10-14T12:00:00+00:00")
        );
        assert_eq!(
            parse("20261014T140000+0200").as_deref(),
            Some("2026-10-14T12:00:00+00:00")
        );
        assert_eq!(
            parse("2026-10-14 12:00:00.5-01:30").as_deref(),
            Some("2026-10-14T13:30:00.500000+00:00")
        );
        assert_eq!(
            parse("2026-10-14T12:00+00:00").as_deref(),
            Some("2026-10-14T12:00:00+00:00")
        );
        assert_eq!(
            parse("2026-10-14T12+00").as_deref(),
            Some("2026-10-14T12:00:00+00:00")
        );
        assert_eq!(parse("2026-10-14"), None);
        assert_eq!(parse("2026-10-14T12:00:00"), None);
        assert_eq!(parse("0001-01-01T00:00:00+01:00"), None);
        assert_eq!(parse("2026-13-01T00:00:00+00:00"), None);
    }

    // --- store fixture ---------------------------------------------------------

    struct Fixture {
        _dir: tempfile::TempDir,
        root: PathBuf,
        account: MailAccount,
        store: RetentionStore,
    }

    fn fixture() -> Fixture {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_path_buf();
        Fixture {
            store: RetentionStore::new(&root),
            _dir: dir,
            root,
            account: make_account(),
        }
    }

    impl Fixture {
        /// `_RetentionTestCase.metadata`: an "Invoice" message from 2020.
        fn meta(
            &self,
            store: &RetentionStore,
            account: &MailAccount,
            folder: &str,
            uid: i64,
            epoch: Option<&str>,
            policies: Option<&BTreeMap<String, i64>>,
        ) -> RetentionMetadata {
            store
                .metadata(
                    account,
                    folder,
                    uid,
                    epoch,
                    &headers("Invoice", ""),
                    OLD,
                    policies,
                )
                .unwrap()
        }

        fn default_meta(&self) -> RetentionMetadata {
            self.meta(&self.store, &self.account, "INBOX", 42, Some("99"), None)
        }

        fn update(&self, category: Patch<String>, days: Patch<i64>) {
            self.store
                .update(&self.account, "INBOX", 42, "99", category, days)
                .unwrap();
        }

        /// `SenderRuleStoreTests.save`.
        fn save(
            &self,
            category: &str,
            cutoff: i64,
            created: &str,
            options: SaveSenderRuleOptions<'_>,
        ) -> Result<SenderRule> {
            self.store.save_sender_rule(
                &self.account,
                "INBOX",
                "Person <PERSON@example.com>",
                category,
                "99",
                cutoff,
                SaveSenderRuleOptions {
                    created_at: Some(created),
                    ..options
                },
            )
        }

        /// `SenderRuleStoreTests.view`.
        #[allow(clippy::too_many_arguments)]
        fn view_with(
            &self,
            store: &RetentionStore,
            account: &MailAccount,
            folder: &str,
            uid: i64,
            epoch: Option<&str>,
            received: Option<&str>,
            sender: &str,
        ) -> RetentionMetadata {
            store
                .metadata(
                    account,
                    folder,
                    uid,
                    epoch,
                    &message(sender),
                    received,
                    None,
                )
                .unwrap()
        }

        fn view(&self, uid: i64, epoch: Option<&str>, received: Option<&str>) -> RetentionMetadata {
            let sender = "person@example.com";
            self.view_with(
                &self.store,
                &self.account,
                "INBOX",
                uid,
                epoch,
                received,
                sender,
            )
        }

        fn rule_view(&self, uid: i64) -> RetentionMetadata {
            self.view(uid, Some("99"), OLD)
        }
    }

    // --- test_retention.py::RetentionStoreTests -------------------------------

    #[test]
    fn reads_are_lazy() {
        let f = fixture();
        assert_eq!(f.default_meta().category_source, "automatic");
        assert!(!f.store.path().exists());
        assert_eq!(
            f.store.path(),
            f.root.join("mail").join("retention.sqlite3")
        );
    }

    #[test]
    fn overrides_survive_restart_and_reset_independently() {
        let f = fixture();
        f.update(Patch::Set("updates".into()), Patch::Set(-7));
        let restarted = RetentionStore::new(&f.root);
        let meta =
            |store: &RetentionStore| f.meta(store, &f.account, "INBOX", 42, Some("99"), None);
        let view = meta(&restarted);
        assert_eq!(
            (
                view.category.as_str(),
                view.category_source.as_str(),
                view.expiration_days
            ),
            ("updates", "manual", -1)
        );
        restarted
            .update(&f.account, "INBOX", 42, "99", Patch::Clear, Patch::Unset)
            .unwrap();
        let view = meta(&restarted);
        assert_eq!(
            (
                view.category.as_str(),
                view.category_source.as_str(),
                view.expiration_source.as_str()
            ),
            ("transactional", "automatic", "manual")
        );
        restarted
            .update(&f.account, "INBOX", 42, "99", Patch::Unset, Patch::Clear)
            .unwrap();
        assert_eq!(meta(&restarted).expiration_source, "category");
        assert_eq!(
            restarted.get(&f.account, "INBOX", 42, Some("99")).unwrap(),
            None
        );
        // The tombstone row keeps the category revision.
        assert_eq!(
            restarted
                .get_category_revision(&f.account, "INBOX", 42, "99")
                .unwrap(),
            2
        );
    }

    #[test]
    fn category_changes_recompute_policy_without_losing_lifetime_override() {
        let f = fixture();
        f.update(Patch::Set("uncategorized".into()), Patch::Unset);
        assert_eq!(f.default_meta().expires_at, ExpiresAt::Never);
        let mut policies = default_category_expiration_days();
        policies.insert("uncategorized".into(), 2);
        let with_policies = || {
            f.meta(
                &f.store,
                &f.account,
                "INBOX",
                42,
                Some("99"),
                Some(&policies),
            )
        };
        assert_eq!(with_policies().expiration_days, 2);
        f.update(Patch::Unset, Patch::Set(80));
        f.update(Patch::Set("verification".into()), Patch::Unset);
        assert_eq!(with_policies().expiration_days, 80);
    }

    #[test]
    fn account_connection_folder_uid_and_epoch_isolation() {
        let f = fixture();
        f.update(Patch::Set("updates".into()), Patch::Unset);
        let accounts = [
            with_account(&f.account, |a| a.email = "other@example.com".into()),
            with_account(&f.account, |a| {
                a.incoming_server = "other.example.com".into()
            }),
            with_account(&f.account, |a| a.incoming_port = 143),
            with_account(&f.account, |a| a.incoming_protocol = "STARTTLS".into()),
        ];
        for account in &accounts {
            let view = f.meta(&f.store, account, "INBOX", 42, Some("99"), None);
            assert_eq!(view.category_source, "automatic");
        }
        for (folder, uid, epoch) in [
            ("Archive", 42, Some("99")),
            ("INBOX", 43, Some("99")),
            ("INBOX", 42, Some("100")),
            ("INBOX", 42, None),
        ] {
            let view = f.meta(&f.store, &f.account, folder, uid, epoch, None);
            assert_eq!(view.category_source, "automatic");
        }
        let view = f.meta(&f.store, &f.account, "inbox", 42, Some("99"), None);
        assert_eq!(view.category_source, "manual");
        // A trailing dot or upper case in the server name keeps the identity.
        let dotted = with_account(&f.account, |a| {
            a.incoming_server = "IMAP.example.com.".into()
        });
        let view = f.meta(&f.store, &dotted, "INBOX", 42, Some("99"), None);
        assert_eq!(view.category_source, "manual");
    }

    #[test]
    fn concurrent_independent_edits_preserve_both_values() {
        let f = fixture();
        f.update(Patch::Set("updates".into()), Patch::Unset);
        let barrier = Arc::new(Barrier::new(2));
        let edits = [
            (Patch::Set("marketing".to_string()), Patch::Unset),
            (Patch::Unset, Patch::Set(90)),
        ];
        let handles: Vec<_> = edits
            .into_iter()
            .map(|(category, days)| {
                let barrier = barrier.clone();
                let root = f.root.clone();
                let account = f.account.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    RetentionStore::new(&root)
                        .update(&account, "INBOX", 42, "99", category, days)
                        .unwrap();
                })
            })
            .collect();
        for handle in handles {
            handle.join().unwrap();
        }
        assert_eq!(
            f.store.get(&f.account, "INBOX", 42, Some("99")).unwrap(),
            Some(RetentionOverride {
                uid: 42,
                category: Some("marketing".into()),
                expiration_days: Some(90),
                category_source: Some("manual".into()),
                category_reason: None,
                category_model: None,
            })
        );
    }

    #[test]
    fn invalid_identity_and_arguments() {
        let f = fixture();
        let update = |uid, epoch, category, days| {
            f.store
                .update(&f.account, "INBOX", uid, epoch, category, days)
                .unwrap_err()
        };
        let conflict = update(0, "99", Patch::Set("updates".into()), Patch::Unset);
        assert_eq!(conflict.status(), 409);
        assert_eq!(
            conflict.to_string(),
            "Message identity is unavailable. Refresh the folder before editing retention."
        );
        assert_eq!(update(42, "abc", Patch::Clear, Patch::Unset).status(), 409);
        let invalid = update(42, "99", Patch::Set("custom".into()), Patch::Unset);
        assert_eq!(invalid.status(), 422);
        assert_eq!(invalid.to_string(), "Choose a valid email category");
        let nothing = update(42, "99", Patch::Unset, Patch::Unset);
        assert_eq!(
            nothing.to_string(),
            "Choose a category or expiration to update"
        );
        assert_eq!(
            update(42, "99", Patch::Unset, Patch::Set(365_001)).status(),
            422
        );
        assert!(!f.store.path().exists());
        f.update(Patch::Set("updates".into()), Patch::Unset);
        let error = f
            .store
            .get_many(&f.account, "INBOX", &[42, 0], Some("99"))
            .unwrap_err();
        assert_eq!(error.status(), 409);
        assert!(f
            .store
            .get_many(&f.account, "INBOX", &[42], None)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn get_many_reads_in_batches() {
        let f = fixture();
        for uid in [1, 250, 451] {
            f.store
                .update(
                    &f.account,
                    "INBOX",
                    uid,
                    "99",
                    Patch::Unset,
                    Patch::Set(uid),
                )
                .unwrap();
        }
        let uids: Vec<i64> = (1..=451).collect();
        let found = f
            .store
            .get_many(&f.account, "INBOX", &uids, Some("99"))
            .unwrap();
        let mut keys: Vec<_> = found.keys().copied().collect();
        keys.sort();
        assert_eq!(keys, [1, 250, 451]);
        assert_eq!(found[&250].expiration_days, Some(250));
    }

    #[test]
    fn save_ai_conflicts_and_validation() {
        let f = fixture();
        let model = "llama3.2:latest";
        f.store
            .save_ai(
                &f.account,
                "INBOX",
                42,
                "99",
                "updates",
                " An update ",
                model,
                0,
            )
            .unwrap();
        let saved = f
            .store
            .get(&f.account, "INBOX", 42, Some("99"))
            .unwrap()
            .unwrap();
        assert_eq!(saved.category_reason.as_deref(), Some("An update"));
        assert_eq!(saved.category_source.as_deref(), Some("ai"));
        let view = f.default_meta();
        assert_eq!(view.category_source, "ai");
        assert_eq!(view.category_model.as_deref(), Some(model));
        assert_eq!(view.category_reason, "An update");
        let stale = f
            .store
            .save_ai(&f.account, "INBOX", 42, "99", "marketing", "x", model, 0);
        assert_eq!(stale.unwrap_err().status(), 409);
        for (category, reason, model, revision, message) in [
            ("custom", "r", "m", 1, "Choose a valid email category"),
            (
                "updates",
                "  ",
                "m",
                1,
                "A short classification reason is required",
            ),
            (
                "updates",
                "r",
                "gpt-oss:20b-cloud",
                1,
                "Choose a locally installed model, not a cloud model",
            ),
            (
                "updates",
                "r",
                "bad model",
                1,
                "Local AI model must be a model name of at most 200 characters",
            ),
            (
                "updates",
                "r",
                "http://x",
                1,
                "Local AI model must be a model identifier",
            ),
            (
                "updates",
                "r",
                "a/../b",
                1,
                "Local AI model must be a model identifier",
            ),
            (
                "updates",
                "r",
                "m",
                -1,
                "A valid category revision is required",
            ),
        ] {
            let error = f
                .store
                .save_ai(
                    &f.account, "INBOX", 42, "99", category, reason, model, revision,
                )
                .unwrap_err();
            assert_eq!(error.to_string(), message);
            assert_eq!(error.status(), 422);
        }
    }

    #[test]
    fn legacy_database_is_migrated() {
        let f = fixture();
        std::fs::create_dir_all(f.root.join("mail")).unwrap();
        let connection = Connection::open(f.store.path()).unwrap();
        let (key, folder) = mailbox_identity(&f.account, "INBOX");
        connection
            .execute_batch(&format!(
                "CREATE TABLE message_retention (account_key TEXT NOT NULL, folder TEXT NOT NULL,
                    uid_validity TEXT NOT NULL, uid INTEGER NOT NULL, category TEXT,
                    expiration_days INTEGER, PRIMARY KEY (account_key, folder, uid_validity, uid));
                 INSERT INTO message_retention VALUES ('{key}', '{folder}', '99', 42, 'updates', 5);
                 CREATE TABLE sender_category_rules (account_key TEXT NOT NULL,
                    folder TEXT NOT NULL, sender TEXT NOT NULL, category TEXT NOT NULL,
                    uid_validity TEXT NOT NULL, first_uid INTEGER NOT NULL,
                    created_at TEXT NOT NULL, revision INTEGER NOT NULL DEFAULT 1,
                    PRIMARY KEY (account_key, folder, sender));
                 INSERT INTO sender_category_rules VALUES ('{key}', '{folder}',
                    'person@example.com', 'marketing', '99', 10, '{CREATED}', 1);"
            ))
            .unwrap();
        drop(connection);
        let view = f.default_meta();
        assert_eq!(
            (
                view.category.as_str(),
                view.category_source.as_str(),
                view.expiration_days
            ),
            ("updates", "manual", 5)
        );
        let events = f
            .store
            .get_sender_rule_events(&f.account, "INBOX", "person@example.com")
            .unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].category.as_deref(), Some("marketing"));
        assert_eq!(
            f.store
                .get_category_revision(&f.account, "INBOX", 42, "99")
                .unwrap(),
            0
        );
    }

    #[test]
    fn mailbox_identity_matches_python_json_sha256() {
        // hashlib.sha256(json.dumps(["user@example.com", "imap.example.com", 993, "ssl"],
        //     separators=(",", ":")).encode()).hexdigest()
        let json = br#"["user@example.com","imap.example.com",993,"ssl"]"#;
        let expected = hex::encode(Sha256::digest(json));
        assert_eq!(
            mailbox_identity(&make_account(), "inbox"),
            (expected, "INBOX".to_string())
        );
        assert_eq!(
            python_json_string("B\u{fc}cher \u{1F600}\n\""),
            // Python output, written with an explicit backslash so the
            // escapes stay literal.
            ["\"B", "u00fccher ", "ud83d", "ude00", "n", "\"\""].join("\\")
        );
    }

    // --- test_sender_rules.py::SenderAddressTests -----------------------------

    #[test]
    fn single_actual_author_normalizes_case_spacing_and_idna() {
        for (sender, expected) in [
            (" Person <PERSON@EXAMPLE.COM> ", "person@example.com"),
            (
                "Person <person@b\u{fc}cher.example>",
                "person@xn--bcher-kva.example",
            ),
            (
                "\"support@bank.example\" <forged@evil.example>",
                "forged@evil.example",
            ),
        ] {
            assert_eq!(
                sender_address(&message(sender)).as_deref(),
                Some(expected),
                "{sender}"
            );
        }
    }

    #[test]
    fn ambiguous_missing_malformed_and_other_headers_cannot_match() {
        for raw in [
            "Subject: Invoice\r\nReply-To: person@example.com\r\n\
             Return-Path: <person@example.com>\r\n\r\n",
            "From: person@example.com\r\nFrom: second@example.com\r\n\r\n",
            "From: person@example.com, second@example.com\r\n\r\n",
            "From: nobody\r\n\r\n",
            "From: person@@example.com\r\n\r\n",
            "From: Group: person@example.com;\r\n\r\n",
            "From: Person <person@example.com\r\n\r\n",
        ] {
            assert_eq!(
                sender_address(&parsing::parse_message(raw.as_bytes())),
                None,
                "{raw}"
            );
        }
    }

    /// Vectors produced by running the original Python functions over the
    /// same inputs (`tests/fixtures/retention_expected.json`).
    #[test]
    fn parity_with_python_vectors() {
        let path = format!(
            "{}/tests/fixtures/retention_expected.json",
            env!("CARGO_MANIFEST_DIR")
        );
        let expected: Value =
            serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        let mut failures = Vec::new();
        for row in expected["normalize"].as_array().unwrap() {
            let input = row[0].as_str().unwrap();
            let got = match normalize_sender_address(input) {
                Ok(address) => (Value::from(address), Value::Null),
                Err(error) => (Value::Null, Value::from(error.to_string())),
            };
            if got != (row[1].clone(), row[2].clone()) {
                failures.push(format!("normalize {input:?}: got {got:?}, want {row}"));
            }
        }
        for row in expected["senders"].as_array().unwrap() {
            // The raw bytes were stored as Latin-1 text.
            let raw: Vec<u8> = row[0].as_str().unwrap().chars().map(|c| c as u8).collect();
            let got = sender_address(&parsing::parse_message(&raw));
            if Value::from(got.clone()) != row[1] {
                failures.push(format!("sender {}: got {got:?}, want {}", row[0], row[1]));
            }
        }
        for row in expected["classify"].as_array().unwrap() {
            let (subject, extra) = (row[0].as_str().unwrap(), row[1].as_str().unwrap());
            let raw = format!("Subject: {subject}\r\n{extra}\r\n");
            let got = classify_headers(&parsing::parse_message(raw.as_bytes())).0;
            if got != row[2].as_str().unwrap() {
                failures.push(format!(
                    "classify {subject:?}/{extra:?}: got {got}, want {}",
                    row[2]
                ));
            }
        }
        for row in expected["uid_validity"].as_array().unwrap() {
            let got = normalize_uid_validity(row[0].as_str().unwrap());
            if Value::from(got.clone()) != row[1] {
                failures.push(format!(
                    "uid_validity {}: got {got:?}, want {}",
                    row[0], row[1]
                ));
            }
        }
        assert!(
            failures.is_empty(),
            "{} mismatches:\n{}",
            failures.len(),
            failures.join("\n")
        );
    }

    // --- test_sender_rules.py::SenderRuleStoreTests ---------------------------

    #[test]
    fn rule_reads_lazy_and_rule_persists_without_changing_old_mail() {
        let f = fixture();
        assert!(f
            .store
            .list_sender_rules(&f.account, None)
            .unwrap()
            .is_empty());
        assert!(!f.store.path().exists());
        let rule = f
            .save("marketing", 100, CREATED, Default::default())
            .unwrap();
        assert_eq!(
            (rule.sender.as_str(), rule.revision),
            ("person@example.com", 1)
        );
        let restarted = RetentionStore::new(&f.root);
        let found = restarted
            .get_sender_rule(&f.account, "inbox", "person@example.com")
            .unwrap();
        assert_eq!(found, Some(rule.clone()));
        let sender = "person@example.com";
        let old = f.view_with(&restarted, &f.account, "INBOX", 99, Some("99"), OLD, sender);
        assert_eq!(
            (old.category.as_str(), old.category_source.as_str()),
            ("transactional", "automatic")
        );
        assert_eq!(old.sender_rule, Some(rule));
        let future = f.view_with(
            &restarted,
            &f.account,
            "INBOX",
            100,
            Some("99"),
            OLD,
            sender,
        );
        assert_eq!(
            (
                future.category.as_str(),
                future.category_source.as_str(),
                future.expiration_days
            ),
            ("marketing", "sender_rule", 30)
        );
        assert_eq!(
            future.category_reason,
            "Saved sender rule for person@example.com assigned this category"
        );
    }

    #[test]
    fn exact_address_folder_account_and_server_isolation() {
        let f = fixture();
        f.save("marketing", 100, CREATED, Default::default())
            .unwrap();
        for sender in [
            "other@example.com",
            "person@sub.example.com",
            "person@example.com.evil",
            "\"person@example.com\" <other@example.com>",
        ] {
            let view = f.view_with(&f.store, &f.account, "INBOX", 100, Some("99"), OLD, sender);
            assert_eq!(view.category_source, "automatic", "{sender}");
        }
        for account in [
            with_account(&f.account, |a| a.email = "second@example.com".into()),
            with_account(&f.account, |a| {
                a.incoming_server = "different.example.com".into()
            }),
            with_account(&f.account, |a| a.incoming_port = 143),
            with_account(&f.account, |a| a.incoming_protocol = "STARTTLS".into()),
        ] {
            let sender = "person@example.com";
            let view = f.view_with(&f.store, &account, "INBOX", 100, Some("99"), OLD, sender);
            assert_eq!(view.category_source, "automatic");
        }
        let sender = "person@example.com";
        let archive = f.view_with(
            &f.store,
            &f.account,
            "Archive",
            100,
            Some("99"),
            OLD,
            sender,
        );
        assert_eq!(archive.category_source, "automatic");
        let inbox = f.view_with(&f.store, &f.account, "inbox", 100, Some("99"), OLD, sender);
        assert_eq!(inbox.category_source, "sender_rule");
    }

    #[test]
    fn uid_epoch_reset_uses_received_time_and_missing_metadata_fails_closed() {
        let f = fixture();
        f.save("marketing", 100, CREATED, Default::default())
            .unwrap();
        for received in [CREATED, "2026-10-14T13:00:00+00:00"] {
            assert_eq!(
                f.view(1, Some("100"), Some(received)).category_source,
                "sender_rule"
            );
        }
        for received in [
            Some("2026-10-14T11:59:59+00:00"),
            None,
            Some("bad"),
            Some("2026-10-15T12:00:00"),
        ] {
            assert_eq!(
                f.view(200, Some("100"), received).category_source,
                "automatic"
            );
        }
        assert_eq!(
            f.view(200, None, Some(CREATED)).category_source,
            "automatic"
        );
        // A new UID in the same mailbox is future mail even with an old INTERNALDATE.
        let imported = f.view(100, Some("99"), Some("2000-01-01T00:00:00+00:00"));
        assert_eq!(imported.category_source, "sender_rule");
    }

    #[test]
    fn manual_and_ai_override_rule_without_losing_individual_expiration() {
        let f = fixture();
        f.save("marketing", 100, CREATED, Default::default())
            .unwrap();
        f.store
            .update(
                &f.account,
                "INBOX",
                100,
                "99",
                Patch::Set("verification".into()),
                Patch::Set(-1),
            )
            .unwrap();
        let view = f.rule_view(100);
        assert_eq!(
            (
                view.category.as_str(),
                view.category_source.as_str(),
                &view.expires_at
            ),
            ("verification", "manual", &ExpiresAt::Never)
        );
        f.store
            .save_ai(
                &f.account,
                "INBOX",
                100,
                "99",
                "updates",
                "An update",
                "llama3.2:latest",
                1,
            )
            .unwrap();
        let view = f.rule_view(100);
        assert_eq!(
            (
                view.category.as_str(),
                view.category_source.as_str(),
                view.expiration_days
            ),
            ("updates", "ai", -1)
        );
        f.store
            .update(&f.account, "INBOX", 100, "99", Patch::Clear, Patch::Unset)
            .unwrap();
        let view = f.rule_view(100);
        assert_eq!(
            (
                view.category.as_str(),
                view.category_source.as_str(),
                view.expiration_days
            ),
            ("marketing", "sender_rule", -1)
        );
    }

    #[test]
    fn rule_edits_removals_and_recreation_preserve_prior_arrival_categories() {
        let f = fixture();
        let first = f
            .save("marketing", 100, CREATED, Default::default())
            .unwrap();
        let options = SaveSenderRuleOptions {
            expected_sender_rule_revision: Some(first.revision),
            ..Default::default()
        };
        let second = f
            .save("updates", 200, "2026-10-14T13:00:00+00:00", options)
            .unwrap();
        assert_eq!(f.rule_view(150).category, "marketing");
        assert_eq!(f.rule_view(200).category, "updates");
        let removed = f
            .store
            .delete_sender_rule(
                &f.account,
                "INBOX",
                "person@example.com",
                "99",
                300,
                Some("2026-10-14T14:00:00+00:00"),
                Some(second.revision),
            )
            .unwrap();
        assert!(removed);
        let rule = f
            .store
            .get_sender_rule(&f.account, "INBOX", "person@example.com")
            .unwrap();
        assert_eq!(rule, None);
        assert_eq!(f.rule_view(150).category, "marketing");
        assert_eq!(f.rule_view(250).category, "updates");
        assert_eq!(f.rule_view(250).sender_rule, None);
        assert_eq!(f.rule_view(300).category_source, "automatic");
        let revision = f
            .store
            .get_sender_rule_revision(&f.account, "INBOX", "person@example.com")
            .unwrap();
        assert_eq!(revision, 3);
        let options = SaveSenderRuleOptions {
            expected_sender_rule_revision: Some(3),
            ..Default::default()
        };
        f.save("verification", 400, CREATED, options).unwrap();
        assert_eq!(f.rule_view(350).category_source, "automatic");
        assert_eq!(f.rule_view(400).category, "verification");
        let restarted = RetentionStore::new(&f.root);
        let sender = "person@example.com";
        let at = |uid| {
            f.view_with(
                &restarted,
                &f.account,
                "INBOX",
                uid,
                Some("99"),
                OLD,
                sender,
            )
        };
        assert_eq!(at(150).category, "marketing");
        assert_eq!(at(350).category_source, "automatic");
        // The folder-wide helpers see the same history.
        let events = f
            .store
            .get_sender_rule_events_for_folder(&f.account, "inbox")
            .unwrap();
        let revisions: Vec<i64> = events[sender].iter().map(|e| e.revision).collect();
        assert_eq!(revisions, [1, 2, 3, 4]);
        assert_eq!(events[sender][2].category, None);
        let rules = f
            .store
            .get_sender_rules_for_folder(&f.account, "INBOX")
            .unwrap();
        assert_eq!(rules[sender].category.as_deref(), Some("verification"));
    }

    #[test]
    fn atomic_category_and_rule_revision_conflicts_leave_rules_untouched() {
        let f = fixture();
        f.update(Patch::Set("marketing".into()), Patch::Unset);
        for options in [
            SaveSenderRuleOptions {
                message_uid: Some(42),
                expected_category_revision: Some(0),
                ..Default::default()
            },
            SaveSenderRuleOptions {
                expected_sender_rule_revision: Some(1),
                ..Default::default()
            },
        ] {
            assert_eq!(
                f.save("marketing", 100, CREATED, options)
                    .unwrap_err()
                    .status(),
                409
            );
        }
        assert!(f
            .store
            .list_sender_rules(&f.account, None)
            .unwrap()
            .is_empty());
        let options = SaveSenderRuleOptions {
            message_uid: Some(42),
            expected_category_revision: Some(1),
            expected_sender_rule_revision: Some(0),
            ..Default::default()
        };
        let rule = f.save("marketing", 100, CREATED, options).unwrap();
        let error = f
            .store
            .delete_sender_rule(
                &f.account,
                "INBOX",
                "person@example.com",
                "99",
                200,
                None,
                Some(0),
            )
            .unwrap_err();
        assert_eq!(error.status(), 409);
        let found = f
            .store
            .get_sender_rule(&f.account, "INBOX", "person@example.com")
            .unwrap();
        assert_eq!(found, Some(rule));
    }

    #[test]
    fn policies_and_uncategorized_never_expiration_use_rule_category() {
        let f = fixture();
        f.save("uncategorized", 100, CREATED, Default::default())
            .unwrap();
        let view = f.rule_view(100);
        assert_eq!(
            (view.category.as_str(), &view.expires_at, view.expired),
            ("uncategorized", &ExpiresAt::Never, false)
        );
        f.save("marketing", 200, CREATED, Default::default())
            .unwrap();
        let mut policies = default_category_expiration_days();
        policies.insert("marketing".into(), 7);
        let headers = message("Person <person@example.com>");
        let view = f
            .store
            .metadata(
                &f.account,
                "INBOX",
                200,
                Some("99"),
                &headers,
                Some(CREATED),
                Some(&policies),
            )
            .unwrap();
        assert_eq!(view.expiration_days, 7);
    }

    #[test]
    fn sender_rule_argument_validation() {
        let f = fixture();
        let save = |category: &str,
                    epoch: &str,
                    cutoff: i64,
                    created: Option<&str>,
                    options: SaveSenderRuleOptions<'_>| {
            let options = SaveSenderRuleOptions {
                created_at: created,
                ..options
            };
            let sender = "person@example.com";
            f.store.save_sender_rule(
                &f.account, "INBOX", sender, category, epoch, cutoff, options,
            )
        };
        let none = SaveSenderRuleOptions::default;
        assert_eq!(
            save("marketing", "0", 1, None, none())
                .unwrap_err()
                .status(),
            409
        );
        assert_eq!(
            save("marketing", "99", 0, None, none())
                .unwrap_err()
                .status(),
            409
        );
        let error = save("custom", "99", 1, None, none()).unwrap_err();
        assert_eq!(error.to_string(), "Choose a valid email category");
        let error = save("marketing", "99", 1, Some("2026-01-01T00:00:00"), none()).unwrap_err();
        assert_eq!(
            error.to_string(),
            "A valid sender rule creation time is required"
        );
        let missing_uid = SaveSenderRuleOptions {
            expected_category_revision: Some(0),
            ..Default::default()
        };
        assert_eq!(
            save("marketing", "99", 1, None, missing_uid)
                .unwrap_err()
                .status(),
            409
        );
        let negative = SaveSenderRuleOptions {
            message_uid: Some(1),
            expected_category_revision: Some(-1),
            ..Default::default()
        };
        let error = save("marketing", "99", 1, None, negative).unwrap_err();
        assert_eq!(error.to_string(), "A valid category revision is required");
        let negative = SaveSenderRuleOptions {
            expected_sender_rule_revision: Some(-1),
            ..Default::default()
        };
        let error = save("marketing", "99", 1, None, negative).unwrap_err();
        assert_eq!(
            error.to_string(),
            "A valid sender rule revision is required"
        );
        let error = f
            .store
            .save_sender_rule(&f.account, "INBOX", "nobody", "marketing", "99", 1, none())
            .unwrap_err();
        assert_eq!(error.status(), 422);
        let sender = "person@example.com";
        let removed = f
            .store
            .delete_sender_rule(&f.account, "INBOX", sender, "99", 1, None, None);
        assert!(!removed.unwrap());
        assert!(!f.store.path().exists());
        let created = save("marketing", "99", 1, None, none()).unwrap().created_at;
        assert!(created.ends_with("+00:00"));
    }
}
