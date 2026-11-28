//! Shared RFC 822 parsing helpers for message viewing and auditing
//! (port of `backend/app/mail/parsing.py`).
//!
//! The Python code parsed messages with `email.parser.BytesParser(policy=
//! policy.default)` and then relied on many behaviours of the standard
//! `email` package: header decoding, the `walk()` order of MIME parts,
//! `get_filename()` with RFC 2231/2047 decoding, `get_payload(decode=True)`,
//! charset fallbacks, `email.utils.getaddresses`/`parseaddr` (strict mode)
//! and `parsedate_to_datetime`. To keep the JSON produced by the backend
//! identical, this module reproduces those behaviours instead of exposing a
//! different MIME interpretation:
//!
//! * [`ParsedMessage::parse`] ports `email.feedparser` (header/body split,
//!   multipart boundaries with the RFC 2046 newline rules, nested `message/*`
//!   parts, `multipart/digest` defaults, `message/delivery-status` blocks).
//! * [`Part::get`] returns what `msg.get(name)` returned under
//!   `policy.default`: unfolded, RFC 2047-decoded text; address headers are
//!   re-serialised like `headerregistry.AddressHeader`.
//! * Transfer decoding ports `binascii.a2b_base64`, `email._encoded_words.
//!   decode_b` and `binascii.a2b_qp`; charsets are decoded with the
//!   `mail-parser` crate's decoder tables, with Python's strict semantics for
//!   UTF-8, ASCII and Latin-1.
//!
//! The public functions keep the Python names: [`decode_value`],
//! [`parse_date`], [`addresses`], [`address_text`], [`first_address`],
//! [`unsubscribe_link`], [`extract_bodies`], [`list_attachments`],
//! [`attachment_payload`], [`snippet`], [`extract_links`], [`parse_message`]
//! and [`header_view`].

use std::collections::HashMap;
use std::sync::LazyLock;

use chrono::{Datelike, NaiveDate, NaiveDateTime, Timelike};
use regex::Regex;
use serde::Serialize;
use serde_json::{Map, Value};

// ---------------------------------------------------------------------------
// Regular expressions (exact ports of the module-level patterns)
// ---------------------------------------------------------------------------

/// `_URL_PATTERN = re.compile(r"https?://[^\s\"'<>\[\]{}()]+", re.IGNORECASE)`
static URL_PATTERN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?i)https?://[^\s"'<>\[\]{}()]+"#).unwrap());

/// `_HTML_LINK_PATTERN` (IGNORECASE | DOTALL).
static HTML_LINK_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?is)<a\b[^>]*?href\s*=\s*["']?([^"'>\s]+)["']?[^>]*>(.*?)</a>"#).unwrap()
});

/// `_TAG_PATTERN = re.compile(r"<[^>]+>")`
static TAG_PATTERN: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"<[^>]+>").unwrap());

/// `_UNSUB_URL = re.compile(r"<([^>]+)>")`
static UNSUB_URL: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"<([^>]+)>").unwrap());

/// `email.header.ecre`: one RFC 2047 encoded word (no DOTALL).
static ECRE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"=\?([^?]*?)\?([qQbB])\?(.*?)\?=").unwrap());

/// `email._header_value_parser.rfc2047_matcher`.
static RFC2047_MATCHER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"=\?[^?]*\?[qQbB]\?.*?\?=").unwrap());

/// `email.utils.rfc2231_continuation` (re.ASCII).
static RFC2231_CONTINUATION: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^(?-u:(\w+))\*(?:([0-9]+)\*?)?$").unwrap());

// ---------------------------------------------------------------------------
// Python string helpers
// ---------------------------------------------------------------------------

/// `str.isspace()` for one character. Rust's `char::is_whitespace` lacks the
/// ASCII information separators U+001C..U+001F that Python treats as space.
pub(crate) fn is_py_space(c: char) -> bool {
    c.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&c)
}

/// `str.split()` without arguments.
pub(crate) fn py_split(value: &str) -> impl Iterator<Item = &str> {
    value.split(is_py_space).filter(|piece| !piece.is_empty())
}

/// `str.strip()` without arguments.
pub(crate) fn py_strip(value: &str) -> &str {
    value.trim_matches(is_py_space)
}

/// `" ".join(value.split())`.
pub(crate) fn collapse_whitespace(value: &str) -> String {
    py_split(value).collect::<Vec<_>>().join(" ")
}

/// `value[:limit]` on a Python `str` (code points, not bytes).
pub(crate) fn truncate_chars(value: &str, limit: usize) -> String {
    value.chars().take(limit).collect()
}

/// `str.splitlines()` (without keepends).
fn py_splitlines(value: &str) -> Vec<&str> {
    let mut lines = Vec::new();
    let mut start = 0;
    let mut chars = value.char_indices().peekable();
    while let Some((index, c)) = chars.next() {
        let is_break = matches!(
            c,
            '\n' | '\r'
                | '\u{0b}'
                | '\u{0c}'
                | '\u{1c}'
                | '\u{1d}'
                | '\u{1e}'
                | '\u{85}'
                | '\u{2028}'
                | '\u{2029}'
        );
        if is_break {
            lines.push(&value[start..index]);
            let mut end = index + c.len_utf8();
            if c == '\r' {
                if let Some(&(next_index, '\n')) = chars.peek() {
                    chars.next();
                    end = next_index + 1;
                }
            }
            start = end;
        }
    }
    if start < value.len() {
        lines.push(&value[start..]);
    }
    lines
}

/// Python `int(text)` for ASCII input: surrounding whitespace, an optional
/// sign and single underscores between digits are accepted.
pub(crate) fn py_int(text: &str) -> Option<i64> {
    let text = py_strip(text);
    let (negative, digits) = match text.as_bytes().first() {
        Some(b'-') => (true, &text[1..]),
        Some(b'+') => (false, &text[1..]),
        _ => (false, text),
    };
    if digits.is_empty()
        || digits.starts_with('_')
        || digits.ends_with('_')
        || digits.contains("__")
        || !digits.bytes().all(|b| b.is_ascii_digit() || b == b'_')
    {
        return None;
    }
    let cleaned: String = digits.chars().filter(|c| *c != '_').collect();
    let value: i64 = cleaned.parse().ok()?;
    Some(if negative { -value } else { value })
}

/// `bytes(text, "raw-unicode-escape")`.
fn raw_unicode_escape(text: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(text.len());
    for c in text.chars() {
        let code = c as u32;
        if code <= 0xff {
            out.push(code as u8);
        } else if code <= 0xffff {
            out.extend(format!("\\u{code:04x}").bytes());
        } else {
            out.extend(format!("\\U{code:08x}").bytes());
        }
    }
    out
}

/// Interpret bytes as Latin-1 (each byte one code point), the inverse of
/// [`raw_unicode_escape`] for code points below 256.
fn latin1(bytes: &[u8]) -> String {
    bytes.iter().map(|b| char::from(*b)).collect()
}

// ---------------------------------------------------------------------------
// Charsets
// ---------------------------------------------------------------------------

/// Failure of a strict `bytes.decode(charset)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CharsetError {
    /// `LookupError`: Python has no codec of that name.
    Unknown,
    /// `UnicodeDecodeError`.
    Invalid,
}

#[derive(Debug, Clone, Copy)]
enum Codec {
    Utf8,
    Ascii,
    Latin1,
    Table(mail_parser::decoders::charsets::DecoderFnc),
}

/// `encodings.normalize_encoding` + the aliases Python resolves for the
/// codecs it implements natively here.
fn lookup_codec(charset: &str) -> Option<Codec> {
    let mut normalized = String::with_capacity(charset.len());
    let mut punctuation = false;
    for c in py_strip(charset).chars() {
        if c.is_ascii_alphanumeric() || c == '.' {
            if punctuation && !normalized.is_empty() {
                normalized.push('_');
            }
            normalized.push(c.to_ascii_lowercase());
            punctuation = false;
        } else {
            punctuation = true;
        }
    }
    let codec = match normalized.as_str() {
        "utf_8" | "utf8" | "u8" | "utf" | "utf8_ucs2" | "utf8_ucs4" | "cp65001" => Codec::Utf8,
        "ascii" | "us_ascii" | "646" | "ansi_x3.4_1968" | "ansi_x3_4_1968" | "ansi_x3.4_1986"
        | "cp367" | "csascii" | "ibm367" | "iso646_us" | "iso_646.irv_1991" | "iso_ir_6" | "us" => {
            Codec::Ascii
        }
        "latin_1" | "latin1" | "latin" | "l1" | "iso_8859_1" | "iso8859_1" | "8859" | "cp819"
        | "iso_ir_100" | "ibm819" | "csisolatin1" | "iso_8859_1_1987" => Codec::Latin1,
        "" => return None,
        _ => Codec::Table(mail_parser::decoders::charsets::map::charset_decoder(
            normalized.as_bytes(),
        )?),
    };
    Some(codec)
}

/// `bytes.decode(charset, "replace")`; `None` means `LookupError`.
pub(crate) fn decode_charset_lossy(bytes: &[u8], charset: &str) -> Option<String> {
    Some(match lookup_codec(charset)? {
        Codec::Utf8 => String::from_utf8_lossy(bytes).into_owned(),
        Codec::Ascii => bytes
            .iter()
            .map(|b| {
                if b.is_ascii() {
                    char::from(*b)
                } else {
                    '\u{fffd}'
                }
            })
            .collect(),
        Codec::Latin1 => latin1(bytes),
        Codec::Table(decoder) => decoder(bytes),
    })
}

/// `bytes.decode(charset)` (errors="strict").
fn decode_charset_strict(bytes: &[u8], charset: &str) -> Result<String, CharsetError> {
    match lookup_codec(charset).ok_or(CharsetError::Unknown)? {
        Codec::Utf8 => String::from_utf8(bytes.to_vec()).map_err(|_| CharsetError::Invalid),
        Codec::Ascii if bytes.is_ascii() => Ok(latin1(bytes)),
        Codec::Ascii => Err(CharsetError::Invalid),
        Codec::Latin1 => Ok(latin1(bytes)),
        Codec::Table(decoder) => {
            // The table decoders are lossy; a replacement character signals
            // bytes the codec could not map.
            let text = decoder(bytes);
            if text.contains('\u{fffd}') {
                Err(CharsetError::Invalid)
            } else {
                Ok(text)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Transfer decoders (binascii / email._encoded_words ports)
// ---------------------------------------------------------------------------

fn base64_value(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

/// `binascii.a2b_base64(data, strict_mode=strict)`; `Err` is `binascii.Error`.
fn a2b_base64(data: &[u8], strict: bool) -> Result<Vec<u8>, ()> {
    let mut out = Vec::with_capacity(data.len() / 4 * 3);
    let mut quad_pos = 0u8;
    let mut left: u8 = 0;
    let mut pads = 0u8;
    let mut padding_started = false;
    for (index, &byte) in data.iter().enumerate() {
        if byte == b'=' {
            padding_started = true;
            if strict && quad_pos == 0 {
                return Err(());
            }
            if quad_pos >= 2 {
                pads += 1;
                if quad_pos + pads >= 4 {
                    if strict && index + 1 < data.len() {
                        return Err(());
                    }
                    return Ok(out);
                }
            }
            continue;
        }
        let Some(value) = base64_value(byte) else {
            if strict {
                return Err(());
            }
            continue;
        };
        if strict && padding_started {
            return Err(());
        }
        pads = 0;
        match quad_pos {
            0 => {
                quad_pos = 1;
                left = value;
            }
            1 => {
                quad_pos = 2;
                out.push((left << 2) | (value >> 4));
                left = value & 0x0f;
            }
            2 => {
                quad_pos = 3;
                out.push((left << 4) | (value >> 2));
                left = value & 0x03;
            }
            _ => {
                quad_pos = 0;
                out.push((left << 6) | value);
                left = 0;
            }
        }
    }
    if quad_pos != 0 {
        return Err(());
    }
    Ok(out)
}

/// `email._encoded_words.decode_b`: never fails, falls back to the input.
fn decode_b(encoded: &[u8]) -> Vec<u8> {
    let pad_err = encoded.len() % 4;
    let mut padded = encoded.to_vec();
    if pad_err != 0 {
        padded.extend(std::iter::repeat_n(b'=', 4 - pad_err));
    }
    if let Ok(value) = a2b_base64(&padded, true) {
        return value;
    }
    if let Ok(value) = a2b_base64(encoded, false) {
        return value;
    }
    let mut padded = encoded.to_vec();
    padded.extend(b"==");
    a2b_base64(&padded, false).unwrap_or_else(|_| encoded.to_vec())
}

/// `binascii.a2b_qp(data, header=False)` (used by `quopri.decodestring`).
fn a2b_qp(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    let mut index = 0;
    let len = data.len();
    while index < len {
        if data[index] == b'=' {
            index += 1;
            if index >= len {
                break;
            }
            if data[index] == b'\n' || data[index] == b'\r' {
                // Soft line break.
                if data[index] != b'\n' {
                    while index < len && data[index] != b'\n' {
                        index += 1;
                    }
                }
                if index < len {
                    index += 1;
                }
            } else if data[index] == b'=' {
                out.push(b'=');
                index += 1;
            } else if index + 1 < len
                && data[index].is_ascii_hexdigit()
                && data[index + 1].is_ascii_hexdigit()
            {
                let high = (data[index] as char).to_digit(16).unwrap_or(0) as u8;
                let low = (data[index + 1] as char).to_digit(16).unwrap_or(0) as u8;
                out.push((high << 4) | low);
                index += 2;
            } else {
                out.push(b'=');
            }
        } else {
            out.push(data[index]);
            index += 1;
        }
    }
    out
}

/// Replace every `=XX` hex escape (`email._encoded_words._q_byte_subber`).
fn replace_hex_escapes(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'='
            && index + 2 < bytes.len()
            && bytes[index + 1].is_ascii_hexdigit()
            && bytes[index + 2].is_ascii_hexdigit()
        {
            let high = (bytes[index + 1] as char).to_digit(16).unwrap_or(0) as u8;
            let low = (bytes[index + 2] as char).to_digit(16).unwrap_or(0) as u8;
            out.push((high << 4) | low);
            index += 3;
        } else {
            out.push(bytes[index]);
            index += 1;
        }
    }
    out
}

/// `email._encoded_words.decode_q`.
fn decode_q(encoded: &[u8]) -> Vec<u8> {
    let spaced: Vec<u8> = encoded
        .iter()
        .map(|b| if *b == b'_' { b' ' } else { *b })
        .collect();
    replace_hex_escapes(&spaced)
}

// ---------------------------------------------------------------------------
// RFC 2047 decoding
// ---------------------------------------------------------------------------

#[derive(Debug)]
enum EncodedWordError {
    /// `HeaderParseError`: not an encoded word at all.
    Parse,
    /// `_InvalidEwError`: looks like one but cannot be decoded.
    Invalid,
}

/// `email._encoded_words.decode` for `"=?" + token + "?="`.
fn decode_encoded_word_token(token: &str) -> Result<String, EncodedWordError> {
    let parts: Vec<&str> = token.split('?').collect();
    if parts.len() != 3 {
        return Err(EncodedWordError::Invalid);
    }
    let charset = parts[0].split('*').next().unwrap_or("");
    let text = parts[2];
    if !text.is_ascii() {
        // `cte_string.encode("ascii", "surrogateescape")` raises.
        return Err(EncodedWordError::Invalid);
    }
    let bytes = match parts[1].to_ascii_lowercase().as_str() {
        "q" => decode_q(text.as_bytes()),
        "b" => decode_b(text.as_bytes()),
        _ => return Err(EncodedWordError::Invalid),
    };
    Ok(match decode_charset_strict(&bytes, charset) {
        Ok(text) => text,
        Err(CharsetError::Invalid) => decode_charset_lossy(&bytes, charset)
            .unwrap_or_else(|| String::from_utf8_lossy(&bytes).into_owned()),
        // Decoded as ASCII with surrogates, then sanitised as UTF-8.
        Err(CharsetError::Unknown) => String::from_utf8_lossy(&bytes).into_owned(),
    })
}

/// `email._header_value_parser.get_encoded_word`: returns the decoded text
/// and the unparsed remainder.
fn get_encoded_word(value: &str) -> Result<(String, &str), EncodedWordError> {
    let Some(after) = value.strip_prefix("=?") else {
        return Err(EncodedWordError::Parse);
    };
    let Some((first, remainder)) = after.split_once("?=") else {
        return Err(EncodedWordError::Parse);
    };
    let mut token = first.to_string();
    let mut rest = remainder;
    let bytes = remainder.as_bytes();
    if bytes.len() > 1
        && bytes[0].is_ascii_hexdigit()
        && bytes[1].is_ascii_hexdigit()
        && first.matches('?').count() < 2
    {
        // The "?" after the CTE was followed by an "=XX" escape.
        let (more, after_more) = remainder.split_once("?=").unwrap_or((remainder, ""));
        token.push_str("?=");
        token.push_str(more);
        rest = after_more;
    }
    Ok((decode_encoded_word_token(&token)?, rest))
}

#[derive(Debug)]
enum UnstructuredToken {
    Whitespace(String),
    EncodedWord(String),
    Text(String),
}

fn is_wsp(c: char) -> bool {
    c == ' ' || c == '\t'
}

/// Decode an unstructured header value the way `policy.default` does
/// (`_header_value_parser.get_unstructured` followed by `str()`): encoded
/// words are decoded even inside words, whitespace between two encoded words
/// is dropped, everything else is kept verbatim.
pub(crate) fn decode_unstructured(value: &str) -> String {
    let mut tokens: Vec<UnstructuredToken> = Vec::new();
    let mut rest = value;
    while !rest.is_empty() {
        let first = rest.chars().next().unwrap_or(' ');
        if is_wsp(first) {
            let stripped = rest.trim_start_matches(is_py_space);
            let whitespace = &rest[..rest.len() - stripped.len()];
            tokens.push(UnstructuredToken::Whitespace(whitespace.to_string()));
            rest = stripped;
            continue;
        }
        let mut valid_encoded_word = true;
        if rest.starts_with("=?") {
            match get_encoded_word(rest) {
                Ok((text, remainder)) => {
                    let has_whitespace =
                        matches!(tokens.last(), Some(UnstructuredToken::Whitespace(_)));
                    if has_whitespace && tokens.len() > 1 {
                        if let Some(UnstructuredToken::EncodedWord(_)) =
                            tokens.get(tokens.len() - 2)
                        {
                            let last = tokens.len() - 1;
                            tokens[last] = UnstructuredToken::Whitespace(String::new());
                        }
                    }
                    tokens.push(UnstructuredToken::EncodedWord(text));
                    rest = remainder;
                    continue;
                }
                Err(EncodedWordError::Invalid) => valid_encoded_word = false,
                Err(EncodedWordError::Parse) => {}
            }
        }
        let token_end = rest.find(is_wsp).unwrap_or(rest.len());
        let mut token = &rest[..token_end];
        let mut remainder = &rest[token_end..];
        if valid_encoded_word && RFC2047_MATCHER.is_match(token) {
            if let Some(position) = rest.find("=?") {
                token = &rest[..position];
                remainder = &rest[position..];
            }
        }
        if token.is_empty() {
            // Defensive: always make progress.
            let width = first.len_utf8();
            token = &rest[..width];
            remainder = &rest[width..];
        }
        tokens.push(UnstructuredToken::Text(token.to_string()));
        rest = remainder;
    }
    tokens
        .into_iter()
        .map(|token| match token {
            UnstructuredToken::Whitespace(text)
            | UnstructuredToken::EncodedWord(text)
            | UnstructuredToken::Text(text) => text,
        })
        .collect()
}

/// One chunk produced by `email.header.decode_header`.
struct DecodedChunk {
    bytes: Vec<u8>,
    charset: Option<String>,
}

/// `email.header.decode_header` for a string containing encoded words.
fn decode_header_chunks(header: &str) -> Result<Vec<DecodedChunk>, ()> {
    // (text, encoding, charset); encoding None marks unencoded text.
    let mut words: Vec<(String, Option<char>, Option<String>)> = Vec::new();
    for line in py_splitlines(header) {
        let mut first = true;
        let mut last_end = 0;
        let push_unencoded = |text: &str, first: &mut bool, words: &mut Vec<_>| {
            let text = if *first {
                *first = false;
                text.trim_start_matches(is_py_space)
            } else {
                text
            };
            if !text.is_empty() {
                words.push((text.to_string(), None, None));
            }
        };
        for captures in ECRE.captures_iter(line) {
            let whole = captures.get(0).expect("match");
            push_unencoded(&line[last_end..whole.start()], &mut first, &mut words);
            let charset = captures[1].to_lowercase();
            let encoding = captures[2]
                .to_ascii_lowercase()
                .chars()
                .next()
                .unwrap_or('q');
            words.push((captures[3].to_string(), Some(encoding), Some(charset)));
            last_end = whole.end();
        }
        push_unencoded(&line[last_end..], &mut first, &mut words);
    }
    // Drop whitespace-only unencoded words between two encoded words.
    let mut drop = Vec::new();
    for n in 2..words.len() {
        if words[n].1.is_some()
            && words[n - 2].1.is_some()
            && !words[n - 1].0.is_empty()
            && words[n - 1].0.chars().all(is_py_space)
        {
            drop.push(n - 1);
        }
    }
    for index in drop.into_iter().rev() {
        words.remove(index);
    }
    let mut decoded: Vec<(Vec<u8>, Option<String>)> = Vec::new();
    for (text, encoding, charset) in words {
        match encoding {
            None => decoded.push((raw_unicode_escape(&text), None)),
            Some('q') => {
                // quoprimime.header_decode returns a str of code points < 256.
                let spaced = text.replace('_', " ");
                let unescaped = replace_hex_escapes(&raw_unicode_escape(&spaced));
                decoded.push((unescaped, charset));
            }
            Some(_) => {
                let mut encoded = text;
                let pad_err = encoded.chars().count() % 4;
                if pad_err != 0 {
                    encoded.push_str(&"==="[..4 - pad_err]);
                }
                let bytes = if encoded.is_empty() {
                    Vec::new()
                } else {
                    a2b_base64(&raw_unicode_escape(&encoded), false)?
                };
                decoded.push((bytes, charset));
            }
        }
    }
    let mut collapsed: Vec<DecodedChunk> = Vec::new();
    for (bytes, charset) in decoded {
        match collapsed.last_mut() {
            Some(last) if last.charset == charset => {
                if charset.is_none() {
                    last.bytes.push(b' ');
                }
                last.bytes.extend(bytes);
            }
            _ => collapsed.push(DecodedChunk { bytes, charset }),
        }
    }
    Ok(collapsed)
}

/// `str(email.header.make_header(chunks))`; `Err` for any exception.
fn make_header_text(chunks: Vec<DecodedChunk>) -> Result<String, ()> {
    // Header.append: decode each chunk and remember its effective charset.
    let mut appended: Vec<(String, String)> = Vec::new();
    for chunk in chunks {
        let charset = chunk
            .charset
            .map(|name| {
                let lower = name.to_lowercase();
                match lower.as_str() {
                    "latin_1" | "latin-1" => "iso-8859-1".to_string(),
                    "ascii" => "us-ascii".to_string(),
                    _ => lower,
                }
            })
            .unwrap_or_else(|| "us-ascii".to_string());
        if !charset.is_ascii() {
            return Err(());
        }
        let text = if charset == "unknown-8bit" {
            chunk
                .bytes
                .iter()
                .map(|b| {
                    if b.is_ascii() {
                        char::from(*b)
                    } else {
                        '\u{fffd}'
                    }
                })
                .collect()
        } else {
            decode_charset_strict(&chunk.bytes, &charset).map_err(|_| ())?
        };
        let effective = if charset == "us-ascii" && !text.is_ascii() {
            "utf-8".to_string()
        } else {
            charset
        };
        appended.push((text, effective));
    }
    // Header._normalize: merge runs with the same charset.
    let mut chunks: Vec<(String, String)> = Vec::new();
    for (text, charset) in appended {
        match chunks.last_mut() {
            Some(last) if last.1 == charset => {
                last.0.push(' ');
                last.0.push_str(&text);
            }
            _ => chunks.push((text, charset)),
        }
    }
    // Header.__str__.
    let nonctext = |c: char| is_py_space(c) || c == '(' || c == ')' || c == '\\';
    let mut out = String::new();
    let mut last_charset: Option<String> = None;
    let mut last_space = false;
    for (index, (text, charset)) in chunks.into_iter().enumerate() {
        let mut next_charset = Some(charset);
        if index > 0 {
            let has_space = text.chars().next().is_some_and(nonctext);
            let last_plain = matches!(last_charset.as_deref(), None | Some("us-ascii"));
            let next_plain = matches!(next_charset.as_deref(), None | Some("us-ascii"));
            if !last_plain {
                if next_plain && !has_space {
                    out.push(' ');
                    next_charset = None;
                }
            } else if !next_plain && !last_space {
                out.push(' ');
            }
        }
        last_space = text.chars().last().is_some_and(nonctext);
        last_charset = next_charset;
        out.push_str(&text);
    }
    Ok(out)
}

/// `decode_value`: `str(make_header(decode_header(value)))`, falling back to
/// the input on any error; `""` for `None`/empty.
pub fn decode_value(value: Option<&str>) -> String {
    let Some(value) = value.filter(|v| !v.is_empty()) else {
        return String::new();
    };
    if !ECRE.is_match(value) {
        return value.to_string();
    }
    decode_header_chunks(value)
        .and_then(make_header_text)
        .unwrap_or_else(|_| value.to_string())
}

// ---------------------------------------------------------------------------
// Addresses (email._parseaddr.AddrlistClass and email.utils ports)
// ---------------------------------------------------------------------------

/// One address found by [`AddrlistClass`].
#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedAddress {
    /// `realname` exactly as the compat parser returns it.
    realname: String,
    address: String,
    /// The phrase words when the address came from `phrase <route-addr>`;
    /// this is the display name `headerregistry` would keep.
    display_words: Option<Vec<String>>,
}

impl ParsedAddress {
    fn pair(realname: String, address: String) -> Self {
        Self {
            realname,
            address,
            display_words: None,
        }
    }
}

/// Port of `email._parseaddr.AddrlistClass` (positions are char indices).
struct AddrlistClass {
    field: Vec<char>,
    pos: usize,
    commentlist: Vec<String>,
}

const ADDR_SPECIALS: &str = "()<>@,:;.\"[]";

impl AddrlistClass {
    fn new(field: &str) -> Self {
        Self {
            field: field.chars().collect(),
            pos: 0,
            commentlist: Vec::new(),
        }
    }

    fn at(&self) -> char {
        self.field[self.pos]
    }

    fn is_atomend(c: char) -> bool {
        ADDR_SPECIALS.contains(c) || " \t\r\n".contains(c)
    }

    fn is_phraseend(c: char) -> bool {
        c != '.' && Self::is_atomend(c)
    }

    fn gotonext(&mut self) -> String {
        let mut whitespace = String::new();
        while self.pos < self.field.len() {
            let c = self.at();
            if " \t\n\r".contains(c) {
                if c != '\n' && c != '\r' {
                    whitespace.push(c);
                }
                self.pos += 1;
            } else if c == '(' {
                let comment = self.getcomment();
                self.commentlist.push(comment);
            } else {
                break;
            }
        }
        whitespace
    }

    fn getaddrlist(&mut self) -> Vec<ParsedAddress> {
        let mut result = Vec::new();
        while self.pos < self.field.len() {
            let addresses = self.getaddress();
            if addresses.is_empty() {
                result.push(ParsedAddress::pair(String::new(), String::new()));
            } else {
                result.extend(addresses);
            }
        }
        result
    }

    fn getaddress(&mut self) -> Vec<ParsedAddress> {
        self.commentlist.clear();
        self.gotonext();
        let oldpos = self.pos;
        let oldcl = self.commentlist.clone();
        let plist = self.getphraselist();
        self.gotonext();
        let mut returnlist = Vec::new();
        if self.pos >= self.field.len() {
            if let Some(first) = plist.first() {
                returnlist.push(ParsedAddress::pair(
                    self.commentlist.join(" "),
                    first.clone(),
                ));
            }
        } else if ".@".contains(self.at()) {
            self.pos = oldpos;
            self.commentlist = oldcl;
            let addrspec = self.getaddrspec();
            returnlist.push(ParsedAddress::pair(self.commentlist.join(" "), addrspec));
        } else if self.at() == ':' {
            let fieldlen = self.field.len();
            self.pos += 1;
            while self.pos < self.field.len() {
                self.gotonext();
                if self.pos < fieldlen && self.at() == ';' {
                    self.pos += 1;
                    break;
                }
                let more = self.getaddress();
                returnlist.extend(more);
            }
        } else if self.at() == '<' {
            let routeaddr = self.getrouteaddr();
            let realname = if self.commentlist.is_empty() {
                plist.join(" ")
            } else {
                format!("{} ({})", plist.join(" "), self.commentlist.join(" "))
            };
            returnlist.push(ParsedAddress {
                realname,
                address: routeaddr,
                display_words: Some(plist.clone()),
            });
        } else if let Some(first) = plist.first() {
            returnlist.push(ParsedAddress::pair(
                self.commentlist.join(" "),
                first.clone(),
            ));
        } else if ADDR_SPECIALS.contains(self.at()) {
            self.pos += 1;
        }
        self.gotonext();
        if self.pos < self.field.len() && self.at() == ',' {
            self.pos += 1;
        }
        returnlist
    }

    fn getrouteaddr(&mut self) -> String {
        if self.at() != '<' {
            return String::new();
        }
        let mut expectroute = false;
        self.pos += 1;
        self.gotonext();
        let mut adlist = String::new();
        while self.pos < self.field.len() {
            if expectroute {
                self.getdomain();
                expectroute = false;
            } else if self.at() == '>' {
                self.pos += 1;
                break;
            } else if self.at() == '@' {
                self.pos += 1;
                expectroute = true;
            } else if self.at() == ':' {
                self.pos += 1;
            } else {
                adlist = self.getaddrspec();
                self.pos += 1;
                break;
            }
            self.gotonext();
        }
        adlist
    }

    fn getaddrspec(&mut self) -> String {
        let mut aslist: Vec<String> = Vec::new();
        self.gotonext();
        while self.pos < self.field.len() {
            let mut preserve_ws = true;
            let c = self.at();
            if c == '.' {
                if aslist.last().is_some_and(|last| py_strip(last).is_empty()) {
                    aslist.pop();
                }
                aslist.push(".".into());
                self.pos += 1;
                preserve_ws = false;
            } else if c == '"' {
                let quoted = self.getquote();
                aslist.push(format!("\"{}\"", quote(&quoted)));
            } else if Self::is_atomend(c) {
                if aslist.last().is_some_and(|last| py_strip(last).is_empty()) {
                    aslist.pop();
                }
                break;
            } else {
                aslist.push(self.getatom(false));
            }
            let whitespace = self.gotonext();
            if preserve_ws && !whitespace.is_empty() {
                aslist.push(whitespace);
            }
        }
        if self.pos >= self.field.len() || self.at() != '@' {
            return aslist.concat();
        }
        aslist.push("@".into());
        self.pos += 1;
        self.gotonext();
        let domain = self.getdomain();
        if domain.is_empty() {
            return String::new();
        }
        aslist.concat() + &domain
    }

    fn getdomain(&mut self) -> String {
        let mut sdlist = String::new();
        while self.pos < self.field.len() {
            let c = self.at();
            if c == ' ' || c == '\t' {
                self.pos += 1;
            } else if c == '(' {
                let comment = self.getcomment();
                self.commentlist.push(comment);
            } else if c == '[' {
                let literal = self.getdomainliteral();
                sdlist.push_str(&literal);
            } else if c == '.' {
                self.pos += 1;
                sdlist.push('.');
            } else if c == '@' {
                return String::new();
            } else if Self::is_atomend(c) {
                break;
            } else {
                let atom = self.getatom(false);
                sdlist.push_str(&atom);
            }
        }
        sdlist
    }

    fn getdelimited(&mut self, beginchar: char, endchars: &str, allowcomments: bool) -> String {
        if self.at() != beginchar {
            return String::new();
        }
        let mut out = String::new();
        let mut quoted = false;
        self.pos += 1;
        while self.pos < self.field.len() {
            let c = self.at();
            if quoted {
                out.push(c);
                quoted = false;
            } else if endchars.contains(c) {
                self.pos += 1;
                break;
            } else if allowcomments && c == '(' {
                let comment = self.getcomment();
                out.push_str(&comment);
                continue;
            } else if c == '\\' {
                quoted = true;
            } else {
                out.push(c);
            }
            self.pos += 1;
        }
        out
    }

    fn getquote(&mut self) -> String {
        self.getdelimited('"', "\"\r", false)
    }

    fn getcomment(&mut self) -> String {
        self.getdelimited('(', ")\r", true)
    }

    fn getdomainliteral(&mut self) -> String {
        format!("[{}]", self.getdelimited('[', "]\r", false))
    }

    fn getatom(&mut self, phrase: bool) -> String {
        let mut atom = String::new();
        while self.pos < self.field.len() {
            let c = self.at();
            let ends = if phrase {
                Self::is_phraseend(c)
            } else {
                Self::is_atomend(c)
            };
            if ends {
                break;
            }
            atom.push(c);
            self.pos += 1;
        }
        atom
    }

    fn getphraselist(&mut self) -> Vec<String> {
        let mut plist = Vec::new();
        while self.pos < self.field.len() {
            let c = self.at();
            if " \t\r\n".contains(c) {
                self.pos += 1;
            } else if c == '"' {
                plist.push(self.getquote());
            } else if c == '(' {
                let comment = self.getcomment();
                self.commentlist.push(comment);
            } else if Self::is_phraseend(c) {
                break;
            } else {
                plist.push(self.getatom(true));
            }
        }
        plist
    }
}

/// `email._parseaddr.quote`.
fn quote(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

/// `email.utils._AddressList(field).addresslist`.
fn address_list(field: &str) -> Vec<ParsedAddress> {
    if field.is_empty() {
        return Vec::new();
    }
    AddrlistClass::new(field).getaddrlist()
}

/// `email.utils._iter_escaped_chars` collapsed to (position, char, escaped).
fn strip_quoted_realnames(addr: &str) -> String {
    if !addr.contains('"') {
        return addr.to_string();
    }
    let chars: Vec<char> = addr.chars().collect();
    let mut start = 0;
    let mut open_pos: Option<usize> = None;
    let mut result = String::new();
    let mut escape = false;
    for (pos, &c) in chars.iter().enumerate() {
        if escape {
            escape = false;
            continue;
        }
        if c == '\\' {
            escape = true;
            continue;
        }
        if c == '"' {
            match open_pos {
                None => open_pos = Some(pos),
                Some(open) => {
                    if start != open {
                        result.extend(&chars[start..open]);
                    }
                    start = pos + 1;
                    open_pos = None;
                }
            }
        }
    }
    if start < chars.len() {
        result.extend(&chars[start..]);
    }
    result
}

/// `email.utils._check_parenthesis`.
fn check_parenthesis(addr: &str) -> bool {
    let stripped = strip_quoted_realnames(addr);
    let mut opens = 0i64;
    let mut escape = false;
    for c in stripped.chars() {
        if escape {
            escape = false;
            continue;
        }
        match c {
            '\\' => escape = true,
            '(' => opens += 1,
            ')' => {
                opens -= 1;
                if opens < 0 {
                    return false;
                }
            }
            _ => {}
        }
    }
    opens == 0
}

/// `email.utils._post_parse_validation`.
fn post_parse_validation(parsed: Vec<ParsedAddress>) -> Vec<(String, String)> {
    parsed
        .into_iter()
        .map(|item| {
            if item.address.contains('[') {
                (String::new(), String::new())
            } else {
                (item.realname, item.address)
            }
        })
        .collect()
}

/// `email.utils.getaddresses(fieldvalues)` (strict mode, Python 3.12).
pub fn getaddresses(fieldvalues: &[&str]) -> Vec<(String, String)> {
    let values: Vec<String> = fieldvalues
        .iter()
        .map(|v| {
            if check_parenthesis(v) {
                v.to_string()
            } else {
                "('', '')".to_string()
            }
        })
        .collect();
    let joined = values.join(", ");
    let result = post_parse_validation(address_list(&joined));
    let expected: usize = values
        .iter()
        .map(|v| 1 + strip_quoted_realnames(v).matches(',').count())
        .sum();
    if result.len() != expected {
        return vec![(String::new(), String::new())];
    }
    result
}

/// `email.utils.parseaddr(addr)` (strict mode, Python 3.12).
pub fn parseaddr(addr: &str) -> (String, String) {
    let addr = if check_parenthesis(addr) {
        addr
    } else {
        "('', '')"
    };
    let mut addresses = post_parse_validation(address_list(addr));
    if addresses.len() != 1 {
        return (String::new(), String::new());
    }
    addresses.remove(0)
}

/// `str()` of a `headerregistry.AddressHeader` built from `raw`: every
/// mailbox re-serialised as `display <addr-spec>` (display names RFC 2047
/// decoded and quoted when they contain specials) or a bare addr-spec.
fn format_address_header(raw: &str) -> String {
    let mut formatted = Vec::new();
    for item in address_list(raw) {
        if item.address.is_empty() && item.realname.is_empty() {
            continue;
        }
        let display = item
            .display_words
            .as_ref()
            .map(|words| {
                words
                    .iter()
                    .map(|word| decode_unstructured(word))
                    .collect::<Vec<_>>()
                    .join(" ")
            })
            .unwrap_or_default();
        let display = if display.chars().any(|c| ADDR_SPECIALS.contains(c)) {
            format!("\"{}\"", quote(&display))
        } else {
            display
        };
        if display.is_empty() {
            formatted.push(item.address);
        } else {
            let addr_spec = if item.address == "<>" {
                ""
            } else {
                item.address.as_str()
            };
            formatted.push(format!("{display} <{addr_spec}>"));
        }
    }
    formatted.join(", ")
}

/// One decoded mailbox: `{"name": ..., "address": ...}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Address {
    pub name: String,
    pub address: String,
}

/// `addresses(value)`: decoded display names and lowercased addresses.
pub fn addresses(value: Option<&str>) -> Vec<Address> {
    let Some(value) = value.filter(|v| !v.is_empty()) else {
        return Vec::new();
    };
    getaddresses(&[value])
        .into_iter()
        .filter(|(_, address)| !address.is_empty())
        .map(|(name, address)| Address {
            name: decode_value(Some(&name)),
            address: address.to_lowercase(),
        })
        .collect()
}

/// `address_text(value)`: `"Name <addr>, addr2"`.
pub fn address_text(value: Option<&str>) -> String {
    addresses(value)
        .iter()
        .map(|item| {
            if item.name.is_empty() {
                item.address.clone()
            } else {
                format!("{} <{}>", item.name, item.address)
            }
        })
        .collect::<Vec<_>>()
        .join(", ")
}

/// `first_address(value)`: the first lowercased address or `""`.
pub fn first_address(value: Option<&str>) -> String {
    addresses(value)
        .into_iter()
        .next()
        .map(|a| a.address)
        .unwrap_or_default()
}

/// `unsubscribe_link(raw)`: the first `<...>` target or the stripped value.
pub fn unsubscribe_link(raw: Option<&str>) -> String {
    let Some(raw) = raw.filter(|v| !v.is_empty()) else {
        return String::new();
    };
    match UNSUB_URL.captures(raw) {
        Some(captures) => captures[1].to_string(),
        None => py_strip(raw).to_string(),
    }
}

// ---------------------------------------------------------------------------
// Dates (email._parseaddr._parsedate_tz / email.utils.parsedate_to_datetime)
// ---------------------------------------------------------------------------

/// A Python `datetime` as produced by `parsedate_to_datetime`: naive when the
/// zone was missing or `-0000`, otherwise with a fixed offset in seconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PyDateTime {
    pub naive: NaiveDateTime,
    pub offset_seconds: Option<i32>,
}

impl PyDateTime {
    /// `datetime.isoformat()`.
    pub fn isoformat(&self) -> String {
        let mut out = format!(
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}",
            self.naive.year(),
            self.naive.month(),
            self.naive.day(),
            self.naive.hour(),
            self.naive.minute(),
            self.naive.second()
        );
        let micros = self.naive.and_utc().timestamp_subsec_micros();
        if micros != 0 {
            out.push_str(&format!(".{micros:06}"));
        }
        if let Some(offset) = self.offset_seconds {
            out.push_str(&format_utc_offset(offset));
        }
        out
    }

    /// The UTC instant for aware values.
    pub fn utc(&self) -> Option<NaiveDateTime> {
        let offset = self.offset_seconds?;
        Some(self.naive - chrono::Duration::seconds(i64::from(offset)))
    }
}

/// Python's `%z`-style isoformat offset: `+HH:MM[:SS]`.
pub(crate) fn format_utc_offset(offset: i32) -> String {
    let sign = if offset < 0 { '-' } else { '+' };
    let total = offset.unsigned_abs();
    let (hours, minutes, seconds) = (total / 3600, (total % 3600) / 60, total % 60);
    if seconds != 0 {
        format!("{sign}{hours:02}:{minutes:02}:{seconds:02}")
    } else {
        format!("{sign}{hours:02}:{minutes:02}")
    }
}

const MONTH_NAMES: [&str; 24] = [
    "jan",
    "feb",
    "mar",
    "apr",
    "may",
    "jun",
    "jul",
    "aug",
    "sep",
    "oct",
    "nov",
    "dec",
    "january",
    "february",
    "march",
    "april",
    "may",
    "june",
    "july",
    "august",
    "september",
    "october",
    "november",
    "december",
];
const DAY_NAMES: [&str; 7] = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"];

fn timezone_offset(name: &str) -> Option<i64> {
    Some(match name {
        "UT" | "UTC" | "GMT" | "Z" => 0,
        "AST" => -400,
        "ADT" => -300,
        "EST" => -500,
        "EDT" => -400,
        "CST" => -600,
        "CDT" => -500,
        "MST" => -700,
        "MDT" => -600,
        "PST" => -800,
        "PDT" => -700,
        _ => return None,
    })
}

/// `_parsedate_tz`: `[yy, mm, dd, hh, mm, ss]` plus the offset in seconds
/// (`None` for a missing zone or `-0000`).
fn parsedate_tz(data: &str) -> Option<([i64; 6], Option<i64>)> {
    let mut data: Vec<String> = py_split(data).map(str::to_string).collect();
    if data.is_empty() {
        return None;
    }
    if data[0].ends_with(',') || DAY_NAMES.contains(&data[0].to_lowercase().as_str()) {
        data.remove(0);
    } else if let Some(index) = data[0].rfind(',') {
        data[0] = data[0][index + 1..].to_string();
    }
    if data.len() == 3 {
        let stuff: Vec<String> = data[0].split('-').map(str::to_string).collect();
        if stuff.len() == 3 {
            let mut rebuilt = stuff;
            rebuilt.extend(data[1..].iter().cloned());
            data = rebuilt;
        }
    }
    if data.len() == 4 {
        let s = data[3].clone();
        let index = s.find('+').or_else(|| s.find('-'));
        match index {
            Some(i) if i > 0 => {
                data.truncate(3);
                data.push(s[..i].to_string());
                data.push(s[i..].to_string());
            }
            _ => data.push(String::new()),
        }
    }
    if data.len() < 5 {
        return None;
    }
    data.truncate(5);
    let [mut dd, mut mm, mut yy, mut tm, mut tz]: [String; 5] = data.try_into().ok()?;
    if dd.is_empty() || mm.is_empty() || yy.is_empty() {
        return None;
    }
    mm = mm.to_lowercase();
    if !MONTH_NAMES.contains(&mm.as_str()) {
        let swapped = dd.to_lowercase();
        dd = mm;
        mm = swapped;
        if !MONTH_NAMES.contains(&mm.as_str()) {
            return None;
        }
    }
    let mut month = MONTH_NAMES.iter().position(|m| *m == mm)? as i64 + 1;
    if month > 12 {
        month -= 12;
    }
    if dd.ends_with(',') {
        dd.pop();
    }
    if yy.find(':').is_some_and(|i| i > 0) {
        std::mem::swap(&mut yy, &mut tm);
    }
    if yy.ends_with(',') {
        yy.pop();
        if yy.is_empty() {
            return None;
        }
    }
    if !yy.chars().next().is_some_and(|c| c.is_ascii_digit()) {
        std::mem::swap(&mut yy, &mut tz);
    }
    if tm.ends_with(',') {
        tm.pop();
    }
    let pieces: Vec<&str> = tm.split(':').collect();
    let (thh, tmm, tss) = match pieces.len() {
        2 => (
            pieces[0].to_string(),
            pieces[1].to_string(),
            "0".to_string(),
        ),
        3 => (
            pieces[0].to_string(),
            pieces[1].to_string(),
            pieces[2].to_string(),
        ),
        1 if pieces[0].contains('.') => {
            let dotted: Vec<&str> = pieces[0].split('.').collect();
            match dotted.len() {
                2 => (
                    dotted[0].to_string(),
                    dotted[1].to_string(),
                    "0".to_string(),
                ),
                3 => (
                    dotted[0].to_string(),
                    dotted[1].to_string(),
                    dotted[2].to_string(),
                ),
                _ => return None,
            }
        }
        _ => return None,
    };
    let mut year = py_int(&yy)?;
    let day = py_int(&dd)?;
    let hour = py_int(&thh)?;
    let minute = py_int(&tmm)?;
    let second = py_int(&tss)?;
    if year < 100 {
        year += if year > 68 { 1900 } else { 2000 };
    }
    let tz = tz.to_uppercase();
    let mut offset = timezone_offset(&tz);
    if offset.is_none() {
        offset = py_int(&tz);
        if offset == Some(0) && tz.starts_with('-') {
            offset = None;
        }
    }
    let offset = offset.map(|value| {
        if value == 0 {
            0
        } else {
            let (sign, magnitude) = if value < 0 { (-1, -value) } else { (1, value) };
            sign * ((magnitude / 100) * 3600 + (magnitude % 100) * 60)
        }
    });
    Some(([year, month, day, hour, minute, second], offset))
}

/// `email.utils.parsedate_to_datetime(value)`; `None` where Python raises.
pub fn parsedate_to_datetime(value: &str) -> Option<PyDateTime> {
    let ([year, month, day, hour, minute, second], offset) = parsedate_tz(value)?;
    if !(1..=9999).contains(&year) {
        return None;
    }
    let date = NaiveDate::from_ymd_opt(
        i32::try_from(year).ok()?,
        u32::try_from(month).ok()?,
        u32::try_from(day).ok()?,
    )?;
    let naive = date.and_hms_opt(
        u32::try_from(hour).ok()?,
        u32::try_from(minute).ok()?,
        u32::try_from(second).ok()?,
    )?;
    let offset_seconds = match offset {
        Some(seconds) if seconds.abs() >= 86_400 => return None,
        Some(seconds) => Some(i32::try_from(seconds).ok()?),
        None => None,
    };
    Some(PyDateTime {
        naive,
        offset_seconds,
    })
}

/// `parse_date(value)`: ISO 8601 text of an RFC 2822 date, or `None`.
pub fn parse_date(value: Option<&str>) -> Option<String> {
    let value = value.filter(|v| !v.is_empty())?;
    parsedate_to_datetime(value).map(|parsed| parsed.isoformat())
}

// ---------------------------------------------------------------------------
// MIME parameters (email.message / email.utils ports)
// ---------------------------------------------------------------------------

/// A parameter value after `email.utils.decode_params`.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ParamValue {
    /// Quoted plain value (`'"%s"' % quote(value)`).
    Plain(String),
    /// RFC 2231 extended value: (charset, language, quoted text).
    Extended(Option<String>, Option<String>, String),
}

/// `email.message._splitparam`.
fn split_param(value: &str) -> (&str, Option<&str>) {
    match value.split_once(';') {
        None => (py_strip(value), None),
        Some((head, tail)) => (py_strip(head), Some(py_strip(tail))),
    }
}

/// `email.message._parseparam`.
fn parse_params(value: &str) -> Vec<String> {
    let mut s = format!(";{value}");
    let mut plist = Vec::new();
    while s.starts_with(';') {
        s.remove(0);
        let quotes_before = |end: usize, s: &str| {
            let head = &s[..end];
            head.matches('"').count() as i64 - head.matches("\\\"").count() as i64
        };
        let mut end = s.find(';').map(|i| i as i64).unwrap_or(-1);
        while end > 0 && quotes_before(end as usize, &s) % 2 != 0 {
            end = s[end as usize + 1..]
                .find(';')
                .map(|i| (i + end as usize + 1) as i64)
                .unwrap_or(-1);
        }
        let end = if end < 0 { s.len() } else { end as usize };
        let mut f = s[..end].to_string();
        if let Some(i) = f.find('=') {
            f = format!(
                "{}={}",
                py_strip(&f[..i]).to_lowercase(),
                py_strip(&f[i + 1..])
            );
        }
        plist.push(py_strip(&f).to_string());
        s = s[end..].to_string();
    }
    plist
}

/// `email.utils.unquote`.
fn unquote(value: &str) -> String {
    let count = value.chars().count();
    if count > 1 {
        if value.starts_with('"') && value.ends_with('"') {
            return value[1..value.len() - 1]
                .replace("\\\\", "\\")
                .replace("\\\"", "\"");
        }
        if value.starts_with('<') && value.ends_with('>') {
            return value[1..value.len() - 1].to_string();
        }
    }
    value.to_string()
}

/// `urllib.parse.unquote(s, encoding="latin-1")`.
fn percent_unquote_latin1(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = String::with_capacity(value.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%'
            && index + 2 < bytes.len()
            && bytes[index + 1].is_ascii_hexdigit()
            && bytes[index + 2].is_ascii_hexdigit()
        {
            let high = (bytes[index + 1] as char).to_digit(16).unwrap_or(0);
            let low = (bytes[index + 2] as char).to_digit(16).unwrap_or(0);
            out.push(char::from_u32(high * 16 + low).unwrap_or('\u{fffd}'));
            index += 3;
        } else {
            let c = value[index..].chars().next().unwrap_or('\u{fffd}');
            out.push(c);
            index += c.len_utf8();
        }
    }
    out
}

/// One RFC 2231 segment: (continuation number, value, percent-encoded?).
type Continuation = (Option<i64>, String, bool);

/// `Message._get_params_preserve` after `utils.decode_params`.
fn get_params_preserve(header: &str) -> Vec<(String, ParamValue)> {
    let mut params: Vec<(String, String)> = Vec::new();
    for p in parse_params(header) {
        match p.split_once('=') {
            Some((name, value)) => {
                params.push((py_strip(name).to_string(), py_strip(value).to_string()))
            }
            None => params.push((py_strip(&p).to_string(), String::new())),
        }
    }
    let mut decoded = Vec::new();
    let mut params = params.into_iter();
    if let Some((name, value)) = params.next() {
        decoded.push((name, ParamValue::Plain(value)));
    }
    // name -> [(num, value, encoded)] in insertion order.
    let mut continuations: Vec<(String, Vec<Continuation>)> = Vec::new();
    for (name, value) in params {
        let encoded = name.ends_with('*');
        let value = unquote(&value);
        if let Some(captures) = RFC2231_CONTINUATION.captures(&name) {
            let base = captures[1].to_string();
            let num = captures.get(2).and_then(|m| m.as_str().parse::<i64>().ok());
            match continuations.iter_mut().find(|(n, _)| *n == base) {
                Some((_, list)) => list.push((num, value, encoded)),
                None => continuations.push((base, vec![(num, value, encoded)])),
            }
        } else {
            decoded.push((name, ParamValue::Plain(format!("\"{}\"", quote(&value)))));
        }
    }
    for (name, mut list) in continuations {
        list.sort_by(|a, b| {
            a.0.cmp(&b.0)
                .then_with(|| a.1.cmp(&b.1))
                .then(a.2.cmp(&b.2))
        });
        let mut extended = false;
        let mut joined = String::new();
        for (_, s, encoded) in list {
            if encoded {
                joined.push_str(&percent_unquote_latin1(&s));
                extended = true;
            } else {
                joined.push_str(&s);
            }
        }
        let value = quote(&joined);
        if extended {
            // decode_rfc2231: split on "'" at most twice.
            let parts: Vec<&str> = value.splitn(3, '\'').collect();
            if parts.len() <= 2 {
                decoded.push((
                    name,
                    ParamValue::Extended(None, None, format!("\"{value}\"")),
                ));
            } else {
                decoded.push((
                    name,
                    ParamValue::Extended(
                        Some(parts[0].to_string()),
                        Some(parts[1].to_string()),
                        format!("\"{}\"", parts[2]),
                    ),
                ));
            }
        } else {
            decoded.push((name, ParamValue::Plain(format!("\"{value}\""))));
        }
    }
    decoded
}

/// `email.utils.collapse_rfc2231_value` applied to an unquoted parameter.
fn collapse_param(value: &ParamValue) -> String {
    match value {
        ParamValue::Plain(text) => unquote(text),
        ParamValue::Extended(charset, _, text) => {
            let text = unquote(text);
            let charset = charset.as_deref().unwrap_or("us-ascii");
            let raw = raw_unicode_escape(&text);
            decode_charset_lossy(&raw, charset).unwrap_or(text)
        }
    }
}

// ---------------------------------------------------------------------------
// MIME tree (email.feedparser port)
// ---------------------------------------------------------------------------

/// A header exactly as it appeared in the source: the field name and the
/// value bytes after `policy.header_source_parse` (leading blanks stripped,
/// continuation lines kept, trailing line break removed).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawHeader {
    pub name: String,
    pub value: Vec<u8>,
}

impl RawHeader {
    /// The value decoded as UTF-8 with replacement (Python `_sanitize`).
    pub fn value_lossy(&self) -> String {
        String::from_utf8_lossy(&self.value).into_owned()
    }

    /// Unfolded value: every CR and LF removed (`policy.header_fetch_parse`).
    fn unfolded(&self) -> String {
        self.value_lossy()
            .chars()
            .filter(|c| *c != '\r' && *c != '\n')
            .collect()
    }
}

#[derive(Debug, Clone)]
enum Payload {
    /// Undecoded body bytes of a non-multipart part.
    Bytes(Vec<u8>),
    /// Sub-parts (`is_multipart()` is true), plus the embedded source for
    /// `message/*` containers.
    Children {
        ids: Vec<usize>,
        source: Option<Vec<u8>>,
    },
}

#[derive(Debug, Clone)]
struct Node {
    headers: Vec<RawHeader>,
    default_type: &'static str,
    payload: Payload,
}

/// Address headers that `policy.default` parses with `AddressHeader`.
const ADDRESS_HEADERS: [&str; 11] = [
    "from",
    "to",
    "cc",
    "bcc",
    "reply-to",
    "sender",
    "resent-from",
    "resent-to",
    "resent-cc",
    "resent-bcc",
    "resent-sender",
];

/// One `email.message.Message` of the parsed tree.
#[derive(Debug, Clone, Copy)]
pub struct Part<'a> {
    message: &'a ParsedMessage,
    id: usize,
}

impl<'a> Part<'a> {
    fn node(&self) -> &'a Node {
        &self.message.nodes[self.id]
    }

    /// Raw headers in source order.
    pub fn raw_headers(&self) -> &'a [RawHeader] {
        &self.node().headers
    }

    fn raw_header(&self, name: &str) -> Option<&'a RawHeader> {
        self.node()
            .headers
            .iter()
            .find(|h| h.name.eq_ignore_ascii_case(name))
    }

    /// `name in msg`.
    pub fn contains(&self, name: &str) -> bool {
        self.raw_header(name).is_some()
    }

    /// `str(msg.get(name))` under `policy.default`, `None` when missing.
    pub fn get(&self, name: &str) -> Option<String> {
        self.raw_header(name).map(header_text)
    }

    /// `[str(v) for v in msg.get_all(name, [])]`.
    pub fn get_all(&self, name: &str) -> Vec<String> {
        self.node()
            .headers
            .iter()
            .filter(|h| h.name.eq_ignore_ascii_case(name))
            .map(header_text)
            .collect()
    }

    /// Raw (folded) values of every header called `name`, in order.
    pub fn get_all_raw(&self, name: &str) -> Vec<&'a [u8]> {
        self.node()
            .headers
            .iter()
            .filter(|h| h.name.eq_ignore_ascii_case(name))
            .map(|h| h.value.as_slice())
            .collect()
    }

    /// `msg.is_multipart()`.
    pub fn is_multipart(&self) -> bool {
        matches!(self.node().payload, Payload::Children { .. })
    }

    /// Direct sub-parts (`msg.get_payload()` when multipart).
    pub fn children(&self) -> Vec<Part<'a>> {
        match &self.node().payload {
            Payload::Children { ids, .. } => ids
                .iter()
                .map(|id| Part {
                    message: self.message,
                    id: *id,
                })
                .collect(),
            Payload::Bytes(_) => Vec::new(),
        }
    }

    /// `msg.walk()`: this part, then every sub-part depth first.
    pub fn walk(&self) -> Vec<Part<'a>> {
        let mut out = vec![*self];
        for child in self.children() {
            out.extend(child.walk());
        }
        out
    }

    /// `msg.get_content_type()`.
    pub fn content_type(&self) -> String {
        content_type_of(self.node())
    }

    /// `msg.get_content_maintype()`.
    pub fn content_maintype(&self) -> String {
        self.content_type()
            .split('/')
            .next()
            .unwrap_or("")
            .to_string()
    }

    /// `msg.get_content_subtype()`.
    pub fn content_subtype(&self) -> String {
        self.content_type()
            .split('/')
            .nth(1)
            .unwrap_or("")
            .to_string()
    }

    /// `msg.get_param(param, header=header)` after unquoting, with RFC 2231
    /// values collapsed (`collapse_rfc2231_value`).
    pub fn get_param(&self, param: &str, header: &str) -> Option<String> {
        self.param_value(param, header)
            .map(|value| collapse_param(&value))
    }

    fn param_value(&self, param: &str, header: &str) -> Option<ParamValue> {
        node_param(self.node(), param, header)
    }

    /// `msg.get_content_charset()`.
    pub fn content_charset(&self) -> Option<String> {
        let value = self.param_value("charset", "content-type")?;
        let charset = match value {
            ParamValue::Plain(text) => unquote(&text),
            ParamValue::Extended(charset, _, text) => {
                let text = unquote(&text);
                let encoding = charset
                    .filter(|c| !c.is_empty())
                    .unwrap_or("us-ascii".into());
                decode_charset_strict(&raw_unicode_escape(&text), &encoding).unwrap_or(text)
            }
        };
        if !charset.is_ascii() {
            return None;
        }
        Some(charset.to_lowercase())
    }

    /// `msg.get_content_disposition()`.
    pub fn content_disposition(&self) -> Option<String> {
        let value = self.get("content-disposition")?;
        Some(split_param(&value).0.to_lowercase())
    }

    /// `msg.get_filename()`: `filename` of Content-Disposition, else `name` of
    /// Content-Type, RFC 2231 collapsed, encoded words decoded, stripped.
    pub fn filename(&self) -> Option<String> {
        let value = self
            .param_value("filename", "content-disposition")
            .or_else(|| self.param_value("name", "content-type"))?;
        let text = match &value {
            // policy.default decodes encoded words inside parameter values
            // before Message.get_param sees them.
            ParamValue::Plain(_) => decode_unstructured(&collapse_param(&value)),
            ParamValue::Extended(..) => collapse_param(&value),
        };
        Some(py_strip(&text).to_string())
    }

    /// `msg.get_payload(decode=True)`: transfer-decoded bytes, `None` for a
    /// multipart part.
    pub fn decoded_payload(&self) -> Option<Vec<u8>> {
        let Payload::Bytes(bytes) = &self.node().payload else {
            return None;
        };
        let cte = self.transfer_encoding();
        Some(match cte.as_str() {
            "quoted-printable" => a2b_qp(bytes),
            "base64" => {
                let joined: Vec<u8> = split_lines_bytes(bytes)
                    .into_iter()
                    .flat_map(|line| strip_line_end(line).to_vec())
                    .collect();
                decode_b(&joined)
            }
            _ => bytes.clone(),
        })
    }

    /// `ContentTransferEncodingHeader.cte`: the first token, lowercased.
    fn transfer_encoding(&self) -> String {
        let Some(header) = self.raw_header("content-transfer-encoding") else {
            return String::new();
        };
        let unfolded = header.unfolded();
        let token = py_strip(&unfolded)
            .split(|c: char| is_py_space(c) || c == '(' || c == ';')
            .next()
            .unwrap_or("");
        token.to_lowercase()
    }

    /// Source bytes of an embedded `message/*` part.
    fn embedded_source(&self) -> Option<&'a [u8]> {
        match &self.node().payload {
            Payload::Children { source, .. } => source.as_deref(),
            Payload::Bytes(_) => None,
        }
    }
}

fn content_type_of(node: &Node) -> String {
    let Some(header) = node
        .headers
        .iter()
        .find(|h| h.name.eq_ignore_ascii_case("content-type"))
    else {
        return node.default_type.to_string();
    };
    let unfolded = header.unfolded();
    let ctype = split_param(&unfolded).0.to_lowercase();
    if ctype.matches('/').count() != 1 {
        return "text/plain".to_string();
    }
    ctype
}

/// `str(header)` under `policy.default`.
fn header_text(header: &RawHeader) -> String {
    let unfolded = header.unfolded();
    if ADDRESS_HEADERS
        .iter()
        .any(|name| header.name.eq_ignore_ascii_case(name))
    {
        format_address_header(&unfolded)
    } else if header.name.eq_ignore_ascii_case("message-id") {
        message_id_text(&unfolded)
    } else {
        decode_unstructured(&unfolded)
    }
}

/// `_header_value_parser.ATOM_ENDS`: `SPECIALS` plus space and tab.
fn is_msgid_atom_end(c: char) -> bool {
    "()<>@,:;.\\\"[] \t".contains(c)
}

/// Verbatim CFWS (blanks and possibly nested comments with quoted pairs) at
/// the start of `value`; returns its byte length.
fn msgid_cfws_len(value: &str) -> usize {
    let mut index = 0;
    let bytes = value.as_bytes();
    while index < bytes.len() {
        match bytes[index] {
            b' ' | b'\t' => index += 1,
            b'(' => {
                let mut depth = 0usize;
                let mut cursor = index;
                while cursor < bytes.len() {
                    match bytes[cursor] {
                        b'\\' => cursor += 1,
                        b'(' => depth += 1,
                        b')' => {
                            depth -= 1;
                            if depth == 0 {
                                break;
                            }
                        }
                        _ => {}
                    }
                    cursor += 1;
                }
                // An unterminated comment runs to the end of the value.
                index = (cursor + 1).min(bytes.len());
            }
            _ => break,
        }
    }
    index
}

/// `get_dot_atom_text`: byte length of `1*atext *("." 1*atext)` at the
/// start of `value`, `None` when it is missing or ends with a dot.
fn msgid_dot_atom_len(value: &str) -> Option<usize> {
    let mut end = 0;
    let mut last_was_dot = true;
    for (index, c) in value.char_indices() {
        if c == '.' && !last_was_dot {
            last_was_dot = true;
        } else if !is_msgid_atom_end(c) {
            last_was_dot = false;
        } else {
            break;
        }
        end = index + c.len_utf8();
    }
    (end > 0 && !last_was_dot).then_some(end)
}

/// Byte length of a verbatim obsolete local-part / domain (`get_obs_local_part`,
/// `get_domain` fallbacks): atoms, dots, blanks, comments and quoted strings up
/// to the next `@` / `>` or other special.
fn msgid_obsolete_len(value: &str, stop_at: &str) -> usize {
    let bytes = value.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'"' => {
                index += 1;
                while index < bytes.len() && bytes[index] != b'"' {
                    if bytes[index] == b'\\' {
                        index += 1;
                    }
                    index += 1;
                }
                index = (index + 1).min(bytes.len());
            }
            b'(' => index += msgid_cfws_len(&value[index..]).max(1),
            b'\\' => index = (index + 2).min(bytes.len()),
            byte if stop_at.as_bytes().contains(&byte) => break,
            _ => index += 1,
        }
    }
    // Stay on a character boundary (multi-byte text never matches the ASCII stops).
    while !value.is_char_boundary(index) {
        index += 1;
    }
    index
}

/// `str(msg["Message-ID"])` under `policy.default` (`MessageIDHeader`, i.e.
/// `parse_message_id`): a valid `msg-id` keeps its text, anything after it is
/// dropped (a parse defect), a missing `>` is supplied, and a value that does
/// not start with `<` (after CFWS) is kept as unstructured text.
///
/// Obsolete id-left / id-right forms are kept verbatim (Python re-renders
/// quoted pairs inside a no-fold literal; such ids do not occur in practice).
fn message_id_text(value: &str) -> String {
    let unstructured = || decode_unstructured(value);
    let mut out = String::new();
    let mut rest = value;
    let cfws = msgid_cfws_len(rest);
    out.push_str(&rest[..cfws]);
    rest = &rest[cfws..];
    let Some(after_open) = rest.strip_prefix('<') else {
        return unstructured();
    };
    out.push('<');
    rest = after_open;
    // id-left = dot-atom-text / obs-id-left
    let left = match msgid_dot_atom_len(rest) {
        Some(length) => length,
        None => msgid_obsolete_len(rest, ")<>@,:;[]"),
    };
    out.push_str(&rest[..left]);
    rest = &rest[left..];
    let Some(after_at) = rest.strip_prefix('@') else {
        // "msg-id with no id-right": keep a directly following '>'.
        if rest.starts_with('>') {
            out.push('>');
        }
        return out;
    };
    out.push('@');
    rest = after_at;
    // id-right = dot-atom-text / no-fold-literal / obs-id-right
    let right = match msgid_dot_atom_len(rest) {
        Some(length) => length,
        None if rest.starts_with('[') => match rest.find(']') {
            Some(close) => close + 1,
            None => return unstructured(),
        },
        None => {
            let length = msgid_obsolete_len(rest, "<>@,:;[]\\\"");
            if rest[..length].trim_matches([' ', '\t']).is_empty() {
                return unstructured();
            }
            length
        }
    };
    out.push_str(&rest[..right]);
    rest = &rest[right..];
    if let Some(after_close) = rest.strip_prefix('>') {
        rest = after_close;
    }
    out.push('>');
    let trailing = msgid_cfws_len(rest);
    out.push_str(&rest[..trailing]);
    out
}

/// Split bytes into lines on `\r\n`, `\r` or `\n`, keeping the endings
/// (`email.feedparser.NLCRE_crack`).
fn split_lines_bytes(data: &[u8]) -> Vec<&[u8]> {
    let mut lines = Vec::new();
    let mut start = 0;
    let mut index = 0;
    while index < data.len() {
        match data[index] {
            b'\r' => {
                let end = if data.get(index + 1) == Some(&b'\n') {
                    index + 2
                } else {
                    index + 1
                };
                lines.push(&data[start..end]);
                start = end;
                index = end;
            }
            b'\n' => {
                lines.push(&data[start..=index]);
                start = index + 1;
                index += 1;
            }
            _ => index += 1,
        }
    }
    if start < data.len() {
        lines.push(&data[start..]);
    }
    lines
}

/// Remove one trailing `\r\n`, `\r` or `\n` (`NLCRE_eol`).
fn strip_line_end(line: &[u8]) -> &[u8] {
    if line.ends_with(b"\r\n") {
        &line[..line.len() - 2]
    } else if line.ends_with(b"\r") || line.ends_with(b"\n") {
        &line[..line.len() - 1]
    } else {
        line
    }
}

/// `headerRE = re.compile(r'^(From |[\041-\071\073-\176]*:|[\t ])')`.
fn is_header_line(line: &[u8]) -> bool {
    if line.starts_with(b"From ") || line.first().is_some_and(|b| *b == b'\t' || *b == b' ') {
        return true;
    }
    for &byte in line {
        if byte == b':' {
            return true;
        }
        if !((0x21..=0x39).contains(&byte) || (0x3b..=0x7e).contains(&byte)) {
            return false;
        }
    }
    false
}

/// `boundarymatch(line)`: `Some(is_close)` when the line is a boundary.
fn boundary_match(line: &[u8], separator: &[u8]) -> Option<bool> {
    let rest = line.strip_prefix(separator)?;
    let (close, rest) = match rest.strip_prefix(b"--") {
        Some(after) => (true, after),
        None => (false, rest),
    };
    let rest = &rest[rest
        .iter()
        .take_while(|b| **b == b' ' || **b == b'\t')
        .count()..];
    match rest {
        b"" | b"\r\n" | b"\r" | b"\n" => Some(close),
        _ => None,
    }
}

#[derive(Debug, Clone)]
enum EofMatcher {
    Boundary(Vec<u8>),
    /// `NLCRE.match`: a line starting with a line break.
    BlankLine,
}

impl EofMatcher {
    fn matches(&self, line: &[u8]) -> bool {
        match self {
            Self::Boundary(separator) => boundary_match(line, separator).is_some(),
            Self::BlankLine => line.first().is_some_and(|b| *b == b'\r' || *b == b'\n'),
        }
    }
}

/// `email.feedparser.BufferedSubFile` over a complete input.
struct LineReader<'a> {
    base: &'a [u8],
    lines: Vec<&'a [u8]>,
    pos: usize,
    pushback: Vec<&'a [u8]>,
    eof_stack: Vec<EofMatcher>,
}

impl<'a> LineReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self {
            base: data,
            lines: split_lines_bytes(data),
            pos: 0,
            pushback: Vec::new(),
            eof_stack: Vec::new(),
        }
    }

    /// Next line, or `None` at EOF or when a pushed EOF matcher matches.
    fn readline(&mut self) -> Option<&'a [u8]> {
        let line = match self.pushback.last() {
            Some(line) => *line,
            None => *self.lines.get(self.pos)?,
        };
        if self
            .eof_stack
            .iter()
            .rev()
            .any(|matcher| matcher.matches(line))
        {
            return None;
        }
        if self.pushback.pop().is_none() {
            self.pos += 1;
        }
        Some(line)
    }

    fn unreadline(&mut self, line: &'a [u8]) {
        self.pushback.push(line);
    }

    /// Byte offset of the next unread line in the original input.
    fn offset(&self) -> usize {
        let next = self
            .pushback
            .last()
            .copied()
            .or_else(|| self.lines.get(self.pos).copied());
        match next {
            Some(line) => line.as_ptr() as usize - self.base.as_ptr() as usize,
            None => self.base.len(),
        }
    }
}

struct FeedParser<'a> {
    input: LineReader<'a>,
    nodes: Vec<Node>,
    stack: Vec<usize>,
    last: usize,
}

impl<'a> FeedParser<'a> {
    fn new_message(&mut self) -> usize {
        let parent = self.stack.last().copied();
        let default_type = match parent {
            Some(id) if content_type_of(&self.nodes[id]) == "multipart/digest" => "message/rfc822",
            _ => "text/plain",
        };
        let id = self.nodes.len();
        self.nodes.push(Node {
            headers: Vec::new(),
            default_type,
            payload: Payload::Bytes(Vec::new()),
        });
        if let Some(parent) = parent {
            match &mut self.nodes[parent].payload {
                Payload::Children { ids, .. } => ids.push(id),
                payload => {
                    *payload = Payload::Children {
                        ids: vec![id],
                        source: None,
                    }
                }
            }
        }
        self.stack.push(id);
        self.last = id;
        id
    }

    fn pop_message(&mut self) {
        self.stack.pop();
    }

    fn current(&self) -> usize {
        *self.stack.last().expect("message stack")
    }

    fn set_payload(&mut self, id: usize, bytes: Vec<u8>) {
        self.nodes[id].payload = Payload::Bytes(bytes);
    }

    fn read_rest(&mut self) -> Vec<u8> {
        let mut out = Vec::new();
        while let Some(line) = self.input.readline() {
            out.extend_from_slice(line);
        }
        out
    }

    fn parse_headers(&mut self, id: usize, lines: &[&'a [u8]]) {
        let mut last_value: Vec<&[u8]> = Vec::new();
        let finish = |nodes: &mut Vec<Node>, last_value: &mut Vec<&[u8]>| {
            if last_value.is_empty() {
                return;
            }
            let first = last_value[0];
            let colon = first.iter().position(|b| *b == b':').unwrap_or(first.len());
            let name = String::from_utf8_lossy(&first[..colon]).into_owned();
            let mut value: Vec<u8> = first.get(colon + 1..).unwrap_or(&[]).to_vec();
            let leading = value
                .iter()
                .take_while(|b| **b == b' ' || **b == b'\t')
                .count();
            value.drain(..leading);
            for line in &last_value[1..] {
                value.extend_from_slice(line);
            }
            while value.last().is_some_and(|b| *b == b'\r' || *b == b'\n') {
                value.pop();
            }
            nodes[id].headers.push(RawHeader { name, value });
            last_value.clear();
        };
        for (lineno, line) in lines.iter().enumerate() {
            if line.first().is_some_and(|b| *b == b' ' || *b == b'\t') {
                if !last_value.is_empty() {
                    last_value.push(line);
                }
                continue;
            }
            finish(&mut self.nodes, &mut last_value);
            if line.starts_with(b"From ") {
                if lineno == 0 {
                    continue;
                } else if lineno == lines.len() - 1 {
                    self.input.unreadline(line);
                    return;
                } else {
                    continue;
                }
            }
            match line.iter().position(|b| *b == b':') {
                Some(0) | None => continue,
                Some(_) => last_value.push(line),
            }
        }
        finish(&mut self.nodes, &mut last_value);
    }

    /// Strip the newline that RFC 2046 assigns to the following boundary
    /// from the most recently created part's payload.
    fn strip_last_payload(&mut self) {
        let last = self.last;
        if content_type_of(&self.nodes[last]).starts_with("multipart/") {
            // Python trims the epilogue here, which this port does not keep.
            return;
        }
        if let Payload::Bytes(bytes) = &mut self.nodes[last].payload {
            let trimmed = strip_line_end(bytes).len();
            bytes.truncate(trimmed);
        }
    }

    fn parsegen(&mut self) {
        let id = self.new_message();
        let mut headers = Vec::new();
        while let Some(line) = self.input.readline() {
            if !is_header_line(line) {
                if !line.first().is_some_and(|b| *b == b'\r' || *b == b'\n') {
                    self.input.unreadline(line);
                }
                break;
            }
            headers.push(line);
        }
        self.parse_headers(id, &headers);
        let content_type = content_type_of(&self.nodes[id]);
        if content_type == "message/delivery-status" {
            let start = self.input.offset();
            loop {
                self.input.eof_stack.push(EofMatcher::BlankLine);
                self.parsegen();
                self.pop_message();
                self.input.eof_stack.pop();
                let _blank = self.input.readline();
                match self.input.readline() {
                    None => break,
                    Some(line) => self.input.unreadline(line),
                }
            }
            self.set_embedded_source(id, start);
            return;
        }
        if content_type.starts_with("message/") {
            let start = self.input.offset();
            self.parsegen();
            self.pop_message();
            self.set_embedded_source(id, start);
            return;
        }
        if content_type.starts_with("multipart/") {
            self.parse_multipart(id);
            return;
        }
        let payload = self.read_rest();
        self.set_payload(id, payload);
    }

    fn set_embedded_source(&mut self, id: usize, start: usize) {
        let end = self.input.offset().max(start);
        let source = self.input.base[start..end].to_vec();
        if let Payload::Children { source: slot, .. } = &mut self.nodes[id].payload {
            *slot = Some(strip_line_end(&source).to_vec());
        }
    }

    fn parse_multipart(&mut self, id: usize) {
        let Some(boundary) = node_boundary(&self.nodes[id]) else {
            let payload = self.read_rest();
            self.set_payload(id, payload);
            return;
        };
        // Non-ASCII boundaries never match the surrogate-escaped body lines.
        let separator = if boundary.is_ascii() {
            Some(format!("--{boundary}").into_bytes())
        } else {
            None
        };
        let matches = |line: &[u8]| separator.as_deref().and_then(|s| boundary_match(line, s));
        let mut capturing_preamble = true;
        let mut preamble: Vec<u8> = Vec::new();
        let mut close_boundary_seen = false;
        while let Some(line) = self.input.readline() {
            match matches(line) {
                Some(true) => {
                    close_boundary_seen = true;
                    break;
                }
                Some(false) => {
                    if capturing_preamble {
                        capturing_preamble = false;
                        self.input.unreadline(line);
                        continue;
                    }
                    // Consume repeated boundary lines.
                    loop {
                        match self.input.readline() {
                            Some(next) if matches(next).is_some() => continue,
                            Some(next) => {
                                self.input.unreadline(next);
                                break;
                            }
                            None => break,
                        }
                    }
                    let separator = separator.clone().expect("matched separator");
                    self.input.eof_stack.push(EofMatcher::Boundary(separator));
                    self.parsegen();
                    self.strip_last_payload();
                    self.input.eof_stack.pop();
                    self.pop_message();
                    self.last = self.current();
                }
                None => preamble.extend_from_slice(line),
            }
        }
        if capturing_preamble {
            self.set_payload(id, preamble);
            // The rest is epilogue; consume it so outer parts continue
            // after this multipart.
            self.read_rest();
            return;
        }
        if !close_boundary_seen {
            return;
        }
        // Everything up to the enclosing EOF is epilogue.
        self.read_rest();
    }
}

/// `msg.get_param(param, header=header)` before unquoting.
fn node_param(node: &Node, param: &str, header: &str) -> Option<ParamValue> {
    let raw = node
        .headers
        .iter()
        .find(|h| h.name.eq_ignore_ascii_case(header))?;
    get_params_preserve(&raw.unfolded())
        .into_iter()
        .find(|(name, _)| name.to_lowercase() == param.to_lowercase())
        .map(|(_, value)| value)
}

/// `msg.get_boundary()`: RFC 2046 boundaries may begin but not end in blanks.
fn node_boundary(node: &Node) -> Option<String> {
    let value = node_param(node, "boundary", "content-type")?;
    Some(
        collapse_param(&value)
            .trim_end_matches(is_py_space)
            .to_string(),
    )
}

/// A parsed RFC 822 message (`BytesParser(policy=policy.default)` result).
///
/// The message is fully owned, cheap to share across threads and can be
/// queried like Python's `EmailMessage` through [`ParsedMessage::root`] or the
/// forwarding helpers below.
#[derive(Debug, Clone)]
pub struct ParsedMessage {
    nodes: Vec<Node>,
}

impl ParsedMessage {
    /// `parse_message(raw)`. Never fails, like the Python parser.
    pub fn parse(raw: &[u8]) -> Self {
        let mut parser = FeedParser {
            input: LineReader::new(raw),
            nodes: Vec::new(),
            stack: Vec::new(),
            last: 0,
        };
        parser.parsegen();
        Self {
            nodes: parser.nodes,
        }
    }

    /// The top-level message.
    pub fn root(&self) -> Part<'_> {
        Part {
            message: self,
            id: 0,
        }
    }

    /// `str(msg.get(name))` of the top-level headers.
    pub fn get(&self, name: &str) -> Option<String> {
        self.root().get(name)
    }

    /// `msg.get_all(name, [])` of the top-level headers.
    pub fn get_all(&self, name: &str) -> Vec<String> {
        self.root().get_all(name)
    }

    /// `name in msg`.
    pub fn contains(&self, name: &str) -> bool {
        self.root().contains(name)
    }

    /// Top-level raw headers in source order (`msg.raw_items()`).
    pub fn raw_headers(&self) -> &[RawHeader] {
        self.root().raw_headers()
    }

    /// `msg.walk()`.
    pub fn walk(&self) -> Vec<Part<'_>> {
        self.root().walk()
    }
}

/// `parse_message(raw)`.
pub fn parse_message(raw: &[u8]) -> ParsedMessage {
    ParsedMessage::parse(raw)
}

// ---------------------------------------------------------------------------
// Bodies, attachments, links
// ---------------------------------------------------------------------------

/// `_part_bytes(part)`. For `message/*` containers Python stringified the
/// list of sub-messages; the embedded message source is returned instead.
fn part_bytes(part: &Part<'_>) -> Vec<u8> {
    if let Some(payload) = part.decoded_payload() {
        return payload;
    }
    part.embedded_source()
        .map(<[u8]>::to_vec)
        .unwrap_or_default()
}

/// `_part_text(part)`.
fn part_text(part: &Part<'_>) -> String {
    let charset = part.content_charset().filter(|c| !c.is_empty());
    let charset = charset.as_deref().unwrap_or("utf-8");
    let bytes = part_bytes(part);
    decode_charset_lossy(&bytes, charset)
        .unwrap_or_else(|| String::from_utf8_lossy(&bytes).into_owned())
}

/// `msg.walk() if msg.is_multipart() else [msg]`.
fn parts_of(message: &ParsedMessage) -> Vec<Part<'_>> {
    let root = message.root();
    if root.is_multipart() {
        root.walk()
    } else {
        vec![root]
    }
}

/// `extract_bodies(msg)`: `(plain text, html)`; either may be empty.
pub fn extract_bodies(message: &ParsedMessage) -> (String, String) {
    let mut text = String::new();
    let mut html = String::new();
    for part in parts_of(message) {
        if part.content_maintype() == "multipart" {
            continue;
        }
        if part.content_disposition().as_deref() == Some("attachment") {
            continue;
        }
        let content_type = part.content_type();
        if content_type == "text/plain" && text.is_empty() {
            text = part_text(&part);
        } else if content_type == "text/html" && html.is_empty() {
            html = part_text(&part);
        }
    }
    (text, html)
}

/// Attachment metadata (`list_attachments` entry).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AttachmentInfo {
    pub index: usize,
    pub filename: String,
    pub content_type: String,
    pub size: usize,
}

/// One attachment's content (`attachment_payload` result).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttachmentPayload {
    pub filename: String,
    pub content_type: String,
    pub content: Vec<u8>,
}

/// Parts that count as attachments, in `walk()` order, with their filename.
fn attachment_parts(message: &ParsedMessage) -> Vec<(Part<'_>, Option<String>)> {
    parts_of(message)
        .into_iter()
        .filter(|part| part.content_maintype() != "multipart")
        .filter_map(|part| {
            let filename = part.filename();
            if filename.is_none() && part.content_disposition().as_deref() != Some("attachment") {
                None
            } else {
                Some((part, filename))
            }
        })
        .collect()
}

fn attachment_name(filename: Option<&str>, index: usize) -> String {
    let decoded = decode_value(filename);
    if decoded.is_empty() {
        format!("attachment-{}", index + 1)
    } else {
        decoded
    }
}

/// `list_attachments(msg)`: metadata in `walk()` order; indexes are stable.
pub fn list_attachments(message: &ParsedMessage) -> Vec<AttachmentInfo> {
    attachment_parts(message)
        .into_iter()
        .enumerate()
        .map(|(index, (part, filename))| AttachmentInfo {
            index,
            filename: attachment_name(filename.as_deref(), index),
            content_type: part.content_type(),
            size: part_bytes(&part).len(),
        })
        .collect()
}

/// `attachment_payload(msg, index)`.
pub fn attachment_payload(message: &ParsedMessage, index: usize) -> Option<AttachmentPayload> {
    let (part, filename) = attachment_parts(message).into_iter().nth(index)?;
    Some(AttachmentPayload {
        filename: attachment_name(filename.as_deref(), index),
        content_type: part.content_type(),
        content: part_bytes(&part),
    })
}

/// `snippet(text, limit=200)`.
pub fn snippet(text: &str, limit: usize) -> String {
    truncate_chars(&collapse_whitespace(text), limit)
}

/// `_TAG_PATTERN.sub(" ", html)`.
pub fn strip_tags(html: &str) -> String {
    TAG_PATTERN.replace_all(html, " ").into_owned()
}

/// One link found in a message body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Link {
    pub url: String,
    pub domain: String,
    pub label: String,
}

/// `urllib.parse.urlsplit(url).hostname or ""` for an http(s) URL.
pub fn url_hostname(url: &str) -> String {
    let Some(colon) = url.find(':') else {
        return String::new();
    };
    let rest = &url[colon + 1..];
    let Some(after) = rest.strip_prefix("//") else {
        return String::new();
    };
    let end = after.find(['/', '?', '#']).unwrap_or(after.len());
    let netloc = &after[..end];
    if netloc.contains('[') != netloc.contains(']') {
        // urlsplit raises ValueError("Invalid IPv6 URL").
        return String::new();
    }
    let hostinfo = netloc
        .rsplit_once('@')
        .map(|(_, host)| host)
        .unwrap_or(netloc);
    let hostname = match hostinfo.split_once('[') {
        Some((_, bracketed)) => {
            let inner = bracketed
                .split_once(']')
                .map(|(h, _)| h)
                .unwrap_or(bracketed);
            // urlsplit validates bracketed hosts as IPv6/IPvFuture literals.
            let address = inner.split('%').next().unwrap_or(inner);
            if !inner.starts_with(['v', 'V']) && address.parse::<std::net::Ipv6Addr>().is_err() {
                return String::new();
            }
            inner
        }
        None => hostinfo.split_once(':').map(|(h, _)| h).unwrap_or(hostinfo),
    };
    match hostname.split_once('%') {
        Some((host, zone)) => format!("{}%{}", host.to_lowercase(), zone),
        None => hostname.to_lowercase(),
    }
}

/// `extract_links(text, html)`: URLs from both bodies plus the display text
/// of `<a>` tags, deduplicated by URL in first-seen order.
pub fn extract_links(text: &str, html: &str) -> Vec<Link> {
    let mut links: Vec<Link> = Vec::new();
    let mut index: HashMap<String, usize> = HashMap::new();
    let mut add = |url: &str, label: &str| {
        let url = py_strip(url).trim_end_matches(['.', ',', ';', ':', '!', '?']);
        let lower = url.to_lowercase();
        if !(lower.starts_with("http://") || lower.starts_with("https://")) {
            return;
        }
        let position = *index.entry(url.to_string()).or_insert_with(|| {
            links.push(Link {
                url: url.to_string(),
                domain: url_hostname(url),
                label: String::new(),
            });
            links.len() - 1
        });
        let entry = &mut links[position];
        if !label.is_empty() && entry.label.is_empty() {
            entry.label = label.to_string();
        }
    };
    for found in URL_PATTERN.find_iter(text) {
        add(found.as_str(), "");
    }
    for captures in HTML_LINK_PATTERN.captures_iter(html) {
        let label = collapse_whitespace(&strip_tags(&captures[2]));
        add(&captures[1], &truncate_chars(&label, 120));
    }
    links
}

/// Decoded header summary used by the message reader (`header_view`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HeaderView {
    pub subject: String,
    pub from_name: String,
    pub from_addr: String,
    pub to: String,
    pub cc: String,
    pub date: Option<String>,
    pub message_id: String,
    pub text_body: String,
    pub html_body: String,
    pub attachments: Vec<AttachmentInfo>,
    pub snippet: String,
}

impl HeaderView {
    /// The view as a JSON object, ready to be extended with more fields.
    pub fn into_map(self) -> Map<String, Value> {
        match serde_json::to_value(self) {
            Ok(Value::Object(map)) => map,
            _ => Map::new(),
        }
    }
}

/// `header_view(msg)`.
pub fn header_view(message: &ParsedMessage) -> HeaderView {
    let (from_name, from_addr) = parseaddr(&message.get("From").unwrap_or_default());
    let (text, html) = extract_bodies(message);
    let snippet_source = if text.is_empty() {
        strip_tags(&html)
    } else {
        text.clone()
    };
    HeaderView {
        subject: decode_value(message.get("Subject").as_deref()),
        from_name: decode_value(Some(&from_name)),
        from_addr: from_addr.to_lowercase(),
        to: address_text(message.get("To").as_deref()),
        cc: address_text(message.get("Cc").as_deref()),
        date: parse_date(message.get("Date").as_deref()),
        message_id: py_strip(&message.get("Message-ID").unwrap_or_default()).to_string(),
        attachments: list_attachments(message),
        snippet: snippet(&snippet_source, 200),
        text_body: text,
        html_body: html,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn message_id_header_matches_python_message_id_header() {
        // Expected values: str(BytesParser(policy=policy.default)
        // .parsebytes(b"Message-ID: " + value + b"\r\n\r\n")["Message-ID"]).
        for (value, expected) in [
            ("<a@b@c.example.com>", "<a@b>"),
            ("<a b@c>", "<a"),
            ("  <x@y>  ", "<x@y>  "),
            ("(c) <x@y> (d)", "(c) <x@y> (d)"),
            ("<\"q s\"@example.com>", "<\"q s\"@example.com>"),
            ("<a@[1.2.3.4]>", "<a@[1.2.3.4]>"),
            ("<a@ex ample.com>", "<a@ex> "),
            ("foo@bar", "foo@bar"),
            ("<a.@b>", "<a.@b>"),
            ("<.a@b>", "<.a@b>"),
            ("<a..b@c>", "<a..b@c>"),
            ("<a@b.>", "<a@b.>"),
            ("<a@b", "<a@b>"),
            ("<a@b> <c@d>", "<a@b> "),
            ("=?utf-8?q?x?= <a@b>", "x <a@b>"),
            ("<=?utf-8?q?x?=@b>", "<=?utf-8?q?x?=@b>"),
            ("<a(c)@b>", "<a"),
            ("<a@b(c)>", "<a@b>(c)"),
            ("<a@(c)b>", "<a@(c)b>"),
            ("", ""),
            ("<>", "<>"),
            ("<@b>", "<@b>"),
            ("<a>", "<a>"),
            ("<a", "<a"),
            ("a", "a"),
            ("<a@b>x", "<a@b>"),
            ("<\u{fc}@b>", "<\u{fc}@b>"),
            ("<a@\u{fc}.de>", "<a@\u{fc}.de>"),
            ("<a@b>\t", "<a@b>\t"),
            ("(un(nested)) <a@b>", "(un(nested)) <a@b>"),
            ("(x\\)y) <a@b>", "(x\\)y) <a@b>"),
            ("<a.\"b\"@c>", "<a.\"b\"@c>"),
            ("<a @ b>", "<a"),
            ("<a@b . c>", "<a@b> "),
        ] {
            let raw = format!("Message-ID: {value}\r\n\r\n");
            let message = parse_message(raw.as_bytes());
            assert_eq!(
                message.get("Message-ID").as_deref(),
                Some(expected),
                "{value:?}"
            );
        }
    }

    #[test]
    fn decode_value_handles_encoded_words_and_fallbacks() {
        assert_eq!(decode_value(None), "");
        assert_eq!(decode_value(Some("")), "");
        assert_eq!(decode_value(Some("Plain é")), "Plain é");
        assert_eq!(decode_value(Some("=?utf-8?q?caf=C3=A9?=")), "café");
        assert_eq!(decode_value(Some("=?utf-8?b?w6k=?=")), "é");
        assert_eq!(decode_value(Some("=?utf-8?q?a?= =?utf-8?q?b?=")), "ab");
        assert_eq!(
            decode_value(Some("Hi =?utf-8?q?there?= you")),
            "Hi there you"
        );
        assert_eq!(decode_value(Some("x=?utf-8?q?a?=y")), "x a y");
        assert_eq!(decode_value(Some("=?iso-8859-1?q?a?= =?utf-8?q?b?=")), "ab");
        // Non-ASCII unencoded text cannot be decoded as us-ascii.
        assert_eq!(
            decode_value(Some("café =?utf-8?q?x?=")),
            "café =?utf-8?q?x?="
        );
        // Unknown charsets make make_header fail: the raw value is kept.
        assert_eq!(decode_value(Some("=?x-bogus?q?abc?=")), "=?x-bogus?q?abc?=");
    }

    #[test]
    fn unstructured_decoding_matches_policy_default() {
        assert_eq!(
            decode_unstructured(
                "=?utf-8?q?Hello?= =?utf-8?q?_World?= x=?utf-8?q?Y?=z =?bogus?q?abc?= plain"
            ),
            "Hello World xYz abc plain"
        );
        assert_eq!(decode_unstructured("=?utf-8?q?=41?="), "A");
        assert_eq!(decode_unstructured("=?utf-8?b?w6k?="), "é");
        assert_eq!(decode_unstructured("no words  here"), "no words  here");
    }

    #[test]
    fn strict_address_parsing() {
        assert_eq!(
            parseaddr("\"Bank Support <support@bank.example>\" <forged@evil.example>"),
            (
                "Bank Support <support@bank.example>".into(),
                "forged@evil.example".into()
            )
        );
        assert_eq!(parseaddr("a@b.c, d@e.f"), (String::new(), String::new()));
        assert_eq!(
            getaddresses(&["alice@example.com <bob@example.com>"]),
            vec![(String::new(), String::new())]
        );
        assert_eq!(getaddresses(&["a@b.c, d@e.f"]).len(), 2);
        assert_eq!(parseaddr("x <a@[1.2.3.4]>"), (String::new(), String::new()));
    }

    #[test]
    fn address_headers_are_reserialized() {
        assert_eq!(format_address_header("a@b.c (Smith, J)"), "a@b.c");
        assert_eq!(
            format_address_header("=?utf-8?q?Bob?= =?utf-8?q?Smith?= <b@x>"),
            "Bob Smith <b@x>"
        );
        assert_eq!(
            format_address_header("John Q. Public <j@x.com>"),
            "\"John Q. Public\" <j@x.com>"
        );
        let message = parse_message(b"To: \"Doe, J\" <J@X.com>, k@y\r\n\r\n");
        assert_eq!(
            address_text(message.get("To").as_deref()),
            "Doe, J <j@x.com>, k@y"
        );
        assert_eq!(first_address(message.get("To").as_deref()), "j@x.com");
    }

    #[test]
    fn dates_follow_parsedate_to_datetime() {
        assert_eq!(
            parse_date(Some("Mon, 13 Oct 2026 10:00:05 +0000")).as_deref(),
            Some("2026-10-13T10:00:05+00:00")
        );
        assert_eq!(
            parse_date(Some("13 Oct 2026 10:00:05 -0000")).as_deref(),
            Some("2026-10-13T10:00:05")
        );
        assert_eq!(
            parse_date(Some("Tue, 1 Jan 2000 00:00:00 +0530")).as_deref(),
            Some("2000-01-01T00:00:00+05:30")
        );
        assert_eq!(
            parse_date(Some("1 Jan 99 1:02 EST")).as_deref(),
            Some("1999-01-01T01:02:00-05:00")
        );
        assert_eq!(parse_date(Some("31 Feb 2020 00:00:00 +0000")), None);
        assert_eq!(parse_date(Some("garbage")), None);
        assert_eq!(parse_date(None), None);
    }

    #[test]
    fn transfer_decoders() {
        assert_eq!(
            a2b_qp(b"caf=C3=A9 =\r\nnext=3d=zz="),
            "café next==zz".as_bytes()
        );
        assert_eq!(decode_b(b"aGVsbG8"), b"hello");
        assert_eq!(decode_b(b"aGVs bG8="), b"hello");
        assert_eq!(decode_b(b"TVo="), b"MZ");
    }

    #[test]
    fn multipart_walk_bodies_and_attachments() {
        let raw = b"From: a@b.c\r\nContent-Type: multipart/mixed; boundary=\"B\"\r\n\r\n\
preamble\r\n--B\r\nContent-Type: multipart/alternative; boundary=\"C\"\r\n\r\n\
--C\r\nContent-Type: text/plain; charset=iso-8859-1\r\n\
Content-Transfer-Encoding: quoted-printable\r\n\r\n\
caf=E9\r\n--C\r\nContent-Type: text/html\r\n\r\n<p>Hi</p>\r\n--C--\r\n\
--B\r\nContent-Type: application/pdf\r\n\
Content-Disposition: attachment; filename*=utf-8''%e2%82%ac.pdf\r\n\
Content-Transfer-Encoding: base64\r\n\r\nTVo=\r\n--B\r\nContent-Type: message/rfc822\r\n\
Content-Disposition: attachment\r\n\r\nSubject: inner\r\n\r\ninner body\r\n--B--\r\n";
        let message = parse_message(raw);
        let types: Vec<String> = message.walk().iter().map(|p| p.content_type()).collect();
        assert_eq!(
            types,
            [
                "multipart/mixed",
                "multipart/alternative",
                "text/plain",
                "text/html",
                "application/pdf",
                "message/rfc822",
                "text/plain"
            ]
        );
        let (text, html) = extract_bodies(&message);
        assert_eq!(text, "café");
        assert_eq!(html, "<p>Hi</p>");
        let attachments = list_attachments(&message);
        assert_eq!(attachments.len(), 2);
        assert_eq!(attachments[0].filename, "€.pdf");
        assert_eq!(attachments[0].size, 2);
        assert_eq!(attachments[1].filename, "attachment-2");
        let payload = attachment_payload(&message, 1).unwrap();
        assert_eq!(payload.content, b"Subject: inner\r\n\r\ninner body");
        assert!(attachment_payload(&message, 2).is_none());
    }

    #[test]
    fn links_and_snippets() {
        let links = extract_links(
            "See https://Example.com/a. and http://x.test/",
            "<a href=\"http://185.10.20.30/login\"><b>https://bank.example</b></a>",
        );
        assert_eq!(links.len(), 3);
        assert_eq!(links[0].url, "https://Example.com/a");
        assert_eq!(links[0].domain, "example.com");
        assert_eq!(links[2].label, "https://bank.example");
        assert_eq!(snippet("  a \n\t b  ", 200), "a b");
        assert_eq!(snippet("abcdef", 3), "abc");
        assert_eq!(
            unsubscribe_link(Some("<mailto:x@y>, <https://u>")),
            "mailto:x@y"
        );
        assert_eq!(unsubscribe_link(Some("  https://u  ")), "https://u");
    }

    #[test]
    fn header_view_shape() {
        let raw = b"From: =?utf-8?q?J=C3=B6rg?= <Joerg@Example.com>\r\nTo: a@b.c\r\n\
Subject: =?utf-8?q?Gr=C3=BC=C3=9Fe?=\r\nDate: Mon, 13 Oct 2026 10:00:00 +0200\r\n\
Message-ID:  <id@example.com> \r\n\r\nHello   world\r\n";
        let view = header_view(&parse_message(raw));
        assert_eq!(view.subject, "Grüße");
        assert_eq!(view.from_name, "Jörg");
        assert_eq!(view.from_addr, "joerg@example.com");
        assert_eq!(view.to, "a@b.c");
        assert_eq!(view.date.as_deref(), Some("2026-10-13T10:00:00+02:00"));
        assert_eq!(view.message_id, "<id@example.com>");
        assert_eq!(view.snippet, "Hello world");
        assert!(view.into_map().contains_key("html_body"));
    }

    #[test]
    fn messages_without_headers_become_plain_bodies() {
        let message = parse_message(b"just some text\nmore");
        assert!(message.raw_headers().is_empty());
        assert_eq!(extract_bodies(&message).0, "just some text\nmore");
    }

    fn mask_message_attachment_sizes(value: &mut Value) {
        match value {
            Value::Object(map) => {
                let is_message = map
                    .get("content_type")
                    .and_then(Value::as_str)
                    .is_some_and(|t| t.starts_with("message/"));
                if is_message && map.contains_key("size") {
                    map.insert("size".into(), Value::Null);
                }
                map.values_mut().for_each(mask_message_attachment_sizes);
            }
            Value::Array(items) => items.iter_mut().for_each(mask_message_attachment_sizes),
            _ => {}
        }
    }

    /// Golden parity with the original Python `parsing.py`/`audit.py`: the
    /// expected JSON was produced by running copies of those modules over
    /// `tests/fixtures/*.eml` (see `tests/fixtures/README.md`).
    #[test]
    fn parity_with_python_fixtures() {
        use base64::Engine;
        let dir = format!("{}/tests/fixtures", env!("CARGO_MANIFEST_DIR"));
        let expected: Value =
            serde_json::from_str(&std::fs::read_to_string(format!("{dir}/expected.json")).unwrap())
                .unwrap();
        let mut failures = Vec::new();
        for (name, want) in expected.as_object().unwrap() {
            let raw = std::fs::read(format!("{dir}/{name}.eml")).unwrap();
            let message = parse_message(&raw);
            let mut check = |field: &str, mut got: Value, want: &Value| {
                // Deliberate deviation: Python measured `str()` of the
                // sub-message list for message/* attachments.
                let mut want = want.clone();
                mask_message_attachment_sizes(&mut got);
                mask_message_attachment_sizes(&mut want);
                if got != want {
                    failures.push(format!(
                        "{name}.{field}:
  got:  {got}
  want: {want}"
                    ));
                }
            };
            check(
                "header_view",
                serde_json::to_value(header_view(&message)).unwrap(),
                &want["header_view"],
            );
            let mut report = crate::audit::audit_message(&raw, Some("me@example.com"));
            report.as_object_mut().unwrap().remove("generated_at");
            check("audit", report, &want["audit"]);
            let (text, html) = extract_bodies(&message);
            check(
                "links",
                serde_json::to_value(extract_links(&text, &html)).unwrap(),
                &want["links"],
            );
            let walk: Vec<Value> = message
                .walk()
                .iter()
                .map(|p| {
                    serde_json::json!({
                        "type": p.content_type(),
                        "filename": p.filename(),
                        "disposition": p.content_disposition(),
                        "charset": p.content_charset(),
                    })
                })
                .collect();
            check("walk", Value::from(walk), &want["walk"]);
            let wanted_payloads = want["payloads"].as_array().unwrap();
            for (index, wanted) in wanted_payloads.iter().enumerate() {
                let got = attachment_payload(&message, index);
                let got = got.map(|payload| {
                    let content = if wanted["content_b64"].is_null() {
                        Value::Null
                    } else {
                        Value::from(
                            base64::engine::general_purpose::STANDARD.encode(&payload.content),
                        )
                    };
                    serde_json::json!({
                        "filename": payload.filename,
                        "content_type": payload.content_type,
                        "content_b64": content,
                    })
                });
                check(
                    &format!("payload[{index}]"),
                    got.unwrap_or(Value::Null),
                    wanted,
                );
            }
            check(
                "addresses_to",
                serde_json::to_value(addresses(message.get("To").as_deref())).unwrap(),
                &want["addresses_to"],
            );
            check(
                "addresses_cc",
                serde_json::to_value(addresses(message.get("Cc").as_deref())).unwrap(),
                &want["addresses_cc"],
            );
            check(
                "subject_header",
                serde_json::to_value(message.get("Subject")).unwrap(),
                &want["subject_header"],
            );
        }
        assert!(
            failures.is_empty(),
            "{} mismatches:
{}",
            failures.len(),
            failures.join(
                "
"
            )
        );
    }
}
