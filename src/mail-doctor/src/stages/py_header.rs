//! Emulation of the parts of Python's `email` package that decode header text:
//! charset codecs, the "surrogateescape" model of raw 8-bit bytes,
//! `email._header_value_parser.get_unstructured` (the `policy.default` path)
//! and `email.header.decode_header` + `make_header` (the legacy path used by
//! `eml_extract._decode`).
//!
//! Python's `BytesParser` decodes message bytes as ASCII with
//! `errors="surrogateescape"`, so every non-ASCII byte becomes one lone
//! surrogate character. Rust strings cannot hold surrogates, so this module
//! maps such bytes into a private-use range instead ("sesc" strings). The
//! mapped characters are neither whitespace nor syntax characters, exactly like
//! Python's surrogates, which keeps index arithmetic and tokenizing identical.

use std::sync::OnceLock;

use encoding_rs::Encoding;
use regex::Regex;

const SESC_BASE: u32 = 0x10_FF00;

/// Python `str.isspace()` for one character.
pub fn py_isspace(ch: char) -> bool {
    ch.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&ch)
}

/// Python `str.isspace()` (non-empty and all whitespace).
pub fn py_is_all_space(value: &str) -> bool {
    !value.is_empty() && value.chars().all(py_isspace)
}

/// Python `str.strip()` with no arguments.
pub fn py_strip(value: &str) -> &str {
    value.trim_matches(py_isspace)
}

/// Python `str.lstrip()` with no arguments.
pub fn py_lstrip(value: &str) -> &str {
    value.trim_start_matches(py_isspace)
}

/// Python `str.split()` with no arguments.
pub fn py_split(value: &str) -> Vec<&str> {
    value
        .split(py_isspace)
        .filter(|part| !part.is_empty())
        .collect()
}

/// Python `str.splitlines()` (line boundaries dropped).
pub fn py_splitlines(value: &str) -> Vec<&str> {
    let mut lines = Vec::new();
    let mut start = 0;
    let mut chars = value.char_indices().peekable();
    while let Some((index, ch)) = chars.next() {
        let boundary = matches!(
            ch,
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
        if boundary {
            lines.push(&value[start..index]);
            let mut end = index + ch.len_utf8();
            if ch == '\r' {
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

/// Decode bytes the way `bytes.decode("ascii", "surrogateescape")` does.
pub fn sesc_decode(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|&b| {
            if b < 0x80 {
                b as char
            } else {
                char::from_u32(SESC_BASE + b as u32).expect("valid PUA code point")
            }
        })
        .collect()
}

/// Encode a sesc string back to bytes (`str.encode("utf-8", "surrogateescape")`).
pub fn sesc_encode(value: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(value.len());
    let mut buffer = [0u8; 4];
    for ch in value.chars() {
        let code = ch as u32;
        if (SESC_BASE + 0x80..=SESC_BASE + 0xff).contains(&code) {
            out.push((code - SESC_BASE) as u8);
        } else {
            out.extend_from_slice(ch.encode_utf8(&mut buffer).as_bytes());
        }
    }
    out
}

/// Python `email.utils._has_surrogates`.
pub fn has_surrogates(value: &str) -> bool {
    value
        .chars()
        .any(|ch| (SESC_BASE + 0x80..=SESC_BASE + 0xff).contains(&(ch as u32)))
}

/// Python `email.utils._sanitize`: raw bytes are re-read as UTF-8 with replacement.
pub fn sanitize(value: &str) -> String {
    if has_surrogates(value) {
        String::from_utf8_lossy(&sesc_encode(value)).into_owned()
    } else {
        value.to_owned()
    }
}

/// `str(Header(value, charset=UNKNOWN8BIT))`: every raw byte becomes U+FFFD.
pub fn replace_surrogates(value: &str) -> String {
    value
        .chars()
        .map(|ch| {
            if (SESC_BASE + 0x80..=SESC_BASE + 0xff).contains(&(ch as u32)) {
                '\u{fffd}'
            } else {
                ch
            }
        })
        .collect()
}

/// A Python codec as resolved by `codecs.lookup`.
#[derive(Debug, Clone, Copy)]
pub enum Codec {
    Ascii,
    Latin1,
    Utf8,
    Other(&'static Encoding),
}

/// Resolve a charset label like Python's `codecs.lookup` (None = `LookupError`).
pub fn lookup_codec(label: &str) -> Option<Codec> {
    // A name holding surrogate-escaped bytes cannot be converted to the C
    // string `codecs.lookup` takes: CPython raises UnicodeEncodeError, which
    // every caller handles like LookupError.
    if has_surrogates(label) {
        return None;
    }
    // CPython's `_Py_normalize_encoding`: lowercase ASCII alphanumerics and
    // dots; every other run of bytes (punctuation, spaces, non-ASCII)
    // becomes one `_`, dropped at both ends. So `-utf-8`, `utf--8` and
    // `utf-8"@` all name UTF-8.
    let mut key = String::with_capacity(label.len());
    let mut punct = false;
    for byte in label.bytes() {
        if byte.is_ascii_alphanumeric() || byte == b'.' {
            if punct && !key.is_empty() {
                key.push('_');
            }
            punct = false;
            key.push(byte.to_ascii_lowercase() as char);
        } else {
            punct = true;
        }
    }
    let normalized = key.replace('_', "-");
    match key.as_str() {
        "ascii" | "us_ascii" | "646" | "us" | "ansi_x3.4_1968" | "ansi_x3_4_1968" | "iso646_us"
        | "cp367" | "csascii" | "ibm367" | "iso_ir_6" => return Some(Codec::Ascii),
        "latin_1" | "latin1" | "latin" | "iso_8859_1" | "iso8859_1" | "8859" | "cp819" | "l1"
        | "iso_ir_100" | "csisolatin1" | "ibm819" => return Some(Codec::Latin1),
        "utf_8" | "utf8" | "u8" | "utf" | "utf8_ucs2" | "utf8_ucs4" | "cp65001" => {
            return Some(Codec::Utf8)
        }
        "eucgb2312_cn" => return Encoding::for_label(b"gb2312").map(Codec::Other),
        "big5_tw" => return Encoding::for_label(b"big5").map(Codec::Other),
        _ => {}
    }
    let encoding = Encoding::for_label(key.as_bytes())
        .or_else(|| Encoding::for_label(normalized.as_bytes()))?;
    if encoding == encoding_rs::REPLACEMENT {
        return None;
    }
    Some(Codec::Other(encoding))
}

/// `bytes.decode(codec)` with `errors="strict"`.
pub fn decode_strict(bytes: &[u8], codec: Codec) -> Option<String> {
    match codec {
        Codec::Ascii => bytes
            .is_ascii()
            .then(|| bytes.iter().map(|&b| b as char).collect()),
        Codec::Latin1 => Some(bytes.iter().map(|&b| b as char).collect()),
        Codec::Utf8 => std::str::from_utf8(bytes).ok().map(str::to_owned),
        Codec::Other(encoding) => encoding
            .decode_without_bom_handling_and_without_replacement(bytes)
            .map(|text| text.into_owned()),
    }
}

/// `bytes.decode(codec, "replace")`.
pub fn decode_replace(bytes: &[u8], codec: Codec) -> String {
    match codec {
        Codec::Ascii => bytes
            .iter()
            .map(|&b| if b < 0x80 { b as char } else { '\u{fffd}' })
            .collect(),
        Codec::Latin1 => bytes.iter().map(|&b| b as char).collect(),
        Codec::Utf8 => String::from_utf8_lossy(bytes).into_owned(),
        Codec::Other(encoding) => encoding.decode_without_bom_handling(bytes).0.into_owned(),
    }
}

/// `bytes.decode(codec, "surrogateescape")`, producing a sesc string.
fn decode_surrogateescape(bytes: &[u8], codec: Codec) -> String {
    match codec {
        Codec::Utf8 => {
            let mut out = String::new();
            let mut rest = bytes;
            loop {
                match std::str::from_utf8(rest) {
                    Ok(text) => {
                        out.push_str(text);
                        break;
                    }
                    Err(error) => {
                        let (valid, after) = rest.split_at(error.valid_up_to());
                        out.push_str(std::str::from_utf8(valid).expect("validated prefix"));
                        let bad = error.error_len().unwrap_or(after.len());
                        out.push_str(&sesc_decode(&after[..bad]));
                        rest = &after[bad..];
                    }
                }
            }
            out
        }
        Codec::Ascii => sesc_decode(bytes),
        other => decode_replace(bytes, other),
    }
}

/// Python `bytes(text, "raw-unicode-escape")`.
fn raw_unicode_escape(text: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(text.len());
    for ch in text.chars() {
        let code = ch as u32;
        if code < 0x100 {
            out.push(code as u8);
        } else if code <= 0xffff {
            out.extend_from_slice(format!("\\u{code:04x}").as_bytes());
        } else {
            out.extend_from_slice(format!("\\U{code:08x}").as_bytes());
        }
    }
    out
}

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

/// `binascii.a2b_base64(data)` in non-strict mode (`Err` = `binascii.Error`).
pub fn a2b_base64(data: &[u8]) -> Result<Vec<u8>, ()> {
    let mut out = Vec::with_capacity(data.len() * 3 / 4);
    let mut quad_pos = 0u8;
    let mut pads = 0u8;
    let mut left = 0u8;
    for &byte in data {
        if byte == b'=' {
            if quad_pos >= 2 {
                pads += 1;
                if quad_pos + pads >= 4 {
                    return Ok(out);
                }
            }
            continue;
        }
        let Some(value) = base64_value(byte) else {
            continue;
        };
        pads = 0;
        match quad_pos {
            0 => {
                left = value;
                quad_pos = 1;
            }
            1 => {
                out.push((left << 2) | (value >> 4));
                left = value & 0x0f;
                quad_pos = 2;
            }
            2 => {
                out.push((left << 4) | (value >> 2));
                left = value & 0x03;
                quad_pos = 3;
            }
            _ => {
                out.push((left << 6) | value);
                quad_pos = 0;
            }
        }
    }
    if quad_pos == 0 {
        Ok(out)
    } else {
        Err(())
    }
}

/// `email._encoded_words.decode_b` (lenient base64 with padding repair).
pub fn decode_b(encoded: &[u8]) -> Vec<u8> {
    if let Ok(value) = a2b_base64(encoded) {
        return value;
    }
    let mut padded = encoded.to_vec();
    padded.extend_from_slice(b"==");
    a2b_base64(&padded).unwrap_or_else(|()| encoded.to_vec())
}

fn hex_value(byte: u8) -> Option<u8> {
    (byte as char).to_digit(16).map(|d| d as u8)
}

/// `email._encoded_words.decode_q`.
fn decode_q(encoded: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(encoded.len());
    let mut i = 0;
    while i < encoded.len() {
        let byte = encoded[i];
        if byte == b'=' {
            if let (Some(hi), Some(lo)) = (
                encoded.get(i + 1).copied().and_then(hex_value),
                encoded.get(i + 2).copied().and_then(hex_value),
            ) {
                out.push((hi << 4) | lo);
                i += 3;
                continue;
            }
        }
        out.push(if byte == b'_' { b' ' } else { byte });
        i += 1;
    }
    out
}

/// `email._encoded_words.decode(ew)` → sesc text, or `Err` for an invalid word.
fn decode_encoded_word(ew: &str) -> Result<String, ()> {
    let pieces: Vec<&str> = ew.split('?').collect();
    if pieces.len() != 5 {
        return Err(());
    }
    let charset = pieces[1].split_once('*').map_or(pieces[1], |(cs, _)| cs);
    let cte_string = pieces[3];
    if !cte_string
        .chars()
        .all(|c| c.is_ascii() || has_surrogates(c.encode_utf8(&mut [0; 4])))
    {
        // `cte_string.encode("ascii", "surrogateescape")` raises UnicodeEncodeError (a ValueError).
        return Err(());
    }
    let raw = sesc_encode(cte_string);
    let bytes = match pieces[2].to_ascii_lowercase().as_str() {
        "q" => decode_q(&raw),
        "b" => decode_b(&raw),
        _ => return Err(()),
    };
    Ok(match lookup_codec(charset) {
        Some(codec) => match decode_strict(&bytes, codec) {
            Some(text) => text,
            None => decode_surrogateescape(&bytes, codec),
        },
        None => sesc_decode(&bytes),
    })
}

fn rfc2047_matcher() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"=\?[^?]*\?[qQbB]\?.*?\?=").expect("valid regex"))
}

pub(crate) enum EwError {
    /// `errors.HeaderParseError`: not an encoded word at all.
    NotEncodedWord,
    /// `_InvalidEwError`: looks like one but cannot be decoded.
    Invalid,
}

/// `_header_value_parser.get_encoded_word` → (decoded sesc text, remaining value).
pub(crate) fn get_encoded_word(value: &str) -> Result<(String, &str), EwError> {
    let body = &value[2..];
    let Some(first) = body.find("?=") else {
        return Err(EwError::NotEncodedWord);
    };
    let mut token_end = first;
    let remstr = &body[first + 2..];
    let mut rest = remstr;
    let rb = remstr.as_bytes();
    if rb.len() > 1
        && rb[0].is_ascii_hexdigit()
        && rb[1].is_ascii_hexdigit()
        && body[..first].matches('?').count() < 2
    {
        match remstr.find("?=") {
            Some(second) => {
                token_end = first + 2 + second;
                rest = &remstr[second + 2..];
            }
            None => {
                token_end = body.len();
                rest = "";
            }
        }
    }
    let token = &body[..token_end];
    let text = decode_encoded_word(&format!("=?{token}?=")).map_err(|()| EwError::Invalid)?;
    Ok((text, rest))
}

#[derive(Clone, Copy, PartialEq)]
enum TokenKind {
    Fws,
    EncodedWord,
    Vtext,
}

/// `str(get_unstructured(value))` on a sesc string; the result is still sesc.
pub fn decode_unstructured(value: &str) -> String {
    let mut tokens: Vec<(TokenKind, String)> = Vec::new();
    let mut rest = value;
    while !rest.is_empty() {
        if rest.starts_with([' ', '\t']) {
            let stripped = py_lstrip(rest);
            let fws = &rest[..rest.len() - stripped.len()];
            tokens.push((TokenKind::Fws, fws.to_owned()));
            rest = stripped;
            continue;
        }
        let mut valid_ew = true;
        if rest.starts_with("=?") {
            match get_encoded_word(rest) {
                Ok((text, remaining)) => {
                    let mut have_ws = true;
                    if let Some((kind, _)) = tokens.last() {
                        if *kind != TokenKind::Fws {
                            have_ws = false;
                        }
                    }
                    if have_ws
                        && tokens.len() > 1
                        && tokens[tokens.len() - 2].0 == TokenKind::EncodedWord
                    {
                        // EWWhiteSpaceTerminal: whitespace between encoded words renders as "".
                        tokens.last_mut().expect("len > 1").1.clear();
                    }
                    tokens.push((TokenKind::EncodedWord, text));
                    rest = remaining;
                    continue;
                }
                Err(EwError::Invalid) => valid_ew = false,
                Err(EwError::NotEncodedWord) => {}
            }
        }
        let split = rest.find([' ', '\t']).unwrap_or(rest.len());
        let mut token = &rest[..split];
        let mut remaining = &rest[split..];
        if valid_ew && rfc2047_matcher().is_match(token) {
            let index = rest.find("=?").expect("matcher found =?");
            token = &rest[..index];
            remaining = &rest[index..];
        }
        if token.is_empty() && remaining.len() == rest.len() {
            // Defensive progress guarantee (cannot happen with Python's grammar).
            let ch = rest.chars().next().expect("non-empty");
            token = &rest[..ch.len_utf8()];
            remaining = &rest[ch.len_utf8()..];
        }
        tokens.push((TokenKind::Vtext, token.to_owned()));
        rest = remaining;
    }
    tokens.into_iter().map(|(_, text)| text).collect()
}

/// Remove CR and LF (`EmailPolicy.header_fetch_parse`'s `linesep_splitter`).
pub fn unfold(value: &str) -> String {
    value.chars().filter(|&c| c != '\r' && c != '\n').collect()
}

/// `str(msg.get(name))` for an unstructured header under `policy.default`.
pub fn modern_unstructured(raw: &str) -> String {
    sanitize(&decode_unstructured(&unfold(raw)))
}

fn ecre() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?m)=\?([^?]*?)\?([qQbB])\?(.*?)\?=").expect("valid regex"))
}

/// `email.charset.Charset(name)`: lower-cased, aliased input charset name.
fn charset_name(name: &str) -> Option<String> {
    if !name.is_ascii() {
        return None; // errors.CharsetError
    }
    let lower = name.to_ascii_lowercase();
    let aliased = match lower.as_str() {
        "latin_1" | "latin-1" => "iso-8859-1",
        "latin_2" | "latin-2" => "iso-8859-2",
        "latin_3" | "latin-3" => "iso-8859-3",
        "latin_4" | "latin-4" => "iso-8859-4",
        "latin_5" | "latin-5" => "iso-8859-9",
        "latin_6" | "latin-6" => "iso-8859-10",
        "latin_7" | "latin-7" => "iso-8859-13",
        "latin_8" | "latin-8" => "iso-8859-14",
        "latin_9" | "latin-9" => "iso-8859-15",
        "latin_10" | "latin-10" => "iso-8859-16",
        "cp949" => "ks_c_5601-1987",
        "euc_jp" => "euc-jp",
        "euc_kr" => "euc-kr",
        "ascii" => "us-ascii",
        other => other,
    };
    Some(aliased.to_owned())
}

/// `Header.append(bytes, Charset(name))`: decode with the charset's input codec.
fn header_append_decode(bytes: &[u8], charset: &str) -> Option<String> {
    match charset {
        "us-ascii" => decode_strict(bytes, Codec::Ascii),
        // UNKNOWN8BIT chunks are rendered with `decode("ascii", "replace")` by `Header.__str__`.
        "unknown-8bit" => Some(decode_replace(bytes, Codec::Ascii)),
        "gb2312" => decode_strict(bytes, lookup_codec("eucgb2312_cn")?),
        "big5" => decode_strict(bytes, lookup_codec("big5_tw")?),
        other => decode_strict(bytes, lookup_codec(other)?),
    }
}

/// `str(make_header(decode_header(value)))`, or `None` when Python would raise.
fn legacy_make_header(value: &str) -> Option<String> {
    // decode_header: split into (text, Some((encoding, charset))) words.
    let mut words: Vec<(String, Option<(char, String)>)> = Vec::new();
    for line in py_splitlines(value) {
        let mut first = true;
        let mut position = 0;
        for capture in ecre().captures_iter(line) {
            let whole = capture.get(0).expect("match");
            let mut unencoded = &line[position..whole.start()];
            if first {
                unencoded = py_lstrip(unencoded);
                first = false;
            }
            if !unencoded.is_empty() {
                words.push((unencoded.to_owned(), None));
            }
            let charset = capture[1].to_lowercase();
            let encoding = capture[2]
                .to_ascii_lowercase()
                .chars()
                .next()
                .expect("q or b");
            words.push((capture[3].to_owned(), Some((encoding, charset))));
            position = whole.end();
        }
        let mut tail = &line[position..];
        if first {
            tail = py_lstrip(tail);
        }
        if !tail.is_empty() {
            words.push((tail.to_owned(), None));
        }
    }
    // Drop whitespace-only words between two encoded words.
    let mut drop = Vec::new();
    for n in 2..words.len() {
        if words[n].1.is_some() && words[n - 2].1.is_some() && py_is_all_space(&words[n - 1].0) {
            drop.push(n - 1);
        }
    }
    for index in drop.into_iter().rev() {
        words.remove(index);
    }
    // Decode each word to bytes.
    let mut decoded: Vec<(Vec<u8>, Option<String>)> = Vec::new();
    for (text, encoding) in words {
        match encoding {
            None => decoded.push((raw_unicode_escape(&text), None)),
            Some(('q', charset)) => {
                // quoprimime.header_decode: "_" → " ", then "=XX" → chr(0xXX).
                let spaced = text.replace('_', " ");
                let chars: Vec<char> = spaced.chars().collect();
                let mut out = String::new();
                let mut i = 0;
                while i < chars.len() {
                    if chars[i] == '='
                        && i + 2 < chars.len()
                        && chars[i + 1].is_ascii_hexdigit()
                        && chars[i + 2].is_ascii_hexdigit()
                    {
                        let code =
                            u32::from_str_radix(&format!("{}{}", chars[i + 1], chars[i + 2]), 16)
                                .expect("hex");
                        out.push(char::from_u32(code).expect("byte value"));
                        i += 3;
                    } else {
                        out.push(chars[i]);
                        i += 1;
                    }
                }
                decoded.push((raw_unicode_escape(&out), Some(charset)));
            }
            Some((_, charset)) => {
                let mut padded = text.clone();
                let pad_error = padded.chars().count() % 4;
                if pad_error != 0 {
                    padded.push_str(&"==="[..4 - pad_error]);
                }
                let bytes = a2b_base64(&raw_unicode_escape(&padded)).ok()?;
                decoded.push((bytes, Some(charset)));
            }
        }
    }
    // Collapse runs with the same charset.
    let mut collapsed: Vec<(Vec<u8>, Option<String>)> = Vec::new();
    for (word, charset) in decoded {
        match collapsed.last_mut() {
            Some((last_word, last_charset)) if *last_charset == charset => {
                if charset.is_none() {
                    last_word.push(b' ');
                }
                last_word.extend_from_slice(&word);
            }
            _ => collapsed.push((word, charset)),
        }
    }
    // make_header + Header._normalize.
    let mut chunks: Vec<(String, String)> = Vec::new();
    for (bytes, charset) in collapsed {
        let name = charset_name(charset.as_deref().unwrap_or("us-ascii"))?;
        let text = header_append_decode(&bytes, &name)?;
        match chunks.last_mut() {
            Some((last_text, last_name)) if *last_name == name => {
                last_text.push(' ');
                last_text.push_str(&text);
            }
            _ => chunks.push((text, name)),
        }
    }
    // Header.__str__.
    let nonctext = |c: char| py_isspace(c) || matches!(c, '(' | ')' | '\\');
    let mut out = String::new();
    let mut started = false;
    let mut last_ascii = true;
    let mut last_space = false;
    for (text, name) in chunks {
        let mut next_ascii = name == "us-ascii";
        if started {
            let has_space = text.chars().next().is_some_and(nonctext);
            if !last_ascii {
                if next_ascii && !has_space {
                    out.push(' ');
                    next_ascii = true;
                }
            } else if !next_ascii && !last_space {
                out.push(' ');
            }
        }
        last_space = text.chars().last().is_some_and(nonctext);
        last_ascii = next_ascii;
        out.push_str(&text);
        started = true;
    }
    Some(out)
}

/// `eml_extract._decode(value)`: legacy RFC 2047 decoding, falling back to the input.
pub fn legacy_decode(value: &str) -> String {
    if value.is_empty() {
        return String::new();
    }
    if !ecre().is_match(value) {
        return value.to_owned();
    }
    legacy_make_header(value).unwrap_or_else(|| value.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unit_cases() -> serde_json::Value {
        serde_json::from_str(include_str!(
            "../../tests/fixtures/pipeline/unit_cases.json"
        ))
        .unwrap()
    }

    #[test]
    fn charset_names_with_raw_bytes_are_unknown() {
        // `=?ISO-8859<0xd0>1?Q?...?=`: Python cannot look the name up and
        // decodes the bytes as ASCII with surrogateescape.
        assert!(lookup_codec(&sesc_decode(b"iso-8859\xd01")).is_none());
        let raw = sesc_decode(b"=?ISO-8859\xd01?Q?Gr=FC=DFe?= signed");
        assert_eq!(
            sanitize(&modern_unstructured(&raw)),
            "Gr\u{fffd}\u{fffd}e signed"
        );
    }

    #[test]
    fn legacy_decode_matches_python_golden_cases() {
        for case in unit_cases()["legacy_decode"].as_array().unwrap() {
            let input = case[0].as_str().unwrap();
            assert_eq!(
                legacy_decode(input),
                case[1].as_str().unwrap(),
                "input {input:?}"
            );
        }
    }

    #[test]
    fn modern_subject_matches_python_golden_cases() {
        for case in unit_cases()["modern_subject"].as_array().unwrap() {
            // The fixture stores the raw header bytes as a latin-1 string.
            let raw: Vec<u8> = case[0].as_str().unwrap().chars().map(|c| c as u8).collect();
            let header = sesc_decode(&raw);
            let value = py_lstrip_header(&header);
            let decoded = legacy_decode(&modern_unstructured(value));
            assert_eq!(decoded, case[1].as_str().unwrap(), "input {:?}", case[0]);
        }
    }

    /// `header_source_parse` strips leading " \t\r\n" from the value.
    fn py_lstrip_header(value: &str) -> &str {
        value.trim_start_matches([' ', '\t', '\r', '\n'])
    }

    #[test]
    fn base64_is_lenient_like_binascii() {
        assert_eq!(a2b_base64(b"YWJj").unwrap(), b"abc");
        assert_eq!(a2b_base64(b"YW Jj\n").unwrap(), b"abc");
        assert_eq!(a2b_base64(b"YQ==YQ==").unwrap(), b"a");
        assert!(a2b_base64(b"YWJ").is_err());
        assert_eq!(decode_b(b"YWJ"), b"ab");
        assert_eq!(decode_b(b"Y"), b"Y");
    }

    #[test]
    fn splitlines_and_whitespace_follow_python() {
        assert_eq!(
            py_splitlines("a\r\nb\rc\nd\u{0b}e"),
            vec!["a", "b", "c", "d", "e"]
        );
        assert_eq!(py_split(" a\u{1c}b  c "), vec!["a", "b", "c"]);
        assert!(py_is_all_space(" \t\u{a0}"));
        assert!(!py_is_all_space(""));
    }

    #[test]
    fn sesc_round_trip_and_sanitize() {
        let raw = "Pr\u{fc}fung".as_bytes();
        let sesc = sesc_decode(raw);
        assert!(has_surrogates(&sesc));
        assert_eq!(sesc_encode(&sesc), raw);
        assert_eq!(sanitize(&sesc), "Prüfung");
        assert_eq!(replace_surrogates(&sesc), "Pr\u{fffd}\u{fffd}fung");
    }

    #[test]
    fn codec_names_are_normalized_like_codecs_lookup() {
        // CPython: codecs.lookup("-utf-8"), ("utf-8\"@"), ("utf--8"), (" UTF 8 ")
        // all return utf-8; "-latin1" is iso8859-1; "u.t.f-8" is unknown.
        for label in ["-utf-8", "utf-8\"@", "utf--8", " UTF 8 ", "utf-8-"] {
            assert!(
                matches!(lookup_codec(label), Some(Codec::Utf8)),
                "{label:?}"
            );
        }
        assert!(matches!(lookup_codec("-latin1"), Some(Codec::Latin1)));
        assert!(lookup_codec("u.t.f-8").is_none());
        assert!(matches!(
            lookup_codec("Windows_1252"),
            Some(Codec::Other(_))
        ));
    }
}
