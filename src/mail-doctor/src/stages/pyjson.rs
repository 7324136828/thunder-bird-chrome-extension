//! Python-compatible JSON values for the report pipeline.
//!
//! The Python stages write JSON with `json.dumps(value, ensure_ascii=False)`
//! (JSONL records) or `json.dumps(value, indent=2, ensure_ascii=False)`
//! (reports), and read user files with `json.loads` into insertion-ordered
//! dicts. `serde_json::Value` sorts object keys, so this module keeps an
//! ordered value type plus serializers that reproduce Python's output byte for
//! byte, and the `str()` / `repr()` renderings the stages apply to JSON values.

use std::fmt::{self, Write as _};

use serde::de::{self, Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};

/// An insertion-ordered JSON value (Python `json.loads` result).
#[derive(Debug, Clone, PartialEq)]
pub enum Json {
    Null,
    Bool(bool),
    Int(i64),
    /// Integers that only fit in `u64`.
    UInt(u64),
    /// Larger integers (Python's `int` is unbounded), as decimal text.
    BigInt(String),
    Float(f64),
    Str(String),
    Array(Vec<Json>),
    Object(Vec<(String, Json)>),
}

impl Json {
    /// Build an object from `(key, value)` pairs, keeping their order.
    pub fn object<K: Into<String>>(pairs: impl IntoIterator<Item = (K, Json)>) -> Json {
        Json::Object(pairs.into_iter().map(|(k, v)| (k.into(), v)).collect())
    }

    pub fn str(value: impl Into<String>) -> Json {
        Json::Str(value.into())
    }

    /// `None` → `null`, otherwise a string.
    pub fn opt_str(value: Option<&str>) -> Json {
        value.map_or(Json::Null, Json::str)
    }

    /// Python `dict.get(key)`.
    pub fn get(&self, key: &str) -> Option<&Json> {
        match self {
            Json::Object(pairs) => pairs.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Json::Str(s) => Some(s),
            _ => None,
        }
    }

    /// Python truthiness (`bool(value)`).
    pub fn truthy(&self) -> bool {
        match self {
            Json::Null => false,
            Json::Bool(b) => *b,
            Json::Int(i) => *i != 0,
            Json::UInt(u) => *u != 0,
            Json::BigInt(_) => true,
            Json::Float(f) => *f != 0.0,
            Json::Str(s) => !s.is_empty(),
            Json::Array(items) => !items.is_empty(),
            Json::Object(pairs) => !pairs.is_empty(),
        }
    }

    /// Python `json.dumps(value, ensure_ascii=False)` (separators `", "` and `": "`).
    pub fn dumps(&self) -> String {
        let mut out = String::new();
        write_compact(self, &mut out);
        out
    }

    /// Python `json.dumps(value, indent=2, ensure_ascii=False)`.
    pub fn dumps_indent(&self) -> String {
        let mut out = String::new();
        write_indented(self, &mut out, 0);
        out
    }

    /// Python `str(value)` for a value produced by `json.loads`.
    pub fn py_str(&self) -> String {
        match self {
            Json::Str(s) => s.clone(),
            other => other.py_repr(),
        }
    }

    /// Python `repr(value)` for a value produced by `json.loads`.
    pub fn py_repr(&self) -> String {
        let mut out = String::new();
        write_repr(self, &mut out);
        out
    }

    /// Parse JSON text into an insertion-ordered value like Python's
    /// `json.loads` (the C scanner of CPython 3.13+): the same accepted
    /// syntax (`NaN`, `Infinity`, `-Infinity`, unbounded integers), dict
    /// semantics for duplicate keys, and `str(JSONDecodeError)` messages
    /// such as `Expecting value: line 1 column 1 (char 0)`.
    ///
    /// Deviation: a lone UTF-16 surrogate escape (`"\ud800"`), which Python
    /// keeps in its `str`, becomes U+FFFD.
    pub fn loads(text: &str) -> Result<Json, String> {
        py_loads(text)
    }

    /// Python `json.loads(path.read_text(encoding="utf-8"))` on the raw file
    /// bytes: strict UTF-8 decoding (with `str(UnicodeDecodeError)` as the
    /// error), universal-newline translation, then [`Json::loads`].
    pub fn loads_file_bytes(bytes: &[u8]) -> Result<Json, String> {
        let text = std::str::from_utf8(bytes).map_err(|error| utf8_error_message(bytes, &error))?;
        if text.contains('\r') {
            Json::loads(&text.replace("\r\n", "\n").replace('\r', "\n"))
        } else {
            Json::loads(text)
        }
    }
}

/// `str(UnicodeDecodeError)` raised by `bytes.decode("utf-8")`.
fn utf8_error_message(bytes: &[u8], error: &std::str::Utf8Error) -> String {
    let start = error.valid_up_to();
    let (length, reason) = match error.error_len() {
        None => (bytes.len() - start, "unexpected end of data"),
        Some(length) if matches!(bytes[start], 0x80..=0xc1 | 0xf5..=0xff) => {
            (length, "invalid start byte")
        }
        Some(length) => (length, "invalid continuation byte"),
    };
    if length <= 1 {
        format!(
            "'utf-8' codec can't decode byte 0x{:02x} in position {start}: {reason}",
            bytes[start]
        )
    } else {
        format!(
            "'utf-8' codec can't decode bytes in position {start}-{}: {reason}",
            start + length - 1
        )
    }
}

/// Nesting depth at which decoding stops with Python's `RecursionError`
/// message. CPython's own limit is higher (a few thousand levels); this one
/// keeps the recursive parser and renderers well inside a 2 MiB worker stack
/// (about 2 KiB per level in debug builds).
const MAX_JSON_DEPTH: usize = 200;
/// `sys.get_int_max_str_digits()` default.
const MAX_INT_DIGITS: usize = 4300;

enum ScanError {
    /// `StopIteration(idx)`: no JSON value starts at `idx`.
    Stop(usize),
    /// `JSONDecodeError(msg, doc, idx)`.
    Decode(&'static str, usize),
    /// Any other exception, already rendered with `str()`.
    Other(String),
}

/// `str(JSONDecodeError(msg, doc, pos))` for a byte offset into `doc`
/// (Python counts code points).
fn decode_error_message(doc: &str, msg: &str, byte_pos: usize) -> String {
    let before = &doc[..byte_pos];
    let pos = before.chars().count();
    let lineno = before.matches('\n').count() + 1;
    let colno = match before.rfind('\n') {
        Some(newline) => before[newline + 1..].chars().count() + 1,
        None => pos + 1,
    };
    format!("{msg}: line {lineno} column {colno} (char {pos})")
}

fn py_loads(doc: &str) -> Result<Json, String> {
    if doc.starts_with('\u{feff}') {
        return Err(decode_error_message(
            doc,
            "Unexpected UTF-8 BOM (decode using utf-8-sig)",
            0,
        ));
    }
    let scanner = Scanner {
        doc,
        bytes: doc.as_bytes(),
    };
    let failure = |error: ScanError| match error {
        ScanError::Stop(idx) => decode_error_message(doc, "Expecting value", idx),
        ScanError::Decode(msg, idx) => decode_error_message(doc, msg, idx),
        ScanError::Other(message) => message,
    };
    let (value, end) = scanner.scan_once(scanner.skip_ws(0), 0).map_err(failure)?;
    let end = scanner.skip_ws(end);
    if end != doc.len() {
        return Err(decode_error_message(doc, "Extra data", end));
    }
    Ok(value)
}

/// Port of the C scanner of CPython's `Modules/_json.c`, on byte offsets
/// (every delimiter is ASCII, so slices stay on character boundaries).
struct Scanner<'a> {
    doc: &'a str,
    bytes: &'a [u8],
}

impl Scanner<'_> {
    fn at(&self, idx: usize) -> Option<u8> {
        self.bytes.get(idx).copied()
    }

    fn skip_ws(&self, mut idx: usize) -> usize {
        while matches!(self.at(idx), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            idx += 1;
        }
        idx
    }

    fn is_digit(&self, idx: usize) -> bool {
        self.at(idx).is_some_and(|b| b.is_ascii_digit())
    }

    fn starts_with(&self, idx: usize, literal: &str) -> bool {
        self.bytes[idx..].starts_with(literal.as_bytes())
    }

    /// `scan_once_unicode`.
    fn scan_once(&self, idx: usize, depth: usize) -> Result<(Json, usize), ScanError> {
        let Some(first) = self.at(idx) else {
            return Err(ScanError::Stop(idx));
        };
        match first {
            b'"' => {
                let (text, end) = self.scan_string(idx + 1)?;
                Ok((Json::Str(text), end))
            }
            b'{' | b'[' => {
                let kind = if first == b'{' { "object" } else { "array" };
                if depth >= MAX_JSON_DEPTH {
                    return Err(ScanError::Other(format!(
                        "maximum recursion depth exceeded while decoding a JSON {kind} from a unicode string"
                    )));
                }
                if first == b'{' {
                    self.parse_object(idx + 1, depth + 1)
                } else {
                    self.parse_array(idx + 1, depth + 1)
                }
            }
            b'n' if self.starts_with(idx, "null") => Ok((Json::Null, idx + 4)),
            b't' if self.starts_with(idx, "true") => Ok((Json::Bool(true), idx + 4)),
            b'f' if self.starts_with(idx, "false") => Ok((Json::Bool(false), idx + 5)),
            b'N' if self.starts_with(idx, "NaN") => Ok((Json::Float(f64::NAN), idx + 3)),
            b'I' if self.starts_with(idx, "Infinity") => Ok((Json::Float(f64::INFINITY), idx + 8)),
            b'-' if self.starts_with(idx, "-Infinity") => {
                Ok((Json::Float(f64::NEG_INFINITY), idx + 9))
            }
            _ => self.match_number(idx),
        }
    }

    /// `_match_number_unicode`.
    fn match_number(&self, start: usize) -> Result<(Json, usize), ScanError> {
        let len = self.bytes.len();
        let mut idx = start;
        if self.at(idx) == Some(b'-') {
            idx += 1;
            if idx >= len {
                return Err(ScanError::Stop(start));
            }
        }
        match self.at(idx) {
            Some(b'1'..=b'9') => {
                idx += 1;
                while self.is_digit(idx) {
                    idx += 1;
                }
            }
            Some(b'0') => idx += 1,
            _ => return Err(ScanError::Stop(start)),
        }
        let mut is_float = false;
        if idx + 1 < len && self.bytes[idx] == b'.' && self.is_digit(idx + 1) {
            is_float = true;
            idx += 2;
            while self.is_digit(idx) {
                idx += 1;
            }
        }
        if idx + 1 < len && matches!(self.bytes[idx], b'e' | b'E') {
            let e_start = idx;
            idx += 1;
            if idx + 1 < len && matches!(self.bytes[idx], b'-' | b'+') {
                idx += 1;
            }
            while self.is_digit(idx) {
                idx += 1;
            }
            if self.is_digit(idx - 1) {
                is_float = true;
            } else {
                idx = e_start;
            }
        }
        let text = &self.doc[start..idx];
        if is_float {
            // `float(text)`: out-of-range values become +-inf like Python.
            let value = text.parse::<f64>().map_err(|_| {
                ScanError::Other(format!("could not convert string to float: '{text}'"))
            })?;
            return Ok((Json::Float(value), idx));
        }
        if let Ok(value) = text.parse::<i64>() {
            return Ok((Json::Int(value), idx));
        }
        if let Ok(value) = text.parse::<u64>() {
            return Ok((Json::UInt(value), idx));
        }
        let digits = text.trim_start_matches('-').len();
        if digits > MAX_INT_DIGITS {
            return Err(ScanError::Other(format!(
                "Exceeds the limit ({MAX_INT_DIGITS} digits) for integer string conversion: value has {digits} digits; use sys.set_int_max_str_digits() to increase the limit"
            )));
        }
        Ok((Json::BigInt(text.to_owned()), idx))
    }

    fn hex4(&self, idx: usize) -> Option<u32> {
        let digits = self.bytes.get(idx..idx + 4)?;
        digits.iter().try_fold(0u32, |acc, &digit| {
            Some(acc << 4 | (digit as char).to_digit(16)?)
        })
    }

    /// `scanstring_unicode(pystr, end, strict=True)`; `end` follows the
    /// opening quote.
    fn scan_string(&self, mut end: usize) -> Result<(String, usize), ScanError> {
        let len = self.bytes.len();
        let begin = end - 1;
        let mut out = String::new();
        loop {
            let mut next = end;
            let mut terminator = None;
            while next < len {
                let d = self.bytes[next];
                if d == b'"' || d == b'\\' {
                    terminator = Some(d);
                    break;
                }
                if d <= 0x1f {
                    return Err(ScanError::Decode("Invalid control character at", next));
                }
                next += 1;
            }
            let Some(terminator) = terminator else {
                return Err(ScanError::Decode("Unterminated string starting at", begin));
            };
            out.push_str(&self.doc[end..next]);
            next += 1;
            if terminator == b'"' {
                return Ok((out, next));
            }
            if next == len {
                return Err(ScanError::Decode("Unterminated string starting at", begin));
            }
            let escape = self.bytes[next];
            if escape != b'u' {
                end = next + 1;
                out.push(match escape {
                    b'"' => '"',
                    b'\\' => '\\',
                    b'/' => '/',
                    b'b' => '\u{8}',
                    b'f' => '\u{c}',
                    b'n' => '\n',
                    b'r' => '\r',
                    b't' => '\t',
                    _ => return Err(ScanError::Decode("Invalid \\escape", end - 2)),
                });
                continue;
            }
            next += 1;
            end = next + 4;
            if end >= len {
                return Err(ScanError::Decode("Invalid \\uXXXX escape", next - 1));
            }
            let Some(mut code) = self.hex4(next) else {
                return Err(ScanError::Decode("Invalid \\uXXXX escape", end - 5));
            };
            if (0xd800..=0xdbff).contains(&code)
                && end + 6 < len
                && self.bytes[end] == b'\\'
                && self.bytes[end + 1] == b'u'
            {
                let Some(low) = self.hex4(end + 2) else {
                    return Err(ScanError::Decode("Invalid \\uXXXX escape", end + 1));
                };
                if (0xdc00..=0xdfff).contains(&low) {
                    code = 0x10000 + ((code - 0xd800) << 10) + (low - 0xdc00);
                    end += 6;
                }
            }
            out.push(char::from_u32(code).unwrap_or('\u{fffd}'));
        }
    }

    /// `_parse_object_unicode`; `idx` follows the `{`. A duplicated key keeps
    /// its first position and takes the last value (dict semantics).
    fn parse_object(&self, idx: usize, depth: usize) -> Result<(Json, usize), ScanError> {
        let mut pairs: Vec<(String, Json)> = Vec::new();
        let mut positions: std::collections::HashMap<String, usize> =
            std::collections::HashMap::new();
        let mut idx = self.skip_ws(idx);
        if self.at(idx) != Some(b'}') {
            loop {
                if self.at(idx) != Some(b'"') {
                    return Err(ScanError::Decode(
                        "Expecting property name enclosed in double quotes",
                        idx,
                    ));
                }
                let (key, after_key) = self.scan_string(idx + 1)?;
                idx = self.skip_ws(after_key);
                if self.at(idx) != Some(b':') {
                    return Err(ScanError::Decode("Expecting ':' delimiter", idx));
                }
                let (value, after_value) = self.scan_once(self.skip_ws(idx + 1), depth)?;
                match positions.get(&key) {
                    Some(&position) => pairs[position].1 = value,
                    None => {
                        positions.insert(key.clone(), pairs.len());
                        pairs.push((key, value));
                    }
                }
                idx = self.skip_ws(after_value);
                if self.at(idx) == Some(b'}') {
                    break;
                }
                if self.at(idx) != Some(b',') {
                    return Err(ScanError::Decode("Expecting ',' delimiter", idx));
                }
                let comma = idx;
                idx = self.skip_ws(idx + 1);
                if self.at(idx) == Some(b'}') {
                    return Err(ScanError::Decode(
                        "Illegal trailing comma before end of object",
                        comma,
                    ));
                }
            }
        }
        Ok((Json::Object(pairs), idx + 1))
    }

    /// `_parse_array_unicode`; `idx` follows the `[`.
    fn parse_array(&self, idx: usize, depth: usize) -> Result<(Json, usize), ScanError> {
        let mut items = Vec::new();
        let mut idx = self.skip_ws(idx);
        if self.at(idx) != Some(b']') {
            loop {
                let (value, after_value) = self.scan_once(idx, depth)?;
                items.push(value);
                idx = self.skip_ws(after_value);
                if self.at(idx) == Some(b']') {
                    break;
                }
                if self.at(idx) != Some(b',') {
                    return Err(ScanError::Decode("Expecting ',' delimiter", idx));
                }
                let comma = idx;
                idx = self.skip_ws(idx + 1);
                if self.at(idx) == Some(b']') {
                    return Err(ScanError::Decode(
                        "Illegal trailing comma before end of array",
                        comma,
                    ));
                }
            }
        }
        Ok((Json::Array(items), idx + 1))
    }
}

/// Python `json.encoder.py_encode_basestring` with `ensure_ascii=False`.
pub fn encode_string(value: &str, out: &mut String) {
    out.push('"');
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

fn write_scalar(value: &Json, out: &mut String) -> bool {
    match value {
        Json::Null => out.push_str("null"),
        Json::Bool(true) => out.push_str("true"),
        Json::Bool(false) => out.push_str("false"),
        Json::Int(i) => {
            let _ = write!(out, "{i}");
        }
        Json::UInt(u) => {
            let _ = write!(out, "{u}");
        }
        Json::BigInt(digits) => out.push_str(digits),
        Json::Float(f) => out.push_str(&json_float(*f)),
        Json::Str(s) => encode_string(s, out),
        Json::Array(_) | Json::Object(_) => return false,
    }
    true
}

fn write_compact(value: &Json, out: &mut String) {
    if write_scalar(value, out) {
        return;
    }
    match value {
        Json::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                write_compact(item, out);
            }
            out.push(']');
        }
        Json::Object(pairs) => {
            out.push('{');
            for (i, (key, item)) in pairs.iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                encode_string(key, out);
                out.push_str(": ");
                write_compact(item, out);
            }
            out.push('}');
        }
        _ => unreachable!(),
    }
}

fn newline_indent(out: &mut String, level: usize) {
    out.push('\n');
    for _ in 0..level {
        out.push_str("  ");
    }
}

fn write_indented(value: &Json, out: &mut String, level: usize) {
    if write_scalar(value, out) {
        return;
    }
    match value {
        Json::Array(items) if items.is_empty() => out.push_str("[]"),
        Json::Object(pairs) if pairs.is_empty() => out.push_str("{}"),
        Json::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                newline_indent(out, level + 1);
                write_indented(item, out, level + 1);
            }
            newline_indent(out, level);
            out.push(']');
        }
        Json::Object(pairs) => {
            out.push('{');
            for (i, (key, item)) in pairs.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                newline_indent(out, level + 1);
                encode_string(key, out);
                out.push_str(": ");
                write_indented(item, out, level + 1);
            }
            newline_indent(out, level);
            out.push('}');
        }
        _ => unreachable!(),
    }
}

/// Python `float.__repr__` (shortest round-trip digits, exponent rules of `repr`).
pub fn py_float_repr(value: f64) -> String {
    if value.is_nan() {
        return "nan".into();
    }
    if value.is_infinite() {
        return if value > 0.0 {
            "inf".into()
        } else {
            "-inf".into()
        };
    }
    // `{:e}` yields the shortest round-trip digits, e.g. "1.5e-5" or "-1e16".
    let sci = format!("{value:e}");
    let (mantissa, exponent) = sci
        .split_once('e')
        .expect("LowerExp always has an exponent");
    let exponent: i32 = exponent.parse().expect("valid exponent");
    let negative = mantissa.starts_with('-');
    let digits: String = mantissa.chars().filter(|c| c.is_ascii_digit()).collect();
    let sign = if negative { "-" } else { "" };
    if (-4..16).contains(&exponent) {
        let point = exponent + 1; // position of the decimal point within `digits`
        let body = if point <= 0 {
            format!("0.{}{}", "0".repeat((-point) as usize), digits)
        } else if point as usize >= digits.len() {
            format!("{}{}.0", digits, "0".repeat(point as usize - digits.len()))
        } else {
            format!(
                "{}.{}",
                &digits[..point as usize],
                &digits[point as usize..]
            )
        };
        format!("{sign}{body}")
    } else {
        let mut mantissa = digits[..1].to_string();
        if digits.len() > 1 {
            mantissa.push('.');
            mantissa.push_str(&digits[1..]);
        }
        let exp_sign = if exponent < 0 { '-' } else { '+' };
        format!("{sign}{mantissa}e{exp_sign}{:02}", exponent.abs())
    }
}

/// Python `float.__repr__` as used by `json.dumps` (`NaN`/`Infinity` spelled the JSON way).
fn json_float(value: f64) -> String {
    if value.is_nan() {
        "NaN".into()
    } else if value.is_infinite() {
        if value > 0.0 {
            "Infinity".into()
        } else {
            "-Infinity".into()
        }
    } else {
        py_float_repr(value)
    }
}

/// Approximation of `str.isprintable()` for one character.
fn is_printable(ch: char) -> bool {
    let code = ch as u32;
    if code < 0x20 || (0x7f..=0xa0).contains(&code) || code == 0xad {
        return false;
    }
    !matches!(
        code,
        0x1680
            | 0x2000..=0x200f
            | 0x2028..=0x202f
            | 0x205f..=0x2064
            | 0x3000
            | 0xfeff
            | 0xe000..=0xf8ff
            | 0xfff9..=0xfffb
            | 0xf0000..
    )
}

/// Python `repr(str)`.
pub fn py_str_repr(value: &str, out: &mut String) {
    let quote = if value.contains('\'') && !value.contains('"') {
        '"'
    } else {
        '\''
    };
    out.push(quote);
    for ch in value.chars() {
        match ch {
            c if c == quote || c == '\\' => {
                out.push('\\');
                out.push(c);
            }
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            c if is_printable(c) => out.push(c),
            c if (c as u32) <= 0xff => {
                let _ = write!(out, "\\x{:02x}", c as u32);
            }
            c if (c as u32) <= 0xffff => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => {
                let _ = write!(out, "\\U{:08x}", c as u32);
            }
        }
    }
    out.push(quote);
}

fn write_repr(value: &Json, out: &mut String) {
    match value {
        Json::Null => out.push_str("None"),
        Json::Bool(true) => out.push_str("True"),
        Json::Bool(false) => out.push_str("False"),
        Json::Int(i) => {
            let _ = write!(out, "{i}");
        }
        Json::UInt(u) => {
            let _ = write!(out, "{u}");
        }
        Json::BigInt(digits) => out.push_str(digits),
        Json::Float(f) => out.push_str(&py_float_repr(*f)),
        Json::Str(s) => py_str_repr(s, out),
        Json::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                write_repr(item, out);
            }
            out.push(']');
        }
        Json::Object(pairs) => {
            out.push('{');
            for (i, (key, item)) in pairs.iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                py_str_repr(key, out);
                out.push_str(": ");
                write_repr(item, out);
            }
            out.push('}');
        }
    }
}

/// Python `f"{value:,}"` for integers.
pub fn thousands(value: i64) -> String {
    let digits = value.unsigned_abs().to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3 + 1);
    if value < 0 {
        out.push('-');
    }
    for (i, ch) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(ch);
    }
    out
}

impl<'de> Deserialize<'de> for Json {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(JsonVisitor)
    }
}

struct JsonVisitor;

impl<'de> Visitor<'de> for JsonVisitor {
    type Value = Json;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("any JSON value")
    }

    fn visit_bool<E: de::Error>(self, value: bool) -> Result<Json, E> {
        Ok(Json::Bool(value))
    }

    fn visit_i64<E: de::Error>(self, value: i64) -> Result<Json, E> {
        Ok(Json::Int(value))
    }

    fn visit_u64<E: de::Error>(self, value: u64) -> Result<Json, E> {
        Ok(i64::try_from(value).map_or(Json::UInt(value), Json::Int))
    }

    fn visit_f64<E: de::Error>(self, value: f64) -> Result<Json, E> {
        Ok(Json::Float(value))
    }

    fn visit_str<E: de::Error>(self, value: &str) -> Result<Json, E> {
        Ok(Json::Str(value.to_owned()))
    }

    fn visit_string<E: de::Error>(self, value: String) -> Result<Json, E> {
        Ok(Json::Str(value))
    }

    fn visit_unit<E: de::Error>(self) -> Result<Json, E> {
        Ok(Json::Null)
    }

    fn visit_none<E: de::Error>(self) -> Result<Json, E> {
        Ok(Json::Null)
    }

    fn visit_some<D: Deserializer<'de>>(self, deserializer: D) -> Result<Json, D::Error> {
        Json::deserialize(deserializer)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Json, A::Error> {
        let mut items = Vec::new();
        while let Some(item) = seq.next_element::<Json>()? {
            items.push(item);
        }
        Ok(Json::Array(items))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Json, A::Error> {
        // Python dicts keep the first position of a duplicated key and the last value.
        let mut pairs: Vec<(String, Json)> = Vec::new();
        while let Some((key, value)) = map.next_entry::<String, Json>()? {
            match pairs.iter_mut().find(|(k, _)| *k == key) {
                Some(slot) => slot.1 = value,
                None => pairs.push((key, value)),
            }
        }
        Ok(Json::Object(pairs))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compact_and_indented_output_match_python() {
        let value = Json::object([
            ("a", Json::str("x\"y\\\n\u{1}é")),
            (
                "b",
                Json::Array(vec![Json::Int(1), Json::Null, Json::Bool(true)]),
            ),
            ("c", Json::Object(vec![])),
            ("d", Json::Array(vec![])),
        ]);
        assert_eq!(
            value.dumps(),
            r#"{"a": "x\"y\\\n\u0001é", "b": [1, null, true], "c": {}, "d": []}"#
        );
        assert_eq!(
            value.dumps_indent(),
            "{\n  \"a\": \"x\\\"y\\\\\\n\\u0001é\",\n  \"b\": [\n    1,\n    null,\n    true\n  ],\n  \"c\": {},\n  \"d\": []\n}"
        );
    }

    #[test]
    fn loads_keeps_order_and_python_duplicate_semantics() {
        let value = Json::loads(r#"{"b": 1, "a": 2, "b": 3}"#).unwrap();
        assert_eq!(
            value,
            Json::object([("b", Json::Int(3)), ("a", Json::Int(2))])
        );
    }

    #[test]
    fn python_str_and_repr() {
        let value =
            Json::loads(r#"["a", 1, null, true, 1.5, {"k": "it's"}, 1e16, 0.0001, 1e-5]"#).unwrap();
        assert_eq!(
            value.py_str(),
            r#"['a', 1, None, True, 1.5, {'k': "it's"}, 1e+16, 0.0001, 1e-05]"#
        );
        assert_eq!(Json::str("plain").py_str(), "plain");
        assert_eq!(py_float_repr(100.0), "100.0");
        assert_eq!(py_float_repr(-2.5e-7), "-2.5e-07");
        assert_eq!(py_float_repr(123456789012345.6), "123456789012345.6");
    }

    #[test]
    fn loads_errors_match_python_json_decode_error() {
        // `str(error)` of CPython's `json.loads` (C scanner).
        for (input, expected) in [
            ("", "Expecting value: line 1 column 1 (char 0)"),
            ("[", "Expecting value: line 1 column 2 (char 1)"),
            (
                "{",
                "Expecting property name enclosed in double quotes: line 1 column 2 (char 1)",
            ),
            (
                "{\"a\" 1}",
                "Expecting ':' delimiter: line 1 column 6 (char 5)",
            ),
            (
                "{\"a\":1 \"b\":2}",
                "Expecting ',' delimiter: line 1 column 8 (char 7)",
            ),
            ("[1 2]", "Expecting ',' delimiter: line 1 column 4 (char 3)"),
            (
                "{'a':1}",
                "Expecting property name enclosed in double quotes: line 1 column 2 (char 1)",
            ),
            (
                "\"abc",
                "Unterminated string starting at: line 1 column 1 (char 0)",
            ),
            ("\"a\\x\"", "Invalid \\escape: line 1 column 3 (char 2)"),
            (
                "\"\\uZZZZ\"",
                "Invalid \\uXXXX escape: line 1 column 3 (char 2)",
            ),
            (
                "\"\\u12\"",
                "Invalid \\uXXXX escape: line 1 column 3 (char 2)",
            ),
            (
                "\"\\ud83d\\uZZZZ\"",
                "Invalid \\uXXXX escape: line 1 column 9 (char 8)",
            ),
            (
                "\"a\u{1}b\"",
                "Invalid control character at: line 1 column 3 (char 2)",
            ),
            ("tru", "Expecting value: line 1 column 1 (char 0)"),
            ("-", "Expecting value: line 1 column 1 (char 0)"),
            ("01", "Extra data: line 1 column 2 (char 1)"),
            ("1.", "Extra data: line 1 column 2 (char 1)"),
            ("{\"a\":1}\n\n x", "Extra data: line 3 column 2 (char 10)"),
            (
                "[\"é😀\", 1 2]",
                "Expecting ',' delimiter: line 1 column 10 (char 9)",
            ),
            (
                "\u{feff}{}",
                "Unexpected UTF-8 BOM (decode using utf-8-sig): line 1 column 1 (char 0)",
            ),
            // CPython 3.13+ wording, reported at the comma.
            (
                "{\"a\":1,}",
                "Illegal trailing comma before end of object: line 1 column 7 (char 6)",
            ),
            (
                "[1,\n]",
                "Illegal trailing comma before end of array: line 1 column 3 (char 2)",
            ),
        ] {
            assert_eq!(Json::loads(input).unwrap_err(), expected, "{input:?}");
        }
        assert!(Json::loads(&"[".repeat(MAX_JSON_DEPTH + 1))
            .unwrap_err()
            .starts_with("maximum recursion depth exceeded while decoding a JSON array"));
        assert!(Json::loads(&"1".repeat(4301)).unwrap_err().starts_with(
            "Exceeds the limit (4300 digits) for integer string conversion: value has 4301 digits"
        ));
    }

    #[test]
    fn loads_accepts_python_extensions() {
        let value = Json::loads(
            "[NaN, Infinity, -Infinity, 1e400, 123456789012345678901234567890, -0, 1E5, \"\\ud83d\\ude00\\/\"]",
        )
        .unwrap();
        assert_eq!(
            value.py_repr(),
            "[nan, inf, -inf, inf, 123456789012345678901234567890, 0, 100000.0, '😀/']"
        );
        assert_eq!(
            Json::loads("{\"note\": 12345678901234567890123}")
                .unwrap()
                .get("note")
                .unwrap()
                .py_str(),
            "12345678901234567890123"
        );
    }

    #[test]
    fn file_bytes_are_decoded_like_read_text() {
        assert_eq!(
            Json::loads_file_bytes(b"\xff\xfe").unwrap_err(),
            "'utf-8' codec can't decode byte 0xff in position 0: invalid start byte"
        );
        assert_eq!(
            Json::loads_file_bytes(b"a\xe2\x82").unwrap_err(),
            "'utf-8' codec can't decode bytes in position 1-2: unexpected end of data"
        );
        assert_eq!(
            Json::loads_file_bytes(b"\xe2\x82(").unwrap_err(),
            "'utf-8' codec can't decode bytes in position 0-1: invalid continuation byte"
        );
        assert_eq!(
            Json::loads_file_bytes(b"\xed\xa0\x80").unwrap_err(),
            "'utf-8' codec can't decode byte 0xed in position 0: invalid continuation byte"
        );
        // Universal newlines shift the reported positions like Python.
        assert_eq!(
            Json::loads_file_bytes(b"{\r\n \"a\": \r\n}").unwrap_err(),
            "Expecting value: line 3 column 1 (char 9)"
        );
    }

    #[test]
    fn thousands_separator() {
        assert_eq!(thousands(0), "0");
        assert_eq!(thousands(999), "999");
        assert_eq!(thousands(1000), "1,000");
        assert_eq!(thousands(1234567), "1,234,567");
        assert_eq!(thousands(-1234), "-1,234");
    }
}
