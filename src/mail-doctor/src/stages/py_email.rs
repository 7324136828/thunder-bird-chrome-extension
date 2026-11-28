//! Emulation of Python's `email` message model as used by
//! `services/stages/eml_extract.py`:
//!
//! * `email.feedparser.FeedParser` (structure, boundaries, preamble/epilogue),
//! * `email.message.Message` accessors (`get_content_type`, `get_param`,
//!   `get_filename`, `get_payload(decode=True)`, `walk`),
//! * `email.generator.BytesGenerator` with the `compat32` policy, which the
//!   original uses to size mbox messages via `len(msg.as_bytes())`,
//! * `mailbox.mbox` message splitting (POSIX `os.linesep == "\n"` semantics).
//!
//! Header values are kept as "sesc" strings (see [`super::py_header`]), body
//! payloads as raw bytes; both are lossless views of the input.

use std::collections::VecDeque;
use std::sync::OnceLock;

use regex::Regex;

use super::py_header::{
    decode_b, has_surrogates, py_isspace, py_lstrip, py_splitlines, py_strip, replace_surrogates,
    sanitize, sesc_decode, sesc_encode, unfold,
};
use super::py_hvp::{content_transfer_encoding_cte, mime_header_str, MimeHeader};

/// The parsing policy, which decides how header values are presented.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Policy {
    /// `email.policy.default` (used for `.eml` files).
    Default,
    /// `email.policy.compat32` (used by `mailbox.mbox`).
    Compat32,
}

#[derive(Debug, Clone)]
enum Payload {
    None,
    Text(Vec<u8>),
    Parts(Vec<usize>),
}

#[derive(Debug, Clone)]
struct Part {
    /// `(name, value)` as stored by `header_source_parse` (sesc strings).
    headers: Vec<(String, String)>,
    payload: Payload,
    default_type: &'static str,
    preamble: Option<Vec<u8>>,
    epilogue: Option<Vec<u8>>,
}

impl Part {
    fn new(default_type: &'static str) -> Self {
        Self {
            headers: Vec::new(),
            payload: Payload::None,
            default_type,
            preamble: None,
            epilogue: None,
        }
    }
}

/// A parsed message tree. Part `0` is the root.
#[derive(Debug, Clone)]
pub struct Message {
    policy: Policy,
    parts: Vec<Part>,
}

/// A MIME parameter value (`email.utils.decode_params` output).
#[derive(Debug, Clone, PartialEq)]
pub enum ParamValue {
    Text(String),
    /// RFC 2231 `(charset, language, value)`.
    Rfc2231(Option<String>, Option<String>, String),
}

/// `binascii.a2b_uu(line)`; `None` for `binascii.Error`.
fn a2b_uu(line: &[u8]) -> Option<Vec<u8>> {
    // CPython reads the terminating NUL of an empty buffer as the length.
    let (first, mut rest): (u8, &[u8]) = match line.split_first() {
        Some((&first, rest)) => (first, rest),
        None => (0, &[]),
    };
    let mut bin_len = usize::from(first.wrapping_sub(b' ') & 0o77);
    let mut out = Vec::with_capacity(bin_len);
    let (mut leftchar, mut leftbits) = (0u32, 0u32);
    while bin_len > 0 {
        let ch = match rest.split_first() {
            None => 0,
            Some((&ch, tail)) => {
                rest = tail;
                if ch == b'\n' || ch == b'\r' {
                    0
                } else if !(b' '..=b' ' + 64).contains(&ch) {
                    return None; // "Illegal char"
                } else {
                    (ch - b' ') & 0o77
                }
            }
        };
        leftchar = (leftchar << 6) | u32::from(ch);
        leftbits += 6;
        if leftbits >= 8 {
            leftbits -= 8;
            out.push((leftchar >> leftbits) as u8);
            leftchar &= (1 << leftbits) - 1;
            bin_len -= 1;
        }
    }
    if rest
        .iter()
        .any(|&ch| ch != b' ' && ch != b' ' + 64 && ch != b'\n' && ch != b'\r')
    {
        return None; // "Trailing garbage"
    }
    Some(out)
}

/// Whether `int(mode, base=8)` succeeds (surrounding whitespace, a sign, a
/// `0o` prefix and single `_` between digits are accepted).
fn is_octal_int(mode: &[u8]) -> bool {
    let text = mode.trim_ascii();
    let text = text
        .strip_prefix(b"+")
        .or_else(|| text.strip_prefix(b"-"))
        .unwrap_or(text);
    let digits = text
        .strip_prefix(b"0o")
        .or_else(|| text.strip_prefix(b"0O"))
        .map(|rest| rest.strip_prefix(b"_").unwrap_or(rest))
        .unwrap_or(text);
    !digits.is_empty()
        && !digits.starts_with(b"_")
        && !digits.ends_with(b"_")
        && !digits.windows(2).any(|pair| pair == b"__")
        && digits
            .iter()
            .all(|&b| (b'0'..=b'7').contains(&b) || b == b'_')
}

/// `bytes.splitlines()` (`\n`, `\r`, `\r\n`; terminators dropped).
fn py_bytes_splitlines(data: &[u8]) -> Vec<&[u8]> {
    let mut lines = Vec::new();
    let (mut start, mut i) = (0, 0);
    while i < data.len() {
        match data[i] {
            b'\n' => {
                lines.push(&data[start..i]);
                i += 1;
                start = i;
            }
            b'\r' => {
                lines.push(&data[start..i]);
                i += if data.get(i + 1) == Some(&b'\n') {
                    2
                } else {
                    1
                };
                start = i;
            }
            _ => i += 1,
        }
    }
    if start < data.len() {
        lines.push(&data[start..]);
    }
    lines
}

/// `email.message._decode_uu`; `None` for its `ValueError`, after which
/// `get_payload(decode=True)` returns the payload undecoded.
fn decode_uu(encoded: &[u8]) -> Option<Vec<u8>> {
    let mut lines = py_bytes_splitlines(encoded).into_iter();
    loop {
        let line = lines.next()?; // "`begin` line not found"
        if let Some(rest) = line.strip_prefix(b"begin ") {
            let mode = rest.split(|&b| b == b' ').next().unwrap_or_default();
            if is_octal_int(mode) {
                break;
            }
        }
    }
    let mut decoded = Vec::new();
    for line in lines {
        if line.is_empty() {
            return None; // "Truncated input"
        }
        if line.trim_ascii() == b"end" {
            break;
        }
        let chunk = match a2b_uu(line) {
            Some(chunk) => chunk,
            None => {
                // "Workaround for broken uuencoders by /Fredrik Lundh".
                let nbytes = (usize::from(line[0].wrapping_sub(32) & 63) * 4 + 5) / 3;
                a2b_uu(&line[..nbytes.min(line.len())])?
            }
        };
        decoded.extend_from_slice(&chunk);
    }
    Some(decoded)
}

/// `email.message._splitparam`.
fn splitparam(value: &str) -> (&str, Option<&str>) {
    match value.split_once(';') {
        Some((a, b)) => (py_strip_str(a), Some(py_strip_str(b))),
        None => (py_strip_str(value), None),
    }
}

fn py_strip_str(value: &str) -> &str {
    value.trim_matches(py_isspace)
}

/// `email.message._parseparam`.
fn parseparam(value: &str) -> Vec<String> {
    let mut s = format!(";{value}");
    let mut plist = Vec::new();
    while s.starts_with(';') {
        s.remove(0);
        let quote_parity = |text: &str, end: usize| {
            let head = &text[..end];
            (head.matches('"').count() - head.matches("\\\"").count()) % 2 == 1
        };
        let mut end = s.find(';');
        while let Some(e) = end {
            if e > 0 && quote_parity(&s, e) {
                end = s[e + 1..].find(';').map(|next| e + 1 + next);
            } else {
                break;
            }
        }
        let end = end.unwrap_or(s.len());
        let mut field = s[..end].to_owned();
        if let Some(i) = field.find('=') {
            field = format!(
                "{}={}",
                py_strip_str(&field[..i]).to_lowercase(),
                py_strip_str(&field[i + 1..])
            );
        }
        plist.push(py_strip_str(&field).to_owned());
        s = s[end..].to_owned();
    }
    plist
}

/// `email.utils.unquote`.
pub fn unquote(value: &str) -> String {
    if value.chars().count() > 1 {
        if value.starts_with('"') && value.ends_with('"') {
            return value[1..value.len() - 1]
                .replace("\\\\", "\\")
                .replace("\\\"", "\"");
        }
        if value.starts_with('<') && value.ends_with('>') {
            return value[1..value.len() - 1].to_owned();
        }
    }
    value.to_owned()
}

fn quote(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

/// `urllib.parse.unquote(s, encoding="latin-1")`.
fn percent_unquote_latin1(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = String::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && bytes[i + 1].is_ascii_hexdigit()
            && bytes[i + 2].is_ascii_hexdigit()
        {
            let byte = u8::from_str_radix(&value[i + 1..i + 3], 16).expect("hex digits");
            out.push(byte as char);
            i += 3;
            continue;
        }
        let ch = value[i..].chars().next().expect("char boundary");
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

fn rfc2231_continuation() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"^(?P<name>[A-Za-z0-9_]+)\*((?P<num>[0-9]+)\*?)?$").expect("valid regex")
    })
}

/// One RFC 2231 continuation segment: (number, value, percent-encoded).
type Continuation = (Option<u64>, String, bool);

/// `email.utils.decode_params`.
fn decode_params(params: Vec<(String, String)>) -> Vec<(String, ParamValue)> {
    let mut iter = params.into_iter();
    let mut new_params: Vec<(String, ParamValue)> = Vec::new();
    if let Some((name, value)) = iter.next() {
        new_params.push((name, ParamValue::Text(value)));
    }
    // name → [(num, value, encoded)] in first-seen order.
    let mut continuations: Vec<(String, Vec<Continuation>)> = Vec::new();
    for (name, value) in iter {
        let encoded = name.ends_with('*');
        let value = unquote(&value);
        if let Some(caps) = rfc2231_continuation().captures(&name) {
            let base = caps["name"].to_owned();
            let num = caps
                .name("num")
                .and_then(|m| m.as_str().parse::<u64>().ok());
            match continuations.iter_mut().find(|(n, _)| *n == base) {
                Some((_, list)) => list.push((num, value, encoded)),
                None => continuations.push((base, vec![(num, value, encoded)])),
            }
        } else {
            new_params.push((name, ParamValue::Text(format!("\"{}\"", quote(&value)))));
        }
    }
    for (name, mut list) in continuations {
        // Python sorts (num, value, encoded) tuples; None sorts before numbers here.
        list.sort_by(|a, b| {
            a.0.cmp(&b.0)
                .then_with(|| a.1.cmp(&b.1))
                .then_with(|| a.2.cmp(&b.2))
        });
        let mut extended = false;
        let mut joined = String::new();
        for (_, segment, encoded) in list {
            if encoded {
                joined.push_str(&percent_unquote_latin1(&segment));
                extended = true;
            } else {
                joined.push_str(&segment);
            }
        }
        let value = quote(&joined);
        if extended {
            // email.utils.decode_rfc2231
            let parts: Vec<&str> = value.splitn(3, '\'').collect();
            if parts.len() <= 2 {
                new_params.push((
                    name,
                    ParamValue::Rfc2231(None, None, format!("\"{value}\"")),
                ));
            } else {
                new_params.push((
                    name,
                    ParamValue::Rfc2231(
                        Some(parts[0].to_owned()),
                        Some(parts[1].to_owned()),
                        format!("\"{}\"", parts[2]),
                    ),
                ));
            }
        } else {
            new_params.push((name, ParamValue::Text(format!("\"{value}\""))));
        }
    }
    new_params
}

/// `email.utils.collapse_rfc2231_value`.
fn collapse_rfc2231_value(value: &ParamValue) -> String {
    match value {
        ParamValue::Text(text) => unquote(text),
        ParamValue::Rfc2231(charset, _, text) => {
            let charset = charset.clone().unwrap_or_else(|| "us-ascii".to_owned());
            let raw: Vec<u8> = text
                .chars()
                .map(|c| if (c as u32) < 0x100 { c as u8 } else { b'?' })
                .collect();
            match super::py_header::lookup_codec(&charset) {
                Some(codec) => super::py_header::decode_replace(&raw, codec),
                None => unquote(text),
            }
        }
    }
}

/// `binascii.a2b_qp(data, header=False)` (used by `quopri.decodestring`).
pub fn a2b_qp(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    let mut i = 0;
    while i < data.len() {
        if data[i] == b'=' {
            i += 1;
            if i >= data.len() {
                break;
            }
            if data[i] == b'\n' || data[i] == b'\r' {
                if data[i] != b'\n' {
                    while i < data.len() && data[i] != b'\n' {
                        i += 1;
                    }
                }
                if i < data.len() {
                    i += 1;
                }
            } else if data[i] == b'=' {
                out.push(b'=');
                i += 1;
            } else if i + 1 < data.len()
                && data[i].is_ascii_hexdigit()
                && data[i + 1].is_ascii_hexdigit()
            {
                let hex = std::str::from_utf8(&data[i..i + 2]).expect("ascii");
                out.push(u8::from_str_radix(hex, 16).expect("hex"));
                i += 2;
            } else {
                out.push(b'=');
            }
        } else {
            out.push(data[i]);
            i += 1;
        }
    }
    out
}

/// Split into lines keeping `\r\n`, `\r` or `\n` endings (`StringIO(newline="")`).
fn split_lines(data: &[u8]) -> VecDeque<&[u8]> {
    let mut lines = VecDeque::new();
    let mut start = 0;
    let mut i = 0;
    while i < data.len() {
        match data[i] {
            b'\n' => {
                lines.push_back(&data[start..=i]);
                start = i + 1;
            }
            b'\r' => {
                let end = if data.get(i + 1) == Some(&b'\n') {
                    i + 1
                } else {
                    i
                };
                lines.push_back(&data[start..=end]);
                i = end;
                start = end + 1;
            }
            _ => {}
        }
        i += 1;
    }
    if start < data.len() {
        lines.push_back(&data[start..]);
    }
    lines
}

/// `NLCRE_eol`: length of the line ending at the end of `data`.
fn eol_len(data: &[u8]) -> usize {
    if data.ends_with(b"\r\n") {
        2
    } else if data.ends_with(b"\n") || data.ends_with(b"\r") {
        1
    } else {
        0
    }
}

/// `NLCRE.match(line)`: the line starts with a line ending (a blank line).
fn starts_with_newline(line: &[u8]) -> bool {
    matches!(line.first(), Some(b'\r' | b'\n'))
}

/// `headerRE = ^(From |[\041-\071\073-\176]*:|[\t ])`.
fn is_header_line(line: &[u8]) -> bool {
    if line.starts_with(b"From ") || matches!(line.first(), Some(b'\t' | b' ')) {
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

struct BoundaryMatch {
    end: bool,
    linesep: bool,
}

/// `boundaryre.match(line)` for `separator = "--" + boundary`.
fn boundary_match(line: &[u8], separator: &Option<Vec<u8>>) -> Option<BoundaryMatch> {
    let separator = separator.as_ref()?;
    let rest = line.strip_prefix(separator.as_slice())?;
    let tail_ok = |tail: &[u8]| {
        let trimmed = {
            let mut t = tail;
            while let Some((&first, after)) = t.split_first() {
                if first == b' ' || first == b'\t' {
                    t = after;
                } else {
                    break;
                }
            }
            t
        };
        match trimmed {
            b"" | b"\n" | b"\r" | b"\r\n" => Some(!trimmed.is_empty()),
            _ => None,
        }
    };
    if let Some(after) = rest.strip_prefix(b"--") {
        if let Some(linesep) = tail_ok(after) {
            return Some(BoundaryMatch { end: true, linesep });
        }
    }
    tail_ok(rest).map(|linesep| BoundaryMatch {
        end: false,
        linesep,
    })
}

enum Matcher {
    Newline,
    Boundary(Option<Vec<u8>>),
}

impl Matcher {
    fn matches(&self, line: &[u8]) -> bool {
        match self {
            Matcher::Newline => starts_with_newline(line),
            Matcher::Boundary(separator) => boundary_match(line, separator).is_some(),
        }
    }
}

/// `email.feedparser.BufferedSubFile` with all data already pushed and closed.
struct Input<'a> {
    lines: VecDeque<&'a [u8]>,
    eof_stack: Vec<Matcher>,
}

impl<'a> Input<'a> {
    fn readline(&mut self) -> Option<&'a [u8]> {
        let line = self.lines.pop_front()?;
        if self
            .eof_stack
            .iter()
            .rev()
            .any(|matcher| matcher.matches(line))
        {
            self.lines.push_front(line);
            return None;
        }
        Some(line)
    }

    fn unreadline(&mut self, line: &'a [u8]) {
        self.lines.push_front(line);
    }
}

struct Parser<'a> {
    input: Input<'a>,
    message: Message,
    stack: Vec<usize>,
    last: usize,
}

impl<'a> Parser<'a> {
    fn cur(&self) -> usize {
        *self.stack.last().expect("message stack is not empty")
    }

    fn new_message(&mut self) -> usize {
        let default_type = match self.stack.last() {
            Some(&parent) if self.message.content_type(parent) == "multipart/digest" => {
                "message/rfc822"
            }
            _ => "text/plain",
        };
        let index = self.message.parts.len();
        self.message.parts.push(Part::new(default_type));
        if let Some(&parent) = self.stack.last() {
            let part = &mut self.message.parts[parent];
            match &mut part.payload {
                Payload::Parts(children) => children.push(index),
                payload => *payload = Payload::Parts(vec![index]),
            }
        }
        self.stack.push(index);
        self.last = index;
        index
    }

    fn pop_message(&mut self) {
        self.stack.pop();
    }

    fn read_rest(&mut self) -> Vec<u8> {
        let mut out = Vec::new();
        while let Some(line) = self.input.readline() {
            out.extend_from_slice(line);
        }
        out
    }

    fn parse_headers(&mut self, lines: &[&'a [u8]]) {
        let cur = self.cur();
        let mut pending: Vec<&[u8]> = Vec::new();
        let store = |message: &mut Message, pending: &[&[u8]]| {
            if let Some(header) = header_source_parse(pending) {
                message.parts[cur].headers.push(header);
            }
        };
        for (lineno, &line) in lines.iter().enumerate() {
            if matches!(line.first(), Some(b' ' | b'\t')) {
                if pending.is_empty() {
                    continue; // FirstHeaderLineIsContinuationDefect
                }
                pending.push(line);
                continue;
            }
            if !pending.is_empty() {
                store(&mut self.message, &pending);
                pending.clear();
            }
            if line.starts_with(b"From ") {
                if lineno == 0 {
                    continue; // unix-from envelope line
                } else if lineno == lines.len() - 1 {
                    self.input.unreadline(line);
                    return;
                } else {
                    continue; // MisplacedEnvelopeHeaderDefect
                }
            }
            match line.iter().position(|&b| b == b':') {
                Some(0) | None => continue, // "Missing header name."
                Some(_) => pending.push(line),
            }
        }
        if !pending.is_empty() {
            store(&mut self.message, &pending);
        }
    }

    fn parsegen(&mut self) {
        self.new_message();
        let mut headers = Vec::new();
        while let Some(line) = self.input.readline() {
            if !is_header_line(line) {
                if !starts_with_newline(line) {
                    self.input.unreadline(line);
                }
                break;
            }
            headers.push(line);
        }
        self.parse_headers(&headers);
        let cur = self.cur();
        let content_type = self.message.content_type(cur);
        if content_type == "message/delivery-status" {
            loop {
                self.input.eof_stack.push(Matcher::Newline);
                self.parsegen();
                self.pop_message();
                self.input.eof_stack.pop();
                let _ = self.input.readline();
                match self.input.readline() {
                    None => break,
                    Some(line) => self.input.unreadline(line),
                }
            }
            return;
        }
        let maintype = content_type.split('/').next().unwrap_or("").to_owned();
        if maintype == "message" {
            self.parsegen();
            self.pop_message();
            return;
        }
        if maintype == "multipart" {
            self.parse_multipart(cur);
            return;
        }
        let body = self.read_rest();
        self.message.parts[cur].payload = Payload::Text(body);
    }

    fn parse_multipart(&mut self, cur: usize) {
        let Some(boundary) = self.message.boundary(cur) else {
            let body = self.read_rest();
            self.message.parts[cur].payload = Payload::Text(body);
            return;
        };
        let separator_text = format!("--{boundary}");
        let separator = separator_text
            .is_ascii()
            .then(|| separator_text.into_bytes());
        let mut capturing_preamble = true;
        let mut preamble: Vec<&[u8]> = Vec::new();
        let mut linesep = false;
        let mut close_boundary_seen = false;
        while let Some(line) = self.input.readline() {
            let Some(found) = boundary_match(line, &separator) else {
                preamble.push(line);
                continue;
            };
            if found.end {
                close_boundary_seen = true;
                linesep = found.linesep;
                break;
            }
            if capturing_preamble {
                if !preamble.is_empty() {
                    let mut text: Vec<u8> = preamble.concat();
                    let last_len = preamble.last().expect("non-empty").len();
                    let trim = eol_len(&text[text.len() - last_len..]);
                    text.truncate(text.len() - trim);
                    self.message.parts[cur].preamble = Some(text);
                }
                capturing_preamble = false;
                self.input.unreadline(line);
                continue;
            }
            // Consume any run of boundary lines.
            loop {
                match self.input.readline() {
                    Some(next) if boundary_match(next, &separator).is_some() => continue,
                    Some(next) => {
                        self.input.unreadline(next);
                        break;
                    }
                    None => break,
                }
            }
            self.input
                .eof_stack
                .push(Matcher::Boundary(separator.clone()));
            self.parsegen();
            let last = self.last;
            if self.message.maintype(last) == "multipart" {
                let part = &mut self.message.parts[last];
                match &part.epilogue {
                    Some(epilogue) if epilogue.is_empty() => part.epilogue = None,
                    Some(epilogue) => {
                        let trim = eol_len(epilogue);
                        let mut epilogue = epilogue.clone();
                        epilogue.truncate(epilogue.len() - trim);
                        part.epilogue = Some(epilogue);
                    }
                    None => {}
                }
            } else if let Payload::Text(payload) = &mut self.message.parts[last].payload {
                let trim = eol_len(payload);
                payload.truncate(payload.len() - trim);
            }
            self.input.eof_stack.pop();
            self.pop_message();
            self.last = cur;
        }
        if capturing_preamble {
            self.message.parts[cur].payload = Payload::Text(preamble.concat());
            let _ = self.read_rest();
            self.message.parts[cur].epilogue = Some(Vec::new());
            return;
        }
        if !close_boundary_seen {
            return;
        }
        let mut epilogue: Vec<Vec<u8>> = if linesep {
            vec![Vec::new()]
        } else {
            Vec::new()
        };
        while let Some(line) = self.input.readline() {
            epilogue.push(line.to_vec());
        }
        if let Some(first) = epilogue.first_mut() {
            let lead = if first.starts_with(b"\r\n") {
                2
            } else if starts_with_newline(first) {
                1
            } else {
                0
            };
            first.drain(..lead);
        }
        self.message.parts[cur].epilogue = Some(epilogue.concat());
    }
}

/// `Policy.header_source_parse` for a header's source lines.
fn header_source_parse(lines: &[&[u8]]) -> Option<(String, String)> {
    let first = lines.first()?;
    let colon = first.iter().position(|&b| b == b':')?;
    let name = sesc_decode(&first[..colon]);
    let mut value: Vec<u8> = first[colon + 1..].to_vec();
    for line in &lines[1..] {
        value.extend_from_slice(line);
    }
    let start = value
        .iter()
        .position(|b| !matches!(b, b' ' | b'\t' | b'\r' | b'\n'))
        .unwrap_or(value.len());
    let mut end = value.len();
    while end > start && matches!(value[end - 1], b'\r' | b'\n') {
        end -= 1;
    }
    Some((name, sesc_decode(&value[start..end])))
}

impl Message {
    /// Parse message bytes (`BytesParser(policy=...).parsebytes`).
    pub fn parse(data: &[u8], policy: Policy) -> Message {
        let mut parser = Parser {
            input: Input {
                lines: split_lines(data),
                eof_stack: Vec::new(),
            },
            message: Message {
                policy,
                parts: Vec::new(),
            },
            stack: Vec::new(),
            last: 0,
        };
        parser.parsegen();
        parser.message
    }

    pub fn policy(&self) -> Policy {
        self.policy
    }

    /// The raw stored value of the first header called `name` (sesc string).
    pub fn raw_header(&self, index: usize, name: &str) -> Option<&str> {
        self.parts[index]
            .headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    /// `str(msg.get(name))` for MIME-structure headers under this policy.
    ///
    /// Under `policy.default`, `Content-Type`, `Content-Disposition` and
    /// `Content-Transfer-Encoding` are `headerregistry` objects whose string
    /// is rebuilt from `_header_value_parser`'s tree
    /// ([`super::py_hvp::mime_header_str`]): unterminated comments and quoted
    /// strings are closed and quoted content is re-escaped before
    /// `_splitparam` / `_parseparam` see the value. Where CPython's parser
    /// raises (an internal `assert`, practically unreachable) the raw value
    /// is used, while CPython failed the access.
    pub fn header_str(&self, index: usize, name: &str) -> Option<String> {
        let raw = self.raw_header(index, name)?;
        Some(match self.policy {
            Policy::Default => {
                let unfolded = unfold(raw);
                MimeHeader::for_name(name)
                    .and_then(|header| mime_header_str(header, &unfolded))
                    .unwrap_or_else(|| sanitize(&unfolded))
            }
            Policy::Compat32 => replace_surrogates(raw),
        })
    }

    /// Whether `msg.get(name)` raises under this policy: a structured MIME
    /// header whose `_header_value_parser` parse fails (`policy.default`).
    pub fn header_raises(&self, index: usize, name: &str) -> bool {
        self.policy == Policy::Default
            && MimeHeader::for_name(name).is_some_and(|header| {
                self.raw_header(index, name)
                    .is_some_and(|raw| mime_header_str(header, &unfold(raw)).is_none())
            })
    }

    /// Whether `BytesParser(policy=policy.default)` raised while parsing:
    /// the feed parser reads `get_content_type()` of every part, so a
    /// `Content-Type` that cannot be parsed fails the whole message (which
    /// `eml_extract` then skips as unparseable).
    pub fn parse_raised(&self) -> bool {
        (0..self.parts.len()).any(|index| self.header_raises(index, "content-type"))
    }

    /// The `cte` that `Message.get_payload(decode=True)` compares: the
    /// header object's `.cte` under `policy.default` (first token, `"7bit"`
    /// when there is none; `Err` where the parser raised, which the snippet
    /// code catches), `str(value).strip().lower()` under `compat32`.
    fn transfer_encoding(&self, index: usize) -> Result<String, ()> {
        let Some(raw) = self.raw_header(index, "content-transfer-encoding") else {
            return Ok(String::new());
        };
        match self.policy {
            Policy::Default => content_transfer_encoding_cte(&unfold(raw)).ok_or(()),
            Policy::Compat32 => Ok(py_strip(&replace_surrogates(raw)).to_lowercase()),
        }
    }

    /// `Message.get_content_type()`.
    pub fn content_type(&self, index: usize) -> String {
        match self.header_str(index, "content-type") {
            None => self.parts[index].default_type.to_owned(),
            Some(value) => {
                let ctype = splitparam(&value).0.to_lowercase();
                if ctype.matches('/').count() != 1 {
                    "text/plain".to_owned()
                } else {
                    ctype
                }
            }
        }
    }

    /// `Message.get_content_maintype()`.
    pub fn maintype(&self, index: usize) -> String {
        self.content_type(index)
            .split('/')
            .next()
            .unwrap_or("")
            .to_owned()
    }

    /// `Message._get_params_preserve(failobj, header)`.
    fn params(&self, index: usize, header: &str) -> Option<Vec<(String, ParamValue)>> {
        let value = self.header_str(index, header)?;
        let raw: Vec<(String, String)> = parseparam(&value)
            .into_iter()
            .map(|p| match p.split_once('=') {
                Some((name, val)) => (py_strip_str(name).to_owned(), py_strip_str(val).to_owned()),
                None => (py_strip_str(&p).to_owned(), String::new()),
            })
            .collect();
        Some(decode_params(raw))
    }

    /// `Message.get_param(param, header=header)` (unquoted).
    pub fn param(&self, index: usize, param: &str, header: &str) -> Option<ParamValue> {
        let params = self.params(index, header)?;
        params
            .into_iter()
            .find(|(name, _)| name.to_lowercase() == param.to_lowercase())
            .map(|(_, value)| match value {
                ParamValue::Text(text) => ParamValue::Text(unquote(&text)),
                ParamValue::Rfc2231(cs, lang, text) => {
                    ParamValue::Rfc2231(cs, lang, unquote(&text))
                }
            })
    }

    /// `Message.get_boundary()`.
    pub fn boundary(&self, index: usize) -> Option<String> {
        let value = self.param(index, "boundary", "content-type")?;
        Some(
            collapse_rfc2231_value(&value)
                .trim_end_matches(py_isspace)
                .to_owned(),
        )
    }

    /// `Message.get_content_charset()`.
    pub fn content_charset(&self, index: usize) -> Option<String> {
        let value = self.param(index, "charset", "content-type")?;
        let charset = match value {
            ParamValue::Text(text) => text,
            ParamValue::Rfc2231(cs, _, text) => {
                let charset = cs.unwrap_or_else(|| "us-ascii".to_owned());
                let raw: Vec<u8> = text
                    .chars()
                    .map(|c| if (c as u32) < 0x100 { c as u8 } else { b'?' })
                    .collect();
                super::py_header::lookup_codec(&charset)
                    .and_then(|codec| super::py_header::decode_strict(&raw, codec))
                    .unwrap_or(text)
            }
        };
        if !charset.chars().all(|c| (c as u32) < 0x80) {
            return None; // str(as_bytes, "us-ascii") raises UnicodeError
        }
        Some(charset.to_lowercase())
    }

    /// `Message.get_content_disposition()`.
    pub fn content_disposition(&self, index: usize) -> Option<String> {
        let value = self.header_str(index, "content-disposition")?;
        Some(splitparam(&value).0.to_lowercase())
    }

    /// `Message.get_filename()`.
    pub fn filename(&self, index: usize) -> Option<String> {
        let value = self
            .param(index, "filename", "content-disposition")
            .or_else(|| self.param(index, "name", "content-type"))?;
        Some(py_strip_str(&collapse_rfc2231_value(&value)).to_owned())
    }

    /// `Message.walk()` (pre-order indices).
    pub fn walk(&self) -> Vec<usize> {
        let mut order = Vec::new();
        let mut stack = vec![0usize];
        while let Some(index) = stack.pop() {
            order.push(index);
            if let Payload::Parts(children) = &self.parts[index].payload {
                stack.extend(children.iter().rev());
            }
        }
        order
    }

    /// `Message.get_payload(decode=True)`: `Ok(None)` for multiparts, `Err` when Python raises.
    pub fn decoded_payload(&self, index: usize) -> Result<Option<Vec<u8>>, ()> {
        let bytes = match &self.parts[index].payload {
            Payload::Parts(_) => return Ok(None),
            Payload::None => return Ok(None),
            Payload::Text(bytes) => bytes,
        };
        let cte = self.transfer_encoding(index)?;
        Ok(Some(match cte.as_str() {
            "quoted-printable" => a2b_qp(bytes),
            "base64" => {
                let joined: Vec<u8> = split_lines(bytes)
                    .into_iter()
                    .flat_map(|line| &line[..line.len() - eol_len(line)])
                    .copied()
                    .collect();
                decode_b(&joined)
            }
            "x-uuencode" | "uuencode" | "uue" | "x-uue" => {
                decode_uu(bytes).unwrap_or_else(|| bytes.clone())
            }
            _ => bytes.clone(),
        }))
    }

    /// `Message.get_payload()` (no decoding) as text, for the snippet fallback.
    pub fn raw_payload_text(&self, index: usize) -> String {
        match &self.parts[index].payload {
            Payload::Text(bytes) => sesc_decode(bytes),
            _ => String::new(),
        }
    }

    /// `len(msg.as_bytes())` with the compat32 `BytesGenerator`; `None` when Python raises.
    pub fn as_bytes_len(&self) -> Option<usize> {
        self.flatten(0, 78).ok().map(|bytes| bytes.len())
    }

    fn flatten(&self, index: usize, max_line_length: usize) -> Result<Vec<u8>, ()> {
        let body = self.dispatch(index, max_line_length)?;
        let mut out = Vec::new();
        for (name, value) in &self.parts[index].headers {
            out.extend_from_slice(&fold_binary(name, value, max_line_length)?);
        }
        out.push(b'\n');
        out.extend_from_slice(&body);
        Ok(out)
    }

    fn dispatch(&self, index: usize, max_line_length: usize) -> Result<Vec<u8>, ()> {
        let content_type = self.content_type(index);
        let maintype = content_type.split('/').next().unwrap_or("");
        match content_type.as_str() {
            "multipart/signed" => self.handle_multipart(index, 0),
            "message/delivery-status" => self.handle_delivery_status(index, max_line_length),
            _ if maintype == "multipart" => self.handle_multipart(index, max_line_length),
            _ if maintype == "message" => self.handle_message(index, max_line_length),
            _ => match &self.parts[index].payload {
                Payload::None => Ok(Vec::new()),
                Payload::Text(bytes) => Ok(write_lines(bytes)),
                Payload::Parts(_) => Err(()),
            },
        }
    }

    fn handle_multipart(&self, index: usize, max_line_length: usize) -> Result<Vec<u8>, ()> {
        let part = &self.parts[index];
        let children: &[usize] = match &part.payload {
            // `Generator._handle_multipart` writes `msg.get_payload()`, which
            // decodes surrogate-escaped bytes with `errors="replace"`; the
            // resulting U+FFFD cannot be re-encoded as ASCII and `as_bytes()`
            // raises (Python then records a size of 0).
            Payload::Text(bytes) if !bytes.is_ascii() => return Err(()),
            Payload::Text(bytes) => return Ok(bytes.clone()),
            Payload::None => &[],
            Payload::Parts(children) => children,
        };
        let mut texts = Vec::new();
        for &child in children {
            texts.push(self.flatten(child, max_line_length)?);
        }
        let boundary = match self.boundary(index) {
            Some(boundary) if !boundary.is_empty() => boundary,
            // Python generates a random "===============<19 digits>==" boundary.
            _ => format!("{}{}==", "=".repeat(15), "0".repeat(19)),
        };
        if !boundary.is_ascii() {
            return Err(());
        }
        let mut out = Vec::new();
        if let Some(preamble) = &part.preamble {
            out.extend_from_slice(&write_lines(preamble));
            out.push(b'\n');
        }
        out.extend_from_slice(format!("--{boundary}\n").as_bytes());
        let mut texts = texts.into_iter();
        if let Some(first) = texts.next() {
            out.extend_from_slice(&first);
        }
        for text in texts {
            out.extend_from_slice(format!("\n--{boundary}\n").as_bytes());
            out.extend_from_slice(&text);
        }
        out.extend_from_slice(format!("\n--{boundary}--\n").as_bytes());
        if let Some(epilogue) = &part.epilogue {
            out.extend_from_slice(&write_lines(epilogue));
        }
        Ok(out)
    }

    fn handle_message(&self, index: usize, max_line_length: usize) -> Result<Vec<u8>, ()> {
        match &self.parts[index].payload {
            Payload::Parts(children) => match children.first() {
                Some(&child) => self.flatten(child, max_line_length),
                None => Err(()),
            },
            Payload::Text(bytes) => Ok(bytes.clone()),
            Payload::None => Err(()),
        }
    }

    fn handle_delivery_status(&self, index: usize, max_line_length: usize) -> Result<Vec<u8>, ()> {
        let Payload::Parts(children) = &self.parts[index].payload else {
            return Err(());
        };
        let mut blocks: Vec<Vec<u8>> = Vec::new();
        for &child in children {
            let text = self.flatten(child, max_line_length)?;
            let lines: Vec<&[u8]> = text.split(|&b| b == b'\n').collect();
            if lines.last().is_some_and(|last| last.is_empty()) {
                blocks.push(lines[..lines.len() - 1].join(&b'\n'));
            } else {
                blocks.push(text.clone());
            }
        }
        Ok(blocks.join(&b'\n'))
    }
}

/// `Generator._write_lines`: normalize every line ending to `\n`.
fn write_lines(data: &[u8]) -> Vec<u8> {
    if data.is_empty() {
        return Vec::new();
    }
    let lines = split_lines(data);
    let mut out = Vec::with_capacity(data.len());
    for line in &lines {
        let ending = eol_len(line);
        out.extend_from_slice(&line[..line.len() - ending]);
        if ending > 0 {
            out.push(b'\n');
        }
    }
    out
}

fn embedded_header() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\n[^ \t]+:").expect("valid regex"))
}

/// `Compat32.fold_binary(name, value)`.
fn fold_binary(name: &str, value: &str, max_line_length: usize) -> Result<Vec<u8>, ()> {
    let mut out = sesc_encode(name);
    out.extend_from_slice(b": ");
    if has_surrogates(value) {
        out.extend_from_slice(&sesc_encode(value));
    } else {
        let encoded = header_encode(value, name.chars().count() + 2, max_line_length);
        if embedded_header().is_match(&encoded) {
            return Err(()); // HeaderParseError
        }
        out.extend_from_slice(encoded.as_bytes());
    }
    out.push(b'\n');
    Ok(out)
}

/// `Header(value, header_name=name).encode(linesep="\n", maxlinelen=...)` for ASCII text.
fn header_encode(value: &str, header_len: usize, max_line_length: usize) -> String {
    let max_len = if max_line_length == 0 {
        1_000_000
    } else {
        max_line_length
    };
    let mut formatter = ValueFormatter::new(header_len, max_len);
    let lines = py_splitlines(value);
    match lines.first() {
        Some(first) => formatter.feed("", first),
        None => formatter.feed("", ""),
    }
    for line in lines.iter().skip(1) {
        formatter.newline();
        let stripped = py_lstrip(line);
        let fws = &line[..line.len() - stripped.len()];
        formatter.feed(fws, stripped);
    }
    if lines.len() > 1 {
        formatter.newline();
    }
    formatter.add_transition();
    formatter.finish("\n")
}

/// `email.header._Accumulator`.
struct Accumulator {
    parts: Vec<(String, String)>,
    initial_size: usize,
}

impl Accumulator {
    fn len(&self) -> usize {
        self.initial_size
            + self
                .parts
                .iter()
                .map(|(f, p)| f.chars().count() + p.chars().count())
                .sum::<usize>()
    }

    fn text(&self) -> String {
        self.parts.iter().map(|(f, p)| format!("{f}{p}")).collect()
    }

    fn pop(&mut self) -> (String, String) {
        self.parts.pop().unwrap_or_default()
    }

    fn reset(&mut self, start: Vec<(String, String)>) {
        self.parts = start;
        self.initial_size = 0;
    }

    fn is_onlyws(&self) -> bool {
        self.initial_size == 0
            && (self.parts.is_empty() || super::py_header::py_is_all_space(&self.text()))
    }
}

/// `email.header._ValueFormatter` (ASCII path only: no RFC 2047 encoding).
struct ValueFormatter {
    max_len: usize,
    lines: Vec<String>,
    current: Accumulator,
}

const SPLITCHARS: [char; 4] = [';', ',', ' ', '\t'];

impl ValueFormatter {
    fn new(header_len: usize, max_len: usize) -> Self {
        Self {
            max_len,
            lines: Vec::new(),
            current: Accumulator {
                parts: Vec::new(),
                initial_size: header_len,
            },
        }
    }

    fn finish(mut self, linesep: &str) -> String {
        self.newline();
        self.lines.join(linesep)
    }

    fn newline(&mut self) {
        let end_of_line = self.current.pop();
        if end_of_line != (" ".to_owned(), String::new()) {
            self.current.parts.push(end_of_line);
        }
        if self.current.len() > 0 {
            if self.current.is_onlyws() && !self.lines.is_empty() {
                let text = self.current.text();
                self.lines.last_mut().expect("non-empty").push_str(&text);
            } else {
                self.lines.push(self.current.text());
            }
        }
        self.current.reset(Vec::new());
    }

    fn add_transition(&mut self) {
        self.current.parts.push((" ".to_owned(), String::new()));
    }

    /// `_ascii_split`: `re.split("([ \t]+)", fws + string)` into (fws, part) pairs.
    fn feed(&mut self, fws: &str, string: &str) {
        let text = format!("{fws}{string}");
        let mut pieces: Vec<String> = Vec::new();
        let mut current = String::new();
        let mut in_ws = false;
        for ch in text.chars() {
            let ws = ch == ' ' || ch == '\t';
            if ws != in_ws {
                pieces.push(std::mem::take(&mut current));
                in_ws = ws;
            }
            current.push(ch);
        }
        pieces.push(current);
        if in_ws {
            // `re.split` ends with an empty text after trailing whitespace,
            // so a header value ending in blanks keeps them.
            pieces.push(String::new());
        }
        // `pieces` alternates text, ws, text, ... starting with (possibly empty) text.
        if !pieces[0].is_empty() {
            pieces.insert(0, String::new());
        } else {
            pieces.remove(0);
        }
        let mut iter = pieces.into_iter();
        while let (Some(ws), Some(part)) = (iter.next(), iter.next()) {
            self.append_chunk(ws, part);
        }
    }

    fn append_chunk(&mut self, fws: String, string: String) {
        self.current.parts.push((fws, string));
        if self.current.len() <= self.max_len {
            return;
        }
        let mut split_at = None;
        'search: for ch in SPLITCHARS {
            for i in (1..self.current.parts.len()).rev() {
                if (ch == ' ' || ch == '\t') && self.current.parts[i].0.starts_with(ch) {
                    split_at = Some(i);
                    break 'search;
                }
                if self.current.parts[i - 1].1.ends_with(ch) {
                    split_at = Some(i);
                    break 'search;
                }
            }
        }
        match split_at {
            None => {
                let (mut fws, part) = self.current.pop();
                if self.current.initial_size > 0 {
                    self.newline();
                    if fws.is_empty() {
                        fws = " ".to_owned();
                    }
                }
                self.current.parts.push((fws, part));
            }
            Some(i) => {
                let remainder = self.current.parts.split_off(i);
                self.lines.push(self.current.text());
                self.current.reset(remainder);
            }
        }
    }
}

/// `mailbox.mbox` iteration: the bytes of each message (after its `From ` line),
/// using `mbox._generate_toc` with `linesep == b"\n"`.
pub fn split_mbox(data: &[u8]) -> Vec<&[u8]> {
    let mut starts = Vec::new();
    let mut stops = Vec::new();
    let mut last_was_empty = false;
    let mut pos = 0usize;
    loop {
        let line_pos = pos;
        let line_end = data[pos..]
            .iter()
            .position(|&b| b == b'\n')
            .map_or(data.len(), |i| pos + i + 1);
        let line = &data[pos..line_end];
        pos = line_end;
        if line.starts_with(b"From ") {
            if stops.len() < starts.len() {
                stops.push(if last_was_empty {
                    line_pos - 1
                } else {
                    line_pos
                });
            }
            starts.push(line_pos);
            last_was_empty = false;
        } else if line.is_empty() {
            stops.push(if last_was_empty {
                line_pos - 1
            } else {
                line_pos
            });
            break;
        } else {
            last_was_empty = line == b"\n";
        }
    }
    starts
        .into_iter()
        .zip(stops)
        .map(|(start, stop)| {
            let from_end = data[start..]
                .iter()
                .position(|&b| b == b'\n')
                .map_or(data.len(), |i| start + i + 1);
            if stop >= from_end {
                &data[from_end..stop]
            } else {
                &data[from_end..]
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn param_json(value: Option<ParamValue>) -> serde_json::Value {
        match value {
            None => serde_json::Value::Null,
            Some(ParamValue::Text(text)) => serde_json::json!(text),
            Some(ParamValue::Rfc2231(charset, lang, text)) => {
                serde_json::json!([charset, lang, text])
            }
        }
    }

    /// Malformed MIME headers against CPython 3.12 `policy.default`
    /// (`tests/fixtures/doctor/mime_header_oracle.json`, written by
    /// `str(msg[name])`, `get_content_type()`, `get_param()`,
    /// `get_content_disposition()`, `get_filename()` and `.cte`).
    #[test]
    fn malformed_mime_headers_match_python_policy_default() {
        let oracle: serde_json::Value = serde_json::from_str(include_str!(
            "../../tests/fixtures/doctor/mime_header_oracle.json"
        ))
        .unwrap();
        let mut failures = Vec::new();
        for case in oracle["ct"].as_array().unwrap() {
            let (input, expected) = (case[0].as_str().unwrap(), &case[1]);
            let msg = Message::parse(
                format!("Content-Type: {input}\n\n").as_bytes(),
                Policy::Default,
            );
            if expected.get("error").is_some() {
                // CPython's feed parser raised: the file is skipped.
                if !msg.parse_raised() {
                    failures.push(format!("CT {input:?}: expected a parse failure"));
                }
                continue;
            }
            let mut actual = serde_json::json!({
                "str": msg.header_str(0, "content-type"),
                "type": msg.content_type(0),
                "filename": msg.filename(0),
            });
            for name in ["charset", "name", "boundary", "format", "x"] {
                actual[name] = param_json(msg.param(0, name, "content-type"));
            }
            if &actual != expected {
                failures.push(format!("CT {input:?}: {actual} != {expected}"));
            }
        }
        for case in oracle["cd"].as_array().unwrap() {
            let (input, expected) = (case[0].as_str().unwrap(), &case[1]);
            let msg = Message::parse(
                format!("Content-Disposition: {input}\n\n").as_bytes(),
                Policy::Default,
            );
            if expected.get("error").is_some() {
                if !msg.header_raises(0, "content-disposition") {
                    failures.push(format!("CD {input:?}: expected an access failure"));
                }
                continue;
            }
            let actual = serde_json::json!({
                "str": msg.header_str(0, "content-disposition"),
                "disposition": msg.content_disposition(0),
                "filename": msg.filename(0),
            });
            if &actual != expected {
                failures.push(format!("CD {input:?}: {actual} != {expected}"));
            }
        }
        for case in oracle["cte"].as_array().unwrap() {
            let (input, expected) = (case[0].as_str().unwrap(), &case[1]);
            let msg = Message::parse(
                format!("Content-Transfer-Encoding: {input}\n\n").as_bytes(),
                Policy::Default,
            );
            let actual = serde_json::json!({
                "str": msg.header_str(0, "content-transfer-encoding"),
                "cte": msg.transfer_encoding(0).unwrap(),
            });
            if &actual != expected {
                failures.push(format!("CTE {input:?}: {actual} != {expected}"));
            }
        }
        assert!(failures.is_empty(), "{}", failures.join("\n"));
    }

    #[test]
    fn transfer_encoding_tokens_decide_payload_decoding() {
        // `.cte` is the first token: comments and junk after it are ignored
        // under policy.default; compat32 compares the stripped string.
        let raw = b"Content-Transfer-Encoding: base64 (comment\n\naGVsbG8=\n";
        let msg = Message::parse(raw, Policy::Default);
        assert_eq!(msg.decoded_payload(0).unwrap().unwrap(), b"hello");
        let raw = b"Content-Transfer-Encoding:\n base64 \n\naGVsbG8=\n";
        let msg = Message::parse(raw, Policy::Compat32);
        assert_eq!(msg.decoded_payload(0).unwrap().unwrap(), b"hello");
    }

    #[test]
    fn uuencoded_payloads_decode_like_decode_uu() {
        // `binascii.b2a_uu(b"hello world")` = b"+:&5L;&\\@=V]R;&0`\n".
        let raw = b"Content-Transfer-Encoding: x-uuencode\n\nbegin 644 a.txt\n+:&5L;&\\@=V]R;&0`\n`\nend\n";
        let msg = Message::parse(raw, Policy::Default);
        assert_eq!(msg.decoded_payload(0).unwrap().unwrap(), b"hello world");
        // No `begin` line: the payload is returned undecoded.
        let raw = b"Content-Transfer-Encoding: uue\n\nnot uuencoded\n";
        let msg = Message::parse(raw, Policy::Default);
        assert_eq!(msg.decoded_payload(0).unwrap().unwrap(), b"not uuencoded\n");
        // A truncated body (empty line before `end`) is a ValueError too.
        let raw =
            b"Content-Transfer-Encoding: uuencode\n\nbegin 644 a\n+:&5L;&\\@=V]R;&0`\n\nend\n";
        let msg = Message::parse(raw, Policy::Default);
        assert_eq!(
            msg.decoded_payload(0).unwrap().unwrap(),
            b"begin 644 a\n+:&5L;&\\@=V]R;&0`\n\nend\n"
        );
    }

    #[test]
    fn mbox_sizes_match_python_golden() {
        let cases: serde_json::Value = serde_json::from_str(include_str!(
            "../../tests/fixtures/pipeline/unit_cases.json"
        ))
        .unwrap();
        let data = include_bytes!("../../tests/fixtures/pipeline/mixed/inputs/list.mbox");
        let sizes: Vec<u64> = split_mbox(data)
            .into_iter()
            .map(|raw| {
                Message::parse(raw, Policy::Compat32)
                    .as_bytes_len()
                    .unwrap_or(0) as u64
            })
            .collect();
        let expected: Vec<u64> = cases["mbox_sizes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_u64().unwrap())
            .collect();
        assert_eq!(sizes, expected);
    }

    #[test]
    fn as_bytes_matches_python_for_trailing_blanks_and_boundaryless_multiparts() {
        // CPython (compat32 BytesGenerator): `Header.encode` keeps blanks
        // that end a header value...
        let msg = Message::parse(
            b"From: a@b.example\r\nX-Empty: value \r\n\r\nlast",
            Policy::Compat32,
        );
        assert_eq!(
            msg.as_bytes_len(),
            Some(b"From: a@b.example\nX-Empty: value \n\nlast".len())
        );
        // ...and `as_bytes()` raises (size 0) for a multipart without a
        // boundary whose body holds raw 8-bit bytes.
        let msg = Message::parse(
            b"Content-Type: multipart/mixed\r\n\r\npre\r\n\xc3\xa9\r\n",
            Policy::Compat32,
        );
        assert_eq!(msg.as_bytes_len(), None);
        let ascii = Message::parse(
            b"Content-Type: multipart/mixed\r\n\r\npre\r\n",
            Policy::Compat32,
        );
        assert!(ascii.as_bytes_len().is_some());
    }

    #[test]
    fn mbox_split_ignores_preamble_and_keeps_escaped_from_lines() {
        let data = b"junk\nFrom a\nSubject: one\n\n>From x\n\nFrom b\nSubject: two\n\nbody\n";
        let messages = split_mbox(data);
        assert_eq!(
            messages,
            vec![
                &b"Subject: one\n\n>From x\n"[..],
                &b"Subject: two\n\nbody\n"[..]
            ]
        );
        assert!(split_mbox(b"no separator\n").is_empty());
    }

    #[test]
    fn multipart_structure_and_payload_decoding() {
        let raw = b"Content-Type: multipart/mixed; boundary=\"b\"\r\n\r\npre\r\n--b\r\nContent-Type: text/plain; charset=iso-8859-1\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\nGr=FC=\r\nsse\r\n--b\r\nContent-Disposition: attachment; filename*=utf-8''r%C3%A9sum%C3%A9.pdf\r\n\r\nx\r\n--b--\r\n";
        let msg = Message::parse(raw, Policy::Default);
        assert_eq!(msg.walk(), vec![0, 1, 2]);
        assert_eq!(msg.content_type(1), "text/plain");
        assert_eq!(msg.content_charset(1).as_deref(), Some("iso-8859-1"));
        assert_eq!(msg.decoded_payload(1).unwrap().unwrap(), b"Gr\xfcsse");
        assert_eq!(msg.content_disposition(2).as_deref(), Some("attachment"));
        assert_eq!(msg.filename(2).as_deref(), Some("résumé.pdf"));
        assert_eq!(msg.parts[0].preamble.as_deref(), Some(&b"pre"[..]));
    }

    #[test]
    fn qp_decoding_follows_binascii() {
        assert_eq!(a2b_qp(b"a=3Db=\nc==d=G1=\r\ne="), b"a=bc=d=G1e");
    }

    #[test]
    fn long_headers_are_refolded_like_compat32() {
        assert_eq!(header_encode("short", 9, 78), "short");
        let token = format!("<{}>", "t".repeat(100));
        assert_eq!(header_encode(&token, 14, 78), format!("\n {token}"));
    }
}
