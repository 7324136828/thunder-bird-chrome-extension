//! A small port of the parts of Python's `email.message.EmailMessage`,
//! `email.contentmanager.raw_data_manager`, `email.generator.BytesGenerator`
//! and `email.policy.default`/`SMTP` header folding that
//! `smtp_client.send_message` relies on.
//!
//! The part tree, header order, transfer-encoding choices (`7bit`/`8bit`/
//! `quoted-printable`/`base64` heuristics of `_encode_text`), base64 line
//! length (76), quoted-printable soft breaks, RFC 2231 parameter folding and
//! boundaries (`===============<19 digits>==`) follow CPython. Header
//! folding follows `_refold_parse_tree` for the cases this module produces
//! (see the deviations listed in `smtp.rs`).

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;

/// `policy.max_line_length`.
const MAX_LINE: usize = 78;
/// `len("=?utf-8?q??=")`: RFC 2047 chrome around the encoded text.
const EW_CHROME: usize = 12;

/// How a header value is folded on output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HeaderValue {
    /// Free text (`UnstructuredHeader`): non-ASCII words (without `utf8`) and
    /// words longer than a line become RFC 2047 encoded words.
    Unstructured(String),
    /// Identifiers and fixed tokens (`Message-ID`, `Content-ID`, `Date`,
    /// `MIME-Version`, ...): folded at whitespace only, never encoded.
    Raw(String),
    /// A mailbox list (`From`/`To`/`Cc`/`Bcc`): the items as given, folded
    /// at the commas; display names are encoded without `utf8`.
    Addresses(Vec<String>),
    /// `Content-Type` / `Content-Disposition` with parameters.
    Params {
        value: String,
        params: Vec<(String, String)>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    pub name: String,
    pub value: HeaderValue,
}

impl Header {
    pub fn new(name: &str, value: HeaderValue) -> Self {
        Self {
            name: name.to_string(),
            value,
        }
    }

    fn is_content(&self) -> bool {
        self.name.to_ascii_lowercase().starts_with("content-")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Body {
    /// Encoded payload with `\n` line endings (`msg.get_payload()`).
    Leaf(String),
    /// `multipart/*` children; the boundary is a `Content-Type` parameter.
    Multipart(Vec<Part>),
}

/// One `EmailMessage` (sub)part.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Part {
    pub headers: Vec<Header>,
    pub body: Body,
}

impl Default for Part {
    fn default() -> Self {
        Self {
            headers: Vec::new(),
            body: Body::Leaf(String::new()),
        }
    }
}

// ---------------------------------------------------------------------------
// Content manager (email.contentmanager.raw_data_manager)
// ---------------------------------------------------------------------------

/// `bytes.splitlines()`: split on `\r\n`, `\r` and `\n`; no trailing empty piece.
fn split_lines_bytes(data: &[u8]) -> Vec<&[u8]> {
    let mut lines = Vec::new();
    let mut start = 0;
    let mut i = 0;
    while i < data.len() {
        match data[i] {
            b'\r' => {
                lines.push(&data[start..i]);
                i += if data.get(i + 1) == Some(&b'\n') {
                    2
                } else {
                    1
                };
                start = i;
            }
            b'\n' => {
                lines.push(&data[start..i]);
                i += 1;
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

fn join_lines(lines: &[&[u8]]) -> Vec<u8> {
    let mut body = lines.join(&b'\n');
    body.push(b'\n');
    body
}

/// `binascii.b2a_base64` line chunks of `_encode_base64(data, 78)`.
pub fn encode_base64_lines(data: &[u8]) -> String {
    let per_line = MAX_LINE / 4 * 3;
    let mut out = String::with_capacity(data.len() * 4 / 3 + data.len() / per_line + 4);
    for chunk in data.chunks(per_line) {
        out.push_str(&BASE64.encode(chunk));
        out.push('\n');
    }
    out
}

fn qp_body_safe(byte: u8) -> bool {
    matches!(byte, b' '..=b'<' | b'>'..=b'~' | b'\t' | b'\r' | b'\n')
}

/// `quoprimime.body_encode(body.decode('latin-1'), maxlinelen)` with `\n` eol.
pub fn qp_body_encode(body: &[u8], maxlinelen: usize) -> String {
    if body.is_empty() {
        return String::new();
    }
    let mut translated = String::with_capacity(body.len() * 2);
    for &byte in body {
        if qp_body_safe(byte) {
            translated.push(byte as char);
        } else {
            translated.push_str(&format!("={byte:02X}"));
        }
    }
    let quote = |c: u8| format!("={c:02X}");
    let soft_break = "=\n";
    let maxlinelen1 = maxlinelen - 1;
    let mut encoded: Vec<String> = Vec::new();
    // Only `\r` / `\n` remain as line breaks after the translation.
    let text = translated.as_bytes();
    for line in split_lines_bytes(text) {
        let line = std::str::from_utf8(line).expect("ascii");
        let lb = line.as_bytes();
        let mut start: isize = 0;
        let laststart = lb.len() as isize - 1 - maxlinelen as isize;
        while start <= laststart {
            let s = start as usize;
            let stop = s + maxlinelen1;
            if lb[stop - 2] == b'=' {
                encoded.push(line[s..stop - 1].to_string());
                start = (stop - 2) as isize;
            } else if lb[stop - 1] == b'=' {
                encoded.push(line[s..stop].to_string());
                start = (stop - 1) as isize;
            } else {
                encoded.push(format!("{}=", &line[s..stop]));
                start = stop as isize;
            }
        }
        let s = start as usize;
        match lb.last() {
            Some(&last) if last == b' ' || last == b'\t' => {
                let room = start - laststart;
                let q = if room >= 3 {
                    quote(last)
                } else if room == 2 {
                    format!("{}{soft_break}", last as char)
                } else {
                    format!("{soft_break}{}", quote(last))
                };
                encoded.push(format!("{}{q}", &line[s.min(lb.len() - 1)..lb.len() - 1]));
            }
            _ => encoded.push(line[s.min(lb.len())..].to_string()),
        }
    }
    if matches!(text.last(), Some(b'\r' | b'\n')) {
        encoded.push(String::new());
    }
    encoded.join("\n")
}

/// `contentmanager._encode_text(string, 'utf-8', None, policy.default)`:
/// the chosen transfer encoding and the payload.
pub fn encode_text(text: &str) -> (&'static str, String) {
    let bytes = text.as_bytes();
    let lines = split_lines_bytes(bytes);
    let normal = || join_lines(&lines);
    if lines.iter().map(|line| line.len()).max().unwrap_or(0) <= MAX_LINE {
        let body = normal();
        let cte = if body.is_ascii() { "7bit" } else { "8bit" };
        return (cte, String::from_utf8(body).expect("utf-8 lines"));
    }
    let sniff = join_lines(&lines[..lines.len().min(10)]);
    let sniff_qp = qp_body_encode(&sniff, MAX_LINE);
    let sniff_base64_len = BASE64.encode(&sniff).len() + 1;
    if sniff_qp.len() > sniff_base64_len {
        ("base64", encode_base64_lines(&normal()))
    } else if lines.len() <= 10 {
        ("quoted-printable", sniff_qp)
    } else {
        ("quoted-printable", qp_body_encode(&normal(), MAX_LINE))
    }
}

/// `set_text_content(msg, text, subtype)` followed by
/// `EmailMessage.set_content`'s `MIME-Version` (when `mime_version`).
pub fn text_part(text: &str, subtype: &str) -> Part {
    let (cte, payload) = encode_text(text);
    let mut part = Part {
        headers: vec![
            Header::new(
                "Content-Type",
                HeaderValue::Params {
                    value: format!("text/{subtype}"),
                    params: vec![("charset".into(), "utf-8".into())],
                },
            ),
            Header::new("Content-Transfer-Encoding", HeaderValue::Raw(cte.into())),
        ],
        body: Body::Leaf(payload),
    };
    part.headers
        .push(Header::new("MIME-Version", HeaderValue::Raw("1.0".into())));
    part
}

/// `set_bytes_content(msg, data, maintype, subtype, cte='base64',
/// disposition=..., filename=..., cid=...)` + `MIME-Version`.
pub fn bytes_part(
    data: &[u8],
    maintype: &str,
    subtype: &str,
    disposition: &str,
    filename: &str,
    cid: Option<&str>,
) -> Part {
    let mut headers = vec![
        Header::new(
            "Content-Type",
            HeaderValue::Params {
                value: format!("{maintype}/{subtype}"),
                params: Vec::new(),
            },
        ),
        Header::new(
            "Content-Transfer-Encoding",
            HeaderValue::Raw("base64".into()),
        ),
        Header::new(
            "Content-Disposition",
            HeaderValue::Params {
                value: disposition.into(),
                params: vec![("filename".into(), filename.into())],
            },
        ),
    ];
    if let Some(cid) = cid {
        headers.push(Header::new("Content-ID", HeaderValue::Raw(cid.into())));
    }
    headers.push(Header::new("MIME-Version", HeaderValue::Raw("1.0".into())));
    Part {
        headers,
        body: Body::Leaf(encode_base64_lines(data)),
    }
}

/// `Generator._make_boundary`: `'=' * 15 + '%019d' % randrange(sys.maxsize) + '=='`.
pub fn make_boundary() -> String {
    let bytes = *uuid::Uuid::new_v4().as_bytes();
    let token = u64::from_le_bytes(bytes[..8].try_into().expect("8 bytes")) & (i64::MAX as u64);
    let token = token % (i64::MAX as u64);
    format!("==============={token:019}==")
}

impl Part {
    fn is_multipart_of(&self, subtype: &str) -> bool {
        self.headers.iter().any(|header| {
            header.name.eq_ignore_ascii_case("content-type")
                && matches!(&header.value, HeaderValue::Params { value, .. }
                    if value.eq_ignore_ascii_case(&format!("multipart/{subtype}")))
        })
    }

    /// `MIMEPart._make_multipart(subtype)`: move the `Content-*` headers and
    /// payload into a first subpart and become `multipart/<subtype>`.
    fn make_multipart(&mut self, subtype: &str) {
        let (content, keep): (Vec<Header>, Vec<Header>) = std::mem::take(&mut self.headers)
            .into_iter()
            .partition(Header::is_content);
        let body = std::mem::replace(&mut self.body, Body::Multipart(Vec::new()));
        let mut children = Vec::new();
        if !content.is_empty() {
            children.push(Part {
                headers: content,
                body,
            });
        }
        self.headers = keep;
        self.headers.push(Header::new(
            "Content-Type",
            HeaderValue::Params {
                value: format!("multipart/{subtype}"),
                params: vec![("boundary".into(), make_boundary())],
            },
        ));
        self.body = Body::Multipart(children);
    }

    /// `MIMEPart._add_multipart(subtype, part)` (`add_alternative`,
    /// `add_related`, `add_attachment`).
    pub fn add_multipart(&mut self, subtype: &str, part: Part) {
        if !self.is_multipart_of(subtype) {
            self.make_multipart(subtype);
        }
        if let Body::Multipart(children) = &mut self.body {
            children.push(part);
        }
    }

    /// The last child of a multipart (`msg.get_payload()[-1]`).
    pub fn last_child_mut(&mut self) -> Option<&mut Part> {
        match &mut self.body {
            Body::Multipart(children) => children.last_mut(),
            Body::Leaf(_) => None,
        }
    }

    /// `BytesGenerator(policy=default/SMTP clone(utf8=...)).flatten(msg,
    /// linesep='\r\n')`.
    pub fn to_bytes(&self, utf8: bool) -> Vec<u8> {
        self.to_bytes_with(utf8, false)
    }

    /// [`Part::to_bytes`] with `Generator(mangle_from_=...)`: `smtplib`'s
    /// ASCII path (`BytesGenerator(bytesmsg)` without a policy) defaults to
    /// `mangle_from_=True`, which rewrites body lines starting with `From `
    /// to `>From `; its SMTPUTF8 path and `as_bytes()` (the Sent copy) do not.
    pub fn to_bytes_with(&self, utf8: bool, mangle_from: bool) -> Vec<u8> {
        let mut out = Vec::new();
        self.write(&mut out, utf8, mangle_from);
        out
    }

    fn write(&self, out: &mut Vec<u8>, utf8: bool, mangle_from: bool) {
        match &self.body {
            Body::Leaf(payload) => {
                self.write_headers(out, utf8, None);
                out.extend_from_slice(b"\r\n");
                if mangle_from {
                    write_lines(out, &mangle_from_lines(payload));
                } else {
                    write_lines(out, payload);
                }
            }
            Body::Multipart(children) => {
                let texts: Vec<Vec<u8>> = children
                    .iter()
                    .map(|child| child.to_bytes_with(utf8, mangle_from))
                    .collect();
                let declared = self.boundary().unwrap_or_else(make_boundary);
                let boundary = unique_boundary(&declared, &texts);
                self.write_headers(out, utf8, Some(&boundary));
                out.extend_from_slice(b"\r\n");
                out.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
                for (index, text) in texts.iter().enumerate() {
                    if index > 0 {
                        out.extend_from_slice(format!("\r\n--{boundary}\r\n").as_bytes());
                    }
                    out.extend_from_slice(text);
                }
                out.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
            }
        }
    }

    fn boundary(&self) -> Option<String> {
        self.headers.iter().find_map(|header| match &header.value {
            HeaderValue::Params { params, .. }
                if header.name.eq_ignore_ascii_case("content-type") =>
            {
                params
                    .iter()
                    .find(|(name, _)| name == "boundary")
                    .map(|(_, value)| value.clone())
            }
            _ => None,
        })
    }

    fn write_headers(&self, out: &mut Vec<u8>, utf8: bool, boundary: Option<&str>) {
        for header in &self.headers {
            let folded = match (&header.value, boundary) {
                (HeaderValue::Params { value, params }, Some(boundary))
                    if header.name.eq_ignore_ascii_case("content-type") =>
                {
                    let params: Vec<(String, String)> = params
                        .iter()
                        .map(|(name, current)| {
                            if name == "boundary" {
                                (name.clone(), boundary.to_string())
                            } else {
                                (name.clone(), current.clone())
                            }
                        })
                        .collect();
                    fold_params(&header.name, value, &params, utf8)
                }
                _ => fold_header(header, utf8),
            };
            out.extend_from_slice(folded.as_bytes());
        }
    }
}

/// `Generator._make_boundary(text)` collision check: no line of the
/// children may be `--boundary` or `--boundary--`.
fn unique_boundary(boundary: &str, texts: &[Vec<u8>]) -> String {
    let collides = |candidate: &str| {
        let open = format!("--{candidate}");
        let close = format!("--{candidate}--");
        texts.iter().any(|text| {
            split_lines_bytes(text)
                .iter()
                .any(|line| *line == open.as_bytes() || *line == close.as_bytes())
        })
    };
    let mut candidate = boundary.to_string();
    let mut counter = 0;
    while collides(&candidate) {
        candidate = format!("{boundary}.{counter}");
        counter += 1;
    }
    candidate
}

/// `fcre.sub('>From ', payload)` with `fcre = re.compile(r'^From ', re.MULTILINE)`:
/// `^` matches at the start and after every `\n` (not after a lone `\r`).
fn mangle_from_lines(payload: &str) -> String {
    let mut out = String::with_capacity(payload.len());
    for (index, line) in payload.split('\n').enumerate() {
        if index > 0 {
            out.push('\n');
        }
        if line.starts_with("From ") {
            out.push('>');
        }
        out.push_str(line);
    }
    out
}

/// `BytesGenerator._write_lines`: universal newlines become CRLF.
fn write_lines(out: &mut Vec<u8>, payload: &str) {
    if payload.is_empty() {
        return;
    }
    let bytes = payload.as_bytes();
    let mut start = 0;
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'\r' | b'\n' => {
                out.extend_from_slice(&bytes[start..i]);
                out.extend_from_slice(b"\r\n");
                i += if bytes[i] == b'\r' && bytes.get(i + 1) == Some(&b'\n') {
                    2
                } else {
                    1
                };
                start = i;
            }
            _ => i += 1,
        }
    }
    out.extend_from_slice(&bytes[start..]);
}

// ---------------------------------------------------------------------------
// Header folding (email._header_value_parser._refold_parse_tree subset)
// ---------------------------------------------------------------------------

fn char_len(text: &str) -> usize {
    text.chars().count()
}

fn q_safe(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'!' | b'*' | b'+' | b'/')
}

/// `email._encoded_words.encode(text, 'utf-8')`: `q` unless `b` is at
/// least 5 characters shorter.
pub fn encoded_word(text: &str) -> String {
    let bytes = text.as_bytes();
    let q_len: usize = bytes
        .iter()
        .map(|&b| if q_safe(b) || b == b' ' { 1 } else { 3 })
        .sum();
    let b_len = bytes.len().div_ceil(3) * 4;
    if q_len as isize - (b_len as isize) < 5 {
        let mut encoded = String::with_capacity(q_len);
        for &b in bytes {
            if q_safe(b) {
                encoded.push(b as char);
            } else if b == b' ' {
                encoded.push('_');
            } else {
                encoded.push_str(&format!("={b:02X}"));
            }
        }
        format!("=?utf-8?q?{encoded}?=")
    } else {
        format!("=?utf-8?b?{}?=", BASE64.encode(bytes))
    }
}

/// Lines being built for one header.
struct Lines {
    lines: Vec<String>,
}

impl Lines {
    fn new(name: &str) -> Self {
        Self {
            lines: vec![format!("{name}:")],
        }
    }

    fn last(&mut self) -> &mut String {
        self.lines.last_mut().expect("at least one line")
    }

    fn room(&self) -> isize {
        MAX_LINE as isize - char_len(self.lines.last().expect("line")) as isize
    }

    /// Append `token` (with its leading whitespace `ws`): on this line when
    /// it fits, else on a new line when it fits there, else (when `force`)
    /// on this line anyway. Returns false when it was not placed.
    fn place(&mut self, ws: &str, token: &str, force: bool) -> bool {
        let candidate = format!("{ws}{token}");
        if char_len(&candidate) as isize <= self.room() {
            self.last().push_str(&candidate);
            return true;
        }
        let ws = if ws.is_empty() { " " } else { ws };
        let on_new_line = format!("{ws}{token}");
        if char_len(&on_new_line) <= MAX_LINE && char_len(self.lines.last().unwrap()) > 0 {
            self.lines.push(on_new_line);
            return true;
        }
        if force {
            self.last().push_str(&candidate);
            return true;
        }
        false
    }

    /// `_fold_as_ew`: encode `text` as one or more encoded words, starting
    /// on the current line after `ws` when there is room.
    fn place_encoded(&mut self, ws: &str, text: &str) {
        let chars: Vec<char> = text.chars().collect();
        let mut index = 0;
        let mut leading = ws.to_string();
        if self.room() - (char_len(&leading) as isize) < (EW_CHROME + 3) as isize {
            self.lines.push(if leading.is_empty() {
                " ".into()
            } else {
                leading.clone()
            });
            leading.clear();
        }
        while index < chars.len() {
            let space = self.room() - char_len(&leading) as isize;
            // Longest prefix whose encoded word fits (at least one char).
            let mut take = 0;
            let mut best = String::new();
            let mut end = index;
            while end < chars.len() {
                end += 1;
                let chunk: String = chars[index..end].iter().collect();
                let word = encoded_word(&chunk);
                if word.len() as isize > space && take > 0 {
                    break;
                }
                take = end - index;
                best = word;
                if best.len() as isize > space {
                    break;
                }
            }
            let line = self.last();
            line.push_str(&leading);
            line.push_str(&best);
            leading.clear();
            index += take;
            if index < chars.len() {
                self.lines.push(" ".into());
            }
        }
    }

    fn finish(self) -> String {
        let mut text = self.lines.join("\r\n");
        text.push_str("\r\n");
        text
    }
}

/// Split into (whitespace, word) pairs: each word with the whitespace
/// before it; a trailing whitespace run has an empty word.
fn words(value: &str) -> Vec<(String, String)> {
    let mut result = Vec::new();
    let mut ws = String::new();
    let mut word = String::new();
    for c in value.chars() {
        if c == ' ' || c == '\t' {
            if !word.is_empty() {
                result.push((std::mem::take(&mut ws), std::mem::take(&mut word)));
            }
            ws.push(c);
        } else {
            word.push(c);
        }
    }
    if !word.is_empty() || !ws.is_empty() {
        result.push((ws, word));
    }
    result
}

fn fold_unstructured(name: &str, value: &str, utf8: bool, encodable: bool) -> String {
    let mut lines = Lines::new(name);
    let tokens = words(value);
    let needs_encoding = |word: &str| encodable && !utf8 && !word.is_ascii();
    let mut i = 0;
    let mut first = true;
    while i < tokens.len() {
        let (ws, word) = &tokens[i];
        // The folding whitespace after "Name:" precedes the first token.
        let ws = if first { format!(" {ws}") } else { ws.clone() };
        first = false;
        if word.is_empty() {
            lines.last().push_str(&ws);
            i += 1;
            continue;
        }
        if needs_encoding(word) {
            // Combine a run of non-ASCII words (and the whitespace between
            // them) into one encoded segment.
            let mut text = word.clone();
            let mut j = i + 1;
            while j < tokens.len() && !tokens[j].1.is_empty() && needs_encoding(&tokens[j].1) {
                text.push_str(&tokens[j].0);
                text.push_str(&tokens[j].1);
                j += 1;
            }
            lines.place_encoded(&ws, &text);
            i = j;
            continue;
        }
        if !lines.place(&ws, word, !encodable) {
            lines.place_encoded(&ws, word);
        }
        i += 1;
    }
    lines.finish()
}

/// Python `email.utils.quote`-style quoting for a display name.
fn quote_phrase(name: &str) -> String {
    let specials = |c: char| "()<>@,:;\".[]\\".contains(c);
    if name.chars().any(specials) {
        format!("\"{}\"", name.replace('\\', "\\\\").replace('"', "\\\""))
    } else {
        name.to_string()
    }
}

/// Unquote a display-name phrase (`"..."` with backslash escapes).
fn unquote_phrase(phrase: &str) -> String {
    let phrase = phrase.trim();
    if phrase.len() >= 2 && phrase.starts_with('"') && phrase.ends_with('"') {
        let inner = &phrase[1..phrase.len() - 1];
        let mut out = String::new();
        let mut escaped = false;
        for c in inner.chars() {
            if escaped {
                out.push(c);
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else {
                out.push(c);
            }
        }
        out
    } else {
        phrase.to_string()
    }
}

/// Encoded words for a display name, each at most 75 characters.
pub fn encode_phrase(name: &str) -> String {
    let chars: Vec<char> = name.chars().collect();
    let mut words = Vec::new();
    let mut index = 0;
    while index < chars.len() {
        let mut end = index + 1;
        let mut best = encoded_word(&chars[index..end].iter().collect::<String>());
        while end < chars.len() {
            let candidate = encoded_word(&chars[index..end + 1].iter().collect::<String>());
            if candidate.len() > 75 {
                break;
            }
            best = candidate;
            end += 1;
        }
        words.push(best);
        index = end;
    }
    words.join(" ")
}

/// One mailbox of an address header, encoded for a non-`utf8` policy.
fn render_mailbox(item: &str, utf8: bool) -> String {
    if utf8 || item.is_ascii() {
        return item.to_string();
    }
    let trimmed = item.trim_end();
    if trimmed.ends_with('>') {
        if let Some(open) = trimmed.rfind('<') {
            let phrase = unquote_phrase(&trimmed[..open]);
            let address = &trimmed[open..];
            if address.is_ascii() {
                if phrase.is_empty() {
                    return address.to_string();
                }
                let leading: String = item
                    .chars()
                    .take_while(|c| *c == ' ' || *c == '\t')
                    .collect();
                return format!("{leading}{} {address}", encode_phrase(&phrase));
            }
        }
    }
    item.to_string()
}

fn fold_addresses(name: &str, items: &[String], utf8: bool) -> String {
    let mut lines = Lines::new(name);
    for (index, item) in items.iter().enumerate() {
        let rendered = render_mailbox(item, utf8);
        if index > 0 {
            lines.last().push(',');
        }
        lines.place(" ", &rendered, true);
    }
    lines.finish()
}

/// `urllib.parse.quote(value, safe='')` (UTF-8).
fn percent_encode(value: &str) -> String {
    let mut out = String::new();
    for &b in value.as_bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// `Message._formatparam(name, value)` as used by `set_param`.
fn format_param(name: &str, value: &str) -> String {
    if value.is_ascii() {
        format!(
            "{name}=\"{}\"",
            value.replace('\\', "\\\\").replace('"', "\\\"")
        )
    } else {
        format!("{name}*=utf-8''{}", percent_encode(value))
    }
}

/// `_fold_mime_parameters` for headers that do not fit on one line.
fn fold_params(name: &str, value: &str, params: &[(String, String)], utf8: bool) -> String {
    let mut unfolded = format!("{name}: {value}");
    for (param, param_value) in params {
        unfolded.push_str("; ");
        unfolded.push_str(&format_param(param, param_value));
    }
    if char_len(&unfolded) <= MAX_LINE {
        return format!("{unfolded}\r\n");
    }
    let encoding = if utf8 { "utf-8" } else { "us-ascii" };
    let mut lines = vec![format!("{name}: {value}")];
    for (param, param_value) in params {
        if !lines.last().unwrap().trim_end().ends_with(';') {
            lines.last_mut().unwrap().push(';');
        }
        let encoding_required = !utf8 && !param_value.is_ascii();
        let charset = if encoding_required { "utf-8" } else { encoding };
        let tstr = if encoding_required {
            format!("{param}*={charset}''{}", percent_encode(param_value))
        } else {
            format!(
                "{param}=\"{}\"",
                param_value.replace('\\', "\\\\").replace('"', "\\\"")
            )
        };
        let last_len = char_len(lines.last().unwrap());
        if last_len + char_len(&tstr) + 1 < MAX_LINE {
            lines.last_mut().unwrap().push(' ');
            lines.last_mut().unwrap().push_str(&tstr);
            continue;
        } else if char_len(&tstr) + 2 <= MAX_LINE {
            lines.push(format!(" {tstr}"));
            continue;
        }
        let mut section = 0;
        let mut extra_chrome = format!("{charset}''");
        let mut remaining: Vec<char> = param_value.chars().collect();
        while !remaining.is_empty() {
            let chrome_len = param.len() + section.to_string().len() + 3 + extra_chrome.len();
            let maxchars = MAX_LINE.saturating_sub(chrome_len + 2).max(1);
            let mut splitpoint = maxchars.min(remaining.len());
            let mut encoded;
            loop {
                let partial: String = remaining[..splitpoint].iter().collect();
                encoded = percent_encode(&partial);
                if encoded.len() <= maxchars || splitpoint == 1 {
                    break;
                }
                splitpoint -= 1;
            }
            lines.push(format!(" {param}*{section}*={extra_chrome}{encoded}"));
            extra_chrome.clear();
            section += 1;
            remaining.drain(..splitpoint);
            if !remaining.is_empty() {
                lines.last_mut().unwrap().push(';');
            }
        }
    }
    let mut text = lines.join("\r\n");
    text.push_str("\r\n");
    text
}

/// `policy.fold(name, value)` for one header, with CRLF line endings.
pub fn fold_header(header: &Header, utf8: bool) -> String {
    match &header.value {
        HeaderValue::Unstructured(value) => fold_unstructured(&header.name, value, utf8, true),
        HeaderValue::Raw(value) => fold_unstructured(&header.name, value, utf8, false),
        HeaderValue::Addresses(items) => fold_addresses(&header.name, items, utf8),
        HeaderValue::Params { value, params } => fold_params(&header.name, value, params, utf8),
    }
}

/// `email.utils.formataddr((name, address))`: `Err` where Python raised
/// `UnicodeEncodeError` (a non-ASCII address).
pub fn formataddr(name: &str, address: &str) -> Result<String, ()> {
    if !address.is_ascii() {
        return Err(());
    }
    if name.is_empty() {
        return Ok(address.to_string());
    }
    if !name.is_ascii() {
        // Charset('utf-8').header_encode(name): the shorter of q and b.
        let bytes = name.as_bytes();
        let q_len: usize = bytes
            .iter()
            .map(|&b| if q_safe(b) || b == b' ' { 1 } else { 3 })
            .sum();
        let b_len = bytes.len().div_ceil(3) * 4;
        let encoded = if b_len < q_len {
            format!("=?utf-8?b?{}?=", BASE64.encode(bytes))
        } else {
            let mut text = String::new();
            for &b in bytes {
                if q_safe(b) {
                    text.push(b as char);
                } else if b == b' ' {
                    text.push('_');
                } else {
                    text.push_str(&format!("={b:02X}"));
                }
            }
            format!("=?utf-8?q?{text}?=")
        };
        return Ok(format!("{encoded} <{address}>"));
    }
    Ok(format!("{} <{address}>", quote_phrase(name)))
}

/// The `From` header item for a display name: Python decodes the
/// `formataddr` encoded word when parsing the header and re-encodes it
/// (split into valid encoded words) on output, or writes it raw with `utf8`.
pub fn from_item(name: &str, address: &str, from_header: &str) -> String {
    if name.is_empty() || name.is_ascii() {
        return from_header.to_string();
    }
    format!("{} <{address}>", quote_phrase(name))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_headers_are_kept_and_long_ones_folded() {
        let subject = Header::new("Subject", HeaderValue::Unstructured("Reply".into()));
        assert_eq!(fold_header(&subject, false), "Subject: Reply\r\n");
        let unicode = Header::new(
            "Subject",
            HeaderValue::Unstructured("Unicode subject caf\u{e9}".into()),
        );
        assert_eq!(
            fold_header(&unicode, false),
            "Subject: Unicode subject =?utf-8?q?caf=C3=A9?=\r\n"
        );
        assert_eq!(
            fold_header(&unicode, true),
            "Subject: Unicode subject caf\u{e9}\r\n"
        );
        let long = Header::new(
            "Subject",
            HeaderValue::Unstructured("word ".repeat(30).trim_end().into()),
        );
        let folded = fold_header(&long, false);
        assert!(
            folded.split("\r\n").all(|line| line.len() <= 78),
            "{folded}"
        );
        assert_eq!(
            folded.replace("\r\n", ""),
            format!("Subject: {}", "word ".repeat(30).trim_end())
        );
    }

    #[test]
    fn content_type_boundary_folds_like_python() {
        let header = Header::new(
            "Content-Type",
            HeaderValue::Params {
                value: "multipart/alternative".into(),
                params: vec![(
                    "boundary".into(),
                    "===============1234567890123456789==".into(),
                )],
            },
        );
        assert_eq!(
            fold_header(&header, false),
            "Content-Type: multipart/alternative;\r\n boundary=\"===============1234567890123456789==\"\r\n"
        );
        let mixed = Header::new(
            "Content-Type",
            HeaderValue::Params {
                value: "multipart/mixed".into(),
                params: vec![(
                    "boundary".into(),
                    "===============1234567890123456789==".into(),
                )],
            },
        );
        assert_eq!(
            fold_header(&mixed, false),
            "Content-Type: multipart/mixed; boundary=\"===============1234567890123456789==\"\r\n"
        );
        let disposition = Header::new(
            "Content-Disposition",
            HeaderValue::Params {
                value: "attachment".into(),
                params: vec![("filename".into(), "r\u{e9}sum\u{e9}.pdf".into())],
            },
        );
        assert_eq!(
            fold_header(&disposition, false),
            "Content-Disposition: attachment; filename*=utf-8''r%C3%A9sum%C3%A9.pdf\r\n"
        );
    }

    #[test]
    fn text_encoding_heuristics_match_python() {
        assert_eq!(encode_text(""), ("7bit", "\n".to_string()));
        assert_eq!(encode_text("a\r\nb"), ("7bit", "a\nb\n".to_string()));
        assert_eq!(encode_text("caf\u{e9}").0, "8bit");
        let long = "x".repeat(100);
        let (cte, payload) = encode_text(&long);
        assert_eq!(cte, "quoted-printable");
        assert_eq!(
            payload,
            format!("{}=\n{}\n", "x".repeat(77), "x".repeat(23))
        );
        let (cte, _) = encode_text(&"\u{e9}".repeat(100));
        assert_eq!(cte, "base64");
    }

    #[test]
    fn qp_keeps_escapes_intact_and_quotes_trailing_space() {
        assert_eq!(qp_body_encode(b"a=b \n", 78), "a=3Db=20\n");
        let line = format!("{}={}", "a".repeat(75), "b".repeat(10));
        let encoded = qp_body_encode(line.as_bytes(), 78);
        assert!(encoded.split('\n').all(|l| l.len() <= 78), "{encoded}");
    }

    #[test]
    fn formataddr_matches_python() {
        assert_eq!(formataddr("", "u@example.com").unwrap(), "u@example.com");
        assert_eq!(
            formataddr("User", "u@example.com").unwrap(),
            "User <u@example.com>"
        );
        assert_eq!(
            formataddr("Doe, J.", "u@example.com").unwrap(),
            "\"Doe, J.\" <u@example.com>"
        );
        // Charset.header_encode picks the shorter of b and q.
        assert_eq!(
            formataddr("Jos\u{e9}", "u@example.com").unwrap(),
            "=?utf-8?b?Sm9zw6k=?= <u@example.com>"
        );
        assert_eq!(
            formataddr("Ren\u{e9} Dupont", "u@example.com").unwrap(),
            "=?utf-8?q?Ren=C3=A9_Dupont?= <u@example.com>"
        );
        assert!(formataddr("Name", "u@b\u{fc}cher.example").is_err());
    }
}
