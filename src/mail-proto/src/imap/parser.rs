//! IMAP response data parser.
//!
//! Replaces the regular expressions the original code ran over `imaplib`
//! data items (`_UID_PATTERN`, `_FLAGS_PATTERN`, `_SIZE_PATTERN`,
//! `_INTERNALDATE_PATTERN`, `_LIST_PATTERN` in `imap_client.py` and the
//! `_LIST` / `_UID` / `_SIZE` patterns in `trash.py`) with a real tokenizer
//! that understands nested parenthesized lists, quoted strings, literals
//! (`{n}` and `~{n}`), `NIL` and bracketed section specifiers such as
//! `BODY[HEADER.FIELDS (FROM TO)]<0>`.
//!
//! The input is a response split the way `imaplib` splits it: a sequence of
//! [`Part`]s, each holding the line text up to and including a `{n}` marker
//! plus the literal bytes that followed it.

use crate::error::{ProtoError, Result};

/// One piece of a server response line, the Rust analogue of an `imaplib`
/// data item: `text` is the line text (for a literal-bearing piece it ends
/// with the `{n}` marker) and `literal` holds the literal bytes, i.e. the
/// tuple `(prefix, literal)`; the final piece has `literal == None`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Part {
    pub text: Vec<u8>,
    pub literal: Option<Vec<u8>>,
}

impl Part {
    /// A piece without a literal.
    pub fn text(text: impl Into<Vec<u8>>) -> Self {
        Part {
            text: text.into(),
            literal: None,
        }
    }
}

/// A parsed IMAP data value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    /// `NIL`.
    Nil,
    /// A bare number.
    Number(u64),
    /// Any other atom (flags such as `\Seen`, keys such as `BODY[]`).
    Atom(String),
    /// A quoted string, unescaped.
    Quoted(Vec<u8>),
    /// A literal (`{n}` or `~{n}`), bytes exactly as received.
    Literal(Vec<u8>),
    /// A parenthesized list.
    List(Vec<Value>),
}

impl Value {
    /// String-like bytes: quoted, literal or atom content.
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Value::Quoted(bytes) | Value::Literal(bytes) => Some(bytes),
            Value::Atom(atom) => Some(atom.as_bytes()),
            _ => None,
        }
    }

    /// String-like content decoded as UTF-8 (lossy); numbers are formatted.
    pub fn to_string_lossy(&self) -> Option<String> {
        match self {
            Value::Number(number) => Some(number.to_string()),
            other => other
                .as_bytes()
                .map(|bytes| String::from_utf8_lossy(bytes).into_owned()),
        }
    }

    /// A number, also accepting all-digit atoms and quoted digits.
    pub fn as_number(&self) -> Option<u64> {
        match self {
            Value::Number(number) => Some(*number),
            Value::Atom(_) | Value::Quoted(_) => {
                std::str::from_utf8(self.as_bytes()?).ok()?.parse().ok()
            }
            _ => None,
        }
    }

    /// List items.
    pub fn as_list(&self) -> Option<&[Value]> {
        match self {
            Value::List(items) => Some(items),
            _ => None,
        }
    }

    /// True for `NIL`.
    pub fn is_nil(&self) -> bool {
        matches!(self, Value::Nil)
    }
}

/// Tokenizer over a sequence of [`Part`]s.
#[derive(Debug, Clone)]
pub(crate) struct Cursor<'a> {
    parts: &'a [Part],
    idx: usize,
    pos: usize,
}

fn protocol(message: impl Into<String>) -> ProtoError {
    ProtoError::Protocol(message.into())
}

impl<'a> Cursor<'a> {
    pub(crate) fn new(parts: &'a [Part], idx: usize, pos: usize) -> Self {
        Cursor { parts, idx, pos }
    }

    fn text(&self) -> &'a [u8] {
        match self.parts.get(self.idx) {
            Some(part) => &part.text[self.pos.min(part.text.len())..],
            None => &[],
        }
    }

    fn peek(&self) -> Option<u8> {
        self.text().first().copied()
    }

    fn skip_spaces(&mut self) {
        while self.peek() == Some(b' ') {
            self.pos += 1;
        }
    }

    /// Read the next value; `None` at the end of input or at a `)`.
    pub(crate) fn next_value(&mut self) -> Result<Option<Value>> {
        self.skip_spaces();
        match self.peek() {
            None | Some(b')') => Ok(None),
            Some(_) => self.read_value().map(Some),
        }
    }

    /// Read all remaining values.
    pub(crate) fn values(&mut self) -> Result<Vec<Value>> {
        let mut values = Vec::new();
        while let Some(value) = self.next_value()? {
            values.push(value);
        }
        if self.peek() == Some(b')') {
            return Err(protocol("unbalanced ')' in server response"));
        }
        Ok(values)
    }

    /// Read one value.
    pub(crate) fn read_value(&mut self) -> Result<Value> {
        self.skip_spaces();
        match self.peek() {
            None => Err(protocol("unexpected end of server response")),
            Some(b'(') => {
                self.pos += 1;
                let mut items = Vec::new();
                loop {
                    self.skip_spaces();
                    match self.peek() {
                        Some(b')') => {
                            self.pos += 1;
                            return Ok(Value::List(items));
                        }
                        None => return Err(protocol("unterminated list in server response")),
                        Some(_) => items.push(self.read_value()?),
                    }
                }
            }
            Some(b')') => Err(protocol("unexpected ')' in server response")),
            Some(b'"') => self.read_quoted().map(Value::Quoted),
            Some(b'{') => self.read_literal().map(Value::Literal),
            Some(b'~') if self.text().get(1) == Some(&b'{') => {
                self.pos += 1;
                self.read_literal().map(Value::Literal)
            }
            Some(_) => {
                let atom = self.read_atom()?;
                if atom.eq_ignore_ascii_case("NIL") {
                    Ok(Value::Nil)
                } else if !atom.is_empty() && atom.bytes().all(|b| b.is_ascii_digit()) {
                    Ok(atom.parse().map(Value::Number).unwrap_or(Value::Atom(atom)))
                } else {
                    Ok(Value::Atom(atom))
                }
            }
        }
    }

    fn read_quoted(&mut self) -> Result<Vec<u8>> {
        let text = self.text();
        let mut out = Vec::new();
        let mut index = 1;
        while index < text.len() {
            match text[index] {
                b'\\' if index + 1 < text.len() => {
                    out.push(text[index + 1]);
                    index += 2;
                }
                b'"' => {
                    self.pos += index + 1;
                    return Ok(out);
                }
                byte => {
                    out.push(byte);
                    index += 1;
                }
            }
        }
        Err(protocol("unterminated quoted string in server response"))
    }

    fn read_literal(&mut self) -> Result<Vec<u8>> {
        let text = self.text();
        let close = text
            .iter()
            .position(|&b| b == b'}')
            .ok_or_else(|| protocol("malformed literal marker"))?;
        let digits = text[1..close].strip_suffix(b"+").unwrap_or(&text[1..close]);
        if digits.is_empty() || !digits.iter().all(u8::is_ascii_digit) {
            return Err(protocol("malformed literal marker"));
        }
        if close + 1 != text.len() {
            return Err(protocol("literal marker is not at the end of a line"));
        }
        let part = &self.parts[self.idx];
        let literal = part
            .literal
            .as_ref()
            .ok_or_else(|| protocol("literal marker without literal data"))?;
        self.idx += 1;
        self.pos = 0;
        Ok(literal.clone())
    }

    fn read_atom(&mut self) -> Result<String> {
        let text = self.text();
        let mut index = 0;
        let mut depth = 0usize;
        while index < text.len() {
            let byte = text[index];
            if depth > 0 {
                match byte {
                    b'[' => depth += 1,
                    b']' => depth -= 1,
                    _ => {}
                }
                index += 1;
                continue;
            }
            match byte {
                b'[' => {
                    depth = 1;
                    index += 1;
                }
                b' ' | b'(' | b')' | b'"' | b'{' | b'\r' | b'\n' => break,
                _ => index += 1,
            }
        }
        if depth > 0 {
            return Err(protocol("unterminated '[' in server response"));
        }
        if index == 0 {
            return Err(protocol("expected an atom in server response"));
        }
        self.pos += index;
        Ok(String::from_utf8_lossy(&text[..index]).into_owned())
    }
}

/// Parse a sequence of values from raw parts (starting at the beginning).
pub fn parse_values(parts: &[Part]) -> Result<Vec<Value>> {
    Cursor::new(parts, 0, 0).values()
}

/// Parse values from a single line without literals.
pub fn parse_line(line: &[u8]) -> Result<Vec<Value>> {
    parse_values(&[Part::text(line.to_vec())])
}

/// One `* n FETCH (...)` response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchResponse {
    /// Message sequence number.
    pub seq: u32,
    /// Attribute name (uppercased, e.g. `UID`, `BODY[HEADER.FIELDS (FROM)]`)
    /// and value, in server order.
    pub attributes: Vec<(String, Value)>,
}

/// Normalize a section specifier for comparison: uppercase, no quotes,
/// collapsed whitespace, no partial `<origin>` suffix and no `.PEEK`.
fn normalize_body_key(key: &str) -> String {
    let upper = key.to_ascii_uppercase().replace(".PEEK[", "[");
    let without_origin = match upper.rfind(']') {
        Some(end) => &upper[..=end],
        None => upper.as_str(),
    };
    without_origin
        .replace('"', "")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .replace("( ", "(")
        .replace(" )", ")")
}

impl FetchResponse {
    /// Attribute by name (case-insensitive, exact).
    pub fn get(&self, name: &str) -> Option<&Value> {
        self.attributes
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value)
    }

    /// `UID n`.
    pub fn uid(&self) -> Option<u32> {
        self.get("UID")?
            .as_number()
            .and_then(|n| u32::try_from(n).ok())
    }

    /// `FLAGS (...)` as strings, original case (e.g. `\Seen`).
    pub fn flags(&self) -> Option<Vec<String>> {
        Some(
            self.get("FLAGS")?
                .as_list()?
                .iter()
                .filter_map(Value::to_string_lossy)
                .collect(),
        )
    }

    /// True when `FLAGS` contains `flag` (case-insensitive).
    pub fn has_flag(&self, flag: &str) -> bool {
        self.flags()
            .unwrap_or_default()
            .iter()
            .any(|item| item.eq_ignore_ascii_case(flag))
    }

    /// `INTERNALDATE "..."` text.
    pub fn internal_date(&self) -> Option<String> {
        self.get("INTERNALDATE")?.to_string_lossy()
    }

    /// `RFC822.SIZE n`.
    pub fn rfc822_size(&self) -> Option<u64> {
        self.get("RFC822.SIZE")?.as_number()
    }

    /// Body section bytes, e.g. `body("")` for `BODY[]`,
    /// `body("HEADER.FIELDS (FROM)")`. Comparison ignores case, quotes,
    /// whitespace differences, `.PEEK` and a partial `<origin>` suffix.
    /// `NIL` yields `None`.
    pub fn body(&self, section: &str) -> Option<&[u8]> {
        let wanted = normalize_body_key(&format!("BODY[{section}]"));
        self.attributes
            .iter()
            .find(|(key, _)| key.starts_with("BODY[") && normalize_body_key(key) == wanted)
            .and_then(|(_, value)| match value {
                Value::Literal(bytes) | Value::Quoted(bytes) => Some(bytes.as_slice()),
                _ => None,
            })
    }

    /// The first message-content attribute (`BODY[...]`, `BINARY[...]`,
    /// `RFC822`, `RFC822.HEADER`, `RFC822.TEXT`) — the `item[1]` the Python
    /// code read from an `imaplib` FETCH tuple.
    pub fn first_body(&self) -> Option<&[u8]> {
        self.attributes
            .iter()
            .filter(|(key, _)| {
                key.starts_with("BODY[")
                    || key.starts_with("BINARY[")
                    || key == "RFC822"
                    || key == "RFC822.HEADER"
                    || key == "RFC822.TEXT"
            })
            .find_map(|(_, value)| match value {
                Value::Literal(bytes) | Value::Quoted(bytes) => Some(bytes.as_slice()),
                _ => None,
            })
    }
}

/// Parse the data of a FETCH response: `(` name value ... `)`.
pub(crate) fn parse_fetch_data(seq: u32, cursor: &mut Cursor<'_>) -> Result<FetchResponse> {
    let value = cursor.read_value()?;
    let items = match value {
        Value::List(items) => items,
        _ => return Err(protocol("FETCH response data is not a list")),
    };
    if items.len() % 2 != 0 {
        return Err(protocol("FETCH response has an odd number of items"));
    }
    let mut attributes = Vec::with_capacity(items.len() / 2);
    let mut iter = items.into_iter();
    while let (Some(key), Some(value)) = (iter.next(), iter.next()) {
        let name = match key {
            Value::Atom(atom) => atom.to_ascii_uppercase(),
            other => {
                return Err(protocol(format!(
                    "unexpected FETCH attribute name {other:?}"
                )))
            }
        };
        attributes.push((name, value));
    }
    Ok(FetchResponse { seq, attributes })
}

/// One `* LIST` / `* LSUB` entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListEntry {
    /// Attributes such as `\HasNoChildren`, `\Noselect`, `\Sent`, original case.
    pub attributes: Vec<String>,
    /// Hierarchy delimiter; `None` for `NIL`.
    pub delimiter: Option<String>,
    /// Mailbox name as sent by the server (quoted strings unescaped,
    /// literals verbatim), decoded as UTF-8 with replacement characters —
    /// the same as `name.decode("utf-8", "replace")` in `_parse_folders`.
    /// Not modified-UTF-7 decoded; see [`ListEntry::decoded_name`].
    pub name: String,
    /// Raw mailbox name bytes.
    pub name_bytes: Vec<u8>,
    /// True when the name was sent as a literal.
    pub name_was_literal: bool,
}

impl ListEntry {
    /// True when the entry has `attribute` (case-insensitive).
    pub fn has_attribute(&self, attribute: &str) -> bool {
        self.attributes
            .iter()
            .any(|item| item.eq_ignore_ascii_case(attribute))
    }

    /// True unless `\Noselect` or `\NonExistent` is present.
    pub fn is_selectable(&self) -> bool {
        !self.has_attribute("\\Noselect") && !self.has_attribute("\\NonExistent")
    }

    /// Name decoded from IMAP modified UTF-7 (falls back to the raw name).
    pub fn decoded_name(&self) -> String {
        super::utf7::decode(&self.name).unwrap_or_else(|_| self.name.clone())
    }
}

/// Parse LIST data: `(attrs) delimiter name [extended-data]`.
pub(crate) fn parse_list_data(cursor: &mut Cursor<'_>) -> Result<ListEntry> {
    let attributes = match cursor.read_value()? {
        Value::List(items) => items.iter().filter_map(Value::to_string_lossy).collect(),
        _ => return Err(protocol("LIST attributes are not a list")),
    };
    let delimiter = match cursor.read_value()? {
        Value::Nil => None,
        Value::Quoted(bytes) | Value::Literal(bytes) => {
            Some(String::from_utf8_lossy(&bytes).into_owned())
        }
        Value::Atom(atom) => Some(atom),
        _ => return Err(protocol("malformed LIST delimiter")),
    };
    let (name_bytes, name_was_literal) = match cursor.read_value()? {
        Value::Quoted(bytes) => (bytes, false),
        Value::Literal(bytes) => (bytes, true),
        Value::Atom(atom) => (atom.into_bytes(), false),
        Value::Number(number) => (number.to_string().into_bytes(), false),
        Value::Nil => (b"NIL".to_vec(), false),
        Value::List(_) => return Err(protocol("malformed LIST mailbox name")),
    };
    Ok(ListEntry {
        attributes,
        delimiter,
        name: String::from_utf8_lossy(&name_bytes).into_owned(),
        name_bytes,
        name_was_literal,
    })
}

/// Parse SEARCH data: numbers, optionally followed by `(MODSEQ n)`.
pub(crate) fn parse_search_data(cursor: &mut Cursor<'_>) -> Result<Vec<u32>> {
    let mut numbers = Vec::new();
    for value in cursor.values()? {
        match value {
            Value::Number(number) => numbers.push(
                u32::try_from(number)
                    .map_err(|_| protocol("SEARCH result number is out of range"))?,
            ),
            Value::List(_) => {}
            other => {
                return Err(protocol(format!(
                    "unexpected token in SEARCH response: {other:?}"
                )))
            }
        }
    }
    Ok(numbers)
}

/// Expand a UID set such as `304,319:320` into numbers (`None` for `*` or
/// malformed input, or for ranges larger than 1,000,000 entries).
pub fn expand_uid_set(set: &str) -> Option<Vec<u32>> {
    let mut out = Vec::new();
    for item in set.split(',') {
        let (low, high) = match item.split_once(':') {
            Some((a, b)) => (a.trim().parse::<u32>().ok()?, b.trim().parse::<u32>().ok()?),
            None => {
                let value = item.trim().parse::<u32>().ok()?;
                (value, value)
            }
        };
        let (low, high) = (low.min(high), low.max(high));
        if (high - low) as usize + out.len() > 1_000_000 {
            return None;
        }
        out.extend(low..=high);
    }
    Some(out)
}

/// Compress UIDs into a set string (`1,2,3,7` -> `1:3,7`), sorted and
/// de-duplicated.
pub fn compress_uid_set(uids: &[u32]) -> String {
    let mut sorted = uids.to_vec();
    sorted.sort_unstable();
    sorted.dedup();
    let mut out: Vec<String> = Vec::new();
    let mut index = 0;
    while index < sorted.len() {
        let start = sorted[index];
        let mut end = start;
        while index + 1 < sorted.len() && sorted[index + 1] == end + 1 {
            index += 1;
            end = sorted[index];
        }
        out.push(if start == end {
            start.to_string()
        } else {
            format!("{start}:{end}")
        });
        index += 1;
    }
    out.join(",")
}
