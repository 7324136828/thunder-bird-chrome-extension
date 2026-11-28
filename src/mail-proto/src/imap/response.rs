//! IMAP response framing: status, response codes, untagged responses and
//! the result of one tagged command (`imaplib`'s `(typ, data)` plus the
//! untagged responses it stores in `untagged_responses`).

use super::parser::{self, Cursor, FetchResponse, ListEntry, Part, Value};
use crate::error::{ProtoError, Result};

/// Tagged completion status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Status {
    Ok,
    No,
    Bad,
}

impl Status {
    /// `"OK"`, `"NO"` or `"BAD"` — the `typ` string `imaplib` returned.
    pub fn as_str(self) -> &'static str {
        match self {
            Status::Ok => "OK",
            Status::No => "NO",
            Status::Bad => "BAD",
        }
    }

    fn parse(word: &str) -> Option<Self> {
        match word.to_ascii_uppercase().as_str() {
            "OK" => Some(Status::Ok),
            "NO" => Some(Status::No),
            "BAD" => Some(Status::Bad),
            _ => None,
        }
    }
}

/// A bracketed response code such as `[UIDVALIDITY 3857529045]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResponseCode {
    /// Uppercased code name, e.g. `UIDVALIDITY`, `APPENDUID`, `READ-ONLY`.
    pub name: String,
    /// Raw argument text after the name (may be empty).
    pub args: String,
}

impl ResponseCode {
    fn parse(inner: &str) -> Self {
        let inner = inner.trim();
        match inner.split_once(' ') {
            Some((name, args)) => ResponseCode {
                name: name.to_ascii_uppercase(),
                args: args.trim().to_string(),
            },
            None => ResponseCode {
                name: inner.to_ascii_uppercase(),
                args: String::new(),
            },
        }
    }

    /// Argument words (parentheses stripped), e.g. the capabilities in
    /// `[CAPABILITY IMAP4rev1 MOVE]` or flags in `[PERMANENTFLAGS (\Seen)]`.
    pub fn words(&self) -> Vec<String> {
        self.args
            .replace(['(', ')'], " ")
            .split_whitespace()
            .map(str::to_string)
            .collect()
    }

    /// The first argument as a number (`UIDVALIDITY`, `UIDNEXT`, ...).
    pub fn number(&self) -> Option<u32> {
        self.args.split_whitespace().next()?.parse().ok()
    }
}

/// Split `"[CODE args] text"` into the code and the remaining text.
fn split_code(text: &str) -> (Option<ResponseCode>, String) {
    let trimmed = text.trim_start();
    if let Some(stripped) = trimmed.strip_prefix('[') {
        if let Some(end) = stripped.find(']') {
            let code = ResponseCode::parse(&stripped[..end]);
            return (Some(code), stripped[end + 1..].trim().to_string());
        }
    }
    (None, trimmed.trim_end().to_string())
}

/// An untagged (`* ...`) server response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UntaggedResponse {
    /// Leading number for `* 3 EXISTS`, `* 7 FETCH (...)`, `* 2 EXPUNGE`.
    pub number: Option<u32>,
    /// Uppercased response name: `FETCH`, `LIST`, `SEARCH`, `EXISTS`, `OK`,
    /// `CAPABILITY`, `BYE`, ...
    pub kind: String,
    /// Response code of a status response (`* OK [UIDNEXT 4392] ...`).
    pub code: Option<ResponseCode>,
    /// The whole response after `* `, split into `imaplib`-style data items
    /// (literals preserved as bytes).
    pub parts: Vec<Part>,
    /// Byte offset in `parts[0].text` where the data after `kind` begins.
    data_offset: usize,
}

impl UntaggedResponse {
    /// Parse the parts of a line whose leading `* ` was already removed.
    pub fn parse(parts: Vec<Part>) -> Result<Self> {
        let first = parts
            .first()
            .ok_or_else(|| ProtoError::Protocol("empty untagged response".to_string()))?;
        let text = &first.text;
        let mut offset = 0;
        let word = |start: usize| -> (usize, usize) {
            let end = text[start..]
                .iter()
                .position(|&b| b == b' ')
                .map_or(text.len(), |i| start + i);
            (start, end)
        };
        let (start, end) = word(offset);
        let first_word = String::from_utf8_lossy(&text[start..end]).into_owned();
        let mut number = None;
        let kind;
        if !first_word.is_empty() && first_word.bytes().all(|b| b.is_ascii_digit()) {
            number = first_word.parse().ok();
            offset = (end + 1).min(text.len());
            let (start, end) = word(offset);
            kind = String::from_utf8_lossy(&text[start..end]).to_ascii_uppercase();
            offset = end;
        } else {
            kind = first_word.to_ascii_uppercase();
            offset = end;
        }
        if text.get(offset) == Some(&b' ') {
            offset += 1;
        }
        if kind.is_empty() {
            return Err(ProtoError::Protocol(
                "untagged response without a name".to_string(),
            ));
        }
        let mut response = UntaggedResponse {
            number,
            kind,
            code: None,
            parts,
            data_offset: offset,
        };
        if response.is_status() {
            let (code, _) = split_code(&response.data_text());
            response.code = code;
        }
        Ok(response)
    }

    fn is_status(&self) -> bool {
        matches!(self.kind.as_str(), "OK" | "NO" | "BAD" | "PREAUTH" | "BYE")
    }

    /// Data text after the response name in the first part (lossy; literal
    /// contents not included).
    pub fn data_text(&self) -> String {
        let text = &self.parts[0].text;
        String::from_utf8_lossy(&text[self.data_offset.min(text.len())..]).into_owned()
    }

    /// Human-readable text of a status response (after any code).
    pub fn text(&self) -> String {
        split_code(&self.data_text()).1
    }

    pub(crate) fn cursor(&self) -> Cursor<'_> {
        Cursor::new(&self.parts, 0, self.data_offset)
    }

    /// Parse all data after the response name as values.
    pub fn values(&self) -> Result<Vec<Value>> {
        self.cursor().values()
    }

    /// Parse as FETCH (`kind == "FETCH"`).
    pub fn fetch(&self) -> Result<FetchResponse> {
        let seq = self
            .number
            .ok_or_else(|| ProtoError::Protocol("FETCH response without a number".into()))?;
        parser::parse_fetch_data(seq, &mut self.cursor())
    }

    /// Parse as LIST / LSUB.
    pub fn list_entry(&self) -> Result<ListEntry> {
        parser::parse_list_data(&mut self.cursor())
    }

    /// Parse as SEARCH.
    pub fn search(&self) -> Result<Vec<u32>> {
        parser::parse_search_data(&mut self.cursor())
    }

    /// Words of a CAPABILITY / ENABLED response, uppercased.
    pub fn words_upper(&self) -> Vec<String> {
        self.data_text()
            .split_whitespace()
            .map(str::to_ascii_uppercase)
            .collect()
    }
}

/// A tagged completion line.
#[derive(Debug, Clone)]
pub(crate) struct Tagged {
    pub tag: String,
    pub status: Status,
    pub code: Option<ResponseCode>,
    pub text: String,
    pub raw_text: String,
}

/// Any server response line.
#[derive(Debug, Clone)]
pub(crate) enum Response {
    Untagged(UntaggedResponse),
    Tagged(Tagged),
    Continuation(String),
}

/// Classify a complete response (all literal parts read).
pub(crate) fn parse_response(mut parts: Vec<Part>) -> Result<Response> {
    let first = &parts[0].text;
    if first.starts_with(b"+") {
        let text = String::from_utf8_lossy(&first[1..]).trim().to_string();
        return Ok(Response::Continuation(text));
    }
    if first.starts_with(b"* ") || first.as_slice() == b"*" {
        let skip = first.len().min(2);
        parts[0].text.drain(..skip);
        return UntaggedResponse::parse(parts).map(Response::Untagged);
    }
    let joined: Vec<u8> = parts.iter().flat_map(|part| part.text.clone()).collect();
    let line = String::from_utf8_lossy(&joined).into_owned();
    let mut words = line.splitn(3, ' ');
    let tag = words.next().unwrap_or_default().to_string();
    let status = words.next().and_then(Status::parse).ok_or_else(|| {
        ProtoError::Protocol(format!(
            "unexpected response line: {}",
            line.chars().take(200).collect::<String>()
        ))
    })?;
    let raw_text = words.next().unwrap_or_default().trim().to_string();
    let (code, text) = split_code(&raw_text);
    Ok(Response::Tagged(Tagged {
        tag,
        status,
        code,
        text,
        raw_text,
    }))
}

/// Return the declared literal size if `line` ends with `{n}`, `{n+}` or
/// `~{n}`.
pub(crate) fn literal_size(line: &[u8]) -> Option<usize> {
    let body = line.strip_suffix(b"}")?;
    let open = body.iter().rposition(|&b| b == b'{')?;
    let digits = &body[open + 1..];
    let digits = digits.strip_suffix(b"+").unwrap_or(digits);
    if digits.is_empty() || digits.len() > 12 || !digits.iter().all(u8::is_ascii_digit) {
        return None;
    }
    std::str::from_utf8(digits).ok()?.parse().ok()
}

/// The outcome of one tagged command: the `(typ, data)` pair `imaplib`
/// returned plus every untagged response received while it ran.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandResponse {
    /// Tagged status.
    pub status: Status,
    /// Response code on the tagged line (`[READ-WRITE]`, `[APPENDUID ..]`).
    pub code: Option<ResponseCode>,
    /// Tagged text after the code.
    pub text: String,
    /// Tagged text including the code (used for error messages).
    pub raw_text: String,
    /// Untagged responses in arrival order.
    pub untagged: Vec<UntaggedResponse>,
}

impl CommandResponse {
    /// True for `OK`.
    pub fn is_ok(&self) -> bool {
        self.status == Status::Ok
    }

    /// Convert `NO` / `BAD` into [`ProtoError::No`] / [`ProtoError::Bad`].
    pub fn into_result(self) -> Result<Self> {
        match self.status {
            Status::Ok => Ok(self),
            Status::No => Err(ProtoError::No(self.raw_text)),
            Status::Bad => Err(ProtoError::Bad(self.raw_text)),
        }
    }

    /// Untagged responses of one kind (case-insensitive).
    pub fn untagged_of<'a>(&'a self, kind: &'a str) -> impl Iterator<Item = &'a UntaggedResponse> {
        self.untagged
            .iter()
            .filter(move |response| response.kind.eq_ignore_ascii_case(kind))
    }

    /// A response code by name, from the tagged line or any untagged status
    /// response (the last one wins, like `imaplib.response(code)`).
    pub fn code_named(&self, name: &str) -> Option<&ResponseCode> {
        if let Some(code) = self
            .code
            .as_ref()
            .filter(|c| c.name.eq_ignore_ascii_case(name))
        {
            return Some(code);
        }
        self.untagged
            .iter()
            .rev()
            .filter_map(|response| response.code.as_ref())
            .find(|code| code.name.eq_ignore_ascii_case(name))
    }

    /// Parse every untagged FETCH response.
    pub fn fetches(&self) -> Result<Vec<FetchResponse>> {
        self.untagged_of("FETCH")
            .map(UntaggedResponse::fetch)
            .collect()
    }

    /// Parse every untagged LIST (or LSUB) response.
    pub fn list_entries(&self) -> Result<Vec<ListEntry>> {
        self.untagged
            .iter()
            .filter(|r| r.kind == "LIST" || r.kind == "LSUB")
            .map(UntaggedResponse::list_entry)
            .collect()
    }

    /// Numbers from every untagged SEARCH response, in order.
    pub fn search_results(&self) -> Result<Vec<u32>> {
        let mut out = Vec::new();
        for response in self.untagged_of("SEARCH") {
            out.extend(response.search()?);
        }
        Ok(out)
    }

    /// Sequence numbers from `* n EXPUNGE` responses, in order.
    pub fn expunged(&self) -> Vec<u32> {
        self.untagged_of("EXPUNGE")
            .filter_map(|r| r.number)
            .collect()
    }
}

/// Result of `SELECT` / `EXAMINE`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MailboxInfo {
    /// `* n EXISTS` (what `imaplib.select` returned as `data[0]`).
    pub exists: u32,
    /// `* n RECENT`.
    pub recent: u32,
    /// `[UIDVALIDITY n]`, if the server sent it.
    pub uid_validity: Option<u32>,
    /// `[UIDNEXT n]`, if the server sent it.
    pub uid_next: Option<u32>,
    /// Raw `[UIDVALIDITY ...]` argument text, for callers that validate it
    /// themselves (`retention.normalize_uid_validity`).
    pub uid_validity_raw: Option<String>,
    /// Raw `[UIDNEXT ...]` argument text.
    pub uid_next_raw: Option<String>,
    /// `* FLAGS (...)`.
    pub flags: Vec<String>,
    /// `[PERMANENTFLAGS (...)]`.
    pub permanent_flags: Option<Vec<String>>,
    /// True for EXAMINE or a `[READ-ONLY]` completion.
    pub read_only: bool,
    /// The full command response, for anything else (e.g. HIGHESTMODSEQ).
    pub response: CommandResponse,
}

impl MailboxInfo {
    pub(crate) fn from_response(response: CommandResponse, examine: bool) -> Self {
        let exists = response
            .untagged_of("EXISTS")
            .filter_map(|r| r.number)
            .last()
            .unwrap_or(0);
        let recent = response
            .untagged_of("RECENT")
            .filter_map(|r| r.number)
            .last()
            .unwrap_or(0);
        let flags = response
            .untagged_of("FLAGS")
            .last()
            .and_then(|r| r.values().ok())
            .and_then(|values| values.into_iter().next())
            .and_then(|value| match value {
                Value::List(items) => {
                    Some(items.iter().filter_map(Value::to_string_lossy).collect())
                }
                _ => None,
            })
            .unwrap_or_default();
        let uid_validity_code = response.code_named("UIDVALIDITY");
        let uid_next_code = response.code_named("UIDNEXT");
        let read_only = examine || response.code_named("READ-ONLY").is_some();
        MailboxInfo {
            exists,
            recent,
            uid_validity: uid_validity_code.and_then(ResponseCode::number),
            uid_next: uid_next_code.and_then(ResponseCode::number),
            uid_validity_raw: uid_validity_code.map(|c| c.args.clone()),
            uid_next_raw: uid_next_code.map(|c| c.args.clone()),
            flags,
            permanent_flags: response
                .code_named("PERMANENTFLAGS")
                .map(ResponseCode::words),
            read_only,
            response,
        }
    }
}

/// `[APPENDUID uidvalidity uid-set]` (RFC 4315).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppendUid {
    pub uid_validity: u32,
    /// UID set of the appended message(s), e.g. `"3955"`.
    pub uids: String,
}

impl AppendUid {
    pub(crate) fn from_code(code: &ResponseCode) -> Option<Self> {
        let mut words = code.args.split_whitespace();
        Some(AppendUid {
            uid_validity: words.next()?.parse().ok()?,
            uids: words.next()?.to_string(),
        })
    }
}

/// `[COPYUID uidvalidity source-set dest-set]` (RFC 4315).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CopyUid {
    /// UIDVALIDITY of the destination mailbox.
    pub uid_validity: u32,
    pub source: String,
    pub destination: String,
}

impl CopyUid {
    pub(crate) fn from_code(code: &ResponseCode) -> Option<Self> {
        let mut words = code.args.split_whitespace();
        Some(CopyUid {
            uid_validity: words.next()?.parse().ok()?,
            source: words.next()?.to_string(),
            destination: words.next()?.to_string(),
        })
    }

    /// `(source uid, destination uid)` pairs, if both sets expand.
    pub fn pairs(&self) -> Option<Vec<(u32, u32)>> {
        let source = parser::expand_uid_set(&self.source)?;
        let destination = parser::expand_uid_set(&self.destination)?;
        (source.len() == destination.len()).then(|| source.into_iter().zip(destination).collect())
    }
}
