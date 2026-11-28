//! Fake IMAP4rev1 server with an in-memory mailbox model.

use std::sync::{Arc, Mutex};

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use native_tls::TlsAcceptor;

use super::{
    acceptor, crlf, lock, now_internal_date, parse_imap_date, Failure, FailureQueue, LoggedCommand,
    ServerCore, TlsMode,
};
use crate::imap::parser::{Cursor, Part, Value};
use crate::imap::response::literal_size;
use crate::imap::{quote, Status};
use crate::transport::Transport;

const MAX_COMMAND_LINE: usize = 1024 * 1024;
const MAX_CLIENT_LITERAL: usize = 64 * 1024 * 1024;
const SYSTEM_FLAGS: &str = "\\Answered \\Flagged \\Deleted \\Seen \\Draft";
const SPECIAL_USE: [&str; 8] = [
    "\\All",
    "\\Archive",
    "\\Drafts",
    "\\Flagged",
    "\\Junk",
    "\\Sent",
    "\\Trash",
    "\\Important",
];

/// A stored message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FakeMessage {
    /// UID; 0 means "assign the folder's next UID" when added.
    pub uid: u32,
    /// Flags in original case, e.g. `\Seen`.
    pub flags: Vec<String>,
    /// IMAP date-time, `dd-Mon-yyyy hh:mm:ss +zzzz`.
    pub internal_date: String,
    /// Raw RFC 5322 bytes (line endings normalized to CRLF when added).
    pub raw: Vec<u8>,
}

impl FakeMessage {
    /// A message with no flags, INTERNALDATE "now" and an automatic UID.
    pub fn new(raw: impl Into<Vec<u8>>) -> Self {
        FakeMessage {
            uid: 0,
            flags: Vec::new(),
            internal_date: now_internal_date(),
            raw: raw.into(),
        }
    }

    /// Set the flags.
    pub fn with_flags(mut self, flags: &[&str]) -> Self {
        self.flags = flags.iter().map(|f| f.to_string()).collect();
        self
    }

    /// Set INTERNALDATE (`"01-Jan-2026 10:00:00 +0000"`).
    pub fn with_internal_date(mut self, date: &str) -> Self {
        self.internal_date = date.to_string();
        self
    }

    /// Force a UID.
    pub fn with_uid(mut self, uid: u32) -> Self {
        self.uid = uid;
        self
    }

    /// Case-insensitive flag check.
    pub fn has_flag(&self, flag: &str) -> bool {
        self.flags.iter().any(|f| f.eq_ignore_ascii_case(flag))
    }

    fn header_end(&self) -> usize {
        header_end(&self.raw)
    }

    fn header(&self) -> &[u8] {
        &self.raw[..self.header_end()]
    }

    fn body(&self) -> &[u8] {
        &self.raw[self.header_end()..]
    }
}

fn header_end(raw: &[u8]) -> usize {
    if let Some(index) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
        return index + 4;
    }
    if let Some(index) = raw.windows(2).position(|w| w == b"\n\n") {
        return index + 2;
    }
    raw.len()
}

/// A mailbox folder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FakeFolder {
    pub name: String,
    /// LIST attributes, e.g. `\Sent`, `\Noselect`, `\HasNoChildren`.
    pub attributes: Vec<String>,
    /// `None` makes SELECT omit `[UIDVALIDITY]` (an "unknown epoch").
    pub uid_validity: Option<u32>,
    pub uid_next: u32,
    /// Messages ordered by UID; sequence number = index + 1.
    pub messages: Vec<FakeMessage>,
}

impl FakeFolder {
    fn new(name: &str, attributes: &[&str], uid_validity: u32) -> Self {
        FakeFolder {
            name: name.to_string(),
            attributes: attributes.iter().map(|a| a.to_string()).collect(),
            uid_validity: Some(uid_validity),
            uid_next: 1,
            messages: Vec::new(),
        }
    }

    /// UIDs in order.
    pub fn uids(&self) -> Vec<u32> {
        self.messages.iter().map(|m| m.uid).collect()
    }

    /// Message by UID.
    pub fn message(&self, uid: u32) -> Option<&FakeMessage> {
        self.messages.iter().find(|m| m.uid == uid)
    }

    /// Case-insensitive attribute check.
    pub fn has_attribute(&self, attribute: &str) -> bool {
        self.attributes
            .iter()
            .any(|a| a.eq_ignore_ascii_case(attribute))
    }

    /// Insert a message, assigning a UID when `uid == 0`; returns the UID.
    pub fn insert(&mut self, mut message: FakeMessage) -> u32 {
        message.raw = crlf(&message.raw);
        if message.uid == 0 {
            message.uid = self.uid_next;
        }
        self.uid_next = self.uid_next.max(message.uid.saturating_add(1));
        let uid = message.uid;
        let position = self.messages.partition_point(|m| m.uid < uid);
        if self.messages.get(position).map(|m| m.uid) == Some(uid) {
            self.messages[position] = message;
        } else {
            self.messages.insert(position, message);
        }
        uid
    }

    fn max_uid(&self) -> u32 {
        self.messages.last().map_or(0, |m| m.uid)
    }
}

/// What the hook sees for each command.
#[derive(Debug, Clone)]
pub struct ImapRequest {
    pub connection: usize,
    pub tag: String,
    /// Uppercased command name (`UID FETCH`, `SELECT`, ...).
    pub command: String,
    /// Logged command line (credentials redacted).
    pub line: String,
    /// Currently selected folder.
    pub selected: Option<String>,
}

/// What the hook wants the server to do.
#[derive(Debug, Clone)]
pub enum HookAction {
    /// Handle the command normally.
    Continue,
    /// Send these raw untagged lines (CRLF appended to each; they may embed
    /// `{n}\r\n` literals) followed by `<tag> <status> <text>`.
    Respond {
        untagged: Vec<Vec<u8>>,
        status: Status,
        text: String,
    },
    /// Close the connection without answering.
    Disconnect,
}

/// Response hook; called (outside the state lock) for every command.
pub type ImapHook = Arc<dyn Fn(&ImapRequest) -> HookAction + Send + Sync>;

#[derive(Debug, Clone)]
struct ImapConfig {
    users: Vec<(String, String)>,
    oauth: Vec<(String, String)>,
    capabilities: Vec<String>,
    pre_auth_capabilities: Option<Vec<String>>,
    greeting_capabilities: bool,
    login_capability_code: bool,
    special_use_in_plain_list: bool,
    literal_names: bool,
    delimiter: Option<String>,
    tls: Option<TlsMode>,
}

impl ImapConfig {
    fn has(&self, capability: &str) -> bool {
        self.capabilities
            .iter()
            .any(|c| c.eq_ignore_ascii_case(capability))
    }

    fn rev2(&self) -> bool {
        self.has("IMAP4rev2")
    }
}

struct ImapShared {
    config: ImapConfig,
    folders: Vec<FakeFolder>,
    log: Vec<LoggedCommand>,
    failures: FailureQueue,
    hook: Option<ImapHook>,
    connections: usize,
    logouts: usize,
    next_uid_validity: u32,
}

impl ImapShared {
    fn find(&self, name: &str) -> Option<usize> {
        if name.eq_ignore_ascii_case("INBOX") {
            return self
                .folders
                .iter()
                .position(|f| f.name.eq_ignore_ascii_case("INBOX"));
        }
        self.folders.iter().position(|f| f.name == name)
    }

    fn folder_mut(&mut self, name: &str) -> &mut FakeFolder {
        if self.find(name).is_none() {
            let validity = self.next_uid_validity;
            self.next_uid_validity += 1;
            self.folders.push(FakeFolder::new(name, &[], validity));
        }
        let index = self.find(name).expect("folder exists");
        &mut self.folders[index]
    }
}

/// Builder for [`FakeImapServer`].
pub struct FakeImapBuilder {
    shared: ImapShared,
}

impl FakeImapBuilder {
    fn new() -> Self {
        FakeImapBuilder {
            shared: ImapShared {
                config: ImapConfig {
                    users: Vec::new(),
                    oauth: Vec::new(),
                    capabilities: [
                        "IMAP4rev1",
                        "ENABLE",
                        "UTF8=ACCEPT",
                        "SPECIAL-USE",
                        "MOVE",
                        "UIDPLUS",
                    ]
                    .iter()
                    .map(|c| c.to_string())
                    .collect(),
                    pre_auth_capabilities: None,
                    greeting_capabilities: false,
                    login_capability_code: false,
                    special_use_in_plain_list: true,
                    literal_names: false,
                    delimiter: Some("/".to_string()),
                    tls: None,
                },
                folders: vec![FakeFolder::new("INBOX", &[], 1)],
                log: Vec::new(),
                failures: FailureQueue::default(),
                hook: None,
                connections: 0,
                logouts: 0,
                next_uid_validity: 1000,
            },
        }
    }

    /// Accept `LOGIN user password` / `AUTHENTICATE PLAIN` for this user
    /// (may be called repeatedly).
    pub fn credentials(mut self, user: &str, password: &str) -> Self {
        self.shared
            .config
            .users
            .push((user.to_string(), password.to_string()));
        self
    }

    /// Accept `AUTHENTICATE XOAUTH2` with this bearer token.
    pub fn oauth_token(mut self, user: &str, token: &str) -> Self {
        self.shared
            .config
            .oauth
            .push((user.to_string(), token.to_string()));
        self
    }

    /// Capabilities after authentication (and before it, unless
    /// [`FakeImapBuilder::pre_auth_capabilities`] is set). Also gates
    /// server features: `MOVE`, `UIDPLUS`, `ENABLE`, `SPECIAL-USE`,
    /// `IMAP4rev2`. Default: `IMAP4rev1 ENABLE UTF8=ACCEPT SPECIAL-USE MOVE
    /// UIDPLUS`.
    pub fn capabilities(mut self, capabilities: &[&str]) -> Self {
        self.shared.config.capabilities = capabilities.iter().map(|c| c.to_string()).collect();
        self
    }

    /// Capabilities advertised before authentication.
    pub fn pre_auth_capabilities(mut self, capabilities: &[&str]) -> Self {
        self.shared.config.pre_auth_capabilities =
            Some(capabilities.iter().map(|c| c.to_string()).collect());
        self
    }

    /// Include `[CAPABILITY ...]` in the greeting (default: no, so clients
    /// send CAPABILITY).
    pub fn greeting_capabilities(mut self, enabled: bool) -> Self {
        self.shared.config.greeting_capabilities = enabled;
        self
    }

    /// Include `[CAPABILITY ...]` in the LOGIN/AUTHENTICATE completion.
    pub fn login_capability_code(mut self, enabled: bool) -> Self {
        self.shared.config.login_capability_code = enabled;
        self
    }

    /// Include special-use attributes in a plain `LIST` (default true, as
    /// Gmail and Dovecot do); when false they only appear with
    /// `RETURN (SPECIAL-USE)`.
    pub fn special_use_in_plain_list(mut self, enabled: bool) -> Self {
        self.shared.config.special_use_in_plain_list = enabled;
        self
    }

    /// Send every LIST mailbox name as a literal.
    pub fn literal_names(mut self, enabled: bool) -> Self {
        self.shared.config.literal_names = enabled;
        self
    }

    /// Hierarchy delimiter (`None` sends `NIL`). Default `/`.
    pub fn delimiter(mut self, delimiter: Option<&str>) -> Self {
        self.shared.config.delimiter = delimiter.map(str::to_string);
        self
    }

    /// Offer TLS with the bundled test certificate.
    pub fn tls(mut self, mode: TlsMode) -> Self {
        self.shared.config.tls = Some(mode);
        self
    }

    /// Add (or replace the attributes of) a folder.
    pub fn folder(mut self, name: &str, attributes: &[&str]) -> Self {
        let folder = self.shared.folder_mut(name);
        folder.attributes = attributes.iter().map(|a| a.to_string()).collect();
        self
    }

    /// Set a folder's UIDVALIDITY (`None` omits it from SELECT).
    pub fn uid_validity(mut self, folder: &str, uid_validity: Option<u32>) -> Self {
        self.shared.folder_mut(folder).uid_validity = uid_validity;
        self
    }

    /// Set a folder's UIDNEXT (must exceed existing UIDs to matter).
    pub fn uid_next(mut self, folder: &str, uid_next: u32) -> Self {
        let folder = self.shared.folder_mut(folder);
        folder.uid_next = uid_next.max(folder.max_uid() + 1);
        self
    }

    /// Add a raw message (no flags, INTERNALDATE now, next UID).
    pub fn message(self, folder: &str, raw: impl Into<Vec<u8>>) -> Self {
        self.message_with(folder, FakeMessage::new(raw))
    }

    /// Add a fully specified message.
    pub fn message_with(mut self, folder: &str, message: FakeMessage) -> Self {
        self.shared.folder_mut(folder).insert(message);
        self
    }

    /// Install a response hook.
    pub fn hook<F>(mut self, hook: F) -> Self
    where
        F: Fn(&ImapRequest) -> HookAction + Send + Sync + 'static,
    {
        self.shared.hook = Some(Arc::new(hook));
        self
    }

    /// Start serving.
    pub fn start(self) -> FakeImapServer {
        let tls = self.shared.config.tls;
        let state = Arc::new(Mutex::new(self.shared));
        let handler_state = Arc::clone(&state);
        let starttls = (tls == Some(TlsMode::StartTls)).then(acceptor);
        let core = ServerCore::spawn(
            "imap",
            tls == Some(TlsMode::Implicit),
            move |transport, id| {
                Session::new(transport, id, Arc::clone(&handler_state), starttls.clone()).run();
            },
        );
        FakeImapServer { core, state }
    }
}

/// A running fake IMAP server.
pub struct FakeImapServer {
    core: ServerCore,
    state: Arc<Mutex<ImapShared>>,
}

impl FakeImapServer {
    /// Start building a server. INBOX exists by default.
    pub fn builder() -> FakeImapBuilder {
        FakeImapBuilder::new()
    }

    /// Always `127.0.0.1`.
    pub fn host(&self) -> &'static str {
        "127.0.0.1"
    }

    pub fn port(&self) -> u16 {
        self.core.addr().port()
    }

    pub fn addr(&self) -> std::net::SocketAddr {
        self.core.addr()
    }

    /// Logged command lines (without tags, credentials redacted).
    pub fn commands(&self) -> Vec<String> {
        lock(&self.state)
            .log
            .iter()
            .map(|c| c.line.clone())
            .collect()
    }

    /// Logged command names (`CAPABILITY`, `UID FETCH`, ...).
    pub fn command_names(&self) -> Vec<String> {
        lock(&self.state)
            .log
            .iter()
            .map(|c| c.name.clone())
            .collect()
    }

    /// Full log entries.
    pub fn log(&self) -> Vec<LoggedCommand> {
        lock(&self.state).log.clone()
    }

    /// Clear the command log.
    pub fn clear_log(&self) {
        lock(&self.state).log.clear();
    }

    /// Number of accepted connections.
    pub fn connection_count(&self) -> usize {
        lock(&self.state).connections
    }

    /// Number of LOGOUT commands handled.
    pub fn logout_count(&self) -> usize {
        lock(&self.state).logouts
    }

    /// Snapshot of a folder.
    pub fn folder(&self, name: &str) -> Option<FakeFolder> {
        let state = lock(&self.state);
        state.find(name).map(|index| state.folders[index].clone())
    }

    /// Folder names in creation order.
    pub fn folder_names(&self) -> Vec<String> {
        lock(&self.state)
            .folders
            .iter()
            .map(|f| f.name.clone())
            .collect()
    }

    /// UIDs in a folder (empty if it does not exist).
    pub fn uids(&self, folder: &str) -> Vec<u32> {
        self.folder(folder).map(|f| f.uids()).unwrap_or_default()
    }

    /// Snapshot of one message.
    pub fn message(&self, folder: &str, uid: u32) -> Option<FakeMessage> {
        self.folder(folder)?.message(uid).cloned()
    }

    /// Flags of one message.
    pub fn flags(&self, folder: &str, uid: u32) -> Option<Vec<String>> {
        self.message(folder, uid).map(|m| m.flags)
    }

    /// Add a message while running; returns its UID. Creates the folder.
    pub fn add_message(&self, folder: &str, message: FakeMessage) -> u32 {
        lock(&self.state).folder_mut(folder).insert(message)
    }

    /// Add a folder while running.
    pub fn add_folder(&self, name: &str, attributes: &[&str]) {
        let mut state = lock(&self.state);
        state.folder_mut(name).attributes = attributes.iter().map(|a| a.to_string()).collect();
    }

    /// Replace the capability list while running.
    pub fn set_capabilities(&self, capabilities: &[&str]) {
        lock(&self.state).config.capabilities =
            capabilities.iter().map(|c| c.to_string()).collect();
    }

    /// Fail the next occurrence of `command` (e.g. `"UID MOVE"`,
    /// `"SELECT"`, `"LOGIN"`); repeated calls queue more failures.
    pub fn fail_next(&self, command: &str, failure: Failure) {
        lock(&self.state).failures.push(command, failure);
    }

    /// Drop all queued failures.
    pub fn clear_failures(&self) {
        lock(&self.state).failures.clear();
    }

    /// Install or replace the response hook.
    pub fn set_hook<F>(&self, hook: F)
    where
        F: Fn(&ImapRequest) -> HookAction + Send + Sync + 'static,
    {
        lock(&self.state).hook = Some(Arc::new(hook));
    }

    /// Remove the response hook.
    pub fn clear_hook(&self) {
        lock(&self.state).hook = None;
    }

    /// Run `f` with mutable access to all folders.
    pub fn with_folders<R>(&self, f: impl FnOnce(&mut Vec<FakeFolder>) -> R) -> R {
        f(&mut lock(&self.state).folders)
    }
}

// ----------------------------------------------------------------------
// Session
// ----------------------------------------------------------------------

struct Selected {
    name: String,
    readonly: bool,
}

enum Flow {
    Continue,
    Close,
}

struct Session {
    transport: Transport,
    id: usize,
    state: Arc<Mutex<ImapShared>>,
    starttls: Option<TlsAcceptor>,
    authenticated: bool,
    selected: Option<Selected>,
    utf8: bool,
    out: Vec<u8>,
}

fn value_string(value: &Value) -> Option<String> {
    value.to_string_lossy()
}

fn is_seq_set(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || b == b':' || b == b'*' || b == b',')
}

fn parse_seq_set(set: &str, max: u32) -> Option<Vec<(u32, u32)>> {
    let mut ranges = Vec::new();
    let number = |text: &str| -> Option<u32> {
        if text == "*" {
            Some(max)
        } else {
            text.parse().ok()
        }
    };
    for item in set.split(',') {
        let (low, high) = match item.split_once(':') {
            Some((a, b)) => (number(a)?, number(b)?),
            None => {
                let value = number(item)?;
                (value, value)
            }
        };
        ranges.push((low.min(high), low.max(high)));
    }
    Some(ranges)
}

fn in_ranges(ranges: &[(u32, u32)], value: u32) -> bool {
    ranges
        .iter()
        .any(|&(low, high)| low <= value && value <= high)
}

fn flag_list(flags: &[String]) -> String {
    format!("({})", flags.join(" "))
}

/// LIST wildcard match: `*` matches anything, `%` anything but the delimiter.
fn wildcard_match(pattern: &[char], name: &[char], delimiter: Option<char>) -> bool {
    match pattern.first() {
        None => name.is_empty(),
        Some('*') => (0..=name.len()).any(|i| wildcard_match(&pattern[1..], &name[i..], delimiter)),
        Some('%') => (0..=name.len())
            .take_while(|&i| i == 0 || Some(name[i - 1]) != delimiter)
            .any(|i| wildcard_match(&pattern[1..], &name[i..], delimiter)),
        Some(&ch) => {
            name.first() == Some(&ch) && wildcard_match(&pattern[1..], &name[1..], delimiter)
        }
    }
}

fn list_matches(pattern: &str, name: &str, delimiter: Option<char>) -> bool {
    let (pattern, name) = if name.eq_ignore_ascii_case("INBOX") {
        (pattern.to_string(), "INBOX".to_string())
    } else {
        (pattern.to_string(), name.to_string())
    };
    let pattern_chars: Vec<char> = pattern.chars().collect();
    let name_chars: Vec<char> = name.chars().collect();
    if wildcard_match(&pattern_chars, &name_chars, delimiter) {
        return true;
    }
    // INBOX is case-insensitive.
    name == "INBOX" && pattern.eq_ignore_ascii_case("INBOX")
}

/// Render a mailbox name as a quoted string or literal.
fn render_name(name: &str, force_literal: bool) -> Vec<u8> {
    let needs_literal =
        force_literal || !name.is_ascii() || name.bytes().any(|b| b < 0x20 || b == 0x7f);
    if needs_literal {
        let mut out = format!("{{{}}}\r\n", name.len()).into_bytes();
        out.extend_from_slice(name.as_bytes());
        out
    } else {
        quote(name).into_bytes()
    }
}

fn literal(data: &[u8]) -> Vec<u8> {
    let mut out = format!("{{{}}}\r\n", data.len()).into_bytes();
    out.extend_from_slice(data);
    out
}

/// Header lines whose field name is (or, with `negate`, is not) listed.
fn header_fields(header: &[u8], names: &[String], negate: bool) -> Vec<u8> {
    let mut out = Vec::new();
    let mut fields: Vec<Vec<u8>> = Vec::new();
    for line in header.split_inclusive(|&b| b == b'\n') {
        if line == b"\r\n" || line == b"\n" {
            break;
        }
        if (line.starts_with(b" ") || line.starts_with(b"\t")) && !fields.is_empty() {
            fields.last_mut().expect("field").extend_from_slice(line);
        } else {
            fields.push(line.to_vec());
        }
    }
    for field in fields {
        let name = field
            .iter()
            .position(|&b| b == b':')
            .map(|i| {
                String::from_utf8_lossy(&field[..i])
                    .trim()
                    .to_ascii_uppercase()
            })
            .unwrap_or_default();
        if names.contains(&name) != negate {
            out.extend_from_slice(&field);
        }
    }
    out.extend_from_slice(b"\r\n");
    out
}

/// Unfolded values of a header field.
fn header_values(header: &[u8], field: &str) -> Vec<String> {
    let text = String::from_utf8_lossy(header);
    let mut values = Vec::new();
    let mut current: Option<String> = None;
    for line in text.split('\n') {
        let line = line.trim_end_matches('\r');
        if line.is_empty() {
            break;
        }
        if line.starts_with(' ') || line.starts_with('\t') {
            if let Some(value) = current.as_mut() {
                value.push(' ');
                value.push_str(line.trim());
            }
            continue;
        }
        if let Some(value) = current.take() {
            values.push(value);
        }
        if let Some((name, value)) = line.split_once(':') {
            if name.trim().eq_ignore_ascii_case(field) {
                current = Some(value.trim().to_string());
            }
        }
    }
    if let Some(value) = current {
        values.push(value);
    }
    values
}

fn contains_ci(haystack: &str, needle: &str) -> bool {
    haystack.to_lowercase().contains(&needle.to_lowercase())
}

#[derive(Debug, Clone, PartialEq)]
enum FetchItem {
    Uid,
    Flags,
    InternalDate,
    Size,
    Rfc822,
    Rfc822Header,
    Rfc822Text,
    Body {
        label: &'static str,
        section: String,
        peek: bool,
        partial: Option<(usize, Option<usize>)>,
    },
}

impl FetchItem {
    fn sets_seen(&self) -> bool {
        matches!(self, FetchItem::Rfc822 | FetchItem::Rfc822Text)
            || matches!(self, FetchItem::Body { peek: false, .. })
    }
}

fn parse_body_item(atom: &str) -> Option<FetchItem> {
    let upper = atom.to_ascii_uppercase();
    let (label, peek, start) = if upper.starts_with("BODY.PEEK[") {
        ("BODY", true, 10)
    } else if upper.starts_with("BODY[") {
        ("BODY", false, 5)
    } else if upper.starts_with("BINARY.PEEK[") {
        ("BINARY", true, 12)
    } else if upper.starts_with("BINARY[") {
        ("BINARY", false, 7)
    } else {
        return None;
    };
    let close = upper.rfind(']')?;
    if close < start {
        return None;
    }
    let section = upper[start..close].to_string();
    let tail = &upper[close + 1..];
    let partial = if tail.is_empty() {
        None
    } else {
        let inner = tail.strip_prefix('<')?.strip_suffix('>')?;
        match inner.split_once('.') {
            Some((origin, length)) => Some((origin.parse().ok()?, Some(length.parse().ok()?))),
            None => Some((inner.parse().ok()?, None)),
        }
    };
    Some(FetchItem::Body {
        label,
        section,
        peek,
        partial,
    })
}

fn parse_fetch_items(args: &[Value]) -> Result<Vec<FetchItem>, String> {
    let atoms: Vec<String> = match args {
        [Value::List(items)] => items.iter().filter_map(value_string).collect(),
        items => items.iter().filter_map(value_string).collect(),
    };
    if atoms.is_empty() {
        return Err("Missing fetch attributes".to_string());
    }
    let mut items = Vec::new();
    for atom in atoms {
        match atom.to_ascii_uppercase().as_str() {
            "ALL" | "FAST" | "FULL" => {
                items.extend([FetchItem::Flags, FetchItem::InternalDate, FetchItem::Size])
            }
            "UID" => items.push(FetchItem::Uid),
            "FLAGS" => items.push(FetchItem::Flags),
            "INTERNALDATE" => items.push(FetchItem::InternalDate),
            "RFC822.SIZE" => items.push(FetchItem::Size),
            "RFC822" => items.push(FetchItem::Rfc822),
            "RFC822.HEADER" => items.push(FetchItem::Rfc822Header),
            "RFC822.TEXT" => items.push(FetchItem::Rfc822Text),
            _ => items.push(
                parse_body_item(&atom)
                    .ok_or_else(|| format!("Unsupported fetch attribute {atom}"))?,
            ),
        }
    }
    Ok(items)
}

fn section_bytes(message: &FakeMessage, section: &str) -> Vec<u8> {
    let section = section.trim();
    if section.is_empty() {
        return message.raw.clone();
    }
    if section == "HEADER" {
        return message.header().to_vec();
    }
    if section == "TEXT" || section == "1" {
        return message.body().to_vec();
    }
    for (keyword, negate) in [("HEADER.FIELDS.NOT", true), ("HEADER.FIELDS", false)] {
        if let Some(rest) = section.strip_prefix(keyword) {
            let names: Vec<String> = rest
                .trim()
                .trim_start_matches('(')
                .trim_end_matches(')')
                .split_whitespace()
                .map(|name| name.trim_matches('"').to_ascii_uppercase())
                .collect();
            return header_fields(message.header(), &names, negate);
        }
    }
    Vec::new()
}

#[derive(Debug)]
enum Key {
    All,
    Flag(String, bool),
    Header(String, String),
    Body(String),
    Text(String),
    Uid(Vec<(u32, u32)>),
    Seq(Vec<(u32, u32)>),
    Not(Box<Key>),
    Or(Box<Key>, Box<Key>),
    And(Vec<Key>),
    Since(i64),
    Before(i64),
    On(i64),
    Larger(u64),
    Smaller(u64),
    Never,
}

struct SearchContext {
    max_uid: u32,
    max_seq: u32,
}

fn take_string(values: &[Value], index: &mut usize) -> Result<String, String> {
    let value = values.get(*index).ok_or("Missing search argument")?;
    *index += 1;
    value_string(value).ok_or_else(|| "Invalid search argument".to_string())
}

fn take_date(values: &[Value], index: &mut usize) -> Result<i64, String> {
    let text = take_string(values, index)?;
    parse_imap_date(&text).ok_or_else(|| format!("Invalid search date {text}"))
}

fn parse_key(values: &[Value], index: &mut usize, ctx: &SearchContext) -> Result<Key, String> {
    let value = values.get(*index).ok_or("Missing search key")?;
    *index += 1;
    let atom = match value {
        Value::List(items) => {
            let mut keys = Vec::new();
            let mut inner = 0;
            while inner < items.len() {
                keys.push(parse_key(items, &mut inner, ctx)?);
            }
            return Ok(Key::And(keys));
        }
        Value::Number(number) => number.to_string(),
        Value::Atom(atom) => atom.clone(),
        _ => return Err("Invalid search key".to_string()),
    };
    if is_seq_set(&atom) {
        return parse_seq_set(&atom, ctx.max_seq)
            .map(Key::Seq)
            .ok_or_else(|| "Invalid sequence set".to_string());
    }
    let flag = |name: &str, present: bool| Ok(Key::Flag(name.to_string(), present));
    match atom.to_ascii_uppercase().as_str() {
        "ALL" | "OLD" => Ok(Key::All),
        "NEW" | "RECENT" => Ok(Key::Never),
        "SEEN" => flag("\\Seen", true),
        "UNSEEN" => flag("\\Seen", false),
        "ANSWERED" => flag("\\Answered", true),
        "UNANSWERED" => flag("\\Answered", false),
        "DELETED" => flag("\\Deleted", true),
        "UNDELETED" => flag("\\Deleted", false),
        "DRAFT" => flag("\\Draft", true),
        "UNDRAFT" => flag("\\Draft", false),
        "FLAGGED" => flag("\\Flagged", true),
        "UNFLAGGED" => flag("\\Flagged", false),
        "KEYWORD" => Ok(Key::Flag(take_string(values, index)?, true)),
        "UNKEYWORD" => Ok(Key::Flag(take_string(values, index)?, false)),
        name @ ("FROM" | "TO" | "CC" | "BCC" | "SUBJECT") => {
            Ok(Key::Header(name.to_string(), take_string(values, index)?))
        }
        "HEADER" => {
            let field = take_string(values, index)?;
            Ok(Key::Header(field, take_string(values, index)?))
        }
        "BODY" => Ok(Key::Body(take_string(values, index)?)),
        "TEXT" => Ok(Key::Text(take_string(values, index)?)),
        "UID" => {
            let set = take_string(values, index)?;
            parse_seq_set(&set, ctx.max_uid)
                .map(Key::Uid)
                .ok_or_else(|| "Invalid UID set".to_string())
        }
        "SINCE" => Ok(Key::Since(take_date(values, index)?)),
        "BEFORE" => Ok(Key::Before(take_date(values, index)?)),
        "ON" => Ok(Key::On(take_date(values, index)?)),
        "LARGER" => take_string(values, index)?
            .parse()
            .map(Key::Larger)
            .map_err(|_| "Invalid LARGER size".to_string()),
        "SMALLER" => take_string(values, index)?
            .parse()
            .map(Key::Smaller)
            .map_err(|_| "Invalid SMALLER size".to_string()),
        "NOT" => Ok(Key::Not(Box::new(parse_key(values, index, ctx)?))),
        "OR" => {
            let left = parse_key(values, index, ctx)?;
            let right = parse_key(values, index, ctx)?;
            Ok(Key::Or(Box::new(left), Box::new(right)))
        }
        other => Err(format!("Unsupported search key {other}")),
    }
}

fn matches(key: &Key, message: &FakeMessage, seq: u32) -> bool {
    match key {
        Key::All => true,
        Key::Never => false,
        Key::Flag(flag, present) => message.has_flag(flag) == *present,
        Key::Header(field, needle) => {
            let values = header_values(message.header(), field);
            if needle.is_empty() {
                !values.is_empty()
            } else {
                values.iter().any(|value| contains_ci(value, needle))
            }
        }
        Key::Body(needle) => contains_ci(&String::from_utf8_lossy(message.body()), needle),
        Key::Text(needle) => contains_ci(&String::from_utf8_lossy(&message.raw), needle),
        Key::Uid(ranges) => in_ranges(ranges, message.uid),
        Key::Seq(ranges) => in_ranges(ranges, seq),
        Key::Not(inner) => !matches(inner, message, seq),
        Key::Or(left, right) => matches(left, message, seq) || matches(right, message, seq),
        Key::And(keys) => keys.iter().all(|k| matches(k, message, seq)),
        Key::Since(day) => parse_imap_date(&message.internal_date).is_some_and(|d| d >= *day),
        Key::Before(day) => parse_imap_date(&message.internal_date).is_some_and(|d| d < *day),
        Key::On(day) => parse_imap_date(&message.internal_date) == Some(*day),
        Key::Larger(size) => message.raw.len() as u64 > *size,
        Key::Smaller(size) => (message.raw.len() as u64) < *size,
    }
}

impl Session {
    fn new(
        transport: Transport,
        id: usize,
        state: Arc<Mutex<ImapShared>>,
        starttls: Option<TlsAcceptor>,
    ) -> Self {
        Session {
            transport,
            id,
            state,
            starttls,
            authenticated: false,
            selected: None,
            utf8: false,
            out: Vec::new(),
        }
    }

    fn untagged(&mut self, line: impl AsRef<[u8]>) {
        self.out.extend_from_slice(b"* ");
        self.out.extend_from_slice(line.as_ref());
        self.out.extend_from_slice(b"\r\n");
    }

    fn tagged(&mut self, tag: &str, status: &str, text: &str) {
        self.out
            .extend_from_slice(format!("{tag} {status} {text}\r\n").as_bytes());
    }

    fn flush(&mut self) -> bool {
        if self.out.is_empty() {
            return true;
        }
        let data = std::mem::take(&mut self.out);
        self.transport.write_all(&data).is_ok()
    }

    fn capability_line(&self) -> String {
        let state = lock(&self.state);
        let mut caps = if self.authenticated {
            state.config.capabilities.clone()
        } else {
            state
                .config
                .pre_auth_capabilities
                .clone()
                .unwrap_or_else(|| state.config.capabilities.clone())
        };
        if !self.authenticated
            && self.starttls.is_some()
            && !self.transport.is_tls()
            && !caps.iter().any(|c| c.eq_ignore_ascii_case("STARTTLS"))
        {
            caps.push("STARTTLS".to_string());
        }
        format!("CAPABILITY {}", caps.join(" "))
    }

    fn run(mut self) {
        let greeting_caps = {
            let mut state = lock(&self.state);
            state.connections += 1;
            state.config.greeting_capabilities
        };
        let greeting = if greeting_caps {
            format!(
                "OK [{}] Fake IMAP4rev1 server ready",
                self.capability_line()
            )
        } else {
            "OK Fake IMAP4rev1 server ready".to_string()
        };
        self.untagged(greeting);
        if !self.flush() {
            return;
        }
        while let Ok(parts) = self.read_command() {
            let flow = self.handle(&parts);
            if !self.flush() {
                break;
            }
            if let Flow::Close = flow {
                break;
            }
        }
        self.transport.shutdown();
    }

    fn read_line(&mut self) -> crate::Result<Vec<u8>> {
        self.transport.read_line(MAX_COMMAND_LINE)
    }

    fn read_command(&mut self) -> crate::Result<Vec<Part>> {
        let mut parts = Vec::new();
        loop {
            let line = self.read_line()?;
            match literal_size(&line) {
                Some(size) if size <= MAX_CLIENT_LITERAL => {
                    if !line.ends_with(b"+}") {
                        self.transport.write_all(b"+ Ready for literal data\r\n")?;
                    }
                    let data = self.transport.read_exact_vec(size)?;
                    parts.push(Part {
                        text: line,
                        literal: Some(data),
                    });
                }
                Some(_) => {
                    return Err(crate::ProtoError::Protocol("literal too large".into()));
                }
                None => {
                    parts.push(Part::text(line));
                    return Ok(parts);
                }
            }
        }
    }

    fn handle(&mut self, parts: &[Part]) -> Flow {
        let mut cursor = Cursor::new(parts, 0, 0);
        let tag = match cursor.read_value() {
            Ok(Value::Atom(tag)) => tag,
            Ok(Value::Number(number)) => number.to_string(),
            _ => {
                self.untagged("BAD Invalid tag");
                return Flow::Continue;
            }
        };
        let mut name = match cursor.read_value() {
            Ok(Value::Atom(name)) => name.to_ascii_uppercase(),
            _ => {
                self.tagged(&tag, "BAD", "Missing command");
                return Flow::Continue;
            }
        };
        if name == "UID" {
            match cursor.read_value() {
                Ok(Value::Atom(sub)) => name = format!("UID {}", sub.to_ascii_uppercase()),
                _ => {
                    self.tagged(&tag, "BAD", "Missing UID command");
                    return Flow::Continue;
                }
            }
        }
        let args = match cursor.values() {
            Ok(args) => args,
            Err(_) => {
                self.tagged(&tag, "BAD", "Invalid arguments");
                return Flow::Continue;
            }
        };

        let line = self.log_line(parts, &tag, &name, &args);
        let selected = self.selected.as_ref().map(|s| s.name.clone());
        let (failure, hook) = {
            let mut state = lock(&self.state);
            state.log.push(LoggedCommand {
                connection: self.id,
                name: name.clone(),
                line: line.clone(),
            });
            (state.failures.take(&name), state.hook.clone())
        };
        if let Some(failure) = failure {
            return match failure {
                Failure::No(text) | Failure::Code(_, text) => {
                    self.tagged(&tag, "NO", &text);
                    Flow::Continue
                }
                Failure::Bad(text) => {
                    self.tagged(&tag, "BAD", &text);
                    Flow::Continue
                }
                Failure::Disconnect => Flow::Close,
            };
        }
        if let Some(hook) = hook {
            let request = ImapRequest {
                connection: self.id,
                tag: tag.clone(),
                command: name.clone(),
                line,
                selected,
            };
            match hook(&request) {
                HookAction::Continue => {}
                HookAction::Respond {
                    untagged,
                    status,
                    text,
                } => {
                    for line in untagged {
                        self.out.extend_from_slice(&line);
                        self.out.extend_from_slice(b"\r\n");
                    }
                    self.tagged(&tag, status.as_str(), &text);
                    return Flow::Continue;
                }
                HookAction::Disconnect => return Flow::Close,
            }
        }
        self.dispatch(&tag, &name, &args)
    }

    fn log_line(&self, parts: &[Part], tag: &str, name: &str, args: &[Value]) -> String {
        if name == "LOGIN" {
            let user = args.first().and_then(value_string).unwrap_or_default();
            return format!("LOGIN {user} ****");
        }
        if name == "AUTHENTICATE" && args.len() > 1 {
            let mechanism = args.first().and_then(value_string).unwrap_or_default();
            return format!("AUTHENTICATE {mechanism} ****");
        }
        let joined: Vec<u8> = parts.iter().flat_map(|p| p.text.clone()).collect();
        let text = String::from_utf8_lossy(&joined).into_owned();
        text.strip_prefix(tag)
            .map(|rest| rest.trim_start().to_string())
            .unwrap_or(text)
    }

    fn dispatch(&mut self, tag: &str, name: &str, args: &[Value]) -> Flow {
        match name {
            "CAPABILITY" => {
                let line = self.capability_line();
                self.untagged(line);
                self.tagged(tag, "OK", "CAPABILITY completed");
                return Flow::Continue;
            }
            "NOOP" | "CHECK" => {
                self.tagged(tag, "OK", &format!("{name} completed"));
                return Flow::Continue;
            }
            "LOGOUT" => {
                self.untagged("BYE Fake IMAP server logging out");
                self.tagged(tag, "OK", "LOGOUT completed");
                lock(&self.state).logouts += 1;
                return Flow::Close;
            }
            "STARTTLS" => return self.cmd_starttls(tag),
            "LOGIN" => {
                self.cmd_login(tag, args);
                return Flow::Continue;
            }
            "AUTHENTICATE" => return self.cmd_authenticate(tag, args),
            _ => {}
        }
        if !self.authenticated {
            let known = matches!(
                name,
                "ENABLE"
                    | "SELECT"
                    | "EXAMINE"
                    | "CREATE"
                    | "DELETE"
                    | "LIST"
                    | "STATUS"
                    | "APPEND"
                    | "CLOSE"
                    | "UNSELECT"
                    | "SEARCH"
                    | "FETCH"
                    | "STORE"
                    | "COPY"
                    | "MOVE"
                    | "EXPUNGE"
            ) || name.starts_with("UID ");
            let text = if known {
                "Command requires authentication"
            } else {
                "Unknown command"
            };
            self.tagged(tag, "BAD", text);
            return Flow::Continue;
        }
        match name {
            "ENABLE" => self.cmd_enable(tag, args),
            "SELECT" => self.cmd_select(tag, args, false),
            "EXAMINE" => self.cmd_select(tag, args, true),
            "CREATE" => self.cmd_create(tag, args),
            "DELETE" => self.cmd_delete(tag, args),
            "LIST" => self.cmd_list(tag, args),
            "STATUS" => self.cmd_status(tag, args),
            "APPEND" => self.cmd_append(tag, args),
            "CLOSE" | "UNSELECT" => {
                if let Some(selected) = self.selected.take() {
                    if name == "CLOSE" && !selected.readonly {
                        let mut state = lock(&self.state);
                        if let Some(index) = state.find(&selected.name) {
                            state.folders[index]
                                .messages
                                .retain(|m| !m.has_flag("\\Deleted"));
                        }
                    }
                    self.tagged(tag, "OK", &format!("{name} completed"));
                } else {
                    self.tagged(tag, "BAD", "No mailbox selected");
                }
            }
            "SEARCH" | "UID SEARCH" | "FETCH" | "UID FETCH" | "STORE" | "UID STORE" | "COPY"
            | "UID COPY" | "MOVE" | "UID MOVE" | "EXPUNGE" | "UID EXPUNGE" => {
                self.selected_command(tag, name, args)
            }
            _ => self.tagged(tag, "BAD", "Unknown command"),
        }
        Flow::Continue
    }

    fn cmd_starttls(&mut self, tag: &str) -> Flow {
        let Some(acceptor) = self.starttls.clone() else {
            self.tagged(tag, "BAD", "Unknown command");
            return Flow::Continue;
        };
        if self.transport.is_tls() || self.authenticated {
            self.tagged(tag, "BAD", "STARTTLS not allowed now");
            return Flow::Continue;
        }
        self.tagged(tag, "OK", "Begin TLS negotiation now");
        if !self.flush() || self.transport.accept_tls(&acceptor).is_err() {
            return Flow::Close;
        }
        Flow::Continue
    }

    fn login_ok(&mut self, tag: &str) {
        self.authenticated = true;
        let code = lock(&self.state).config.login_capability_code;
        if code {
            let line = self.capability_line();
            self.tagged(tag, "OK", &format!("[{line}] Logged in"));
        } else {
            self.tagged(tag, "OK", "Logged in");
        }
    }

    fn check_password(&self, user: &str, password: &str) -> bool {
        lock(&self.state)
            .config
            .users
            .iter()
            .any(|(u, p)| u == user && p == password)
    }

    fn cmd_login(&mut self, tag: &str, args: &[Value]) {
        if self.authenticated {
            self.tagged(tag, "BAD", "Already authenticated");
            return;
        }
        let (Some(user), Some(password)) = (
            args.first().and_then(value_string),
            args.get(1).and_then(value_string),
        ) else {
            self.tagged(tag, "BAD", "LOGIN expects user and password");
            return;
        };
        if self.check_password(&user, &password) {
            self.login_ok(tag);
        } else {
            self.tagged(
                tag,
                "NO",
                "[AUTHENTICATIONFAILED] Invalid credentials (Failure)",
            );
        }
    }

    fn cmd_authenticate(&mut self, tag: &str, args: &[Value]) -> Flow {
        if self.authenticated {
            self.tagged(tag, "BAD", "Already authenticated");
            return Flow::Continue;
        }
        let mechanism = args
            .first()
            .and_then(value_string)
            .unwrap_or_default()
            .to_ascii_uppercase();
        if mechanism != "PLAIN" && mechanism != "XOAUTH2" {
            self.tagged(tag, "NO", "Unsupported authentication mechanism");
            return Flow::Continue;
        }
        let response = match args.get(1).and_then(value_string) {
            Some(initial) => initial,
            None => {
                self.out.extend_from_slice(b"+ \r\n");
                if !self.flush() {
                    return Flow::Close;
                }
                match self.read_line() {
                    Ok(line) => String::from_utf8_lossy(&line).trim().to_string(),
                    Err(_) => return Flow::Close,
                }
            }
        };
        if response == "*" {
            self.tagged(tag, "BAD", "Authentication cancelled");
            return Flow::Continue;
        }
        let decoded = BASE64.decode(response.as_bytes()).unwrap_or_default();
        let decoded = String::from_utf8_lossy(&decoded).into_owned();
        let ok = if mechanism == "PLAIN" {
            let fields: Vec<&str> = decoded.split('\0').collect();
            fields.len() == 3 && self.check_password(fields[1], fields[2])
        } else {
            let mut user = None;
            let mut token = None;
            for field in decoded.split('\x01') {
                if let Some(value) = field.strip_prefix("user=") {
                    user = Some(value.to_string());
                } else if let Some(value) = field.strip_prefix("auth=Bearer ") {
                    token = Some(value.to_string());
                }
            }
            match (user, token) {
                (Some(user), Some(token)) => lock(&self.state)
                    .config
                    .oauth
                    .iter()
                    .any(|(u, t)| *u == user && *t == token),
                _ => false,
            }
        };
        if ok {
            self.login_ok(tag);
            return Flow::Continue;
        }
        if mechanism == "XOAUTH2" {
            let error = BASE64.encode(
                br#"{"status":"401","schemes":"bearer","scope":"https://mail.google.com/"}"#,
            );
            self.out
                .extend_from_slice(format!("+ {error}\r\n").as_bytes());
            if !self.flush() || self.read_line().is_err() {
                return Flow::Close;
            }
        }
        self.tagged(
            tag,
            "NO",
            "[AUTHENTICATIONFAILED] Invalid credentials (Failure)",
        );
        Flow::Continue
    }

    fn cmd_enable(&mut self, tag: &str, args: &[Value]) {
        let config = lock(&self.state).config.clone();
        if !config.has("ENABLE") {
            self.tagged(tag, "BAD", "Unknown command");
            return;
        }
        let mut enabled = Vec::new();
        for capability in args.iter().filter_map(value_string) {
            // RFC 6855: a UTF8=ONLY server also accepts ENABLE UTF8=ACCEPT.
            let utf8_accept = capability.eq_ignore_ascii_case("UTF8=ACCEPT");
            if config.has(&capability) || (utf8_accept && config.has("UTF8=ONLY")) {
                if utf8_accept {
                    self.utf8 = true;
                }
                enabled.push(capability.to_ascii_uppercase());
            }
        }
        self.untagged(format!("ENABLED {}", enabled.join(" ")).trim_end());
        self.tagged(tag, "OK", "ENABLE completed");
    }

    fn cmd_select(&mut self, tag: &str, args: &[Value], readonly: bool) {
        self.selected = None;
        let Some(name) = args.first().and_then(value_string) else {
            self.tagged(tag, "BAD", "Missing mailbox");
            return;
        };
        let state = Arc::clone(&self.state);
        let state = lock(&state);
        let Some(index) = state.find(&name) else {
            self.tagged(tag, "NO", "[NONEXISTENT] Mailbox does not exist");
            return;
        };
        let folder = &state.folders[index];
        if folder.has_attribute("\\Noselect") || folder.has_attribute("\\NonExistent") {
            self.tagged(tag, "NO", "Mailbox is not selectable");
            return;
        }
        self.untagged(format!("FLAGS ({SYSTEM_FLAGS})"));
        if !readonly {
            self.untagged(format!(
                "OK [PERMANENTFLAGS ({SYSTEM_FLAGS} \\*)] Flags permitted"
            ));
        }
        self.untagged(format!("{} EXISTS", folder.messages.len()));
        self.untagged("0 RECENT");
        if let Some(validity) = folder.uid_validity {
            self.untagged(format!("OK [UIDVALIDITY {validity}] UIDs valid"));
        }
        self.untagged(format!(
            "OK [UIDNEXT {}] Predicted next UID",
            folder.uid_next
        ));
        if readonly {
            self.tagged(tag, "OK", "[READ-ONLY] EXAMINE completed");
        } else {
            self.tagged(tag, "OK", "[READ-WRITE] SELECT completed");
        }
        self.selected = Some(Selected {
            name: folder.name.clone(),
            readonly,
        });
    }

    fn cmd_create(&mut self, tag: &str, args: &[Value]) {
        let Some(name) = args.first().and_then(value_string) else {
            self.tagged(tag, "BAD", "Missing mailbox");
            return;
        };
        let mut state = lock(&self.state);
        let delimiter = state.config.delimiter.clone().unwrap_or_default();
        let name = if delimiter.is_empty() {
            name
        } else {
            name.trim_end_matches(delimiter.as_str()).to_string()
        };
        if name.is_empty() || state.find(&name).is_some() {
            drop(state);
            self.tagged(tag, "NO", "[ALREADYEXISTS] Mailbox already exists");
            return;
        }
        state.folder_mut(&name);
        drop(state);
        self.tagged(tag, "OK", "CREATE completed");
    }

    fn cmd_delete(&mut self, tag: &str, args: &[Value]) {
        let Some(name) = args.first().and_then(value_string) else {
            self.tagged(tag, "BAD", "Missing mailbox");
            return;
        };
        let mut state = lock(&self.state);
        match state.find(&name) {
            Some(index) if !name.eq_ignore_ascii_case("INBOX") => {
                state.folders.remove(index);
                drop(state);
                self.tagged(tag, "OK", "DELETE completed");
            }
            _ => {
                drop(state);
                self.tagged(tag, "NO", "[NONEXISTENT] Mailbox does not exist");
            }
        }
    }

    fn cmd_list(&mut self, tag: &str, args: &[Value]) {
        let mut index = 0;
        if let Some(Value::List(_)) = args.first() {
            index += 1; // LIST-EXTENDED selection options are ignored.
        }
        let (Some(reference), Some(pattern)) = (
            args.get(index).and_then(value_string),
            args.get(index + 1).and_then(value_string),
        ) else {
            self.tagged(tag, "BAD", "LIST expects reference and pattern");
            return;
        };
        let mut return_special_use = false;
        if let Some(Value::Atom(word)) = args.get(index + 2) {
            if word.eq_ignore_ascii_case("RETURN") {
                if let Some(Value::List(options)) = args.get(index + 3) {
                    return_special_use = options
                        .iter()
                        .filter_map(value_string)
                        .any(|o| o.eq_ignore_ascii_case("SPECIAL-USE"));
                }
            }
        }
        let state = Arc::clone(&self.state);
        let state = lock(&state);
        let config = &state.config;
        if return_special_use && !(config.has("SPECIAL-USE") || config.rev2()) {
            self.tagged(tag, "BAD", "Unknown LIST return option");
            return;
        }
        let delimiter_text = match &config.delimiter {
            Some(delimiter) => quote(delimiter),
            None => "NIL".to_string(),
        };
        if pattern.is_empty() {
            self.untagged(format!("LIST (\\Noselect) {delimiter_text} \"\""));
            self.tagged(tag, "OK", "LIST completed");
            return;
        }
        let full_pattern = format!("{reference}{pattern}");
        let delimiter_char = config.delimiter.as_ref().and_then(|d| d.chars().next());
        let include_special = return_special_use || config.special_use_in_plain_list;
        for folder in &state.folders {
            if !list_matches(&full_pattern, &folder.name, delimiter_char) {
                continue;
            }
            let attributes: Vec<&str> = folder
                .attributes
                .iter()
                .map(String::as_str)
                .filter(|a| {
                    include_special || !SPECIAL_USE.iter().any(|s| s.eq_ignore_ascii_case(a))
                })
                .collect();
            let mut line =
                format!("LIST ({}) {delimiter_text} ", attributes.join(" ")).into_bytes();
            line.extend(render_name(&folder.name, config.literal_names));
            self.untagged(line);
        }
        self.tagged(tag, "OK", "LIST completed");
    }

    fn cmd_status(&mut self, tag: &str, args: &[Value]) {
        let Some(name) = args.first().and_then(value_string) else {
            self.tagged(tag, "BAD", "Missing mailbox");
            return;
        };
        let Some(Value::List(items)) = args.get(1) else {
            self.tagged(tag, "BAD", "Missing status items");
            return;
        };
        let state = Arc::clone(&self.state);
        let state = lock(&state);
        let Some(index) = state.find(&name) else {
            self.tagged(tag, "NO", "[NONEXISTENT] Mailbox does not exist");
            return;
        };
        let folder = &state.folders[index];
        let mut pairs = Vec::new();
        for item in items.iter().filter_map(value_string) {
            let value = match item.to_ascii_uppercase().as_str() {
                "MESSAGES" => folder.messages.len() as u64,
                "UIDNEXT" => u64::from(folder.uid_next),
                "UIDVALIDITY" => u64::from(folder.uid_validity.unwrap_or(0)),
                "UNSEEN" => folder
                    .messages
                    .iter()
                    .filter(|m| !m.has_flag("\\Seen"))
                    .count() as u64,
                "RECENT" => 0,
                _ => continue,
            };
            pairs.push(format!("{} {value}", item.to_ascii_uppercase()));
        }
        let mut line = b"STATUS ".to_vec();
        line.extend(render_name(&folder.name, false));
        line.extend(format!(" ({})", pairs.join(" ")).into_bytes());
        self.untagged(line);
        self.tagged(tag, "OK", "STATUS completed");
    }

    fn cmd_append(&mut self, tag: &str, args: &[Value]) {
        let Some(name) = args.first().and_then(value_string) else {
            self.tagged(tag, "BAD", "Missing mailbox");
            return;
        };
        let mut index = 1;
        let mut flags = Vec::new();
        if let Some(Value::List(items)) = args.get(index) {
            flags = items.iter().filter_map(value_string).collect();
            index += 1;
        }
        let mut date = None;
        if let Some(Value::Quoted(bytes)) = args.get(index) {
            date = Some(String::from_utf8_lossy(bytes).into_owned());
            index += 1;
        }
        let raw = match (args.get(index), args.get(index + 1)) {
            (Some(Value::Literal(bytes)), _) => bytes.clone(),
            (Some(Value::Atom(word)), Some(Value::List(items)))
                if word.eq_ignore_ascii_case("UTF8") =>
            {
                if !self.utf8 {
                    self.tagged(tag, "BAD", "UTF8 APPEND requires ENABLE UTF8=ACCEPT");
                    return;
                }
                match items.as_slice() {
                    [Value::Literal(bytes)] => bytes.clone(),
                    _ => {
                        self.tagged(tag, "BAD", "Malformed UTF8 APPEND");
                        return;
                    }
                }
            }
            _ => {
                self.tagged(tag, "BAD", "Missing message literal");
                return;
            }
        };
        let mut state = lock(&self.state);
        let uidplus = state.config.has("UIDPLUS") || state.config.rev2();
        let Some(folder_index) = state.find(&name) else {
            drop(state);
            self.tagged(tag, "NO", "[TRYCREATE] Mailbox does not exist");
            return;
        };
        let mut message = FakeMessage::new(raw).with_flags(&[]);
        message.flags = flags;
        if let Some(date) = date {
            message.internal_date = date;
        }
        let folder = &mut state.folders[folder_index];
        let uid = folder.insert(message);
        let validity = folder.uid_validity;
        let count = folder.messages.len();
        let folder_name = folder.name.clone();
        drop(state);
        if self
            .selected
            .as_ref()
            .is_some_and(|s| s.name == folder_name)
        {
            self.untagged(format!("{count} EXISTS"));
        }
        match validity {
            Some(validity) if uidplus => self.tagged(
                tag,
                "OK",
                &format!("[APPENDUID {validity} {uid}] APPEND completed"),
            ),
            _ => self.tagged(tag, "OK", "APPEND completed"),
        }
    }

    fn selected_command(&mut self, tag: &str, name: &str, args: &[Value]) {
        let Some((folder_name, readonly)) =
            self.selected.as_ref().map(|s| (s.name.clone(), s.readonly))
        else {
            self.tagged(tag, "BAD", "No mailbox selected");
            return;
        };
        let uid_mode = name.starts_with("UID ");
        let verb = name.trim_start_matches("UID ");
        let config = lock(&self.state).config.clone();
        match verb {
            "MOVE" if !(config.has("MOVE") || config.rev2()) => {
                self.tagged(tag, "BAD", "Unknown command");
                return;
            }
            "EXPUNGE" if uid_mode && !(config.has("UIDPLUS") || config.rev2()) => {
                self.tagged(tag, "BAD", "Unknown command");
                return;
            }
            _ => {}
        }
        let state_arc = Arc::clone(&self.state);
        let mut state = lock(&state_arc);
        let Some(folder_index) = state.find(&folder_name) else {
            self.tagged(tag, "NO", "Selected mailbox no longer exists");
            return;
        };
        let result = match verb {
            "SEARCH" => self.do_search(&state.folders[folder_index], args, uid_mode),
            "FETCH" => self.do_fetch(&mut state.folders[folder_index], args, uid_mode, readonly),
            "STORE" => self.do_store(&mut state.folders[folder_index], args, uid_mode, readonly),
            "COPY" | "MOVE" => self.do_copy(
                &mut state,
                folder_index,
                args,
                uid_mode,
                readonly,
                verb == "MOVE",
            ),
            "EXPUNGE" => {
                self.do_expunge(&mut state.folders[folder_index], args, uid_mode, readonly)
            }
            _ => Err(("BAD", "Unknown command".to_string())),
        };
        drop(state);
        match result {
            Ok(text) => self.tagged(tag, "OK", &text),
            Err((status, text)) => self.tagged(tag, status, &text),
        }
    }

    fn do_search(
        &mut self,
        folder: &FakeFolder,
        args: &[Value],
        uid_mode: bool,
    ) -> Result<String, (&'static str, String)> {
        let mut index = 0;
        if let Some(Value::Atom(word)) = args.first() {
            if word.eq_ignore_ascii_case("CHARSET") {
                let charset = args.get(1).and_then(value_string).unwrap_or_default();
                if !charset.eq_ignore_ascii_case("UTF-8")
                    && !charset.eq_ignore_ascii_case("US-ASCII")
                {
                    return Err((
                        "NO",
                        "[BADCHARSET (UTF-8 US-ASCII)] Unsupported charset".into(),
                    ));
                }
                index = 2;
            }
        }
        let context = SearchContext {
            max_uid: folder.max_uid(),
            max_seq: folder.messages.len() as u32,
        };
        let mut keys = Vec::new();
        while index < args.len() {
            keys.push(parse_key(args, &mut index, &context).map_err(|e| ("BAD", e))?);
        }
        if keys.is_empty() {
            return Err(("BAD", "Missing search criteria".into()));
        }
        let key = Key::And(keys);
        let hits: Vec<String> = folder
            .messages
            .iter()
            .enumerate()
            .filter(|(i, m)| matches(&key, m, *i as u32 + 1))
            .map(|(i, m)| if uid_mode { m.uid } else { i as u32 + 1 }.to_string())
            .collect();
        if hits.is_empty() {
            self.untagged("SEARCH");
        } else {
            self.untagged(format!("SEARCH {}", hits.join(" ")));
        }
        Ok("SEARCH completed".into())
    }

    fn do_fetch(
        &mut self,
        folder: &mut FakeFolder,
        args: &[Value],
        uid_mode: bool,
        readonly: bool,
    ) -> Result<String, (&'static str, String)> {
        let set = args
            .first()
            .and_then(value_string)
            .ok_or(("BAD", "Missing sequence set".to_string()))?;
        let mut items = parse_fetch_items(&args[1..]).map_err(|e| ("BAD", e))?;
        if uid_mode && !items.contains(&FetchItem::Uid) {
            items.insert(0, FetchItem::Uid);
        }
        let max = if uid_mode {
            folder.max_uid()
        } else {
            folder.messages.len() as u32
        };
        let ranges = parse_seq_set(&set, max).ok_or(("BAD", "Invalid sequence set".to_string()))?;
        for (index, message) in folder.messages.iter_mut().enumerate() {
            let seq = index as u32 + 1;
            if !in_ranges(&ranges, if uid_mode { message.uid } else { seq }) {
                continue;
            }
            let mut set_seen = false;
            if !readonly && items.iter().any(FetchItem::sets_seen) && !message.has_flag("\\Seen") {
                message.flags.push("\\Seen".to_string());
                set_seen = true;
            }
            let mut line = format!("{seq} FETCH (").into_bytes();
            let mut flags_sent = false;
            for (position, item) in items.iter().enumerate() {
                if position > 0 {
                    line.push(b' ');
                }
                match item {
                    FetchItem::Uid => line.extend(format!("UID {}", message.uid).into_bytes()),
                    FetchItem::Flags => {
                        flags_sent = true;
                        line.extend(format!("FLAGS {}", flag_list(&message.flags)).into_bytes());
                    }
                    FetchItem::InternalDate => line.extend(
                        format!("INTERNALDATE {}", quote(&message.internal_date)).into_bytes(),
                    ),
                    FetchItem::Size => {
                        line.extend(format!("RFC822.SIZE {}", message.raw.len()).into_bytes())
                    }
                    FetchItem::Rfc822 => {
                        line.extend_from_slice(b"RFC822 ");
                        line.extend(literal(&message.raw));
                    }
                    FetchItem::Rfc822Header => {
                        line.extend_from_slice(b"RFC822.HEADER ");
                        line.extend(literal(message.header()));
                    }
                    FetchItem::Rfc822Text => {
                        line.extend_from_slice(b"RFC822.TEXT ");
                        line.extend(literal(message.body()));
                    }
                    FetchItem::Body {
                        label,
                        section,
                        partial,
                        ..
                    } => {
                        let mut data = section_bytes(message, section);
                        let mut key = format!("{label}[{section}]");
                        if let Some((origin, length)) = partial {
                            let start = (*origin).min(data.len());
                            let end = length.map_or(data.len(), |l| (start + l).min(data.len()));
                            data = data[start..end].to_vec();
                            key.push_str(&format!("<{origin}>"));
                        }
                        line.extend(format!("{key} ").into_bytes());
                        line.extend(literal(&data));
                    }
                }
            }
            if set_seen && !flags_sent {
                line.extend(format!(" FLAGS {}", flag_list(&message.flags)).into_bytes());
            }
            line.push(b')');
            self.untagged(line);
        }
        Ok("FETCH completed".into())
    }

    fn do_store(
        &mut self,
        folder: &mut FakeFolder,
        args: &[Value],
        uid_mode: bool,
        readonly: bool,
    ) -> Result<String, (&'static str, String)> {
        if readonly {
            return Err(("NO", "[READ-ONLY] Mailbox is read-only".into()));
        }
        let set = args
            .first()
            .and_then(value_string)
            .ok_or(("BAD", "Missing sequence set".to_string()))?;
        let operation = args
            .get(1)
            .and_then(value_string)
            .ok_or(("BAD", "Missing STORE operation".to_string()))?
            .to_ascii_uppercase();
        let silent = operation.ends_with(".SILENT");
        let mode = operation.trim_end_matches(".SILENT");
        if !matches!(mode, "FLAGS" | "+FLAGS" | "-FLAGS") {
            return Err(("BAD", format!("Unsupported STORE operation {operation}")));
        }
        let flags: Vec<String> = match &args[2..] {
            [Value::List(items)] => items.iter().filter_map(value_string).collect(),
            items => items.iter().filter_map(value_string).collect(),
        };
        let max = if uid_mode {
            folder.max_uid()
        } else {
            folder.messages.len() as u32
        };
        let ranges = parse_seq_set(&set, max).ok_or(("BAD", "Invalid sequence set".to_string()))?;
        for (index, message) in folder.messages.iter_mut().enumerate() {
            let seq = index as u32 + 1;
            if !in_ranges(&ranges, if uid_mode { message.uid } else { seq }) {
                continue;
            }
            match mode {
                "FLAGS" => message.flags = flags.clone(),
                "+FLAGS" => {
                    for flag in &flags {
                        if !message.has_flag(flag) {
                            message.flags.push(flag.clone());
                        }
                    }
                }
                _ => message
                    .flags
                    .retain(|f| !flags.iter().any(|r| r.eq_ignore_ascii_case(f))),
            }
            if !silent {
                let uid = if uid_mode {
                    format!("UID {} ", message.uid)
                } else {
                    String::new()
                };
                self.untagged(format!(
                    "{seq} FETCH ({uid}FLAGS {})",
                    flag_list(&message.flags)
                ));
            }
        }
        Ok("STORE completed".into())
    }

    fn do_copy(
        &mut self,
        state: &mut ImapShared,
        source_index: usize,
        args: &[Value],
        uid_mode: bool,
        readonly: bool,
        is_move: bool,
    ) -> Result<String, (&'static str, String)> {
        let set = args
            .first()
            .and_then(value_string)
            .ok_or(("BAD", "Missing sequence set".to_string()))?;
        let target = args
            .get(1)
            .and_then(value_string)
            .ok_or(("BAD", "Missing target mailbox".to_string()))?;
        if is_move && readonly {
            return Err(("NO", "[READ-ONLY] Mailbox is read-only".into()));
        }
        let target_index = state
            .find(&target)
            .ok_or(("NO", "[TRYCREATE] Mailbox does not exist".to_string()))?;
        let uidplus = state.config.has("UIDPLUS") || state.config.rev2();
        let source = &state.folders[source_index];
        let max = if uid_mode {
            source.max_uid()
        } else {
            source.messages.len() as u32
        };
        let ranges = parse_seq_set(&set, max).ok_or(("BAD", "Invalid sequence set".to_string()))?;
        let selected: Vec<(u32, FakeMessage)> = source
            .messages
            .iter()
            .enumerate()
            .filter(|(i, m)| in_ranges(&ranges, if uid_mode { m.uid } else { *i as u32 + 1 }))
            .map(|(i, m)| (i as u32 + 1, m.clone()))
            .collect();
        let verb = if is_move { "MOVE" } else { "COPY" };
        if selected.is_empty() {
            return Ok(format!("{verb} completed (no messages)"));
        }
        let mut source_uids = Vec::new();
        let mut target_uids = Vec::new();
        for (_, message) in &selected {
            source_uids.push(message.uid);
            let mut copy = message.clone();
            copy.uid = 0;
            target_uids.push(state.folders[target_index].insert(copy));
        }
        let code = match state.folders[target_index].uid_validity {
            Some(validity) if uidplus => Some(format!(
                "[COPYUID {validity} {} {}]",
                source_uids
                    .iter()
                    .map(u32::to_string)
                    .collect::<Vec<_>>()
                    .join(","),
                target_uids
                    .iter()
                    .map(u32::to_string)
                    .collect::<Vec<_>>()
                    .join(",")
            )),
            _ => None,
        };
        if !is_move {
            return Ok(match code {
                Some(code) => format!("{code} COPY completed"),
                None => "COPY completed".to_string(),
            });
        }
        if let Some(code) = &code {
            self.untagged(format!("OK {code} Moved"));
        }
        let source = &mut state.folders[source_index];
        for (seq, message) in selected.iter().rev() {
            if let Some(position) = source.messages.iter().position(|m| m.uid == message.uid) {
                source.messages.remove(position);
                self.untagged(format!("{seq} EXPUNGE"));
            }
        }
        Ok("MOVE completed".into())
    }

    fn do_expunge(
        &mut self,
        folder: &mut FakeFolder,
        args: &[Value],
        uid_mode: bool,
        readonly: bool,
    ) -> Result<String, (&'static str, String)> {
        if readonly {
            return Err(("NO", "[READ-ONLY] Mailbox is read-only".into()));
        }
        let ranges = if uid_mode {
            let set = args
                .first()
                .and_then(value_string)
                .ok_or(("BAD", "Missing UID set".to_string()))?;
            Some(
                parse_seq_set(&set, folder.max_uid())
                    .ok_or(("BAD", "Invalid UID set".to_string()))?,
            )
        } else {
            None
        };
        for index in (0..folder.messages.len()).rev() {
            let message = &folder.messages[index];
            let in_set = ranges.as_ref().is_none_or(|r| in_ranges(r, message.uid));
            if message.has_flag("\\Deleted") && in_set {
                folder.messages.remove(index);
                self.untagged(format!("{} EXPUNGE", index + 1));
            }
        }
        Ok("EXPUNGE completed".into())
    }
}
