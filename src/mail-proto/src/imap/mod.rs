//! Blocking IMAP4rev1 client modelled on Python's `imaplib.IMAP4`.
//!
//! Covers every `imaplib` call made by the original backend:
//!
//! * `imap_client.py`: `IMAP4_SSL`/`IMAP4` + `starttls()`, `login`,
//!   `capability`, `enable("UTF8=ACCEPT")`, `list()` and
//!   `list('""', '"*" RETURN (SPECIAL-USE)')`, `create`, `select(readonly=)`,
//!   `response("UIDVALIDITY"/"UIDNEXT")`, `uid("search"|"fetch"|"store"|
//!   "move"|"copy"|"expunge", ...)`, `append(mailbox, "(\\Seen)", None, raw)`,
//!   `logout`;
//! * `trash.py`: `list`, `capability`, `response("UIDVALIDITY")`,
//!   `uid("search"/"fetch"/"store"/"expunge")`;
//! * `doctor/services/mailbox_download.py`: `starttls`,
//!   `authenticate("XOAUTH2", ...)`, `login`, `select("INBOX", readonly=True)`,
//!   `uid("search", None, "SINCE", ..., "BEFORE", ...)`, `uid("fetch", ...)`.
//!
//! Differences from `imaplib`, all deliberate:
//!
//! * Typed helpers return `Err(ProtoError::No | ProtoError::Bad)` for a
//!   non-OK completion instead of a `("NO", data)` tuple; the generic
//!   [`ImapConnection::command`] returns the status for all three.
//! * Mailbox arguments are passed unquoted; the helpers quote them exactly
//!   like `imap_client._mailbox` (see [`quote`]).
//! * Capabilities are refreshed after STARTTLS and after authentication
//!   (from a `[CAPABILITY]` code when present, otherwise with an explicit
//!   CAPABILITY command).

pub mod parser;
pub mod response;
pub mod utf7;

use std::time::Duration;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use native_tls::TlsConnector;

pub use parser::{compress_uid_set, expand_uid_set, FetchResponse, ListEntry, Part, Value};
pub use response::{
    AppendUid, CommandResponse, CopyUid, MailboxInfo, ResponseCode, Status, UntaggedResponse,
};

use crate::error::{ProtoError, Result};
use crate::transport::{default_connector, Security, Transport};
use response::{literal_size, parse_response, Response, Tagged};

/// Default cap on a single literal (message bodies are literals).
pub const DEFAULT_MAX_LITERAL: usize = 256 * 1024 * 1024;
/// Maximum response line length (without literals).
const MAX_LINE: usize = 16 * 1024 * 1024;

/// Quote a string for an IMAP command, exactly like
/// `imap_client._mailbox`: wrap in `"` and escape `\` and `"`.
pub fn quote(value: &str) -> String {
    format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""))
}

/// Reverse of [`quote`] (`imap_client._unquote`): strip surrounding quotes
/// and unescape `\"` and `\\`; unquoted input is returned unchanged.
pub fn unquote(value: &str) -> String {
    if value.len() >= 2 && value.starts_with('"') && value.ends_with('"') {
        let inner = &value[1..value.len() - 1];
        let mut out = String::with_capacity(inner.len());
        let mut chars = inner.chars();
        while let Some(ch) = chars.next() {
            if ch == '\\' {
                match chars.next() {
                    Some(next @ ('"' | '\\')) => out.push(next),
                    Some(next) => {
                        out.push('\\');
                        out.push(next);
                    }
                    None => out.push('\\'),
                }
            } else {
                out.push(ch);
            }
        }
        out
    } else {
        value.to_string()
    }
}

/// Normalize line endings to CRLF like `imaplib.MapCRLF` does for APPEND.
pub fn normalize_crlf(message: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(message.len() + message.len() / 32);
    let mut index = 0;
    while index < message.len() {
        match message[index] {
            b'\r' => {
                out.extend_from_slice(b"\r\n");
                if message.get(index + 1) == Some(&b'\n') {
                    index += 1;
                }
            }
            b'\n' => out.extend_from_slice(b"\r\n"),
            byte => out.push(byte),
        }
        index += 1;
    }
    out
}

/// One command argument.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Arg {
    /// Sent verbatim (atoms, sequence sets, parenthesized item lists such as
    /// `(UID FLAGS BODY.PEEK[])`). Like an `imaplib` str argument: must be
    /// ASCII unless UTF-8 mode is active, and may not contain CR/LF/NUL.
    Atom(String),
    /// Sent as a quoted string (see [`quote`]); same encoding rules.
    Quoted(String),
    /// Quoted when it is plain ASCII, otherwise sent as a synchronizing
    /// literal (used for credentials and free-text search strings).
    AString(String),
    /// A synchronizing literal `{n}`.
    Literal(Vec<u8>),
}

impl Arg {
    pub fn atom(value: impl Into<String>) -> Self {
        Arg::Atom(value.into())
    }

    pub fn quoted(value: impl Into<String>) -> Self {
        Arg::Quoted(value.into())
    }

    pub fn astring(value: impl Into<String>) -> Self {
        Arg::AString(value.into())
    }

    pub fn literal(value: impl Into<Vec<u8>>) -> Self {
        Arg::Literal(value.into())
    }
}

impl From<&str> for Arg {
    fn from(value: &str) -> Self {
        Arg::Atom(value.to_string())
    }
}

impl From<String> for Arg {
    fn from(value: String) -> Self {
        Arg::Atom(value)
    }
}

/// A piece of an outgoing command.
#[derive(Debug, Clone)]
enum Segment {
    Text(Vec<u8>),
    Literal { data: Vec<u8>, binary: bool },
}

fn has_line_break(value: &str) -> bool {
    value.bytes().any(|b| b == b'\r' || b == b'\n' || b == 0)
}

/// A connected IMAP session.
pub struct ImapConnection {
    transport: Transport,
    connector: TlsConnector,
    host: String,
    next_tag: u32,
    capabilities: Vec<String>,
    capabilities_seen: bool,
    greeting: String,
    preauth: bool,
    utf8_enabled: bool,
    bye: Option<String>,
    closed: bool,
    max_literal: usize,
}

impl std::fmt::Debug for ImapConnection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ImapConnection")
            .field("host", &self.host)
            .field("tls", &self.transport.is_tls())
            .field("capabilities", &self.capabilities)
            .field("utf8_enabled", &self.utf8_enabled)
            .field("closed", &self.closed)
            .finish()
    }
}

impl ImapConnection {
    /// Connect, read the greeting, learn capabilities and (for
    /// [`Security::StartTls`]) upgrade with STARTTLS. Uses the system trust
    /// store. `timeout` applies to connect and every socket operation
    /// (zero disables it).
    pub fn connect(host: &str, port: u16, security: Security, timeout: Duration) -> Result<Self> {
        Self::connect_with_tls(host, port, security, timeout, default_connector()?)
    }

    /// Like [`ImapConnection::connect`] with a caller-supplied TLS
    /// connector (tests use one that trusts the testkit certificate).
    pub fn connect_with_tls(
        host: &str,
        port: u16,
        security: Security,
        timeout: Duration,
        connector: TlsConnector,
    ) -> Result<Self> {
        let mut transport = Transport::connect(host, port, timeout)?;
        if security == Security::Ssl {
            transport.start_tls(&connector, host)?;
        }
        let mut connection = ImapConnection {
            transport,
            connector,
            host: host.to_string(),
            next_tag: 0,
            capabilities: Vec::new(),
            capabilities_seen: false,
            greeting: String::new(),
            preauth: false,
            utf8_enabled: false,
            bye: None,
            closed: false,
            max_literal: DEFAULT_MAX_LITERAL,
        };
        connection.read_greeting()?;
        if security == Security::StartTls {
            connection.starttls()?;
        }
        Ok(connection)
    }

    fn read_greeting(&mut self) -> Result<()> {
        let greeting = match self.read_response()? {
            Response::Untagged(response) => response,
            _ => {
                return Err(ProtoError::Protocol(
                    "the server did not send an IMAP greeting".to_string(),
                ))
            }
        };
        match greeting.kind.as_str() {
            "OK" => {}
            "PREAUTH" => self.preauth = true,
            "BYE" => {
                self.closed = true;
                return Err(ProtoError::Protocol(format!(
                    "the server refused the connection: {}",
                    greeting.text()
                )));
            }
            _ => {
                return Err(ProtoError::Protocol(
                    "the server did not send an IMAP greeting".to_string(),
                ))
            }
        }
        self.greeting = greeting.text();
        let mut learned = false;
        if let Some(code) = greeting.code.as_ref().filter(|c| c.name == "CAPABILITY") {
            self.capabilities = code
                .words()
                .iter()
                .map(|w| w.to_ascii_uppercase())
                .collect();
            learned = true;
        }
        if !learned {
            self.capability()?;
        }
        Ok(())
    }

    /// Greeting text (after any response code).
    pub fn greeting(&self) -> &str {
        &self.greeting
    }

    /// True when the greeting was `PREAUTH`.
    pub fn is_preauthenticated(&self) -> bool {
        self.preauth
    }

    /// Host name used for the connection (and TLS verification).
    pub fn host(&self) -> &str {
        &self.host
    }

    /// True once TLS is active (implicit or after STARTTLS).
    pub fn is_tls(&self) -> bool {
        self.transport.is_tls()
    }

    /// True after `ENABLE UTF8=ACCEPT` succeeded.
    pub fn utf8_enabled(&self) -> bool {
        self.utf8_enabled
    }

    /// Change the maximum accepted literal size.
    pub fn set_max_literal_size(&mut self, bytes: usize) {
        self.max_literal = bytes;
    }

    /// Cached capabilities (uppercased).
    pub fn capabilities(&self) -> &[String] {
        &self.capabilities
    }

    /// Case-insensitive capability check against the cached list.
    pub fn has_capability(&self, name: &str) -> bool {
        self.capabilities
            .iter()
            .any(|c| c.eq_ignore_ascii_case(name))
    }

    /// Replace the cached capability list (the Python code assigned
    /// `conn.capabilities` before `enable`).
    pub fn set_capabilities<I, S>(&mut self, capabilities: I)
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        self.capabilities = capabilities
            .into_iter()
            .map(|c| c.as_ref().to_ascii_uppercase())
            .collect();
    }

    fn utf8_allowed(&self) -> bool {
        self.utf8_enabled || self.has_capability("IMAP4REV2")
    }

    // ------------------------------------------------------------------
    // Low-level I/O
    // ------------------------------------------------------------------

    fn ensure_open(&self) -> Result<()> {
        if self.closed {
            return Err(ProtoError::Closed(match &self.bye {
                Some(text) => format!("the IMAP connection is closed: {text}"),
                None => "the IMAP connection is closed".to_string(),
            }));
        }
        Ok(())
    }

    fn read_parts(&mut self) -> Result<Vec<Part>> {
        let mut parts = Vec::new();
        loop {
            let line = match self.transport.read_line(MAX_LINE) {
                Ok(line) => line,
                Err(error) => {
                    self.closed = true;
                    return Err(match (&error, &self.bye) {
                        (ProtoError::Closed(_), Some(text)) => {
                            ProtoError::Closed(format!("the server closed the connection: {text}"))
                        }
                        _ => error,
                    });
                }
            };
            match literal_size(&line) {
                Some(size) => {
                    if size > self.max_literal {
                        self.closed = true;
                        self.transport.shutdown();
                        return Err(ProtoError::Protocol(format!(
                            "the server sent a {size}-byte literal (limit {})",
                            self.max_literal
                        )));
                    }
                    let literal = self.transport.read_exact_vec(size).inspect_err(|_| {
                        self.closed = true;
                    })?;
                    parts.push(Part {
                        text: line,
                        literal: Some(literal),
                    });
                }
                None => {
                    parts.push(Part::text(line));
                    return Ok(parts);
                }
            }
        }
    }

    fn read_response(&mut self) -> Result<Response> {
        let parts = self.read_parts()?;
        parse_response(parts)
    }

    fn note_untagged(&mut self, response: &UntaggedResponse) {
        match response.kind.as_str() {
            "CAPABILITY" => {
                self.capabilities = response.words_upper();
                self.capabilities_seen = true;
            }
            "BYE" => self.bye = Some(response.text()),
            _ => {}
        }
        if let Some(code) = response.code.as_ref().filter(|c| c.name == "CAPABILITY") {
            self.capabilities = code
                .words()
                .iter()
                .map(|w| w.to_ascii_uppercase())
                .collect();
            self.capabilities_seen = true;
        }
    }

    fn new_tag(&mut self) -> String {
        self.next_tag += 1;
        format!("A{:04}", self.next_tag)
    }

    fn finish(
        &mut self,
        tag: &str,
        tagged: Tagged,
        untagged: Vec<UntaggedResponse>,
    ) -> Result<CommandResponse> {
        if tagged.tag != tag {
            self.closed = true;
            return Err(ProtoError::Protocol(format!(
                "unexpected tagged response {:?} (expected {tag})",
                tagged.tag
            )));
        }
        if let Some(code) = tagged.code.as_ref().filter(|c| c.name == "CAPABILITY") {
            self.capabilities = code
                .words()
                .iter()
                .map(|w| w.to_ascii_uppercase())
                .collect();
            self.capabilities_seen = true;
        }
        Ok(CommandResponse {
            status: tagged.status,
            code: tagged.code,
            text: tagged.text,
            raw_text: tagged.raw_text,
            untagged,
        })
    }

    /// Read responses until the tagged completion for `tag`.
    fn collect(
        &mut self,
        tag: &str,
        mut untagged: Vec<UntaggedResponse>,
    ) -> Result<CommandResponse> {
        loop {
            match self.read_response()? {
                Response::Untagged(response) => {
                    self.note_untagged(&response);
                    untagged.push(response);
                }
                Response::Tagged(tagged) => return self.finish(tag, tagged, untagged),
                Response::Continuation(_) => {
                    self.closed = true;
                    return Err(ProtoError::Protocol(
                        "unexpected continuation request from the server".to_string(),
                    ));
                }
            }
        }
    }

    fn render(&self, args: &[Arg]) -> Result<Vec<Segment>> {
        let mut segments = Vec::new();
        for arg in args {
            segments.push(Segment::Text(b" ".to_vec()));
            match arg {
                Arg::Atom(value) => {
                    self.check_text(value)?;
                    segments.push(Segment::Text(value.as_bytes().to_vec()));
                }
                Arg::Quoted(value) => {
                    self.check_text(value)?;
                    segments.push(Segment::Text(quote(value).into_bytes()));
                }
                Arg::AString(value) => {
                    if value.is_ascii() && !has_line_break(value) {
                        segments.push(Segment::Text(quote(value).into_bytes()));
                    } else {
                        segments.push(Segment::Literal {
                            data: value.as_bytes().to_vec(),
                            binary: false,
                        });
                    }
                }
                Arg::Literal(data) => segments.push(Segment::Literal {
                    data: data.clone(),
                    binary: false,
                }),
            }
        }
        Ok(segments)
    }

    fn check_text(&self, value: &str) -> Result<()> {
        if has_line_break(value) {
            return Err(ProtoError::Encoding(
                "IMAP command arguments cannot contain line breaks".to_string(),
            ));
        }
        if !value.is_ascii() && !self.utf8_allowed() {
            return Err(ProtoError::Encoding(
                "a non-ASCII IMAP argument requires UTF8=ACCEPT or IMAP4rev2".to_string(),
            ));
        }
        Ok(())
    }

    /// Send `name` + segments and wait for the tagged completion.
    fn run(&mut self, name: &str, segments: Vec<Segment>) -> Result<CommandResponse> {
        self.ensure_open()?;
        self.capabilities_seen = false;
        let tag = self.new_tag();
        let mut pending = format!("{tag} {name}").into_bytes();
        let mut untagged = Vec::new();
        for segment in segments {
            match segment {
                Segment::Text(text) => pending.extend_from_slice(&text),
                Segment::Literal { data, binary } => {
                    if binary {
                        pending.push(b'~');
                    }
                    pending.extend_from_slice(format!("{{{}}}\r\n", data.len()).as_bytes());
                    self.write(&pending)?;
                    pending.clear();
                    loop {
                        match self.read_response()? {
                            Response::Continuation(_) => break,
                            Response::Untagged(response) => {
                                self.note_untagged(&response);
                                untagged.push(response);
                            }
                            // The server rejected the command before the literal.
                            Response::Tagged(tagged) => return self.finish(&tag, tagged, untagged),
                        }
                    }
                    self.write(&data)?;
                }
            }
        }
        pending.extend_from_slice(b"\r\n");
        self.write(&pending)?;
        self.collect(&tag, untagged)
    }

    fn write(&mut self, data: &[u8]) -> Result<()> {
        self.transport.write_all(data).inspect_err(|_| {
            self.closed = true;
        })
    }

    /// Generic tagged command executor: `name` followed by `args`.
    ///
    /// Returns the response for `OK`, `NO` and `BAD` alike; only transport
    /// and protocol failures are errors. Use
    /// [`CommandResponse::into_result`] to turn `NO`/`BAD` into errors.
    pub fn command(&mut self, name: &str, args: &[Arg]) -> Result<CommandResponse> {
        let segments = self.render(args)?;
        self.run(name, segments)
    }

    /// `imaplib.IMAP4.uid(command, *args)`: `UID <command> args...`.
    pub fn uid(&mut self, command: &str, args: &[Arg]) -> Result<CommandResponse> {
        let mut all = Vec::with_capacity(args.len() + 1);
        all.push(Arg::atom(command.to_ascii_uppercase()));
        all.extend_from_slice(args);
        self.command("UID", &all)
    }

    // ------------------------------------------------------------------
    // Connection state commands
    // ------------------------------------------------------------------

    /// `CAPABILITY`: refresh and return the capability list.
    pub fn capability(&mut self) -> Result<Vec<String>> {
        self.command("CAPABILITY", &[])?.into_result()?;
        Ok(self.capabilities.clone())
    }

    /// `NOOP`.
    pub fn noop(&mut self) -> Result<CommandResponse> {
        self.command("NOOP", &[])?.into_result()
    }

    /// `STARTTLS` on a plain connection, then refresh capabilities.
    ///
    /// Like `imaplib.starttls`, fails before sending anything when the
    /// server does not advertise STARTTLS.
    pub fn starttls(&mut self) -> Result<()> {
        self.ensure_open()?;
        if self.transport.is_tls() {
            return Err(ProtoError::Protocol(
                "TLS session already established".to_string(),
            ));
        }
        if !self.has_capability("STARTTLS") {
            return Err(ProtoError::Protocol(
                "TLS not supported by server".to_string(),
            ));
        }
        self.command("STARTTLS", &[])?.into_result()?;
        let connector = self.connector.clone();
        let host = self.host.clone();
        if let Err(error) = self.transport.start_tls(&connector, &host) {
            self.closed = true;
            return Err(error);
        }
        self.capabilities.clear();
        self.capability()?;
        Ok(())
    }

    /// Pre-authentication capabilities can be narrower than the real ones;
    /// refresh unless the authentication response already carried them. A
    /// NO/BAD answer keeps the old list (authentication still succeeded);
    /// transport failures propagate.
    fn refresh_after_auth(&mut self) -> Result<()> {
        if self.capabilities_seen {
            return Ok(());
        }
        self.command("CAPABILITY", &[]).map(|_| ())
    }

    /// `LOGIN user password`. Credentials are quoted when ASCII and sent as
    /// literals otherwise; they never appear in errors.
    pub fn login(&mut self, user: &str, password: &str) -> Result<()> {
        self.command("LOGIN", &[Arg::astring(user), Arg::astring(password)])?
            .into_result()?;
        self.refresh_after_auth()
    }

    /// `AUTHENTICATE mechanism` with a challenge/response callback, like
    /// `imaplib.authenticate`. The callback receives each decoded server
    /// challenge and returns the raw (unencoded) reply, or `None` to cancel
    /// with `*`.
    pub fn authenticate<F>(&mut self, mechanism: &str, mut responder: F) -> Result<()>
    where
        F: FnMut(&[u8]) -> Option<Vec<u8>>,
    {
        self.ensure_open()?;
        self.capabilities_seen = false;
        let tag = self.new_tag();
        let line = format!("{tag} AUTHENTICATE {}\r\n", mechanism.to_ascii_uppercase());
        self.write(line.as_bytes())?;
        let mut untagged = Vec::new();
        loop {
            match self.read_response()? {
                Response::Continuation(text) => {
                    let challenge = BASE64.decode(text.trim()).unwrap_or_default();
                    let reply = match responder(&challenge) {
                        Some(data) => {
                            let mut encoded = BASE64.encode(data).into_bytes();
                            encoded.extend_from_slice(b"\r\n");
                            encoded
                        }
                        None => b"*\r\n".to_vec(),
                    };
                    self.write(&reply)?;
                }
                Response::Untagged(response) => {
                    self.note_untagged(&response);
                    untagged.push(response);
                }
                Response::Tagged(tagged) => {
                    self.finish(&tag, tagged, untagged)?.into_result()?;
                    return self.refresh_after_auth();
                }
            }
        }
    }

    /// `AUTHENTICATE XOAUTH2` as in `mailbox_download.download_inbox`:
    /// `user={email}\x01auth=Bearer {token}\x01\x01`. A second (error)
    /// challenge is answered with an empty line so the server completes
    /// with `NO`.
    pub fn authenticate_xoauth2(&mut self, user: &str, access_token: &str) -> Result<()> {
        let auth = format!("user={user}\x01auth=Bearer {access_token}\x01\x01");
        let mut sent = false;
        self.authenticate("XOAUTH2", move |_challenge| {
            if sent {
                Some(Vec::new())
            } else {
                sent = true;
                Some(auth.as_bytes().to_vec())
            }
        })
    }

    /// `ENABLE capability`. Like `imaplib.enable`, fails without sending
    /// when ENABLE is not advertised. On success with `UTF8=ACCEPT`, UTF-8
    /// arguments and the APPEND `UTF8 (~{n})` form are used. Returns the
    /// capabilities listed in `* ENABLED`.
    pub fn enable(&mut self, capability: &str) -> Result<Vec<String>> {
        if !self.has_capability("ENABLE") {
            return Err(ProtoError::Protocol(
                "Server does not support ENABLE".to_string(),
            ));
        }
        let response = self
            .command("ENABLE", &[Arg::atom(capability)])?
            .into_result()?;
        if capability.eq_ignore_ascii_case("UTF8=ACCEPT") {
            self.utf8_enabled = true;
        }
        Ok(response
            .untagged_of("ENABLED")
            .flat_map(UntaggedResponse::words_upper)
            .collect())
    }

    /// `LOGOUT` and close the socket. Never fails when the server simply
    /// hangs up after `BYE`.
    pub fn logout(&mut self) -> Result<()> {
        if self.closed {
            self.transport.shutdown();
            return Ok(());
        }
        let result = match self.command("LOGOUT", &[]) {
            Ok(_) => Ok(()),
            Err(ProtoError::Closed(_)) if self.bye.is_some() => Ok(()),
            Err(error) => Err(error),
        };
        self.closed = true;
        self.transport.shutdown();
        result
    }

    // ------------------------------------------------------------------
    // Mailbox commands
    // ------------------------------------------------------------------

    /// `SELECT` (or `EXAMINE` when `readonly`, like
    /// `imaplib.select(readonly=True)`).
    pub fn select(&mut self, mailbox: &str, readonly: bool) -> Result<MailboxInfo> {
        let name = if readonly { "EXAMINE" } else { "SELECT" };
        let response = self.command(name, &[Arg::quoted(mailbox)])?.into_result()?;
        Ok(MailboxInfo::from_response(response, readonly))
    }

    /// `EXAMINE` (read-only select).
    pub fn examine(&mut self, mailbox: &str) -> Result<MailboxInfo> {
        self.select(mailbox, true)
    }

    /// `CLOSE` (expunges `\Deleted` in a read-write mailbox).
    pub fn close(&mut self) -> Result<()> {
        self.command("CLOSE", &[])?.into_result().map(|_| ())
    }

    /// `UNSELECT` (RFC 3691).
    pub fn unselect(&mut self) -> Result<()> {
        self.command("UNSELECT", &[])?.into_result().map(|_| ())
    }

    /// `CREATE mailbox`.
    pub fn create(&mut self, mailbox: &str) -> Result<()> {
        self.command("CREATE", &[Arg::quoted(mailbox)])?
            .into_result()
            .map(|_| ())
    }

    /// `DELETE mailbox`.
    pub fn delete_mailbox(&mut self, mailbox: &str) -> Result<()> {
        self.command("DELETE", &[Arg::quoted(mailbox)])?
            .into_result()
            .map(|_| ())
    }

    /// `LIST "reference" "pattern"`; `list("", "*")` is `imaplib.list()`.
    pub fn list(&mut self, reference: &str, pattern: &str) -> Result<Vec<ListEntry>> {
        self.command("LIST", &[Arg::quoted(reference), Arg::quoted(pattern)])?
            .into_result()?
            .list_entries()
    }

    /// `LIST "" "*" RETURN (SPECIAL-USE)` (RFC 6154), as sent by
    /// `imap_client._list_folders(special_use=True)`.
    pub fn list_special_use(&mut self) -> Result<Vec<ListEntry>> {
        self.command(
            "LIST",
            &[
                Arg::quoted(""),
                Arg::quoted("*"),
                Arg::atom("RETURN (SPECIAL-USE)"),
            ],
        )?
        .into_result()?
        .list_entries()
    }

    /// `STATUS mailbox (items)`; returns `(name, value)` pairs.
    pub fn status(&mut self, mailbox: &str, items: &str) -> Result<Vec<(String, u64)>> {
        let response = self
            .command("STATUS", &[Arg::quoted(mailbox), Arg::atom(items)])?
            .into_result()?;
        let mut out = Vec::new();
        for status in response.untagged_of("STATUS") {
            let values = status.values()?;
            if let Some(Value::List(items)) = values.get(1) {
                for pair in items.chunks(2) {
                    if let [key, value] = pair {
                        if let (Some(key), Some(value)) = (key.to_string_lossy(), value.as_number())
                        {
                            out.push((key.to_ascii_uppercase(), value));
                        }
                    }
                }
            }
        }
        Ok(out)
    }

    /// `APPEND mailbox [flags] [date] literal`, mirroring
    /// `imaplib.append(mailbox, flags, date_time, message)`:
    /// flags without parentheses are wrapped, `internal_date` is an IMAP
    /// date-time (`"01-Jan-2026 10:00:00 +0000"`, quotes optional), and
    /// line endings are normalized to CRLF. After `ENABLE UTF8=ACCEPT` the
    /// RFC 6855 `UTF8 (~{n})` form is used. Returns `[APPENDUID]` if sent.
    pub fn append(
        &mut self,
        mailbox: &str,
        flags: Option<&str>,
        internal_date: Option<&str>,
        message: &[u8],
    ) -> Result<Option<AppendUid>> {
        let mut segments = self.render(&[Arg::quoted(mailbox)])?;
        if let Some(flags) = flags.map(str::trim).filter(|f| !f.is_empty()) {
            self.check_text(flags)?;
            let wrapped = if flags.starts_with('(') && flags.ends_with(')') {
                flags.to_string()
            } else {
                format!("({flags})")
            };
            segments.push(Segment::Text(format!(" {wrapped}").into_bytes()));
        }
        if let Some(date) = internal_date.map(str::trim).filter(|d| !d.is_empty()) {
            self.check_text(date)?;
            let quoted = if date.starts_with('"') {
                date.to_string()
            } else {
                quote(date)
            };
            segments.push(Segment::Text(format!(" {quoted}").into_bytes()));
        }
        let data = normalize_crlf(message);
        if self.utf8_enabled {
            segments.push(Segment::Text(b" UTF8 (".to_vec()));
            segments.push(Segment::Literal { data, binary: true });
            segments.push(Segment::Text(b")".to_vec()));
        } else {
            segments.push(Segment::Text(b" ".to_vec()));
            segments.push(Segment::Literal {
                data,
                binary: false,
            });
        }
        let response = self.run("APPEND", segments)?.into_result()?;
        Ok(response
            .code_named("APPENDUID")
            .and_then(AppendUid::from_code))
    }

    // ------------------------------------------------------------------
    // Selected-state commands
    // ------------------------------------------------------------------

    fn search_args(charset: Option<&str>, criteria: &[Arg]) -> Vec<Arg> {
        let mut args = Vec::with_capacity(criteria.len() + 2);
        if let Some(charset) = charset {
            args.push(Arg::atom("CHARSET"));
            args.push(Arg::atom(charset));
        }
        args.extend_from_slice(criteria);
        args
    }

    /// `UID SEARCH [CHARSET cs] criteria...` — `conn.uid("search", None,
    /// *criteria)`. Returns UIDs in server order.
    pub fn uid_search(&mut self, charset: Option<&str>, criteria: &[Arg]) -> Result<Vec<u32>> {
        let mut args = vec![Arg::atom("SEARCH")];
        args.extend(Self::search_args(charset, criteria));
        self.command("UID", &args)?.into_result()?.search_results()
    }

    /// `SEARCH` (sequence numbers).
    pub fn search(&mut self, charset: Option<&str>, criteria: &[Arg]) -> Result<Vec<u32>> {
        let args = Self::search_args(charset, criteria);
        self.command("SEARCH", &args)?
            .into_result()?
            .search_results()
    }

    /// `UID FETCH uid_set items`, e.g.
    /// `uid_fetch("1,5:7", "(UID FLAGS BODY.PEEK[])")`.
    pub fn uid_fetch(&mut self, uid_set: &str, items: &str) -> Result<Vec<FetchResponse>> {
        self.command(
            "UID",
            &[Arg::atom("FETCH"), Arg::atom(uid_set), Arg::atom(items)],
        )?
        .into_result()?
        .fetches()
    }

    /// `FETCH seq_set items`.
    pub fn fetch(&mut self, seq_set: &str, items: &str) -> Result<Vec<FetchResponse>> {
        self.command("FETCH", &[Arg::atom(seq_set), Arg::atom(items)])?
            .into_result()?
            .fetches()
    }

    /// `UID STORE uid_set mode flags`, e.g.
    /// `uid_store("7", "+FLAGS.SILENT", "(\\Deleted)")`. Returns the FETCH
    /// responses the server sent (none for `.SILENT`).
    pub fn uid_store(
        &mut self,
        uid_set: &str,
        mode: &str,
        flags: &str,
    ) -> Result<Vec<FetchResponse>> {
        self.command(
            "UID",
            &[
                Arg::atom("STORE"),
                Arg::atom(uid_set),
                Arg::atom(mode),
                Arg::atom(flags),
            ],
        )?
        .into_result()?
        .fetches()
    }

    /// `UID COPY uid_set mailbox`; returns `[COPYUID]` when sent.
    pub fn uid_copy(&mut self, uid_set: &str, mailbox: &str) -> Result<Option<CopyUid>> {
        let response = self
            .command(
                "UID",
                &[Arg::atom("COPY"), Arg::atom(uid_set), Arg::quoted(mailbox)],
            )?
            .into_result()?;
        Ok(response.code_named("COPYUID").and_then(CopyUid::from_code))
    }

    /// `UID MOVE uid_set mailbox` (RFC 6851); returns `[COPYUID]` when sent.
    pub fn uid_move(&mut self, uid_set: &str, mailbox: &str) -> Result<Option<CopyUid>> {
        let response = self
            .command(
                "UID",
                &[Arg::atom("MOVE"), Arg::atom(uid_set), Arg::quoted(mailbox)],
            )?
            .into_result()?;
        Ok(response.code_named("COPYUID").and_then(CopyUid::from_code))
    }

    /// `UID EXPUNGE uid_set` (UIDPLUS); returns expunged sequence numbers.
    pub fn uid_expunge(&mut self, uid_set: &str) -> Result<Vec<u32>> {
        Ok(self
            .command("UID", &[Arg::atom("EXPUNGE"), Arg::atom(uid_set)])?
            .into_result()?
            .expunged())
    }

    /// Mailbox-wide `EXPUNGE`; returns expunged sequence numbers.
    ///
    /// The original deletion code never uses this as a fallback because it
    /// would also erase messages another client marked `\Deleted`.
    pub fn expunge(&mut self) -> Result<Vec<u32>> {
        Ok(self.command("EXPUNGE", &[])?.into_result()?.expunged())
    }
}

impl Drop for ImapConnection {
    fn drop(&mut self) {
        self.transport.shutdown();
    }
}
