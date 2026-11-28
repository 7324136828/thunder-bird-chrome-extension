//! IMAP operations against an unlocked [`MailAccount`] (port of
//! `app/mail/imap_client.py`).
//!
//! Each call opens a short-lived connection, mirroring how Thunderbird talks
//! to a server. The password comes from the in-memory session store only.
//!
//! # Fixed public contract (Phase 2)
//!
//! The signatures below are pinned so routes, `trash`, `pop3`, the MCP server
//! and Inbox Doctor can be written in parallel.
//!
//! # POP3 dispatch
//!
//! Every public *read* entry point (`verify_login`, `list_folders`,
//! `list_messages`, `fetch_raw`, `fetch_message`, `fetch_attachment`,
//! `fetch_classification_message`, `prepare_sender_rule`,
//! `prepare_sender_rule_scope`, `update_retention`) first checks
//! `account.is_pop3()` and, if so, delegates to the same-named function in
//! [`crate::pop3`]. Mutating server operations (`set_flags`,
//! `delete_message`, `delete_messages`) return [`crate::pop3::imap_only`]
//! for POP3 accounts. `save_sent_copy` never connects for a POP3 account and
//! answers `MailError::SentCopy { folder: None, .. }` (the send route skips
//! it for POP3 accounts anyway).
//!
//! Python `dict` results that go straight to JSON are `serde_json::Value`
//! with the exact Python keys. Dicts consumed internally are typed structs.
//!
//! # Error model
//!
//! `imaplib` returned `("NO", data)` for a refused command but *raised*
//! `IMAP4.error` for `BAD`, protocol aborts and socket failures (`OSError`).
//! The port keeps that distinction internally ([`Fail::Proto`] versus
//! [`Fail::Mail`]) so the functions that caught `(OSError, IMAP4.error)` in
//! Python (`save_sent_copy`, `delete_messages`, the `RETURN (SPECIAL-USE)`
//! fallback) produce exactly the Python messages. Where Python let such an
//! exception escape (an HTTP 500 "Internal Server Error"), the port answers
//! `MailError::Operation("The mail server connection failed: …")` (502).
//!
//! # Intentional deviations
//!
//! * `set_flags` reports the real flags from the server's `FETCH (FLAGS)`
//!   reply. Python looked for them only in `imaplib` tuple items, which a
//!   plain FLAGS response never is, so it always answered `flags: []` (an
//!   `imaplib` parsing bug, not a contract). The Rust behaviour is kept
//!   deliberately: callers get the flags the server actually stored.
//! * Every connection caps a single server literal at [`MAX_LITERAL_BYTES`]
//!   (100 MiB) instead of `mail_proto`'s 256 MiB default; a larger literal
//!   aborts the command with a connection error (502). `imaplib` had no cap.
//! * FETCH data is parsed with a real tokenizer: a `UID`/`FLAGS` item after
//!   the literal and quoted (non-literal) bodies are understood, and one
//!   malformed FETCH or LIST response is skipped instead of being matched
//!   by regular expressions.
//! * TLS certificates are verified against the system trust store
//!   (`imaplib`'s default context did not verify them).
//! * Command arguments containing CR/LF (search text, Message-ID) are
//!   rejected by the protocol client instead of being sent verbatim.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use mail_proto::imap::{Arg, CommandResponse, FetchResponse, ImapConnection, Status};
use mail_proto::{ProtoError, Security, DEFAULT_TIMEOUT};
use serde_json::{json, Map, Value};

use crate::error::{MailError, Result};
use crate::model::is_category;
use crate::parsing::{self, AttachmentPayload, ParsedMessage};
use crate::retention::{
    self, normalize_uid_validity, MetadataOptions, Patch, RetentionOverride, RetentionStore,
    SenderRule,
};
use crate::servers::python_repr_str;
use crate::sessions::MailAccount;

#[path = "imap_parts/domains.rs"]
mod domains;
#[path = "imap_parts/folders.rs"]
mod folders;

use folders::Folder;

/// Largest single literal accepted from an IMAP server (100 MiB).
///
/// A hostile or broken server could otherwise announce literals up to
/// `mail_proto`'s default 256 MiB cap. The cap must stay at least as large as
/// the biggest message the app handles: the trash archive accepts messages up
/// to [`crate::trash::MAX_MESSAGE_BYTES`] (64 MiB), checked at compile time
/// below. The cap is per literal; `mail_proto` does not bound how many
/// literals one command response may carry.
pub const MAX_LITERAL_BYTES: usize = 100 * 1024 * 1024;

const _: () = assert!(MAX_LITERAL_BYTES as u64 >= crate::trash::MAX_MESSAGE_BYTES);

/// `SentCopyError` message (the error itself is [`MailError::SentCopy`]).
pub const SENT_COPY_MESSAGE: &str = "The server could not save the message in Sent.";

/// `_HEADER_FIELDS`: the headers every list summary is built from.
const HEADER_FIELDS: &str =
    "(FROM TO CC BCC SUBJECT DATE MESSAGE-ID LIST-ID LIST-UNSUBSCRIBE PRECEDENCE AUTO-SUBMITTED)";
/// `_DOMAIN_FETCH_BATCH_SIZE`.
const DOMAIN_FETCH_BATCH_SIZE: usize = 200;
const MAX_UID: i64 = 4_294_967_295;

/// Keyword arguments of `list_messages` (Python defaults via `Default`).
#[derive(Debug, Clone, Copy)]
pub struct ListMessagesOptions<'a> {
    pub offset: usize,
    pub limit: usize,
    pub query: &'a str,
    /// `"all"`, `"unread"` or `"read"`.
    pub read_status: &'a str,
    /// Already normalized with [`normalize_sender_domains`].
    pub sender_domains: &'a [String],
    pub has_unicode_input: bool,
    pub retention_store: Option<&'a RetentionStore>,
    pub category_expiration_days: Option<&'a BTreeMap<String, i64>>,
    pub category: Option<&'a str>,
    pub expired_only: bool,
}

impl Default for ListMessagesOptions<'_> {
    fn default() -> Self {
        Self {
            offset: 0,
            limit: 5,
            query: "",
            read_status: "all",
            sender_domains: &[],
            has_unicode_input: false,
            retention_store: None,
            category_expiration_days: None,
            category: None,
            expired_only: false,
        }
    }
}

/// `fetch_classification_message` result
/// (`{"raw", "headers", "received_at", "uid_validity"}`).
#[derive(Debug, Clone)]
pub struct ClassificationMessage {
    pub raw: Vec<u8>,
    pub headers: ParsedMessage,
    pub received_at: Option<String>,
    pub uid_validity: String,
}

/// `_sender_rule_scope` / `prepare_sender_rule_scope` result
/// (`{"uid_validity", "first_uid"}`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SenderRuleScope {
    pub uid_validity: String,
    pub first_uid: i64,
}

/// `prepare_sender_rule` result (`{**scope, "sender", "headers", "received_at"}`).
#[derive(Debug, Clone)]
pub struct PreparedSenderRule {
    pub scope: SenderRuleScope,
    pub sender: String,
    pub headers: ParsedMessage,
    pub received_at: Option<String>,
}

// ---------------------------------------------------------------------------
// Internal error model
// ---------------------------------------------------------------------------

/// A failure inside one operation: a Python-visible mail error
/// (`MailOperationError`, `RetentionConflictError`, `ValueError`, ...) or
/// what `imaplib` raised (`IMAP4.error`, `OSError`, `UnicodeError`).
#[derive(Debug)]
enum Fail {
    Mail(MailError),
    Proto(ProtoError),
}

type R<T> = std::result::Result<T, Fail>;

impl From<MailError> for Fail {
    fn from(error: MailError) -> Self {
        Fail::Mail(error)
    }
}

impl From<ProtoError> for Fail {
    fn from(error: ProtoError) -> Self {
        Fail::Proto(error)
    }
}

impl Fail {
    /// An uncaught `imaplib`/socket exception becomes a safe 502.
    fn into_mail(self) -> MailError {
        match self {
            Fail::Mail(error) => error,
            Fail::Proto(error) => {
                MailError::operation(format!("The mail server connection failed: {error}"))
            }
        }
    }
}

fn op(message: impl Into<String>) -> Fail {
    Fail::Mail(MailError::operation(message))
}

fn conflict(message: &str) -> MailError {
    MailError::RetentionConflict(message.to_string())
}

/// `imaplib` semantics for a command result: `BAD` raises, `OK`/`NO` are
/// returned for the caller to check.
fn checked(response: std::result::Result<CommandResponse, ProtoError>) -> R<CommandResponse> {
    let response = response?;
    if response.status == Status::Bad {
        return Err(Fail::Proto(ProtoError::Bad(response.raw_text)));
    }
    Ok(response)
}

/// Run `body` on a fresh connection and always log out afterwards
/// (`try: ... finally: _logout(conn)`).
fn with_connection<T>(
    account: &MailAccount,
    body: impl FnOnce(&mut ImapConnection) -> R<T>,
) -> Result<T> {
    let mut conn = connect(account)?;
    let result = body(&mut conn);
    logout(conn);
    result.map_err(Fail::into_mail)
}

// ---------------------------------------------------------------------------
// Connection
// ---------------------------------------------------------------------------

/// Open an authenticated IMAP connection (`connect`). Failures are
/// `MailError::Operation` with the Python messages. Server literals are
/// capped at [`MAX_LITERAL_BYTES`].
pub fn connect(account: &MailAccount) -> Result<ImapConnection> {
    let security = match account.imap_security().as_str() {
        "ssl" => Security::Ssl,
        "starttls" => Security::StartTls,
        _ => Security::None,
    };
    let connect_error = |error: &ProtoError| {
        MailError::operation(format!(
            "Could not connect to {}:{}: {error}",
            account.incoming_server, account.incoming_port
        ))
    };
    let mut conn = ImapConnection::connect(
        &account.incoming_server,
        account.incoming_port,
        security,
        DEFAULT_TIMEOUT,
    )
    .map_err(|error| connect_error(&error))?;
    // Bound server literals before any authenticated traffic (see
    // `MAX_LITERAL_BYTES`). The greeting and pre-login CAPABILITY replies are
    // read under mail_proto's default cap; they carry no literals in practice.
    conn.set_max_literal_size(MAX_LITERAL_BYTES);
    if let Err(error) = conn.login(&account.email, &account.password) {
        let _ = conn.logout();
        return Err(match error {
            // Python only caught IMAP4.error here; a socket failure during
            // LOGIN is reported like a connection failure instead of a 500.
            ProtoError::Io(_) | ProtoError::Timeout | ProtoError::Tls(_) => connect_error(&error),
            _ => MailError::operation(
                "Mailbox sign-in failed. Check the password or use an app password.",
            ),
        });
    }
    Ok(conn)
}

/// Best-effort LOGOUT (`_logout`); never fails.
pub fn logout(conn: ImapConnection) {
    let mut conn = conn;
    let _ = conn.logout();
}

/// Mailbox state learned from SELECT/EXAMINE.
#[derive(Debug, Clone)]
struct Selected {
    exists: u64,
    /// `_uid_validity(conn)`: the normalized epoch, `None` when unknown.
    uid_validity: Option<String>,
    /// Raw `[UIDNEXT ...]` value (`conn.response("UIDNEXT")`).
    uid_next: Option<String>,
}

/// The first value of a response code, in `imaplib.response(code)` order:
/// untagged status responses as they arrived, then the tagged line.
fn first_code(response: &CommandResponse, name: &str) -> Option<String> {
    response
        .untagged
        .iter()
        .filter_map(|item| item.code.as_ref())
        .chain(response.code.as_ref())
        .find(|code| code.name.eq_ignore_ascii_case(name))
        .map(|code| code.args.clone())
}

/// `_select` plus the `_uid_validity` / `UIDNEXT` reads that follow it.
fn select_info(conn: &mut ImapConnection, folder: &str, readonly: bool) -> R<Selected> {
    let command = if readonly { "EXAMINE" } else { "SELECT" };
    let response = checked(conn.command(command, &[Arg::quoted(folder)]))?;
    if !response.is_ok() {
        return Err(op(format!(
            "The server would not open folder {}",
            python_repr_str(folder)
        )));
    }
    if !readonly && first_code(&response, "READ-ONLY").is_some() {
        // imaplib raised IMAP4.readonly for a read-only SELECT.
        return Err(Fail::Proto(ProtoError::Protocol(format!(
            "{} is not writable",
            mail_proto::imap::quote(folder)
        ))));
    }
    let exists = response
        .untagged_of("EXISTS")
        .find_map(|item| item.number)
        .map_or(0, u64::from);
    Ok(Selected {
        exists,
        uid_validity: first_code(&response, "UIDVALIDITY")
            .as_deref()
            .and_then(normalize_uid_validity),
        uid_next: first_code(&response, "UIDNEXT"),
    })
}

/// `_select`: SELECT/EXAMINE `folder`; returns the EXISTS count (0 when
/// unparsable). Failure → `MailError::Operation("The server would not open folder '…'")`.
pub fn select(conn: &mut ImapConnection, folder: &str, readonly: bool) -> Result<u64> {
    select_info(conn, folder, readonly)
        .map(|selected| selected.exists)
        .map_err(Fail::into_mail)
}

/// Prove the credentials work; used when unlocking a session.
pub fn verify_login(account: &MailAccount) -> Result<()> {
    if account.is_pop3() {
        return crate::pop3::verify_login(account);
    }
    with_connection(account, |conn| {
        let response = checked(conn.command("EXAMINE", &[Arg::atom("INBOX")]))?;
        if !response.is_ok() {
            return Err(op("The server would not open the INBOX folder"));
        }
        Ok(())
    })
}

// ---------------------------------------------------------------------------
// Folders
// ---------------------------------------------------------------------------

/// `_list_folders(conn, special_use=...)`.
fn list_folders_inner(conn: &mut ImapConnection, special_use: bool) -> R<Vec<Folder>> {
    if special_use {
        // RFC 6154 requires special-use attributes only when requested. Keep
        // ordinary LIST as a fallback for servers with inaccurate capabilities.
        let response = conn.command(
            "LIST",
            &[
                Arg::atom("\"\""),
                Arg::atom("\"*\""),
                Arg::atom("RETURN (SPECIAL-USE)"),
            ],
        );
        if let Ok(response) = response {
            if response.is_ok() {
                return Ok(folders::parse_folders(&response));
            }
        }
    }
    let response = checked(conn.command("LIST", &[Arg::atom("\"\""), Arg::atom("*")]))?;
    if !response.is_ok() {
        return Err(op("The server did not return a folder list"));
    }
    Ok(folders::parse_folders(&response))
}

/// `list_folders` → list of folder dicts
/// (`{"name", "delimiter", "flags", "special", "selectable"}`, as Python).
pub fn list_folders(account: &MailAccount) -> Result<Vec<Value>> {
    if account.is_pop3() {
        return crate::pop3::list_folders(account);
    }
    with_connection(account, |conn| {
        Ok(list_folders_inner(conn, false)?
            .iter()
            .map(Folder::to_json)
            .collect())
    })
}

// ---------------------------------------------------------------------------
// Sent copy
// ---------------------------------------------------------------------------

/// Capabilities from a CAPABILITY response (untagged data and
/// `[CAPABILITY ...]` codes), uppercased.
fn capability_set(response: &CommandResponse) -> BTreeSet<String> {
    let mut capabilities: BTreeSet<String> = response
        .untagged_of("CAPABILITY")
        .flat_map(|item| item.words_upper())
        .collect();
    for code in response
        .untagged
        .iter()
        .filter_map(|item| item.code.as_ref())
        .chain(response.code.as_ref())
        .filter(|code| code.name == "CAPABILITY")
    {
        capabilities.extend(code.words().iter().map(|w| w.to_ascii_uppercase()));
    }
    capabilities
}

/// `re.split(rb"\r?\n\r?\n", raw, maxsplit=1)[0]`.
fn header_block(raw: &[u8]) -> &[u8] {
    for index in 0..raw.len() {
        if raw[index] != b'\n' {
            continue;
        }
        let rest = &raw[index + 1..];
        if rest.starts_with(b"\n") || rest.starts_with(b"\r\n") {
            let start = if index > 0 && raw[index - 1] == b'\r' {
                index - 1
            } else {
                index
            };
            return &raw[..start];
        }
    }
    raw
}

fn sent_copy_error(folder: Option<String>) -> MailError {
    MailError::SentCopy {
        folder,
        message: SENT_COPY_MESSAGE.to_string(),
    }
}

fn save_sent_copy_inner(
    conn: &mut ImapConnection,
    raw_message: &[u8],
    message_id: &str,
    folder_slot: &mut Option<String>,
) -> R<String> {
    let response = checked(conn.command("CAPABILITY", &[]))?;
    let capabilities = if response.is_ok() {
        capability_set(&response)
    } else {
        BTreeSet::new()
    };
    let rev2 = capabilities.contains("IMAP4REV2");
    let headers = header_block(raw_message);
    if !rev2 && (!headers.is_ascii() || capabilities.contains("UTF8=ONLY")) {
        if !capabilities.contains("UTF8=ACCEPT") && !capabilities.contains("UTF8=ONLY") {
            return Err(Fail::Mail(sent_copy_error(None)));
        }
        // imaplib checks its capability list before ENABLE. Refresh it from
        // the authenticated CAPABILITY response rather than login's possibly
        // narrower pre-authentication capabilities.
        conn.set_capabilities(capabilities.iter());
        conn.enable("UTF8=ACCEPT")?;
    }
    let special_use = capabilities.contains("SPECIAL-USE") || rev2;
    let listed = list_folders_inner(conn, special_use)?;
    let mut folder = folders::sent_folder(&listed);
    if folder.is_none() {
        let candidate = folders::new_sent_folder(&listed);
        let response = checked(conn.command("CREATE", &[Arg::quoted(candidate.as_str())]))?;
        if !response.is_ok() {
            // Another client may have created Sent after our LIST.
            folder = folders::sent_folder(&list_folders_inner(conn, special_use)?);
            if folder.is_none() {
                return Err(Fail::Mail(sent_copy_error(None)));
            }
        } else {
            folder = Some(candidate);
        }
    }
    let folder = folder.unwrap_or_default();
    *folder_slot = Some(folder.clone());
    let response = checked(conn.command("EXAMINE", &[Arg::quoted(folder.as_str())]))?;
    if !response.is_ok() {
        return Err(Fail::Mail(sent_copy_error(Some(folder))));
    }
    let response = checked(conn.uid(
        "SEARCH",
        &[
            Arg::atom("HEADER"),
            Arg::atom("Message-ID"),
            Arg::quoted(message_id),
        ],
    ))?;
    if !response.is_ok() {
        return Err(Fail::Mail(sent_copy_error(Some(folder))));
    }
    let already_saved = response
        .untagged_of("SEARCH")
        .any(|item| !item.data_text().trim().is_empty());
    if !already_saved {
        conn.append(&folder, Some("(\\Seen)"), None, raw_message)?;
    }
    Ok(folder)
}

/// Save an accepted SMTP message in Sent unless the provider already saved
/// it. Returns the folder name. Failure → `MailError::SentCopy{folder,..}`
/// with `folder` set once the Sent folder was discovered.
/// POP3 accounts: `MailError::SentCopy { folder: None, .. }` without
/// connecting; the send route skips this call entirely for POP3 accounts.
pub fn save_sent_copy(
    account: &MailAccount,
    raw_message: &[u8],
    message_id: &str,
) -> Result<String> {
    if account.is_pop3() {
        return Err(sent_copy_error(None));
    }
    let Ok(mut conn) = connect(account) else {
        return Err(sent_copy_error(None));
    };
    let mut folder = None;
    let result = save_sent_copy_inner(&mut conn, raw_message, message_id, &mut folder);
    logout(conn);
    // Every failure (refusals, disconnects, encoding problems) is reported
    // without server details: SMTP delivery already succeeded.
    result.map_err(|_| sent_copy_error(folder))
}

// ---------------------------------------------------------------------------
// Listing
// ---------------------------------------------------------------------------

/// Validate sender-domain filters. `Err(String)` is the Python `ValueError`
/// message (routes answer 422 with it as string detail).
pub fn normalize_sender_domains(
    values: Option<&[String]>,
) -> std::result::Result<Vec<String>, String> {
    domains::normalize_sender_domains(values)
}

/// `_search_uids`: the first SEARCH response's UID tokens.
fn search_uids(
    conn: &mut ImapConnection,
    query: &str,
    sender_domains: &[String],
    has_unicode_input: bool,
    read_status: &str,
) -> R<Vec<String>> {
    let mut criteria: Vec<Arg> = Vec::new();
    if !query.is_empty() {
        let replaced = query.replace('\\', "\\\\").replace('"', " ");
        let safe = parsing::py_strip(&replaced);
        criteria = vec![Arg::atom("TEXT"), Arg::atom(format!("\"{safe}\""))];
    }
    if read_status != "all" {
        criteria.push(Arg::atom(if read_status == "unread" {
            "UNSEEN"
        } else {
            "SEEN"
        }));
    }
    // FROM is a substring search: narrow candidates on the server, then verify
    // the parsed address domain below. International domains can be stored in
    // Unicode or punycode, so retain all query candidates for those filters.
    if !sender_domains.is_empty()
        && !has_unicode_input
        && !sender_domains.iter().any(|domain| domain.contains("xn--"))
    {
        criteria.extend((1..sender_domains.len()).map(|_| Arg::atom("OR")));
        for domain in sender_domains {
            criteria.push(Arg::atom("FROM"));
            criteria.push(Arg::atom(format!("\"{domain}\"")));
        }
    }
    if criteria.is_empty() {
        criteria = vec![Arg::atom("ALL")];
    }
    let response = checked(conn.uid("SEARCH", &criteria))?;
    if !response.is_ok() {
        return Err(op("The server could not search this folder"));
    }
    let tokens = response
        .untagged_of("SEARCH")
        .next()
        .map(|item| {
            item.data_text()
                .split_ascii_whitespace()
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();
    Ok(tokens)
}

/// `int(uid)` over search tokens for listing.
fn parse_uids(tokens: &[String]) -> R<Vec<u32>> {
    tokens
        .iter()
        .map(|token| token.parse::<u32>())
        .collect::<std::result::Result<_, _>>()
        .map_err(|_| op("The server could not search this folder"))
}

fn uid_set(uids: &[u32]) -> String {
    uids.iter()
        .map(u32::to_string)
        .collect::<Vec<_>>()
        .join(",")
}

/// Parse every untagged FETCH response, skipping malformed ones (Python
/// skipped data items it could not interpret).
fn fetches(response: &CommandResponse) -> Vec<FetchResponse> {
    response
        .untagged_of("FETCH")
        .filter_map(|item| item.fetch().ok())
        .collect()
}

/// `_filter_sender_domains`: check only From headers in bounded batches
/// before counting and paging.
fn filter_sender_domains(
    conn: &mut ImapConnection,
    uids: &[u32],
    sender_domains: &[String],
) -> R<Vec<u32>> {
    let mut matches: BTreeSet<u32> = BTreeSet::new();
    for batch in uids.chunks(DOMAIN_FETCH_BATCH_SIZE) {
        let response = checked(conn.uid(
            "FETCH",
            &[
                Arg::atom(uid_set(batch)),
                Arg::atom("(UID BODY.PEEK[HEADER.FIELDS (FROM)])"),
            ],
        ))?;
        if !response.is_ok() {
            return Err(op("The server could not filter messages by sender domain"));
        }
        for fetch in fetches(&response) {
            let (Some(uid), Some(body)) = (fetch.uid(), fetch.first_body()) else {
                continue;
            };
            let headers = parsing::parse_message(body);
            let values = headers.get_all("From");
            let refs: Vec<&str> = values.iter().map(String::as_str).collect();
            for (_, address) in parsing::getaddresses(&refs) {
                let Some((_, host)) = address.rsplit_once('@') else {
                    continue;
                };
                let Ok(host) = domains::normalize_sender_domain(host) else {
                    continue;
                };
                if sender_domains
                    .iter()
                    .any(|domain| host == *domain || host.ends_with(&format!(".{domain}")))
                {
                    matches.insert(uid);
                    break;
                }
            }
        }
    }
    Ok(uids
        .iter()
        .copied()
        .filter(|uid| matches.contains(uid))
        .collect())
}

/// `_internal_iso(value)`.
fn internal_iso(value: &str) -> Option<String> {
    parsing::parsedate_to_datetime(value).map(|parsed| parsed.isoformat())
}

/// Keyword arguments of `_fetch_summaries`.
#[derive(Clone, Copy)]
struct SummaryContext<'a> {
    account: Option<&'a MailAccount>,
    folder: &'a str,
    uid_validity: Option<&'a str>,
    retention_store: Option<&'a RetentionStore>,
    category_expiration_days: Option<&'a BTreeMap<String, i64>>,
    sender_rules: Option<&'a HashMap<String, SenderRule>>,
    sender_rule_events: Option<&'a HashMap<String, Vec<SenderRule>>>,
}

/// One list summary (the Python dict) plus the fields filters read.
#[derive(Debug, Clone)]
struct Summary {
    uid: u32,
    category: String,
    expired: bool,
    fields: Map<String, Value>,
}

/// `_fetch_summaries`: header-only summaries with retention metadata.
fn fetch_summaries(
    conn: &mut ImapConnection,
    uids: &[u32],
    ctx: &SummaryContext<'_>,
) -> R<Vec<Summary>> {
    if uids.is_empty() {
        return Ok(Vec::new());
    }
    let query =
        format!("(UID FLAGS INTERNALDATE RFC822.SIZE BODY.PEEK[HEADER.FIELDS {HEADER_FIELDS}])");
    let response = checked(conn.uid("FETCH", &[Arg::atom(uid_set(uids)), Arg::atom(query)]))?;
    if !response.is_ok() {
        return Err(op("The server could not list messages in this folder"));
    }
    let store_account = ctx.retention_store.zip(ctx.account);
    let overrides: HashMap<i64, RetentionOverride> = match store_account {
        Some((store, account)) => {
            let numbers: Vec<i64> = uids.iter().map(|uid| i64::from(*uid)).collect();
            store.get_many(account, ctx.folder, &numbers, ctx.uid_validity)?
        }
        None => HashMap::new(),
    };
    let loaded_rules;
    let sender_rules = match ctx.sender_rules {
        Some(rules) => rules,
        None => {
            loaded_rules = match store_account {
                Some((store, account)) => store.get_sender_rules_for_folder(account, ctx.folder)?,
                None => HashMap::new(),
            };
            &loaded_rules
        }
    };
    let loaded_events;
    let sender_rule_events = match ctx.sender_rule_events {
        Some(events) => events,
        None => {
            loaded_events = match store_account {
                Some((store, account)) => {
                    store.get_sender_rule_events_for_folder(account, ctx.folder)?
                }
                None => HashMap::new(),
            };
            &loaded_events
        }
    };
    let mut summaries = Vec::new();
    for fetch in fetches(&response) {
        let (Some(uid), Some(raw_headers)) = (fetch.uid(), fetch.first_body()) else {
            continue;
        };
        let flags = fetch.flags().unwrap_or_default();
        let size = fetch.rfc822_size().unwrap_or(0);
        let internal = fetch.internal_date().unwrap_or_default();
        let msg = parsing::parse_message(raw_headers);
        let received_at = internal_iso(&internal);
        let sender = retention::sender_address(&msg);
        let metadata = retention::retention_metadata(
            &msg,
            received_at.as_deref(),
            ctx.category_expiration_days,
            &MetadataOptions {
                overrides: overrides.get(&i64::from(uid)),
                uid_validity: ctx.uid_validity,
                now: None,
                sender_rule: sender.as_ref().and_then(|s| sender_rules.get(s)),
                uid: Some(i64::from(uid)),
                sender_rule_events: Some(
                    sender
                        .as_ref()
                        .and_then(|s| sender_rule_events.get(s))
                        .map_or(&[][..], Vec::as_slice),
                ),
            },
        )?;
        let lowered: Vec<String> = flags.iter().map(|f| f.to_lowercase()).collect();
        let has = |flag: &str| lowered.iter().any(|l| l == flag);
        let category = metadata.category.clone();
        let expired = metadata.expired;
        let mut fields = Map::new();
        fields.insert("uid".into(), json!(uid));
        fields.insert("flags".into(), json!(flags));
        fields.insert("seen".into(), json!(has("\\seen")));
        fields.insert("flagged".into(), json!(has("\\flagged")));
        fields.insert("answered".into(), json!(has("\\answered")));
        fields.insert("size".into(), json!(size));
        fields.insert("internal_date".into(), json!(received_at));
        fields.insert(
            "subject".into(),
            json!(parsing::decode_value(msg.get("Subject").as_deref())),
        );
        fields.insert(
            "from".into(),
            json!(parsing::address_text(msg.get("From").as_deref())),
        );
        fields.insert(
            "to".into(),
            json!(parsing::address_text(msg.get("To").as_deref())),
        );
        fields.insert(
            "date".into(),
            json!(parsing::parse_date(msg.get("Date").as_deref()).or_else(|| received_at.clone())),
        );
        fields.extend(metadata.into_map());
        summaries.push(Summary {
            uid,
            category,
            expired,
            fields,
        });
    }
    Ok(summaries)
}

/// `list_messages` → `{"total","offset","limit","messages":[...]}`,
/// newest first for one page window. Python `ValueError`s (read status,
/// category, sender domains) are `MailError::validation` (422).
pub fn list_messages(
    account: &MailAccount,
    folder: &str,
    options: &ListMessagesOptions<'_>,
) -> Result<Value> {
    if account.is_pop3() {
        return crate::pop3::list_messages(account, folder, options);
    }
    if !matches!(options.read_status, "all" | "unread" | "read") {
        return Err(MailError::validation(
            "Read status must be all, unread, or read",
        ));
    }
    if options
        .category
        .is_some_and(|category| !is_category(category))
    {
        return Err(MailError::validation("Choose a valid email category"));
    }
    // IDNA can map Unicode to ordinary ASCII (e.g. faß.de -> fass.de), so
    // preserve the original spelling before normalization as well as xn--.
    let has_unicode_input = options.has_unicode_input
        || options
            .sender_domains
            .iter()
            .any(|domain| !domain.is_ascii());
    let domains =
        normalize_sender_domains(Some(options.sender_domains)).map_err(MailError::validation)?;
    with_connection(account, |conn| {
        let selected = select_info(conn, folder, true)?;
        let uid_validity = selected.uid_validity;
        let filtering = options.category.is_some() || options.expired_only;
        if filtering && uid_validity.is_none() {
            return Err(conflict(
                "Mailbox identity is unavailable. Refresh the folder before filtering retention.",
            )
            .into());
        }
        let tokens = search_uids(
            conn,
            options.query,
            &domains,
            has_unicode_input,
            options.read_status,
        )?;
        let mut uids = parse_uids(&tokens)?;
        if !domains.is_empty() {
            uids = filter_sender_domains(conn, &uids, &domains)?;
        }
        let (sender_rules, sender_rule_events) = match options.retention_store {
            Some(store) => (
                store.get_sender_rules_for_folder(account, folder)?,
                store.get_sender_rule_events_for_folder(account, folder)?,
            ),
            None => (HashMap::new(), HashMap::new()),
        };
        let ctx = SummaryContext {
            account: Some(account),
            folder,
            uid_validity: uid_validity.as_deref(),
            retention_store: options.retention_store,
            category_expiration_days: options.category_expiration_days,
            sender_rules: Some(&sender_rules),
            sender_rule_events: Some(&sender_rule_events),
        };
        let mut filtered: Option<HashMap<u32, Summary>> = None;
        if filtering {
            let mut kept = HashMap::new();
            for batch in uids.chunks(DOMAIN_FETCH_BATCH_SIZE) {
                for summary in fetch_summaries(conn, batch, &ctx)? {
                    if options.category.is_some_and(|c| summary.category != c) {
                        continue;
                    }
                    if options.expired_only && !summary.expired {
                        continue;
                    }
                    kept.insert(summary.uid, summary);
                }
            }
            uids.retain(|uid| kept.contains_key(uid));
            filtered = Some(kept);
        }
        let total = uids.len();
        let mut ordered = uids;
        ordered.sort_unstable();
        let window: Vec<u32> = ordered
            .into_iter()
            .rev()
            .skip(options.offset)
            .take(options.limit)
            .collect();
        let mut messages = match &filtered {
            None => fetch_summaries(conn, &window, &ctx)?,
            Some(kept) => window
                .iter()
                .filter_map(|uid| kept.get(uid).cloned())
                .collect(),
        };
        messages.sort_by_key(|summary| std::cmp::Reverse(summary.uid));
        let messages: Vec<Value> = messages
            .into_iter()
            .map(|summary| Value::Object(summary.fields))
            .collect();
        Ok(json!({
            "total": total,
            "offset": options.offset,
            "limit": options.limit,
            "messages": messages,
        }))
    })
}

// ---------------------------------------------------------------------------
// Single messages
// ---------------------------------------------------------------------------

/// True when the FETCH carries no UID or the expected one.
fn uid_matches_or_absent(fetch: &FetchResponse, uid: u32) -> bool {
    match fetch.get("UID") {
        None => true,
        Some(value) => value.as_number() == Some(u64::from(uid)),
    }
}

/// `_raw_message_data`: `(raw, flags, received_at)` without setting `\Seen`.
fn raw_message_data(
    conn: &mut ImapConnection,
    uid: u32,
) -> R<(Vec<u8>, Vec<String>, Option<String>)> {
    let response = checked(conn.uid(
        "FETCH",
        &[
            Arg::atom(uid.to_string()),
            Arg::atom("(UID FLAGS INTERNALDATE BODY.PEEK[])"),
        ],
    ))?;
    if !response.is_ok() {
        return Err(op(format!("The server could not fetch message UID {uid}")));
    }
    let mut raw = None;
    let mut flags = Vec::new();
    let mut received_at = None;
    for fetch in fetches(&response) {
        let Some(body) = fetch.first_body() else {
            continue;
        };
        if !uid_matches_or_absent(&fetch, uid) {
            continue;
        }
        raw = Some(body.to_vec());
        if let Some(found) = fetch.flags() {
            flags = found;
        }
        if let Some(internal) = fetch.internal_date() {
            received_at = internal_iso(&internal);
        }
    }
    match raw {
        Some(raw) => Ok((raw, flags, received_at)),
        None => Err(op(format!(
            "The server returned no data for message UID {uid}"
        ))),
    }
}

/// Raw RFC 822 bytes of one message.
pub fn fetch_raw(account: &MailAccount, folder: &str, uid: u32) -> Result<Vec<u8>> {
    if account.is_pop3() {
        return crate::pop3::fetch_raw(account, folder, uid);
    }
    with_connection(account, |conn| {
        select_info(conn, folder, true)?;
        Ok(raw_message_data(conn, uid)?.0)
    })
}

/// Message for classification, verified against `expected_uid_validity`
/// without changing read status.
pub fn fetch_classification_message(
    account: &MailAccount,
    folder: &str,
    uid: u32,
    expected_uid_validity: &str,
) -> Result<ClassificationMessage> {
    if account.is_pop3() {
        return crate::pop3::fetch_classification_message(
            account,
            folder,
            uid,
            expected_uid_validity,
        );
    }
    let Some(expected) = normalize_uid_validity(expected_uid_validity).filter(|_| uid >= 1) else {
        return Err(conflict(
            "Message identity is unavailable. Refresh the folder before classifying.",
        ));
    };
    with_connection(account, |conn| {
        let selected = select_info(conn, folder, true)?;
        let epoch = match selected.uid_validity {
            Some(epoch) if epoch == expected => epoch,
            _ => {
                return Err(
                    conflict("The mailbox changed. Refresh the folder before classifying.").into(),
                )
            }
        };
        let (raw, _, received_at) = raw_message_data(conn, uid)?;
        Ok(ClassificationMessage {
            headers: parsing::parse_message(&raw),
            raw,
            received_at,
            uid_validity: epoch,
        })
    })
}

/// `_sender_rule_scope`: the epoch and the first UID a new rule may affect.
fn sender_rule_scope(conn: &mut ImapConnection, selected: &Selected) -> R<SenderRuleScope> {
    let Some(epoch) = selected.uid_validity.clone() else {
        return Err(conflict(
            "Mailbox identity is unavailable. Refresh before editing sender rules.",
        )
        .into());
    };
    let first_uid = selected
        .uid_next
        .as_deref()
        .and_then(normalize_uid_validity)
        .and_then(|value| value.parse::<i64>().ok());
    // Validate even a supplied UIDNEXT against the entire mailbox, protecting
    // existing mail from buggy/stale server responses. This reads only UID
    // numbers, and includes arrivals during the SELECT-to-save interval.
    let tokens = search_uids(conn, "", &[], false, "all")?;
    let future_unavailable =
        || conflict("Future message identity is unavailable. Refresh before editing sender rules.");
    let mut numbers = Vec::with_capacity(tokens.len());
    for token in &tokens {
        let number = parse_python_int(token).ok_or_else(future_unavailable)?;
        numbers.push(number);
    }
    if numbers
        .iter()
        .any(|uid| !(1..=i128::from(MAX_UID)).contains(uid))
    {
        return Err(future_unavailable().into());
    }
    let highest = numbers.iter().copied().max().unwrap_or(0);
    let first_uid = i128::from(first_uid.filter(|v| *v != 0).unwrap_or(1)).max(highest + 1);
    if first_uid > i128::from(MAX_UID) {
        return Err(conflict(
            "The mailbox UID sequence is exhausted. Refresh before editing sender rules.",
        )
        .into());
    }
    Ok(SenderRuleScope {
        uid_validity: epoch,
        first_uid: first_uid as i64,
    })
}

/// `int(token)` for an ASCII search token (optional sign, digits,
/// underscores between digits are not expected from servers).
fn parse_python_int(token: &str) -> Option<i128> {
    let digits = token.strip_prefix('+').unwrap_or(token);
    if digits.len() > 30 {
        return None;
    }
    digits.parse::<i128>().ok()
}

/// Capture a future boundary for rule removal without downloading messages.
pub fn prepare_sender_rule_scope(account: &MailAccount, folder: &str) -> Result<SenderRuleScope> {
    if account.is_pop3() {
        return crate::pop3::prepare_sender_rule_scope(account, folder);
    }
    with_connection(account, |conn| {
        let selected = select_info(conn, folder, true)?;
        sender_rule_scope(conn, &selected)
    })
}

/// Verify the selected message and capture the folder's future cutoff.
/// Python `ValueError` (invalid sender) → `MailError::validation` (422).
pub fn prepare_sender_rule(
    account: &MailAccount,
    folder: &str,
    uid: i64,
    expected_uid_validity: &str,
) -> Result<PreparedSenderRule> {
    if account.is_pop3() {
        return crate::pop3::prepare_sender_rule(account, folder, uid, expected_uid_validity);
    }
    let Some(expected) =
        normalize_uid_validity(expected_uid_validity).filter(|_| (1..=MAX_UID).contains(&uid))
    else {
        return Err(conflict(
            "Message identity is unavailable. Refresh before saving a sender rule.",
        ));
    };
    with_connection(account, |conn| {
        let selected = select_info(conn, folder, true)?;
        let scope = sender_rule_scope(conn, &selected)?;
        if scope.uid_validity != expected {
            return Err(
                conflict("The mailbox changed. Refresh before saving a sender rule.").into(),
            );
        }
        let query = format!("(UID INTERNALDATE BODY.PEEK[HEADER.FIELDS {HEADER_FIELDS}])");
        let response = checked(conn.uid("FETCH", &[Arg::atom(uid.to_string()), Arg::atom(query)]))?;
        if !response.is_ok() {
            return Err(op(format!("The server could not fetch message UID {uid}")));
        }
        for fetch in fetches(&response) {
            let Some(body) = fetch.first_body() else {
                continue;
            };
            if fetch.get("UID").and_then(|value| value.as_number()) != Some(uid as u64) {
                continue;
            }
            let headers = parsing::parse_message(body);
            let Some(sender) = retention::sender_address(&headers) else {
                return Err(MailError::validation(
                    "Sender rules require exactly one valid From email address",
                )
                .into());
            };
            let received_at = fetch.internal_date().and_then(|value| internal_iso(&value));
            if scope.first_uid <= uid {
                return Err(
                    conflict("The mailbox changed. Refresh before saving a sender rule.").into(),
                );
            }
            return Ok(PreparedSenderRule {
                scope,
                sender,
                headers,
                received_at,
            });
        }
        Err(op(format!("Message UID {uid} is no longer available")))
    })
}

/// `fetch_message` → message view dict exactly as Python
/// (`header_view` keys plus `uid`, `folder`, `flags`, `seen`, `flagged`
/// and the retention metadata).
pub fn fetch_message(
    account: &MailAccount,
    folder: &str,
    uid: u32,
    mark_seen: bool,
    retention_store: Option<&RetentionStore>,
    category_expiration_days: Option<&BTreeMap<String, i64>>,
) -> Result<Value> {
    if account.is_pop3() {
        return crate::pop3::fetch_message(
            account,
            folder,
            uid,
            mark_seen,
            retention_store,
            category_expiration_days,
        );
    }
    with_connection(account, |conn| {
        let selected = select_info(conn, folder, !mark_seen)?;
        let uid_validity = selected.uid_validity;
        let (raw, mut flags, received_at) = raw_message_data(conn, uid)?;
        if mark_seen && !flags.iter().any(|flag| flag.to_lowercase() == "\\seen") {
            // The status is ignored like Python; only BAD/socket errors abort.
            checked(conn.uid(
                "STORE",
                &[
                    Arg::atom(uid.to_string()),
                    Arg::atom("+FLAGS"),
                    Arg::atom("(\\Seen)"),
                ],
            ))?;
            flags.push("\\Seen".to_string());
        }
        let msg = parsing::parse_message(&raw);
        let mut view = parsing::header_view(&msg).into_map();
        let metadata = match retention_store {
            Some(store) => store.metadata(
                account,
                folder,
                i64::from(uid),
                uid_validity.as_deref(),
                &msg,
                received_at.as_deref(),
                category_expiration_days,
            )?,
            None => retention::retention_metadata(
                &msg,
                received_at.as_deref(),
                category_expiration_days,
                &MetadataOptions {
                    uid_validity: uid_validity.as_deref(),
                    ..MetadataOptions::default()
                },
            )?,
        };
        let lowered: Vec<String> = flags.iter().map(|f| f.to_lowercase()).collect();
        view.insert("uid".into(), json!(uid));
        view.insert("folder".into(), json!(folder));
        view.insert("flags".into(), json!(flags));
        view.insert("seen".into(), json!(lowered.iter().any(|f| f == "\\seen")));
        view.insert(
            "flagged".into(),
            json!(lowered.iter().any(|f| f == "\\flagged")),
        );
        view.extend(metadata.into_map());
        Ok(Value::Object(view))
    })
}

/// `update_retention` → `{"uid", "folder", **summary}` exactly as Python.
#[allow(clippy::too_many_arguments)]
pub fn update_retention(
    account: &MailAccount,
    folder: &str,
    uid: u32,
    store: &RetentionStore,
    policies: &BTreeMap<String, i64>,
    category: Patch<String>,
    expiration_days: Patch<i64>,
    expected_uid_validity: Option<&str>,
) -> Result<Value> {
    if account.is_pop3() {
        return crate::pop3::update_retention(
            account,
            folder,
            uid,
            store,
            policies,
            category,
            expiration_days,
            expected_uid_validity,
        );
    }
    let Some(expected) = expected_uid_validity.and_then(normalize_uid_validity) else {
        return Err(conflict(
            "Message identity is unavailable. Refresh the folder before editing retention.",
        ));
    };
    with_connection(account, move |conn| {
        let selected = select_info(conn, folder, true)?;
        let uid_validity = match selected.uid_validity {
            Some(epoch) if epoch == expected => epoch,
            _ => {
                return Err(conflict(
                    "The mailbox changed. Refresh the folder before editing retention.",
                )
                .into())
            }
        };
        let ctx = SummaryContext {
            account: Some(account),
            folder,
            uid_validity: Some(&uid_validity),
            retention_store: Some(store),
            category_expiration_days: Some(policies),
            sender_rules: None,
            sender_rule_events: None,
        };
        let missing = || op(format!("Message UID {uid} is no longer available"));
        if !fetch_summaries(conn, &[uid], &ctx)?
            .iter()
            .any(|summary| summary.uid == uid)
        {
            return Err(missing());
        }
        store.update(
            account,
            folder,
            i64::from(uid),
            &uid_validity,
            category,
            expiration_days,
        )?;
        // Re-fetch only the same headers to reuse the exact display contract.
        let summary = fetch_summaries(conn, &[uid], &ctx)?
            .into_iter()
            .find(|summary| summary.uid == uid)
            .ok_or_else(missing)?;
        let mut result = Map::new();
        result.insert("uid".into(), json!(uid));
        result.insert("folder".into(), json!(folder));
        result.extend(summary.fields);
        Ok(Value::Object(result))
    })
}

// ---------------------------------------------------------------------------
// Mutations
// ---------------------------------------------------------------------------

/// `set_flags` → `{"uid","flags","seen","flagged"}`.
pub fn set_flags(
    account: &MailAccount,
    folder: &str,
    uid: u32,
    seen: Option<bool>,
    flagged: Option<bool>,
) -> Result<Value> {
    if account.is_pop3() {
        return Err(crate::pop3::imap_only());
    }
    with_connection(account, |conn| {
        select_info(conn, folder, false)?;
        for (value, flag) in [(seen, "\\Seen"), (flagged, "\\Flagged")] {
            let Some(value) = value else {
                continue;
            };
            let mode = if value { "+FLAGS" } else { "-FLAGS" };
            let response = checked(conn.uid(
                "STORE",
                &[
                    Arg::atom(uid.to_string()),
                    Arg::atom(mode),
                    Arg::atom(format!("({flag})")),
                ],
            ))?;
            if !response.is_ok() {
                return Err(op(format!("The server could not update flag {flag}")));
            }
        }
        // Like Python, the FETCH status is not checked: no data → no flags.
        let response =
            checked(conn.uid("FETCH", &[Arg::atom(uid.to_string()), Arg::atom("(FLAGS)")]))?;
        let mut flags: Vec<String> = Vec::new();
        for fetch in fetches(&response) {
            if !uid_matches_or_absent(&fetch, uid) {
                continue;
            }
            if let Some(found) = fetch.flags() {
                flags = found;
            }
        }
        let lowered: Vec<String> = flags.iter().map(|f| f.to_lowercase()).collect();
        Ok(json!({
            "uid": uid,
            "flags": flags,
            "seen": lowered.iter().any(|f| f == "\\seen"),
            "flagged": lowered.iter().any(|f| f == "\\flagged"),
        }))
    })
}

/// Move to `trash_folder` (or delete permanently when empty).
pub fn delete_message(
    account: &MailAccount,
    folder: &str,
    uid: u32,
    trash_folder: &str,
    expected_uid_validity: Option<&str>,
) -> Result<()> {
    delete_messages(account, folder, &[uid], trash_folder, expected_uid_validity).map(|_| ())
}

#[allow(clippy::too_many_arguments)]
fn delete_messages_inner(
    conn: &mut ImapConnection,
    folder: &str,
    unique: &[u32],
    trash_folder: &str,
    expected: Option<&str>,
    copy_warning: &mut String,
) -> R<()> {
    let uid_set = uid_set(unique);
    // Refresh after authentication: pre-login capabilities can differ.
    let response = checked(conn.command("CAPABILITY", &[]))?;
    if !response.is_ok() {
        return Err(op("The server could not report its mail capabilities"));
    }
    let capabilities = capability_set(&response);
    // IMAP4rev2 includes MOVE and UIDPLUS in the base protocol.
    let rev2 = capabilities.contains("IMAP4REV2");
    let can_move = capabilities.contains("MOVE") || rev2;
    let can_uid_expunge = capabilities.contains("UIDPLUS") || rev2;
    let move_to_trash = !trash_folder.is_empty() && trash_folder != folder;
    if !can_uid_expunge && !(move_to_trash && can_move) {
        return Err(op(
            "This server does not support safely deleting only the selected messages \
             (MOVE or UIDPLUS is required)",
        ));
    }
    let selected = select_info(conn, folder, false)?;
    if let Some(expected) = expected {
        if selected.uid_validity.as_deref() != Some(expected) {
            return Err(conflict(
                "The mailbox changed. Refresh the folder before deleting messages.",
            )
            .into());
        }
    }
    let trash_repr = python_repr_str(trash_folder);
    if move_to_trash && can_move {
        let response = checked(conn.uid(
            "MOVE",
            &[Arg::atom(uid_set.as_str()), Arg::quoted(trash_folder)],
        ))?;
        if !response.is_ok() {
            return Err(op(format!(
                "The server could not move all selected messages to {trash_repr}. \
                 Refresh the folder before retrying."
            )));
        }
        return Ok(());
    }
    if move_to_trash {
        let response = checked(conn.uid(
            "COPY",
            &[Arg::atom(uid_set.as_str()), Arg::quoted(trash_folder)],
        ))?;
        if !response.is_ok() {
            return Err(op(format!(
                "The server could not copy the selected messages to {trash_repr}"
            )));
        }
        *copy_warning = format!(
            "The messages were copied to {trash_repr}, but removing them from \
             the original folder failed. Check {trash_folder} before retrying."
        );
    }
    let or_warning = |message: &str| {
        if copy_warning.is_empty() {
            message.to_string()
        } else {
            copy_warning.clone()
        }
    };
    let response = checked(conn.uid(
        "STORE",
        &[
            Arg::atom(uid_set.as_str()),
            Arg::atom("+FLAGS.SILENT"),
            Arg::atom("(\\Deleted)"),
        ],
    ))?;
    if !response.is_ok() {
        return Err(op(or_warning(
            "The server could not mark the selected messages deleted",
        )));
    }
    let response = checked(conn.uid("EXPUNGE", &[Arg::atom(uid_set.as_str())]))?;
    if !response.is_ok() {
        return Err(op(or_warning(
            "The server could not remove all selected messages. Refresh the folder before retrying.",
        )));
    }
    Ok(())
}

/// Bulk delete; returns the UIDs that were deleted (deduplicated, in the
/// given order).
///
/// Prefer MOVE to a distinct trash folder. Without MOVE, COPY followed by
/// UID EXPUNGE is safe when UIDPLUS is available. Mailbox-wide EXPUNGE could
/// erase messages another client marked deleted, so it is never a fallback.
/// A failed command can leave a partially changed mailbox; callers must
/// reload rather than treating any error as success.
pub fn delete_messages(
    account: &MailAccount,
    folder: &str,
    uids: &[u32],
    trash_folder: &str,
    expected_uid_validity: Option<&str>,
) -> Result<Vec<u32>> {
    if account.is_pop3() {
        return Err(crate::pop3::imap_only());
    }
    if uids.is_empty() || uids.len() > 500 || uids.contains(&0) {
        return Err(MailError::operation(
            "Select between 1 and 500 valid message UIDs",
        ));
    }
    let mut unique: Vec<u32> = Vec::with_capacity(uids.len());
    for uid in uids {
        if !unique.contains(uid) {
            unique.push(*uid);
        }
    }
    let expected = expected_uid_validity.and_then(normalize_uid_validity);
    if expected_uid_validity.is_some() && expected.is_none() {
        return Err(conflict(
            "Message identity is unavailable. Refresh the folder before deleting.",
        ));
    }
    let mut conn = connect(account)?;
    let mut copy_warning = String::new();
    let result = delete_messages_inner(
        &mut conn,
        folder,
        &unique,
        trash_folder,
        expected.as_deref(),
        &mut copy_warning,
    );
    logout(conn);
    match result {
        Ok(()) => Ok(unique),
        Err(Fail::Mail(error)) => Err(error),
        Err(Fail::Proto(_)) => Err(MailError::operation(if copy_warning.is_empty() {
            "The server connection failed while deleting messages. Refresh the folder before retrying."
                .to_string()
        } else {
            copy_warning
        })),
    }
}

/// One attachment's content. Missing → `MailError::Operation("Attachment {index} was not found on message UID {uid}")`.
pub fn fetch_attachment(
    account: &MailAccount,
    folder: &str,
    uid: u32,
    index: usize,
) -> Result<AttachmentPayload> {
    if account.is_pop3() {
        return crate::pop3::fetch_attachment(account, folder, uid, index);
    }
    let raw = with_connection(account, |conn| {
        select_info(conn, folder, true)?;
        Ok(raw_message_data(conn, uid)?.0)
    })?;
    parsing::attachment_payload(&parsing::parse_message(&raw), index).ok_or_else(|| {
        MailError::operation(format!(
            "Attachment {index} was not found on message UID {uid}"
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_block_splits_at_first_blank_line() {
        assert_eq!(header_block(b"A: 1\r\nB: 2\r\n\r\nbody"), b"A: 1\r\nB: 2");
        assert_eq!(header_block(b"A: 1\n\nbody\n\nmore"), b"A: 1");
        assert_eq!(header_block(b"A: 1\r\n\nbody"), b"A: 1");
        assert_eq!(header_block(b"A: 1\n\r\nbody"), b"A: 1");
        assert_eq!(header_block(b"A: 1"), b"A: 1");
    }

    #[test]
    fn internal_dates_use_python_isoformat() {
        assert_eq!(
            internal_iso("17-Jul-1996 02:44:25 -0700").as_deref(),
            Some("1996-07-17T02:44:25-07:00")
        );
        assert_eq!(internal_iso(""), None);
        assert_eq!(internal_iso("garbage"), None);
    }

    #[test]
    fn python_int_parsing_of_search_tokens() {
        assert_eq!(parse_python_int("42"), Some(42));
        assert_eq!(parse_python_int("-1"), Some(-1));
        assert_eq!(parse_python_int("abc"), None);
    }
}
