//! POP3 compatibility mode (new; the original app was IMAP-only).
//!
//! Scope agreed with the user: **compatibility level** — unlock, list and
//! read the INBOX. POP3 has no folders, flags, stable integer UIDs or server
//! trash, so those operations answer [`imap_only`] (HTTP 400).
//!
//! # Fixed public contract (Phase 2)
//!
//! [`crate::imap`]'s public read functions delegate here when
//! `account.is_pop3()`; signatures mirror them exactly. Design rules:
//!
//! * The only folder is `"INBOX"`; any other folder → `MailError::Operation`
//!   ("The server would not open folder '…'"), like IMAP.
//! * UIDs are 1-based POP3 message numbers for the current maildrop.
//! * `uid_validity` is a synthetic positive 32-bit decimal derived from a
//!   stable hash of the full UIDL list (falls back to sizes when UIDL is not
//!   supported), so it changes whenever the maildrop changes and stale
//!   message numbers are rejected with the same 409/422 semantics as IMAP.
//! * No read state on the server: every message is reported unseen with no
//!   flags; `mark_seen` is a no-op; `read_status="read"` matches nothing.
//! * Messages are listed newest first (highest number first). Summaries use
//!   `TOP n 0`; search/sender-domain/category filtering matches IMAP output
//!   semantics as closely as practical (documented per function).
//!
//! # Implementation notes
//!
//! Every call opens one short-lived session (connect → `USER`/`PASS` →
//! `LIST` + `UIDL` → work → `QUIT`) with `account.imap_security()` on
//! `incoming_server:incoming_port` (`ssl` = implicit TLS, `starttls` =
//! `STLS`, `none` = plain). The maildrop is never modified: no `DELE` is
//! ever sent.
//!
//! The JSON produced by [`list_messages`], [`fetch_message`] and
//! [`update_retention`] has exactly the keys of `imap_client.py`'s
//! `_fetch_summaries` / `fetch_message` / `update_retention` dicts, with the
//! retention fields computed by the same [`crate::retention`] code.
//!
//! **Arrival time.** POP3 has no INTERNALDATE. The POP3 analogue used for
//! `internal_date` and `received_at` (and therefore for expiry and for
//! sender rules across epochs) is the date of the topmost parseable
//! `Received:` header — the final delivery hop — falling back to the `Date:`
//! header, else `None` (expiry then stays unknown, as for IMAP messages
//! without INTERNALDATE).
//!
//! **Epoch consequences.** Because the synthetic `uid_validity` changes
//! whenever a message arrives or is removed by another client, per-message
//! manual/AI retention choices saved under an older epoch stop applying
//! after the maildrop changes (IMAP keeps them until UIDVALIDITY changes).
//! Sender rules keep working: across epochs they compare arrival times, as
//! the retention module already does after an IMAP UIDVALIDITY reset.
//!
//! **Response cap.** Every session caps one multi-line response (`RETR`,
//! `TOP`, `LIST`, `UIDL`) at [`MAX_RESPONSE_BYTES`] (100 MiB) instead of
//! `mail_proto`'s 256 MiB default, so a hostile server cannot make the
//! backend buffer an arbitrarily large reply. A larger reply ends the
//! session with a connection error.
//!
//! **Errors.** A socket/protocol failure in the middle of an operation,
//! which Python let escape as an unhandled `OSError` (HTTP 500), is reported
//! as `MailError::Operation` (502) with the message the IMAP code uses for
//! the same step.

use std::cmp::Reverse;
use std::collections::{BTreeMap, HashMap};

use serde_json::{json, Map, Value};

use crate::error::{MailError, Result};
use crate::imap::{
    ClassificationMessage, ListMessagesOptions, PreparedSenderRule, SenderRuleScope,
};
use crate::model::is_category;
use crate::parsing::{self, AttachmentPayload, ParsedMessage};
use crate::retention::{
    self, MetadataOptions, Patch, RetentionOverride, RetentionStore, SenderRule,
};
use crate::sessions::MailAccount;

/// Largest multi-line POP3 response accepted (100 MiB).
///
/// Must stay at least as large as the biggest message the app handles (the
/// trash archive's [`crate::trash::MAX_MESSAGE_BYTES`], 64 MiB), checked at
/// compile time below; a `RETR` reply is the message plus dot-stuffing.
pub const MAX_RESPONSE_BYTES: usize = 100 * 1024 * 1024;

const _: () = assert!(MAX_RESPONSE_BYTES as u64 >= crate::trash::MAX_MESSAGE_BYTES);

#[path = "pop3_parts/domains.rs"]
mod domains;
#[path = "pop3_parts/session.rs"]
mod session;
#[cfg(test)]
#[path = "pop3_parts/tests.rs"]
mod tests;

use session::{Maildrop, Session, MAX_UID};

/// Detail of the 400 answered for IMAP-only operations on POP3 accounts.
pub const IMAP_ONLY_MESSAGE: &str =
    "This operation requires an IMAP account. POP3 accounts can only list and read the INBOX.";

/// `_DOMAIN_FETCH_BATCH_SIZE`: retention filters read headers in batches.
const BATCH_SIZE: usize = 200;

/// 400 error for IMAP-only operations on a POP3 account.
pub fn imap_only() -> MailError {
    MailError::bad_request(IMAP_ONLY_MESSAGE)
}

/// Prove the credentials work; used when unlocking a session.
///
/// IMAP selects INBOX; POP3 sends `STAT` after logging in. A `STAT` failure
/// answers "The server would not open the INBOX folder" like a failed
/// SELECT.
pub fn verify_login(account: &MailAccount) -> Result<()> {
    let mut session = session::open(account)?;
    session.stat("The server would not open the INBOX folder")?;
    Ok(())
}

/// `list_folders`: the single selectable INBOX, shaped like
/// `imap_client._parse_folders` output
/// (`{"name","delimiter","flags","special","selectable"}`).
///
/// Connects and sends `STAT` so credential and server errors surface as for
/// IMAP's `LIST`; a `STAT` failure answers "The server did not return a
/// folder list".
pub fn list_folders(account: &MailAccount) -> Result<Vec<Value>> {
    let mut session = session::open(account)?;
    session.stat("The server did not return a folder list")?;
    Ok(vec![json!({
        "name": "INBOX",
        "delimiter": "",
        "flags": [],
        "special": "inbox",
        "selectable": true,
    })])
}

/// `list_messages` → `{"total","offset","limit","messages":[...]}`, newest
/// (highest message number) first.
///
/// Filters apply before counting and paging, in the IMAP order:
///
/// * `query` (IMAP `TEXT` search, done by the server): every message is
///   downloaded with `RETR` and matched case-insensitively (whitespace
///   collapsed) against its raw header block, its decoded header values and
///   its text/HTML bodies. Only done when a query is given.
/// * `read_status`: `"unread"` matches every message, `"read"` none.
/// * `sender_domains` (validated again like Python's `list_messages`):
///   From addresses of the `TOP n 0` headers, exactly as
///   `_filter_sender_domains`; `has_unicode_input` only affected the IMAP
///   server-side narrowing and is not needed.
/// * `category` / `expired_only`: full summaries of every candidate, in
///   batches of 200 for the retention reads, like IMAP.
pub fn list_messages(
    account: &MailAccount,
    folder: &str,
    options: &ListMessagesOptions<'_>,
) -> Result<Value> {
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
    let domains =
        domains::normalize_sender_domains(options.sender_domains).map_err(MailError::validation)?;
    let mut session = session::open(account)?;
    let maildrop = session.open(folder)?;
    let mut numbers = search(&mut session, &maildrop, options.query, options.read_status)?;
    if !domains.is_empty() {
        numbers = filter_sender_domains(&mut session, &numbers, &domains)?;
    }
    let context = SummaryContext::new(
        account,
        folder,
        &maildrop.uid_validity,
        options.retention_store,
        options.category_expiration_days,
    )?;
    let mut filtered: Option<HashMap<u32, Value>> = None;
    if options.category.is_some() || options.expired_only {
        let mut matches = HashMap::new();
        for batch in numbers.chunks(BATCH_SIZE) {
            for summary in context.summaries(&mut session, &maildrop, batch)? {
                if let Some(category) = options.category {
                    if summary["category"].as_str() != Some(category) {
                        continue;
                    }
                }
                if options.expired_only && summary["expired"] != Value::Bool(true) {
                    continue;
                }
                matches.insert(summary_uid(&summary), summary);
            }
        }
        numbers.retain(|number| matches.contains_key(number));
        filtered = Some(matches);
    }
    let total = numbers.len();
    let window: Vec<u32> = numbers
        .iter()
        .rev()
        .skip(options.offset)
        .take(options.limit)
        .copied()
        .collect();
    let mut messages = match filtered {
        None => context.summaries(&mut session, &maildrop, &window)?,
        Some(mut matches) => window
            .iter()
            .filter_map(|number| matches.remove(number))
            .collect(),
    };
    messages.sort_by_key(|message| Reverse(summary_uid(message)));
    Ok(json!({
        "total": total,
        "offset": options.offset,
        "limit": options.limit,
        "messages": messages,
    }))
}

/// Raw RFC 822 bytes of one message (`RETR`, CRLF line endings).
///
/// Unlike IMAP UIDs, message numbers are only stable while the maildrop is
/// unchanged; this call has no epoch argument, so a stale number reads
/// whatever message now has it (unavoidable with this signature).
pub fn fetch_raw(account: &MailAccount, folder: &str, uid: u32) -> Result<Vec<u8>> {
    let mut session = session::open(account)?;
    let maildrop = session.open(folder)?;
    raw_message(&mut session, &maildrop, uid)
}

/// Message for classification, verified against `expected_uid_validity`
/// (the synthetic epoch) without changing anything on the server.
pub fn fetch_classification_message(
    account: &MailAccount,
    folder: &str,
    uid: u32,
    expected_uid_validity: &str,
) -> Result<ClassificationMessage> {
    let expected = retention::normalize_uid_validity(expected_uid_validity);
    if expected.is_none() || uid < 1 {
        return Err(MailError::RetentionConflict(
            "Message identity is unavailable. Refresh the folder before classifying.".into(),
        ));
    }
    let mut session = session::open(account)?;
    let maildrop = session.open(folder)?;
    if Some(&maildrop.uid_validity) != expected.as_ref() {
        return Err(MailError::RetentionConflict(
            "The mailbox changed. Refresh the folder before classifying.".into(),
        ));
    }
    let raw = raw_message(&mut session, &maildrop, uid)?;
    let headers = parsing::parse_message(&raw);
    let received_at = received_at(&headers);
    Ok(ClassificationMessage {
        raw,
        headers,
        received_at,
        uid_validity: maildrop.uid_validity,
    })
}

/// `_sender_rule_scope`: the current epoch and the first message number a
/// future arrival would receive (`max(numbers) + 1`; POP3 has no UIDNEXT).
fn sender_rule_scope(maildrop: &Maildrop) -> Result<SenderRuleScope> {
    let first_uid = maildrop.next_number().max(1);
    if first_uid > MAX_UID {
        return Err(MailError::RetentionConflict(
            "The mailbox UID sequence is exhausted. Refresh before editing sender rules.".into(),
        ));
    }
    Ok(SenderRuleScope {
        uid_validity: maildrop.uid_validity.clone(),
        first_uid,
    })
}

/// Capture a future boundary for rule removal without downloading messages
/// (only `LIST`/`UIDL`).
pub fn prepare_sender_rule_scope(account: &MailAccount, folder: &str) -> Result<SenderRuleScope> {
    let mut session = session::open(account)?;
    let maildrop = session.open(folder)?;
    sender_rule_scope(&maildrop)
}

/// Verify the selected message and capture the folder's future cutoff,
/// reading only its headers (`TOP n 0`).
/// Python `ValueError` (invalid sender) → `MailError::validation` (422).
pub fn prepare_sender_rule(
    account: &MailAccount,
    folder: &str,
    uid: i64,
    expected_uid_validity: &str,
) -> Result<PreparedSenderRule> {
    let expected = retention::normalize_uid_validity(expected_uid_validity);
    if expected.is_none() || !(1..=MAX_UID).contains(&uid) {
        return Err(MailError::RetentionConflict(
            "Message identity is unavailable. Refresh before saving a sender rule.".into(),
        ));
    }
    let mut session = session::open(account)?;
    let maildrop = session.open(folder)?;
    let scope = sender_rule_scope(&maildrop)?;
    if Some(&scope.uid_validity) != expected.as_ref() {
        return Err(MailError::RetentionConflict(
            "The mailbox changed. Refresh before saving a sender rule.".into(),
        ));
    }
    let Some(number) = maildrop.size_of(uid).and_then(|_| u32::try_from(uid).ok()) else {
        return Err(MailError::operation(format!(
            "Message UID {uid} is no longer available"
        )));
    };
    let raw = session.headers(number).map_err(|_| {
        MailError::operation(format!("The server could not fetch message UID {uid}"))
    })?;
    let headers = parsing::parse_message(&raw);
    let Some(sender) = retention::sender_address(&headers) else {
        return Err(MailError::validation(
            "Sender rules require exactly one valid From email address",
        ));
    };
    let received_at = received_at(&headers);
    if scope.first_uid <= uid {
        return Err(MailError::RetentionConflict(
            "The mailbox changed. Refresh before saving a sender rule.".into(),
        ));
    }
    Ok(PreparedSenderRule {
        scope,
        sender,
        headers,
        received_at,
    })
}

/// `fetch_message` → message view dict exactly as Python (`header_view`
/// fields plus `uid`, `folder`, `flags`, `seen`, `flagged` and the retention
/// metadata). `mark_seen` is accepted and ignored: POP3 has no flags, so the
/// message stays `seen: false`.
pub fn fetch_message(
    account: &MailAccount,
    folder: &str,
    uid: u32,
    mark_seen: bool,
    retention_store: Option<&RetentionStore>,
    category_expiration_days: Option<&BTreeMap<String, i64>>,
) -> Result<Value> {
    let _ = mark_seen;
    let mut session = session::open(account)?;
    let maildrop = session.open(folder)?;
    let raw = raw_message(&mut session, &maildrop, uid)?;
    drop(session);
    let message = parsing::parse_message(&raw);
    let received_at = received_at(&message);
    let epoch = maildrop.uid_validity.as_str();
    let metadata = match retention_store {
        Some(store) => store.metadata(
            account,
            folder,
            i64::from(uid),
            Some(epoch),
            &message,
            received_at.as_deref(),
            category_expiration_days,
        )?,
        None => retention::retention_metadata(
            &message,
            received_at.as_deref(),
            category_expiration_days,
            &MetadataOptions {
                uid_validity: Some(epoch),
                ..MetadataOptions::default()
            },
        )?,
    };
    let mut view = parsing::header_view(&message).into_map();
    view.insert("uid".into(), json!(uid));
    view.insert("folder".into(), json!(folder));
    view.insert("flags".into(), json!([]));
    view.insert("seen".into(), json!(false));
    view.insert("flagged".into(), json!(false));
    view.extend(metadata.into_map());
    Ok(Value::Object(view))
}

/// `update_retention` → `{"uid", "folder", **summary}` exactly as Python:
/// verify the epoch, check the message still exists, save the local
/// override, then answer the recomputed summary. The headers are read once
/// (`TOP n 0`) and reused for the second summary, whose retention fields
/// are read fresh from the store.
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
    let Some(expected) = expected_uid_validity.and_then(retention::normalize_uid_validity) else {
        return Err(MailError::RetentionConflict(
            "Message identity is unavailable. Refresh the folder before editing retention.".into(),
        ));
    };
    let mut session = session::open(account)?;
    let maildrop = session.open(folder)?;
    if maildrop.uid_validity != expected {
        return Err(MailError::RetentionConflict(
            "The mailbox changed. Refresh the folder before editing retention.".into(),
        ));
    }
    let epoch = maildrop.uid_validity.as_str();
    let missing = || MailError::operation(format!("Message UID {uid} is no longer available"));
    let summary_of = |session: &mut Session| -> Result<Value> {
        let context = SummaryContext::new(account, folder, epoch, Some(store), Some(policies))?;
        context
            .summaries(session, &maildrop, &[uid])?
            .into_iter()
            .find(|summary| summary_uid(summary) == uid)
            .ok_or_else(missing)
    };
    summary_of(&mut session)?;
    store.update(
        account,
        folder,
        i64::from(uid),
        epoch,
        category,
        expiration_days,
    )?;
    let summary = summary_of(&mut session)?;
    let mut result = Map::new();
    result.insert("uid".into(), json!(uid));
    result.insert("folder".into(), json!(folder));
    if let Value::Object(fields) = summary {
        result.extend(fields);
    }
    Ok(Value::Object(result))
}

/// One attachment's content. Missing → `MailError::Operation("Attachment {index} was not found on message UID {uid}")`.
pub fn fetch_attachment(
    account: &MailAccount,
    folder: &str,
    uid: u32,
    index: usize,
) -> Result<AttachmentPayload> {
    let raw = {
        let mut session = session::open(account)?;
        let maildrop = session.open(folder)?;
        raw_message(&mut session, &maildrop, uid)?
    };
    parsing::attachment_payload(&parsing::parse_message(&raw), index).ok_or_else(|| {
        MailError::operation(format!(
            "Attachment {index} was not found on message UID {uid}"
        ))
    })
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// `_raw_message_data` for POP3: a number outside the maildrop is "returned
/// no data" (IMAP's answer for an unknown UID); a refused `RETR` is "could
/// not fetch".
fn raw_message(session: &mut Session, maildrop: &Maildrop, uid: u32) -> Result<Vec<u8>> {
    if maildrop.size_of(i64::from(uid)).is_none() {
        return Err(MailError::operation(format!(
            "The server returned no data for message UID {uid}"
        )));
    }
    session
        .retr(uid)
        .map_err(|_| MailError::operation(format!("The server could not fetch message UID {uid}")))
}

/// The POP3 stand-in for INTERNALDATE (see the module docs): the date of
/// the topmost parseable `Received:` header, else the `Date:` header.
fn received_at(headers: &ParsedMessage) -> Option<String> {
    headers
        .get_all("Received")
        .iter()
        .filter_map(|value| value.rsplit_once(';'))
        .find_map(|(_, date)| parsing::parsedate_to_datetime(parsing::py_strip(date)))
        .map(|parsed| parsed.isoformat())
        .or_else(|| parsing::parse_date(headers.get("Date").as_deref()))
}

fn summary_uid(summary: &Value) -> u32 {
    summary["uid"]
        .as_u64()
        .and_then(|uid| u32::try_from(uid).ok())
        .unwrap_or(0)
}

/// `_search_uids` for POP3 (see [`list_messages`]). Returns ascending
/// message numbers.
fn search(
    session: &mut Session,
    maildrop: &Maildrop,
    query: &str,
    read_status: &str,
) -> Result<Vec<u32>> {
    if read_status == "read" {
        // Nothing is ever \Seen on a POP3 maildrop.
        return Ok(Vec::new());
    }
    let numbers = maildrop.numbers();
    // IMAP sent `TEXT "<query with quotes blanked>"`; an empty quoted string
    // matches every message.
    let needle = parsing::collapse_whitespace(&query.replace('"', " ")).to_lowercase();
    if query.is_empty() || needle.is_empty() {
        return Ok(numbers);
    }
    let mut matches = Vec::new();
    for number in numbers {
        let raw = session
            .retr(number)
            .map_err(|_| MailError::operation("The server could not search this folder"))?;
        if message_matches(&raw, &needle) {
            matches.push(number);
        }
    }
    Ok(matches)
}

/// Case-insensitive substring match of a full message (IMAP `TEXT`).
fn message_matches(raw: &[u8], needle: &str) -> bool {
    let message = parsing::parse_message(raw);
    let mut haystack = String::from_utf8_lossy(&session::header_block(raw)).into_owned();
    for header in message.raw_headers() {
        let value: String = header
            .value_lossy()
            .chars()
            .filter(|c| *c != '\r' && *c != '\n')
            .collect();
        haystack.push('\n');
        haystack.push_str(&header.name);
        haystack.push_str(": ");
        haystack.push_str(&parsing::decode_value(Some(&value)));
    }
    let (text, html) = parsing::extract_bodies(&message);
    haystack.push('\n');
    haystack.push_str(&text);
    haystack.push('\n');
    haystack.push_str(&parsing::strip_tags(&html));
    parsing::collapse_whitespace(&haystack)
        .to_lowercase()
        .contains(needle)
}

/// `_filter_sender_domains`: keep numbers whose From headers match.
fn filter_sender_domains(
    session: &mut Session,
    numbers: &[u32],
    domains: &[String],
) -> Result<Vec<u32>> {
    let mut matches = Vec::new();
    for &number in numbers {
        let raw = session.headers(number).map_err(|_| {
            MailError::operation("The server could not filter messages by sender domain")
        })?;
        if domains::from_matches(&parsing::parse_message(&raw), domains) {
            matches.push(number);
        }
    }
    Ok(matches)
}

/// Shared inputs of `_fetch_summaries` (sender rules are loaded once per
/// listing, like `list_messages` does).
struct SummaryContext<'a> {
    account: &'a MailAccount,
    folder: &'a str,
    uid_validity: &'a str,
    store: Option<&'a RetentionStore>,
    policies: Option<&'a BTreeMap<String, i64>>,
    sender_rules: HashMap<String, SenderRule>,
    sender_rule_events: HashMap<String, Vec<SenderRule>>,
}

impl<'a> SummaryContext<'a> {
    fn new(
        account: &'a MailAccount,
        folder: &'a str,
        uid_validity: &'a str,
        store: Option<&'a RetentionStore>,
        policies: Option<&'a BTreeMap<String, i64>>,
    ) -> Result<Self> {
        let (sender_rules, sender_rule_events) = match store {
            Some(store) => (
                store.get_sender_rules_for_folder(account, folder)?,
                store.get_sender_rule_events_for_folder(account, folder)?,
            ),
            None => (HashMap::new(), HashMap::new()),
        };
        Ok(Self {
            account,
            folder,
            uid_validity,
            store,
            policies,
            sender_rules,
            sender_rule_events,
        })
    }

    /// `_fetch_summaries(conn, uids, ...)`: header summaries of `numbers`
    /// (all known to exist in `maildrop`).
    fn summaries(
        &self,
        session: &mut Session,
        maildrop: &Maildrop,
        numbers: &[u32],
    ) -> Result<Vec<Value>> {
        if numbers.is_empty() {
            return Ok(Vec::new());
        }
        let mut fetched = Vec::with_capacity(numbers.len());
        for &number in numbers {
            let Some(size) = maildrop.size_of(i64::from(number)) else {
                // IMAP skips UIDs the server does not return.
                continue;
            };
            let raw = session.headers(number).map_err(|_| {
                MailError::operation("The server could not list messages in this folder")
            })?;
            fetched.push((number, size, raw));
        }
        let overrides = match self.store {
            Some(store) => {
                let uids: Vec<i64> = numbers.iter().map(|n| i64::from(*n)).collect();
                store.get_many(self.account, self.folder, &uids, Some(self.uid_validity))?
            }
            None => HashMap::new(),
        };
        fetched
            .into_iter()
            .map(|(number, size, raw)| {
                let message = parsing::parse_message(&raw);
                self.summary(number, size, &message, overrides.get(&i64::from(number)))
            })
            .collect()
    }

    fn summary(
        &self,
        uid: u32,
        size: u64,
        message: &ParsedMessage,
        overrides: Option<&RetentionOverride>,
    ) -> Result<Value> {
        let received_at = received_at(message);
        let sender = retention::sender_address(message);
        let sender_rule = sender
            .as_ref()
            .and_then(|sender| self.sender_rules.get(sender));
        let events: &[SenderRule] = sender
            .as_ref()
            .and_then(|sender| self.sender_rule_events.get(sender))
            .map_or(&[], Vec::as_slice);
        let metadata = retention::retention_metadata(
            message,
            received_at.as_deref(),
            self.policies,
            &MetadataOptions {
                overrides,
                uid_validity: Some(self.uid_validity),
                now: None,
                sender_rule,
                uid: Some(i64::from(uid)),
                sender_rule_events: Some(events),
            },
        )?;
        let date =
            parsing::parse_date(message.get("Date").as_deref()).or_else(|| received_at.clone());
        let mut summary = Map::new();
        summary.insert("uid".into(), json!(uid));
        summary.insert("flags".into(), json!([]));
        summary.insert("seen".into(), json!(false));
        summary.insert("flagged".into(), json!(false));
        summary.insert("answered".into(), json!(false));
        summary.insert("size".into(), json!(size));
        summary.insert("internal_date".into(), json!(received_at));
        summary.insert(
            "subject".into(),
            json!(parsing::decode_value(message.get("Subject").as_deref())),
        );
        summary.insert(
            "from".into(),
            json!(parsing::address_text(message.get("From").as_deref())),
        );
        summary.insert(
            "to".into(),
            json!(parsing::address_text(message.get("To").as_deref())),
        );
        summary.insert("date".into(), json!(date));
        summary.extend(metadata.into_map());
        Ok(Value::Object(summary))
    }
}
