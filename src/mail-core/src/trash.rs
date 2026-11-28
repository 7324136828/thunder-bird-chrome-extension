//! Prepared Trash emptying: snapshot → optional ZIP archive → delete exactly
//! the snapshot (port of `app/mail/trash.py`).
//!
//! Account-bound, expiring snapshots for archiving and emptying server Trash.
//! Preparing is read-only. Deletion uses only the snapshot's UIDs and
//! `UID EXPUNGE`, so newly arrived messages and another client's deleted
//! messages are untouched. The operation's mailbox identity is checked again
//! before every commit.
//!
//! # Fixed public contract (Phase 2)
//! Held in `AppState` as `TrashOperations::new(data_directory.join("trash_archives"))`.
//! Errors: `TrashOperationError` → `MailError::Operation` (502),
//! `TrashOperationNotFound` → `MailError::TrashNotFound` (404).
//! POP3 accounts → `crate::pop3::imap_only()` (`prepare` and `empty`; an
//! operation can never exist for a POP3 account, so `archive`/`discard`
//! answer the usual 404).
//!
//! # Additions to the pinned API
//! [`TrashLimits`] / [`TrashOperations::with_limits`] replace the module
//! constants the Python tests patched (`MAX_*`, `UID_BATCH_SIZE`, the TTL and
//! the deadline); [`TrashOperations::cleanup`] is `_cleanup` and
//! [`TrashOperations::operation_count`] is `len(_operations)`.
//!
//! # Intentional deviations
//! * Python held the registry lock for the whole preparation (up to ten
//!   minutes of IMAP work), blocking `archive`/`empty`/`discard`/`forget` of
//!   every other operation. Preparations are still serialized (by a
//!   dedicated lock, which keeps the `MAX_OPERATIONS` and spool bounds), but
//!   the registry is only locked briefly. An operation prepared while
//!   `close()` ran is rejected instead of being registered.
//! * The operation id has the shape of `secrets.token_urlsafe(32)` (43
//!   URL-safe characters) built from two random v4 UUIDs (244 random bits).
//! * The SELECT/EXAMINE is issued here rather than through
//!   `crate::imap::select`, because the snapshot needs the response's
//!   `[UIDVALIDITY]` and Python's distinction between a refused SELECT
//!   (`MailOperationError`) and a protocol error (`IMAP4.error`).
//! * `testzip()` failures that were not `BadZipFile` (e.g. a corrupt deflate
//!   stream, a 500 in Python) are reported as "could not be verified".

use std::collections::{HashMap, HashSet};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Condvar, LazyLock, Mutex, MutexGuard, Weak};
use std::thread;
use std::time::{Duration, Instant, SystemTime};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use mail_proto::imap::{Arg, CommandResponse, ImapConnection, Status};
use mail_proto::ProtoError;
use regex::bytes::Regex;
use serde_json::{json, Value};

use crate::error::{MailError, Result};
use crate::sessions::MailAccount;

/// `OPERATION_TTL_SECONDS`.
pub const OPERATION_TTL_SECONDS: u64 = 30 * 60;
/// `OPERATION_TIMEOUT_SECONDS`: deadline of one prepare or commit.
pub const OPERATION_TIMEOUT_SECONDS: u64 = 600;
pub const MAX_OPERATIONS: usize = 4;
pub const MAX_MESSAGES: usize = 100_000;
pub const MAX_MESSAGE_BYTES: u64 = 64 * 1024 * 1024;
pub const MAX_SOURCE_BYTES: u64 = 1024 * 1024 * 1024;
pub const MAX_ARCHIVE_BYTES: u64 = 1024 * 1024 * 1024;
pub const MAX_SPOOL_BYTES: u64 = 2 * 1024 * 1024 * 1024;
pub const UID_BATCH_SIZE: usize = 500;
/// `_cleanup_loop`: `self._stop.wait(60)`.
pub const CLEANUP_INTERVAL_SECONDS: u64 = 60;

const MAX_UID: u64 = 4_294_967_295;
const NOT_DELETED: &str = "No messages were deleted";

const NOT_FOUND_MESSAGE: &str =
    "This Trash operation has expired or is unavailable. Prepare it again.";
const INACTIVE_MESSAGE: &str = "This Trash operation is no longer available.";
const PARTIAL_WITH_ARCHIVE: &str = "Trash could only be partially emptied. Some messages may have been permanently deleted. Keep the downloaded archive and retry this same operation to finish safely.";
const PARTIAL_WITHOUT_ARCHIVE: &str = "Trash could only be partially emptied. Some messages may have been permanently deleted. Retry this same operation to finish safely.";

/// `_LIST`.
static LIST_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?-u)\A\(([^)]*)\)\s+(?:"(?:[^"\\]|\\.)*"|NIL)\s+(.+)\z"#).expect("valid regex")
});
/// `_UID`.
static UID_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i-u)\bUID\s+(\d+)\b").expect("valid regex"));
/// `_SIZE`.
static SIZE_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i-u)\bRFC822\.SIZE\s+(\d+)\b").expect("valid regex"));

/// The module constants as one value, so tests can shrink them (the Python
/// tests patched the constants).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrashLimits {
    pub operation_ttl: Duration,
    pub operation_timeout: Duration,
    pub max_operations: usize,
    pub max_messages: usize,
    pub max_message_bytes: u64,
    pub max_source_bytes: u64,
    pub max_archive_bytes: u64,
    pub max_spool_bytes: u64,
    pub uid_batch_size: usize,
    pub cleanup_interval: Duration,
}

impl Default for TrashLimits {
    fn default() -> Self {
        Self {
            operation_ttl: Duration::from_secs(OPERATION_TTL_SECONDS),
            operation_timeout: Duration::from_secs(OPERATION_TIMEOUT_SECONDS),
            max_operations: MAX_OPERATIONS,
            max_messages: MAX_MESSAGES,
            max_message_bytes: MAX_MESSAGE_BYTES,
            max_source_bytes: MAX_SOURCE_BYTES,
            max_archive_bytes: MAX_ARCHIVE_BYTES,
            max_spool_bytes: MAX_SPOOL_BYTES,
            uid_batch_size: UID_BATCH_SIZE,
            cleanup_interval: Duration::from_secs(CLEANUP_INTERVAL_SECONDS),
        }
    }
}

// ---------------------------------------------------------------------------
// Internal error model
// ---------------------------------------------------------------------------

/// What a step raised in Python.
#[derive(Debug)]
enum Fail {
    /// `TrashOperationError(message)`.
    Trash(String),
    /// `imap_client.MailOperationError` (connect, `_select`).
    Mail(MailError),
    /// `OSError`, `imaplib.IMAP4.error`, `zipfile.BadZipFile`, `RuntimeError`.
    Other,
}

type R<T> = std::result::Result<T, Fail>;

impl From<ProtoError> for Fail {
    fn from(_: ProtoError) -> Self {
        Fail::Other
    }
}

impl From<io::Error> for Fail {
    fn from(_: io::Error) -> Self {
        Fail::Other
    }
}

impl From<zip::result::ZipError> for Fail {
    fn from(_: zip::result::ZipError) -> Self {
        Fail::Other
    }
}

fn trash(message: &str) -> Fail {
    Fail::Trash(message.to_string())
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// `imaplib` semantics: `BAD` raises (`IMAP4.error`), `OK`/`NO` are returned.
fn checked(response: std::result::Result<CommandResponse, ProtoError>) -> R<CommandResponse> {
    let response = response?;
    if response.status == Status::Bad {
        return Err(Fail::Other);
    }
    Ok(response)
}

// ---------------------------------------------------------------------------
// Operation records
// ---------------------------------------------------------------------------

/// `_owner(account)`: never retains credentials.
#[derive(Debug, Clone, PartialEq)]
struct Owner {
    email: String,
    unlocked_at: f64,
    incoming_server: String,
    incoming_port: u16,
    incoming_protocol: String,
}

impl Owner {
    fn of(account: &MailAccount) -> Self {
        Self {
            email: account.email.trim().to_lowercase(),
            unlocked_at: account.unlocked_at,
            incoming_server: account.incoming_server.clone(),
            incoming_port: account.incoming_port,
            incoming_protocol: account.incoming_protocol.clone(),
        }
    }
}

#[derive(Debug, Default)]
struct OperationState {
    archive_requested: bool,
    result: Option<Value>,
}

/// `_Operation`; `state` is the per-operation `lock` plus the fields it guards.
#[derive(Debug)]
struct Operation {
    operation_id: String,
    owner: Owner,
    folder: String,
    uidvalidity: u32,
    uids: Vec<u32>,
    expires: Instant,
    path: Option<PathBuf>,
    filename: Option<String>,
    state: Mutex<OperationState>,
}

impl Operation {
    /// `_remove_file`: an in-progress download may still hold the file on
    /// Windows; the disk-expiration sweep collects it later.
    fn remove_file(&self) {
        if let Some(path) = &self.path {
            remove_quietly(path);
        }
    }
}

fn remove_quietly(path: &Path) {
    let _ = fs::remove_file(path);
}

#[derive(Debug, Default)]
struct Registry {
    operations: HashMap<String, Arc<Operation>>,
    closed: bool,
}

/// Stop signal of the cleanup thread (`self._stop`).
#[derive(Debug, Default)]
struct StopSignal {
    stopped: Mutex<bool>,
    wake: Condvar,
}

impl StopSignal {
    fn set(&self) {
        *lock(&self.stopped) = true;
        self.wake.notify_all();
    }
}

#[derive(Debug)]
struct Inner {
    directory: PathBuf,
    limits: TrashLimits,
    registry: Mutex<Registry>,
    /// Serializes preparations (staging files count against the bounds).
    prepare_lock: Mutex<()>,
    stop: Arc<StopSignal>,
}

impl Drop for Inner {
    fn drop(&mut self) {
        self.stop.set();
    }
}

/// An authenticated connection that is logged out when dropped
/// (`finally: imap_client._logout(conn)`).
struct Session(Option<ImapConnection>);

impl Session {
    fn connect(account: &MailAccount) -> R<Self> {
        crate::imap::connect(account)
            .map(|conn| Session(Some(conn)))
            .map_err(Fail::Mail)
    }

    fn conn(&mut self) -> &mut ImapConnection {
        self.0.as_mut().expect("connection is open until dropped")
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        if let Some(conn) = self.0.take() {
            crate::imap::logout(conn);
        }
    }
}

// ---------------------------------------------------------------------------
// IMAP steps (module-level helpers of trash.py)
// ---------------------------------------------------------------------------

/// `_safe_folder`.
fn safe_folder(folder: &str) -> R<()> {
    if folder.is_empty()
        || folder.chars().count() > 500
        || !folder.is_ascii()
        || folder.bytes().any(|byte| byte < 32 || byte == 127)
    {
        return Err(trash(
            "This Trash folder name is not supported for safe deletion.",
        ));
    }
    Ok(())
}

/// Python `bytes.isspace` set.
fn is_py_space(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c)
}

/// Python `bytes.strip()`.
fn py_strip(bytes: &[u8]) -> &[u8] {
    let start = bytes
        .iter()
        .position(|b| !is_py_space(*b))
        .unwrap_or(bytes.len());
    let end = bytes
        .iter()
        .rposition(|b| !is_py_space(*b))
        .map_or(start, |i| i + 1);
    &bytes[start..end.max(start)]
}

/// `re.sub(rb'\\(.)', rb'\1', value)`.
fn unescape(value: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(value.len());
    let mut index = 0;
    while index < value.len() {
        if value[index] == b'\\' && index + 1 < value.len() && value[index + 1] != b'\n' {
            out.push(value[index + 1]);
            index += 2;
        } else {
            out.push(value[index]);
            index += 1;
        }
    }
    out
}

/// The `imaplib` data items of the untagged `kind` responses: one
/// `(line, literal)` pair per literal-bearing piece (the tuples) followed by
/// the remaining line text. With `strip_name`, the first line starts after
/// the response name, as `imaplib` reports named responses (`LIST`).
fn data_items(
    response: &CommandResponse,
    kind: &str,
    strip_name: bool,
) -> Vec<(Vec<u8>, Option<Vec<u8>>)> {
    let mut items = Vec::new();
    for untagged in response.untagged_of(kind) {
        for (index, part) in untagged.parts.iter().enumerate() {
            let line = if index == 0 && strip_name {
                untagged.data_text().into_bytes()
            } else {
                part.text.clone()
            };
            items.push((line, part.literal.clone()));
        }
    }
    items
}

/// `_verify_trash`: require the exact selectable mailbox advertised as
/// server Trash.
fn verify_trash(conn: &mut ImapConnection, folder: &str) -> R<()> {
    safe_folder(folder)?;
    let response = checked(conn.command("LIST", &[Arg::quoted(""), Arg::atom("*")]))?;
    if !response.is_ok() {
        return Err(trash("The server could not verify its Trash folder."));
    }
    for (line, literal) in data_items(&response, "LIST", true) {
        let Some(captures) = LIST_RE.captures(py_strip(&line)) else {
            continue;
        };
        let flags: HashSet<Vec<u8>> = captures[1]
            .split(|b| is_py_space(*b))
            .filter(|flag| !flag.is_empty())
            .map(<[u8]>::to_ascii_lowercase)
            .collect();
        if !flags.contains(b"\\trash".as_slice()) || flags.contains(b"\\noselect".as_slice()) {
            continue;
        }
        let mut raw_name = literal.unwrap_or_else(|| captures[2].to_vec());
        if raw_name.first() == Some(&b'"') && raw_name.last() == Some(&b'"') {
            let inner = if raw_name.len() >= 2 {
                &raw_name[1..raw_name.len() - 1]
            } else {
                &[][..]
            };
            raw_name = unescape(inner);
        }
        if raw_name.is_ascii() && raw_name == folder.as_bytes() {
            return Ok(());
        }
    }
    Err(trash(
        "Emptying is only available for the server's verified Trash folder.",
    ))
}

/// `_require_uid_expunge`.
fn require_uid_expunge(conn: &mut ImapConnection) -> R<()> {
    let response = checked(conn.command("CAPABILITY", &[]))?;
    let mut capabilities: HashSet<String> = response
        .untagged_of("CAPABILITY")
        .flat_map(|item| item.words_upper())
        .collect();
    // imaplib also files `[CAPABILITY ...]` response codes under CAPABILITY.
    let codes = response
        .untagged
        .iter()
        .filter_map(|item| item.code.as_ref())
        .chain(response.code.as_ref())
        .filter(|code| code.name == "CAPABILITY");
    for code in codes {
        capabilities.extend(code.args.split_whitespace().map(str::to_ascii_uppercase));
    }
    if !response.is_ok()
        || !(capabilities.contains("UIDPLUS") || capabilities.contains("IMAP4REV2"))
    {
        return Err(trash(
            "This server cannot safely empty Trash: UIDPLUS or IMAP4rev2 is required.",
        ));
    }
    Ok(())
}

/// `imap_client._select` (returning the response for `_uidvalidity`).
fn select(conn: &mut ImapConnection, folder: &str, readonly: bool) -> R<CommandResponse> {
    let command = if readonly { "EXAMINE" } else { "SELECT" };
    let response = checked(conn.command(command, &[Arg::quoted(folder)]))?;
    if !response.is_ok() {
        return Err(Fail::Mail(MailError::operation(format!(
            "The server would not open folder {}",
            crate::servers::python_repr_str(folder)
        ))));
    }
    let read_only = response
        .untagged
        .iter()
        .filter_map(|item| item.code.as_ref())
        .chain(response.code.as_ref())
        .any(|code| code.name == "READ-ONLY");
    if !readonly && read_only {
        // imaplib raised IMAP4.readonly.
        return Err(Fail::Other);
    }
    Ok(response)
}

/// `_uidvalidity`: the first `[UIDVALIDITY n]` of the SELECT.
fn uidvalidity(selected: &CommandResponse) -> R<u32> {
    let value = selected
        .untagged
        .iter()
        .filter_map(|item| item.code.as_ref())
        .chain(selected.code.as_ref())
        .find(|code| code.name == "UIDVALIDITY")
        .and_then(|code| crate::schemas::parse_python_int(&code.args));
    match value {
        Some(value) if (1..=i128::from(MAX_UID)).contains(&value) => {
            Ok(u32::try_from(value).expect("range checked"))
        }
        _ => Err(trash(
            "The server did not identify this Trash mailbox safely.",
        )),
    }
}

/// `_uids`: every UID of the selected mailbox, sorted and unique.
fn uids(conn: &mut ImapConnection) -> R<Vec<u32>> {
    let response = checked(conn.uid("SEARCH", &[Arg::atom("ALL")]))?;
    let first = response
        .untagged_of("SEARCH")
        .next()
        .map(|item| item.data_text());
    let (true, Some(text)) = (response.is_ok(), first) else {
        return Err(trash("The server could not list all messages in Trash."));
    };
    let invalid = || trash("The server returned an invalid Trash message list.");
    let mut values = Vec::new();
    for token in text.split(|c: char| c.is_ascii() && is_py_space(c as u8)) {
        if token.is_empty() {
            continue;
        }
        if !token.bytes().all(|b| b.is_ascii_digit()) {
            return Err(invalid());
        }
        let value = token.parse::<u64>().unwrap_or(u64::MAX);
        if !(1..=MAX_UID).contains(&value) {
            return Err(invalid());
        }
        values.push(u32::try_from(value).expect("range checked"));
    }
    values.sort_unstable();
    values.dedup();
    Ok(values)
}

/// `_uid_set`.
fn uid_set(values: &[u32]) -> String {
    values
        .iter()
        .map(u32::to_string)
        .collect::<Vec<_>>()
        .join(",")
}

/// `_check_deadline`.
fn check_deadline(deadline: Instant) -> R<()> {
    if Instant::now() >= deadline {
        return Err(trash("The Trash operation timed out."));
    }
    Ok(())
}

fn capture_number(captures: &regex::bytes::Captures<'_>) -> u64 {
    std::str::from_utf8(&captures[1])
        .ok()
        .and_then(|digits| digits.parse().ok())
        .unwrap_or(u64::MAX)
}

/// `_sizes`.
fn sizes(
    conn: &mut ImapConnection,
    uids: &[u32],
    deadline: Instant,
    limits: &TrashLimits,
) -> R<HashMap<u32, u64>> {
    let mut sizes = HashMap::new();
    for batch in uids.chunks(limits.uid_batch_size.max(1)) {
        check_deadline(deadline)?;
        let response = checked(conn.uid(
            "FETCH",
            &[Arg::atom(uid_set(batch)), Arg::atom("(UID RFC822.SIZE)")],
        ))?;
        if !response.is_ok() {
            return Err(trash("The server could not check the Trash archive size."));
        }
        for (meta, _) in data_items(&response, "FETCH", false) {
            let (Some(uid), Some(size)) = (UID_RE.captures(&meta), SIZE_RE.captures(&meta)) else {
                continue;
            };
            let uid = capture_number(&uid);
            if let Some(uid) = u32::try_from(uid).ok().filter(|uid| batch.contains(uid)) {
                sizes.insert(uid, capture_number(&size));
            }
        }
    }
    let wanted: HashSet<u32> = uids.iter().copied().collect();
    if sizes.keys().copied().collect::<HashSet<_>>() != wanted {
        return Err(trash(
            "Trash changed while preparing the archive. No messages were deleted; retry.",
        ));
    }
    if sizes.values().any(|size| *size > limits.max_message_bytes) {
        return Err(trash(
            "A Trash message is too large to archive safely. No messages were deleted.",
        ));
    }
    let total: u128 = sizes.values().map(|size| u128::from(*size)).sum();
    if total > u128::from(limits.max_source_bytes) {
        return Err(trash(
            "Trash is too large to archive in one download. No messages were deleted.",
        ));
    }
    Ok(sizes)
}

/// `_raw`: one complete original message.
fn raw(
    conn: &mut ImapConnection,
    uid: u32,
    size: u64,
    deadline: Instant,
    limits: &TrashLimits,
) -> R<Vec<u8>> {
    check_deadline(deadline)?;
    let response = checked(conn.uid(
        "FETCH",
        &[Arg::atom(uid.to_string()), Arg::atom("(UID BODY.PEEK[])")],
    ))?;
    if !response.is_ok() {
        return Err(trash(
            "A Trash message could not be archived. No messages were deleted.",
        ));
    }
    let mut payloads: Vec<Vec<u8>> = Vec::new();
    for (meta, literal) in data_items(&response, "FETCH", false) {
        let Some(raw) = literal else { continue };
        if UID_RE
            .captures(&meta)
            .is_some_and(|captures| capture_number(&captures) == u64::from(uid))
        {
            payloads.push(raw);
        }
    }
    match payloads.pop() {
        Some(payload)
            if payloads.is_empty()
                && payload.len() as u64 == size
                && payload.len() as u64 <= limits.max_message_bytes =>
        {
            Ok(payload)
        }
        _ => Err(trash(
            "A Trash message could not be completely archived. No messages were deleted.",
        )),
    }
}

/// `directory.glob("trash-*.zip")` name test.
fn is_archive_name(name: &str) -> bool {
    name.len() >= "trash-.zip".len() && name.starts_with("trash-") && name.ends_with(".zip")
}

fn archive_entries(directory: &Path) -> io::Result<Vec<fs::DirEntry>> {
    let mut entries = Vec::new();
    let listing = match fs::read_dir(directory) {
        Ok(listing) => listing,
        // glob() of a missing directory is empty.
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(entries),
        Err(error) => return Err(error),
    };
    for entry in listing {
        let entry = entry?;
        if entry.file_name().to_str().is_some_and(is_archive_name) {
            entries.push(entry);
        }
    }
    Ok(entries)
}

/// `secrets.token_urlsafe(32)`.
fn token_urlsafe() -> String {
    let mut bytes = [0u8; 32];
    bytes[..16].copy_from_slice(uuid::Uuid::new_v4().as_bytes());
    bytes[16..].copy_from_slice(uuid::Uuid::new_v4().as_bytes());
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Write every message into a new ZIP at `path` (`zipfile.ZipFile(path, "x",
/// ZIP_DEFLATED, compresslevel=6)`), then verify it like `testzip()`.
fn write_archive(
    conn: &mut ImapConnection,
    path: &Path,
    uids: &[u32],
    sizes: &HashMap<u32, u64>,
    deadline: Instant,
    limits: &TrashLimits,
) -> R<()> {
    let too_large = || trash("The Trash archive is too large. No messages were deleted.");
    {
        let file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)?;
        let mut output = zip::ZipWriter::new(file);
        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated)
            .compression_level(Some(6));
        let mut written: R<()> = Ok(());
        for uid in uids {
            let step = (|| -> R<()> {
                let message = raw(conn, *uid, sizes[uid], deadline, limits)?;
                output.start_file(format!("message-{uid}.eml"), options)?;
                io::Write::write_all(&mut output, &message)?;
                if fs::metadata(path)?.len() > limits.max_archive_bytes {
                    return Err(too_large());
                }
                Ok(())
            })();
            if step.is_err() {
                written = step;
                break;
            }
        }
        // The `with` block closes (finishes) the ZIP even on failure.
        let finished = output.finish();
        written?;
        finished?;
    }
    verify_archive(path, uids.len())?;
    if fs::metadata(path)?.len() > limits.max_archive_bytes {
        return Err(too_large());
    }
    Ok(())
}

/// `len(check.infolist()) != count or check.testzip() is not None`.
fn verify_archive(path: &Path, count: usize) -> R<()> {
    let unverified = || trash("The Trash archive could not be verified. No messages were deleted.");
    let mut archive = zip::ZipArchive::new(fs::File::open(path)?)?;
    if archive.len() != count {
        return Err(unverified());
    }
    for index in 0..archive.len() {
        let mut entry = archive.by_index(index).map_err(|_| unverified())?;
        io::copy(&mut entry, &mut io::sink()).map_err(|_| unverified())?;
    }
    Ok(())
}

fn not_found(message: &str) -> MailError {
    MailError::TrashNotFound(message.to_string())
}

// ---------------------------------------------------------------------------
// TrashOperations
// ---------------------------------------------------------------------------

/// Thread-safe operation registry; clones share state.
///
/// Short-lived archive files and IMAP snapshots; thread-safe per commit.
#[derive(Debug, Clone)]
pub struct TrashOperations {
    inner: Arc<Inner>,
}

impl TrashOperations {
    /// Creates `directory` and starts the background expiry cleanup.
    pub fn new(directory: impl AsRef<Path>) -> Self {
        Self::with_limits(directory, TrashLimits::default())
    }

    /// Like [`TrashOperations::new`] with explicit limits.
    pub fn with_limits(directory: impl AsRef<Path>, limits: TrashLimits) -> Self {
        let directory = directory.as_ref().to_path_buf();
        // Python raised here; the pinned constructor cannot fail, and a
        // missing directory makes `prepare(archive=True)` fail safely.
        let _ = fs::create_dir_all(&directory);
        let stop = Arc::new(StopSignal::default());
        let interval = limits.cleanup_interval;
        let inner = Arc::new(Inner {
            directory,
            limits,
            registry: Mutex::new(Registry::default()),
            prepare_lock: Mutex::new(()),
            stop: Arc::clone(&stop),
        });
        spawn_cleaner(Arc::downgrade(&inner), stop, interval);
        Self { inner }
    }

    pub fn directory(&self) -> &Path {
        &self.inner.directory
    }

    /// The limits in effect.
    pub fn limits(&self) -> &TrashLimits {
        &self.inner.limits
    }

    /// Number of registered (possibly expired, not yet collected) operations.
    pub fn operation_count(&self) -> usize {
        lock(&self.inner.registry).operations.len()
    }

    /// `_cleanup`: drop expired operations and their files, and remove
    /// archive files left by a crash or an interrupted download.
    pub fn cleanup(&self) {
        let now = Instant::now();
        let (expired, live) = {
            let mut registry = lock(&self.inner.registry);
            let expired: Vec<Arc<Operation>> = registry
                .operations
                .values()
                .filter(|operation| operation.expires <= now)
                .cloned()
                .collect();
            for operation in &expired {
                registry.operations.remove(&operation.operation_id);
            }
            let live: HashSet<PathBuf> = registry
                .operations
                .values()
                .filter_map(|operation| operation.path.clone())
                .collect();
            (expired, live)
        };
        for operation in expired {
            let _guard = lock(&operation.state);
            operation.remove_file();
        }
        let Some(cutoff) = SystemTime::now().checked_sub(self.inner.limits.operation_ttl) else {
            return;
        };
        let Ok(entries) = archive_entries(&self.inner.directory) else {
            return;
        };
        for entry in entries {
            let path = entry.path();
            if live.contains(&path) {
                continue;
            }
            let stale = entry
                .metadata()
                .and_then(|metadata| metadata.modified())
                .is_ok_and(|modified| modified < cutoff);
            if stale {
                remove_quietly(&path);
            }
        }
    }

    /// `_find`.
    fn find(&self, account: &MailAccount, operation_id: &str) -> Result<Arc<Operation>> {
        let registry = lock(&self.inner.registry);
        match registry.operations.get(operation_id) {
            Some(operation)
                if !registry.closed
                    && operation.owner == Owner::of(account)
                    && operation.expires > Instant::now() =>
            {
                Ok(Arc::clone(operation))
            }
            _ => Err(not_found(NOT_FOUND_MESSAGE)),
        }
    }

    /// `_assert_active`.
    fn assert_active(&self, operation: &Arc<Operation>) -> Result<()> {
        let registry = lock(&self.inner.registry);
        let registered = registry
            .operations
            .get(&operation.operation_id)
            .is_some_and(|current| Arc::ptr_eq(current, operation));
        if registry.closed || !registered || operation.expires <= Instant::now() {
            return Err(not_found(INACTIVE_MESSAGE));
        }
        Ok(())
    }

    /// `prepare(account, folder, archive)` → operation dict exactly as Python.
    pub fn prepare(&self, account: &MailAccount, folder: &str, archive: bool) -> Result<Value> {
        if account.is_pop3() {
            return Err(crate::pop3::imap_only());
        }
        if let Err(Fail::Trash(message)) = safe_folder(folder) {
            return Err(MailError::Operation(message));
        }
        self.cleanup();
        let _serialized = lock(&self.inner.prepare_lock);
        {
            let registry = lock(&self.inner.registry);
            if registry.closed {
                return Err(MailError::operation("Trash operations are unavailable."));
            }
            if registry.operations.len() >= self.inner.limits.max_operations {
                return Err(MailError::operation(
                    "Finish or discard an existing Trash operation before preparing another.",
                ));
            }
        }
        let mut staged: Option<PathBuf> = None;
        let outcome = self.prepare_snapshot(account, folder, archive, &mut staged);
        if let Some(path) = staged {
            let registered = lock(&self.inner.registry)
                .operations
                .values()
                .any(|operation| operation.path.as_deref() == Some(path.as_path()));
            if !registered {
                remove_quietly(&path);
            }
        }
        outcome.map_err(|fail| match fail {
            Fail::Trash(message) if message.contains(NOT_DELETED) => MailError::Operation(message),
            Fail::Trash(message) => {
                MailError::Operation(format!("{message} No messages were deleted."))
            }
            Fail::Mail(error) => MailError::Operation(error.to_string()),
            Fail::Other => {
                MailError::operation("Trash could not be prepared. No messages were deleted.")
            }
        })
    }

    /// The `try:` body of `prepare` (the connection is logged out on return).
    fn prepare_snapshot(
        &self,
        account: &MailAccount,
        folder: &str,
        archive: bool,
        staged: &mut Option<PathBuf>,
    ) -> R<Value> {
        let limits = &self.inner.limits;
        let deadline = Instant::now() + limits.operation_timeout;
        check_deadline(deadline)?;
        let mut session = Session::connect(account)?;
        let conn = session.conn();
        check_deadline(deadline)?;
        require_uid_expunge(conn)?;
        verify_trash(conn, folder)?;
        let selected = select(conn, folder, true)?;
        let uidvalidity = uidvalidity(&selected)?;
        let uids = uids(conn)?;
        if uids.len() > limits.max_messages {
            return Err(trash(
                "Trash has too many messages for one operation. No messages were deleted.",
            ));
        }
        let operation_id = token_urlsafe();
        let mut filename = None;
        if archive {
            let sizes = sizes(conn, &uids, deadline, limits)?;
            let mut spool_size: u128 = 0;
            for entry in archive_entries(&self.inner.directory)? {
                spool_size += u128::from(entry.metadata()?.len());
            }
            // ZIP deflate can be marginally larger than its input.
            let expected: u128 = sizes.values().map(|size| u128::from(*size)).sum::<u128>()
                + uids.len() as u128 * 512
                + 1024;
            if expected > u128::from(limits.max_archive_bytes)
                || spool_size + expected > u128::from(limits.max_spool_bytes)
            {
                return Err(trash(
                    "There is not enough archive space for Trash. No messages were deleted.",
                ));
            }
            let path = self
                .inner
                .directory
                .join(format!("trash-{operation_id}.zip"));
            *staged = Some(path.clone());
            write_archive(conn, &path, &uids, &sizes, deadline, limits)?;
            filename = Some(format!(
                "trash-{}.zip",
                chrono::Utc::now().format("%Y%m%d-%H%M%S")
            ));
        }
        check_deadline(deadline)?;
        let count = uids.len();
        let operation = Arc::new(Operation {
            operation_id: operation_id.clone(),
            owner: Owner::of(account),
            folder: folder.to_string(),
            uidvalidity,
            uids,
            expires: Instant::now() + limits.operation_ttl,
            path: staged.clone(),
            filename: filename.clone(),
            state: Mutex::new(OperationState::default()),
        });
        {
            let mut registry = lock(&self.inner.registry);
            if registry.closed {
                return Err(trash("Trash operations are unavailable."));
            }
            registry.operations.insert(operation_id.clone(), operation);
        }
        drop(session);
        Ok(json!({
            "operation_id": operation_id,
            "count": count,
            "archive": archive,
            "filename": filename,
        }))
    }

    /// `archive(...)` → (ZIP path, download filename).
    pub fn archive(&self, account: &MailAccount, operation_id: &str) -> Result<(PathBuf, String)> {
        let operation = self.find(account, operation_id)?;
        let mut state = lock(&operation.state);
        self.assert_active(&operation)?;
        match (&operation.path, &operation.filename) {
            (Some(path), Some(filename)) if path.is_file() => {
                state.archive_requested = true;
                Ok((path.clone(), filename.clone()))
            }
            _ => Err(MailError::operation(
                "No archive is available for this Trash operation.",
            )),
        }
    }

    /// `empty(...)` → result dict exactly as Python.
    pub fn empty(&self, account: &MailAccount, operation_id: &str) -> Result<Value> {
        if account.is_pop3() {
            return Err(crate::pop3::imap_only());
        }
        let operation = self.find(account, operation_id)?;
        let mut state = lock(&operation.state);
        self.assert_active(&operation)?;
        if let Some(result) = &state.result {
            return Ok(result.clone());
        }
        if let Some(path) = &operation.path {
            if !state.archive_requested || !path.is_file() {
                return Err(MailError::operation(
                    "Download and save the Trash archive before permanently deleting the messages.",
                ));
            }
        }
        let mut attempted = false;
        match self.commit(account, &operation, &mut attempted) {
            Ok(result) => {
                state.result = Some(result.clone());
                Ok(result)
            }
            Err(_) if attempted => Err(MailError::operation(if operation.path.is_some() {
                PARTIAL_WITH_ARCHIVE
            } else {
                PARTIAL_WITHOUT_ARCHIVE
            })),
            Err(Fail::Trash(message)) => Err(MailError::Operation(message)),
            Err(_) => Err(MailError::operation(
                "The server could not empty Trash. No messages were deleted.",
            )),
        }
    }

    /// The `try:` body of `empty` (the connection is logged out on return).
    fn commit(
        &self,
        account: &MailAccount,
        operation: &Operation,
        attempted: &mut bool,
    ) -> R<Value> {
        let limits = &self.inner.limits;
        let deadline = Instant::now() + limits.operation_timeout;
        check_deadline(deadline)?;
        let mut session = Session::connect(account)?;
        let conn = session.conn();
        check_deadline(deadline)?;
        require_uid_expunge(conn)?;
        verify_trash(conn, &operation.folder)?;
        let selected = select(conn, &operation.folder, false)?;
        if uidvalidity(&selected)? != operation.uidvalidity {
            return Err(trash(
                "Trash changed its mailbox identity. No messages were deleted; prepare a new operation.",
            ));
        }
        let existing: HashSet<u32> = uids(conn)?.into_iter().collect();
        let pending: Vec<u32> = operation
            .uids
            .iter()
            .copied()
            .filter(|uid| existing.contains(uid))
            .collect();
        for batch in pending.chunks(limits.uid_batch_size.max(1)) {
            check_deadline(deadline)?;
            let set = uid_set(batch);
            *attempted = true;
            let stored = checked(conn.uid(
                "STORE",
                &[
                    Arg::atom(set.clone()),
                    Arg::atom("+FLAGS.SILENT"),
                    Arg::atom("(\\Deleted)"),
                ],
            ))?;
            if !stored.is_ok() {
                return Err(trash(
                    "The server could not mark all Trash messages for permanent deletion.",
                ));
            }
            check_deadline(deadline)?;
            let expunged = checked(conn.uid("EXPUNGE", &[Arg::atom(set)]))?;
            if !expunged.is_ok() {
                return Err(trash(
                    "The server could not permanently delete all Trash messages.",
                ));
            }
        }
        check_deadline(deadline)?;
        let remaining = uids(conn)?;
        let snapshot: HashSet<u32> = operation.uids.iter().copied().collect();
        if remaining.iter().any(|uid| snapshot.contains(uid)) {
            return Err(trash(
                "The server still contains some of the Trash messages selected for deletion.",
            ));
        }
        drop(session);
        Ok(json!({"deleted": operation.uids.len(), "remaining": remaining.len()}))
    }

    pub fn discard(&self, account: &MailAccount, operation_id: &str) -> Result<()> {
        let operation = self.find(account, operation_id)?;
        let _state = lock(&operation.state);
        self.assert_active(&operation)?;
        lock(&self.inner.registry).operations.remove(operation_id);
        operation.remove_file();
        Ok(())
    }

    /// Drop every operation (and archive file) owned by `email`.
    pub fn forget(&self, email: &str) {
        let email = email.trim().to_lowercase();
        let removed: Vec<Arc<Operation>> = {
            let mut registry = lock(&self.inner.registry);
            let ids: Vec<String> = registry
                .operations
                .values()
                .filter(|operation| operation.owner.email == email)
                .map(|operation| operation.operation_id.clone())
                .collect();
            ids.iter()
                .filter_map(|id| registry.operations.remove(id))
                .collect()
        };
        for operation in removed {
            let _state = lock(&operation.state);
            operation.remove_file();
        }
    }

    /// Stop cleanup and remove every archive file.
    pub fn close(&self) {
        self.inner.stop.set();
        let removed: Vec<Arc<Operation>> = {
            let mut registry = lock(&self.inner.registry);
            registry.closed = true;
            registry
                .operations
                .drain()
                .map(|(_, operation)| operation)
                .collect()
        };
        for operation in removed {
            let _state = lock(&operation.state);
            operation.remove_file();
        }
    }
}

/// `_cleanup_loop` on a daemon-like thread that ends when the registry is
/// closed or dropped.
fn spawn_cleaner(inner: Weak<Inner>, stop: Arc<StopSignal>, interval: Duration) {
    let _ = thread::Builder::new()
        .name("trash-archive-cleanup".into())
        .spawn(move || loop {
            let stopped = lock(&stop.stopped);
            let (stopped, _) = stop
                .wake
                .wait_timeout_while(stopped, interval, |stopped| !*stopped)
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if *stopped {
                break;
            }
            drop(stopped);
            match inner.upgrade() {
                Some(inner) => TrashOperations { inner }.cleanup(),
                None => break,
            }
        });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn folder_names_are_restricted_like_python() {
        assert!(safe_folder("Trash").is_ok());
        assert!(safe_folder("Trash \"quoted\"").is_ok());
        assert!(safe_folder(&"x".repeat(500)).is_ok());
        for bad in ["", "Trash\r\nINBOX", "Tr\u{e4}sh", "a\u{7f}"] {
            assert!(matches!(safe_folder(bad), Err(Fail::Trash(_))), "{bad:?}");
        }
        assert!(safe_folder(&"x".repeat(501)).is_err());
    }

    #[test]
    fn list_regex_and_unescape_match_python() {
        let line = br#"(\Trash) NIL "Trash \"quoted\"""#;
        let captures = LIST_RE.captures(line).unwrap();
        assert_eq!(&captures[1], br"\Trash");
        assert_eq!(&captures[2], br#""Trash \"quoted\"""#);
        assert_eq!(unescape(br#"Trash \"quoted\""#), b"Trash \"quoted\"");
        assert_eq!(unescape(b"a\\\\b\\"), b"a\\b\\");
        assert!(LIST_RE.captures(b"garbage").is_none());
        assert_eq!(py_strip(b" \x0b x \x0c"), b"x");
        assert_eq!(py_strip(b"  "), b"");
    }

    #[test]
    fn archive_names_match_glob() {
        assert!(is_archive_name("trash-abc.zip"));
        assert!(is_archive_name("trash-.zip"));
        assert!(!is_archive_name("trash.zip"));
        assert!(!is_archive_name("other-abc.zip"));
        assert!(!is_archive_name("trash-abc.zip.part"));
    }

    #[test]
    fn token_has_token_urlsafe_shape() {
        let token = token_urlsafe();
        assert_eq!(token.len(), 43);
        assert!(token
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'));
        assert_ne!(token, token_urlsafe());
    }

    /// Replaces the Python test that patched `ZipFile.testzip`: a corrupted
    /// member fails verification, a wrong member count too.
    #[test]
    fn archive_verification_detects_corruption_and_wrong_count() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("trash-test.zip");
        {
            let mut output = zip::ZipWriter::new(fs::File::create(&path).unwrap());
            let options = zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Stored);
            output.start_file("message-1.eml", options).unwrap();
            io::Write::write_all(&mut output, b"Subject: one\r\n\r\nBody one\r\n").unwrap();
            output.finish().unwrap();
        }
        assert!(verify_archive(&path, 1).is_ok());
        assert!(matches!(verify_archive(&path, 2), Err(Fail::Trash(m)) if m.contains("verified")));
        let mut bytes = fs::read(&path).unwrap();
        let offset = bytes
            .windows(8)
            .position(|window| window == b"Body one")
            .unwrap();
        bytes[offset] = b'X';
        fs::write(&path, bytes).unwrap();
        assert!(matches!(verify_archive(&path, 1), Err(Fail::Trash(m)) if m.contains("verified")));
    }

    #[test]
    fn owner_ignores_password_and_normalizes_email() {
        let mut account = MailAccount::new(
            " User@Example.com ",
            "secret-password",
            "imap.example.com",
            993,
            "SSL/TLS",
            "smtp.example.com",
            587,
            "STARTTLS",
        );
        let owner = Owner::of(&account);
        assert_eq!(owner.email, "user@example.com");
        assert!(!format!("{owner:?}").contains("secret-password"));
        account.password = "other".into();
        assert_eq!(Owner::of(&account), owner);
        account.unlocked_at += 1.0;
        assert_ne!(Owner::of(&account), owner);
    }

    #[test]
    fn close_stops_and_drop_releases_cleaner() {
        let directory = tempfile::tempdir().unwrap();
        let operations = TrashOperations::new(directory.path().join("trash_archives"));
        assert!(operations.directory().is_dir());
        let weak = Arc::downgrade(&operations.inner);
        operations.close();
        drop(operations);
        assert!(weak.upgrade().is_none());
    }
}
