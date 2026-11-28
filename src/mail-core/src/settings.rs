//! Per-user application settings and storage paths (port of `backend/settings.py`).
//!
//! # Settings location
//!
//! Python resolved `settings.json` from `%APPDATA%` (Windows) or
//! `$XDG_CONFIG_HOME` / `~/.config` (elsewhere). The Rust port keeps that
//! default and adds two overrides so tests and the backend never have to touch
//! the real per-user file:
//!
//! 1. [`set_settings_path_override`] / [`scoped_settings_path`] (process-wide);
//! 2. the `WEBMAIL_SETTINGS_PATH` environment variable ([`SETTINGS_PATH_ENV`]),
//!    holding the full path of the settings file.
//!
//! # Concurrency
//!
//! Python serialized every reader and writer in the process with
//! `_SETTINGS_LOCK`; [`settings_lock`] is the same process-wide lock and must be
//! held by every module that reads or rewrites `settings.json`
//! (display names, signatures, ...). Files are always published atomically by
//! [`write_json`] so another process never observes a partial file.
//!
//! # Deviations from Python
//!
//! * `initialize_mail_servers` takes an optional seed *file* instead of the
//!   project root: the extension build has no repository `mail-servers.json`,
//!   so the backend passes `None` (or a bundled file) and an empty
//!   `{"servers": {}}` document is created on first start.
//! * Rewriting the settings file preserves every key, value and the original
//!   key order (serde_json `preserve_order`); new keys are appended, as with a
//!   Python dict. Formatting matches `json.dump(indent=2)` with `ensure_ascii`.
//! * serde_json rejects lone UTF-16 surrogate escapes (`"\ud800"`) that Python
//!   accepted; such files are reported as unreadable configuration instead of
//!   an invalid signature. Both raise `SettingsError` (HTTP 500).

use crate::error::{MailError, Result};
use regex::Regex;
use serde::Serialize;
use serde_json::{Map, Value};
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::io::{self, Write};
use std::path::{Component, Path, PathBuf, Prefix};
use std::sync::{LazyLock, Mutex, MutexGuard, RwLock};

pub use crate::model::{
    default_category_expiration_days, is_category, normalize_expiration_days,
    validate_category_expiration_days, APP_NAME, DEFAULT_LOCAL_AI_MODEL, DEFAULT_MESSAGES_PER_PAGE,
    EMAIL_CATEGORIES, MAIL_SERVERS_FILENAME, MAX_EXPIRATION_DAYS, MAX_MESSAGES_PER_PAGE,
    MAX_SIGNATURE_LENGTH,
};

/// `LOCAL_AI_MODEL_PATTERN`: an Ollama model identifier (full match).
pub const LOCAL_AI_MODEL_PATTERN: &str = r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,199}";

/// Environment variable naming the full path of `settings.json`.
pub const SETTINGS_PATH_ENV: &str = "WEBMAIL_SETTINGS_PATH";

static LOCAL_AI_MODEL_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(&format!("^(?:{LOCAL_AI_MODEL_PATTERN})$")).unwrap());
static CLOUD_MODEL_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)(?:^|[-:/])cloud(?:$|[-:/])").unwrap());

/// `_SETTINGS_LOCK`: serializes settings readers and writers in this process.
static SETTINGS_LOCK: Mutex<()> = Mutex::new(());
/// Process-wide settings path override (see [`set_settings_path_override`]).
static SETTINGS_PATH_OVERRIDE: RwLock<Option<PathBuf>> = RwLock::new(None);
/// Serializes holders of [`ScopedSettingsPath`] so parallel tests never share
/// an override. Deliberately separate from [`SETTINGS_LOCK`].
static SCOPED_PATH_SERIAL: Mutex<()> = Mutex::new(());

/// Acquire `_SETTINGS_LOCK`. A panic in another holder does not poison it.
pub fn settings_lock() -> MutexGuard<'static, ()> {
    SETTINGS_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Python `AppSettings`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppSettings {
    pub settings_path: PathBuf,
    pub data_directory: PathBuf,
}

/// Python `MailPreferences` (the `GET/PUT /api/settings` response body).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MailPreferences {
    pub messages_per_page: u32,
    pub signature: String,
    /// Serialized in `EMAIL_CATEGORIES` order, like the Python dict.
    #[serde(serialize_with = "serialize_category_expiration_days")]
    pub category_expiration_days: BTreeMap<String, i64>,
    pub local_ai_model: String,
}

/// A category policy map as a JSON object in `EMAIL_CATEGORIES` order (the
/// order Python's `validate_category_expiration_days` produced); any other
/// keys follow in sorted order.
pub fn category_expiration_json(policies: &BTreeMap<String, i64>) -> Value {
    let mut object = Map::new();
    for category in EMAIL_CATEGORIES {
        if let Some(days) = policies.get(category) {
            object.insert(category.to_string(), Value::from(*days));
        }
    }
    for (category, days) in policies {
        if !object.contains_key(category) {
            object.insert(category.clone(), Value::from(*days));
        }
    }
    Value::Object(object)
}

fn serialize_category_expiration_days<S: serde::Serializer>(
    policies: &BTreeMap<String, i64>,
    serializer: S,
) -> std::result::Result<S::Ok, S::Error> {
    category_expiration_json(policies).serialize(serializer)
}

/// Optional arguments of `save_mail_preferences`; `None` means "not supplied"
/// (Python's `_SIGNATURE_UNSET` / `_EXPIRATION_UNSET` / `_LOCAL_AI_MODEL_UNSET`).
/// Values are raw JSON so the same type checks as Python apply.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct MailPreferencesUpdate {
    pub signature: Option<Value>,
    pub category_expiration_days: Option<Value>,
    pub local_ai_model: Option<Value>,
}

/// Validated `frontend_port` / `backend_port` pair (`port_mapping.json`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct PortMapping {
    pub frontend_port: u16,
    pub backend_port: u16,
}

fn settings_error(message: impl Into<String>) -> MailError {
    MailError::Settings(message.into())
}

// ---------------------------------------------------------------------------
// Paths
// ---------------------------------------------------------------------------

/// Replace (or clear with `None`) the process-wide settings path override.
/// The backend calls this at startup when it is given an explicit location.
pub fn set_settings_path_override(path: Option<PathBuf>) {
    let mut guard = SETTINGS_PATH_OVERRIDE
        .write()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    *guard = path;
}

/// Current process-wide override, if any.
pub fn settings_path_override() -> Option<PathBuf> {
    SETTINGS_PATH_OVERRIDE
        .read()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone()
}

/// RAII override for tests: points [`settings_path`] at `path` until dropped,
/// then restores the previous override. Holders are serialized process-wide,
/// so concurrently running tests that each use a scoped path never interfere.
pub struct ScopedSettingsPath {
    previous: Option<PathBuf>,
    _serial: MutexGuard<'static, ()>,
}

/// Point [`settings_path`] at `path` for the lifetime of the returned guard.
pub fn scoped_settings_path(path: impl Into<PathBuf>) -> ScopedSettingsPath {
    let serial = SCOPED_PATH_SERIAL
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let previous = settings_path_override();
    set_settings_path_override(Some(path.into()));
    ScopedSettingsPath {
        previous,
        _serial: serial,
    }
}

impl Drop for ScopedSettingsPath {
    fn drop(&mut self) {
        set_settings_path_override(self.previous.take());
    }
}

/// Python `settings_path()`, plus the override hooks described in the module docs.
pub fn settings_path() -> PathBuf {
    if let Some(path) = settings_path_override() {
        return path;
    }
    if let Some(value) = std::env::var_os(SETTINGS_PATH_ENV) {
        let text = value.to_string_lossy();
        if !text.trim().is_empty() {
            let expanded = expand_user(&text);
            return resolve_path(&expanded).unwrap_or(expanded);
        }
    }
    platform_settings_path(|name| std::env::var_os(name), &home_dir())
}

/// The default per-user location, computed from an environment lookup.
fn platform_settings_path(env: impl Fn(&str) -> Option<OsString>, home: &Path) -> PathBuf {
    let non_empty = |name: &str| env(name).filter(|value| !value.is_empty());
    let root = if cfg!(windows) {
        non_empty("APPDATA")
            .map(PathBuf::from)
            .unwrap_or_else(|| home.join("AppData").join("Roaming"))
    } else {
        non_empty("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| home.join(".config"))
    };
    let root = expand_user_with(&root.to_string_lossy(), home);
    resolve_path(&root)
        .unwrap_or(root)
        .join(APP_NAME)
        .join("settings.json")
}

/// Python `default_data_directory()`: `%TEMP%` (or the platform temp folder)
/// joined with the application name.
pub fn default_data_directory() -> PathBuf {
    let root = std::env::var_os("TEMP")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    let root = expand_user(&root.to_string_lossy());
    resolve_path(&root).unwrap_or(root).join(APP_NAME)
}

/// Python `mail_servers_path()`: the per-user profile file beside settings.json.
pub fn mail_servers_path() -> PathBuf {
    let path = settings_path();
    path.parent()
        .map(Path::to_path_buf)
        .unwrap_or_default()
        .join(MAIL_SERVERS_FILENAME)
}

/// `Path.home()`: `%USERPROFILE%` on Windows, `$HOME` elsewhere.
pub fn home_dir() -> PathBuf {
    let variable = if cfg!(windows) { "USERPROFILE" } else { "HOME" };
    if let Some(home) = std::env::var_os(variable).filter(|value| !value.is_empty()) {
        return PathBuf::from(home);
    }
    if cfg!(windows) {
        if let (Some(drive), Some(path)) =
            (std::env::var_os("HOMEDRIVE"), std::env::var_os("HOMEPATH"))
        {
            let mut combined = drive;
            combined.push(path);
            return PathBuf::from(combined);
        }
    }
    #[allow(deprecated)]
    std::env::home_dir().unwrap_or_else(|| PathBuf::from("."))
}

/// `os.path.expanduser` for `~` and `~/...` (other forms are returned unchanged).
pub fn expand_user(path: &str) -> PathBuf {
    expand_user_with(path, &home_dir())
}

fn expand_user_with(path: &str, home: &Path) -> PathBuf {
    let Some(rest) = path.strip_prefix('~') else {
        return PathBuf::from(path);
    };
    let is_separator = |c: char| c == '/' || (cfg!(windows) && c == '\\');
    if rest.is_empty() {
        return home.to_path_buf();
    }
    if rest.starts_with(is_separator) {
        let mut combined = home.to_path_buf();
        let trimmed = rest.trim_start_matches(is_separator);
        if !trimmed.is_empty() {
            combined.push(trimmed);
        }
        return combined;
    }
    PathBuf::from(path)
}

/// `os.path.expandvars`: `%VAR%`, `$VAR` and `${VAR}` on Windows (text in
/// single quotes is left alone), `$VAR` and `${VAR}` elsewhere. Unknown
/// variables are left unchanged.
pub fn expand_vars(path: &str) -> String {
    expand_vars_with(path, |name| std::env::var(name).ok())
}

#[cfg(windows)]
fn expand_vars_with(path: &str, lookup: impl Fn(&str) -> Option<String>) -> String {
    if !path.contains('$') && !path.contains('%') {
        return path.to_string();
    }
    let is_var_char = |c: char| c.is_ascii_alphanumeric() || c == '_' || c == '-';
    let chars: Vec<char> = path.chars().collect();
    let mut result = String::new();
    let mut index = 0;
    while index < chars.len() {
        let c = chars[index];
        match c {
            '\'' => {
                // No expansion within single quotes.
                match chars[index + 1..].iter().position(|&x| x == '\'') {
                    Some(offset) => {
                        let end = index + 1 + offset;
                        result.extend(&chars[index..=end]);
                        index = end + 1;
                    }
                    None => {
                        result.extend(&chars[index..]);
                        index = chars.len();
                    }
                }
            }
            '%' => {
                if chars.get(index + 1) == Some(&'%') {
                    result.push('%');
                    index += 2;
                    continue;
                }
                match chars[index + 1..].iter().position(|&x| x == '%') {
                    Some(offset) => {
                        let end = index + 1 + offset;
                        let name: String = chars[index + 1..end].iter().collect();
                        match lookup(&name) {
                            Some(value) => result.push_str(&value),
                            None => {
                                result.push('%');
                                result.push_str(&name);
                                result.push('%');
                            }
                        }
                        index = end + 1;
                    }
                    None => {
                        result.extend(&chars[index..]);
                        index = chars.len();
                    }
                }
            }
            '$' => {
                if chars.get(index + 1) == Some(&'$') {
                    result.push('$');
                    index += 2;
                } else if chars.get(index + 1) == Some(&'{') {
                    match chars[index + 2..].iter().position(|&x| x == '}') {
                        Some(offset) => {
                            let end = index + 2 + offset;
                            let name: String = chars[index + 2..end].iter().collect();
                            match lookup(&name) {
                                Some(value) => result.push_str(&value),
                                None => {
                                    result.push_str("${");
                                    result.push_str(&name);
                                    result.push('}');
                                }
                            }
                            index = end + 1;
                        }
                        None => {
                            result.extend(&chars[index..]);
                            index = chars.len();
                        }
                    }
                } else {
                    let start = index + 1;
                    let mut end = start;
                    while end < chars.len() && is_var_char(chars[end]) {
                        end += 1;
                    }
                    let name: String = chars[start..end].iter().collect();
                    match lookup(&name).filter(|_| !name.is_empty()) {
                        Some(value) => result.push_str(&value),
                        None => {
                            result.push('$');
                            result.push_str(&name);
                        }
                    }
                    index = end;
                }
            }
            _ => {
                result.push(c);
                index += 1;
            }
        }
    }
    result
}

#[cfg(not(windows))]
fn expand_vars_with(path: &str, lookup: impl Fn(&str) -> Option<String>) -> String {
    static VARIABLE: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"\$([A-Za-z0-9_]+|\{[^}]*\})").unwrap());
    if !path.contains('$') {
        return path.to_string();
    }
    let mut result = String::new();
    let mut last = 0;
    for captures in VARIABLE.captures_iter(path) {
        let whole = captures.get(0).unwrap();
        let mut name = &captures[1];
        if name.starts_with('{') && name.ends_with('}') {
            name = &name[1..name.len() - 1];
        }
        if let Some(value) = lookup(name) {
            result.push_str(&path[last..whole.start()]);
            result.push_str(&value);
            last = whole.end();
        }
    }
    result.push_str(&path[last..]);
    result
}

/// `Path.resolve()` (non-strict): make absolute, normalize `.`/`..`, resolve
/// symlinks of the existing prefix and keep the missing remainder as-is.
/// Windows verbatim prefixes (`\\?\`) are removed like Python does.
pub fn resolve_path(path: &Path) -> io::Result<PathBuf> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    let normalized = lexical_normalize(&absolute);
    let mut existing = normalized.as_path();
    let mut missing: Vec<OsString> = Vec::new();
    loop {
        if let Ok(canonical) = fs::canonicalize(existing) {
            let mut resolved = strip_verbatim(&canonical);
            for component in missing.iter().rev() {
                resolved.push(component);
            }
            return Ok(resolved);
        }
        match (existing.parent(), existing.file_name()) {
            (Some(parent), Some(name)) => {
                missing.push(name.to_os_string());
                existing = parent;
            }
            _ => return Ok(normalized),
        }
    }
}

fn lexical_normalize(path: &Path) -> PathBuf {
    let mut parts: Vec<Component<'_>> = Vec::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                if matches!(parts.last(), Some(Component::Normal(_))) {
                    parts.pop();
                } else if parts.is_empty() {
                    parts.push(component);
                }
            }
            other => parts.push(other),
        }
    }
    parts.iter().collect()
}

fn strip_verbatim(path: &Path) -> PathBuf {
    let mut components = path.components();
    let Some(Component::Prefix(prefix)) = components.next() else {
        return path.to_path_buf();
    };
    let mut result = match prefix.kind() {
        Prefix::VerbatimDisk(drive) => PathBuf::from(format!("{}:\\", drive as char)),
        Prefix::VerbatimUNC(server, share) => {
            let mut text = OsString::from(r"\\");
            text.push(server);
            text.push(r"\");
            text.push(share);
            text.push(r"\");
            PathBuf::from(text)
        }
        _ => return path.to_path_buf(),
    };
    for component in components {
        if let Component::Normal(name) = component {
            result.push(name);
        }
    }
    result
}

// ---------------------------------------------------------------------------
// JSON files
// ---------------------------------------------------------------------------

/// Python `repr(float)` (also what `json.dumps` writes for a float): the
/// shortest round-trip digits, positional for decimal exponents in `-4..16`
/// (with a trailing `.0` when whole), otherwise scientific with a signed, at
/// least two-digit exponent (`1e+16`, `1e-05`).
pub fn python_float_repr(number: f64) -> String {
    let scientific = format!("{number:e}");
    let (mantissa, exponent) = scientific
        .split_once('e')
        .unwrap_or((scientific.as_str(), "0"));
    let exponent: i32 = exponent.parse().unwrap_or(0);
    if number == 0.0 || (-4..16).contains(&exponent) {
        let text = number.to_string();
        return if text.contains('.') {
            text
        } else {
            format!("{text}.0")
        };
    }
    let sign = if exponent < 0 { '-' } else { '+' };
    format!("{mantissa}e{sign}{:02}", exponent.abs())
}

/// serde_json formatter reproducing Python's `json.dump(..., indent=2)` with
/// the default `ensure_ascii=True` (every non-printable-ASCII character is
/// written as a `\uXXXX` escape).
struct PythonJsonFormatter {
    pretty: serde_json::ser::PrettyFormatter<'static>,
}

impl PythonJsonFormatter {
    fn new() -> Self {
        Self {
            pretty: serde_json::ser::PrettyFormatter::with_indent(b"  "),
        }
    }
}

impl serde_json::ser::Formatter for PythonJsonFormatter {
    fn begin_array<W: ?Sized + Write>(&mut self, writer: &mut W) -> io::Result<()> {
        self.pretty.begin_array(writer)
    }
    fn end_array<W: ?Sized + Write>(&mut self, writer: &mut W) -> io::Result<()> {
        self.pretty.end_array(writer)
    }
    fn begin_array_value<W: ?Sized + Write>(
        &mut self,
        writer: &mut W,
        first: bool,
    ) -> io::Result<()> {
        self.pretty.begin_array_value(writer, first)
    }
    fn end_array_value<W: ?Sized + Write>(&mut self, writer: &mut W) -> io::Result<()> {
        self.pretty.end_array_value(writer)
    }
    fn begin_object<W: ?Sized + Write>(&mut self, writer: &mut W) -> io::Result<()> {
        self.pretty.begin_object(writer)
    }
    fn end_object<W: ?Sized + Write>(&mut self, writer: &mut W) -> io::Result<()> {
        self.pretty.end_object(writer)
    }
    fn begin_object_key<W: ?Sized + Write>(
        &mut self,
        writer: &mut W,
        first: bool,
    ) -> io::Result<()> {
        self.pretty.begin_object_key(writer, first)
    }
    fn begin_object_value<W: ?Sized + Write>(&mut self, writer: &mut W) -> io::Result<()> {
        self.pretty.begin_object_value(writer)
    }
    fn end_object_value<W: ?Sized + Write>(&mut self, writer: &mut W) -> io::Result<()> {
        self.pretty.end_object_value(writer)
    }
    fn write_f64<W: ?Sized + Write>(&mut self, writer: &mut W, value: f64) -> io::Result<()> {
        writer.write_all(python_float_repr(value).as_bytes())
    }
    fn write_string_fragment<W: ?Sized + Write>(
        &mut self,
        writer: &mut W,
        fragment: &str,
    ) -> io::Result<()> {
        let mut start = 0;
        for (index, ch) in fragment.char_indices() {
            if (' '..='~').contains(&ch) {
                continue;
            }
            writer.write_all(&fragment.as_bytes()[start..index])?;
            let mut units = [0u16; 2];
            for unit in ch.encode_utf16(&mut units) {
                write!(writer, "\\u{unit:04x}")?;
            }
            start = index + ch.len_utf8();
        }
        writer.write_all(&fragment.as_bytes()[start..])
    }
}

/// Serialize like Python `json.dump(values, file, indent=2)` followed by `"\n"`.
pub fn to_python_json(values: &Value) -> String {
    let mut buffer = Vec::new();
    let mut serializer =
        serde_json::Serializer::with_formatter(&mut buffer, PythonJsonFormatter::new());
    values
        .serialize(&mut serializer)
        .expect("serializing a JSON value cannot fail");
    buffer.push(b'\n');
    String::from_utf8(buffer).expect("formatter writes ASCII only")
}

/// Python `_write_json`: publish complete JSON so another startup never reads
/// a partial file. With `overwrite = false` an existing file is left untouched
/// (another process won the race to create it).
pub fn write_json(path: &Path, values: &Value, overwrite: bool) -> io::Result<()> {
    let directory = path.parent().unwrap_or_else(|| Path::new("."));
    let content = to_python_json(values);
    let (temporary_path, mut file) = create_temporary_file(directory)?;
    let result = (|| {
        file.write_all(content.as_bytes())?;
        file.flush()?;
        drop(file);
        if overwrite {
            return rename_replacing(&temporary_path, path);
        }
        match fs::hard_link(&temporary_path, path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => Ok(()),
            // File systems without hard links: fall back to a rename that
            // only happens when nothing has been published yet.
            Err(_) if path.exists() => Ok(()),
            Err(_) => fs::rename(&temporary_path, path),
        }
    })();
    let _ = fs::remove_file(&temporary_path);
    result
}

/// `rename` over an existing file.
///
/// On Windows this transiently fails with `PermissionDenied` ("Access is
/// denied", os error 5) while another process (antivirus, search indexer, a
/// concurrent reader) has the destination open without `FILE_SHARE_DELETE`.
/// A short bounded retry (about 180 ms in total) rides that out; any other
/// error, and a persistent denial, is returned unchanged.
fn rename_replacing(from: &Path, to: &Path) -> io::Result<()> {
    const MAX_RETRIES: u64 = 8;
    let mut attempt = 0;
    loop {
        match fs::rename(from, to) {
            Err(error)
                if cfg!(windows)
                    && error.kind() == io::ErrorKind::PermissionDenied
                    && attempt < MAX_RETRIES =>
            {
                attempt += 1;
                std::thread::sleep(std::time::Duration::from_millis(5 * attempt));
            }
            result => return result,
        }
    }
}

fn create_temporary_file(directory: &Path) -> io::Result<(PathBuf, fs::File)> {
    loop {
        let name = format!(".settings-{}.tmp", uuid::Uuid::new_v4().simple());
        let candidate = directory.join(name);
        match fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&candidate)
        {
            Ok(file) => return Ok((candidate, file)),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        }
    }
}

/// Read a file as `utf-8-sig` text (an optional BOM is removed).
pub fn read_utf8_sig(path: &Path) -> io::Result<String> {
    let bytes = fs::read(path)?;
    let bytes = bytes.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(&bytes);
    String::from_utf8(bytes.to_vec())
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}

/// Parse `utf-8-sig` JSON, reporting I/O, decoding and syntax errors as text.
fn read_json_value(path: &Path) -> std::result::Result<Value, String> {
    let text = read_utf8_sig(path).map_err(|error| error.to_string())?;
    serde_json::from_str(&text).map_err(|error| error.to_string())
}

/// Python `_read_json_object`.
pub fn read_json_object(path: &Path) -> Result<Map<String, Value>> {
    let value = read_json_value(path).map_err(|error| {
        settings_error(format!(
            "Cannot read configuration at {}: {error}",
            path.display()
        ))
    })?;
    match value {
        Value::Object(map) => Ok(map),
        _ => Err(settings_error(format!(
            "Invalid configuration at {}: expected a JSON object",
            path.display()
        ))),
    }
}

/// Read settings.json under the caller's [`settings_lock`]; a missing file is
/// an empty object (`_read_json_object(path) if path.exists() else {}`).
pub fn read_settings_object(path: &Path) -> Result<Map<String, Value>> {
    if path.exists() {
        read_json_object(path)
    } else {
        Ok(Map::new())
    }
}

/// Python `type(value) is int`: a JSON integer (not a bool or a float).
fn json_int(value: &Value) -> Option<i128> {
    match value {
        Value::Number(number) => number
            .as_i64()
            .map(i128::from)
            .or_else(|| number.as_u64().map(i128::from)),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Ports
// ---------------------------------------------------------------------------

fn validate_ports(values: &Map<String, Value>, path: &Path) -> Result<PortMapping> {
    let mut ports = [0u16; 2];
    for (slot, field) in ["frontend_port", "backend_port"].into_iter().enumerate() {
        let Some(value) = values.get(field) else {
            return Err(settings_error(format!(
                "Invalid configuration at {}: missing {field}",
                path.display()
            )));
        };
        match json_int(value) {
            Some(port) if (1..=65535).contains(&port) => ports[slot] = port as u16,
            _ => {
                return Err(settings_error(format!(
                    "Invalid configuration at {}: {field} must be an integer from 1 to 65535",
                    path.display()
                )))
            }
        }
    }
    if ports[0] == ports[1] {
        return Err(settings_error(format!(
            "Invalid configuration at {}: frontend_port and backend_port must be different",
            path.display()
        )));
    }
    Ok(PortMapping {
        frontend_port: ports[0],
        backend_port: ports[1],
    })
}

/// Python `load_port_mapping`: read and validate default frontend/backend ports.
///
/// Kept for parity with the Python launcher; the extension backend binds a
/// fixed port and does not need it at runtime.
pub fn load_port_mapping(path: &Path) -> Result<PortMapping> {
    validate_ports(&read_json_object(path)?, path)
}

/// Python `initialize_port_settings`: persist missing port defaults, then read
/// the effective per-user ports.
pub fn initialize_port_settings(defaults_path: &Path) -> Result<PortMapping> {
    let _guard = settings_lock();
    let defaults = load_port_mapping(defaults_path)?;
    let path = settings_path();
    let create = || -> io::Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        if !path.exists() {
            write_json(&path, &Value::Object(Map::new()), false)?;
        }
        Ok(())
    };
    create().map_err(|error| {
        settings_error(format!(
            "Cannot create settings at {}: {error}",
            path.display()
        ))
    })?;

    let mut values = read_json_object(&path)?;
    let mut missing = false;
    for (field, default) in [
        ("frontend_port", defaults.frontend_port),
        ("backend_port", defaults.backend_port),
    ] {
        if !values.contains_key(field) {
            values.insert(field.to_string(), Value::from(default));
            missing = true;
        }
    }
    // Validate before updating so invalid existing ports are never replaced.
    validate_ports(&values, &path)?;
    if missing {
        write_json(&path, &Value::Object(values), true).map_err(|error| {
            settings_error(format!(
                "Cannot update port settings at {}: {error}",
                path.display()
            ))
        })?;
    }
    validate_ports(&read_json_object(&path)?, &path)
}

// ---------------------------------------------------------------------------
// Application settings
// ---------------------------------------------------------------------------

/// Python `load_settings`: create defaults once; preserve settings the user
/// has already written.
pub fn load_settings() -> Result<AppSettings> {
    // Windows can briefly deny reads during a simultaneous startup's rename.
    let _guard = settings_lock();
    let path = settings_path();
    let default_directory = default_data_directory();
    let read = || -> std::result::Result<Value, String> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|error| error.to_string())?;
        }
        if !path.exists() {
            let defaults = serde_json::json!({
                "data_directory": default_directory.to_string_lossy(),
            });
            write_json(&path, &defaults, false).map_err(|error| error.to_string())?;
        }
        read_json_value(&path)
    };
    let settings = read().map_err(|error| {
        settings_error(format!(
            "Cannot read or create settings at {}: {error}",
            path.display()
        ))
    })?;
    let Value::Object(settings) = settings else {
        return Err(settings_error(format!(
            "Invalid settings at {}: expected a JSON object",
            path.display()
        )));
    };
    let configured = match settings.get("data_directory") {
        None => default_directory.to_string_lossy().into_owned(),
        Some(Value::String(text)) if !text.trim().is_empty() && !text.contains('\0') => {
            text.clone()
        }
        Some(_) => {
            return Err(settings_error(format!(
                "Invalid settings at {}: data_directory must be a non-empty folder path",
                path.display()
            )))
        }
    };
    let data_directory = resolve_configured_directory(&configured, &path).map_err(|error| {
        settings_error(format!(
            "Invalid data_directory in settings at {}: {error}",
            path.display()
        ))
    })?;
    Ok(AppSettings {
        settings_path: path,
        data_directory,
    })
}

/// Expand variables and `~`, anchor relative paths beside settings.json, resolve.
pub(crate) fn resolve_configured_directory(
    configured: &str,
    settings_file: &Path,
) -> io::Result<PathBuf> {
    let mut directory = expand_user(&expand_vars(configured));
    if !directory.is_absolute() {
        directory = settings_file
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_default()
            .join(directory);
    }
    resolve_path(&directory)
}

// ---------------------------------------------------------------------------
// Mail preferences
// ---------------------------------------------------------------------------

fn validate_messages_per_page(value: &Value, path: &Path) -> Result<u32> {
    match json_int(value) {
        Some(count) if (1..=MAX_MESSAGES_PER_PAGE as i128).contains(&count) => Ok(count as u32),
        _ => Err(settings_error(format!(
            "Invalid settings at {}: messages_per_page must be an integer from 1 to {MAX_MESSAGES_PER_PAGE}",
            path.display()
        ))),
    }
}

/// Python `validate_signature` for text: multiline plain text that can be
/// serialized and sent as UTF-8. `Err` holds the `ValueError` message.
pub fn validate_signature(value: &str) -> std::result::Result<String, String> {
    if value.chars().count() > MAX_SIGNATURE_LENGTH {
        return Err(format!(
            "Signature must be text with no more than {MAX_SIGNATURE_LENGTH} characters"
        ));
    }
    let invalid = value
        .chars()
        .any(|c| ((c as u32) < 32 && !matches!(c, '\t' | '\n' | '\r')) || c as u32 == 127);
    if invalid {
        return Err("Signature must be valid Unicode text without control characters".into());
    }
    Ok(value.to_string())
}

/// Python `validate_signature` for an arbitrary JSON value (non-strings fail).
pub fn validate_signature_value(value: &Value) -> std::result::Result<String, String> {
    match value {
        Value::String(text) => validate_signature(text),
        _ => Err(format!(
            "Signature must be text with no more than {MAX_SIGNATURE_LENGTH} characters"
        )),
    }
}

fn validate_signature_setting(value: &Value, path: &Path) -> Result<String> {
    validate_signature_value(value).map_err(|error| {
        settings_error(format!(
            "Invalid settings at {}: signature: {error}",
            path.display()
        ))
    })
}

/// Python `validate_local_ai_model`: accept an Ollama model identifier, never
/// an endpoint or cloud model. `Err` holds the `ValueError` message.
pub fn validate_local_ai_model(value: &str) -> std::result::Result<String, String> {
    if !LOCAL_AI_MODEL_RE.is_match(value) {
        return Err("Local AI model must be a model name of at most 200 characters".into());
    }
    if CLOUD_MODEL_RE.is_match(value) {
        return Err("Choose a locally installed model, not a cloud model".into());
    }
    if value.contains("://") || value.contains("..") || value.starts_with('/') {
        return Err("Local AI model must be a model identifier".into());
    }
    Ok(value.to_string())
}

/// Python `validate_local_ai_model` for an arbitrary JSON value.
pub fn validate_local_ai_model_value(value: &Value) -> std::result::Result<String, String> {
    match value {
        Value::String(text) => validate_local_ai_model(text),
        _ => Err("Local AI model must be a model name of at most 200 characters".into()),
    }
}

fn validate_local_ai_model_setting(value: &Value, path: &Path) -> Result<String> {
    validate_local_ai_model_value(value).map_err(|error| {
        settings_error(format!(
            "Invalid settings at {}: local_ai_model: {error}",
            path.display()
        ))
    })
}

fn validate_category_expiration_setting(
    value: &Value,
    path: &Path,
) -> Result<BTreeMap<String, i64>> {
    validate_category_expiration_days(value).map_err(|error| {
        settings_error(format!(
            "Invalid settings at {}: category_expiration_days: {error}",
            path.display()
        ))
    })
}

fn default_expiration_value() -> Value {
    category_expiration_json(&default_category_expiration_days())
}

fn stored_signature(values: &Map<String, Value>, path: &Path) -> Result<String> {
    validate_signature_setting(values.get("signature").unwrap_or(&Value::from("")), path)
}

fn stored_expiration(values: &Map<String, Value>, path: &Path) -> Result<BTreeMap<String, i64>> {
    match values.get("category_expiration_days") {
        Some(value) => validate_category_expiration_setting(value, path),
        None => validate_category_expiration_setting(&default_expiration_value(), path),
    }
}

fn stored_model(values: &Map<String, Value>, path: &Path) -> Result<String> {
    validate_local_ai_model_setting(
        values
            .get("local_ai_model")
            .unwrap_or(&Value::from(DEFAULT_LOCAL_AI_MODEL)),
        path,
    )
}

/// Python `load_mail_preferences`: read without rewriting existing settings.
pub fn load_mail_preferences() -> Result<MailPreferences> {
    let path = settings_path();
    let values = {
        let _guard = settings_lock();
        read_settings_object(&path)?
    };
    Ok(MailPreferences {
        messages_per_page: validate_messages_per_page(
            values
                .get("messages_per_page")
                .unwrap_or(&Value::from(DEFAULT_MESSAGES_PER_PAGE)),
            &path,
        )?,
        signature: stored_signature(&values, &path)?,
        category_expiration_days: stored_expiration(&values, &path)?,
        local_ai_model: stored_model(&values, &path)?,
    })
}

/// Python `save_mail_preferences`: atomically update mail preferences,
/// preserving omitted and unrelated settings.
pub fn save_mail_preferences(
    messages_per_page: &Value,
    update: &MailPreferencesUpdate,
) -> Result<MailPreferences> {
    let path = settings_path();
    let count = validate_messages_per_page(messages_per_page, &path)?;
    let signature = update
        .signature
        .as_ref()
        .map(|value| validate_signature_setting(value, &path))
        .transpose()?;
    let expiration = update
        .category_expiration_days
        .as_ref()
        .map(|value| validate_category_expiration_setting(value, &path))
        .transpose()?;
    let model = update
        .local_ai_model
        .as_ref()
        .map(|value| validate_local_ai_model_setting(value, &path))
        .transpose()?;

    let _guard = settings_lock();
    let mut values = read_settings_object(&path)?;
    let effective_signature = match &signature {
        Some(signature) => signature.clone(),
        None => stored_signature(&values, &path)?,
    };
    let effective_expiration = match &expiration {
        Some(expiration) => expiration.clone(),
        None => stored_expiration(&values, &path)?,
    };
    let effective_model = match &model {
        Some(model) => model.clone(),
        None => stored_model(&values, &path)?,
    };
    values.insert("messages_per_page".into(), Value::from(count));
    if let Some(signature) = signature {
        values.insert("signature".into(), Value::from(signature));
    }
    if let Some(expiration) = expiration {
        values.insert(
            "category_expiration_days".into(),
            category_expiration_json(&expiration),
        );
    }
    if let Some(model) = model {
        values.insert("local_ai_model".into(), Value::from(model));
    }
    let write = || -> io::Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        write_json(&path, &Value::Object(values), true)
    };
    write().map_err(|error| {
        settings_error(format!(
            "Cannot update mail settings at {}: {error}",
            path.display()
        ))
    })?;
    Ok(MailPreferences {
        messages_per_page: count,
        signature: effective_signature,
        category_expiration_days: effective_expiration,
        local_ai_model: effective_model,
    })
}

// ---------------------------------------------------------------------------
// Mail server profiles file
// ---------------------------------------------------------------------------

/// Python `initialize_mail_servers`: ensure the per-user mail server profiles
/// exist. On first start `seed_file` (if it is a file) is copied; otherwise an
/// empty `{"servers": {}}` document is written. An existing file is never
/// overwritten. The file holds server attributes only - never passwords.
/// An explicit `target` (e.g. `MAIL_SERVERS_PATH`) overrides the appdata file.
///
/// Deviation: Python took the project root and looked for
/// `<root>/mail-servers.json`; the extension build has no project root, so
/// the caller passes the seed file directly (usually `None`).
pub fn initialize_mail_servers(seed_file: Option<&Path>, target: Option<&Path>) -> Result<PathBuf> {
    let path = match target {
        Some(target) => target.to_path_buf(),
        None => mail_servers_path(),
    };
    let create = || -> io::Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        if !path.exists() {
            match seed_file.filter(|seed| seed.is_file()) {
                Some(seed) => {
                    fs::copy(seed, &path)?;
                }
                None => write_json(&path, &serde_json::json!({"servers": {}}), false)?,
            }
        }
        Ok(())
    };
    create().map_err(|error| {
        settings_error(format!(
            "Cannot create mail server profiles at {}: {error}",
            path.display()
        ))
    })?;
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// Isolated settings location (port of `SettingsTestCase.setUp`).
    struct Fixture {
        root: PathBuf,
        _temporary: tempfile::TempDir,
        _scope: ScopedSettingsPath,
    }

    impl Fixture {
        fn new() -> Self {
            let temporary = tempfile::tempdir().unwrap();
            let root = resolve_path(temporary.path()).unwrap();
            let scope =
                scoped_settings_path(root.join("roaming").join(APP_NAME).join("settings.json"));
            Self {
                root,
                _temporary: temporary,
                _scope: scope,
            }
        }

        fn write_settings(&self, content: &str) -> PathBuf {
            let path = settings_path();
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(&path, content.as_bytes()).unwrap();
            path
        }

        fn temp_files(&self) -> Vec<PathBuf> {
            let directory = settings_path().parent().unwrap().to_path_buf();
            fs::read_dir(directory)
                .map(|entries| {
                    entries
                        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
                        .filter(|path| {
                            let name = path.file_name().unwrap().to_string_lossy();
                            name.starts_with(".settings-") && name.ends_with(".tmp")
                        })
                        .collect()
                })
                .unwrap_or_default()
        }
    }

    fn preferences(count: u32, signature: &str) -> MailPreferences {
        MailPreferences {
            messages_per_page: count,
            signature: signature.into(),
            category_expiration_days: default_category_expiration_days(),
            local_ai_model: DEFAULT_LOCAL_AI_MODEL.into(),
        }
    }

    fn read_value(path: &Path) -> Value {
        serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap()
    }

    fn save_count(value: Value) -> Result<MailPreferences> {
        save_mail_preferences(&value, &MailPreferencesUpdate::default())
    }

    #[test]
    fn platform_path_uses_appdata_or_home() {
        let home = PathBuf::from(if cfg!(windows) {
            r"C:\Users\someone"
        } else {
            "/home/someone"
        });
        let fallback = platform_settings_path(|_| None, &home);
        let expected_root = if cfg!(windows) {
            home.join("AppData").join("Roaming")
        } else {
            home.join(".config")
        };
        assert_eq!(fallback, expected_root.join(APP_NAME).join("settings.json"));

        let configured = if cfg!(windows) {
            r"C:\Config\Roaming"
        } else {
            "/config/xdg"
        };
        let variable = if cfg!(windows) {
            "APPDATA"
        } else {
            "XDG_CONFIG_HOME"
        };
        let explicit = platform_settings_path(
            |name| (name == variable).then(|| OsString::from(configured)),
            &home,
        );
        assert_eq!(
            explicit,
            PathBuf::from(configured)
                .join(APP_NAME)
                .join("settings.json")
        );
        // An empty variable falls back to the home directory like Python's `or`.
        let empty = platform_settings_path(|_| Some(OsString::new()), &home);
        assert_eq!(empty, fallback);
    }

    #[test]
    fn first_load_creates_per_user_settings_with_temp_default() {
        let fixture = Fixture::new();
        let loaded = load_settings().unwrap();
        let expected_data = default_data_directory();
        assert_eq!(loaded.settings_path, settings_path());
        assert_eq!(loaded.data_directory, expected_data);
        assert_eq!(
            read_value(&loaded.settings_path),
            json!({"data_directory": expected_data.to_string_lossy()})
        );
        let original = fs::read(&loaded.settings_path).unwrap();
        assert_eq!(load_settings().unwrap(), loaded);
        assert_eq!(fs::read(&loaded.settings_path).unwrap(), original);
        assert!(fixture.temp_files().is_empty());
    }

    #[test]
    fn simultaneous_first_loads_read_complete_identical_defaults() {
        let _fixture = Fixture::new();
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(8));
        let handles: Vec<_> = (0..8)
            .map(|_| {
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    load_settings()
                })
            })
            .collect();
        // Other threads read the scoped override because it is process-wide.
        for handle in handles {
            let loaded = handle.join().unwrap().unwrap();
            assert_eq!(loaded.settings_path, settings_path());
            assert_eq!(loaded.data_directory, default_data_directory());
        }
        assert_eq!(
            read_value(&settings_path()),
            json!({"data_directory": default_data_directory().to_string_lossy()})
        );
    }

    #[test]
    fn existing_settings_preserve_formatting_and_unknown_keys() {
        let fixture = Fixture::new();
        let content = "{\n  \"data_directory\": \"../my-data\",\n  \"theme\": \"dark\"\n}\n";
        let path = fixture.write_settings(content);
        let loaded = load_settings().unwrap();
        let expected = resolve_path(&path.parent().unwrap().join("../my-data")).unwrap();
        assert_eq!(loaded.data_directory, expected);
        assert_eq!(fs::read(&path).unwrap(), content.as_bytes());
    }

    #[test]
    fn python_json_writes_floats_like_json_dump() {
        // json.dump({"a": 1e16, "b": 1e-05, "c": 2.5, "d": 3.0, "e": "\x7f"}, f, indent=2)
        let value = json!({"a": 1e16, "b": 0.00001, "c": 2.5, "d": 3.0, "e": "\u{7f}"});
        assert_eq!(
            to_python_json(&value),
            "{\n  \"a\": 1e+16,\n  \"b\": 1e-05,\n  \"c\": 2.5,\n  \"d\": 3.0,\n  \"e\": \"\\u007f\"\n}\n"
        );
        for (number, expected) in [
            (-0.0, "-0.0"),
            (0.0001, "0.0001"),
            (1.5e-7, "1.5e-07"),
            (123456789012345.0, "123456789012345.0"),
            (1.25e17, "1.25e+17"),
            (-2.5e300, "-2.5e+300"),
        ] {
            assert_eq!(python_float_repr(number), expected, "{number}");
        }
    }

    #[test]
    fn missing_data_directory_uses_default_without_rewriting() {
        let fixture = Fixture::new();
        let content = "{ \"theme\": \"dark\" }\n";
        let path = fixture.write_settings(content);
        assert_eq!(
            load_settings().unwrap().data_directory,
            default_data_directory()
        );
        assert_eq!(fs::read(&path).unwrap(), content.as_bytes());
    }

    #[test]
    fn invalid_settings_report_path_and_preserve_user_file() {
        let fixture = Fixture::new();
        for content in [
            "{broken json",
            "null",
            "[]",
            "\"a string\"",
            "{\"data_directory\": null}",
            "{\"data_directory\": 42}",
            "{\"data_directory\": false}",
            "{\"data_directory\": \"\"}",
            "{\"data_directory\": \"   \"}",
        ] {
            let path = fixture.write_settings(content);
            let error = load_settings().unwrap_err();
            assert_eq!(error.status(), 500, "{content}");
            assert!(
                error.to_string().contains(&path.display().to_string()),
                "{content}: {error}"
            );
            assert_eq!(fs::read(&path).unwrap(), content.as_bytes());
        }
    }

    #[test]
    fn data_directory_expands_environment_variables_and_home() {
        let fixture = Fixture::new();
        let expanded_root = fixture.root.join("expanded");
        std::env::set_var("SETTINGS_TEST_STORAGE_RS", &expanded_root);
        let variable = if cfg!(windows) {
            "%SETTINGS_TEST_STORAGE_RS%"
        } else {
            "${SETTINGS_TEST_STORAGE_RS}"
        };
        fixture
            .write_settings(&json!({"data_directory": format!("{variable}/records")}).to_string());
        assert_eq!(
            load_settings().unwrap().data_directory,
            expanded_root.join("records")
        );

        let home = fixture.root.join("home");
        assert_eq!(expand_user_with("~/records", &home), home.join("records"));
        assert_eq!(expand_user_with("~", &home), home);
        assert_eq!(
            expand_user_with("~other/x", &home),
            PathBuf::from("~other/x")
        );
        assert_eq!(expand_user_with("a/~", &home), PathBuf::from("a/~"));
    }

    #[test]
    fn expand_vars_leaves_unknown_variables() {
        let lookup = |name: &str| (name == "KNOWN").then(|| "value".to_string());
        assert_eq!(expand_vars_with("$KNOWN/${KNOWN}", lookup), "value/value");
        assert_eq!(
            expand_vars_with("$UNKNOWN/${UNKNOWN}", lookup),
            "$UNKNOWN/${UNKNOWN}"
        );
        assert_eq!(expand_vars_with("no variables", lookup), "no variables");
        if cfg!(windows) {
            assert_eq!(
                expand_vars_with("%KNOWN%\\%UNKNOWN%", lookup),
                "value\\%UNKNOWN%"
            );
            assert_eq!(expand_vars_with("'%KNOWN%' %%", lookup), "'%KNOWN%' %");
            assert_eq!(expand_vars_with("50%", lookup), "50%");
        }
    }

    #[test]
    fn temp_directory_uses_temp_root() {
        let expected_root = std::env::var_os("TEMP")
            .filter(|value| !value.is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir);
        assert_eq!(
            default_data_directory(),
            resolve_path(&expected_root).unwrap().join(APP_NAME)
        );
    }

    #[test]
    fn resolve_normalizes_missing_paths() {
        let temporary = tempfile::tempdir().unwrap();
        let root = resolve_path(temporary.path()).unwrap();
        let resolved =
            resolve_path(&root.join("a").join("..").join("b").join(".").join("c")).unwrap();
        assert_eq!(resolved, root.join("b").join("c"));
        assert!(!resolved.to_string_lossy().starts_with(r"\\?\"));
    }

    #[test]
    fn mail_servers_path_lives_beside_settings() {
        let _fixture = Fixture::new();
        assert_eq!(
            mail_servers_path(),
            settings_path().parent().unwrap().join("mail-servers.json")
        );
    }

    #[test]
    fn mail_servers_are_seeded_or_created_empty_and_never_overwritten() {
        let fixture = Fixture::new();
        let path = initialize_mail_servers(None, None).unwrap();
        assert_eq!(path, mail_servers_path());
        assert_eq!(read_value(&path), json!({"servers": {}}));

        let seed = fixture.root.join("seed.json");
        fs::write(
            &seed,
            r#"{"servers": {"purelymail": {"incoming_server": "imap.purelymail.com"}}}"#,
        )
        .unwrap();
        let explicit = fixture.root.join("explicit").join("profiles.json");
        assert_eq!(
            initialize_mail_servers(Some(&seed), Some(&explicit)).unwrap(),
            explicit
        );
        assert!(read_value(&explicit)["servers"].get("purelymail").is_some());
        assert!(!fs::read_to_string(&explicit)
            .unwrap()
            .to_lowercase()
            .contains("password"));

        fs::write(&explicit, r#"{"servers": {"mine": {}}}"#).unwrap();
        initialize_mail_servers(Some(&seed), Some(&explicit)).unwrap();
        assert!(read_value(&explicit)["servers"].get("mine").is_some());
    }

    #[test]
    fn explicit_profiles_path_does_not_require_valid_settings() {
        let fixture = Fixture::new();
        let path = fixture.write_settings("{invalid}");
        let profiles = fixture.root.join("explicit").join("profiles.json");
        initialize_mail_servers(None, Some(&profiles)).unwrap();
        assert!(profiles.is_file());
        assert_eq!(fs::read(&path).unwrap(), b"{invalid}");
    }

    #[test]
    fn python_json_format_matches_json_dump_indent_2() {
        let value =
            json!({"b": [1, {"x": null}], "a": "Zo\u{eb}\t\u{1F600}\u{7f}", "e": {}, "f": []});
        assert_eq!(
            to_python_json(&value),
            // serde_json's preserve_order keeps insertion order, like Python dicts.
            "{\n  \"b\": [\n    1,\n    {\n      \"x\": null\n    }\n  ],\n  \"a\": \"Zo\\u00eb\\t\\ud83d\\ude00\\u007f\",\n  \"e\": {},\n  \"f\": []\n}\n"
        );
    }

    #[test]
    fn write_json_without_overwrite_keeps_existing_file() {
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("settings.json");
        write_json(&path, &json!({"first": 1}), false).unwrap();
        write_json(&path, &json!({"second": 2}), false).unwrap();
        assert_eq!(read_value(&path), json!({"first": 1}));
        write_json(&path, &json!({"third": 3}), true).unwrap();
        assert_eq!(read_value(&path), json!({"third": 3}));
        let leftovers = fs::read_dir(temporary.path()).unwrap().count();
        assert_eq!(leftovers, 1);
    }

    // -- MailPreferencesTests ------------------------------------------------

    #[test]
    fn default_page_size_is_five_without_creating_or_rewriting_settings() {
        let fixture = Fixture::new();
        assert_eq!(load_mail_preferences().unwrap(), preferences(5, ""));
        assert!(!settings_path().exists());
        let content = "{ \"data_directory\": \"../saved-data\", \"theme\": \"dark\" }\n";
        let path = fixture.write_settings(content);
        assert_eq!(load_mail_preferences().unwrap(), preferences(5, ""));
        assert_eq!(fs::read(&path).unwrap(), content.as_bytes());
    }

    #[test]
    fn saving_page_size_preserves_storage_ports_and_unknown_keys() {
        let fixture = Fixture::new();
        let original = json!({
            "data_directory": "../saved-data", "frontend_port": 4310,
            "backend_port": 4320, "theme": {"color": "blue"}, "custom": [1, null],
        });
        let path = fixture.write_settings(&original.to_string());
        assert_eq!(save_count(json!(37)).unwrap(), preferences(37, ""));
        assert_eq!(load_mail_preferences().unwrap(), preferences(37, ""));
        let mut expected = original.clone();
        expected["messages_per_page"] = json!(37);
        assert_eq!(read_value(&path), expected);
        assert!(fixture.temp_files().is_empty());
    }

    #[test]
    fn page_size_accepts_boundaries_and_rejects_invalid_values() {
        let fixture = Fixture::new();
        for count in [1, 200] {
            assert_eq!(save_count(json!(count)).unwrap(), preferences(count, ""));
        }
        let path = settings_path();
        let previous = fs::read(&path).unwrap();
        for invalid in [
            json!(null),
            json!(true),
            json!(false),
            json!(0),
            json!(-1),
            json!(201),
            json!(5.5),
            json!(5.0),
            json!("5"),
            json!([]),
            json!({}),
        ] {
            let error = save_count(invalid.clone()).unwrap_err();
            assert!(error.to_string().contains("messages_per_page"), "{invalid}");
            assert_eq!(error.status(), 500);
            assert_eq!(fs::read(&path).unwrap(), previous);
            fixture.write_settings(&json!({"messages_per_page": invalid}).to_string());
            let error = load_mail_preferences().unwrap_err();
            assert!(error.to_string().contains("messages_per_page"), "{invalid}");
            fs::write(&path, &previous).unwrap();
        }
    }

    #[test]
    fn malformed_settings_are_preserved_on_read_or_save() {
        let fixture = Fixture::new();
        for content in ["{broken", "null", "[]"] {
            let path = fixture.write_settings(content);
            assert!(matches!(
                load_mail_preferences(),
                Err(MailError::Settings(_))
            ));
            assert!(matches!(save_count(json!(10)), Err(MailError::Settings(_))));
            assert_eq!(fs::read(&path).unwrap(), content.as_bytes());
        }
    }

    #[test]
    fn multiline_signature_save_preserves_settings_and_partial_updates() {
        let fixture = Fixture::new();
        let original =
            json!({"messages_per_page": 5, "data_directory": "../data", "theme": "dark"});
        let path = fixture.write_settings(&original.to_string());
        let signature = "Thanks,\nZo\u{eb}\t| Example Co.\r\nhttps://example.com";
        let expected = preferences(5, signature);
        let update = MailPreferencesUpdate {
            signature: Some(json!(signature)),
            ..Default::default()
        };
        assert_eq!(save_mail_preferences(&json!(5), &update).unwrap(), expected);
        assert_eq!(load_mail_preferences().unwrap(), expected);
        let mut on_disk = original.clone();
        on_disk["signature"] = json!(signature);
        assert_eq!(read_value(&path), on_disk);
        // Non-ASCII is escaped like Python's ensure_ascii.
        assert!(fs::read_to_string(&path).unwrap().contains("Zo\\u00eb"));

        let mut twelve = expected.clone();
        twelve.messages_per_page = 12;
        assert_eq!(save_count(json!(12)).unwrap(), twelve);
        on_disk["messages_per_page"] = json!(12);
        assert_eq!(read_value(&path), on_disk);
        assert!(fixture.temp_files().is_empty());
    }

    #[test]
    fn signature_can_be_disabled_and_accepts_length_boundary() {
        let _fixture = Fixture::new();
        let signature = "a".repeat(MAX_SIGNATURE_LENGTH);
        let update = |value: &str| MailPreferencesUpdate {
            signature: Some(json!(value)),
            ..Default::default()
        };
        assert_eq!(
            save_mail_preferences(&json!(5), &update(&signature))
                .unwrap()
                .signature,
            signature
        );
        assert_eq!(load_mail_preferences().unwrap().signature, signature);
        assert_eq!(
            save_mail_preferences(&json!(5), &update(""))
                .unwrap()
                .signature,
            ""
        );
        assert_eq!(load_mail_preferences().unwrap().signature, "");
    }

    #[test]
    fn invalid_signature_preserves_settings_on_save_and_load() {
        let fixture = Fixture::new();
        let original =
            json!({"messages_per_page": 5, "signature": "Saved signature", "theme": "dark"});
        let path = fixture.write_settings(&original.to_string());
        let previous = fs::read(&path).unwrap();
        for invalid in [
            json!(null),
            json!(true),
            json!(42),
            json!([]),
            json!({}),
            json!("a".repeat(MAX_SIGNATURE_LENGTH + 1)),
            json!("bad\0text"),
            json!("bad\u{1}text"),
            json!("bad\u{7f}text"),
        ] {
            let update = MailPreferencesUpdate {
                signature: Some(invalid.clone()),
                ..Default::default()
            };
            let error = save_mail_preferences(&json!(10), &update).unwrap_err();
            assert!(
                error.to_string().contains("signature"),
                "{invalid}: {error}"
            );
            assert_eq!(fs::read(&path).unwrap(), previous);
            let mut malformed = original.clone();
            malformed["signature"] = invalid.clone();
            let malformed = malformed.to_string();
            fixture.write_settings(&malformed);
            assert!(load_mail_preferences()
                .unwrap_err()
                .to_string()
                .contains("signature"));
            assert!(save_count(json!(10))
                .unwrap_err()
                .to_string()
                .contains("signature"));
            assert_eq!(fs::read(&path).unwrap(), malformed.as_bytes());
            fs::write(&path, &previous).unwrap();
        }
    }

    #[test]
    fn expiration_and_model_updates_are_validated_and_persisted() {
        let fixture = Fixture::new();
        let path = fixture.write_settings(r#"{"theme": "dark"}"#);
        let update = MailPreferencesUpdate {
            category_expiration_days: Some(json!({
                "marketing": -4, "transactional": 2, "updates": 3, "verification": 4, "uncategorized": 5,
            })),
            local_ai_model: Some(json!("qwen2.5:7b")),
            ..Default::default()
        };
        let saved = save_mail_preferences(&json!(9), &update).unwrap();
        assert_eq!(saved.category_expiration_days["marketing"], -1);
        assert_eq!(saved.local_ai_model, "qwen2.5:7b");
        assert_eq!(load_mail_preferences().unwrap(), saved);
        assert_eq!(
            read_value(&path)["category_expiration_days"]["marketing"],
            json!(-1)
        );

        let previous = fs::read(&path).unwrap();
        for (field, value) in [
            ("category_expiration_days", json!({"marketing": 1})),
            ("local_ai_model", json!("gpt-oss:20b-cloud")),
        ] {
            let mut update = MailPreferencesUpdate::default();
            if field == "local_ai_model" {
                update.local_ai_model = Some(value);
            } else {
                update.category_expiration_days = Some(value);
            }
            let error = save_mail_preferences(&json!(9), &update).unwrap_err();
            assert!(error.to_string().contains(field), "{error}");
            assert_eq!(fs::read(&path).unwrap(), previous);
        }
    }

    #[test]
    fn category_expiration_days_follow_email_categories_order() {
        let fixture = Fixture::new();
        let path = fixture.write_settings(r#"{"theme": "dark", "messages_per_page": 4}"#);
        let order: Vec<String> = EMAIL_CATEGORIES.iter().map(|c| c.to_string()).collect();
        let keys =
            |value: &Value| -> Vec<String> { value.as_object().unwrap().keys().cloned().collect() };
        // Response body (GET/PUT /api/settings) in category order.
        let loaded = serde_json::to_value(load_mail_preferences().unwrap()).unwrap();
        assert_eq!(keys(&loaded["category_expiration_days"]), order);
        assert_eq!(
            keys(&loaded),
            [
                "messages_per_page",
                "signature",
                "category_expiration_days",
                "local_ai_model"
            ]
        );
        // Reverse input order is stored and returned in category order.
        let update = MailPreferencesUpdate {
            category_expiration_days: Some(json!({
                "uncategorized": 5, "verification": 4, "updates": 3, "transactional": 2, "marketing": 1,
            })),
            ..Default::default()
        };
        let saved =
            serde_json::to_value(save_mail_preferences(&json!(9), &update).unwrap()).unwrap();
        assert_eq!(keys(&saved["category_expiration_days"]), order);
        let stored = read_value(&path);
        assert_eq!(keys(&stored["category_expiration_days"]), order);
        // Existing keys keep their positions; new keys are appended.
        assert_eq!(
            keys(&stored),
            ["theme", "messages_per_page", "category_expiration_days"]
        );
    }

    #[test]
    fn local_ai_model_validation_messages() {
        assert_eq!(
            validate_local_ai_model("llama3.2:latest").unwrap(),
            "llama3.2:latest"
        );
        assert_eq!(
            validate_local_ai_model("library/qwen2.5:7b").unwrap(),
            "library/qwen2.5:7b"
        );
        for (value, message) in [
            (
                "",
                "Local AI model must be a model name of at most 200 characters",
            ),
            (
                "-bad",
                "Local AI model must be a model name of at most 200 characters",
            ),
            (
                "bad model",
                "Local AI model must be a model name of at most 200 characters",
            ),
            (
                "gpt-oss:120b-cloud",
                "Choose a locally installed model, not a cloud model",
            ),
            (
                "CLOUD",
                "Choose a locally installed model, not a cloud model",
            ),
            (
                "a/cloud/b",
                "Choose a locally installed model, not a cloud model",
            ),
            ("http://x", "Local AI model must be a model identifier"),
            ("a..b", "Local AI model must be a model identifier"),
        ] {
            assert_eq!(
                validate_local_ai_model(value).unwrap_err(),
                message,
                "{value}"
            );
        }
        assert!(validate_local_ai_model(&"a".repeat(200)).is_ok());
        assert!(validate_local_ai_model(&"a".repeat(201)).is_err());
        assert!(validate_local_ai_model("cloudy").is_ok());
        assert!(validate_local_ai_model_value(&json!(null)).is_err());
    }

    // -- PortSettingsTests ---------------------------------------------------

    struct PortFixture {
        fixture: Fixture,
        mapping_path: PathBuf,
        defaults: PortMapping,
    }

    impl PortFixture {
        fn new() -> Self {
            let fixture = Fixture::new();
            let mapping_path = fixture.root.join("project").join("port_mapping.json");
            fs::create_dir_all(mapping_path.parent().unwrap()).unwrap();
            fs::write(
                &mapping_path,
                r#"{"frontend_port": 4310, "backend_port": 4320}"#,
            )
            .unwrap();
            Self {
                fixture,
                mapping_path,
                defaults: PortMapping {
                    frontend_port: 4310,
                    backend_port: 4320,
                },
            }
        }
    }

    #[test]
    fn mapping_reads_defaults_ignoring_other_keys_and_accepts_boundaries() {
        let ports = PortFixture::new();
        fs::write(
            &ports.mapping_path,
            r#"{"frontend_port": 4310, "backend_port": 4320, "application_name": "example"}"#,
        )
        .unwrap();
        assert_eq!(
            load_port_mapping(&ports.mapping_path).unwrap(),
            ports.defaults
        );
        assert!(!settings_path().exists());
        fs::write(
            &ports.mapping_path,
            r#"{"frontend_port": 1, "backend_port": 65535}"#,
        )
        .unwrap();
        assert_eq!(
            load_port_mapping(&ports.mapping_path).unwrap(),
            PortMapping {
                frontend_port: 1,
                backend_port: 65535
            }
        );
    }

    #[test]
    fn first_initialization_creates_settings_with_ports() {
        let ports = PortFixture::new();
        assert_eq!(
            initialize_port_settings(&ports.mapping_path).unwrap(),
            ports.defaults
        );
        let path = settings_path();
        assert_eq!(
            read_value(&path),
            json!({"frontend_port": 4310, "backend_port": 4320})
        );
        assert!(ports.fixture.temp_files().is_empty());
        assert_eq!(
            load_settings().unwrap().data_directory,
            default_data_directory()
        );
        assert_eq!(
            read_value(&path),
            json!({"frontend_port": 4310, "backend_port": 4320})
        );
    }

    #[test]
    fn partial_configuration_fills_only_missing_port() {
        let ports = PortFixture::new();
        for existing in ["frontend_port", "backend_port"] {
            let mut original = json!({
                "data_directory": "../saved-data",
                "theme": {"color": "blue", "enabled": true},
                "custom": [1, "two", null],
            });
            original[existing] = json!(4500);
            let path = ports.fixture.write_settings(&original.to_string());
            let mut expected = PortMapping { ..ports.defaults };
            if existing == "frontend_port" {
                expected.frontend_port = 4500;
            } else {
                expected.backend_port = 4500;
            }
            assert_eq!(
                initialize_port_settings(&ports.mapping_path).unwrap(),
                expected
            );
            let mut on_disk = original.clone();
            on_disk["frontend_port"] = json!(expected.frontend_port);
            on_disk["backend_port"] = json!(expected.backend_port);
            assert_eq!(read_value(&path), on_disk);
        }
    }

    #[test]
    fn complete_configuration_preserves_custom_ports_formatting_and_bom() {
        let ports = PortFixture::new();
        let content = "{\n \"frontend_port\": 4510, \"backend_port\": 4520,\n \"data_directory\": \"../saved-data\", \"theme\": \"dark\"\n}\n";
        let path = ports.fixture.write_settings(content);
        for _ in 0..2 {
            assert_eq!(
                initialize_port_settings(&ports.mapping_path).unwrap(),
                PortMapping {
                    frontend_port: 4510,
                    backend_port: 4520
                }
            );
            assert_eq!(fs::read(&path).unwrap(), content.as_bytes());
        }
        fs::write(
            &ports.mapping_path,
            "\u{feff}{\"frontend_port\": 4310, \"backend_port\": 4320}",
        )
        .unwrap();
        let bom = "\u{feff}{\"frontend_port\": 4510, \"backend_port\": 4520}";
        let path = ports.fixture.write_settings(bom);
        assert_eq!(
            load_port_mapping(&ports.mapping_path).unwrap(),
            ports.defaults
        );
        assert_eq!(
            initialize_port_settings(&ports.mapping_path).unwrap(),
            PortMapping {
                frontend_port: 4510,
                backend_port: 4520
            }
        );
        assert_eq!(fs::read(&path).unwrap(), bom.as_bytes());
    }

    #[test]
    fn existing_data_settings_gain_ports_without_changing_data_directory() {
        let ports = PortFixture::new();
        let loaded = load_settings().unwrap();
        assert_eq!(
            initialize_port_settings(&ports.mapping_path).unwrap(),
            ports.defaults
        );
        assert_eq!(
            read_value(&loaded.settings_path),
            json!({
                "data_directory": loaded.data_directory.to_string_lossy(),
                "frontend_port": 4310, "backend_port": 4320,
            })
        );
    }

    #[test]
    fn malformed_settings_and_invalid_ports_are_preserved() {
        let ports = PortFixture::new();
        for content in ["{broken", "null", "[]", "\"text\"", "true"] {
            let path = ports.fixture.write_settings(content);
            let error = initialize_port_settings(&ports.mapping_path).unwrap_err();
            assert!(error.to_string().contains(&path.display().to_string()));
            assert_eq!(fs::read(&path).unwrap(), content.as_bytes());
        }
        for field in ["frontend_port", "backend_port"] {
            for invalid in [
                json!(null),
                json!(true),
                json!(false),
                json!("4500"),
                json!(4500.0),
                json!(0),
                json!(-1),
                json!(65536),
                json!([]),
                json!({}),
            ] {
                let content = json!({field: invalid, "theme": "dark"}).to_string();
                let path = ports.fixture.write_settings(&content);
                let error = initialize_port_settings(&ports.mapping_path)
                    .unwrap_err()
                    .to_string();
                assert!(error.contains(&path.display().to_string()), "{error}");
                assert!(error.contains(field), "{error}");
                assert_eq!(fs::read(&path).unwrap(), content.as_bytes());
            }
        }
        for content in [
            r#"{"frontend_port": 4500, "backend_port": 4500}"#,
            r#"{"frontend_port": 4320}"#,
            r#"{"backend_port": 4310}"#,
        ] {
            let path = ports.fixture.write_settings(content);
            let error = initialize_port_settings(&ports.mapping_path)
                .unwrap_err()
                .to_string();
            assert!(
                error.contains("frontend_port") && error.contains("backend_port"),
                "{error}"
            );
            assert_eq!(fs::read(&path).unwrap(), content.as_bytes());
        }
    }

    #[test]
    fn invalid_or_missing_mapping_never_creates_user_settings() {
        let ports = PortFixture::new();
        let mut invalid: Vec<(String, Option<&str>)> = vec![
            ("{broken".into(), None),
            ("null".into(), None),
            ("[]".into(), None),
            ("{}".into(), Some("frontend_port")),
            (r#"{"frontend_port": 4310}"#.into(), Some("backend_port")),
            (
                r#"{"frontend_port": 4310, "backend_port": 4310}"#.into(),
                Some("backend_port"),
            ),
        ];
        for field in ["frontend_port", "backend_port"] {
            for value in [
                json!(null),
                json!(true),
                json!(false),
                json!("4500"),
                json!(4500.0),
                json!(0),
                json!(-1),
                json!(65536),
                json!([]),
                json!({}),
            ] {
                let mut mapping = json!({"frontend_port": 4310, "backend_port": 4320});
                mapping[field] = value;
                invalid.push((mapping.to_string(), Some(field)));
            }
        }
        for (content, field) in invalid {
            fs::write(&ports.mapping_path, &content).unwrap();
            let error = initialize_port_settings(&ports.mapping_path)
                .unwrap_err()
                .to_string();
            assert!(
                error.contains(&ports.mapping_path.display().to_string()),
                "{error}"
            );
            if let Some(field) = field {
                assert!(error.contains(field), "{error}");
            }
            assert!(!settings_path().exists());
            assert_eq!(fs::read_to_string(&ports.mapping_path).unwrap(), content);
        }
        let missing = ports.fixture.root.join("missing_mapping.json");
        let error = initialize_port_settings(&missing).unwrap_err().to_string();
        assert!(error.contains(&missing.display().to_string()));
        assert!(!settings_path().exists());

        let content = "{ \"theme\": \"dark\" }\n";
        let path = ports.fixture.write_settings(content);
        fs::write(&ports.mapping_path, "{}").unwrap();
        assert!(initialize_port_settings(&ports.mapping_path).is_err());
        assert_eq!(fs::read(&path).unwrap(), content.as_bytes());
    }

    #[test]
    fn initialization_is_idempotent() {
        let ports = PortFixture::new();
        let first = initialize_port_settings(&ports.mapping_path).unwrap();
        let original = fs::read(settings_path()).unwrap();
        assert_eq!(
            initialize_port_settings(&ports.mapping_path).unwrap(),
            first
        );
        assert_eq!(fs::read(settings_path()).unwrap(), original);
    }
}
