//! Per-account rich signatures with atomic settings and raster asset storage
//! (port of `app/mail/signatures.py`).
//!
//! * [`sanitize_html`] is the strict whitelist `_Sanitizer`, driven by a port
//!   of CPython 3.14's `html.parser.HTMLParser` ([`html_parser`]) so tags,
//!   attributes, character references and escaping come out byte-identical.
//! * Signatures live in `settings.json` under `emails_signatures` (keyed by
//!   the trimmed, lowercased account); images live next to it under
//!   `signature-images/<sha256(account)>/<revision>/<content_id>.<ext>`.
//!   Every reader and writer holds [`settings::settings_lock`].
//! * Errors: Python's `SettingsError` is [`MailError::Settings`] (HTTP 500);
//!   `ValueError`s raised by [`save_signature`] become
//!   [`MailError::validation`] (the route answered 422 with the message);
//!   `HTTPException`s of [`signature_image`] are [`MailError::Http`].
//!
//! The multipart request parsing (`parse_signature_uploads`) is async and
//! lives in the backend route; its JSON metadata validation is
//! [`parse_signature_metadata`]. The request size middleware is
//! `mail_backend::limits::RequestSizeLimitLayer::signature()`.
//!
//! `multipart-path` keeps the saved insertion (upload) order when read back
//! from `settings.json`, like Python's dicts (serde_json `preserve_order`).

use std::collections::BTreeSet;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use serde::ser::{Serialize, SerializeMap, Serializer};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::error::{MailError, Result};
use crate::parsing::py_strip;
use crate::schemas::{MAX_SEND_FILES, MAX_SEND_FILES_BYTES, MAX_SEND_FILE_BYTES};
use crate::send_uploads::{image_type, validate_files, MessageFile};
use crate::settings;

#[path = "signatures_parts/html_entities.rs"]
mod html_entities;
#[path = "signatures_parts/html_parser.rs"]
pub(crate) mod html_parser;

#[path = "signatures_parts/urlsplit.rs"]
mod urlsplit;

use html_parser::{escape, Attrs, Handler};

/// `MAX_SIGNATURE_HTML_BYTES`.
pub const MAX_SIGNATURE_HTML_BYTES: usize = 256 * 1024;
/// `MAX_SIGNATURE_JSON_BYTES`: the multipart `signature` metadata part.
pub const MAX_SIGNATURE_JSON_BYTES: usize = MAX_SIGNATURE_HTML_BYTES * 6 + 16 * 1024;
/// `MAX_SIGNATURE_REQUEST_BYTES`: the whole multipart request.
pub const MAX_SIGNATURE_REQUEST_BYTES: usize =
    MAX_SEND_FILES_BYTES + MAX_SIGNATURE_JSON_BYTES + 64 * 1024;
/// `EXTENSIONS` (in Python's dict order).
pub const EXTENSIONS: [(&str, &str); 5] = [
    ("image/png", "png"),
    ("image/jpeg", "jpg"),
    ("image/gif", "gif"),
    ("image/webp", "webp"),
    ("image/bmp", "bmp"),
];

const TAGS: [&str; 19] = [
    "b",
    "strong",
    "i",
    "em",
    "u",
    "s",
    "strike",
    "p",
    "div",
    "br",
    "span",
    "blockquote",
    "ul",
    "ol",
    "li",
    "pre",
    "code",
    "a",
    "img",
];
const VOID: [&str; 14] = [
    "br", "img", "hr", "input", "meta", "link", "base", "area", "source", "wbr", "embed", "param",
    "track", "col",
];
const SUPPRESS: [&str; 12] = [
    "script", "style", "iframe", "object", "svg", "math", "template", "textarea", "title", "xmp",
    "noembed", "noscript",
];
const RESERVED_DEVICE_NAMES: [&str; 4] = ["con", "prn", "aux", "nul"];

fn extension_of(content_type: &str) -> Option<&'static str> {
    EXTENSIONS
        .iter()
        .find(|(kind, _)| *kind == content_type)
        .map(|(_, extension)| *extension)
}

/// `_RESERVED_FILENAMES`: Windows device names (`con`, `com1`..`com9`, ...).
fn is_reserved_filename(stem: &str) -> bool {
    if RESERVED_DEVICE_NAMES.contains(&stem) {
        return true;
    }
    let bytes = stem.as_bytes();
    bytes.len() == 4
        && (stem.starts_with("com") || stem.starts_with("lpt"))
        && (b'1'..=b'9').contains(&bytes[3])
}

/// `CONTENT_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,99}")` (full match).
fn content_id_pattern(value: &str) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 100
        && bytes[0].is_ascii_alphanumeric()
        && bytes[1..]
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'))
}

/// `REVISION = re.compile(r"[0-9a-f]{32}")` (full match).
pub fn is_revision(value: &str) -> bool {
    value.len() == 32
        && value
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// `_valid_content_id`.
pub fn valid_content_id(value: &str) -> bool {
    content_id_pattern(value)
        && !is_reserved_filename(&value.split('.').next().unwrap_or_default().to_lowercase())
}

/// `_valid_text` for a string; `Err` holds the `ValueError` message.
fn valid_text(value: &str) -> std::result::Result<(), String> {
    let invalid = value
        .chars()
        .any(|c| ((c as u32) < 32 && !matches!(c, '\t' | '\n' | '\r')) || c as u32 == 127);
    if invalid {
        return Err("Signature must be valid Unicode without control characters".into());
    }
    if value.len() > MAX_SIGNATURE_HTML_BYTES {
        return Err("Signature HTML must be no larger than 256 KiB".into());
    }
    Ok(())
}

/// `_safe_link`: `mailto:`/`tel:` or an `http(s)` URL with a host and no
/// user information, as judged by `urllib.parse.urlsplit`.
fn safe_link(value: &str) -> bool {
    if value.is_empty()
        || value.chars().count() > 8192
        || value.chars().any(|c| c as u32 <= 32 || c as u32 == 127)
        || value.contains('\\')
    {
        return false;
    }
    let Some(parsed) = urlsplit::urlsplit(value) else {
        return false;
    };
    match parsed.scheme.as_str() {
        "mailto" | "tel" => true,
        "http" | "https" => !parsed.hostname().is_empty() && !parsed.netloc.contains('@'),
        _ => false,
    }
}

/// `_Sanitizer`.
#[derive(Default)]
struct Sanitizer {
    parts: String,
    stack: Vec<String>,
    suppressed: Vec<String>,
    content_ids: BTreeSet<String>,
    visible: bool,
}

fn attribute<'a>(attrs: &'a Attrs, name: &str) -> Option<&'a Option<String>> {
    // dict(attrs): the last duplicate wins.
    attrs
        .iter()
        .rev()
        .find(|(key, _)| key == name)
        .map(|(_, value)| value)
}

impl Handler for Sanitizer {
    type Error = String;

    fn start_tag(&mut self, tag: &str, attrs: &Attrs) -> std::result::Result<(), String> {
        if !self.suppressed.is_empty() {
            if !VOID.contains(&tag) {
                self.suppressed.push(tag.to_string());
            }
            return Ok(());
        }
        if SUPPRESS.contains(&tag) {
            self.suppressed.push(tag.to_string());
            return Ok(());
        }
        if !TAGS.contains(&tag) {
            return Ok(());
        }
        let text = |name: &str| -> &str {
            attribute(attrs, name)
                .and_then(|value| value.as_deref())
                .unwrap_or("")
        };
        let mut safe: Vec<(&str, String)> = Vec::new();
        if tag == "a" && safe_link(text("href")) {
            safe.push(("href", text("href").to_string()));
            safe.push(("rel", "noopener noreferrer".into()));
        }
        if tag == "img" {
            let source = text("src");
            let Some(content_id) = source
                .strip_prefix("cid:")
                .filter(|id| valid_content_id(id))
            else {
                return Ok(());
            };
            safe.push(("src", source.to_string()));
            self.content_ids.insert(content_id.to_string());
            self.visible = true;
            for name in ["width", "height"] {
                let dimension = text(name);
                if !dimension.is_empty()
                    && dimension.len() <= 4
                    && dimension.bytes().all(|b| b.is_ascii_digit())
                {
                    let number: u32 = dimension.parse().unwrap_or(0);
                    if (1..=2000).contains(&number) {
                        safe.push((name, number.to_string()));
                    }
                }
            }
            if let Some(Some(alt)) = attribute(attrs, "alt") {
                valid_text(alt)?;
                safe.push(("alt", alt.clone()));
            }
        }
        if let Some(Some(title)) = attribute(attrs, "title") {
            valid_text(title)?;
            safe.push(("title", title.clone()));
        }
        self.parts.push('<');
        self.parts.push_str(tag);
        for (key, value) in &safe {
            self.parts.push(' ');
            self.parts.push_str(key);
            self.parts.push_str("=\"");
            self.parts.push_str(&escape(value, true));
            self.parts.push('"');
        }
        self.parts.push('>');
        if !VOID.contains(&tag) {
            self.stack.push(tag.to_string());
        }
        Ok(())
    }

    fn start_end_tag(&mut self, tag: &str, attrs: &Attrs) -> std::result::Result<(), String> {
        self.start_tag(tag, attrs)?;
        if !VOID.contains(&tag) {
            self.end_tag(tag)?;
        }
        Ok(())
    }

    fn end_tag(&mut self, tag: &str) -> std::result::Result<(), String> {
        if !self.suppressed.is_empty() {
            if let Some(index) = self.suppressed.iter().position(|item| item == tag) {
                self.suppressed.truncate(index);
            }
            return Ok(());
        }
        if self.stack.iter().any(|item| item == tag) {
            while let Some(current) = self.stack.pop() {
                self.parts.push_str("</");
                self.parts.push_str(&current);
                self.parts.push('>');
                if current == tag {
                    break;
                }
            }
        }
        Ok(())
    }

    fn data(&mut self, value: &str) -> std::result::Result<(), String> {
        if self.suppressed.is_empty() {
            valid_text(value)?;
            self.parts.push_str(&escape(value, false));
            if !py_strip(value).is_empty() {
                self.visible = true;
            }
        }
        Ok(())
    }
}

impl Sanitizer {
    fn result(mut self) -> std::result::Result<(String, BTreeSet<String>), String> {
        for tag in self.stack.iter().rev() {
            self.parts.push_str("</");
            self.parts.push_str(tag);
            self.parts.push('>');
        }
        let result = if self.visible {
            self.parts
        } else {
            String::new()
        };
        valid_text(&result)?;
        Ok((result, self.content_ids))
    }
}

/// `sanitize_html(value)`: the whitelisted HTML and its `cid:` image
/// references. `Err` holds the `ValueError` message.
pub fn sanitize_html(value: &str) -> std::result::Result<(String, BTreeSet<String>), String> {
    valid_text(value)?;
    let mut parser = Sanitizer::default();
    html_parser::parse(value, &mut parser)?;
    parser.result()
}

/// `sanitize_html` for an arbitrary JSON value (non-strings are rejected
/// with `"Signature text must be rich HTML"`).
pub fn sanitize_html_value(
    value: &Value,
) -> std::result::Result<(String, BTreeSet<String>), String> {
    match value {
        Value::String(text) => sanitize_html(text),
        _ => Err("Signature text must be rich HTML".into()),
    }
}

/// The JSON metadata part of `parse_signature_uploads`: the sanitized HTML
/// and the declared image content IDs, in order. `None` means Python's 422
/// `"Check the signature HTML, size, and image metadata"`.
pub fn parse_signature_metadata(metadata: &str) -> Option<(String, Vec<String>)> {
    let body: Value = serde_json::from_str(metadata).ok()?;
    let body = body.as_object()?;
    if body.len() != 2 || !body.contains_key("text") {
        return None;
    }
    let uploads = body.get("uploads")?.as_array()?;
    if uploads.len() > MAX_SEND_FILES {
        return None;
    }
    let (text, _) = sanitize_html_value(&body["text"]).ok()?;
    let mut identifiers = Vec::with_capacity(uploads.len());
    for upload in uploads {
        let upload = upload.as_object()?;
        let content_id = upload.get("content_id")?.as_str()?;
        if upload.len() != 1 || !valid_content_id(content_id) {
            return None;
        }
        identifiers.push(content_id.to_string());
    }
    let lowered: BTreeSet<String> = identifiers.iter().map(|id| id.to_lowercase()).collect();
    if lowered.len() != identifiers.len() {
        return None;
    }
    Some((text, identifiers))
}

// ---------------------------------------------------------------------------
// Storage
// ---------------------------------------------------------------------------

/// One entry of the `images` list of a signature response.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct SignatureImage {
    pub content_id: String,
    pub filename: String,
    pub content_type: String,
    pub url: String,
}

/// The signature dict returned by `load_signature` / `save_signature`:
/// `{"account", "text", "multipart-path": {cid: relative path}, "images"}`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signature {
    pub account: String,
    pub text: String,
    /// `content_id -> path relative to the settings folder`, in order.
    pub multipart_path: Vec<(String, String)>,
    pub images: Vec<SignatureImage>,
}

struct OrderedMap<'a>(&'a [(String, String)]);

impl Serialize for OrderedMap<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(self.0.len()))?;
        for (key, value) in self.0 {
            map.serialize_entry(key, value)?;
        }
        map.end()
    }
}

impl Serialize for Signature {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(4))?;
        map.serialize_entry("account", &self.account)?;
        map.serialize_entry("text", &self.text)?;
        map.serialize_entry("multipart-path", &OrderedMap(&self.multipart_path))?;
        map.serialize_entry("images", &self.images)?;
        map.end()
    }
}

/// A validated saved record (`{"text", "multipart-path"}`).
struct Record {
    text: String,
    multipart_path: Vec<(String, String)>,
}

impl Record {
    fn to_value(&self) -> Value {
        let paths: Map<String, Value> = self
            .multipart_path
            .iter()
            .map(|(cid, path)| (cid.clone(), Value::from(path.as_str())))
            .collect();
        let mut record = Map::new();
        record.insert("text".into(), Value::from(self.text.as_str()));
        record.insert("multipart-path".into(), Value::Object(paths));
        Value::Object(record)
    }
}

fn settings_error(message: impl Into<String>) -> MailError {
    MailError::Settings(message.into())
}

/// `_account_key`.
fn account_key(account: &str) -> String {
    py_strip(account).to_lowercase()
}

/// `Path.resolve()`.
fn resolve(path: &Path) -> PathBuf {
    settings::resolve_path(path).unwrap_or_else(|_| path.to_path_buf())
}

/// `path.parent.resolve()`.
fn settings_folder(path: &Path) -> PathBuf {
    resolve(path.parent().unwrap_or_else(|| Path::new(".")))
}

/// `_account_root`.
fn account_root(path: &Path, account: &str) -> PathBuf {
    let digest = hex::encode(Sha256::digest(account_key(account).as_bytes()));
    settings_folder(path).join("signature-images").join(digest)
}

/// `PurePath.relative_to` succeeds (case-insensitive on Windows).
fn is_within(path: &Path, root: &Path) -> bool {
    #[cfg(windows)]
    {
        let parts = |p: &Path| -> Vec<String> {
            p.components()
                .map(|c| c.as_os_str().to_string_lossy().to_lowercase())
                .collect()
        };
        let (path, root) = (parts(path), parts(root));
        path.len() >= root.len() && path[..root.len()] == root[..]
    }
    #[cfg(not(windows))]
    {
        path.starts_with(root)
    }
}

/// `_confined`.
fn confined(path: &Path, root: &Path) -> Result<PathBuf> {
    let resolved = resolve(path);
    if !is_within(&resolved, root) {
        return Err(settings_error(
            "Signature images must stay inside their account's storage folder",
        ));
    }
    Ok(resolved)
}

/// `PurePosixPath(value).parts`.
fn posix_parts(value: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let rest = if value.starts_with("//") && !value.starts_with("///") {
        parts.push("//");
        &value[2..]
    } else if value.starts_with('/') {
        parts.push("/");
        value.trim_start_matches('/')
    } else {
        value
    };
    parts.extend(
        rest.split('/')
            .filter(|part| !part.is_empty() && *part != "."),
    );
    parts
}

/// `_asset_path`.
fn asset_path(path: &Path, account: &str, content_id: &str, relative: &Value) -> Result<PathBuf> {
    let relative = match relative {
        Value::String(relative) if !relative.contains('\\') && valid_content_id(content_id) => {
            relative
        }
        _ => return Err(settings_error("Invalid signature image path")),
    };
    let parts = posix_parts(relative);
    let root = account_root(path, account);
    let root_name = root
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    if parts.len() != 4
        || parts[0] != "signature-images"
        || parts[1] != root_name
        || !is_revision(parts[2])
    {
        return Err(settings_error(
            "Signature image path does not belong to this account",
        ));
    }
    if !EXTENSIONS
        .iter()
        .any(|(_, extension)| parts[3] == format!("{content_id}.{extension}"))
    {
        return Err(settings_error("Invalid signature image filename"));
    }
    confined(&settings_folder(path).join(relative), &root)
}

/// `_read_asset`.
fn read_asset(path: &Path) -> Result<(Vec<u8>, &'static str)> {
    let cannot_read = || settings_error("Cannot read saved signature image");
    let mut content = Vec::new();
    fs::File::open(path)
        .and_then(|file| {
            file.take(MAX_SEND_FILE_BYTES as u64 + 1)
                .read_to_end(&mut content)
        })
        .map_err(|_| cannot_read())?;
    if content.len() > MAX_SEND_FILE_BYTES {
        return Err(settings_error("Saved signature image exceeds 10 MiB"));
    }
    let content_type = image_type(&content).ok_or_else(cannot_read)?;
    let expected = extension_of(content_type).unwrap_or_default();
    if path.extension().and_then(|value| value.to_str()) != Some(expected) {
        return Err(settings_error(
            "Saved signature image type does not match its filename",
        ));
    }
    Ok((content, content_type))
}

/// `values.get("emails_signatures", {})`, which must be an object.
fn saved_signatures(values: &Map<String, Value>) -> Result<Map<String, Value>> {
    match values.get("emails_signatures") {
        None => Ok(Map::new()),
        Some(Value::Object(signatures)) => Ok(signatures.clone()),
        Some(_) => Err(settings_error("Invalid emails_signatures in settings")),
    }
}

/// `_record`.
fn record(values: &Map<String, Value>, account: &str, path: &Path) -> Result<Record> {
    let signatures = saved_signatures(values)?;
    let Some(saved) = signatures.get(account) else {
        return Ok(Record {
            text: String::new(),
            multipart_path: Vec::new(),
        });
    };
    let invalid = || settings_error("Invalid saved email signature");
    let saved = saved.as_object().ok_or_else(invalid)?;
    if saved.len() != 2 || !saved.contains_key("text") {
        return Err(invalid());
    }
    let paths = saved
        .get("multipart-path")
        .and_then(Value::as_object)
        .ok_or_else(invalid)?;
    let (sanitized, references) = sanitize_html_value(&saved["text"])
        .map_err(|error| settings_error(format!("Invalid saved email signature: {error}")))?;
    let keys: BTreeSet<String> = paths.keys().cloned().collect();
    let lowered: BTreeSet<String> = references.iter().map(|id| id.to_lowercase()).collect();
    if keys != references || references.len() > MAX_SEND_FILES || lowered.len() != references.len()
    {
        return Err(settings_error(
            "Saved signature images do not match its HTML",
        ));
    }
    let mut multipart_path = Vec::with_capacity(paths.len());
    for (content_id, relative) in paths {
        asset_path(path, account, content_id, relative)?;
        multipart_path.push((
            content_id.clone(),
            relative.as_str().unwrap_or_default().to_string(),
        ));
    }
    Ok(Record {
        text: sanitized,
        multipart_path,
    })
}

/// `urllib.parse.quote_plus` (safe: letters, digits, `_.-~`).
fn quote_plus(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'_' | b'.' | b'-' | b'~' => {
                out.push(byte as char)
            }
            b' ' => out.push('+'),
            other => out.push_str(&format!("%{other:02X}")),
        }
    }
    out
}

/// `_response`.
fn response(path: &Path, account: &str, record: Record) -> Result<Signature> {
    let mut images = Vec::with_capacity(record.multipart_path.len());
    let mut total = 0usize;
    for (content_id, relative) in &record.multipart_path {
        let asset = asset_path(path, account, content_id, &Value::from(relative.as_str()))?;
        let (data, content_type) = read_asset(&asset)?;
        total += data.len();
        if total > MAX_SEND_FILES_BYTES {
            return Err(settings_error("Saved signature images exceed 20 MiB"));
        }
        let name = |p: Option<&std::ffi::OsStr>| {
            p.map(|name| name.to_string_lossy().into_owned())
                .unwrap_or_default()
        };
        let revision = name(asset.parent().and_then(Path::file_name));
        images.push(SignatureImage {
            content_id: content_id.clone(),
            filename: name(asset.file_name()),
            content_type: content_type.to_string(),
            url: format!(
                "/api/mail/signature/image?account={}&content_id={}&revision={}",
                quote_plus(account),
                quote_plus(content_id),
                quote_plus(&revision)
            ),
        });
    }
    Ok(Signature {
        account: account.to_string(),
        text: record.text,
        multipart_path: record.multipart_path,
        images,
    })
}

/// `load_signature(account)`: the account's signature, migrating the old
/// global plain-text signature into this account on first use.
pub fn load_signature(account: &str) -> Result<Signature> {
    let account = account_key(account);
    let path = settings::settings_path();
    let _guard = settings::settings_lock();
    let mut values = settings::read_settings_object(&path)?;
    let mut signatures = saved_signatures(&values)?;
    let legacy = match values.get("signature") {
        Some(Value::String(text)) if !py_strip(text).is_empty() => Some(text.clone()),
        _ => None,
    };
    if let (false, Some(legacy)) = (signatures.contains_key(&account), legacy) {
        let migrate_error = || settings_error("Cannot migrate the existing email signature");
        let legacy = settings::validate_signature(&legacy).map_err(|_| migrate_error())?;
        let escaped = escape(&legacy, true)
            .replace("\r\n", "\n")
            .replace('\r', "\n")
            .replace('\n', "<br>");
        let (text, _) =
            sanitize_html(&format!("<div>{escaped}</div>")).map_err(|_| migrate_error())?;
        let migrated = Record {
            text,
            multipart_path: Vec::new(),
        };
        signatures.insert(account.clone(), migrated.to_value());
        values.insert("emails_signatures".into(), Value::Object(signatures));
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|_| migrate_error())?;
        }
        settings::write_json(&path, &Value::Object(values.clone()), true)
            .map_err(|_| migrate_error())?;
    }
    let saved = record(&values, &account, &path)?;
    response(&path, &account, saved)
}

fn save_error() -> MailError {
    settings_error("Cannot save the email signature")
}

/// `save_signature(account, text, images)`: sanitize, validate, stage the
/// images under a fresh revision and publish the settings last, so a
/// failure keeps the previous signature (prior revisions are retained for
/// open compose windows).
pub fn save_signature(account: &str, text: &str, images: &[MessageFile]) -> Result<Signature> {
    let account = account_key(account);
    let (text, references) = sanitize_html(text).map_err(MailError::validation)?;
    let images = validate_files(&text, images).map_err(MailError::validation)?;
    if images
        .iter()
        .any(|image| image.disposition != "inline" || !valid_content_id(&image.content_id))
    {
        return Err(MailError::validation(
            "Signature images require valid inline content IDs",
        ));
    }
    let lowered: BTreeSet<String> = images
        .iter()
        .map(|image| image.content_id.to_lowercase())
        .collect();
    if lowered.len() != images.len() {
        return Err(MailError::validation(
            "Signature image content IDs must be unique regardless of letter case",
        ));
    }
    let identifiers: BTreeSet<String> = images
        .iter()
        .map(|image| image.content_id.clone())
        .collect();
    if identifiers != references {
        return Err(MailError::validation(
            "Every signature image must match an HTML cid reference",
        ));
    }
    let path = settings::settings_path();
    let _guard = settings::settings_lock();
    let mut stage = None;
    let result = save_locked(&path, &account, text, &images, &mut stage);
    if let (Err(_), Some(stage)) = (&result, stage) {
        if let Ok(safe_stage) = confined(&stage, &account_root(&path, &account)) {
            if safe_stage.exists() {
                let _ = fs::remove_dir_all(&safe_stage);
            }
        }
    }
    result
}

fn save_locked(
    path: &Path,
    account: &str,
    text: String,
    images: &[MessageFile],
    stage: &mut Option<PathBuf>,
) -> Result<Signature> {
    let mut values = settings::read_settings_object(path)?;
    let mut signatures = saved_signatures(&values)?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|_| save_error())?;
    }
    let mut paths = Vec::with_capacity(images.len());
    if !images.is_empty() {
        let root = account_root(path, account);
        let staged = confined(&root.join(uuid::Uuid::new_v4().simple().to_string()), &root)?;
        *stage = Some(staged.clone());
        // stage.mkdir(parents=True, exist_ok=False)
        if let Some(parent) = staged.parent() {
            fs::create_dir_all(parent).map_err(|_| save_error())?;
        }
        fs::create_dir(&staged).map_err(|_| save_error())?;
        let folder = settings_folder(path);
        for image in images {
            let extension = extension_of(&image.content_type).ok_or_else(save_error)?;
            let asset = confined(
                &staged.join(format!("{}.{extension}", image.content_id)),
                &root,
            )?;
            fs::write(&asset, &image.data).map_err(|_| save_error())?;
            let relative = asset.strip_prefix(&folder).map_err(|_| save_error())?;
            let relative: Vec<String> = relative
                .components()
                .map(|part| part.as_os_str().to_string_lossy().into_owned())
                .collect();
            paths.push((image.content_id.clone(), relative.join("/")));
        }
    }
    let saved = Record {
        text,
        multipart_path: paths,
    };
    signatures.insert(account.to_string(), saved.to_value());
    values.insert("emails_signatures".into(), Value::Object(signatures));
    let signature = response(path, account, saved)?;
    settings::write_json(path, &Value::Object(values), true).map_err(|_| save_error())?;
    Ok(signature)
}

/// `signature_image(account, content_id, revision)`: the stored image bytes
/// and their sniffed content type.
pub fn signature_image(
    account: &str,
    content_id: &str,
    revision: &str,
) -> Result<(Vec<u8>, &'static str)> {
    if !valid_content_id(content_id) || (!revision.is_empty() && !is_revision(revision)) {
        return Err(MailError::bad_request("Invalid signature image identifier"));
    }
    let account = account_key(account);
    let path = settings::settings_path();
    let _guard = settings::settings_lock();
    let values = settings::read_settings_object(&path)?;
    let saved = record(&values, &account, &path)?;
    let relative = saved
        .multipart_path
        .iter()
        .find(|(cid, _)| cid == content_id)
        .map(|(_, relative)| relative.clone());
    let not_found = || MailError::not_found("Signature image not found");
    let asset = if !revision.is_empty() {
        // A revision is an opaque token returned in this account's own image
        // URL. Construct only one safe filename per supported extension.
        let root = account_root(&path, &account);
        let mut matches = Vec::new();
        for (_, extension) in EXTENSIONS {
            let candidate = confined(
                &root
                    .join(revision)
                    .join(format!("{content_id}.{extension}")),
                &root,
            )?;
            if candidate.is_file() {
                matches.push(candidate);
            }
        }
        if matches.len() != 1 {
            return Err(not_found());
        }
        matches.remove(0)
    } else if let Some(relative) = relative {
        asset_path(&path, &account, content_id, &Value::from(relative))?
    } else {
        return Err(not_found());
    };
    read_asset(&asset)
}

/// `_account_root(settings_path, account)` (exposed for tests).
pub fn account_root_for(settings_path: &Path, account: &str) -> PathBuf {
    account_root(settings_path, account)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn clean(html: &str) -> String {
        sanitize_html(html).unwrap().0
    }

    #[test]
    fn content_ids_and_revisions() {
        assert!(valid_content_id("attach1"));
        assert!(valid_content_id("a.b-c_d"));
        assert!(!valid_content_id("CON"));
        assert!(!valid_content_id("nul.logo"));
        assert!(!valid_content_id("com7"));
        assert!(valid_content_id("com0"));
        assert!(valid_content_id("com10"));
        assert!(!valid_content_id("../secret"));
        assert!(!valid_content_id(".x"));
        assert!(!valid_content_id(&"a".repeat(101)));
        assert!(valid_content_id(&"a".repeat(100)));
        assert!(is_revision(&"0a".repeat(16)));
        assert!(!is_revision(&"A".repeat(32)));
    }

    #[test]
    fn safe_links_follow_urlsplit() {
        assert!(safe_link("https://example.com"));
        assert!(safe_link("HTTP://Example.com/path?q#f"));
        assert!(safe_link("mailto:someone@example.com"));
        assert!(safe_link("tel:+1555"));
        assert!(safe_link("http://[::1]:80/"));
        assert!(!safe_link("http://[::1/"));
        assert!(!safe_link("http://[127.0.0.1]/"));
        assert!(!safe_link("https://user@example.com"));
        assert!(!safe_link("https:///path"));
        assert!(!safe_link("javascript:alert(1)"));
        assert!(!safe_link("//example.com"));
        assert!(!safe_link("https://exa mple.com"));
        assert!(!safe_link("https://example.com\\x"));
        assert!(!safe_link("https://example\u{2100}.com"));
        assert!(!safe_link(""));
    }

    #[test]
    fn sanitizer_output_matches_python() {
        assert_eq!(clean("<p><b>Thanks</b></p>"), "<p><b>Thanks</b></p>");
        assert_eq!(
            clean(r#"<a href="https://example.com/?a=1&amp;b=2" onclick="x" title='T"'>L</a>"#),
            r#"<a href="https://example.com/?a=1&amp;b=2" rel="noopener noreferrer" title="T&quot;">L</a>"#
        );
        assert_eq!(clean(r#"<a href="javascript:x">L</a>"#), "<a>L</a>");
        assert_eq!(
            clean(r#"<img src="cid:a1" width="0200" height="2001" alt="A&lt;">"#),
            r#"<img src="cid:a1" width="200" alt="A&lt;">"#
        );
        assert_eq!(clean(r#"<img src="https://t.example/x">x"#), "x");
        assert_eq!(clean("<p><br></p><div>\u{a0}</div>"), "");
        assert_eq!(clean("<p>&nbsp;</p>"), "");
        assert_eq!(clean("a<script>b</script><style>c</style>d"), "ad");
        assert_eq!(clean("<svg><a>x</a></svg>y"), "y");
        assert_eq!(clean("<div><span>open"), "<div><span>open</span></div>");
        assert_eq!(clean("<b><i>x</b>y</i>"), "<b><i>x</i></b>y");
        assert_eq!(clean("<b/>x<br/>"), "<b></b>x<br>");
        assert_eq!(clean("a &lt; b & c > d"), "a &lt; b &amp; c &gt; d");
        assert_eq!(clean("<unknown>x</unknown>"), "x");
        assert_eq!(
            clean("<noframes><b>x</b></noframes>"),
            "&lt;b&gt;x&lt;/b&gt;"
        );
        assert_eq!(
            sanitize_html(r#"<img src="cid:one"><img src="cid:two">"#)
                .unwrap()
                .1,
            BTreeSet::from(["one".to_string(), "two".to_string()])
        );
        assert_eq!(
            sanitize_html("\u{1}").unwrap_err(),
            "Signature must be valid Unicode without control characters"
        );
        assert_eq!(
            sanitize_html("x&#1;y").unwrap().0,
            "xy",
            "invalid code points are dropped by html.unescape"
        );
        assert_eq!(
            sanitize_html_value(&Value::Null).unwrap_err(),
            "Signature text must be rich HTML"
        );
        assert_eq!(
            sanitize_html(&"x".repeat(MAX_SIGNATURE_HTML_BYTES + 1)).unwrap_err(),
            "Signature HTML must be no larger than 256 KiB"
        );
    }

    #[test]
    fn metadata_validation() {
        assert_eq!(
            parse_signature_metadata(
                r#"{"text": "<img src=\"cid:a\">", "uploads": [{"content_id": "a"}]}"#
            ),
            Some((r#"<img src="cid:a">"#.to_string(), vec!["a".to_string()]))
        );
        for bad in [
            r#"{"text": "x", "uploads": [], "extra": 1}"#,
            r#"{"text": "x", "uploads": {}}"#,
            r#"{"text": 1, "uploads": []}"#,
            r#"{"text": "x", "uploads": [{"content_id": "a", "x": 1}]}"#,
            r#"{"text": "x", "uploads": [{"content_id": "a"}, {"content_id": "A"}]}"#,
            "broken",
        ] {
            assert_eq!(parse_signature_metadata(bad), None, "{bad}");
        }
    }

    #[test]
    fn posix_parts_like_purepath() {
        assert_eq!(posix_parts("a//b/./c"), ["a", "b", "c"]);
        assert_eq!(posix_parts("/a"), ["/", "a"]);
        assert_eq!(posix_parts("//a"), ["//", "a"]);
        assert_eq!(posix_parts("///a"), ["/", "a"]);
        assert_eq!(posix_parts("../x"), ["..", "x"]);
        assert_eq!(
            quote_plus("User@Example.com x~*"),
            "User%40Example.com+x~%2A"
        );
    }
}
