//! Mail server profiles stored in the per-user appdata `mail-servers.json`
//! (port of `app/mail/servers.py`).
//!
//! Profiles describe how to reach an IMAP/POP3/SMTP provider. They never
//! contain passwords; credentials live only in the in-memory session store.
//!
//! Extension: profiles carry `incoming_mail_protocol` (`"imap"` default or
//! `"pop3"`), the user-requested POP3 compatibility mode. Files written by the
//! Python app (without the field) load as IMAP.
//!
//! Profiles are kept in an insertion-ordered [`IndexMap`] (like a Python
//! dict), so iteration, the saved file and the "first match wins" order of
//! [`profile_for_email`] follow the order of the profiles in the file. Remove
//! entries with `shift_remove` to keep the remaining order (`del profiles[key]`).

use crate::error::{MailError, Result};
use crate::schemas::{parse_python_int, ServerProfileIn};
use crate::sessions::{PROTOCOL_IMAP, PROTOCOL_POP3};
use crate::settings::{python_float_repr, read_utf8_sig, write_json};
use indexmap::IndexMap;
use regex::Regex;
use serde::Serialize;
use serde_json::{json, Map, Value};
use std::fs;
use std::path::Path;
use std::sync::LazyLock;

/// `PROFILE_FIELDS` (plus the POP3 extension field).
pub const PROFILE_FIELDS: [&str; 9] = [
    "incoming_server",
    "incoming_port",
    "incoming_protocol",
    "outgoing_server",
    "outgoing_port",
    "outgoing_protocol",
    "email_address",
    "display_name",
    "incoming_mail_protocol",
];

const SSL_PROTOCOLS: &[&str] = &[
    "ssl", "tls", "ssl/tls", "ssl/tss", "imaps", "smtps", "ssl_tls",
];
const STARTTLS_PROTOCOLS: &[&str] = &["starttls", "start-tls", "start_tls", "tls-upgrade"];

/// Profiles keyed by profile key, in file (insertion) order.
pub type Profiles = IndexMap<String, ServerProfile>;

/// Python `ServerProfile`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ServerProfile {
    #[serde(skip)]
    pub key: String,
    pub incoming_server: String,
    pub incoming_port: i64,
    pub incoming_protocol: String,
    pub outgoing_server: String,
    pub outgoing_port: i64,
    pub outgoing_protocol: String,
    pub email_address: String,
    pub display_name: String,
    /// `"imap"` or `"pop3"` (extension; not in the Python profile).
    pub incoming_mail_protocol: String,
}

impl ServerProfile {
    /// A profile with the Python dataclass defaults for the optional fields.
    pub fn new(
        key: impl Into<String>,
        incoming_server: impl Into<String>,
        incoming_port: i64,
        incoming_protocol: impl Into<String>,
        outgoing_server: impl Into<String>,
        outgoing_port: i64,
        outgoing_protocol: impl Into<String>,
    ) -> Self {
        Self {
            key: key.into(),
            incoming_server: incoming_server.into(),
            incoming_port,
            incoming_protocol: incoming_protocol.into(),
            outgoing_server: outgoing_server.into(),
            outgoing_port,
            outgoing_protocol: outgoing_protocol.into(),
            email_address: String::new(),
            display_name: String::new(),
            incoming_mail_protocol: PROTOCOL_IMAP.into(),
        }
    }

    /// `ServerProfile(key=key, **body.model_dump())` in `upsert_server_profile`.
    pub fn from_input(key: impl Into<String>, body: &ServerProfileIn) -> Self {
        Self {
            key: key.into(),
            incoming_server: body.incoming_server.clone(),
            incoming_port: i64::from(body.incoming_port),
            incoming_protocol: body.incoming_protocol.clone(),
            outgoing_server: body.outgoing_server.clone(),
            outgoing_port: i64::from(body.outgoing_port),
            outgoing_protocol: body.outgoing_protocol.clone(),
            email_address: body.email_address.clone(),
            display_name: body.display_name.clone(),
            incoming_mail_protocol: body.incoming_mail_protocol.clone(),
        }
    }

    /// Python `to_dict()` (never contains secrets).
    pub fn to_dict(&self) -> Value {
        json!({
            "incoming_server": self.incoming_server,
            "incoming_port": self.incoming_port,
            "incoming_protocol": self.incoming_protocol,
            "outgoing_server": self.outgoing_server,
            "outgoing_port": self.outgoing_port,
            "outgoing_protocol": self.outgoing_protocol,
            "email_address": self.email_address,
            "display_name": self.display_name,
            "incoming_mail_protocol": self.incoming_mail_protocol,
        })
    }

    pub fn is_pop3(&self) -> bool {
        self.incoming_mail_protocol == PROTOCOL_POP3
    }
}

/// Python `normalize_protocol(protocol, *, default_port)`: map a free-form
/// protocol label to `"ssl"`, `"starttls"`, or `"none"`.
pub fn normalize_protocol(protocol: &str, default_port: u16) -> String {
    let value = protocol.trim().to_lowercase();
    let implicit_tls = matches!(default_port, 465 | 993 | 995);
    if SSL_PROTOCOLS.contains(&value.as_str()) {
        return "ssl".into();
    }
    if STARTTLS_PROTOCOLS.contains(&value.as_str()) {
        return "starttls".into();
    }
    if ["none", "plain", "clear", "no encryption", ""].contains(&value.as_str()) {
        return if implicit_tls { "ssl" } else { "none" }.into();
    }
    if implicit_tls { "ssl" } else { "starttls" }.into()
}

fn servers_error(message: String) -> MailError {
    MailError::Settings(message)
}

fn read_object(path: &Path) -> Result<Map<String, Value>> {
    let text = read_utf8_sig(path).map_err(|error| {
        servers_error(format!(
            "Cannot read mail server profiles at {}: {error}",
            path.display()
        ))
    })?;
    let value: Value = serde_json::from_str(&text).map_err(|error| {
        servers_error(format!(
            "Cannot read mail server profiles at {}: {error}",
            path.display()
        ))
    })?;
    match value {
        Value::Object(map) => Ok(map),
        _ => Err(servers_error(format!(
            "Invalid mail server profiles at {}: expected a JSON object",
            path.display()
        ))),
    }
}

/// Python truthiness of a JSON value.
fn truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(flag) => *flag,
        Value::Number(number) => number.as_f64().map(|n| n != 0.0).unwrap_or(true),
        Value::String(text) => !text.is_empty(),
        Value::Array(items) => !items.is_empty(),
        Value::Object(map) => !map.is_empty(),
    }
}

/// Python `repr()` of a string.
pub(crate) fn python_repr_str(text: &str) -> String {
    let quote = if text.contains('\'') && !text.contains('"') {
        '"'
    } else {
        '\''
    };
    let mut out = String::new();
    out.push(quote);
    for ch in text.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c == quote => {
                out.push('\\');
                out.push(c);
            }
            c if (c as u32) < 0x20 || c as u32 == 0x7f => {
                out.push_str(&format!("\\x{:02x}", c as u32))
            }
            c => out.push(c),
        }
    }
    out.push(quote);
    out
}

/// Python `str()` of a JSON value (`True`, `None`, `['a']`, `{'k': 1}`...).
fn python_str(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        other => python_repr(other),
    }
}

fn python_repr(value: &Value) -> String {
    match value {
        Value::Null => "None".into(),
        Value::Bool(true) => "True".into(),
        Value::Bool(false) => "False".into(),
        Value::Number(number) => match number
            .as_i64()
            .map(|n| n.to_string())
            .or_else(|| number.as_u64().map(|n| n.to_string()))
        {
            Some(text) => text,
            None => python_float_repr(number.as_f64().unwrap_or(0.0)),
        },
        Value::String(text) => python_repr_str(text),
        Value::Array(items) => format!(
            "[{}]",
            items.iter().map(python_repr).collect::<Vec<_>>().join(", ")
        ),
        Value::Object(map) => format!(
            "{{{}}}",
            map.iter()
                .map(|(key, value)| format!("{}: {}", python_repr_str(key), python_repr(value)))
                .collect::<Vec<_>>()
                .join(", ")
        ),
    }
}

/// Python `int(value)` for a JSON value; `Err` is the exception message.
fn python_int(value: &Value) -> std::result::Result<i64, String> {
    let clamp = |n: i128| n.clamp(i64::MIN as i128, i64::MAX as i128) as i64;
    match value {
        Value::Bool(flag) => Ok(i64::from(*flag)),
        Value::Number(number) => Ok(match number.as_i64() {
            Some(n) => n,
            None => match number.as_u64() {
                Some(n) => clamp(n as i128),
                None => clamp(number.as_f64().unwrap_or(0.0).trunc() as i128),
            },
        }),
        Value::String(text) => parse_python_int(text).map(clamp).ok_or_else(|| {
            format!(
                "invalid literal for int() with base 10: {}",
                python_repr_str(text)
            )
        }),
        Value::Null => Err(
            "int() argument must be a string, a bytes-like object or a real number, not 'NoneType'"
                .into(),
        ),
        Value::Array(_) => Err(
            "int() argument must be a string, a bytes-like object or a real number, not 'list'"
                .into(),
        ),
        Value::Object(_) => Err(
            "int() argument must be a string, a bytes-like object or a real number, not 'dict'"
                .into(),
        ),
    }
}

/// `str(raw.get(field) or default).strip()`.
fn text_field(raw: &Map<String, Value>, field: &str, default: &str) -> String {
    match raw.get(field).filter(|value| truthy(value)) {
        Some(value) => python_str(value).trim().to_string(),
        None => default.trim().to_string(),
    }
}

/// `int(raw.get(field) or default)`.
fn port_field(
    raw: &Map<String, Value>,
    field: &str,
    default: i64,
) -> std::result::Result<i64, String> {
    match raw.get(field).filter(|value| truthy(value)) {
        Some(value) => python_int(value),
        None => Ok(default),
    }
}

fn parse_profile(
    key: &str,
    raw: &Map<String, Value>,
) -> std::result::Result<ServerProfile, String> {
    let incoming_port = port_field(raw, "incoming_port", 993)?;
    let outgoing_port = port_field(raw, "outgoing_port", 587)?;
    let incoming_mail_protocol =
        text_field(raw, "incoming_mail_protocol", PROTOCOL_IMAP).to_lowercase();
    if incoming_mail_protocol != PROTOCOL_IMAP && incoming_mail_protocol != PROTOCOL_POP3 {
        return Err("incoming_mail_protocol must be 'imap' or 'pop3'".into());
    }
    Ok(ServerProfile {
        key: key.to_string(),
        incoming_server: text_field(raw, "incoming_server", ""),
        incoming_port,
        incoming_protocol: text_field(raw, "incoming_protocol", "SSL/TLS"),
        outgoing_server: text_field(raw, "outgoing_server", ""),
        outgoing_port,
        outgoing_protocol: text_field(raw, "outgoing_protocol", "STARTTLS"),
        email_address: text_field(raw, "email_address", ""),
        display_name: text_field(raw, "display_name", ""),
        incoming_mail_protocol,
    })
}

/// Python `load_profiles(path)`. Errors are `MailServersError` (HTTP 500).
pub fn load_profiles(path: &Path) -> Result<Profiles> {
    let values = read_object(path)?;
    let servers = match values.get("servers") {
        None => return Ok(Profiles::new()),
        Some(Value::Object(servers)) => servers,
        Some(_) => {
            return Err(servers_error(format!(
                "Invalid mail server profiles at {}: 'servers' must be an object",
                path.display()
            )))
        }
    };
    let mut profiles = Profiles::new();
    for (key, raw) in servers {
        let Value::Object(raw) = raw else {
            return Err(servers_error(format!(
                "Invalid profile {} at {}: expected an object",
                python_repr_str(key),
                path.display()
            )));
        };
        let profile = parse_profile(key, raw).map_err(|error| {
            servers_error(format!(
                "Invalid profile {} at {}: {error}",
                python_repr_str(key),
                path.display()
            ))
        })?;
        profiles.insert(key.clone(), profile);
    }
    Ok(profiles)
}

/// Python `save_profiles(path, profiles)`: atomic overwrite, no secrets.
pub fn save_profiles(path: &Path, profiles: &Profiles) -> Result<()> {
    let servers: Map<String, Value> = profiles
        .iter()
        .map(|(key, profile)| (key.clone(), profile.to_dict()))
        .collect();
    let payload = json!({ "servers": servers });
    let write = || -> std::io::Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        write_json(path, &payload, true)
    };
    write().map_err(|error| {
        servers_error(format!(
            "Cannot write mail server profiles at {}: {error}",
            path.display()
        ))
    })
}

/// Python `profile_for_email`: a profile whose `email_address` matches, else
/// one whose incoming server matches the address's domain.
pub fn profile_for_email<'a>(profiles: &'a Profiles, email: &str) -> Option<&'a ServerProfile> {
    let address = email.trim().to_lowercase();
    if let Some(profile) = profiles
        .values()
        .find(|profile| profile.email_address.to_lowercase() == address)
    {
        return Some(profile);
    }
    let domain = match address.rsplit_once('@') {
        Some((_, domain)) => domain,
        None => "",
    };
    if domain.is_empty() {
        return None;
    }
    profiles.values().find(|profile| {
        let host = profile.incoming_server.to_lowercase();
        let host_suffix = host.split_once('.').map(|(_, rest)| rest).unwrap_or(&host);
        host.ends_with(domain) || domain.ends_with(host_suffix)
    })
}

/// `_profile_key` from `main.py`: a filesystem/URL-safe profile key, at most
/// 120 characters. An empty result is HTTP 400 "Profile key is empty".
pub fn profile_key(value: &str) -> Result<String> {
    static UNSAFE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"[^0-9A-Za-z_.-]+").unwrap());
    let replaced = UNSAFE.replace_all(value.trim(), "-");
    let key = replaced
        .trim_matches(|c| c == '-' || c == '.')
        .to_lowercase();
    if key.is_empty() {
        return Err(MailError::bad_request("Profile key is empty"));
    }
    Ok(key.chars().take(120).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(directory: &Path, value: Value) -> std::path::PathBuf {
        let path = directory.join("mail-servers.json");
        fs::write(&path, value.to_string()).unwrap();
        path
    }

    #[test]
    fn load_profiles_from_project_shape() {
        let directory = tempfile::tempdir().unwrap();
        let path = write(
            directory.path(),
            json!({"servers": {"purelymail": {
                "incoming_server": "imap.purelymail.com", "incoming_port": 993,
                "incoming_protocol": "SSL/TLS", "outgoing_server": "smtp.purelymail.com",
                "outgoing_port": 587, "outgoing_protocol": "STARTTLS", "email_address": "y@czpzc.com",
            }}}),
        );
        let profiles = load_profiles(&path).unwrap();
        let profile = &profiles["purelymail"];
        assert_eq!(profile.incoming_server, "imap.purelymail.com");
        assert_eq!(profile.outgoing_port, 587);
        assert_eq!(profile.incoming_mail_protocol, "imap");
        assert_eq!(profile_for_email(&profiles, "y@czpzc.com"), Some(profile));
    }

    #[test]
    fn profile_for_email_falls_back_to_domain() {
        let directory = tempfile::tempdir().unwrap();
        let path = write(
            directory.path(),
            json!({"servers": {"example": {
                "incoming_server": "imap.example.com", "outgoing_server": "smtp.example.com",
            }}}),
        );
        let profiles = load_profiles(&path).unwrap();
        let profile = profile_for_email(&profiles, "someone@example.com").unwrap();
        assert_eq!(profile.incoming_server, "imap.example.com");
        assert_eq!(profile.incoming_port, 993);
        assert_eq!(profile.incoming_protocol, "SSL/TLS");
        assert_eq!(profile.outgoing_protocol, "STARTTLS");
        assert!(profile_for_email(&profiles, "someone@other.org").is_none());
        assert!(profile_for_email(&profiles, "no-at-sign").is_none());
    }

    #[test]
    fn save_profiles_roundtrips_and_never_holds_passwords() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("nested").join("mail-servers.json");
        let mut profile = ServerProfile::new(
            "mine",
            "imap.test",
            993,
            "SSL/TLS",
            "smtp.test",
            465,
            "SSL/TLS",
        );
        profile.email_address = "me@test".into();
        profile.incoming_mail_protocol = "pop3".into();
        let profiles: Profiles = [("mine".to_string(), profile.clone())].into();
        save_profiles(&path, &profiles).unwrap();
        assert!(!fs::read_to_string(&path)
            .unwrap()
            .to_lowercase()
            .contains("password"));
        let loaded = load_profiles(&path).unwrap();
        assert_eq!(loaded["mine"].to_dict(), profile.to_dict());
        assert!(loaded["mine"].is_pop3());
    }

    #[test]
    fn profiles_keep_file_order_and_first_match_wins() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("mail-servers.json");
        // "zeta" sorts after "alpha" but comes first in the file, as in a
        // Python dict; both match the domain of the address.
        fs::write(
            &path,
            r#"{"servers": {
                "zeta": {"incoming_server": "imap.example.com", "outgoing_server": "smtp.example.com"},
                "alpha": {"incoming_server": "mail.example.com", "outgoing_server": "smtp.example.com"},
                "mid": {"incoming_server": "imap.example.org", "outgoing_server": "smtp.example.org",
                        "email_address": "dup@example.org"},
                "beta": {"incoming_server": "imap2.example.org", "outgoing_server": "smtp.example.org",
                         "email_address": "dup@example.org"}
            }}"#,
        )
        .unwrap();
        let mut profiles = load_profiles(&path).unwrap();
        let keys: Vec<&str> = profiles.keys().map(String::as_str).collect();
        assert_eq!(keys, ["zeta", "alpha", "mid", "beta"]);
        assert_eq!(
            profile_for_email(&profiles, "user@example.com")
                .unwrap()
                .key,
            "zeta"
        );
        assert_eq!(
            profile_for_email(&profiles, "DUP@example.org").unwrap().key,
            "mid"
        );

        // Saving keeps the order; replacing keeps the position, new keys append,
        // removing keeps the order of the rest (Python `del profiles[key]`).
        let replacement =
            ServerProfile::new("alpha", "x.test", 993, "SSL/TLS", "y.test", 587, "STARTTLS");
        profiles.insert("alpha".into(), replacement);
        profiles.insert(
            "new".into(),
            ServerProfile::new("new", "n.test", 993, "SSL/TLS", "m.test", 587, "STARTTLS"),
        );
        profiles.shift_remove("zeta");
        save_profiles(&path, &profiles).unwrap();
        let text = fs::read_to_string(&path).unwrap();
        let positions: Vec<usize> = ["\"alpha\"", "\"mid\"", "\"beta\"", "\"new\""]
            .iter()
            .map(|key| text.find(key).unwrap())
            .collect();
        assert!(positions.windows(2).all(|pair| pair[0] < pair[1]), "{text}");
        let reloaded: Vec<String> = load_profiles(&path).unwrap().keys().cloned().collect();
        assert_eq!(reloaded, ["alpha", "mid", "beta", "new"]);
        assert_eq!(
            load_profiles(&path).unwrap()["alpha"].incoming_server,
            "x.test"
        );
    }

    #[test]
    fn python_float_repr_matches_python() {
        for (number, expected) in [
            (25.9, "25.9"),
            (1.0, "1.0"),
            (-0.0, "-0.0"),
            (0.0001, "0.0001"),
            (0.00001, "1e-05"),
            (1.5e-7, "1.5e-07"),
            (123456789012345.0, "123456789012345.0"),
            (1e16, "1e+16"),
            (1.25e17, "1.25e+17"),
            (-2.5e300, "-2.5e+300"),
        ] {
            assert_eq!(python_float_repr(number), expected, "{number}");
        }
    }

    #[test]
    fn protocol_aliases() {
        assert_eq!(normalize_protocol("SSL/TSS", 993), "ssl");
        assert_eq!(normalize_protocol("STARTTLS", 587), "starttls");
        assert_eq!(normalize_protocol("NONE", 25), "none");
        assert_eq!(normalize_protocol("", 995), "ssl");
        assert_eq!(normalize_protocol("weird", 143), "starttls");
        assert_eq!(normalize_protocol("weird", 465), "ssl");
    }

    #[test]
    fn python_coercions_and_errors() {
        let directory = tempfile::tempdir().unwrap();
        let path = write(
            directory.path(),
            json!({"servers": {"odd": {
                "incoming_server": 42, "incoming_port": " 1_43 ", "outgoing_port": 25.9,
                "incoming_protocol": "", "display_name": true,
            }}}),
        );
        let profile = &load_profiles(&path).unwrap()["odd"];
        assert_eq!(profile.incoming_server, "42");
        assert_eq!(profile.incoming_port, 143);
        assert_eq!(profile.outgoing_port, 25);
        assert_eq!(profile.incoming_protocol, "SSL/TLS");
        assert_eq!(profile.display_name, "True");

        for (raw, message) in [
            (
                json!({"incoming_port": "abc"}),
                "invalid literal for int() with base 10: 'abc'",
            ),
            (json!({"incoming_port": [1]}), "not 'list'"),
            (
                json!({"incoming_mail_protocol": "smtp"}),
                "incoming_mail_protocol must be 'imap' or 'pop3'",
            ),
        ] {
            let path = write(directory.path(), json!({"servers": {"bad": raw}}));
            let error = load_profiles(&path).unwrap_err();
            assert_eq!(error.status(), 500);
            let text = error.to_string();
            assert!(text.starts_with("Invalid profile 'bad' at "), "{text}");
            assert!(text.contains(message), "{text}");
        }
        let path = write(directory.path(), json!({"servers": {"bad": 5}}));
        assert!(load_profiles(&path)
            .unwrap_err()
            .to_string()
            .contains("expected an object"));
        let path = write(directory.path(), json!({"servers": []}));
        assert!(load_profiles(&path)
            .unwrap_err()
            .to_string()
            .contains("'servers' must be an object"));
        let path = write(directory.path(), json!([]));
        assert!(load_profiles(&path)
            .unwrap_err()
            .to_string()
            .contains("expected a JSON object"));
        let path = write(directory.path(), json!({}));
        assert!(load_profiles(&path).unwrap().is_empty());
    }

    #[test]
    fn corrupt_profiles_file_is_reported_with_its_path() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("mail-servers.json");
        fs::write(&path, "{broken").unwrap();
        let error = load_profiles(&path).unwrap_err();
        assert_eq!(error.status(), 500);
        assert!(error.to_string().contains("mail-servers.json"));
        let missing = directory.path().join("missing.json");
        assert!(load_profiles(&missing)
            .unwrap_err()
            .to_string()
            .starts_with("Cannot read mail server profiles at"));
    }

    #[test]
    fn profile_keys_are_sanitized() {
        assert_eq!(
            profile_key("  Me@Work.Example ").unwrap(),
            "me-work.example"
        );
        assert_eq!(profile_key("..a b..").unwrap(), "a-b");
        assert_eq!(profile_key(&"x".repeat(200)).unwrap().len(), 120);
        let error = profile_key(" -.- ").unwrap_err();
        assert_eq!(error.status(), 400);
        assert_eq!(error.body(), json!({"detail": "Profile key is empty"}));
    }
}
