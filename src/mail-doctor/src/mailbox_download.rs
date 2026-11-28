//! Download a recent INBOX window over IMAP without persisting credentials
//! (port of `backend/app/doctor/services/mailbox_download.py`).
//!
//! Authentication material is accepted as an in-memory argument and is never
//! written to the job workspace. `BODY.PEEK[]` keeps messages unread and the
//! INBOX is opened read-only (`EXAMINE`).

use crate::cancellation::AuditCancelled;
use chrono::{DateTime, Duration, Local, NaiveDateTime, Utc};
use mail_core::MailAccount;
use mail_proto::imap::{Arg, ImapConnection};
use mail_proto::{ProtoError, Security, DEFAULT_TIMEOUT};
use std::fmt;
use std::path::Path;

/// Known provider IMAP endpoints (`IMAP_SERVERS`), sorted by domain.
pub const IMAP_SERVERS: [(&str, &str, u16); 14] = [
    ("aol.com", "imap.aol.com", 993),
    ("foxmail.com", "imap.qq.com", 993),
    ("gmail.com", "imap.gmail.com", 993),
    ("googlemail.com", "imap.gmail.com", 993),
    ("hotmail.com", "outlook.office365.com", 993),
    ("live.cn", "outlook.office365.com", 993),
    ("live.com", "outlook.office365.com", 993),
    ("msn.com", "outlook.office365.com", 993),
    ("outlook.com", "outlook.office365.com", 993),
    ("pm.me", "127.0.0.1", 1143),
    ("proton.me", "127.0.0.1", 1143),
    ("protonmail.com", "127.0.0.1", 1143),
    ("qq.com", "imap.qq.com", 993),
    ("yahoo.com", "imap.mail.yahoo.com", 993),
];

pub const GOOGLE_DOMAINS: [&str; 2] = ["gmail.com", "googlemail.com"];
pub const MICROSOFT_DOMAINS: [&str; 5] = [
    "outlook.com",
    "hotmail.com",
    "live.com",
    "live.cn",
    "msn.com",
];

/// `sorted(IMAP_SERVERS)` (the `known_domains` of `/api/mail/providers`).
pub fn known_domains() -> Vec<&'static str> {
    IMAP_SERVERS.iter().map(|(domain, _, _)| *domain).collect()
}

/// Python `email_domain`: the lowercased part after the last `@`, or `""`.
pub fn email_domain(address: &str) -> String {
    match address.rsplit_once('@') {
        Some((_, domain)) => domain.trim().to_lowercase(),
        None => String::new(),
    }
}

/// Python `provider_for_email`: `google`, `microsoft` or `credentials`.
pub fn provider_for_email(address: &str) -> &'static str {
    let domain = email_domain(address);
    if GOOGLE_DOMAINS.contains(&domain.as_str()) {
        "google"
    } else if MICROSOFT_DOMAINS.contains(&domain.as_str()) {
        "microsoft"
    } else {
        "credentials"
    }
}

/// Python `resolve_imap`: the known server, else `imap.{domain}:993`.
pub fn resolve_imap(address: &str) -> (String, u16) {
    let domain = email_domain(address);
    IMAP_SERVERS
        .iter()
        .find(|(known, _, _)| *known == domain)
        .map(|(_, server, port)| (server.to_string(), *port))
        .unwrap_or_else(|| (format!("imap.{domain}"), 993))
}

/// Python `since_date_str(days)` relative to a local naive `now`.
pub fn since_date_str(days: i64, now: NaiveDateTime) -> String {
    (now - Duration::days(days)).format("%d-%b-%Y").to_string()
}

/// Python `MailboxDownloadError`: a user-facing failure message.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct MailboxDownloadError(pub String);

impl MailboxDownloadError {
    pub fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

/// Python `DownloadCancelled`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("Mailbox download was cancelled")]
pub struct DownloadCancelled;

/// Every way [`download_inbox`] (or one of its callbacks) can stop.
#[derive(Debug, thiserror::Error)]
pub enum DownloadError {
    #[error(transparent)]
    Failed(#[from] MailboxDownloadError),
    #[error(transparent)]
    Cancelled(#[from] DownloadCancelled),
    /// A callback observed the job's cancellation (`check_cancel()`).
    #[error(transparent)]
    AuditCancelled(#[from] AuditCancelled),
    /// An unexpected failure (socket error after connecting, file system
    /// error, or a callback failure); Python let these propagate unchanged.
    #[error("{0}")]
    Other(String),
}

impl DownloadError {
    pub fn is_cancellation(&self) -> bool {
        matches!(self, Self::Cancelled(_) | Self::AuditCancelled(_))
    }
}

impl From<std::io::Error> for DownloadError {
    fn from(error: std::io::Error) -> Self {
        Self::Other(error.to_string())
    }
}

/// In-memory mailbox authentication and connection overrides (the Python
/// `auth` dict). Secrets are overwritten when cleared or dropped and never
/// printed by `Debug`.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct MailboxAuth {
    pub password: Option<String>,
    pub access_token: Option<String>,
    pub imap_server: Option<String>,
    pub imap_port: Option<u16>,
    pub use_ssl: Option<bool>,
    pub incoming_protocol: Option<String>,
}

impl fmt::Debug for MailboxAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let secret = |value: &Option<String>| value.as_ref().map(|_| "<redacted>");
        f.debug_struct("MailboxAuth")
            .field("password", &secret(&self.password))
            .field("access_token", &secret(&self.access_token))
            .field("imap_server", &self.imap_server)
            .field("imap_port", &self.imap_port)
            .field("use_ssl", &self.use_ssl)
            .field("incoming_protocol", &self.incoming_protocol)
            .finish()
    }
}

fn wipe(value: &mut Option<String>) {
    if let Some(text) = value.take() {
        let mut bytes = text.into_bytes();
        bytes.iter_mut().for_each(|byte| *byte = 0);
        std::hint::black_box(&bytes);
    }
}

impl MailboxAuth {
    /// `{"access_token": token}` (OAuth callback).
    pub fn access_token(token: impl Into<String>) -> Self {
        let mut auth = Self::default();
        auth.access_token = Some(token.into());
        auth
    }

    /// The auth built from an unlocked account by `create_account_job` and
    /// the weekly scheduler: password, incoming server/port and the security
    /// mapped to `SSL/TLS` / `STARTTLS` / `NONE`.
    pub fn from_account(account: &MailAccount) -> Self {
        let protocol = match account.imap_security().as_str() {
            "ssl" => "SSL/TLS",
            "starttls" => "STARTTLS",
            _ => "NONE",
        };
        Self {
            password: Some(account.password.clone()),
            access_token: None,
            imap_server: Some(account.incoming_server.clone()),
            imap_port: Some(account.incoming_port),
            use_ssl: None,
            incoming_protocol: Some(protocol.to_string()),
        }
    }

    /// Python `auth.clear()`: forget every field, overwriting the secrets.
    pub fn clear(&mut self) {
        wipe(&mut self.password);
        wipe(&mut self.access_token);
        self.imap_server = None;
        self.imap_port = None;
        self.use_ssl = None;
        self.incoming_protocol = None;
    }

    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }

    /// The secret values to redact from error messages.
    pub fn secrets(&self) -> impl Iterator<Item = &str> {
        [&self.password, &self.access_token]
            .into_iter()
            .filter_map(|value| value.as_deref())
            .filter(|value| !value.is_empty())
    }
}

impl Drop for MailboxAuth {
    fn drop(&mut self) {
        wipe(&mut self.password);
        wipe(&mut self.access_token);
    }
}

/// Arguments of [`download_inbox`] (Python keyword arguments).
pub struct DownloadOptions<'a> {
    pub email: &'a str,
    pub output_dir: &'a Path,
    pub days: i64,
    pub auth: &'a MailboxAuth,
    /// Exact `[window_start, window_end)` as aware ISO timestamps.
    pub window_start: Option<&'a str>,
    pub window_end: Option<&'a str>,
    pub max_bytes: u64,
    pub max_messages: usize,
    /// Local "now" for the `SINCE` date (defaults to the current local time).
    pub now: Option<NaiveDateTime>,
    /// Pause between downloaded messages (Python `time.sleep(0.03)`).
    pub pause: std::time::Duration,
    /// TLS connector override (tests trust the testkit certificate).
    #[doc(hidden)]
    pub tls_connector: Option<native_tls::TlsConnector>,
}

impl<'a> DownloadOptions<'a> {
    /// Options with the Python defaults (200 MiB, 50000 messages, no window).
    pub fn new(email: &'a str, output_dir: &'a Path, days: i64, auth: &'a MailboxAuth) -> Self {
        Self {
            email,
            output_dir,
            days,
            auth,
            window_start: None,
            window_end: None,
            max_bytes: 200 * 1024 * 1024,
            max_messages: 50_000,
            now: None,
            pause: std::time::Duration::from_millis(30),
            tls_connector: None,
        }
    }
}

type Counter<'a> = Box<dyn FnMut(usize, usize) -> Result<(), DownloadError> + 'a>;

/// Callbacks of [`download_inbox`]: `progress(done, total)`, `log(text)`,
/// `should_cancel()` and `on_batch(done, total)` after each saved message.
pub struct DownloadHooks<'a> {
    pub progress: Counter<'a>,
    pub log: Box<dyn FnMut(&str) + 'a>,
    pub should_cancel: Box<dyn Fn() -> bool + 'a>,
    pub on_batch: Counter<'a>,
}

impl Default for DownloadHooks<'_> {
    fn default() -> Self {
        Self {
            progress: Box::new(|_, _| Ok(())),
            log: Box::new(|_| {}),
            should_cancel: Box::new(|| false),
            on_batch: Box::new(|_, _| Ok(())),
        }
    }
}

fn parse_window(
    value: Option<&str>,
    name: &str,
) -> Result<Option<DateTime<Utc>>, MailboxDownloadError> {
    match value {
        None => Ok(None),
        Some(text) => crate::db::parse_aware_utc(text).map(Some).ok_or_else(|| {
            MailboxDownloadError(format!(
                "The audit {name} must be a date and time with a timezone"
            ))
        }),
    }
}

/// Python `_internal_date`: parse `dd-Mon-yyyy HH:MM:SS +zzzz` to UTC.
pub fn parse_internal_date(text: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_str(text.trim(), "%d-%b-%Y %H:%M:%S %z")
        .ok()
        .map(|value| value.with_timezone(&Utc))
}

fn is_server_refusal(error: &ProtoError) -> bool {
    matches!(
        error,
        ProtoError::No(_) | ProtoError::Bad(_) | ProtoError::Protocol(_)
    )
}

fn unexpected(error: ProtoError) -> DownloadError {
    DownloadError::Other(error.to_string())
}

fn check(hooks: &DownloadHooks<'_>) -> Result<(), DownloadError> {
    if (hooks.should_cancel)() {
        Err(DownloadCancelled.into())
    } else {
        Ok(())
    }
}

/// Python `download_inbox`: download recent INBOX messages, or an exact
/// `[window_start, window_end)`, into `output_dir/<uid>.eml`. Returns
/// `(downloaded, total)`.
pub fn download_inbox(
    options: &DownloadOptions<'_>,
    hooks: &mut DownloadHooks<'_>,
) -> Result<(usize, usize), DownloadError> {
    check(hooks)?;
    let start = parse_window(options.window_start, "window start")?;
    let end = parse_window(options.window_end, "window end")?;
    let window = match (start, end) {
        (None, None) => None,
        (Some(start), Some(end)) if start < end => Some((start, end)),
        _ => {
            return Err(MailboxDownloadError::new(
                "Supply both audit window boundaries in increasing order",
            )
            .into())
        }
    };
    let auth = options.auth;
    let (default_server, default_port) = resolve_imap(options.email);
    let server = auth
        .imap_server
        .as_deref()
        .filter(|server| !server.is_empty())
        .unwrap_or(&default_server)
        .trim()
        .to_string();
    let port = auth
        .imap_port
        .filter(|port| *port != 0)
        .unwrap_or(default_port);
    let mut ssl_enabled = auth.use_ssl.unwrap_or(port == 993);
    let protocol = auth.incoming_protocol.as_deref();
    if let Some(protocol) = protocol {
        if !matches!(protocol, "SSL/TLS" | "STARTTLS" | "NONE") {
            return Err(MailboxDownloadError::new("Unsupported incoming security protocol").into());
        }
        ssl_enabled = protocol == "SSL/TLS";
    }
    std::fs::create_dir_all(options.output_dir)?;

    let security = if ssl_enabled {
        Security::Ssl
    } else {
        Security::None
    };
    let connected = match &options.tls_connector {
        Some(connector) => ImapConnection::connect_with_tls(
            &server,
            port,
            security,
            DEFAULT_TIMEOUT,
            connector.clone(),
        ),
        None => ImapConnection::connect(&server, port, security, DEFAULT_TIMEOUT),
    };
    let mut conn = connected.map_err(|error| {
        MailboxDownloadError(format!(
            "Could not connect to IMAP server {server}:{port}: {error}"
        ))
    })?;
    conn.set_max_literal_size(
        (options.max_bytes as usize).max(mail_proto::imap::DEFAULT_MAX_LITERAL),
    );
    let result = download_with(&mut conn, options, hooks, protocol, window);
    let _ = conn.logout();
    result
}

fn download_with(
    conn: &mut ImapConnection,
    options: &DownloadOptions<'_>,
    hooks: &mut DownloadHooks<'_>,
    protocol: Option<&str>,
    window: Option<(DateTime<Utc>, DateTime<Utc>)>,
) -> Result<(usize, usize), DownloadError> {
    check(hooks)?;
    if protocol == Some("STARTTLS") {
        conn.starttls().map_err(|_| {
            MailboxDownloadError::new("The server could not establish IMAP STARTTLS")
        })?;
    }
    let auth = options.auth;
    let signed_in = if let Some(token) = auth.access_token.as_deref().filter(|t| !t.is_empty()) {
        conn.authenticate_xoauth2(options.email, token)
    } else if let Some(password) = auth.password.as_deref().filter(|p| !p.is_empty()) {
        conn.login(options.email, password)
    } else {
        return Err(MailboxDownloadError::new("No mailbox authentication was supplied").into());
    };
    signed_in.map_err(|error| {
        if is_server_refusal(&error) {
            DownloadError::from(MailboxDownloadError::new(
                "Mailbox sign-in failed. Check provider permissions or use an app password.",
            ))
        } else {
            unexpected(error)
        }
    })?;

    conn.select("INBOX", true).map_err(|error| {
        if is_server_refusal(&error) {
            MailboxDownloadError::new("The server would not open the INBOX folder").into()
        } else {
            unexpected(error)
        }
    })?;

    let since = match window {
        Some((start, _)) => (start - Duration::days(1)).format("%d-%b-%Y").to_string(),
        None => since_date_str(
            options.days,
            options.now.unwrap_or_else(|| Local::now().naive_local()),
        ),
    };
    // IMAP date searches ignore times and use the server's INTERNALDATE
    // calendar date. Padding catches messages on either side of UTC in any
    // timezone; INTERNALDATE below applies the exact inclusive/exclusive
    // boundaries before fetching bodies or counting messages.
    let mut criteria = vec![Arg::atom("SINCE"), Arg::atom(since.clone())];
    if let Some((_, end)) = window {
        criteria.push(Arg::atom("BEFORE"));
        criteria.push(Arg::atom(
            (end + Duration::days(2)).format("%d-%b-%Y").to_string(),
        ));
    }
    let mut uids = conn.uid_search(None, &criteria).map_err(|error| {
        if is_server_refusal(&error) {
            MailboxDownloadError::new("The server could not search the requested date range").into()
        } else {
            unexpected(error)
        }
    })?;
    if let Some((start, end)) = window {
        let mut selected = Vec::new();
        for uid in uids {
            check(hooks)?;
            let fetched = conn.uid_fetch(&uid.to_string(), "(INTERNALDATE)");
            check(hooks)?;
            let received = match fetched {
                Ok(responses) => responses
                    .iter()
                    .find_map(|response| response.internal_date())
                    .and_then(|text| parse_internal_date(&text)),
                Err(error) if is_server_refusal(&error) => None,
                Err(error) => return Err(unexpected(error)),
            };
            // Guessing from the sender's Date header would make missed weekly
            // runs inaccurate; fail so the durable run retries.
            let Some(received) = received else {
                return Err(MailboxDownloadError::new(
                    "The server did not return a valid received date for the audit window",
                )
                .into());
            };
            if start <= received && received < end {
                selected.push(uid);
                if selected.len() > options.max_messages {
                    return Err(too_many_messages().into());
                }
            }
        }
        uids = selected;
    }
    let total = uids.len();
    if total > options.max_messages {
        return Err(too_many_messages().into());
    }
    let found = match window {
        Some((start, end)) => format!(
            "Found {total} INBOX messages in [{}, {})",
            crate::db::isoformat(&start),
            crate::db::isoformat(&end)
        ),
        None => format!("Found {total} INBOX messages since {since}"),
    };
    (hooks.log)(&found);
    (hooks.progress)(0, total)?;

    let mut downloaded = 0;
    let mut total_bytes: u64 = 0;
    for uid in uids {
        check(hooks)?;
        let target = options.output_dir.join(format!("{uid}.eml"));
        if !target.exists() {
            let fetched = conn.uid_fetch(&uid.to_string(), "(BODY.PEEK[])");
            let raw = match &fetched {
                Ok(responses) => responses.iter().find_map(|response| response.first_body()),
                Err(error) if is_server_refusal(error) => None,
                Err(_) => None,
            };
            check(hooks)?;
            if let Err(error) = &fetched {
                if !is_server_refusal(error) {
                    return Err(DownloadError::Other(error.to_string()));
                }
            }
            let Some(raw) = raw else {
                (hooks.log)(&format!(
                    "Skipped UID {uid}: the server returned no message data"
                ));
                continue;
            };
            total_bytes += raw.len() as u64;
            if total_bytes > options.max_bytes {
                return Err(too_large().into());
            }
            let partial = options.output_dir.join(format!("{uid}.eml.part"));
            std::fs::write(&partial, raw)?;
            std::fs::rename(&partial, &target)?;
            if !options.pause.is_zero() {
                std::thread::sleep(options.pause);
            }
        } else {
            total_bytes += std::fs::metadata(&target)?.len();
            if total_bytes > options.max_bytes {
                return Err(too_large().into());
            }
        }
        downloaded += 1;
        (hooks.progress)(downloaded, total)?;
        (hooks.on_batch)(downloaded, total)?;
    }
    Ok((downloaded, total))
}

fn too_many_messages() -> MailboxDownloadError {
    MailboxDownloadError::new(
        "The mailbox exceeds the maximum audit message count; choose fewer days",
    )
}

fn too_large() -> MailboxDownloadError {
    MailboxDownloadError::new(
        "The mailbox download exceeds the maximum allowed size; choose fewer days",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_helpers() {
        assert_eq!(email_domain("User@GMAIL.com "), "gmail.com");
        assert_eq!(email_domain("a@b@Example.ORG"), "example.org");
        assert_eq!(email_domain("no-at-sign"), "");
        assert_eq!(provider_for_email("x@googlemail.com"), "google");
        assert_eq!(provider_for_email("x@live.cn"), "microsoft");
        assert_eq!(provider_for_email("x@example.com"), "credentials");
        assert_eq!(resolve_imap("u@proton.me"), ("127.0.0.1".into(), 1143));
        assert_eq!(
            resolve_imap("u@yahoo.com"),
            ("imap.mail.yahoo.com".into(), 993)
        );
        assert_eq!(
            resolve_imap("u@example.net"),
            ("imap.example.net".into(), 993)
        );
        let domains = known_domains();
        let mut sorted = domains.clone();
        sorted.sort();
        assert_eq!(domains, sorted);
        assert_eq!(domains.len(), 14);
    }

    #[test]
    fn dates() {
        let now = chrono::NaiveDate::from_ymd_opt(2026, 10, 13)
            .unwrap()
            .and_hms_opt(12, 0, 0)
            .unwrap();
        assert_eq!(since_date_str(7, now), "06-Oct-2026");
        assert_eq!(since_date_str(3, now), "10-Oct-2026");
        let parsed = parse_internal_date("11-Oct-2026 12:00:00 +1400").unwrap();
        assert_eq!(crate::db::isoformat(&parsed), "2026-10-10T22:00:00+00:00");
        assert!(parse_internal_date("not a received date").is_none());
        // RFC 3501 `date-day-fixed` pads single-digit days with a space;
        // Python strips the value and `%d` accepts one digit.
        let padded = parse_internal_date(" 1-oct-2026 09:05:00 -0400").unwrap();
        assert_eq!(crate::db::isoformat(&padded), "2026-10-01T13:05:00+00:00");
    }

    #[test]
    fn auth_is_redacted_and_cleared() {
        let account = MailAccount::new(
            "u@example.com",
            "pw-secret",
            "imap.example.com",
            143,
            "STARTTLS",
            "smtp.example.com",
            587,
            "STARTTLS",
        );
        let mut auth = MailboxAuth::from_account(&account);
        assert_eq!(auth.incoming_protocol.as_deref(), Some("STARTTLS"));
        assert_eq!(auth.imap_port, Some(143));
        assert!(!format!("{auth:?}").contains("pw-secret"));
        assert_eq!(auth.secrets().collect::<Vec<_>>(), ["pw-secret"]);
        auth.clear();
        assert!(auth.is_empty());
    }
}
