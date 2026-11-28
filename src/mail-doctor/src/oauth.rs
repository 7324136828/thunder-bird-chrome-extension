//! Minimal OAuth authorization-code + PKCE support for IMAP access (port of
//! `backend/app/doctor/services/oauth.py`).
//!
//! Pending flows (state, PKCE verifier) live in memory for ten minutes;
//! access tokens are returned to the caller and never persisted.

use crate::config::DoctorSettings;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Pending flows expire after ten minutes (`FLOW_TTL_SECONDS`).
pub const FLOW_TTL_SECONDS: f64 = 10.0 * 60.0;
/// Maximum number of simultaneously pending flows.
pub const MAX_PENDING_FLOWS: usize = 100;

/// One OAuth provider's endpoints and IMAP scope (`PROVIDERS`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderEndpoints {
    pub authorize: String,
    pub token: String,
    pub scope: &'static str,
}

/// `PROVIDERS[name]` for `google` and `microsoft`.
pub fn provider_endpoints(provider: &str) -> Option<ProviderEndpoints> {
    match provider {
        "google" => Some(ProviderEndpoints {
            authorize: "https://accounts.google.com/o/oauth2/v2/auth".into(),
            token: "https://oauth2.googleapis.com/token".into(),
            scope: "openid email https://mail.google.com/",
        }),
        "microsoft" => Some(ProviderEndpoints {
            authorize: "https://login.microsoftonline.com/common/oauth2/v2.0/authorize".into(),
            token: "https://login.microsoftonline.com/common/oauth2/v2.0/token".into(),
            scope: "openid email offline_access https://outlook.office.com/IMAP.AccessAsUser.All",
        }),
        _ => None,
    }
}

/// Python `OAuthError`; the message is user-facing (the router answers 503
/// for start failures and renders it in the callback page).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct OAuthError(pub String);

impl OAuthError {
    fn new(message: &str) -> Self {
        Self(message.to_string())
    }
}

/// A pending authorization taken back by the callback.
#[derive(Clone, PartialEq)]
pub struct OAuthFlow {
    pub provider: String,
    pub email: String,
    pub days: i64,
    pub verifier: String,
    /// Seconds since the Unix epoch.
    pub created: f64,
    /// The browser-extension origin that started the flow; the callback page
    /// posts its result there (`None`: the configured `frontend_url`).
    pub message_origin: Option<String>,
}

impl fmt::Debug for OAuthFlow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OAuthFlow")
            .field("provider", &self.provider)
            .field("email", &self.email)
            .field("days", &self.days)
            .field("verifier", &"<redacted>")
            .field("created", &self.created)
            .field("message_origin", &self.message_origin)
            .finish()
    }
}

type Clock = Arc<dyn Fn() -> f64 + Send + Sync>;

fn system_clock() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
}

/// Python `secrets.token_urlsafe(nbytes)`.
pub fn token_urlsafe(nbytes: usize) -> String {
    let mut bytes = vec![0u8; nbytes];
    getrandom::getrandom(&mut bytes).expect("the operating system random source is available");
    URL_SAFE_NO_PAD.encode(bytes)
}

/// PKCE S256 challenge for a verifier.
pub fn pkce_challenge(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

/// Python `urllib.parse.quote_plus` (safe: letters, digits, `_.-~`).
pub fn quote_plus(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'_' | b'.' | b'-' | b'~' => {
                out.push(byte as char)
            }
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

/// Python `urllib.parse.urlencode` for string pairs.
pub fn urlencode(pairs: &[(&str, &str)]) -> String {
    pairs
        .iter()
        .map(|(key, value)| format!("{}={}", quote_plus(key), quote_plus(value)))
        .collect::<Vec<_>>()
        .join("&")
}

/// Python `OAuthService`.
pub struct OAuthService {
    public_backend_url: String,
    google: (String, String),
    microsoft: (String, String),
    flows: Mutex<HashMap<String, OAuthFlow>>,
    token_overrides: Mutex<HashMap<String, String>>,
    clock: Clock,
}

impl fmt::Debug for OAuthService {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OAuthService")
            .field("public_backend_url", &self.public_backend_url)
            .field("google_configured", &self.is_configured("google"))
            .field("microsoft_configured", &self.is_configured("microsoft"))
            .finish()
    }
}

impl OAuthService {
    pub fn new(settings: &DoctorSettings) -> Self {
        Self::with_clock(settings, Arc::new(system_clock))
    }

    /// Like [`OAuthService::new`] with an injectable clock (seconds since the
    /// epoch), so flow expiry can be tested.
    pub fn with_clock(
        settings: &DoctorSettings,
        clock: Arc<dyn Fn() -> f64 + Send + Sync>,
    ) -> Self {
        Self {
            public_backend_url: settings.public_backend_url.clone(),
            google: (
                settings.google_oauth_client_id.clone(),
                settings.google_oauth_client_secret.clone(),
            ),
            microsoft: (
                settings.microsoft_oauth_client_id.clone(),
                settings.microsoft_oauth_client_secret.clone(),
            ),
            flows: Mutex::new(HashMap::new()),
            token_overrides: Mutex::new(HashMap::new()),
            clock,
        }
    }

    /// Replace a provider's token endpoint (tests point it at a local server).
    #[doc(hidden)]
    pub fn override_token_url(&self, provider: &str, url: &str) {
        self.token_overrides
            .lock()
            .unwrap()
            .insert(provider.to_string(), url.to_string());
    }

    fn client(&self, provider: &str) -> (&str, &str) {
        match provider {
            "google" => (&self.google.0, &self.google.1),
            "microsoft" => (&self.microsoft.0, &self.microsoft.1),
            _ => ("", ""),
        }
    }

    /// `{public_backend_url}/api/mail/oauth/{provider}/callback`.
    pub fn callback_url(&self, provider: &str) -> String {
        format!(
            "{}/api/mail/oauth/{provider}/callback",
            self.public_backend_url
        )
    }

    /// Google needs a client ID and secret; Microsoft (public client) only an ID.
    pub fn is_configured(&self, provider: &str) -> bool {
        let (client_id, client_secret) = self.client(provider);
        if provider == "google" {
            !client_id.is_empty() && !client_secret.is_empty()
        } else {
            !client_id.is_empty()
        }
    }

    /// Python `start_flow`: returns `(authorization_url, state)`.
    pub fn start_flow(
        &self,
        provider: &str,
        email: &str,
        days: i64,
    ) -> Result<(String, String), OAuthError> {
        self.start_flow_for_origin(provider, email, days, None)
    }

    /// [`OAuthService::start_flow`] remembering the extension origin whose
    /// page opened the sign-in window (stored with the pending flow, in
    /// memory only).
    pub fn start_flow_for_origin(
        &self,
        provider: &str,
        email: &str,
        days: i64,
        message_origin: Option<&str>,
    ) -> Result<(String, String), OAuthError> {
        let Some(endpoints) = provider_endpoints(provider) else {
            return Err(OAuthError::new("Unsupported OAuth provider"));
        };
        if !self.is_configured(provider) {
            let names = if provider == "google" {
                "GOOGLE_OAUTH_CLIENT_ID and GOOGLE_OAUTH_CLIENT_SECRET"
            } else {
                "MICROSOFT_OAUTH_CLIENT_ID"
            };
            return Err(OAuthError(format!(
                "OAuth is not configured; set {names} in .env"
            )));
        }
        let state = token_urlsafe(32);
        let verifier = token_urlsafe(64);
        let challenge = pkce_challenge(&verifier);
        {
            let mut flows = self.flows.lock().unwrap();
            self.purge_expired(&mut flows);
            if flows.len() >= MAX_PENDING_FLOWS {
                return Err(OAuthError::new(
                    "Too many pending OAuth requests; try again later",
                ));
            }
            flows.insert(
                state.clone(),
                OAuthFlow {
                    provider: provider.to_string(),
                    email: email.to_string(),
                    days,
                    verifier,
                    created: (self.clock)(),
                    message_origin: message_origin.map(str::to_string),
                },
            );
        }
        let (client_id, _) = self.client(provider);
        let redirect_uri = self.callback_url(provider);
        let mut params = vec![
            ("client_id", client_id),
            ("redirect_uri", redirect_uri.as_str()),
            ("response_type", "code"),
            ("scope", endpoints.scope),
            ("state", state.as_str()),
            ("code_challenge", challenge.as_str()),
            ("code_challenge_method", "S256"),
            ("login_hint", email),
        ];
        if provider == "google" {
            params.push(("access_type", "offline"));
            params.push(("prompt", "consent"));
        }
        let url = format!("{}?{}", endpoints.authorize, urlencode(&params));
        Ok((url, state))
    }

    /// Python `take_flow`: remove and return the pending flow for `state`.
    pub fn take_flow(&self, state: &str, provider: &str) -> Result<OAuthFlow, OAuthError> {
        let flow = self.flows.lock().unwrap().remove(state);
        match flow {
            Some(flow)
                if flow.provider == provider
                    && (self.clock)() - flow.created <= FLOW_TTL_SECONDS =>
            {
                Ok(flow)
            }
            _ => Err(OAuthError::new(
                "OAuth request is missing, expired, or invalid",
            )),
        }
    }

    /// Number of pending (possibly expired) flows.
    pub fn pending_flows(&self) -> usize {
        self.flows.lock().unwrap().len()
    }

    /// Python `exchange_code`: trade the authorization code for an access
    /// token (blocking HTTP; call from a blocking thread).
    pub fn exchange_code(
        &self,
        provider: &str,
        code: &str,
        flow: &OAuthFlow,
    ) -> Result<String, OAuthError> {
        let Some(endpoints) = provider_endpoints(provider) else {
            return Err(OAuthError::new("Unsupported OAuth provider"));
        };
        let token_url = self
            .token_overrides
            .lock()
            .unwrap()
            .get(provider)
            .cloned()
            .unwrap_or(endpoints.token);
        let (client_id, client_secret) = self.client(provider);
        let redirect_uri = self.callback_url(provider);
        let mut payload = vec![
            ("client_id", client_id),
            ("code", code),
            ("redirect_uri", redirect_uri.as_str()),
            ("grant_type", "authorization_code"),
            ("code_verifier", flow.verifier.as_str()),
        ];
        if !client_secret.is_empty() {
            payload.push(("client_secret", client_secret));
        }
        let exchange_failed =
            || OAuthError::new("The provider did not complete the token exchange");
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|_| exchange_failed())?;
        let response = client
            .post(token_url)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(urlencode(&payload))
            .send()
            .map_err(|_| exchange_failed())?;
        if !response.status().is_success() {
            return Err(exchange_failed());
        }
        let bytes = response.bytes().map_err(|_| exchange_failed())?;
        let text = std::str::from_utf8(&bytes).map_err(|_| exchange_failed())?;
        let body: serde_json::Value = serde_json::from_str(text).map_err(|_| exchange_failed())?;
        let missing = || OAuthError::new("The provider response did not contain an access token");
        match body.get("access_token") {
            Some(serde_json::Value::String(token)) if !token.is_empty() => Ok(token.clone()),
            Some(serde_json::Value::Number(number)) if number.as_f64() != Some(0.0) => {
                Ok(number.to_string())
            }
            _ => Err(missing()),
        }
    }

    fn purge_expired(&self, flows: &mut HashMap<String, OAuthFlow>) {
        let cutoff = (self.clock)() - FLOW_TTL_SECONDS;
        flows.retain(|_, flow| flow.created >= cutoff);
    }
}

// ---------------------------------------------------------------------------
// Callback page (router.py `oauth_callback`)
// ---------------------------------------------------------------------------

/// Python `html.escape(text, quote=True)`.
pub fn html_escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#x27;"),
            _ => out.push(c),
        }
    }
    out
}

/// Python `json.dumps(str)` (ASCII-only output).
fn python_json_string(text: &str) -> String {
    let mut out = String::from("\"");
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 || (c as u32) > 0x7e => {
                let mut units = [0u16; 2];
                for unit in c.encode_utf16(&mut units) {
                    out.push_str(&format!("\\u{unit:04x}"));
                }
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// The `postMessage` payload sent to the opener window by the callback page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CallbackMessage {
    /// `{"type": "email-doctor-oauth", "jobId": ...}`
    Started { job_id: String },
    /// `{"type": "email-doctor-oauth", "error": ...}`
    Failed { error: String },
}

impl CallbackMessage {
    /// Python `json.dumps(message)` (default separators, `ensure_ascii`).
    pub fn to_python_json(&self) -> String {
        let (key, value) = match self {
            Self::Started { job_id } => ("jobId", job_id),
            Self::Failed { error } => ("error", error),
        };
        format!(
            "{{\"type\": \"email-doctor-oauth\", {}: {}}}",
            python_json_string(key),
            python_json_string(value)
        )
    }
}

/// Response headers of the callback page.
pub const CALLBACK_HEADERS: [(&str, &str); 2] = [
    ("Cache-Control", "no-store"),
    ("Referrer-Policy", "no-referrer"),
];

/// The exact HTML document returned by `GET /api/mail/oauth/{provider}/callback`
/// (`title`: "Permission granted" or "Could not connect mailbox").
pub fn render_callback_page(
    title: &str,
    detail: &str,
    message: &CallbackMessage,
    frontend_url: &str,
) -> String {
    let payload = message.to_python_json().replace('<', "\\u003c");
    let origin = python_json_string(frontend_url).replace('<', "\\u003c");
    let title = html_escape(title);
    let detail = html_escape(detail);
    format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>{title}</title></head>\
         <body style=\"font-family:system-ui;padding:2rem\"><h2>{title}</h2><p>{detail}</p>\
         <script>if(window.opener){{window.opener.postMessage({payload},{origin});setTimeout(()=>window.close(),500);}}</script></body></html>"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn settings() -> DoctorSettings {
        let mut settings = DoctorSettings::with_defaults("/data");
        settings.public_backend_url = "http://localhost:48101".into();
        settings.google_oauth_client_id = "google-id".into();
        settings.google_oauth_client_secret = "google-secret".into();
        settings.microsoft_oauth_client_id = "ms-id".into();
        settings
    }

    #[test]
    fn configuration_rules() {
        let mut unconfigured = DoctorSettings::with_defaults("/data");
        unconfigured.google_oauth_client_id = "only-id".into();
        let service = OAuthService::new(&unconfigured);
        assert!(!service.is_configured("google"));
        assert!(!service.is_configured("microsoft"));
        assert_eq!(
            service.start_flow("google", "u@gmail.com", 7).unwrap_err().0,
            "OAuth is not configured; set GOOGLE_OAUTH_CLIENT_ID and GOOGLE_OAUTH_CLIENT_SECRET in .env"
        );
        assert_eq!(
            service
                .start_flow("microsoft", "u@outlook.com", 7)
                .unwrap_err()
                .0,
            "OAuth is not configured; set MICROSOFT_OAUTH_CLIENT_ID in .env"
        );
        assert_eq!(
            service.start_flow("yahoo", "u@yahoo.com", 7).unwrap_err().0,
            "Unsupported OAuth provider"
        );
        let service = OAuthService::new(&settings());
        assert!(service.is_configured("google") && service.is_configured("microsoft"));
        assert_eq!(
            service.callback_url("google"),
            "http://localhost:48101/api/mail/oauth/google/callback"
        );
    }

    #[test]
    fn authorization_url_has_pkce_and_provider_parameters() {
        let service = OAuthService::new(&settings());
        let (url, state) = service.start_flow("google", "u+x@gmail.com", 5).unwrap();
        assert_eq!(state.len(), 43);
        let parsed = url::Url::parse(&url).unwrap();
        assert_eq!(parsed.host_str(), Some("accounts.google.com"));
        let query: HashMap<String, String> = parsed.query_pairs().into_owned().collect();
        assert_eq!(query["client_id"], "google-id");
        assert_eq!(query["state"], state);
        assert_eq!(query["scope"], "openid email https://mail.google.com/");
        assert_eq!(query["login_hint"], "u+x@gmail.com");
        assert_eq!(query["access_type"], "offline");
        assert_eq!(query["prompt"], "consent");
        assert_eq!(query["code_challenge_method"], "S256");
        assert!(url.contains("login_hint=u%2Bx%40gmail.com"));
        assert!(url.contains("scope=openid+email+https%3A%2F%2Fmail.google.com%2F"));
        let flow = service.take_flow(&state, "google").unwrap();
        assert_eq!(query["code_challenge"], pkce_challenge(&flow.verifier));
        assert_eq!((flow.email.as_str(), flow.days), ("u+x@gmail.com", 5));
        assert!(!format!("{flow:?}").contains(&flow.verifier));
        // A state can only be used once.
        assert!(service.take_flow(&state, "google").is_err());

        let (url, state) = service.start_flow("microsoft", "u@outlook.com", 7).unwrap();
        assert!(!url.contains("access_type"));
        // Wrong provider consumes and rejects the flow.
        assert_eq!(
            service.take_flow(&state, "google").unwrap_err().0,
            "OAuth request is missing, expired, or invalid"
        );
    }

    #[test]
    fn flows_expire_and_are_bounded() {
        let now = Arc::new(AtomicU64::new(1_000_000));
        let clock_now = now.clone();
        let service = OAuthService::with_clock(
            &settings(),
            Arc::new(move || clock_now.load(Ordering::SeqCst) as f64),
        );
        let (_, state) = service.start_flow("google", "u@gmail.com", 7).unwrap();
        now.fetch_add(601, Ordering::SeqCst);
        assert!(service.take_flow(&state, "google").is_err());
        for _ in 0..MAX_PENDING_FLOWS {
            service.start_flow("google", "u@gmail.com", 7).unwrap();
        }
        assert_eq!(
            service
                .start_flow("google", "u@gmail.com", 7)
                .unwrap_err()
                .0,
            "Too many pending OAuth requests; try again later"
        );
        now.fetch_add(601, Ordering::SeqCst);
        service.start_flow("google", "u@gmail.com", 7).unwrap();
        assert_eq!(service.pending_flows(), 1);
    }

    fn serve_once(status: &str, body: &'static str) -> (String, std::thread::JoinHandle<String>) {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/token", listener.local_addr().unwrap());
        let status = status.to_string();
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut request = Vec::new();
            let mut buffer = [0u8; 4096];
            loop {
                let read = stream.read(&mut buffer).unwrap_or(0);
                request.extend_from_slice(&buffer[..read]);
                let text = String::from_utf8_lossy(&request);
                if let Some(end) = text.find("\r\n\r\n") {
                    let length = text
                        .lines()
                        .find_map(|l| {
                            l.to_ascii_lowercase()
                                .strip_prefix("content-length:")
                                .map(|v| v.trim().parse::<usize>().unwrap())
                        })
                        .unwrap_or(0);
                    if request.len() >= end + 4 + length || read == 0 {
                        break;
                    }
                }
                if read == 0 {
                    break;
                }
            }
            let response = format!(
                "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            stream.write_all(response.as_bytes()).unwrap();
            String::from_utf8_lossy(&request).into_owned()
        });
        (url, handle)
    }

    #[test]
    fn token_exchange_posts_pkce_form_and_returns_token() {
        let service = OAuthService::new(&settings());
        let (_, state) = service.start_flow("google", "u@gmail.com", 7).unwrap();
        let flow = service.take_flow(&state, "google").unwrap();
        let (url, server) = serve_once(
            "200 OK",
            r#"{"access_token": "memory-token", "expires_in": 3600}"#,
        );
        service.override_token_url("google", &url);
        assert_eq!(
            service.exchange_code("google", "the code", &flow).unwrap(),
            "memory-token"
        );
        let request = server.join().unwrap();
        assert!(request.starts_with("POST /token"));
        assert!(request.contains("grant_type=authorization_code"));
        assert!(request.contains("code=the+code"));
        assert!(request.contains(&format!("code_verifier={}", flow.verifier)));
        assert!(request.contains("client_secret=google-secret"));

        let (url, server) = serve_once("400 Bad Request", r#"{"error": "invalid_grant"}"#);
        service.override_token_url("google", &url);
        assert_eq!(
            service.exchange_code("google", "c", &flow).unwrap_err().0,
            "The provider did not complete the token exchange"
        );
        server.join().unwrap();

        let (url, server) = serve_once("200 OK", r#"{"token_type": "Bearer"}"#);
        service.override_token_url("google", &url);
        assert_eq!(
            service.exchange_code("google", "c", &flow).unwrap_err().0,
            "The provider response did not contain an access token"
        );
        server.join().unwrap();
    }

    #[test]
    fn microsoft_public_client_omits_secret() {
        let service = OAuthService::new(&settings());
        let (_, state) = service.start_flow("microsoft", "u@outlook.com", 7).unwrap();
        let flow = service.take_flow(&state, "microsoft").unwrap();
        let (url, server) = serve_once("200 OK", r#"{"access_token": "t"}"#);
        service.override_token_url("microsoft", &url);
        assert_eq!(service.exchange_code("microsoft", "c", &flow).unwrap(), "t");
        assert!(!server.join().unwrap().contains("client_secret"));
    }

    #[test]
    fn callback_page_matches_python_rendering() {
        let message = CallbackMessage::Started {
            job_id: "abc".into(),
        };
        assert_eq!(
            message.to_python_json(),
            r#"{"type": "email-doctor-oauth", "jobId": "abc"}"#
        );
        let failed = CallbackMessage::Failed {
            error: "<b>é\"".into(),
        };
        assert_eq!(
            failed.to_python_json(),
            concat!(
                r#"{"type": "email-doctor-oauth", "error": "<b>"#,
                "\u{5c}u00e9",
                r#"\""}"#
            )
        );
        let page = render_callback_page(
            "Could not connect <mailbox>",
            "x & 'y'",
            &failed,
            "http://localhost:3741",
        );
        assert!(page.starts_with("<!doctype html><html><head><meta charset=\"utf-8\"><title>Could not connect &lt;mailbox&gt;</title>"));
        assert!(page.contains("<p>x &amp; &#x27;y&#x27;</p>"));
        assert!(page.contains(concat!(
            r#"window.opener.postMessage({"type": "email-doctor-oauth", "error": "#,
            "\"\u{5c}u003cb>\u{5c}u00e9",
            r#"\""},"http://localhost:3741");"#
        )));
        assert!(!page.contains("<b>"));
    }
}
