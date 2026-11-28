//! Loopback Host / extension Origin guard and CORS policy.
//!
//! Replaces `CORSMiddleware(allow_origins=CORS_ORIGINS)` from
//! `backend/app/main.py`. The original served a web frontend on
//! `http://localhost:3741`; this port is consumed by a browser extension (and
//! the local MCP server), so the policy follows the_editor's office-backend:
//!
//! * The `Host` header (or HTTP/2 authority) must name loopback —
//!   an IPv4 literal in `127.0.0.0/8` (the backend may listen on e.g.
//!   `127.0.0.2`), `localhost` or `[::1]`, any port. This defeats DNS
//!   rebinding: a page on `evil.example` that resolves to 127.0.0.1 still
//!   sends `Host: evil.example`.
//! * A request carrying an `Origin` is accepted only from an *allowed*
//!   browser-extension origin: `chrome-extension://<id>`, `extension://<id>`
//!   (Edge) or `moz-extension://<id>` whose id is on the allow-list. By
//!   default the list holds only this extension's pinned id
//!   ([`DEFAULT_EXTENSION_ID`], derived by Chrome and Edge from the manifest
//!   `key`), so another installed extension cannot read mailboxes through the
//!   reflected CORS grant. [`EXTENSION_IDS_ENV`] (`MAIL_BACKEND_EXTENSION_IDS`,
//!   comma-separated ids, read once at first use) replaces that list — e.g.
//!   for an unpacked development copy without the key, or for Firefox, whose
//!   `moz-extension://` origins carry a random per-install UUID and are
//!   therefore only allowed when listed there. The value `*` is an explicit,
//!   **insecure** development opt-in that trusts every extension id. Web pages
//!   always send `Origin` on cross-site POST/PUT/DELETE and CORS fetches, so
//!   they are refused with 403 before any handler runs.
//! * Requests without `Origin` (MCP server, curl, tests) are accepted unless
//!   `Sec-Fetch-Site` says another site issued them (`cross-site` /
//!   `same-site`): that is an `<img>`/`<script>`/form probe from a web page.
//!   A user typing the URL sends `Sec-Fetch-Site: none`.
//! * Exception: the OAuth provider redirects the sign-in window to
//!   `GET /api/mail/oauth/{provider}/callback`, a top-level cross-site
//!   navigation without `Origin`. Such navigations (`Sec-Fetch-Mode:
//!   navigate`, `Sec-Fetch-Dest: document`, or the headers absent) are let
//!   through for that one path. The page only completes a flow whose
//!   unguessable `state` the extension started, and posts the result to that
//!   extension's origin, so a web page gains nothing readable from it.
//! * CORS headers are reflected only for allowed extension origins.

use std::net::Ipv4Addr;
use std::sync::OnceLock;
use std::time::Duration;

use axum::extract::Request;
use axum::http::{header, HeaderValue, Method};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use tower_http::cors::{AllowOrigin, CorsLayer};

use crate::error::ApiError;

/// Origin schemes of browser extensions allowed to call the backend.
pub const EXTENSION_ORIGIN_PREFIXES: [&str; 3] =
    ["chrome-extension://", "extension://", "moz-extension://"];

/// Id of this extension in Chrome and Edge (pinned by the manifest `key`).
pub const DEFAULT_EXTENSION_ID: &str = "hhhanbkdjaecdfoclhpoicmfhejdbkjl";

/// Environment variable replacing the extension-id allow-list
/// (comma-separated ids; `*` trusts every id — insecure, development only).
pub const EXTENSION_IDS_ENV: &str = "MAIL_BACKEND_EXTENSION_IDS";

/// Which extension ids may call the backend.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExtensionIds {
    /// Any syntactically valid id (`MAIL_BACKEND_EXTENSION_IDS=*`). Insecure:
    /// every installed extension can read the unlocked mailboxes.
    Any,
    /// Exactly these ids (lowercase), under any extension scheme.
    Only(Vec<String>),
}

impl ExtensionIds {
    /// The default list: [`DEFAULT_EXTENSION_ID`] only.
    pub fn default_list() -> Self {
        Self::Only(vec![DEFAULT_EXTENSION_ID.to_string()])
    }

    /// Parse the value of [`EXTENSION_IDS_ENV`]: unset or blank → the
    /// default list; `*` (alone or among the entries) → [`ExtensionIds::Any`];
    /// otherwise the comma-separated ids, trimmed and lowercased, where a full
    /// origin (`chrome-extension://<id>/`) is reduced to its id. Entries that
    /// are not valid ids are ignored; if none remains the default list is used.
    pub fn parse(value: Option<&str>) -> Self {
        let Some(value) = value.filter(|value| !value.trim().is_empty()) else {
            return Self::default_list();
        };
        let mut ids: Vec<String> = Vec::new();
        for entry in value.split(',') {
            let entry = entry.trim().to_ascii_lowercase();
            if entry == "*" {
                return Self::Any;
            }
            let id = EXTENSION_ORIGIN_PREFIXES
                .iter()
                .find_map(|prefix| entry.strip_prefix(prefix))
                .unwrap_or(&entry)
                .trim_end_matches('/');
            if valid_extension_id(id) && !ids.iter().any(|known| known == id) {
                ids.push(id.to_string());
            }
        }
        if ids.is_empty() {
            tracing::warn!("{EXTENSION_IDS_ENV} lists no valid extension id; using the default");
            return Self::default_list();
        }
        Self::Only(ids)
    }

    /// True when `id` (already lowercase) is allowed.
    pub fn allows(&self, id: &str) -> bool {
        match self {
            Self::Any => true,
            Self::Only(ids) => ids.iter().any(|known| known == id),
        }
    }

    /// Human-readable list for the start-up log.
    pub fn describe(&self) -> String {
        match self {
            Self::Any => {
                format!("any extension id ({EXTENSION_IDS_ENV}=*; INSECURE, development only)")
            }
            Self::Only(ids) => ids.join(", "),
        }
    }
}

/// The process-wide allow-list, read from [`EXTENSION_IDS_ENV`] once.
pub fn allowed_extension_ids() -> &'static ExtensionIds {
    static IDS: OnceLock<ExtensionIds> = OnceLock::new();
    IDS.get_or_init(|| ExtensionIds::parse(std::env::var(EXTENSION_IDS_ENV).ok().as_deref()))
}

/// A non-empty extension id of `[a-z0-9._-]` (lowercase input).
fn valid_extension_id(id: &str) -> bool {
    !id.is_empty()
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_'))
}

/// True when a `Host` header value names loopback: an IPv4 literal in
/// `127.0.0.0/8` (dotted quad, as `Ipv4Addr` parses it — no shorthand,
/// octal or integer forms), `localhost` or `[::1]`, optionally with a numeric
/// port.
pub fn host_allowed(host: &[u8]) -> bool {
    let Ok(host) = std::str::from_utf8(host) else {
        return false;
    };
    let host = host.trim().to_ascii_lowercase();
    let (name, port) = if host.starts_with('[') {
        match host.find(']') {
            Some(end) => (&host[..=end], &host[end + 1..]),
            None => return false,
        }
    } else {
        match host.find(':') {
            Some(colon) => (&host[..colon], &host[colon..]),
            None => (host.as_str(), ""),
        }
    };
    let port_ok = port.is_empty()
        || (port.len() >= 2
            && port.len() <= 6
            && port.starts_with(':')
            && port[1..].bytes().all(|byte| byte.is_ascii_digit()));
    let name_ok = matches!(name, "localhost" | "[::1]")
        || name
            .parse::<Ipv4Addr>()
            .is_ok_and(|address| address.is_loopback());
    port_ok && name_ok
}

/// True for allowed browser-extension origins (see the module docs): one of
/// [`EXTENSION_ORIGIN_PREFIXES`] followed by an id on the process-wide
/// allow-list ([`allowed_extension_ids`]).
pub fn origin_allowed(origin: &[u8]) -> bool {
    origin_allowed_for(origin, allowed_extension_ids())
}

/// [`origin_allowed`] against an explicit allow-list (pure; for tests).
pub fn origin_allowed_for(origin: &[u8], ids: &ExtensionIds) -> bool {
    let Ok(origin) = std::str::from_utf8(origin) else {
        return false;
    };
    let origin = origin.trim().to_ascii_lowercase();
    EXTENSION_ORIGIN_PREFIXES.iter().any(|prefix| {
        origin
            .strip_prefix(prefix)
            .is_some_and(|id| valid_extension_id(id) && ids.allows(id))
    })
}

/// True for `GET /api/mail/oauth/{provider}/callback` issued as a top-level
/// document navigation (the provider's redirect of the sign-in window).
pub fn is_oauth_callback_navigation(request: &Request) -> bool {
    if request.method() != Method::GET {
        return false;
    }
    let is_callback = request
        .uri()
        .path()
        .strip_prefix("/api/mail/oauth/")
        .and_then(|rest| rest.strip_suffix("/callback"))
        .is_some_and(|provider| !provider.is_empty() && !provider.contains('/'));
    let header_is = |name: &str, expected: &[u8]| {
        request
            .headers()
            .get(name)
            .is_none_or(|value| value.as_bytes().eq_ignore_ascii_case(expected))
    };
    is_callback
        && header_is("sec-fetch-mode", b"navigate")
        && header_is("sec-fetch-dest", b"document")
}

/// Middleware enforcing the Host / Origin / Sec-Fetch-Site rules above.
/// Refusals are JSON 403 `{"detail": "Forbidden: ..."}` without CORS headers.
pub async fn guard(request: Request, next: Next) -> Response {
    // HTTP/2 carries the authority in the URI instead of a Host header.
    let host = request
        .headers()
        .get(header::HOST)
        .map(|value| value.as_bytes().to_vec())
        .or_else(|| {
            request
                .uri()
                .authority()
                .map(|authority| authority.as_str().as_bytes().to_vec())
        });
    if let Some(host) = host {
        if !host_allowed(&host) {
            tracing::warn!(
                "refused request for foreign Host {:?}",
                String::from_utf8_lossy(&host)
            );
            return ApiError::forbidden(format!(
                "Forbidden: requests must be addressed to 127.0.0.1 or localhost (got Host {:?}).",
                String::from_utf8_lossy(&host)
            ))
            .into_response();
        }
    }
    if let Some(origin) = request.headers().get(header::ORIGIN) {
        if !origin_allowed(origin.as_bytes()) {
            tracing::warn!(
                "refused request from Origin {:?}",
                String::from_utf8_lossy(origin.as_bytes())
            );
            return ApiError::forbidden(format!(
                "Forbidden: only the browser extension may use this service (Origin {:?} refused).",
                String::from_utf8_lossy(origin.as_bytes())
            ))
            .into_response();
        }
    } else if !is_oauth_callback_navigation(&request)
        && request
            .headers()
            .get("sec-fetch-site")
            .is_some_and(|value| {
                matches!(
                    value.as_bytes().to_ascii_lowercase().as_slice(),
                    b"cross-site" | b"same-site"
                )
            })
    {
        // No Origin but issued by another web page (an <img>/<script>/form
        // GET used for probing). Extension fetches carry their Origin; a user
        // opening a URL in a tab sends Sec-Fetch-Site: none.
        return ApiError::forbidden("Forbidden: only the browser extension may use this service.")
            .into_response();
    }
    next.run(request).await
}

/// CORS for allowed extension origins only: methods GET/POST/PUT/DELETE (as in
/// main.py), JSON/multipart request headers, and `Content-Disposition`
/// exposed for downloads.
pub fn cors_layer() -> CorsLayer {
    CorsLayer::new()
        .allow_origin(AllowOrigin::predicate(|origin: &HeaderValue, _| {
            origin_allowed(origin.as_bytes())
        }))
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::DELETE,
            Method::OPTIONS,
        ])
        .allow_headers([
            header::CONTENT_TYPE,
            header::ACCEPT,
            header::ACCEPT_LANGUAGE,
            header::CACHE_CONTROL,
        ])
        .expose_headers([header::CONTENT_DISPOSITION])
        .allow_private_network(true)
        .max_age(Duration::from_secs(600))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_rules() {
        for ok in [
            "127.0.0.1",
            "127.0.0.1:48101",
            "127.0.0.2:48101",
            "127.255.255.254",
            "localhost",
            "LOCALHOST:1",
            "[::1]",
            "[::1]:48101",
            " localhost:48101 ",
        ] {
            assert!(host_allowed(ok.as_bytes()), "{ok}");
        }
        for bad in [
            "evil.example",
            "evil.example:48101",
            "127.0.0.1.evil.example",
            "localhost.evil:80",
            "128.0.0.1:48101",
            "127.1:48101",
            "127.0.0.01",
            "2130706433",
            "[::2]:1",
            "localhost:abc",
            "localhost:",
            "localhost:1234567",
            "[::1",
            "0.0.0.0:48101",
            "",
        ] {
            assert!(!host_allowed(bad.as_bytes()), "{bad}");
        }
        assert!(!host_allowed(b"local\xffhost"));
    }

    const OWN: &str = "chrome-extension://hhhanbkdjaecdfoclhpoicmfhejdbkjl";

    #[test]
    fn origin_rules() {
        let default = ExtensionIds::default_list();
        let any = ExtensionIds::Any;
        for ok in [
            OWN,
            "extension://hhhanbkdjaecdfoclhpoicmfhejdbkjl",
            "CHROME-EXTENSION://HHHANBKDJAECDFOCLHPOICMFHEJDBKJL",
            " chrome-extension://hhhanbkdjaecdfoclhpoicmfhejdbkjl ",
        ] {
            assert!(origin_allowed_for(ok.as_bytes(), &default), "{ok}");
            assert!(origin_allowed_for(ok.as_bytes(), &any), "{ok}");
        }
        // Other extensions (and Firefox's random per-install UUIDs) are only
        // allowed when listed, or with the insecure `*` opt-in.
        for foreign in [
            "chrome-extension://omagnaefngeklmcndepoihhodddomkgo",
            "chrome-extension://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "extension://abc",
            "moz-extension://1234-abcd",
            "chrome-extension://hhhanbkdjaecdfoclhpoicmfhejdbkjlx",
        ] {
            assert!(
                !origin_allowed_for(foreign.as_bytes(), &default),
                "{foreign}"
            );
            assert!(origin_allowed_for(foreign.as_bytes(), &any), "{foreign}");
        }
        for bad in [
            "https://evil.example",
            "null",
            "chrome-extension://",
            "http://127.0.0.1:48101",
            "http://localhost:3741",
            "file://",
            "chrome-extension://hhhanbkdjaecdfoclhpoicmfhejdbkjl/b",
            "chrome-extension://a b",
            "chrome-extensionx://hhhanbkdjaecdfoclhpoicmfhejdbkjl",
            "https://hhhanbkdjaecdfoclhpoicmfhejdbkjl",
        ] {
            assert!(!origin_allowed_for(bad.as_bytes(), &default), "{bad}");
            assert!(!origin_allowed_for(bad.as_bytes(), &any), "{bad}");
        }
        assert!(!origin_allowed_for(b"chrome-extension://\xff", &any));
        // The process-wide list (no env var in tests) is the default.
        assert!(origin_allowed(OWN.as_bytes()));
        assert!(!origin_allowed(
            b"chrome-extension://omagnaefngeklmcndepoihhodddomkgo"
        ));
    }

    #[test]
    fn extension_id_list_parsing() {
        let default = ExtensionIds::default_list();
        assert_eq!(ExtensionIds::parse(None), default);
        assert_eq!(ExtensionIds::parse(Some("  ")), default);
        assert_eq!(ExtensionIds::parse(Some(" , ,")), default);
        assert_eq!(ExtensionIds::parse(Some("bad id!")), default);
        assert_eq!(ExtensionIds::parse(Some("*")), ExtensionIds::Any);
        assert_eq!(ExtensionIds::parse(Some("abc, *")), ExtensionIds::Any);
        let listed = ExtensionIds::parse(Some(
            " ABCdef , moz-extension://1b2c-3d4e/,abcdef,chrome-extension://hhhanbkdjaecdfoclhpoicmfhejdbkjl",
        ));
        assert_eq!(
            listed,
            ExtensionIds::Only(vec![
                "abcdef".into(),
                "1b2c-3d4e".into(),
                DEFAULT_EXTENSION_ID.into()
            ])
        );
        // The list replaces the default and applies to every scheme.
        let only_other = ExtensionIds::parse(Some("abcdef,1b2c-3d4e"));
        assert!(origin_allowed_for(b"extension://abcdef", &only_other));
        assert!(origin_allowed_for(
            b"moz-extension://1b2c-3d4e",
            &only_other
        ));
        assert!(!origin_allowed_for(OWN.as_bytes(), &only_other));
        assert!(listed.describe().contains("abcdef"));
        assert!(ExtensionIds::Any.describe().contains("INSECURE"));
    }
}
