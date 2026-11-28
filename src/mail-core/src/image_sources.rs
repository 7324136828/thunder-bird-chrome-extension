//! Remote image URLs that each rendered message may load (port of
//! `app/mail/image_sources.py`).
//!
//! # Fixed public contract (Phase 2)
//! `ImageSources` is held in `AppState`; `fetch_message`'s route registers the
//! message HTML, the image proxy route checks `sources`, and account lock /
//! shutdown call `forget` / `clear`.
//!
//! URL extraction follows Python 3.14's `html.parser.HTMLParser`
//! (`images_parts/html.rs`), fed once without `close()` exactly like
//! `image_urls` did, and `normalize_url` follows `urllib.parse` and the
//! `"idna"` codec (`images_parts/urllib.rs`).

use std::collections::{HashSet, VecDeque};
use std::sync::{Arc, LazyLock, Mutex};
use std::time::{Duration, Instant};

use regex::Regex;

#[path = "images_parts/entities.rs"]
mod entities;
#[path = "images_parts/html.rs"]
mod html;
#[path = "images_parts/ip.rs"]
pub(crate) mod ip;
#[path = "images_parts/stringprep.rs"]
mod stringprep;
#[path = "images_parts/urllib.rs"]
pub(crate) mod urllib;

use urllib::{idna_encode, py_split, py_strip, quote, urlsplit, urlunsplit};

/// `MAX_SOURCES`: URLs recorded per message.
pub const MAX_SOURCES: usize = 256;
/// `MAX_MESSAGES`: messages remembered per process.
pub const MAX_MESSAGES: usize = 128;
/// `SOURCE_TTL`: how long a registration stays valid.
pub const SOURCE_TTL: Duration = Duration::from_secs(30 * 60);

/// `_CSS_URL` (`re.I`; Python's `\s` also covers `\x1c`-`\x1f`).
static CSS_URL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?i)url\([\s\x1c-\x1f]*(?:"([^"]*)"|'([^']*)'|([^\s\x1c-\x1f)]*))[\s\x1c-\x1f]*\)"#,
    )
    .expect("valid CSS url() pattern")
});

/// `_normalize_path`: resolve literal and percent-encoded dot segments like
/// the browser does.
fn normalize_path(path: &str) -> String {
    let path = if path.is_empty() { "/" } else { path };
    let segments: Vec<&str> = path.split('/').collect();
    let mut result: Vec<&str> = Vec::new();
    for (index, segment) in segments.iter().enumerate() {
        let decoded = percent_encoding::percent_decode_str(segment).collect::<Vec<u8>>();
        if decoded == b"." || decoded == b".." {
            if decoded == b".." && result.len() > 1 {
                result.pop();
            }
            if index == segments.len() - 1 {
                result.push("");
            }
        } else {
            result.push(segment);
        }
    }
    let joined = result.join("/");
    if joined.is_empty() {
        "/".to_string()
    } else {
        joined
    }
}

/// Normalized absolute http(s) URL, or `None` (`normalize_url`).
pub fn normalize_url(value: &str) -> Option<String> {
    let mut value = py_strip(value).to_string();
    if value.starts_with("//") {
        value = format!("https:{value}");
    }
    if value.chars().count() > 4096 || value.chars().any(|c| (c as u32) < 32) {
        return None;
    }
    let parsed = urlsplit(&value, "").ok()?;
    let scheme = parsed.scheme.to_lowercase();
    if scheme != "http" && scheme != "https" {
        return None;
    }
    let hostname = parsed.hostname()?;
    if parsed.username().is_some() || parsed.password().is_some() {
        return None;
    }
    let mut hostname = idna_encode(&hostname).ok()?.to_lowercase();
    if hostname.contains(':') {
        let (address, scope) = ip::parse_ip(&hostname)?;
        let compressed = match address {
            std::net::IpAddr::V6(address) => ip::ipv6_compressed(address, scope),
            std::net::IpAddr::V4(address) => address.to_string(),
        };
        hostname = format!("[{compressed}]");
    }
    let port = parsed.port().ok()?;
    if port == Some(0) {
        return None;
    }
    let mut netloc = hostname;
    let default_port = if scheme == "https" { 443 } else { 80 };
    if let Some(port) = port.filter(|port| *port != default_port) {
        netloc.push_str(&format!(":{port}"));
    }
    Some(urlunsplit(
        &scheme,
        &netloc,
        &quote(&normalize_path(&parsed.path), "/:@!$&'()*+,;=-._~%"),
        &quote(&parsed.query, "=?/:@!$&'()*+,;[]-._~%"),
        "",
    ))
}

/// `_ImageParser`.
#[derive(Default)]
struct ImageParser {
    urls: HashSet<String>,
    in_style: bool,
}

impl ImageParser {
    fn add(&mut self, value: &str) {
        if self.urls.len() >= MAX_SOURCES {
            return;
        }
        if let Some(normalized) = normalize_url(value) {
            self.urls.insert(normalized);
        }
    }

    fn add_css(&mut self, css: &str) {
        let values: Vec<String> = CSS_URL
            .captures_iter(css)
            .map(|captures| {
                (1..=3)
                    .find_map(|group| captures.get(group))
                    .map_or(String::new(), |found| found.as_str().to_string())
            })
            .collect();
        for value in values {
            self.add(&value);
        }
    }
}

impl html::Handler for ImageParser {
    fn start_tag(&mut self, tag: &str, attrs: &[(String, Option<String>)]) {
        // HTML's DOM parser keeps the first attribute when names repeat.
        let get = |name: &str| -> Option<&str> {
            attrs
                .iter()
                .find(|(candidate, _)| candidate == name)
                .and_then(|(_, value)| value.as_deref())
                .filter(|value| !value.is_empty())
        };
        if tag == "style" {
            self.in_style = true;
        }
        if tag == "img" {
            if let Some(src) = get("src") {
                self.add(src);
            }
        }
        if tag == "img" || tag == "source" {
            if let Some(srcset) = get("srcset") {
                for candidate in srcset.split(',') {
                    if let Some(first) = py_split(candidate).next() {
                        self.add(first);
                    }
                }
            }
        }
        if let Some(background) = get("background") {
            self.add(background);
        }
        if tag == "video" {
            if let Some(poster) = get("poster") {
                self.add(poster);
            }
        }
        if let Some(style) = get("style") {
            self.add_css(style);
        }
    }

    fn end_tag(&mut self, tag: &str) {
        if tag == "style" {
            self.in_style = false;
        }
    }

    fn data(&mut self, data: &str) {
        if self.in_style {
            self.add_css(data);
        }
    }
}

/// Every remote image URL referenced by `html` (`image_urls`).
pub fn image_urls(html: &str) -> HashSet<String> {
    let mut parser = ImageParser::default();
    html::feed(html, &mut parser);
    parser.urls
}

type Key = (String, String, u32);

#[derive(Debug, Default)]
struct Registry {
    /// Oldest first (`OrderedDict` order).
    messages: VecDeque<(Key, Instant, HashSet<String>)>,
}

impl Registry {
    fn position(&self, key: &Key) -> Option<usize> {
        self.messages
            .iter()
            .position(|(candidate, _, _)| candidate == key)
    }
}

/// Thread-safe registry (`ImageSources`). Clone shares the same registry.
#[derive(Debug, Clone, Default)]
pub struct ImageSources {
    inner: Arc<Mutex<Registry>>,
}

impl ImageSources {
    pub fn new() -> Self {
        Self::default()
    }

    fn key(account: &str, folder: &str, uid: u32) -> Key {
        (py_strip(account).to_lowercase(), folder.to_string(), uid)
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Registry> {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    pub fn register(&self, account: &str, folder: &str, uid: u32, html: &str) {
        self.register_at(account, folder, uid, html, Instant::now());
    }

    /// [`ImageSources::register`] at an explicit monotonic time (tests use it
    /// where Python patched `time.monotonic`).
    #[doc(hidden)]
    pub fn register_at(&self, account: &str, folder: &str, uid: u32, html: &str, now: Instant) {
        let urls = image_urls(html);
        let key = Self::key(account, folder, uid);
        let mut registry = self.lock();
        if let Some(index) = registry.position(&key) {
            registry.messages.remove(index);
        }
        registry.messages.push_back((key, now + SOURCE_TTL, urls));
        while registry.messages.len() > MAX_MESSAGES {
            registry.messages.pop_front();
        }
    }

    /// Registered URLs, or `None` when the message was never registered.
    pub fn sources(&self, account: &str, folder: &str, uid: u32) -> Option<HashSet<String>> {
        self.sources_at(account, folder, uid, Instant::now())
    }

    /// [`ImageSources::sources`] at an explicit monotonic time.
    #[doc(hidden)]
    pub fn sources_at(
        &self,
        account: &str,
        folder: &str,
        uid: u32,
        now: Instant,
    ) -> Option<HashSet<String>> {
        let key = Self::key(account, folder, uid);
        let mut registry = self.lock();
        let index = registry.position(&key)?;
        if registry.messages[index].1 <= now {
            registry.messages.remove(index);
            return None;
        }
        let entry = registry.messages.remove(index).expect("index is valid");
        let urls = entry.2.clone();
        registry.messages.push_back(entry);
        Some(urls)
    }

    pub fn forget(&self, account: &str) {
        let account = py_strip(account).to_lowercase();
        self.lock()
            .messages
            .retain(|((email, _, _), _, _)| *email != account);
    }

    pub fn clear(&self) {
        self.lock().messages.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_path_resolves_dot_segments() {
        assert_eq!(normalize_path(""), "/");
        assert_eq!(normalize_path("/a/../b"), "/b");
        assert_eq!(normalize_path("/a/%2E%2e/b"), "/b");
        assert_eq!(normalize_path("/a/."), "/a/");
        assert_eq!(normalize_path("/.."), "/");
    }
}
