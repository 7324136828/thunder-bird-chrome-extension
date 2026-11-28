//! Ports of the `urllib.parse`, `str.strip` and `"idna"` codec behavior the
//! image code depends on (`urlsplit`, `SplitResult.hostname/port/username/
//! password`, `urlunsplit`, `urljoin`, `quote`).
//!
//! Python indexes strings by code point; every delimiter used here is ASCII,
//! so byte offsets at those delimiters are always valid `str` boundaries.

use unicode_normalization::UnicodeNormalization;

/// A `ValueError` / `UnicodeError` raised by the ported functions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct UrlError;

/// Python `str.isspace()` for one character (Unicode `White_Space` plus the
/// `\x1c`-`\x1f` separators Python also counts).
pub(crate) fn py_isspace(character: char) -> bool {
    character.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&character)
}

/// Python `str.strip()` with no arguments.
pub(crate) fn py_strip(value: &str) -> &str {
    value.trim_matches(py_isspace)
}

/// Python `str.split()` with no arguments.
pub(crate) fn py_split(value: &str) -> impl Iterator<Item = &str> {
    value.split(py_isspace).filter(|field| !field.is_empty())
}

/// `urllib.parse.SplitResult`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SplitResult {
    pub scheme: String,
    pub netloc: String,
    pub path: String,
    pub query: String,
    pub fragment: String,
}

const SCHEME_CHARS: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+-.";

/// `urllib.parse.urlsplit(url, scheme)` (Python 3.12+ semantics).
pub(crate) fn urlsplit(url: &str, default_scheme: &str) -> Result<SplitResult, UrlError> {
    let c0_or_space = |c: char| c <= ' ';
    let mut url: String = url
        .trim_start_matches(c0_or_space)
        .chars()
        .filter(|c| !matches!(c, '\t' | '\r' | '\n'))
        .collect();
    let mut scheme: String = default_scheme
        .trim_matches(c0_or_space)
        .chars()
        .filter(|c| !matches!(c, '\t' | '\r' | '\n'))
        .collect();
    let mut netloc = String::new();
    let mut query = String::new();
    let mut fragment = String::new();
    if let Some(index) = url.find(':') {
        let first = url.chars().next();
        if index > 0
            && first.is_some_and(|c| c.is_ascii_alphabetic())
            && url[..index].chars().all(|c| SCHEME_CHARS.contains(c))
        {
            scheme = url[..index].to_ascii_lowercase();
            url = url[index + 1..].to_string();
        }
    }
    if url.starts_with("//") {
        let delimiter = url[2..]
            .find(['/', '?', '#'])
            .map(|position| position + 2)
            .unwrap_or(url.len());
        netloc = url[2..delimiter].to_string();
        url = url[delimiter..].to_string();
        let open = netloc.contains('[');
        let close = netloc.contains(']');
        if open != close {
            return Err(UrlError);
        }
        if open && close {
            check_bracketed_netloc(&netloc)?;
        }
    }
    if let Some((before, after)) = url.split_once('#') {
        fragment = after.to_string();
        url = before.to_string();
    }
    if let Some((before, after)) = url.split_once('?') {
        query = after.to_string();
        url = before.to_string();
    }
    check_netloc(&netloc)?;
    Ok(SplitResult {
        scheme,
        netloc,
        path: url,
        query,
        fragment,
    })
}

/// `_check_bracketed_netloc`.
fn check_bracketed_netloc(netloc: &str) -> Result<(), UrlError> {
    let host_and_port = rpartition_after(netloc, '@');
    let hostname = match host_and_port.split_once('[') {
        Some((before, bracketed)) => {
            if !before.is_empty() {
                return Err(UrlError);
            }
            let (hostname, port) = bracketed.split_once(']').unwrap_or((bracketed, ""));
            if !port.is_empty() && !port.starts_with(':') {
                return Err(UrlError);
            }
            hostname
        }
        None => host_and_port.split_once(':').map_or(host_and_port, |p| p.0),
    };
    check_bracketed_host(hostname)
}

/// `_check_bracketed_host`.
fn check_bracketed_host(hostname: &str) -> Result<(), UrlError> {
    if let Some(rest) = hostname.strip_prefix('v') {
        // \Av[a-fA-F0-9]+\..+\Z
        let hex_len = rest.bytes().take_while(u8::is_ascii_hexdigit).count();
        let tail = &rest[hex_len..];
        let valid =
            hex_len > 0 && tail.starts_with('.') && tail.len() > 1 && !tail[1..].contains('\n');
        return if valid { Ok(()) } else { Err(UrlError) };
    }
    match super::ip::parse_ip(hostname) {
        Some((std::net::IpAddr::V6(_), _)) => Ok(()),
        _ => Err(UrlError),
    }
}

/// `_checknetloc`: reject netlocs whose NFKC form introduces delimiters.
fn check_netloc(netloc: &str) -> Result<(), UrlError> {
    if netloc.is_empty() || netloc.is_ascii() {
        return Ok(());
    }
    let n: String = netloc
        .chars()
        .filter(|c| !matches!(c, '@' | ':' | '#' | '?'))
        .collect();
    let normalized: String = n.nfkc().collect();
    if n == normalized {
        return Ok(());
    }
    if normalized.contains(['/', '?', '#', '@', ':']) {
        return Err(UrlError);
    }
    Ok(())
}

/// The part after the last `sep` (all of `value` without one).
fn rpartition_after(value: &str, sep: char) -> &str {
    value.rsplit_once(sep).map_or(value, |(_, after)| after)
}

impl SplitResult {
    /// `_userinfo` -> `(username, password)`.
    fn userinfo(&self) -> (Option<&str>, Option<&str>) {
        match self.netloc.rsplit_once('@') {
            Some((userinfo, _)) => match userinfo.split_once(':') {
                Some((user, password)) => (Some(user), Some(password)),
                None => (Some(userinfo), None),
            },
            None => (None, None),
        }
    }

    pub fn username(&self) -> Option<&str> {
        self.userinfo().0
    }

    pub fn password(&self) -> Option<&str> {
        self.userinfo().1
    }

    /// `_hostinfo` -> `(hostname, port)`.
    fn hostinfo(&self) -> (&str, Option<&str>) {
        let hostinfo = rpartition_after(&self.netloc, '@');
        let (hostname, port) = match hostinfo.split_once('[') {
            Some((_, bracketed)) => {
                let (hostname, rest) = bracketed.split_once(']').unwrap_or((bracketed, ""));
                (hostname, rest.split_once(':').map_or("", |p| p.1))
            }
            None => hostinfo.split_once(':').unwrap_or((hostinfo, "")),
        };
        (hostname, (!port.is_empty()).then_some(port))
    }

    /// `SplitResult.hostname`: lowercased (except an IPv6 zone id).
    pub fn hostname(&self) -> Option<String> {
        let (hostname, _) = self.hostinfo();
        if hostname.is_empty() {
            return None;
        }
        Some(match hostname.split_once('%') {
            Some((host, zone)) => format!("{}%{zone}", host.to_lowercase()),
            None => hostname.to_lowercase(),
        })
    }

    /// `SplitResult.port` (`Err` where Python raised `ValueError`).
    pub fn port(&self) -> Result<Option<u16>, UrlError> {
        match self.hostinfo().1 {
            None => Ok(None),
            Some(port) => {
                if !port.bytes().all(|b| b.is_ascii_digit()) {
                    return Err(UrlError);
                }
                let digits = port.trim_start_matches('0');
                if digits.len() > 5 {
                    return Err(UrlError);
                }
                let value: u32 = if digits.is_empty() {
                    0
                } else {
                    digits.parse().map_err(|_| UrlError)?
                };
                u16::try_from(value).map(Some).map_err(|_| UrlError)
            }
        }
    }
}

/// `urllib.parse.urlunsplit((scheme, netloc, path, query, fragment))`.
pub(crate) fn urlunsplit(
    scheme: &str,
    netloc: &str,
    path: &str,
    query: &str,
    fragment: &str,
) -> String {
    let mut url = path.to_string();
    if !netloc.is_empty() {
        if !url.is_empty() && !url.starts_with('/') {
            url.insert(0, '/');
        }
        url = format!("//{netloc}{url}");
    } else if url.starts_with("//")
        || (uses_netloc(scheme) && (url.is_empty() || url.starts_with('/')))
    {
        url = format!("//{url}");
    }
    if !scheme.is_empty() {
        url = format!("{scheme}:{url}");
    }
    if !query.is_empty() {
        url = format!("{url}?{query}");
    }
    if !fragment.is_empty() {
        url = format!("{url}#{fragment}");
    }
    url
}

/// `urllib.parse.uses_netloc` membership.
fn uses_netloc(scheme: &str) -> bool {
    matches!(
        scheme,
        "" | "ftp"
            | "http"
            | "gopher"
            | "nntp"
            | "telnet"
            | "imap"
            | "wais"
            | "file"
            | "mms"
            | "https"
            | "shttp"
            | "snews"
            | "prospero"
            | "rtsp"
            | "rtsps"
            | "rtspu"
            | "rsync"
            | "svn"
            | "svn+ssh"
            | "sftp"
            | "nfs"
            | "git"
            | "git+ssh"
            | "ws"
            | "wss"
            | "itms-services"
    )
}

/// `urllib.parse.uses_relative` membership.
fn uses_relative(scheme: &str) -> bool {
    matches!(
        scheme,
        "" | "ftp"
            | "http"
            | "gopher"
            | "nntp"
            | "imap"
            | "wais"
            | "file"
            | "https"
            | "shttp"
            | "mms"
            | "prospero"
            | "rtsp"
            | "rtsps"
            | "rtspu"
            | "sftp"
            | "svn"
            | "svn+ssh"
            | "ws"
            | "wss"
    )
}

/// `urllib.parse.uses_params` membership.
fn uses_params(scheme: &str) -> bool {
    matches!(
        scheme,
        "" | "ftp"
            | "hdl"
            | "prospero"
            | "http"
            | "imap"
            | "https"
            | "shttp"
            | "rtsp"
            | "rtsps"
            | "rtspu"
            | "sip"
            | "sips"
            | "mms"
            | "sftp"
            | "tel"
    )
}

/// `urlparse` = `urlsplit` + `;params` of the last path segment.
struct ParseResult {
    scheme: String,
    netloc: String,
    path: String,
    params: String,
    query: String,
    fragment: String,
}

fn urlparse(url: &str, default_scheme: &str) -> Result<ParseResult, UrlError> {
    let split = urlsplit(url, default_scheme)?;
    let (path, params) = if uses_params(&split.scheme) && split.path.contains(';') {
        split_params(&split.path)
    } else {
        (split.path.clone(), String::new())
    };
    Ok(ParseResult {
        scheme: split.scheme,
        netloc: split.netloc,
        path,
        params,
        query: split.query,
        fragment: split.fragment,
    })
}

/// `_splitparams`.
fn split_params(url: &str) -> (String, String) {
    let index = if let Some(slash) = url.rfind('/') {
        match url[slash..].find(';') {
            Some(position) => slash + position,
            None => return (url.to_string(), String::new()),
        }
    } else {
        url.find(';').unwrap_or(0)
    };
    (url[..index].to_string(), url[index + 1..].to_string())
}

/// `urlunparse`.
fn urlunparse(parts: &ParseResult) -> String {
    let path = if parts.params.is_empty() {
        parts.path.clone()
    } else {
        format!("{};{}", parts.path, parts.params)
    };
    urlunsplit(
        &parts.scheme,
        &parts.netloc,
        &path,
        &parts.query,
        &parts.fragment,
    )
}

/// `urllib.parse.urljoin(base, url)`.
pub(crate) fn urljoin(base: &str, url: &str) -> Result<String, UrlError> {
    if base.is_empty() {
        return Ok(url.to_string());
    }
    if url.is_empty() {
        return Ok(base.to_string());
    }
    let b = urlparse(base, "")?;
    let mut r = urlparse(url, &b.scheme)?;
    if r.scheme != b.scheme || !uses_relative(&r.scheme) {
        return Ok(url.to_string());
    }
    if uses_netloc(&r.scheme) {
        if !r.netloc.is_empty() {
            return Ok(urlunparse(&r));
        }
        r.netloc = b.netloc.clone();
    }
    if r.path.is_empty() && r.params.is_empty() {
        r.path = b.path.clone();
        r.params = b.params.clone();
        if r.query.is_empty() {
            r.query = b.query.clone();
        }
        return Ok(urlunparse(&r));
    }
    let mut base_parts: Vec<&str> = b.path.split('/').collect();
    if base_parts.last().is_some_and(|last| !last.is_empty()) {
        base_parts.pop();
    }
    let segments: Vec<&str> = if r.path.starts_with('/') {
        r.path.split('/').collect()
    } else {
        let mut segments: Vec<&str> = base_parts;
        segments.extend(r.path.split('/'));
        if segments.len() > 2 {
            let last = segments.len() - 1;
            let middle: Vec<&str> = segments[1..last]
                .iter()
                .copied()
                .filter(|segment| !segment.is_empty())
                .collect();
            let mut filtered = vec![segments[0]];
            filtered.extend(middle);
            filtered.push(segments[last]);
            segments = filtered;
        }
        segments
    };
    let mut resolved: Vec<&str> = Vec::new();
    for segment in &segments {
        match *segment {
            ".." => {
                resolved.pop();
            }
            "." => {}
            other => resolved.push(other),
        }
    }
    if matches!(segments.last(), Some(&".") | Some(&"..")) {
        resolved.push("");
    }
    let joined = resolved.join("/");
    r.path = if joined.is_empty() {
        "/".to_string()
    } else {
        joined
    };
    Ok(urlunparse(&r))
}

/// `urllib.parse.quote(value, safe=safe)`: UTF-8 bytes outside the
/// always-safe set and `safe` become `%XX` (uppercase hex).
pub(crate) fn quote(value: &str, safe: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        let always_safe = byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-' | b'~');
        if always_safe || (byte.is_ascii() && safe.as_bytes().contains(&byte)) {
            out.push(byte as char);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

/// Python `str.encode("idna")` (IDNA 2003 codec) decoded back to ASCII.
///
/// ASCII names take Python's fast path exactly (labels 1..=63 characters,
/// only the last may be empty). Non-ASCII labels go through `nameprep`
/// (RFC 3491, `images_parts/stringprep.rs`) before Punycode.
pub(crate) fn idna_encode(input: &str) -> Result<String, UrlError> {
    if input.is_empty() {
        return Ok(String::new());
    }
    if input.is_ascii() {
        let labels: Vec<&str> = input.split('.').collect();
        let (last, rest) = labels.split_last().expect("split yields one item");
        if rest
            .iter()
            .any(|label| label.is_empty() || label.len() >= 64)
            || last.len() >= 64
        {
            return Err(UrlError);
        }
        return Ok(input.to_string());
    }
    let mut labels: Vec<&str> = input
        .split(['.', '\u{3002}', '\u{ff0e}', '\u{ff61}'])
        .collect();
    let trailing_dot = labels.last().is_some_and(|label| label.is_empty());
    if trailing_dot {
        labels.pop();
    }
    let mut result = Vec::new();
    for label in labels {
        result.push(to_ascii(label)?);
    }
    let mut joined = result.join(".");
    if trailing_dot {
        joined.push('.');
    }
    Ok(joined)
}

/// `encodings.idna.ToASCII`.
fn to_ascii(label: &str) -> Result<String, UrlError> {
    let check = |label: String| {
        if !label.is_empty() && label.len() < 64 {
            Ok(label)
        } else {
            Err(UrlError)
        }
    };
    if label.is_ascii() {
        return check(label.to_string());
    }
    let prepared = super::stringprep::nameprep(label).map_err(|_| UrlError)?;
    if prepared.is_ascii() {
        return check(prepared);
    }
    if prepared.starts_with("xn--") {
        return Err(UrlError);
    }
    let encoded = idna::punycode::encode_str(&prepared).ok_or(UrlError)?;
    check(format!("xn--{encoded}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn split(url: &str) -> SplitResult {
        urlsplit(url, "").unwrap()
    }

    #[test]
    fn urlsplit_matches_python() {
        let parsed = split("  HTTPS://User:pw@Example.COM:0443/a b?x=1#frag");
        assert_eq!(parsed.scheme, "https");
        assert_eq!(parsed.netloc, "User:pw@Example.COM:0443");
        assert_eq!(parsed.path, "/a b");
        assert_eq!(parsed.query, "x=1");
        assert_eq!(parsed.fragment, "frag");
        assert_eq!(parsed.username(), Some("User"));
        assert_eq!(parsed.password(), Some("pw"));
        assert_eq!(parsed.hostname().as_deref(), Some("example.com"));
        assert_eq!(parsed.port(), Ok(Some(443)));
        assert_eq!(split("https://@x/").username(), Some(""));
        assert_eq!(split("https://x:/").port(), Ok(None));
        assert!(split("https://x:bad/").port().is_err());
        assert!(split("https://x:65536/").port().is_err());
        assert!(urlsplit("http://[::1/", "").is_err());
        assert!(urlsplit("http://[1.2.3.4]/", "").is_err());
        assert_eq!(
            split("http://[FE80::1%Zone]:8/").hostname().as_deref(),
            Some("fe80::1%Zone")
        );
        assert_eq!(split("http://a\tb\n.com/").netloc, "ab.com");
        assert_eq!(split("data:image/png,a").scheme, "data");
        assert_eq!(split("1http://x").scheme, "");
    }

    #[test]
    fn urljoin_matches_python() {
        let base = "https://images.example/path/image.png";
        for (location, expected) in [
            ("../cafe.png?q=1", "https://images.example/cafe.png?q=1"),
            ("/final.png", "https://images.example/final.png"),
            ("other.png", "https://images.example/path/other.png"),
            ("//cdn.example/x.png", "https://cdn.example/x.png"),
            ("http://cdn.example/x", "http://cdn.example/x"),
            ("?a=b", "https://images.example/path/image.png?a=b"),
            ("#f", "https://images.example/path/image.png#f"),
            ("../../../x", "https://images.example/x"),
            (".", "https://images.example/path/"),
            ("a//b/./c/..", "https://images.example/path/a/b/"),
            ("x;p=1", "https://images.example/path/x;p=1"),
            ("data:image/png,a", "data:image/png,a"),
        ] {
            assert_eq!(urljoin(base, location).unwrap(), expected, "{location}");
        }
    }

    #[test]
    fn quote_and_idna() {
        assert_eq!(quote("/a b/é%", "/%"), "/a%20b/%C3%A9%");
        assert_eq!(idna_encode("example.com.").unwrap(), "example.com.");
        assert!(idna_encode("a..b").is_err());
        assert!(idna_encode(&"a".repeat(64)).is_err());
        assert_eq!(
            idna_encode("bücher.example").unwrap(),
            "xn--bcher-kva.example"
        );
        assert_eq!(py_strip("\u{1c} x \u{a0}"), "x");
    }
}
