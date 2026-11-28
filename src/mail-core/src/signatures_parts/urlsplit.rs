//! The parts of CPython 3.14's `urllib.parse.urlsplit` that
//! `signatures._safe_link` relies on: the scheme, the netloc, the
//! `ValueError`s for malformed brackets / NFKC netlocs, and `hostname`.
//!
//! `_safe_link` already rejected whitespace, control characters and
//! backslashes, so the WHATWG stripping steps are no-ops and are omitted.

use std::net::{Ipv4Addr, Ipv6Addr};

use unicode_normalization::UnicodeNormalization;

/// `SplitResult` (only the fields `_safe_link` reads).
pub(super) struct SplitResult {
    /// Lowercased scheme, `""` when there is none.
    pub scheme: String,
    pub netloc: String,
}

impl SplitResult {
    /// `hostname or ""` (case is irrelevant to the callers).
    pub fn hostname(&self) -> &str {
        let hostinfo = self
            .netloc
            .rsplit_once('@')
            .map_or(self.netloc.as_str(), |(_, h)| h);
        match hostinfo.split_once('[') {
            Some((_, bracketed)) => bracketed
                .split_once(']')
                .map_or(bracketed, |(host, _)| host),
            None => hostinfo.split_once(':').map_or(hostinfo, |(host, _)| host),
        }
    }
}

/// `scheme_chars`.
fn is_scheme_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.')
}

/// `urlsplit(url)`; `None` where Python raised `ValueError`.
pub(super) fn urlsplit(url: &str) -> Option<SplitResult> {
    let mut scheme = String::new();
    let mut rest = url;
    if let Some(i) = url.find(':') {
        let first = url.chars().next().unwrap_or(' ');
        if i > 0 && first.is_ascii_alphabetic() && url[..i].chars().all(is_scheme_char) {
            scheme = url[..i].to_ascii_lowercase();
            rest = &url[i + 1..];
        }
    }
    let mut netloc = String::new();
    if let Some(after) = rest.strip_prefix("//") {
        let delimiter = after.find(['/', '?', '#']).unwrap_or(after.len());
        netloc = after[..delimiter].to_string();
        let (open, close) = (netloc.contains('['), netloc.contains(']'));
        if open != close {
            return None;
        }
        if open && !check_bracketed_netloc(&netloc) {
            return None;
        }
    }
    if !check_netloc(&netloc) {
        return None;
    }
    Some(SplitResult { scheme, netloc })
}

/// `_checknetloc`: reject characters that NFKC-normalize into URL delimiters.
fn check_netloc(netloc: &str) -> bool {
    if netloc.is_empty() || netloc.is_ascii() {
        return true;
    }
    let stripped: String = netloc
        .chars()
        .filter(|c| !matches!(c, '@' | ':' | '#' | '?'))
        .collect();
    let normalized: String = stripped.nfkc().collect();
    stripped == normalized || !normalized.contains(['/', '?', '#', '@', ':'])
}

/// `_check_bracketed_netloc`.
fn check_bracketed_netloc(netloc: &str) -> bool {
    let host_and_port = netloc.rsplit_once('@').map_or(netloc, |(_, h)| h);
    let hostname = match host_and_port.split_once('[') {
        Some((before, bracketed)) => {
            if !before.is_empty() {
                return false;
            }
            let (hostname, port) = bracketed.split_once(']').unwrap_or((bracketed, ""));
            if !port.is_empty() && !port.starts_with(':') {
                return false;
            }
            hostname
        }
        None => host_and_port
            .split_once(':')
            .map_or(host_and_port, |(h, _)| h),
    };
    check_bracketed_host(hostname)
}

/// `_check_bracketed_host`: an IPvFuture literal or an IPv6 address.
fn check_bracketed_host(hostname: &str) -> bool {
    if let Some(rest) = hostname.strip_prefix('v') {
        // \Av[a-fA-F0-9]+\..+\z
        let Some((version, tail)) = rest.split_once('.') else {
            return false;
        };
        return !version.is_empty()
            && version.chars().all(|c| c.is_ascii_hexdigit())
            && !tail.is_empty()
            && !tail.contains('\n');
    }
    if hostname.parse::<Ipv4Addr>().is_ok() {
        // An IPv4 address cannot be in brackets.
        return false;
    }
    // ipaddress.IPv6Address, including an optional non-empty %scope_id.
    let (address, scope) = match hostname.split_once('%') {
        Some((address, scope)) => (address, Some(scope)),
        None => (hostname, None),
    };
    if scope.is_some_and(|scope| scope.is_empty() || scope.contains('%')) {
        return false;
    }
    address.parse::<Ipv6Addr>().is_ok()
}
