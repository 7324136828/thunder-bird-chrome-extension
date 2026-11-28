//! Sender-domain helpers for POP3 listing: a private copy of
//! `imap_client._normalize_sender_domain` / `normalize_sender_domains` and of
//! the From-address check in `_filter_sender_domains`.
//!
//! A copy (rather than a call into `crate::imap`) keeps the POP3 mode
//! independent from the IMAP module's internals; the behaviour is the same
//! Python code.

use std::sync::LazyLock;

use regex::Regex;

use crate::parsing::{self, py_strip, ParsedMessage};

static DOMAIN_LABEL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$").unwrap());

/// Python's `str.encode("idna")` codec (IDNA 2003 ToASCII per label).
fn python_idna_encode(domain: &str) -> Option<String> {
    if domain.is_empty() {
        return Some(String::new());
    }
    if domain.is_ascii() {
        let labels: Vec<&str> = domain.split('.').collect();
        let (last, rest) = labels.split_last()?;
        if rest
            .iter()
            .any(|label| label.is_empty() || label.len() >= 64)
            || last.len() >= 64
        {
            return None;
        }
        return Some(domain.to_string());
    }
    let mut labels: Vec<&str> = domain
        .split(['.', '\u{3002}', '\u{ff0e}', '\u{ff61}'])
        .collect();
    let trailing_dot = if labels.last().is_some_and(|label| label.is_empty()) {
        labels.pop();
        "."
    } else {
        ""
    };
    let mut encoded = Vec::with_capacity(labels.len());
    for label in labels {
        let ascii = if label.is_ascii() {
            label.to_string()
        } else {
            // nameprep maps these differently from UTS #46 non-transitional.
            let mapped: String = label
                .chars()
                .flat_map(|c| match c {
                    'ß' | 'ẞ' => vec!['s', 's'],
                    'ς' => vec!['σ'],
                    '\u{200c}' | '\u{200d}' => vec![],
                    c => vec![c],
                })
                .collect();
            idna::domain_to_ascii(&mapped).ok()?
        };
        if ascii.is_empty() || ascii.len() >= 64 || ascii.contains('.') {
            return None;
        }
        encoded.push(ascii);
    }
    Some(encoded.join(".") + trailing_dot)
}

/// `_normalize_sender_domain(value)`; `Err` is the Python `ValueError` text.
pub(super) fn normalize_sender_domain(value: &str) -> Result<String, String> {
    let stripped = py_strip(value);
    if stripped.is_empty() || value.chars().count() > 253 {
        return Err(
            "Sender domains must be non-empty domain names up to 253 characters".to_string(),
        );
    }
    let trimmed = stripped.strip_suffix('.').unwrap_or(stripped);
    let domain = python_idna_encode(trimmed)
        .ok_or_else(|| "Enter a valid sender domain".to_string())?
        .to_lowercase();
    if domain.len() > 253 || domain.split('.').any(|label| !DOMAIN_LABEL.is_match(label)) {
        return Err("Enter a valid sender domain without an email address or URL".to_string());
    }
    Ok(domain)
}

/// `normalize_sender_domains(values)`: validate and de-duplicate in order.
pub(super) fn normalize_sender_domains(values: &[String]) -> Result<Vec<String>, String> {
    if values.len() > 200 {
        return Err("Choose at most 200 sender domains".to_string());
    }
    let mut domains: Vec<String> = Vec::with_capacity(values.len());
    for value in values {
        let domain = normalize_sender_domain(value)?;
        if !domains.contains(&domain) {
            domains.push(domain);
        }
    }
    Ok(domains)
}

/// The per-message check of `_filter_sender_domains`: some From address
/// whose normalized host equals a filter domain or is a subdomain of it.
pub(super) fn from_matches(headers: &ParsedMessage, domains: &[String]) -> bool {
    let values = headers.get_all("From");
    let refs: Vec<&str> = values.iter().map(String::as_str).collect();
    for (_, address) in parsing::getaddresses(&refs) {
        let Some((_, host)) = address.rsplit_once('@') else {
            continue;
        };
        let Ok(host) = normalize_sender_domain(host) else {
            continue;
        };
        if domains
            .iter()
            .any(|domain| host == *domain || host.ends_with(&format!(".{domain}")))
        {
            return true;
        }
    }
    false
}
