//! Sender-domain validation (`_normalize_sender_domain`,
//! `normalize_sender_domains`, `_DOMAIN_LABEL`) and the Python `idna` codec
//! it relies on.

use crate::parsing::py_strip;

const MESSAGE_LENGTH: &str = "Sender domains must be non-empty domain names up to 253 characters";
const MESSAGE_IDNA: &str = "Enter a valid sender domain";
const MESSAGE_LABEL: &str = "Enter a valid sender domain without an email address or URL";
const MESSAGE_COUNT: &str = "Choose at most 200 sender domains";

/// `_DOMAIN_LABEL.fullmatch(label)`:
/// `[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?`.
fn valid_label(label: &str) -> bool {
    let bytes = label.as_bytes();
    let edge = |b: u8| b.is_ascii_lowercase() || b.is_ascii_digit();
    match bytes {
        [] => false,
        [only] => edge(*only),
        [first, middle @ .., last] => {
            bytes.len() <= 63
                && edge(*first)
                && edge(*last)
                && middle.iter().all(|&b| edge(b) || b == b'-')
        }
    }
}

/// Python's `str.encode("idna")` (IDNA 2003): ASCII names pass through with
/// label length checks; other names are mapped per label (nameprep-like
/// mapping, then punycode). `Err` where Python raises `UnicodeError`.
fn python_idna_encode(domain: &str) -> Result<String, ()> {
    if domain.is_empty() {
        return Ok(String::new());
    }
    if domain.is_ascii() {
        let labels: Vec<&str> = domain.split('.').collect();
        let (last, rest) = labels.split_last().ok_or(())?;
        if rest
            .iter()
            .any(|label| label.is_empty() || label.len() >= 64)
            || last.len() >= 64
        {
            return Err(());
        }
        return Ok(domain.to_string());
    }
    let mut labels: Vec<&str> = domain
        .split(['.', '\u{3002}', '\u{ff0e}', '\u{ff61}'])
        .collect();
    let trailing_dot = if labels.last().is_some_and(|l| l.is_empty()) {
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
            let mapped: String = label
                .chars()
                .flat_map(|c| match c {
                    'ß' | 'ẞ' => vec!['s', 's'],
                    'ς' => vec!['σ'],
                    '\u{200c}' | '\u{200d}' => vec![],
                    c => vec![c],
                })
                .collect();
            idna::domain_to_ascii(&mapped).map_err(|_| ())?
        };
        if ascii.is_empty() || ascii.len() >= 64 || ascii.contains('.') {
            return Err(());
        }
        encoded.push(ascii);
    }
    Ok(encoded.join(".") + trailing_dot)
}

/// `_normalize_sender_domain(value)`; `Err` carries the `ValueError` text.
pub(crate) fn normalize_sender_domain(value: &str) -> Result<String, String> {
    if py_strip(value).is_empty() || value.chars().count() > 253 {
        return Err(MESSAGE_LENGTH.into());
    }
    let stripped = py_strip(value);
    let stripped = stripped.strip_suffix('.').unwrap_or(stripped);
    let domain = python_idna_encode(stripped)
        .map_err(|()| MESSAGE_IDNA.to_string())?
        .to_lowercase();
    if domain.len() > 253 || domain.split('.').any(|label| !valid_label(label)) {
        return Err(MESSAGE_LABEL.into());
    }
    Ok(domain)
}

/// `normalize_sender_domains(values)`.
pub(crate) fn normalize_sender_domains(values: Option<&[String]>) -> Result<Vec<String>, String> {
    let Some(values) = values else {
        return Ok(Vec::new());
    };
    if values.len() > 200 {
        return Err(MESSAGE_COUNT.into());
    }
    let mut out: Vec<String> = Vec::with_capacity(values.len());
    for value in values {
        let domain = normalize_sender_domain(value)?;
        if !out.contains(&domain) {
            out.push(domain);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn domains(values: &[&str]) -> Result<Vec<String>, String> {
        let owned: Vec<String> = values.iter().map(|v| v.to_string()).collect();
        normalize_sender_domains(Some(&owned))
    }

    #[test]
    fn normalizes_case_trailing_dot_idna_and_duplicates() {
        assert_eq!(
            domains(&["EXAMPLE.com.", "other.test", "example.com"]).unwrap(),
            vec!["example.com", "other.test"]
        );
        assert_eq!(
            domains(&["b\u{fc}cher.example"]).unwrap(),
            vec!["xn--bcher-kva.example"]
        );
        assert_eq!(domains(&["fa\u{df}.de"]).unwrap(), vec!["fass.de"]);
        assert_eq!(
            normalize_sender_domains(None).unwrap(),
            Vec::<String>::new()
        );
    }

    #[test]
    fn rejects_addresses_urls_and_malformed_names() {
        assert_eq!(domains(&[""]).unwrap_err(), MESSAGE_LENGTH);
        assert_eq!(domains(&["   "]).unwrap_err(), MESSAGE_LENGTH);
        assert_eq!(domains(&["user@example.com"]).unwrap_err(), MESSAGE_LABEL);
        assert_eq!(domains(&["example.com\" ALL"]).unwrap_err(), MESSAGE_LABEL);
        assert_eq!(
            domains(&["https://example.com"]).unwrap_err(),
            MESSAGE_LABEL
        );
        assert_eq!(domains(&["a..com"]).unwrap_err(), MESSAGE_IDNA);
        assert_eq!(domains(&["-a.com"]).unwrap_err(), MESSAGE_LABEL);
        let many: Vec<&str> = vec!["a.example"; 201];
        assert_eq!(domains(&many).unwrap_err(), MESSAGE_COUNT);
        let long = format!("{}.com", "a".repeat(250));
        assert_eq!(domains(&[long.as_str()]).unwrap_err(), MESSAGE_LENGTH);
    }

    #[test]
    fn label_pattern_matches_python_regex() {
        assert!(valid_label("a"));
        assert!(valid_label("a-b"));
        assert!(valid_label(&"a".repeat(63)));
        assert!(!valid_label(&"a".repeat(64)));
        assert!(!valid_label("a-"));
        assert!(!valid_label("A"));
        assert!(!valid_label(""));
    }
}
