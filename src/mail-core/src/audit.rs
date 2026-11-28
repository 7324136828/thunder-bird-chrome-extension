//! Single-message audit: authentication, routing, and phishing heuristics
//! (port of `backend/app/mail/audit.py`).
//!
//! Produces a structured report for one raw RFC 822 message - the web
//! Thunderbird equivalent of email-doctor's audit, focused on a single email.
//! The JSON keys, finding titles/details, severity weights and verdict
//! thresholds are identical to the Python implementation.

use std::collections::BTreeMap;
use std::sync::LazyLock;

use chrono::Utc;
use regex::Regex;
use serde_json::{json, Value};

use crate::parsing::{self, PyDateTime};

/// `_AUTH_RESULT_ITEM`.
static AUTH_RESULT_ITEM: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(spf|dkim|dmarc|iprev|auth)=([\w.-]+)(?:\s+[^;]*)?").unwrap()
});
/// `_AUTH_DOMAIN`.
static AUTH_DOMAIN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(?:smtp\.mailfrom|header\.i|header\.d|header\.from)=([\w.-]+)").unwrap()
});
/// `_RECEIVED_FROM` (note: no word boundary, exactly like the Python).
static RECEIVED_FROM: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)from\s+([^\s;]+)").unwrap());
/// `_RECEIVED_BY`.
static RECEIVED_BY: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\bby\s+([^\s;]+)").unwrap());
/// `_RECEIVED_WITH`.
static RECEIVED_WITH: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\bwith\s+([^\s;]+)").unwrap());
/// `_RECEIVED_FOR`.
static RECEIVED_FOR: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\bfor\s+([^\s;<]+)").unwrap());
/// `_IP_LITERAL` (`$` also matches before a final newline in Python).
static IP_LITERAL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^\d{1,3}(\.\d{1,3}){3}\n?$").unwrap());

/// `_RISKY_EXTENSIONS`.
const RISKY_EXTENSIONS: [&str; 22] = [
    ".exe", ".scr", ".bat", ".cmd", ".com", ".pif", ".msi", ".msp", ".js", ".jse", ".vbs", ".vbe",
    ".wsf", ".wsh", ".ps1", ".hta", ".lnk", ".iso", ".img", ".jar", ".cpl", ".reg",
];
/// `_DOUBLE_EXT_SECOND`.
const DOUBLE_EXT_SECOND: [&str; 13] = [
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".zip", ".rar", ".7z", ".txt",
    ".jpg", ".png",
];

/// `_SEVERITY_ORDER`.
fn severity_order(severity: &str) -> i32 {
    match severity {
        "pass" => 0,
        "info" => 1,
        "warn" => 2,
        _ => 3,
    }
}

/// `_SEVERITY_SCORE`.
fn severity_score(severity: &str) -> u32 {
    match severity {
        "pass" => 0,
        "info" => 2,
        "warn" => 15,
        _ => 35,
    }
}

/// `_domain(address)`.
fn domain(address: &str) -> String {
    match address.rsplit_once('@') {
        Some((_, domain)) => domain.to_lowercase(),
        None => String::new(),
    }
}

/// `_registered_domain(host)`: the last two labels.
fn registered_domain(host: &str) -> String {
    let lower = host.to_lowercase();
    let parts: Vec<&str> = lower.trim_matches('.').split('.').collect();
    if parts.len() >= 2 {
        parts[parts.len() - 2..].join(".")
    } else {
        lower
    }
}

/// `_is_ip_literal(host)`.
fn is_ip_literal(host: &str) -> bool {
    IP_LITERAL.is_match(host) || host.contains(':')
}

/// Authentication verdicts collected by `_auth_results`.
struct AuthResults {
    spf: String,
    dkim: String,
    dmarc: String,
    /// Domains mentioned in the results (collected but, as in the Python,
    /// not part of the report).
    #[allow(dead_code)]
    domains: BTreeMap<String, String>,
    raw: Vec<String>,
}

/// `_auth_results(msg)`: spf/dkim/dmarc verdicts from every
/// Authentication-Results header; the first non-neutral verdict wins.
fn auth_results(message: &parsing::ParsedMessage) -> AuthResults {
    let mut spf = "none".to_string();
    let mut dkim = "none".to_string();
    let mut dmarc = "none".to_string();
    let mut domains = BTreeMap::new();
    let raw = message.get_all("Authentication-Results");
    for header in &raw {
        for captures in AUTH_RESULT_ITEM.captures_iter(header) {
            let key = captures[1].to_lowercase();
            let value = captures[2].to_lowercase();
            let slot = match key.as_str() {
                "spf" => &mut spf,
                "dkim" => &mut dkim,
                "dmarc" => &mut dmarc,
                _ => continue,
            };
            if slot == "none" || slot == "neutral" {
                *slot = value;
            }
        }
        for captures in AUTH_DOMAIN.captures_iter(header) {
            domains.insert(captures[1].to_lowercase(), captures[1].to_string());
        }
    }
    AuthResults {
        spf,
        dkim,
        dmarc,
        domains,
        raw,
    }
}

/// `_received_field(pattern, text)`.
fn received_field(pattern: &Regex, text: &str) -> String {
    pattern
        .captures(text)
        .map(|captures| captures[1].to_string())
        .unwrap_or_default()
}

/// `_received_chain(msg)`: hops (newest first) and the total delivery
/// seconds between the oldest and newest parsable timestamps.
fn received_chain(message: &parsing::ParsedMessage) -> (Vec<Value>, Option<f64>) {
    let mut hops = Vec::new();
    let mut stamps: Vec<PyDateTime> = Vec::new();
    for (index, header) in message.get_all("Received").iter().enumerate() {
        let text = parsing::collapse_whitespace(header);
        let timestamp = text
            .split(';')
            .rev()
            .find_map(|piece| parsing::parsedate_to_datetime(parsing::py_strip(piece)));
        if let Some(stamp) = timestamp {
            stamps.push(stamp);
        }
        hops.push(json!({
            "index": index,
            "from": received_field(&RECEIVED_FROM, &text),
            "by": received_field(&RECEIVED_BY, &text),
            "with": received_field(&RECEIVED_WITH, &text),
            "for": received_field(&RECEIVED_FOR, &text),
            "timestamp": timestamp.map(|stamp| stamp.isoformat()),
        }));
    }
    (hops, delivery_seconds(&stamps))
}

/// `abs((max(stamps) - min(stamps)).total_seconds())` for two or more stamps.
///
/// Python compares the parsed values directly; mixing naive (`-0000`) and
/// aware timestamps raised `TypeError` there (an HTTP 500). This port reports
/// `None` for that case instead of failing the whole audit.
fn delivery_seconds(stamps: &[PyDateTime]) -> Option<f64> {
    if stamps.len() < 2 {
        return None;
    }
    let all_aware = stamps.iter().all(|s| s.offset_seconds.is_some());
    let all_naive = stamps.iter().all(|s| s.offset_seconds.is_none());
    let instants: Vec<_> = if all_aware {
        stamps.iter().filter_map(PyDateTime::utc).collect()
    } else if all_naive {
        stamps.iter().map(|s| s.naive).collect()
    } else {
        return None;
    };
    let max = instants.iter().max()?;
    let min = instants.iter().min()?;
    Some((*max - *min).num_milliseconds().unsigned_abs() as f64 / 1000.0)
}

/// `_display_name_address_mismatch`: a display name containing a different
/// email address is a classic spoof.
fn display_name_address_mismatch(from_name: &str, from_addr: &str) -> String {
    let (_, embedded) = parsing::parseaddr(from_name);
    if !embedded.contains('@') || from_addr.is_empty() {
        return String::new();
    }
    if embedded.to_lowercase() != from_addr.to_lowercase() {
        return embedded.to_lowercase();
    }
    String::new()
}

/// Suffix (`"." + last piece`) used by the risky-attachment check.
fn attachment_suffix(name: &str) -> String {
    match name.rsplit_once('.') {
        Some((_, extension)) => format!(".{extension}"),
        None => String::new(),
    }
}

/// `audit_message(raw, account_email=...)`: the full report as JSON.
pub fn audit_message(raw: &[u8], account_email: Option<&str>) -> Value {
    let message = parsing::parse_message(raw);
    let (from_name, from_addr) = parsing::parseaddr(&message.get("From").unwrap_or_default());
    let from_addr = from_addr.to_lowercase();
    let from_domain = domain(&from_addr);
    let reply_to = parsing::first_address(message.get("Reply-To").as_deref());
    let return_path = parsing::first_address(message.get("Return-Path").as_deref());
    let message_id = parsing::py_strip(&message.get("Message-ID").unwrap_or_default()).to_string();
    let message_id_domain = match message_id.rsplit_once('@') {
        Some((_, tail)) => tail.trim_matches(['>', ' ']).to_lowercase(),
        None => String::new(),
    };

    let auth = auth_results(&message);
    let (hops, delivery_seconds) = received_chain(&message);
    let (text, html_body) = parsing::extract_bodies(&message);
    let links = parsing::extract_links(&text, &html_body);
    let attachments = parsing::list_attachments(&message);

    let mut findings: Vec<(String, String, String)> = Vec::new();
    let mut add = |severity: &str, title: String, detail: String| {
        findings.push((severity.to_string(), title, detail));
    };

    // Authentication verdicts.
    for (check, value) in [
        ("spf", &auth.spf),
        ("dkim", &auth.dkim),
        ("dmarc", &auth.dmarc),
    ] {
        let label = check.to_uppercase();
        match value.as_str() {
            "pass" => add(
                "pass",
                format!("{label} passed"),
                format!("The sending infrastructure was authorized for {label}."),
            ),
            "none" | "neutral" => add(
                "info",
                format!("{label} not reported"),
                format!("No {label} verdict was recorded by the receiving server."),
            ),
            "fail" | "permerror" | "temperror" | "policy" | "reject" => add(
                "alert",
                format!("{label} failed"),
                format!("{label} reported '{value}' - the message may be forged."),
            ),
            _ => add(
                "warn",
                format!("{label} inconclusive"),
                format!("{label} reported '{value}'."),
            ),
        }
    }

    // Sender alignment checks.
    let sender_registered = registered_domain(&from_domain);
    if !return_path.is_empty() && registered_domain(&domain(&return_path)) != sender_registered {
        add(
            "warn",
            "Return-Path domain differs".into(),
            format!(
                "Bounces go to {} but the visible sender is {from_domain}.",
                domain(&return_path)
            ),
        );
    }
    if !reply_to.is_empty() && registered_domain(&domain(&reply_to)) != sender_registered {
        add(
            "warn",
            "Replies go elsewhere".into(),
            format!(
                "Reply-To points at {}, not the sender domain {from_domain}.",
                domain(&reply_to)
            ),
        );
    }
    let spoofed =
        display_name_address_mismatch(&parsing::decode_value(Some(&from_name)), &from_addr);
    if !spoofed.is_empty() {
        add(
            "alert",
            "Display-name spoofing".into(),
            format!(
                "The display name contains '{spoofed}' but the actual sender is '{from_addr}'."
            ),
        );
    }
    if !message_id_domain.is_empty() && registered_domain(&message_id_domain) != sender_registered {
        add(
            "info",
            "Message-ID domain differs".into(),
            format!("Message-ID was minted by {message_id_domain}, not {from_domain}."),
        );
    }
    if message_id.is_empty() {
        add(
            "warn",
            "Missing Message-ID".into(),
            "Well-behaved mail agents almost always add a Message-ID.".into(),
        );
    }

    // Routing.
    if hops.is_empty() {
        add(
            "info",
            "No Received headers".into(),
            "The routing chain was stripped or never recorded.".into(),
        );
    } else if hops.len() > 12 {
        add(
            "info",
            "Long delivery path".into(),
            format!("The message crossed {} recorded servers.", hops.len()),
        );
    }
    for link in &links {
        let host = &link.domain;
        if host.is_empty() {
            continue;
        }
        if is_ip_literal(host) {
            add(
                "warn",
                "Link to a raw IP address".into(),
                format!("{} uses a numeric host instead of a domain.", link.url),
            );
        } else if host.starts_with("xn--") || host.contains(".xn--") {
            add(
                "warn",
                "Punycode link domain".into(),
                format!("{host} may be a lookalike (internationalized) domain."),
            );
        }
        let label_host = if link.label.starts_with("http://") || link.label.starts_with("https://")
        {
            parsing::url_hostname(&link.label)
        } else {
            String::new()
        };
        if !label_host.is_empty() && registered_domain(&label_host) != registered_domain(host) {
            add(
                "warn",
                "Link text masks another domain".into(),
                format!("Text shows {label_host} but the link goes to {host}."),
            );
        }
    }

    let mut suspicious_attachments: Vec<String> = Vec::new();
    for attachment in &attachments {
        let name = attachment.filename.to_lowercase();
        let suffix = attachment_suffix(&name);
        if RISKY_EXTENSIONS.contains(&suffix.as_str()) {
            suspicious_attachments.push(attachment.filename.clone());
            continue;
        }
        // A document-looking name hiding a risky trailing extension, e.g. "a.pdf.js".
        let pieces: Vec<&str> = name.split('.').collect();
        if pieces.len() >= 3 {
            let second = pieces[pieces.len() - 2];
            if !second.is_empty() && DOUBLE_EXT_SECOND.contains(&format!(".{second}").as_str()) {
                suspicious_attachments.push(attachment.filename.clone());
            }
        }
    }
    if !suspicious_attachments.is_empty() {
        add(
            "alert",
            "Risky attachment type".into(),
            format!(
                "Potentially dangerous attachment(s): {}.",
                suspicious_attachments.join(", ")
            ),
        );
    }

    let unsubscribe_header = message.get("List-Unsubscribe");
    let unsubscribe_present = unsubscribe_header.as_deref().is_some_and(|v| !v.is_empty());
    if unsubscribe_present {
        add(
            "info",
            "Bulk-mail unsubscribe".into(),
            "A List-Unsubscribe method is present (mailing-list style).".into(),
        );
    }
    if message.get("X-Mailer").is_none() && hops.is_empty() {
        add(
            "info",
            "Minimal headers".into(),
            "No X-Mailer or routing metadata to corroborate origin.".into(),
        );
    }

    let score = findings
        .iter()
        .map(|(severity, _, _)| severity_score(severity))
        .sum::<u32>()
        .min(100);
    let verdict = if score >= 50 {
        "high"
    } else if score >= 20 {
        "medium"
    } else {
        "low"
    };
    // Stable sort, most severe first (Python list.sort is stable too).
    findings.sort_by_key(|(severity, _, _)| -severity_order(severity));

    let importance = message
        .get("Importance")
        .filter(|value| !value.is_empty())
        .or_else(|| message.get("X-Priority"))
        .unwrap_or_default();
    let snippet_source = if text.is_empty() {
        parsing::strip_tags(&html_body)
    } else {
        text.clone()
    };
    let hop_count = hops.len();
    let link_count = links.len();

    json!({
        "generated_at": python_utc_now_isoformat(),
        "account": account_email.unwrap_or(""),
        "subject": parsing::decode_value(message.get("Subject").as_deref()),
        "from_name": parsing::decode_value(Some(&from_name)),
        "from_addr": from_addr,
        "to": parsing::address_text(message.get("To").as_deref()),
        "date": parsing::parse_date(message.get("Date").as_deref()),
        "message_id": message_id,
        "authentication": {
            "spf": auth.spf,
            "dkim": auth.dkim,
            "dmarc": auth.dmarc,
            "raw": auth.raw,
        },
        "sender": {
            "from_domain": from_domain,
            "reply_to": reply_to,
            "return_path": return_path,
            "message_id_domain": message_id_domain,
            "x_mailer": parsing::decode_value(message.get("X-Mailer").as_deref()),
            "importance": parsing::py_strip(&importance),
        },
        "routing": {
            "hop_count": hop_count,
            "delivery_seconds": delivery_seconds,
            "hops": hops.into_iter().take(20).collect::<Vec<_>>(),
        },
        "links": links.into_iter().take(100).collect::<Vec<_>>(),
        "link_count": link_count,
        "attachments": attachments,
        "unsubscribe": {
            "present": unsubscribe_present,
            "link": parsing::unsubscribe_link(unsubscribe_header.as_deref()),
            "one_click": message.get("List-Unsubscribe-Post").is_some_and(|v| !v.is_empty()),
        },
        "findings": findings
            .into_iter()
            .map(|(severity, title, detail)| json!({
                "severity": severity,
                "title": title,
                "detail": detail,
            }))
            .collect::<Vec<_>>(),
        "risk_score": score,
        "verdict": verdict,
        "snippet": parsing::snippet(&snippet_source, 200),
    })
}

/// `datetime.now(timezone.utc).isoformat()`.
fn python_utc_now_isoformat() -> String {
    PyDateTime {
        naive: Utc::now().naive_utc(),
        offset_seconds: Some(0),
    }
    .isoformat()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(name: &str) -> Vec<u8> {
        let path = format!("{}/tests/fixtures/{name}.eml", env!("CARGO_MANIFEST_DIR"));
        std::fs::read(path).expect("fixture")
    }

    fn titles(report: &Value) -> Vec<String> {
        report["findings"]
            .as_array()
            .unwrap()
            .iter()
            .map(|f| f["title"].as_str().unwrap().to_string())
            .collect()
    }

    /// test_mail.py::AuditTests::test_audit_flags_spoofed_and_unauthenticated_message
    #[test]
    fn audit_flags_spoofed_and_unauthenticated_message() {
        let report = audit_message(&fixture("sample_phish"), None);
        assert_eq!(report["authentication"]["spf"], "fail");
        assert_eq!(report["authentication"]["dmarc"], "fail");
        assert_eq!(report["authentication"]["dkim"], "none");
        assert_eq!(report["routing"]["hop_count"], 2);
        let titles = titles(&report);
        for expected in [
            "Display-name spoofing",
            "SPF failed",
            "DMARC failed",
            "Replies go elsewhere",
            "Return-Path domain differs",
            "Risky attachment type",
            "Link to a raw IP address",
            "Punycode link domain",
            "Link text masks another domain",
        ] {
            assert!(titles.iter().any(|t| t == expected), "missing {expected}");
        }
        assert!(report["risk_score"].as_u64().unwrap() >= 50);
        assert_eq!(report["verdict"], "high");
        assert_eq!(report["routing"]["delivery_seconds"], json!(15.0));
        assert_eq!(report["account"], "");
    }

    /// test_mail.py::AuditTests::test_audit_clean_message_scores_low
    #[test]
    fn audit_clean_message_scores_low() {
        let report = audit_message(&fixture("clean"), Some("bob@example.com"));
        assert_eq!(report["verdict"], "low");
        assert_eq!(report["authentication"]["spf"], "pass");
        assert!(!report["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f["severity"] == "alert"));
        assert_eq!(report["account"], "bob@example.com");
        let generated = report["generated_at"].as_str().unwrap();
        assert!(generated.ends_with("+00:00"));
    }

    #[test]
    fn helpers() {
        assert_eq!(registered_domain("Mail.Example.COM."), "example.com");
        assert_eq!(registered_domain("localhost"), "localhost");
        assert_eq!(registered_domain(""), "");
        assert!(is_ip_literal("185.10.20.30"));
        assert!(is_ip_literal("::1"));
        assert!(!is_ip_literal("1.2.3"));
        assert_eq!(domain("a@B.c"), "b.c");
        assert_eq!(domain("nobody"), "");
        assert_eq!(
            display_name_address_mismatch("Bank <support@bank.example>", "forged@evil.example"),
            "support@bank.example"
        );
        assert_eq!(
            display_name_address_mismatch("Alice", "alice@example.com"),
            ""
        );
    }

    #[test]
    fn mixed_naive_and_aware_received_dates_do_not_fail() {
        let raw = b"Received: by a; Mon, 13 Oct 2026 10:00:00 -0000\r\n\
Received: by b; Mon, 13 Oct 2026 10:00:00 +0000\r\n\r\nx";
        let report = audit_message(raw, None);
        assert_eq!(report["routing"]["delivery_seconds"], Value::Null);
        assert_eq!(
            report["routing"]["hops"][0]["timestamp"],
            "2026-10-13T10:00:00"
        );
    }
}
