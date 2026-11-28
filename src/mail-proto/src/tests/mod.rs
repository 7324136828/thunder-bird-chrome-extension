//! Crate tests. Round trips run the real clients against the testkit fake
//! servers (compiled automatically for `cfg(test)`).

mod imap_client;
mod imap_tls;
mod parser;
mod pop3;
mod smtp;
mod utf7;

use std::time::Duration;

use crate::imap::parser::Part;
use crate::imap::response::literal_size;

pub(crate) const TIMEOUT: Duration = Duration::from_secs(10);

/// Split raw wire bytes (one response, CRLF terminated) into parts the
/// way the client reader does.
pub(crate) fn wire_parts(wire: &[u8]) -> Vec<Part> {
    let mut parts = Vec::new();
    let mut rest = wire;
    loop {
        let end = rest
            .windows(2)
            .position(|w| w == b"\r\n")
            .expect("CRLF-terminated line");
        let line = rest[..end].to_vec();
        rest = &rest[end + 2..];
        match literal_size(&line) {
            Some(size) => {
                parts.push(Part {
                    text: line,
                    literal: Some(rest[..size].to_vec()),
                });
                rest = &rest[size..];
            }
            None => {
                parts.push(Part::text(line));
                assert!(rest.is_empty(), "trailing bytes after response");
                return parts;
            }
        }
    }
}

/// Build `prefix {n}\r\n<literal>suffix\r\n`.
pub(crate) fn with_literal(prefix: &str, literal: &[u8], suffix: &str) -> Vec<u8> {
    let mut out = format!("{prefix}{{{}}}\r\n", literal.len()).into_bytes();
    out.extend_from_slice(literal);
    out.extend_from_slice(suffix.as_bytes());
    out.extend_from_slice(b"\r\n");
    out
}
