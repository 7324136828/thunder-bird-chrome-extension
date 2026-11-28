//! IMAP modified UTF-7 (RFC 3501 section 5.1.3) mailbox-name encoding.
//!
//! Printable US-ASCII except `&` represents itself, `&` is `&-`, and other
//! characters are UTF-16BE encoded in modified BASE64 (`,` instead of `/`,
//! no padding) between `&` and `-`.

use base64::alphabet;
use base64::engine::general_purpose::{GeneralPurpose, GeneralPurposeConfig};
use base64::engine::DecodePaddingMode;
use base64::Engine;

use crate::error::{ProtoError, Result};

const MUTF7: GeneralPurpose = GeneralPurpose::new(
    &alphabet::IMAP_MUTF7,
    GeneralPurposeConfig::new()
        .with_encode_padding(false)
        .with_decode_padding_mode(DecodePaddingMode::RequireNone),
);

fn is_direct(ch: char) -> bool {
    ('\u{20}'..='\u{7e}').contains(&ch)
}

/// Encode a Unicode mailbox name to modified UTF-7.
pub fn encode(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut pending: Vec<u16> = Vec::new();
    let flush = |pending: &mut Vec<u16>, out: &mut String| {
        if pending.is_empty() {
            return;
        }
        let bytes: Vec<u8> = pending.iter().flat_map(|unit| unit.to_be_bytes()).collect();
        out.push('&');
        out.push_str(&MUTF7.encode(bytes));
        out.push('-');
        pending.clear();
    };
    for ch in name.chars() {
        if is_direct(ch) {
            flush(&mut pending, &mut out);
            if ch == '&' {
                out.push_str("&-");
            } else {
                out.push(ch);
            }
        } else {
            let mut units = [0u16; 2];
            pending.extend_from_slice(ch.encode_utf16(&mut units));
        }
    }
    flush(&mut pending, &mut out);
    out
}

fn invalid(name: &str) -> ProtoError {
    ProtoError::Protocol(format!("invalid modified UTF-7 mailbox name {name:?}"))
}

/// Decode a modified UTF-7 mailbox name. Fails on malformed input
/// (unterminated shifts, bad BASE64, invalid UTF-16, raw non-ASCII).
pub fn decode(name: &str) -> Result<String> {
    let mut out = String::with_capacity(name.len());
    let mut rest = name;
    while let Some(index) = rest.find('&') {
        let direct = &rest[..index];
        if !direct.chars().all(is_direct) {
            return Err(invalid(name));
        }
        out.push_str(direct);
        let after = &rest[index + 1..];
        let end = after.find('-').ok_or_else(|| invalid(name))?;
        let encoded = &after[..end];
        if encoded.is_empty() {
            out.push('&');
        } else {
            let bytes = MUTF7.decode(encoded).map_err(|_| invalid(name))?;
            if bytes.len() % 2 != 0 {
                return Err(invalid(name));
            }
            let units: Vec<u16> = bytes
                .as_chunks::<2>()
                .0
                .iter()
                .map(|pair| u16::from_be_bytes(*pair))
                .collect();
            let decoded = String::from_utf16(&units).map_err(|_| invalid(name))?;
            // Directly representable characters must not be encoded.
            if decoded.chars().any(is_direct) {
                return Err(invalid(name));
            }
            out.push_str(&decoded);
        }
        rest = &after[end + 1..];
    }
    if !rest.chars().all(is_direct) {
        return Err(invalid(name));
    }
    out.push_str(rest);
    Ok(out)
}
