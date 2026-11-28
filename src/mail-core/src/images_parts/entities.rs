//! Python `html.unescape` and Python 3.14 `html.parser._unescape_attrvalue`.
//!
//! Named references use the WHATWG table shipped with `html-escape` (the
//! same 2125 names as Python's `html.entities.html5`), plus Python's 106
//! legacy names that also match without a trailing `;`.

use html_escape::NAMED_ENTITIES;

/// `html.entities.html5` keys without a trailing semicolon.
const LEGACY: [&str; 106] = [
    "AElig", "AMP", "Aacute", "Acirc", "Agrave", "Aring", "Atilde", "Auml", "COPY", "Ccedil",
    "ETH", "Eacute", "Ecirc", "Egrave", "Euml", "GT", "Iacute", "Icirc", "Igrave", "Iuml", "LT",
    "Ntilde", "Oacute", "Ocirc", "Ograve", "Oslash", "Otilde", "Ouml", "QUOT", "REG", "THORN",
    "Uacute", "Ucirc", "Ugrave", "Uuml", "Yacute", "aacute", "acirc", "acute", "aelig", "agrave",
    "amp", "aring", "atilde", "auml", "brvbar", "ccedil", "cedil", "cent", "copy", "curren", "deg",
    "divide", "eacute", "ecirc", "egrave", "eth", "euml", "frac12", "frac14", "frac34", "gt",
    "iacute", "icirc", "iexcl", "igrave", "iquest", "iuml", "laquo", "lt", "macr", "micro",
    "middot", "nbsp", "not", "ntilde", "oacute", "ocirc", "ograve", "ordf", "ordm", "oslash",
    "otilde", "ouml", "para", "plusmn", "pound", "quot", "raquo", "reg", "sect", "shy", "sup1",
    "sup2", "sup3", "szlig", "thorn", "times", "uacute", "ucirc", "ugrave", "uml", "uuml",
    "yacute", "yen", "yuml",
];

fn named(name: &str) -> Option<&'static str> {
    NAMED_ENTITIES
        .binary_search_by(|(candidate, _)| candidate.cmp(&name.as_bytes()))
        .ok()
        .map(|index| NAMED_ENTITIES[index].1)
}

/// `key in html.entities.html5`.
fn html5(key: &str) -> Option<&'static str> {
    match key.strip_suffix(';') {
        Some(name) => named(name),
        None if LEGACY.contains(&key) => named(key),
        None => None,
    }
}

/// `html._invalid_charrefs`.
fn invalid_charref(number: u32) -> Option<&'static str> {
    Some(match number {
        0x00 => "\u{fffd}",
        0x0d => "\r",
        0x80 => "\u{20ac}",
        0x81 => "\u{81}",
        0x82 => "\u{201a}",
        0x83 => "\u{0192}",
        0x84 => "\u{201e}",
        0x85 => "\u{2026}",
        0x86 => "\u{2020}",
        0x87 => "\u{2021}",
        0x88 => "\u{02c6}",
        0x89 => "\u{2030}",
        0x8a => "\u{0160}",
        0x8b => "\u{2039}",
        0x8c => "\u{0152}",
        0x8d => "\u{8d}",
        0x8e => "\u{017d}",
        0x8f => "\u{8f}",
        0x90 => "\u{90}",
        0x91 => "\u{2018}",
        0x92 => "\u{2019}",
        0x93 => "\u{201c}",
        0x94 => "\u{201d}",
        0x95 => "\u{2022}",
        0x96 => "\u{2013}",
        0x97 => "\u{2014}",
        0x98 => "\u{02dc}",
        0x99 => "\u{2122}",
        0x9a => "\u{0161}",
        0x9b => "\u{203a}",
        0x9c => "\u{0153}",
        0x9d => "\u{9d}",
        0x9e => "\u{017e}",
        0x9f => "\u{0178}",
        _ => return None,
    })
}

/// `html._invalid_codepoints`.
fn invalid_codepoint(number: u32) -> bool {
    matches!(number, 0x1..=0x8 | 0xb | 0xe..=0x1f | 0x7f..=0x9f | 0xfdd0..=0xfdef)
        || (number & 0xfffe == 0xfffe && number <= 0x10ffff)
}

/// `html._replace_charref` for a numeric reference body (`#123` / `#x7b`,
/// optionally ending in `;`).
fn numeric(reference: &str) -> String {
    let body = reference.trim_end_matches(';');
    let (digits, radix) = match body.strip_prefix("#x").or_else(|| body.strip_prefix("#X")) {
        Some(hex) => (hex, 16),
        None => (&body[1..], 10),
    };
    // Saturate: anything above U+10FFFF is replaced anyway.
    let mut number: u64 = 0;
    for digit in digits.chars() {
        number = number
            .saturating_mul(radix)
            .saturating_add(digit.to_digit(radix as u32).unwrap_or(0) as u64);
        number = number.min(0x11_0000);
    }
    let number = number as u32;
    if let Some(replacement) = invalid_charref(number) {
        return replacement.to_string();
    }
    if (0xd800..=0xdfff).contains(&number) || number > 0x10ffff {
        return "\u{fffd}".to_string();
    }
    if invalid_codepoint(number) {
        return String::new();
    }
    char::from_u32(number).map(String::from).unwrap_or_default()
}

/// Length in bytes of a `_charref` match body starting at `rest` (just after
/// `&`): `#[0-9]+;?` | `#[xX][0-9a-fA-F]+;?` | `[^\t\n\f <&#;]{1,32};?`.
fn charref_len(rest: &str) -> Option<usize> {
    let bytes = rest.as_bytes();
    let with_semicolon = |end: usize| {
        if bytes.get(end) == Some(&b';') {
            end + 1
        } else {
            end
        }
    };
    if bytes.first() == Some(&b'#') {
        if matches!(bytes.get(1), Some(b'x' | b'X')) {
            let count = bytes[2..]
                .iter()
                .take_while(|b| b.is_ascii_hexdigit())
                .count();
            if count > 0 {
                return Some(with_semicolon(2 + count));
            }
        }
        let count = bytes[1..].iter().take_while(|b| b.is_ascii_digit()).count();
        return (count > 0).then(|| with_semicolon(1 + count));
    }
    let mut end = 0;
    for (count, (index, character)) in rest.char_indices().enumerate() {
        if count == 32
            || matches!(
                character,
                '\t' | '\n' | '\u{c}' | ' ' | '<' | '&' | '#' | ';'
            )
        {
            break;
        }
        end = index + character.len_utf8();
    }
    (end > 0).then(|| with_semicolon(end))
}

/// `html._replace_charref` for a whole match body (without `&`).
fn replace_charref(body: &str) -> String {
    if body.starts_with('#') {
        return numeric(body);
    }
    if let Some(value) = html5(body) {
        return value.to_string();
    }
    let boundaries: Vec<usize> = body.char_indices().map(|(index, _)| index).collect();
    // for x in range(len(s)-1, 1, -1): s[:x]
    for x in (2..boundaries.len()).rev() {
        let prefix = &body[..boundaries[x]];
        if let Some(value) = html5(prefix) {
            return format!("{value}{}", &body[boundaries[x]..]);
        }
    }
    format!("&{body}")
}

/// Python `html.unescape`.
pub(crate) fn unescape(value: &str) -> String {
    if !value.contains('&') {
        return value.to_string();
    }
    let mut out = String::with_capacity(value.len());
    let mut rest = value;
    while let Some(position) = rest.find('&') {
        out.push_str(&rest[..position]);
        let after = &rest[position + 1..];
        match charref_len(after) {
            Some(length) => {
                out.push_str(&replace_charref(&after[..length]));
                rest = &after[length..];
            }
            None => {
                out.push('&');
                rest = after;
            }
        }
    }
    out.push_str(rest);
    out
}

/// Python 3.14 `html.parser._unescape_attrvalue`: numeric references are
/// always decoded; named ones only when they match exactly and are not
/// followed by `=` (`&(#[0-9]+|#[xX][0-9a-fA-F]+|[a-zA-Z][a-zA-Z0-9]*)[;=]?`).
pub(crate) fn unescape_attribute(value: &str) -> String {
    if !value.contains('&') {
        return value.to_string();
    }
    let mut out = String::with_capacity(value.len());
    let mut rest = value;
    while let Some(position) = rest.find('&') {
        out.push_str(&rest[..position]);
        let after = &rest[position + 1..];
        let bytes = after.as_bytes();
        let body_len = if bytes.first() == Some(&b'#') {
            let hex = matches!(bytes.get(1), Some(b'x' | b'X'))
                && bytes.get(2).is_some_and(u8::is_ascii_hexdigit);
            if hex {
                Some(
                    2 + bytes[2..]
                        .iter()
                        .take_while(|b| b.is_ascii_hexdigit())
                        .count(),
                )
            } else {
                let count = bytes[1..].iter().take_while(|b| b.is_ascii_digit()).count();
                (count > 0).then_some(1 + count)
            }
        } else if bytes.first().is_some_and(u8::is_ascii_alphabetic) {
            Some(
                bytes
                    .iter()
                    .take_while(|b| b.is_ascii_alphanumeric())
                    .count(),
            )
        } else {
            None
        };
        let Some(body_len) = body_len else {
            out.push('&');
            rest = after;
            continue;
        };
        let length = if matches!(bytes.get(body_len), Some(b';' | b'=')) {
            body_len + 1
        } else {
            body_len
        };
        let reference = &after[..length];
        // Numeric references always decode; named ones only on an exact
        // match that is not followed by "=".
        let decode =
            reference.starts_with('#') || (!reference.ends_with('=') && html5(reference).is_some());
        if decode {
            out.push_str(&unescape(&format!("&{reference}")));
        } else {
            out.push('&');
            out.push_str(reference);
        }
        rest = &after[length..];
    }
    out.push_str(rest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unescape_matches_python() {
        for (input, expected) in [
            ("a=1&amp;b=2", "a=1&b=2"),
            ("&ampx;", "&x;"),
            ("&notit;", "\u{ac}it;"),
            ("&notin;", "\u{2209}"),
            ("&#38;&#x26;&#X26", "&&&"),
            (
                "&#0;&#128;&#xD800;&#1;&#x110000;",
                "\u{fffd}\u{20ac}\u{fffd}\u{fffd}",
            ),
            ("&bogus; & &#; &", "&bogus; & &#; &"),
            ("&lt", "<"),
            ("&LT;&Lt;", "<\u{226a}"),
        ] {
            assert_eq!(unescape(input), expected, "{input}");
        }
    }

    #[test]
    fn attribute_unescape_matches_python_314() {
        for (input, expected) in [
            ("?a=1&amp;b=2", "?a=1&b=2"),
            ("?a=1&b=2", "?a=1&b=2"),
            ("?x&copy=1", "?x&copy=1"),
            ("&copy2", "&copy2"),
            ("&copy", "\u{a9}"),
            ("&#38=", "&="),
            ("&notit;", "&notit;"),
        ] {
            assert_eq!(unescape_attribute(input), expected, "{input}");
        }
    }
}
