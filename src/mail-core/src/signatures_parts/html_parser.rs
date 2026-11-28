//! Port of CPython 3.14's `html.parser.HTMLParser` with
//! `convert_charrefs=True` and `scripting=False` (the configuration used by
//! `signatures._Sanitizer` and `local_classifier._VisibleHTML`), plus
//! `html.unescape` and `html.escape`.
//!
//! The tokenizer reproduces the regular expressions of the Python module
//! (`locatetagend`, `tagfind_tolerant`, `attrfind_tolerant`, `commentclose`,
//! ...) including the backtracking of the attribute value group, the
//! RAWTEXT elements (`script`, `style`, `xmp`, `iframe`, `noembed`,
//! `noframes`, `plaintext`), the escapable RCDATA elements (`textarea`,
//! `title`), the HTML5 end-of-file rules of `close()` and the attribute
//! value character reference rules (`_unescape_attrvalue`).
//!
//! Both Python callers did `parser.feed(text); parser.close()`. That is
//! equivalent to a single `goahead(end=True)` over the whole text: `feed`
//! only stops early (to wait for more input) at points that `close()` then
//! re-parses with the same state, and the only difference in the loop (a
//! lone trailing `<`) is handled identically once `end` is true. [`parse`]
//! therefore runs `goahead(1)` once. `handle_data` may receive the text in
//! different chunks than Python, which no caller depends on.
//!
//! With `convert_charrefs=True`, `handle_charref`/`handle_entityref` are
//! never called, and comments, declarations and processing instructions
//! are ignored by both callers, so only start/end tags and data reach the
//! [`Handler`].

use super::html_entities::{HTML5, INVALID_CHARREFS, INVALID_CODEPOINTS};

/// Attributes as `HTMLParser` reports them: lowercased names, values with
/// character references resolved, `None` for attributes without a value.
pub(crate) type Attrs = Vec<(String, Option<String>)>;

/// The `handle_*` callbacks of an `HTMLParser` subclass. An error aborts the
/// parse, like an exception raised from a Python handler.
pub(crate) trait Handler {
    type Error;

    fn start_tag(&mut self, tag: &str, attrs: &Attrs) -> Result<(), Self::Error>;

    /// `handle_startendtag` (XHTML-style `<tag ... />`). The default calls
    /// `handle_starttag` then `handle_endtag`, like `HTMLParser`.
    fn start_end_tag(&mut self, tag: &str, attrs: &Attrs) -> Result<(), Self::Error> {
        self.start_tag(tag, attrs)?;
        self.end_tag(tag)
    }

    fn end_tag(&mut self, tag: &str) -> Result<(), Self::Error>;

    fn data(&mut self, data: &str) -> Result<(), Self::Error>;
}

/// `HTMLParser.CDATA_CONTENT_ELEMENTS` (RAWTEXT).
const CDATA_CONTENT_ELEMENTS: [&str; 6] =
    ["script", "style", "xmp", "iframe", "noembed", "noframes"];
/// `HTMLParser.RCDATA_CONTENT_ELEMENTS` (escapable raw text).
const RCDATA_CONTENT_ELEMENTS: [&str; 2] = ["textarea", "title"];

/// `[\t\n\r\f ]` (the HTML whitespace class of the tokenizer regexes).
fn is_ws(byte: u8) -> bool {
    matches!(byte, b'\t' | b'\n' | b'\r' | b'\x0c' | b' ')
}

fn find_byte(bytes: &[u8], from: usize, needle: u8) -> Option<usize> {
    bytes
        .get(from..)?
        .iter()
        .position(|b| *b == needle)
        .map(|offset| from + offset)
}

fn find_bytes(bytes: &[u8], from: usize, needle: &[u8]) -> Option<usize> {
    let haystack = bytes.get(from..)?;
    if haystack.len() < needle.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
        .map(|offset| from + offset)
}

/// Python `str.strip()`.
fn py_strip(value: &str) -> &str {
    value.trim_matches(|c: char| c.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&c))
}

/// Parse `html` like `HTMLParser().feed(html); close()`.
pub(crate) fn parse<H: Handler>(html: &str, handler: &mut H) -> Result<(), H::Error> {
    Parser {
        raw: html,
        bytes: html.as_bytes(),
        cdata_elem: None,
        escapable: true,
    }
    .goahead(handler)
}

struct Parser<'a> {
    raw: &'a str,
    bytes: &'a [u8],
    cdata_elem: Option<String>,
    escapable: bool,
}

/// One `attrfind_tolerant` match: the attribute name span, the value span
/// (`None` when there is no `=` group) and the end of the match.
struct AttrMatch {
    name: (usize, usize),
    value: Option<(usize, usize)>,
    end: usize,
}

impl<'a> Parser<'a> {
    fn data<H: Handler>(&self, handler: &mut H, text: &str) -> Result<(), H::Error> {
        if self.escapable {
            handler.data(&unescape(text))
        } else {
            handler.data(text)
        }
    }

    /// `goahead(end=True)`.
    fn goahead<H: Handler>(&mut self, handler: &mut H) -> Result<(), H::Error> {
        let n = self.bytes.len();
        let mut i = 0;
        while i < n {
            let j = match &self.cdata_elem {
                None => find_byte(self.bytes, i, b'<').unwrap_or(n),
                Some(element) => match self.cdata_end(i, element) {
                    Some(j) => j,
                    None => break,
                },
            };
            if i < j {
                self.data(handler, &self.raw[i..j])?;
            }
            i = j;
            if i == n {
                break;
            }
            let rest = &self.bytes[i..];
            let k = if rest.len() >= 2 && rest[1].is_ascii_alphabetic() {
                self.parse_starttag(i, handler)?
            } else if rest.starts_with(b"</") {
                self.parse_endtag(i, handler)?
            } else if rest.starts_with(b"<!--") {
                self.parse_comment(i)
            } else if rest.starts_with(b"<?") {
                find_byte(self.bytes, i + 2, b'>').map(|j| j + 1)
            } else if rest.starts_with(b"<!") {
                self.parse_html_declaration(i)
            } else {
                // `(i + 1) < n or end`: always true at end of input.
                handler.data("<")?;
                Some(i + 1)
            };
            i = match k {
                Some(k) => k,
                None => {
                    // End of input inside a construct: HTML5 EOF rules.
                    // Only "</" at the very end is reported as text;
                    // incomplete tags are dropped and comments,
                    // declarations and PIs are closed (and ignored here).
                    if rest.starts_with(b"</") && i + 2 == n {
                        handler.data("</")?;
                    }
                    n
                }
            };
        }
        if i < n {
            self.data(handler, &self.raw[i..n])?;
        }
        Ok(())
    }

    /// `self.interesting.search(rawdata, i)` in CDATA mode:
    /// `</elem(?=[\t\n\r\f />])` (ASCII, case-insensitive), or the end of
    /// the input for `plaintext` (`\z`).
    fn cdata_end(&self, from: usize, element: &str) -> Option<usize> {
        let n = self.bytes.len();
        if element == "plaintext" {
            return Some(n);
        }
        let name = element.as_bytes();
        let mut position = from;
        while let Some(start) = find_bytes(self.bytes, position, b"</") {
            let name_end = start + 2 + name.len();
            if name_end < n
                && self.bytes[start + 2..name_end].eq_ignore_ascii_case(name)
                && (is_ws(self.bytes[name_end]) || matches!(self.bytes[name_end], b'/' | b'>'))
            {
                return Some(start);
            }
            position = start + 1;
        }
        None
    }

    fn set_cdata_mode(&mut self, element: &str, escapable: bool) {
        self.cdata_elem = Some(element.to_lowercase());
        self.escapable = escapable;
    }

    fn clear_cdata_mode(&mut self) {
        self.cdata_elem = None;
        self.escapable = true;
    }

    /// `parse_comment`: `--!?>` searched from `i + 4`, else the abrupt
    /// `<!-->` / `<!--->` forms.
    fn parse_comment(&self, i: usize) -> Option<usize> {
        let bytes = self.bytes;
        let mut position = i + 4;
        while let Some(start) = find_bytes(bytes, position, b"--") {
            match bytes.get(start + 2) {
                Some(b'>') => return Some(start + 3),
                Some(b'!') if bytes.get(start + 3) == Some(&b'>') => return Some(start + 4),
                _ => position = start + 1,
            }
        }
        match bytes.get(i + 4..) {
            Some([b'>', ..]) => Some(i + 5),
            Some([b'-', b'>', ..]) => Some(i + 6),
            _ => None,
        }
    }

    /// `parse_html_declaration` (`<!--` is handled by the caller).
    fn parse_html_declaration(&self, i: usize) -> Option<usize> {
        let bytes = self.bytes;
        if bytes[i..].starts_with(b"<![CDATA[") {
            // `_support_cdata` is True by default.
            find_bytes(bytes, i + 9, b"]]>").map(|j| j + 3)
        } else if bytes
            .get(i..i + 9)
            .is_some_and(|head| head.eq_ignore_ascii_case(b"<!doctype"))
        {
            find_byte(bytes, i + 9, b'>').map(|j| j + 1)
        } else {
            // parse_bogus_comment
            find_byte(bytes, i + 2, b'>').map(|j| j + 1)
        }
    }

    /// `tagfind_tolerant` at `start` (an ASCII letter): the end of the tag
    /// name and the end of the match.
    fn tagfind(&self, start: usize) -> (usize, usize) {
        let bytes = self.bytes;
        let n = bytes.len();
        let mut p = start + 1;
        while p < n && !is_ws(bytes[p]) && !matches!(bytes[p], b'/' | b'>') {
            p += 1;
        }
        let name_end = p;
        while p < n && (is_ws(bytes[p]) || (bytes[p] == b'/' && bytes.get(p + 1) != Some(&b'>'))) {
            p += 1;
        }
        (name_end, p)
    }

    /// The optional value group of `attrfind_tolerant` / `locatetagend`
    /// starting right after an attribute name:
    /// `[\t\n\r\f ]*=[\t\n\r\f ]*('[^']*'|"[^"]*"|(?!['"])[^>\t\n\r\f ]*)`.
    /// Returns the end of the group and the value span. When the value
    /// starts with an unterminated quote, the regex engine backtracks the
    /// whitespace after `=` and matches an empty bare value instead.
    fn value_group(&self, p: usize) -> Option<(usize, (usize, usize))> {
        let bytes = self.bytes;
        let n = bytes.len();
        let mut q = p;
        while q < n && is_ws(bytes[q]) {
            q += 1;
        }
        if q >= n || bytes[q] != b'=' {
            return None;
        }
        let r = q + 1;
        let mut s = r;
        while s < n && is_ws(bytes[s]) {
            s += 1;
        }
        loop {
            let alternative = match bytes.get(s) {
                Some(&quote @ (b'\'' | b'"')) => {
                    find_byte(bytes, s + 1, quote).map(|close| close + 1)
                }
                _ => {
                    let mut e = s;
                    while e < n && bytes[e] != b'>' && !is_ws(bytes[e]) {
                        e += 1;
                    }
                    Some(e)
                }
            };
            if let Some(end) = alternative {
                return Some((end, (s, end)));
            }
            if s == r {
                return None;
            }
            s -= 1;
        }
    }

    /// `(?<=['"\t\n\r\f /])[^\t\n\r\f />]`: can an attribute name start at `p`?
    fn attribute_starts(&self, p: usize) -> bool {
        let bytes = self.bytes;
        p > 0
            && p < bytes.len()
            && (matches!(bytes[p - 1], b'\'' | b'"' | b'/') || is_ws(bytes[p - 1]))
            && !is_ws(bytes[p])
            && !matches!(bytes[p], b'/' | b'>')
    }

    /// End of an attribute name starting at `p`: `[^\t\n\r\f /=>]*` after
    /// the first character.
    fn attribute_name_end(&self, p: usize) -> usize {
        let bytes = self.bytes;
        let mut q = p + 1;
        while q < bytes.len() && !is_ws(bytes[q]) && !matches!(bytes[q], b'/' | b'=' | b'>') {
            q += 1;
        }
        q
    }

    /// `locatetagend.match(rawdata, start).end()` (`start` is an ASCII letter).
    fn locate_tag_end(&self, start: usize) -> usize {
        let bytes = self.bytes;
        let n = bytes.len();
        let mut p = start + 1;
        while p < n && !is_ws(bytes[p]) && !matches!(bytes[p], b'/' | b'>') {
            p += 1;
        }
        while p < n && (is_ws(bytes[p]) || bytes[p] == b'/') {
            p += 1;
        }
        while self.attribute_starts(p) {
            let mut q = self.attribute_name_end(p);
            if let Some((end, _)) = self.value_group(q) {
                q = end;
            }
            while q < n && (is_ws(bytes[q]) || bytes[q] == b'/') {
                q += 1;
            }
            p = q;
        }
        if p < n && bytes[p] == b'>' {
            p += 1;
        }
        p
    }

    /// `attrfind_tolerant.match(rawdata, k)`.
    fn attrfind(&self, k: usize) -> Option<AttrMatch> {
        if !self.attribute_starts(k) {
            return None;
        }
        let bytes = self.bytes;
        let n = bytes.len();
        let name_end = self.attribute_name_end(k);
        let mut q = name_end;
        let mut value = None;
        if let Some((end, span)) = self.value_group(q) {
            q = end;
            value = Some(span);
        }
        while q < n && (is_ws(bytes[q]) || (bytes[q] == b'/' && bytes.get(q + 1) != Some(&b'>'))) {
            q += 1;
        }
        Some(AttrMatch {
            name: (k, name_end),
            value,
            end: q,
        })
    }

    /// `parse_starttag`; `None` when the tag is incomplete.
    fn parse_starttag<H: Handler>(
        &mut self,
        i: usize,
        handler: &mut H,
    ) -> Result<Option<usize>, H::Error> {
        let endpos = self.locate_tag_end(i + 1);
        if self.bytes[endpos - 1] != b'>' {
            return Ok(None);
        }
        let (name_end, mut k) = self.tagfind(i + 1);
        let tag = self.raw[i + 1..name_end].to_lowercase();
        let mut attrs: Attrs = Vec::new();
        while k < endpos {
            let Some(found) = self.attrfind(k) else {
                break;
            };
            let name = self.raw[found.name.0..found.name.1].to_lowercase();
            let value = found.value.map(|(start, end)| {
                let mut value = &self.raw[start..end];
                if value.len() >= 2
                    && ((value.starts_with('\'') && value.ends_with('\''))
                        || (value.starts_with('"') && value.ends_with('"')))
                {
                    value = &value[1..value.len() - 1];
                }
                if value.is_empty() {
                    String::new()
                } else {
                    unescape_attribute_value(value)
                }
            });
            attrs.push((name, value));
            k = found.end;
        }
        let end = if k <= endpos {
            py_strip(&self.raw[k..endpos])
        } else {
            ""
        };
        if end != ">" && end != "/>" {
            handler.data(&self.raw[i..endpos])?;
            return Ok(Some(endpos));
        }
        if end == "/>" {
            handler.start_end_tag(&tag, &attrs)?;
        } else {
            handler.start_tag(&tag, &attrs)?;
            if CDATA_CONTENT_ELEMENTS.contains(&tag.as_str()) || tag == "plaintext" {
                self.set_cdata_mode(&tag, false);
            } else if RCDATA_CONTENT_ELEMENTS.contains(&tag.as_str()) {
                self.set_cdata_mode(&tag, true);
            }
        }
        Ok(Some(endpos))
    }

    /// `parse_endtag`; `None` when incomplete.
    fn parse_endtag<H: Handler>(
        &mut self,
        i: usize,
        handler: &mut H,
    ) -> Result<Option<usize>, H::Error> {
        let bytes = self.bytes;
        if find_byte(bytes, i + 2, b'>').is_none() {
            return Ok(None);
        }
        if !bytes.get(i + 2).is_some_and(u8::is_ascii_alphabetic) {
            if bytes.get(i + 2) == Some(&b'>') {
                // "</>" is ignored.
                return Ok(Some(i + 3));
            }
            // parse_bogus_comment
            return Ok(find_byte(bytes, i + 2, b'>').map(|position| position + 1));
        }
        let j = self.locate_tag_end(i + 2);
        if bytes[j - 1] != b'>' {
            return Ok(None);
        }
        let (name_end, _) = self.tagfind(i + 2);
        let tag = self.raw[i + 2..name_end].to_lowercase();
        handler.end_tag(&tag)?;
        self.clear_cdata_mode();
        Ok(Some(j))
    }
}

// ---------------------------------------------------------------------------
// html.escape / html.unescape
// ---------------------------------------------------------------------------

/// `html.escape(value, quote)`.
pub(crate) fn escape(value: &str, quote: bool) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' if quote => out.push_str("&quot;"),
            '\'' if quote => out.push_str("&#x27;"),
            other => out.push(other),
        }
    }
    out
}

fn html5_entity(name: &str) -> Option<&'static str> {
    HTML5
        .binary_search_by(|(key, _)| (*key).cmp(name))
        .ok()
        .map(|index| HTML5[index].1)
}

/// `_replace_charref` for a numeric reference (`digits` without `&#`/`x`).
fn numeric_reference(digits: &str, radix: u32) -> String {
    // Python ints are unbounded; anything that overflows is > 0x10FFFF.
    let number = u32::from_str_radix(digits, radix).unwrap_or(u32::MAX);
    if let Ok(index) = INVALID_CHARREFS.binary_search_by(|(key, _)| key.cmp(&number)) {
        return INVALID_CHARREFS[index].1.to_string();
    }
    if (0xD800..=0xDFFF).contains(&number) || number > 0x10FFFF {
        return '\u{fffd}'.to_string();
    }
    if INVALID_CODEPOINTS.binary_search(&number).is_ok() {
        return String::new();
    }
    char::from_u32(number).map(String::from).unwrap_or_default()
}

/// `_replace_charref` for a named reference (`name` may end with `;`).
fn named_reference(name: &str) -> String {
    if let Some(value) = html5_entity(name) {
        return value.to_string();
    }
    let boundaries: Vec<usize> = name.char_indices().map(|(index, _)| index).collect();
    // for x in range(len(s)-1, 1, -1): s[:x]
    for x in (2..boundaries.len()).rev() {
        let (prefix, rest) = name.split_at(boundaries[x]);
        if let Some(value) = html5_entity(prefix) {
            return format!("{value}{rest}");
        }
    }
    format!("&{name}")
}

/// `html.unescape(s)`: resolve every
/// `&(#[0-9]+;?|#[xX][0-9a-fA-F]+;?|[^\t\n\f <&#;]{1,32};?)`.
pub(crate) fn unescape(s: &str) -> String {
    if !s.contains('&') {
        return s.to_string();
    }
    let bytes = s.as_bytes();
    let n = bytes.len();
    let mut out = String::with_capacity(s.len());
    let mut last = 0;
    let mut i = 0;
    while let Some(amp) = find_byte(bytes, i, b'&') {
        let start = amp + 1;
        let mut end = None;
        let mut replacement = String::new();
        if bytes.get(start) == Some(&b'#') {
            let digits_start = start + 1;
            let mut p = digits_start;
            while p < n && bytes[p].is_ascii_digit() {
                p += 1;
            }
            if p > digits_start {
                replacement = numeric_reference(&s[digits_start..p], 10);
                end = Some(if bytes.get(p) == Some(&b';') {
                    p + 1
                } else {
                    p
                });
            } else if matches!(bytes.get(digits_start), Some(b'x' | b'X')) {
                let hex_start = digits_start + 1;
                let mut p = hex_start;
                while p < n && bytes[p].is_ascii_hexdigit() {
                    p += 1;
                }
                if p > hex_start {
                    replacement = numeric_reference(&s[hex_start..p], 16);
                    end = Some(if bytes.get(p) == Some(&b';') {
                        p + 1
                    } else {
                        p
                    });
                }
            }
        } else {
            let mut p = start;
            let mut count = 0;
            for c in s[start..].chars() {
                if count == 32 || matches!(c, '\t' | '\n' | '\x0c' | ' ' | '<' | '&' | '#' | ';') {
                    break;
                }
                p += c.len_utf8();
                count += 1;
            }
            if count > 0 {
                let name_end = if bytes.get(p) == Some(&b';') {
                    p + 1
                } else {
                    p
                };
                replacement = named_reference(&s[start..name_end]);
                end = Some(name_end);
            }
        }
        match end {
            Some(end) => {
                out.push_str(&s[last..amp]);
                out.push_str(&replacement);
                last = end;
                i = end;
            }
            None => i = amp + 1,
        }
    }
    out.push_str(&s[last..]);
    out
}

/// `_unescape_attrvalue`: numeric references are always resolved; named
/// ones only on an exact `html5` match not followed by `=`.
pub(crate) fn unescape_attribute_value(s: &str) -> String {
    if !s.contains('&') {
        return s.to_string();
    }
    let bytes = s.as_bytes();
    let n = bytes.len();
    let mut out = String::with_capacity(s.len());
    let mut last = 0;
    let mut i = 0;
    while let Some(amp) = find_byte(bytes, i, b'&') {
        let start = amp + 1;
        // &(#[0-9]+|#[xX][0-9a-fA-F]+|[a-zA-Z][a-zA-Z0-9]*)[;=]?
        let mut reference_end = None;
        if bytes.get(start) == Some(&b'#') {
            let mut p = start + 1;
            while p < n && bytes[p].is_ascii_digit() {
                p += 1;
            }
            if p > start + 1 {
                reference_end = Some(p);
            } else if matches!(bytes.get(start + 1), Some(b'x' | b'X')) {
                let mut p = start + 2;
                while p < n && bytes[p].is_ascii_hexdigit() {
                    p += 1;
                }
                if p > start + 2 {
                    reference_end = Some(p);
                }
            }
        } else if bytes.get(start).is_some_and(u8::is_ascii_alphabetic) {
            let mut p = start + 1;
            while p < n && bytes[p].is_ascii_alphanumeric() {
                p += 1;
            }
            reference_end = Some(p);
        }
        let Some(mut end) = reference_end else {
            i = amp + 1;
            continue;
        };
        if matches!(bytes.get(end), Some(b';' | b'=')) {
            end += 1;
        }
        let reference = &s[amp..end];
        let replacement = if reference.starts_with("&#")
            || (!reference.ends_with('=') && html5_entity(&reference[1..]).is_some())
        {
            unescape(reference)
        } else {
            reference.to_string()
        };
        out.push_str(&s[last..amp]);
        out.push_str(&replacement);
        last = end;
        i = end;
    }
    out.push_str(&s[last..]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct Recorder(Vec<String>);

    impl Handler for Recorder {
        type Error = std::convert::Infallible;

        fn start_tag(&mut self, tag: &str, attrs: &Attrs) -> Result<(), Self::Error> {
            self.0.push(format!("start {tag} {attrs:?}"));
            Ok(())
        }

        fn start_end_tag(&mut self, tag: &str, attrs: &Attrs) -> Result<(), Self::Error> {
            self.0.push(format!("startend {tag} {attrs:?}"));
            Ok(())
        }

        fn end_tag(&mut self, tag: &str) -> Result<(), Self::Error> {
            self.0.push(format!("end {tag}"));
            Ok(())
        }

        fn data(&mut self, data: &str) -> Result<(), Self::Error> {
            // Merge adjacent chunks: Python may split data differently.
            if let Some(last) = self.0.last_mut().filter(|last| last.starts_with("data ")) {
                last.push_str(data);
            } else {
                self.0.push(format!("data {data}"));
            }
            Ok(())
        }
    }

    fn events(html: &str) -> Vec<String> {
        let mut recorder = Recorder::default();
        parse(html, &mut recorder).unwrap();
        recorder.0
    }

    #[test]
    fn unescape_matches_python() {
        assert_eq!(unescape("a &amp; b"), "a & b");
        assert_eq!(unescape("&lt;b&gt;"), "<b>");
        assert_eq!(unescape("&ampx"), "&x");
        assert_eq!(unescape("&notit;"), "\u{ac}it;");
        assert_eq!(unescape("&#38;&#x26;&#X26"), "&&&");
        assert_eq!(
            unescape("&#0;&#128;&#xD800;&#1;&#x110000;"),
            "\u{fffd}\u{20ac}\u{fffd}\u{fffd}"
        );
        assert_eq!(unescape("&#99999999999999999999;"), "\u{fffd}");
        assert_eq!(unescape("&#x;&#;&;& &unknown;"), "&#x;&#;&;& &unknown;");
        assert_eq!(unescape("&nbsp"), "\u{a0}");
    }

    #[test]
    fn attribute_values_keep_ambiguous_named_references() {
        assert_eq!(unescape_attribute_value("?a=1&copy=2"), "?a=1&copy=2");
        assert_eq!(
            unescape_attribute_value("&copy;&copy &copyx"),
            "\u{a9}\u{a9} &copyx"
        );
        assert_eq!(unescape_attribute_value("&#38=&amp;"), "&=&");
    }

    #[test]
    fn tags_attributes_and_data() {
        assert_eq!(
            events(r#"<P Class=x ID='a&amp;b' hidden>Hi &amp; bye<br/></p>"#),
            [
                r#"start p [("class", Some("x")), ("id", Some("a&b")), ("hidden", None)]"#,
                "data Hi & bye",
                "startend br []",
                "end p",
            ]
        );
        // Unterminated quote: the regex backtracks to an empty bare value.
        assert_eq!(
            events("<a b= 'x>t"),
            [r#"start a [("b", Some("")), ("'x", None)]"#, "data t"]
        );
        assert_eq!(
            events(r#"<a href=x/>"#),
            [r#"start a [("href", Some("x/"))]"#]
        );
        assert_eq!(events("<img src=\"x"), Vec::<String>::new());
        assert_eq!(events("a < b"), ["data a < b"]);
        assert_eq!(events("x</"), ["data x</"]);
        assert_eq!(events("x</b"), ["data x"]);
        assert_eq!(events("</>x</ y>z"), ["data xz"]);
    }

    #[test]
    fn raw_text_comments_and_declarations() {
        assert_eq!(
            events("<script>a<b>&amp;</script >c"),
            ["start script []", "data a<b>&amp;", "end script", "data c"]
        );
        assert_eq!(
            events("<title>a&amp;<b></title>"),
            ["start title []", "data a&<b>", "end title"]
        );
        assert_eq!(
            events("<style>unclosed"),
            ["start style []", "data unclosed"]
        );
        assert_eq!(
            events("<plaintext><b>x</b>"),
            ["start plaintext []", "data <b>x</b>"]
        );
        assert_eq!(events("a<!-- c -- > d -->b"), ["data ab"]);
        assert_eq!(events("a<!-->b<!--->c<!-- x --!>d"), ["data acd"]);
        assert_eq!(events("a<!-->b"), ["data ab"]);
        assert_eq!(
            events("a<!DOCTYPE html>b<![CDATA[x>y]]>c<?pi>d<!bogus>e"),
            ["data abcde"]
        );
        assert_eq!(events("a<!-- open"), ["data a"]);
    }
}
