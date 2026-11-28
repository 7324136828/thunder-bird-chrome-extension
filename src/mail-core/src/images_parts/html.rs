//! Port of Python 3.14's `html.parser.HTMLParser` (`convert_charrefs=True`)
//! for a single `feed()` call **without** `close()`, which is exactly how
//! `image_sources.image_urls` used it: constructs left incomplete at the end
//! of the input are never reported.
//!
//! The tokenizer reproduces the regular expressions `tagfind_tolerant`,
//! `attrfind_tolerant` and `locatetagend` (including their backtracking on
//! an unterminated quoted value after `= `), the RAWTEXT content mode of
//! `script`/`style`/`xmp`/`iframe`/`noembed`/`noframes`/`plaintext` and the
//! escapable RCDATA mode of `textarea`/`title`, comments (`--!?>` and the abrupt
//! `<!-->`), `<![CDATA[...]]>`, doctype, processing instructions and bogus
//! comments.

use super::entities::{unescape, unescape_attribute};
use super::urllib::py_strip;

/// Receives parser events (`HTMLParser.handle_*`).
pub(crate) trait Handler {
    /// `handle_starttag` (also called for `handle_startendtag`, which
    /// `_ImageParser` forwards to `handle_starttag`).
    fn start_tag(&mut self, tag: &str, attrs: &[(String, Option<String>)]);
    fn end_tag(&mut self, tag: &str);
    fn data(&mut self, data: &str);
}

/// `HTMLParser.CDATA_CONTENT_ELEMENTS` plus the other RAWTEXT elements that
/// Python 3.14.6's `parse_starttag` switches to CDATA mode (`scripting=False`,
/// so `noscript` is parsed normally; `plaintext` is handled separately).
const CDATA_CONTENT_ELEMENTS: [&str; 6] =
    ["script", "style", "xmp", "iframe", "noembed", "noframes"];
const RCDATA_CONTENT_ELEMENTS: [&str; 2] = ["textarea", "title"];

/// `[\t\n\r\f ]`.
fn is_ws(byte: u8) -> bool {
    matches!(byte, b'\t' | b'\n' | b'\r' | 0x0c | b' ')
}

fn find_from(s: &[u8], start: usize, needle: &[u8]) -> Option<usize> {
    if start > s.len() {
        return None;
    }
    s[start..]
        .windows(needle.len())
        .position(|window| window == needle)
        .map(|position| start + position)
}

fn find_byte(s: &[u8], start: usize, byte: u8) -> Option<usize> {
    s.get(start..)?
        .iter()
        .position(|b| *b == byte)
        .map(|position| start + position)
}

/// `'[^']*'` | `"[^"]*"` | `(?!['"])[^>\t\n\r\f ]*` at `r`; the end offset.
fn value_at(s: &[u8], r: usize) -> Option<usize> {
    match s.get(r) {
        Some(&quote @ (b'\'' | b'"')) => find_byte(s, r + 1, quote).map(|end| end + 1),
        _ => {
            let mut q = r;
            while q < s.len() && !(s[q] == b'>' || is_ws(s[q])) {
                q += 1;
            }
            Some(q)
        }
    }
}

/// `[\t\n\r\f ]*=[\t\n\r\f ]*(value)` at `p`, with the regex engine's
/// backtracking: when the value after `= ` is an unterminated quote, the
/// whitespace is given back and an empty bare value matches before it.
/// Returns `(value_start, value_end)`; the group ends at `value_end`.
fn value_indicator(s: &[u8], p: usize) -> Option<(usize, usize)> {
    let mut q = p;
    while q < s.len() && is_ws(s[q]) {
        q += 1;
    }
    if s.get(q) != Some(&b'=') {
        return None;
    }
    let after_equals = q + 1;
    let mut r = after_equals;
    while r < s.len() && is_ws(s[r]) {
        r += 1;
    }
    if let Some(end) = value_at(s, r) {
        return Some((r, end));
    }
    (r > after_equals).then_some((r - 1, r - 1))
}

/// Attribute-name lookbehind `(?<=['"\t\n\r\f /])` plus the first name
/// character `[^\t\n\r\f />]`.
fn attribute_starts(s: &[u8], q: usize) -> bool {
    q > 0
        && q < s.len()
        && (matches!(s[q - 1], b'\'' | b'"' | b'/') || is_ws(s[q - 1]))
        && !(is_ws(s[q]) || matches!(s[q], b'/' | b'>'))
}

/// End of the attribute name started at `q` (`[^\t\n\r\f /=>]*`).
fn attribute_name_end(s: &[u8], q: usize) -> usize {
    let mut q = q + 1;
    while q < s.len() && !(is_ws(s[q]) || matches!(s[q], b'/' | b'=' | b'>')) {
        q += 1;
    }
    q
}

/// `locatetagend.match(rawdata, p)` (p at the tag name's first letter).
fn locate_tag_end(s: &[u8], p: usize) -> usize {
    let mut q = p + 1;
    while q < s.len() && !(is_ws(s[q]) || matches!(s[q], b'/' | b'>')) {
        q += 1;
    }
    while q < s.len() && (is_ws(s[q]) || s[q] == b'/') {
        q += 1;
    }
    while attribute_starts(s, q) {
        q = attribute_name_end(s, q);
        if let Some((_, end)) = value_indicator(s, q) {
            q = end;
        }
        while q < s.len() && (is_ws(s[q]) || s[q] == b'/') {
            q += 1;
        }
    }
    if s.get(q) == Some(&b'>') {
        q += 1;
    }
    q
}

/// `(?:[\t\n\r\f ]|/(?!>))*` from `q`.
fn skip_ws_or_lone_slash(s: &[u8], mut q: usize) -> usize {
    while q < s.len() && (is_ws(s[q]) || (s[q] == b'/' && s.get(q + 1) != Some(&b'>'))) {
        q += 1;
    }
    q
}

/// `tagfind_tolerant.match(rawdata, p)`: `(name_end, match_end)`.
fn tagfind(s: &[u8], p: usize) -> Option<(usize, usize)> {
    if !s.get(p)?.is_ascii_alphabetic() {
        return None;
    }
    let mut q = p + 1;
    while q < s.len() && !(is_ws(s[q]) || matches!(s[q], b'/' | b'>')) {
        q += 1;
    }
    Some((q, skip_ws_or_lone_slash(s, q)))
}

struct Parser<'a, H: Handler> {
    raw: &'a str,
    s: &'a [u8],
    handler: &'a mut H,
    cdata_elem: Option<String>,
    escapable: bool,
}

/// Feed `html` once (no `close()`), reporting events to `handler`.
pub(crate) fn feed<H: Handler>(html: &str, handler: &mut H) {
    let mut parser = Parser {
        raw: html,
        s: html.as_bytes(),
        handler,
        cdata_elem: None,
        escapable: true,
    };
    parser.goahead();
}

impl<H: Handler> Parser<'_, H> {
    /// `interesting.search` in CDATA/RCDATA mode:
    /// `</{elem}(?=[\t\n\r\f />])`, ASCII case-insensitive.
    /// For `plaintext` the pattern is `\z`: everything up to the end.
    fn search_cdata_end(&self, start: usize, elem: &str) -> Option<usize> {
        let s = self.s;
        if elem == "plaintext" {
            return Some(s.len());
        }
        let needle = elem.as_bytes();
        let mut i = start;
        while let Some(position) = find_from(s, i, b"</") {
            let name_start = position + 2;
            let name_end = name_start + needle.len();
            if name_end <= s.len()
                && s[name_start..name_end].eq_ignore_ascii_case(needle)
                && s.get(name_end)
                    .is_some_and(|b| is_ws(*b) || matches!(b, b'/' | b'>'))
            {
                return Some(position);
            }
            i = position + 1;
        }
        None
    }

    /// Byte offset where the last 34 characters begin (`n - 34`, in code
    /// points), or 0.
    fn tail_34(&self) -> usize {
        self.raw
            .char_indices()
            .rev()
            .nth(33)
            .map_or(0, |(index, _)| index)
    }

    fn goahead(&mut self) {
        let s = self.s;
        let n = s.len();
        let mut i = 0;
        while i < n {
            let j;
            if let Some(elem) = self.cdata_elem.clone() {
                match self.search_cdata_end(i, &elem) {
                    Some(position) => j = position,
                    None => break,
                }
            } else {
                match find_byte(s, i, b'<') {
                    Some(position) => j = position,
                    None => {
                        // A charref may be cut in half at the end of the
                        // buffer: hold back the text (feed() without close()).
                        let from = i.max(self.tail_34());
                        if let Some(amp) = s[from..].iter().rposition(|b| *b == b'&') {
                            let amp = from + amp;
                            if !s[amp..]
                                .iter()
                                .any(|b| matches!(b, b'\t' | b'\n' | b'\r' | 0x0c | b' ' | b';'))
                            {
                                break;
                            }
                        }
                        j = n;
                    }
                }
            }
            if i < j {
                let text = &self.raw[i..j];
                if self.escapable {
                    self.handler.data(&unescape(text));
                } else {
                    self.handler.data(text);
                }
            }
            i = j;
            if i == n {
                break;
            }
            // s[i] == b'<' here.
            let k: Option<usize> = if s.get(i + 1).is_some_and(u8::is_ascii_alphabetic) {
                self.parse_starttag(i)
            } else if s[i..].starts_with(b"</") {
                self.parse_endtag(i)
            } else if s[i..].starts_with(b"<!--") {
                self.parse_comment(i)
            } else if s[i..].starts_with(b"<?") {
                find_byte(s, i + 2, b'>').map(|end| end + 1)
            } else if s[i..].starts_with(b"<!") {
                self.parse_html_declaration(i)
            } else if i + 1 < n {
                self.handler.data("<");
                Some(i + 1)
            } else {
                break;
            };
            match k {
                Some(k) => i = k,
                None => break,
            }
        }
    }

    fn parse_starttag(&mut self, i: usize) -> Option<usize> {
        let s = self.s;
        let endpos = locate_tag_end(s, i + 1);
        if s[endpos - 1] != b'>' {
            return None;
        }
        let (name_end, mut k) = tagfind(s, i + 1).expect("letter after <");
        let tag = self.raw[i + 1..name_end].to_lowercase();
        let mut attrs: Vec<(String, Option<String>)> = Vec::new();
        while k < endpos {
            if !attribute_starts(s, k) {
                break;
            }
            let name_end = attribute_name_end(s, k);
            let name = self.raw[k..name_end].to_lowercase();
            let mut q = name_end;
            let mut value = None;
            if let Some((start, end)) = value_indicator(s, q) {
                let mut text = &self.raw[start..end];
                if text.len() >= 2
                    && ((text.starts_with('\'') && text.ends_with('\''))
                        || (text.starts_with('"') && text.ends_with('"')))
                {
                    text = &text[1..text.len() - 1];
                }
                value = Some(if text.is_empty() {
                    String::new()
                } else {
                    unescape_attribute(text)
                });
                q = end;
            }
            attrs.push((name, value));
            k = skip_ws_or_lone_slash(s, q);
        }
        let end = py_strip(&self.raw[k..endpos]);
        if end != ">" && end != "/>" {
            self.handler.data(&self.raw[i..endpos]);
            return Some(endpos);
        }
        self.handler.start_tag(&tag, &attrs);
        if !end.ends_with("/>") {
            if CDATA_CONTENT_ELEMENTS.contains(&tag.as_str()) || tag == "plaintext" {
                self.cdata_elem = Some(tag);
                self.escapable = false;
            } else if RCDATA_CONTENT_ELEMENTS.contains(&tag.as_str()) {
                self.cdata_elem = Some(tag);
                self.escapable = true;
            }
        }
        Some(endpos)
    }

    fn parse_endtag(&mut self, i: usize) -> Option<usize> {
        let s = self.s;
        find_byte(s, i + 2, b'>')?;
        if !s.get(i + 2).is_some_and(u8::is_ascii_alphabetic) {
            if s.get(i + 2) == Some(&b'>') {
                return Some(i + 3);
            }
            return self.parse_bogus_comment(i);
        }
        let j = locate_tag_end(s, i + 2);
        if s[j - 1] != b'>' {
            return None;
        }
        let (name_end, _) = tagfind(s, i + 2).expect("letter after </");
        let tag = self.raw[i + 2..name_end].to_lowercase();
        self.handler.end_tag(&tag);
        self.cdata_elem = None;
        self.escapable = true;
        Some(j)
    }

    fn parse_comment(&mut self, i: usize) -> Option<usize> {
        let s = self.s;
        // commentclose = --!?>
        let mut from = i + 4;
        while let Some(position) = find_from(s, from, b"--") {
            if s.get(position + 2) == Some(&b'>') {
                return Some(position + 3);
            }
            if s.get(position + 2) == Some(&b'!') && s.get(position + 3) == Some(&b'>') {
                return Some(position + 4);
            }
            from = position + 1;
        }
        // commentabruptclose = -?> matched right after <!--
        match (s.get(i + 4), s.get(i + 5)) {
            (Some(b'>'), _) => Some(i + 5),
            (Some(b'-'), Some(b'>')) => Some(i + 6),
            _ => None,
        }
    }

    fn parse_html_declaration(&mut self, i: usize) -> Option<usize> {
        let s = self.s;
        if s[i..].starts_with(b"<![CDATA[") {
            return find_from(s, i + 9, b"]]>").map(|end| end + 3);
        }
        if s.len() >= i + 9 && s[i..i + 9].eq_ignore_ascii_case(b"<!doctype") {
            return find_byte(s, i + 9, b'>').map(|end| end + 1);
        }
        self.parse_bogus_comment(i)
    }

    fn parse_bogus_comment(&mut self, i: usize) -> Option<usize> {
        find_byte(self.s, i + 2, b'>').map(|end| end + 1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct Recorder {
        events: Vec<String>,
    }

    impl Handler for Recorder {
        fn start_tag(&mut self, tag: &str, attrs: &[(String, Option<String>)]) {
            let attrs: Vec<String> = attrs
                .iter()
                .map(|(name, value)| match value {
                    Some(value) => format!("{name}={value:?}"),
                    None => name.clone(),
                })
                .collect();
            self.events.push(format!("<{tag} {}>", attrs.join(" ")));
        }
        fn end_tag(&mut self, tag: &str) {
            self.events.push(format!("</{tag}>"));
        }
        fn data(&mut self, data: &str) {
            self.events.push(format!("data:{data:?}"));
        }
    }

    fn events(html: &str) -> Vec<String> {
        let mut recorder = Recorder::default();
        feed(html, &mut recorder);
        recorder.events
    }

    #[test]
    fn tags_attributes_and_text() {
        assert_eq!(
            events("<IMG SRC='a&amp;b' alt=x data-x checked/>t&lt;</IMG>"),
            vec![
                r#"<img src="a&b" alt="x" data-x checked>"#.to_string(),
                r#"data:"t<""#.to_string(),
                "</img>".to_string(),
            ]
        );
        // Unterminated quote after "= " backtracks to an empty bare value.
        assert_eq!(events("<a b= 'c>"), vec![r#"<a b="" 'c>"#.to_string()]);
        // Unterminated quote right after "=" leaves the tag incomplete.
        assert_eq!(events("<a b='c>text"), Vec::<String>::new());
        assert_eq!(events("<br/>"), vec!["<br >".to_string()]);
    }

    #[test]
    fn style_content_comments_and_incomplete_input() {
        assert_eq!(
            events("<style>a{b:url(&amp;)}<img src=x></style><p>"),
            vec![
                "<style >".to_string(),
                r#"data:"a{b:url(&amp;)}<img src=x>""#.to_string(),
                "</style>".to_string(),
                "<p >".to_string(),
            ]
        );
        assert_eq!(events("<!-- <img src=x> -->"), Vec::<String>::new());
        assert_eq!(
            events("<!--><img src=y>"),
            vec!["<img src=\"y\">".to_string()]
        );
        assert_eq!(events("<style>never closed"), vec!["<style >".to_string()]);
        assert_eq!(
            events("<title><img src=z></title>")[1],
            r#"data:"<img src=z>""#
        );
        assert_eq!(events("x &amp"), Vec::<String>::new());
        assert_eq!(
            events("<! bogus <img> ><b>"),
            vec![r#"data:" >""#.to_string(), "<b >".to_string()]
        );
        assert_eq!(
            events("< b"),
            vec![r#"data:"<""#.to_string(), r#"data:" b""#.to_string()]
        );
    }

    #[test]
    fn rawtext_elements_and_plaintext() {
        for element in ["xmp", "iframe", "noembed", "noframes"] {
            assert_eq!(
                events(&format!("<{element}><img src=x>&amp;</{element}><b>")),
                vec![
                    format!("<{element} >"),
                    r#"data:"<img src=x>&amp;""#.to_string(),
                    format!("</{element}>"),
                    "<b >".to_string(),
                ],
                "{element}"
            );
        }
        // plaintext runs to the end of the input, even without close().
        assert_eq!(
            events("<plaintext><img src=x></plaintext>&amp;"),
            vec![
                "<plaintext >".to_string(),
                r#"data:"<img src=x></plaintext>&amp;""#.to_string(),
            ]
        );
        // scripting=False: noscript content is parsed normally.
        assert_eq!(
            events("<noscript><img src=y></noscript>"),
            vec![
                "<noscript >".to_string(),
                r#"<img src="y">"#.to_string(),
                "</noscript>".to_string(),
            ]
        );
    }
}
