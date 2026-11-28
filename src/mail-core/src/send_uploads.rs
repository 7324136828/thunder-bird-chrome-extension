//! Multipart send upload parsing/validation (port of `app/mail/send_uploads.py`).
//!
//! # Fixed public contract (Phase 2)
//! [`MessageFile`] is shared with `smtp` and `signatures`.
//!
//! The synchronous, transport-independent parts of the Python module live
//! here: [`normalize_filename`], [`normalize_content_type`], the
//! `_CidSources` HTML scan ([`cid_sources`]) and [`validate_files`]. The
//! multipart request parsing (`parse_send_uploads`) is async and lives in the
//! backend route (`mail-backend/src/routes/send.rs`); the request size
//! middleware is `mail_backend::limits::RequestSizeLimitLayer`.
//!
//! Python raised `ValueError(message)`; these functions return
//! `Err(message)` with the identical text.

use std::collections::BTreeSet;
use std::sync::LazyLock;

use regex::Regex;
use unicode_normalization::UnicodeNormalization;

use crate::schemas::{
    header_safe, CONTENT_ID_PATTERN, MAX_SEND_FILES, MAX_SEND_FILES_BYTES, MAX_SEND_FILE_BYTES,
};

/// `MAX_MESSAGE_JSON_BYTES`: the JSON send body / multipart `message` part.
pub const MAX_MESSAGE_JSON_BYTES: usize = 8 * 1024 * 1024;
/// `MAX_SEND_REQUEST_BYTES`: the whole multipart send request.
pub const MAX_SEND_REQUEST_BYTES: usize = 30 * 1024 * 1024;

/// `_MIME_TYPE` (full match).
static MIME_TYPE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^[A-Za-z0-9!#$&^_.+-]+/[A-Za-z0-9!#$&^_.+-]+$").expect("valid regex")
});
static CONTENT_ID_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(&format!("^(?:{CONTENT_ID_PATTERN})$")).expect("valid regex"));
/// `re.findall(r"(?i)\bcid:([^\s\"'<>)]*)", style)`.
static STYLE_CID_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?i)\bcid:([^\s"'<>)]*)"#).expect("valid regex"));

/// One uploaded file (`MessageFile` dataclass).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageFile {
    pub filename: String,
    pub content_type: String,
    pub data: Vec<u8>,
    /// Empty for ordinary attachments.
    pub content_id: String,
    /// `"attachment"` (default) or `"inline"`.
    pub disposition: String,
}

impl MessageFile {
    /// Attachment with the dataclass defaults (`content_id=""`, `disposition="attachment"`).
    pub fn attachment(
        filename: impl Into<String>,
        content_type: impl Into<String>,
        data: Vec<u8>,
    ) -> Self {
        Self {
            filename: filename.into(),
            content_type: content_type.into(),
            data,
            content_id: String::new(),
            disposition: "attachment".into(),
        }
    }

    /// Inline image (`MessageFile(filename, content_type, data, content_id, "inline")`).
    pub fn inline(
        filename: impl Into<String>,
        content_type: impl Into<String>,
        data: Vec<u8>,
        content_id: impl Into<String>,
    ) -> Self {
        Self {
            filename: filename.into(),
            content_type: content_type.into(),
            data,
            content_id: content_id.into(),
            disposition: "inline".into(),
        }
    }
}

/// Python `str.strip()` (Unicode whitespace).
fn py_strip(value: &str) -> &str {
    value.trim_matches(|c: char| c.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&c))
}

/// Python `normalize_filename(value)`. An empty value means `None`
/// (`value or "attachment"`).
pub fn normalize_filename(value: &str) -> Result<String, String> {
    if !value.is_empty() && !header_safe(value) {
        return Err("Attachment filenames cannot contain control characters".into());
    }
    let source = if value.is_empty() {
        "attachment"
    } else {
        value
    };
    let normalized: String = source.nfc().collect::<String>().replace('\\', "/");
    let last = normalized.rsplit('/').next().unwrap_or_default();
    let mut name = py_strip(last).to_string();
    if name.is_empty() || name == "." || name == ".." {
        name = "attachment".into();
    }
    if name.chars().count() > 255 {
        return Err("Attachment filenames must be no longer than 255 characters".into());
    }
    Ok(name)
}

/// Python `normalize_content_type(value)`. An empty value means `None`.
pub fn normalize_content_type(value: &str) -> Result<String, String> {
    if !value.is_empty() && !header_safe(value) {
        return Err("Attachment content types cannot contain control characters".into());
    }
    let source = if value.is_empty() {
        "application/octet-stream"
    } else {
        value
    };
    let essence = source.split(';').next().unwrap_or_default();
    let content_type = py_strip(essence).to_lowercase();
    if !MIME_TYPE_RE.is_match(&content_type) {
        return Err("The attachment content type is invalid".into());
    }
    Ok(content_type)
}

// ---------------------------------------------------------------------------
// _CidSources: a port of the parts of html.parser.HTMLParser it relies on
// ---------------------------------------------------------------------------

/// Elements whose content `HTMLParser` treats as raw text.
const CDATA_CONTENT_ELEMENTS: [&str; 2] = ["script", "style"];

fn is_html_space(byte: u8) -> bool {
    // Python's `\s` for the ASCII range.
    matches!(byte, b' ' | b'\t' | b'\n' | b'\r' | b'\x0b' | b'\x0c')
}

/// Result of scanning one start tag.
enum StartTag {
    /// The input ended inside the tag (`HTMLParser.feed` keeps it buffered
    /// and, without `close()`, never processes it).
    Incomplete,
    /// A complete tag: its lowercased name, attributes, end offset and
    /// whether attributes are reported (`end in (">", "/>")`).
    Complete {
        name: String,
        attrs: Vec<(String, Option<String>)>,
        end: usize,
        reported: bool,
    },
}

/// `parse_starttag` + `check_for_whole_start_tag` for the tag starting at
/// `start` (`<` followed by an ASCII letter).
fn scan_start_tag(html: &str, start: usize) -> StartTag {
    let bytes = html.as_bytes();
    let n = bytes.len();
    // Tag name: [a-zA-Z][^\t\n\r\f />\x00]*
    let mut k = start + 1;
    while k < n
        && !matches!(
            bytes[k],
            b'\t' | b'\n' | b'\r' | b'\x0c' | b' ' | b'/' | b'>' | 0
        )
    {
        k += 1;
    }
    let name = html[start + 1..k].to_ascii_lowercase();
    let mut attrs = Vec::new();
    // (?:\s|/(?!>))*
    let skip_separators = |mut k: usize| {
        while k < n
            && (is_html_space(bytes[k]) || (bytes[k] == b'/' && bytes.get(k + 1) != Some(&b'>')))
        {
            k += 1;
        }
        k
    };
    k = skip_separators(k);
    loop {
        if k >= n {
            return StartTag::Incomplete;
        }
        match bytes[k] {
            b'>' => {
                return StartTag::Complete {
                    name,
                    attrs,
                    end: k + 1,
                    reported: true,
                }
            }
            b'/' if bytes.get(k + 1) == Some(&b'>') => {
                return StartTag::Complete {
                    name,
                    attrs,
                    end: k + 2,
                    reported: true,
                }
            }
            _ => {}
        }
        // Attribute name: [^\s/>][^\s/=>]*
        let name_start = k;
        k += 1;
        while k < n && !is_html_space(bytes[k]) && !matches!(bytes[k], b'/' | b'=' | b'>') {
            k += 1;
        }
        let attr_name = html[name_start..k].to_lowercase();
        // Optional value: \s*=+\s*('[^']*'|"[^"]*"|(?!['"])[^>\s]*)
        let mut probe = k;
        while probe < n && is_html_space(bytes[probe]) {
            probe += 1;
        }
        let mut value = None;
        if probe < n && bytes[probe] == b'=' {
            while probe < n && bytes[probe] == b'=' {
                probe += 1;
            }
            while probe < n && is_html_space(bytes[probe]) {
                probe += 1;
            }
            if probe >= n {
                return StartTag::Incomplete;
            }
            match bytes[probe] {
                quote @ (b'\'' | b'"') => match html[probe + 1..].find(quote as char) {
                    Some(offset) => {
                        let close = probe + 1 + offset;
                        value = Some(html[probe + 1..close].to_string());
                        k = close + 1;
                    }
                    // An unterminated quoted value: the tag never ends.
                    None => return StartTag::Incomplete,
                },
                _ => {
                    let value_start = probe;
                    while probe < n && !is_html_space(bytes[probe]) && bytes[probe] != b'>' {
                        probe += 1;
                    }
                    value = Some(html[value_start..probe].to_string());
                    k = probe;
                }
            }
        }
        let value = value.map(|text| {
            if text.is_empty() {
                text
            } else {
                html_escape::decode_html_entities(&text).into_owned()
            }
        });
        attrs.push((attr_name, value));
        k = skip_separators(k);
    }
}

/// Offset just past the first occurrence of `needle` at or after `from`.
fn find_after(html: &str, from: usize, needle: &str) -> Option<usize> {
    html.get(from..)?
        .find(needle)
        .map(|offset| from + offset + needle.len())
}

/// Offset of the closing tag of a raw-text element (`</script` followed by
/// whitespace, `/` or `>`), searched case-insensitively.
fn find_cdata_end(html: &str, from: usize, element: &str) -> Option<usize> {
    let lower = html.to_ascii_lowercase();
    let needle = format!("</{element}");
    let mut search = from;
    while let Some(offset) = lower.get(search..)?.find(&needle) {
        let position = search + offset;
        match lower.as_bytes().get(position + needle.len()) {
            Some(b) if is_html_space(*b) || *b == b'/' || *b == b'>' => return Some(position),
            _ => search = position + needle.len(),
        }
    }
    None
}

fn record_cid_sources(attrs: &[(String, Option<String>)], content_ids: &mut BTreeSet<String>) {
    for (name, value) in attrs {
        let Some(value) = value.as_deref().filter(|value| !value.is_empty()) else {
            continue;
        };
        if matches!(
            name.as_str(),
            "src" | "href" | "background" | "poster" | "data"
        ) {
            let source = py_strip(value);
            if source
                .get(..4)
                .is_some_and(|prefix| prefix.eq_ignore_ascii_case("cid:"))
            {
                content_ids.insert(source[4..].to_string());
            }
        } else if name == "style" {
            for capture in STYLE_CID_RE.captures_iter(value) {
                content_ids.insert(capture[1].to_string());
            }
        }
    }
}

/// `_CidSources().feed(html).content_ids`: every `cid:` reference in a
/// `src`/`href`/`background`/`poster`/`data` attribute or a `style`
/// attribute of a start tag. Like `feed()` without `close()`, a trailing
/// incomplete construct is ignored.
pub fn cid_sources(html: &str) -> BTreeSet<String> {
    let bytes = html.as_bytes();
    let n = bytes.len();
    let mut content_ids = BTreeSet::new();
    let mut i = 0;
    let mut cdata_elem: Option<&'static str> = None;
    while i < n {
        let next = match cdata_elem {
            Some(element) => match find_cdata_end(html, i, element) {
                Some(position) => position,
                None => break,
            },
            None => match html[i..].find('<') {
                Some(offset) => i + offset,
                None => break,
            },
        };
        i = next;
        let rest = &bytes[i..];
        if rest.len() >= 2 && rest[1].is_ascii_alphabetic() {
            match scan_start_tag(html, i) {
                StartTag::Incomplete => break,
                StartTag::Complete {
                    name,
                    attrs,
                    end,
                    reported,
                } => {
                    if reported {
                        record_cid_sources(&attrs, &mut content_ids);
                        let self_closing = html[..end].ends_with("/>");
                        if !self_closing {
                            cdata_elem = CDATA_CONTENT_ELEMENTS
                                .iter()
                                .copied()
                                .find(|element| *element == name);
                        }
                    }
                    i = end;
                }
            }
        } else if rest.starts_with(b"</") {
            match find_after(html, i + 2, ">") {
                Some(end) => {
                    cdata_elem = None;
                    i = end;
                }
                None => break,
            }
        } else if rest.starts_with(b"<!--") {
            match find_after(html, i + 4, "-->") {
                Some(end) => i = end,
                None => break,
            }
        } else if rest.starts_with(b"<?") || rest.starts_with(b"<!") {
            match find_after(html, i + 2, ">") {
                Some(end) => i = end,
                None => break,
            }
        } else if i + 1 < n {
            i += 1;
        } else {
            break;
        }
    }
    content_ids
}

// ---------------------------------------------------------------------------
// Inline image sniffing (remote_images._image_type)
// ---------------------------------------------------------------------------

/// `remote_images.MAX_IMAGE_PIXELS`.
const MAX_IMAGE_PIXELS: i128 = 25_000_000;

fn dimensions_ok(width: i128, height: i128) -> bool {
    width > 0 && height > 0 && width * height <= MAX_IMAGE_PIXELS
}

fn be_u32(data: &[u8], offset: usize) -> Option<u32> {
    data.get(offset..offset + 4)
        .map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
}

fn le_u32(data: &[u8], offset: usize) -> Option<u32> {
    data.get(offset..offset + 4)
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

fn le_i32(data: &[u8], offset: usize) -> Option<i32> {
    data.get(offset..offset + 4)
        .map(|b| i32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

fn be_u16(data: &[u8], offset: usize) -> Option<u16> {
    data.get(offset..offset + 2)
        .map(|b| u16::from_be_bytes([b[0], b[1]]))
}

fn le_u16(data: &[u8], offset: usize) -> Option<u16> {
    data.get(offset..offset + 2)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
}

fn png_type(content: &[u8]) -> Option<&'static str> {
    let mut offset = 8;
    let (mut saw_header, mut saw_data, mut saw_end) = (false, false, false);
    while offset + 12 <= content.len() {
        let length = be_u32(content, offset)? as usize;
        let end = offset + 12 + length;
        if end > content.len() {
            break;
        }
        let kind = &content[offset + 4..offset + 8];
        let data = &content[offset + 8..offset + 8 + length];
        let crc = be_u32(content, offset + 8 + length)?;
        let mut hasher = crc32fast::Hasher::new();
        hasher.update(kind);
        hasher.update(data);
        if hasher.finalize() != crc {
            break;
        }
        if !saw_header {
            if kind != b"IHDR" || length != 13 {
                break;
            }
            let width = i128::from(be_u32(data, 0)?);
            let height = i128::from(be_u32(data, 4)?);
            if !dimensions_ok(width, height) {
                return None;
            }
            saw_header = true;
        } else if kind == b"IHDR" {
            break;
        }
        if kind == b"IDAT" {
            saw_data = true;
        }
        if kind == b"IEND" {
            saw_end = length == 0 && end == content.len();
            break;
        }
        offset = end;
    }
    (saw_header && saw_data && saw_end).then_some("image/png")
}

fn jpeg_type(content: &[u8]) -> Option<&'static str> {
    const SOF: [u8; 13] = [
        0xC0, 0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7, 0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xCF,
    ];
    let len = content.len();
    let mut offset = 2;
    while offset + 4 <= len {
        if content[offset] != 0xFF {
            break;
        }
        while offset < len && content[offset] == 0xFF {
            offset += 1;
        }
        if offset + 3 > len {
            break;
        }
        let marker = content[offset];
        offset += 1;
        if marker == 0x01 || (0xD0..0xDA).contains(&marker) {
            continue;
        }
        let length = usize::from(be_u16(content, offset)?);
        if length < 2 || offset + length > len {
            break;
        }
        if SOF.contains(&marker) {
            if length >= 8 {
                let height = i128::from(be_u16(content, offset + 3)?);
                let width = i128::from(be_u16(content, offset + 5)?);
                return dimensions_ok(width, height).then_some("image/jpeg");
            }
            break;
        }
        if marker == 0xDA {
            break;
        }
        offset += length;
    }
    None
}

fn webp_type(content: &[u8]) -> Option<&'static str> {
    if le_u32(content, 4)? as usize + 8 != content.len() {
        return None;
    }
    let kind = &content[12..16];
    let chunk_length = le_u32(content, 16)? as usize;
    if chunk_length + 20 > content.len() {
        return None;
    }
    let little = |bytes: &[u8]| {
        bytes
            .iter()
            .rev()
            .fold(0i128, |acc, b| (acc << 8) | i128::from(*b))
    };
    let (width, height) = if kind == b"VP8X" && chunk_length == 10 {
        (little(&content[24..27]) + 1, little(&content[27..30]) + 1)
    } else if kind == b"VP8 " && &content[23..26] == b"\x9d\x01\x2a" {
        (
            i128::from(le_u16(content, 26)? & 0x3FFF),
            i128::from(le_u16(content, 28)? & 0x3FFF),
        )
    } else if kind == b"VP8L" && content[20] == 0x2F {
        let packed = le_u32(content, 21)?;
        (
            i128::from(packed & 0x3FFF) + 1,
            i128::from((packed >> 14) & 0x3FFF) + 1,
        )
    } else {
        return None;
    };
    dimensions_ok(width, height).then_some("image/webp")
}

fn bmp_type(content: &[u8]) -> Option<&'static str> {
    let file_size = le_u32(content, 2)? as usize;
    let pixel_offset = le_u32(content, 10)? as usize;
    let dib_size = le_u32(content, 14)? as usize;
    if file_size == content.len()
        && dib_size >= 40
        && 14 + dib_size <= pixel_offset
        && pixel_offset < content.len()
    {
        let width = i128::from(le_i32(content, 18)?);
        let height = i128::from(le_i32(content, 22)?).abs();
        return dimensions_ok(width, height).then_some("image/bmp");
    }
    None
}

/// `remote_images._image_type`: the sniffed raster type, or `None` where
/// Python raised `ImageDownloadError` (unsupported, malformed or with
/// forbidden dimensions). SVG and HTML are never images.
pub fn image_type(content: &[u8]) -> Option<&'static str> {
    if content.starts_with(b"\x89PNG\r\n\x1a\n") {
        png_type(content)
    } else if content.starts_with(b"GIF87a") || content.starts_with(b"GIF89a") {
        if content.len() >= 14 && content.ends_with(b";") {
            let width = i128::from(le_u16(content, 6)?);
            let height = i128::from(le_u16(content, 8)?);
            return dimensions_ok(width, height).then_some("image/gif");
        }
        None
    } else if content.starts_with(b"\xff\xd8") && content.ends_with(b"\xff\xd9") {
        jpeg_type(content)
    } else if content.len() >= 30 && &content[..4] == b"RIFF" && &content[8..12] == b"WEBP" {
        webp_type(content)
    } else if content.len() >= 54 && &content[..2] == b"BM" {
        bmp_type(content)
    } else {
        None
    }
}

fn image_alias(content_type: &str) -> &str {
    match content_type {
        "image/jpg" | "image/pjpeg" => "image/jpeg",
        "image/x-png" => "image/png",
        "image/x-ms-bmp" => "image/bmp",
        other => other,
    }
}

/// Python `validate_files(html, files)`: enforce the count and size limits,
/// normalize names and types, sniff inline images and require every inline
/// image to be referenced by exactly the `cid:` sources of `html`.
pub fn validate_files(html: &str, files: &[MessageFile]) -> Result<Vec<MessageFile>, String> {
    if files.len() > MAX_SEND_FILES {
        return Err("Attach no more than 20 files".into());
    }
    let mut total = 0usize;
    let mut normalized = Vec::with_capacity(files.len());
    let mut inline_ids = BTreeSet::new();
    for file in files {
        total += file.data.len();
        if file.data.len() > MAX_SEND_FILE_BYTES {
            return Err("Each attachment must be no larger than 10 MiB".into());
        }
        if total > MAX_SEND_FILES_BYTES {
            return Err("Attachments must total no more than 20 MiB".into());
        }
        let filename = normalize_filename(&file.filename)?;
        let mut content_type = normalize_content_type(&file.content_type)?;
        if file.disposition == "inline" {
            if !CONTENT_ID_RE.is_match(&file.content_id) || inline_ids.contains(&file.content_id) {
                return Err("Inline image content IDs must be valid and unique".into());
            }
            inline_ids.insert(file.content_id.clone());
            let Some(detected) = image_type(&file.data) else {
                return Err(
                    "Inline images must be valid PNG, JPEG, GIF, WebP, or BMP images".into(),
                );
            };
            if content_type != "application/octet-stream" && image_alias(&content_type) != detected
            {
                return Err("The inline image content type does not match its bytes".into());
            }
            content_type = detected.to_string();
        } else if file.disposition != "attachment" || !file.content_id.is_empty() {
            return Err("Attachment metadata is invalid".into());
        }
        normalized.push(MessageFile {
            filename,
            content_type,
            data: file.data.clone(),
            content_id: file.content_id.clone(),
            disposition: file.disposition.clone(),
        });
    }
    if cid_sources(html) != inline_ids {
        return Err(
            "Every inline image must have a matching cid reference in the HTML message".into(),
        );
    }
    Ok(normalized)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filenames_are_normalized_like_python() {
        assert_eq!(normalize_filename("").unwrap(), "attachment");
        assert_eq!(
            normalize_filename("C:\\private\\folder\\r\u{e9}sum\u{e9}.pdf").unwrap(),
            "r\u{e9}sum\u{e9}.pdf"
        );
        assert_eq!(
            normalize_filename("re\u{301}sume\u{301}.pdf").unwrap(),
            "r\u{e9}sum\u{e9}.pdf"
        );
        assert_eq!(normalize_filename("dir/..").unwrap(), "attachment");
        assert_eq!(normalize_filename("dir/  ").unwrap(), "attachment");
        assert_eq!(normalize_filename(" a.txt ").unwrap(), "a.txt");
        assert!(normalize_filename("unsafe\r\nfile.txt").is_err());
        assert!(normalize_filename(&"a".repeat(256)).is_err());
        assert_eq!(normalize_filename(&"a".repeat(255)).unwrap().len(), 255);
    }

    #[test]
    fn content_types_are_normalized_like_python() {
        assert_eq!(
            normalize_content_type("").unwrap(),
            "application/octet-stream"
        );
        assert_eq!(
            normalize_content_type(" Text/Plain; charset=utf-8").unwrap(),
            "text/plain"
        );
        assert_eq!(
            normalize_content_type("text/plain\r\nX: y").unwrap_err(),
            "Attachment content types cannot contain control characters"
        );
        assert_eq!(
            normalize_content_type("text").unwrap_err(),
            "The attachment content type is invalid"
        );
    }

    #[test]
    fn cid_sources_follow_html_parser_rules() {
        let ids = |html: &str| cid_sources(html).into_iter().collect::<Vec<_>>();
        assert_eq!(
            ids(r#"<p>Hi<img src="cid:photo@draft"></p>"#),
            ["photo@draft"]
        );
        assert_eq!(ids(r#"<img SRC=' CID:Upper '>"#), ["Upper"]);
        assert_eq!(ids(r#"<img src=cid:bare/>"#), ["bare/"]);
        assert_eq!(
            ids(r#"<img src="cid:a" /><a href="cid:b">x</a>"#),
            ["a", "b"]
        );
        assert_eq!(
            ids(r#"<div style="background:url(cid:bg) ; x: url('CID:two')">"#),
            ["bg", "two"]
        );
        assert_eq!(ids(r#"<img src="cid:a&amp;b">"#), ["a&b"]);
        assert!(ids(r#"<!-- <img src="cid:hidden"> -->"#).is_empty());
        assert!(ids(r#"<script><img src="cid:script"></script>"#).is_empty());
        assert_eq!(ids(r#"<script>x</script><img src="cid:after">"#), ["after"]);
        // A trailing incomplete tag is never processed (feed without close).
        assert!(ids(r#"<img src="cid:unterminated""#).is_empty());
        assert!(ids(r#"<img src="cid:x"#).is_empty());
        assert!(ids("<p>No image reference</p>").is_empty());
        assert!(ids(r#"<img src="">"#).is_empty());
    }

    #[test]
    fn image_sniffing_matches_python() {
        assert_eq!(image_type(b"<svg/>"), None);
        assert_eq!(
            image_type(b"GIF89a\x01\x00\x01\x00\x00\x00\x00;"),
            Some("image/gif")
        );
        assert_eq!(image_type(b"GIF89a\x00\x00\x01\x00\x00\x00\x00;"), None);
        let jpeg = b"\xff\xd8\xff\xc0\x00\x0b\x08\x00\x02\x00\x03\x01\x01\x11\x00\xff\xd9";
        assert_eq!(image_type(jpeg), Some("image/jpeg"));
    }
}
