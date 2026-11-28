//! The slice of Python's `http.client` (plus the `email.feedparser` header
//! parsing it delegates to) that the image downloader uses, over one pinned
//! connection: request serialization like `HTTPConnection.putrequest`, the
//! status line / header / body framing rules of `HTTPResponse.begin`,
//! `read1` (fixed length, chunked, or until EOF) and `getheader`.
//!
//! Every limit matches http.client: 65536-byte lines, at most 100 header
//! lines, `100 Continue` responses skipped.

use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpStream};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use crate::image_sources::urllib::py_isspace;

/// `http.client._MAXLINE`.
const MAX_LINE: usize = 65536;
/// `http.client._MAXHEADERS`.
const MAX_HEADERS: usize = 100;

/// An `http.client.HTTPException` (or `ValueError`) â€” the caller maps it to
/// "The image download failed." just like an `OSError`.
#[derive(Debug)]
pub(crate) struct ProtocolError;

impl From<io::Error> for ProtocolError {
    fn from(_: io::Error) -> Self {
        ProtocolError
    }
}

/// Plain TCP or TLS over the pinned socket.
pub(crate) enum Stream {
    Plain(TcpStream),
    Tls(Box<native_tls::TlsStream<TcpStream>>),
}

impl Read for Stream {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        match self {
            Stream::Plain(stream) => stream.read(buffer),
            Stream::Tls(stream) => stream.read(buffer),
        }
    }
}

impl Write for Stream {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        match self {
            Stream::Plain(stream) => stream.write(buffer),
            Stream::Tls(stream) => stream.write(buffer),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Stream::Plain(stream) => stream.flush(),
            Stream::Tls(stream) => stream.flush(),
        }
    }
}

/// One single-use connection with a read buffer (`HTTPResponse.fp`).
pub(crate) struct Connection {
    stream: Stream,
    /// A handle to the same socket, for timeouts and the deadline shutdown.
    socket: TcpStream,
    buffer: Vec<u8>,
    position: usize,
    deadline: Instant,
    closed: bool,
}

impl Connection {
    pub(crate) fn new(stream: Stream, socket: TcpStream, deadline: Instant) -> Self {
        Self {
            stream,
            socket,
            buffer: Vec::new(),
            position: 0,
            deadline,
            closed: false,
        }
    }

    pub(crate) fn socket(&self) -> &TcpStream {
        &self.socket
    }

    pub(crate) fn set_timeout(&self, timeout: Duration) -> io::Result<()> {
        let timeout = timeout.max(Duration::from_millis(1));
        self.socket.set_read_timeout(Some(timeout))?;
        self.socket.set_write_timeout(Some(timeout))
    }

    pub(crate) fn send(&mut self, request: &[u8]) -> io::Result<()> {
        self.stream.write_all(request)?;
        self.stream.flush()
    }

    fn buffered(&self) -> &[u8] {
        &self.buffer[self.position..]
    }

    /// One raw read into the buffer; `Ok(false)` at EOF.
    fn fill(&mut self) -> io::Result<bool> {
        if self.closed {
            return Ok(false);
        }
        // The deadline watchdog shuts the socket down; reads after the
        // deadline behave like reads from that closed transport.
        if Instant::now() >= self.deadline {
            return Err(io::Error::new(io::ErrorKind::TimedOut, "deadline"));
        }
        if self.position == self.buffer.len() {
            self.buffer.clear();
            self.position = 0;
        }
        let mut chunk = [0u8; 16384];
        let count = self.stream.read(&mut chunk)?;
        if count == 0 {
            return Ok(false);
        }
        self.buffer.extend_from_slice(&chunk[..count]);
        Ok(true)
    }

    /// `fp.readline(limit)`: up to and including `\n`, at most `limit`
    /// bytes, shorter at EOF.
    fn readline(&mut self, limit: usize) -> io::Result<Vec<u8>> {
        let mut line = Vec::new();
        loop {
            let available = self.buffered();
            let wanted = limit - line.len();
            if let Some(newline) = available.iter().take(wanted).position(|b| *b == b'\n') {
                line.extend_from_slice(&available[..=newline]);
                self.position += newline + 1;
                return Ok(line);
            }
            let take = available.len().min(wanted);
            line.extend_from_slice(&available[..take]);
            self.position += take;
            if line.len() >= limit || !self.fill()? {
                return Ok(line);
            }
        }
    }

    /// `fp.read1(n)`: buffered bytes, or one raw read, at most `n` bytes.
    fn read1(&mut self, n: usize) -> io::Result<Vec<u8>> {
        if n == 0 {
            return Ok(Vec::new());
        }
        if self.buffered().is_empty() && !self.fill()? {
            return Ok(Vec::new());
        }
        let take = self.buffered().len().min(n);
        let data = self.buffered()[..take].to_vec();
        self.position += take;
        Ok(data)
    }

    /// `fp.read(n)`: exactly `n` bytes unless EOF comes first.
    fn read_exact_or_eof(&mut self, n: usize) -> io::Result<Vec<u8>> {
        let mut data = Vec::new();
        while data.len() < n {
            let chunk = self.read1(n - data.len())?;
            if chunk.is_empty() {
                break;
            }
            data.extend_from_slice(&chunk);
        }
        Ok(data)
    }
}

/// Interrupts even a blocking read at the total deadline (Python's
/// `threading.Timer` calling `transport.shutdown(SHUT_RDWR)`).
pub(crate) struct Watchdog {
    cancel: Option<mpsc::Sender<()>>,
}

impl Watchdog {
    pub(crate) fn start(socket: &TcpStream, after: Duration) -> Self {
        let Ok(socket) = socket.try_clone() else {
            return Self { cancel: None };
        };
        let (cancel, cancelled) = mpsc::channel::<()>();
        let spawned = std::thread::Builder::new()
            .name("email-image-deadline".into())
            .spawn(move || {
                if let Err(mpsc::RecvTimeoutError::Timeout) = cancelled.recv_timeout(after) {
                    let _ = socket.shutdown(Shutdown::Both);
                }
            });
        Self {
            cancel: spawned.ok().map(|_| cancel),
        }
    }
}

impl Drop for Watchdog {
    fn drop(&mut self) {
        // Dropping the sender wakes the thread with `Disconnected`.
        self.cancel.take();
    }
}

/// Latin-1 decoding (`str(line, "iso-8859-1")`).
fn latin1(bytes: &[u8]) -> String {
    bytes.iter().map(|b| *b as char).collect()
}

/// Python `int(text, radix)` for the forms http.client can meet: optional
/// surrounding whitespace and sign, an optional `0x` prefix in base 16,
/// single underscores between digits.
pub(crate) fn py_int(text: &str, radix: u32) -> Option<i128> {
    let mut text = text.trim_matches(py_isspace);
    let negative = text.starts_with('-');
    if let Some(rest) = text.strip_prefix(['+', '-']) {
        text = rest;
    }
    if radix == 16 {
        if let Some(rest) = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
            text = rest.strip_prefix('_').unwrap_or(rest);
        }
    }
    if text.is_empty() || text.starts_with('_') || text.ends_with('_') || text.contains("__") {
        return None;
    }
    let mut value: i128 = 0;
    for character in text.chars() {
        if character == '_' {
            continue;
        }
        let digit = character.to_digit(radix)?;
        value = value
            .saturating_mul(radix as i128)
            .saturating_add(digit as i128);
    }
    Some(if negative { -value } else { value })
}

/// `str.split(None, maxsplit)`.
fn split_whitespace_max(text: &str, maxsplit: usize) -> Vec<String> {
    let mut parts = Vec::new();
    let mut rest = text.trim_start_matches(py_isspace);
    while !rest.is_empty() {
        if parts.len() == maxsplit {
            parts.push(rest.to_string());
            break;
        }
        let end = rest.find(py_isspace).unwrap_or(rest.len());
        parts.push(rest[..end].to_string());
        rest = rest[end..].trim_start_matches(py_isspace);
    }
    parts
}

/// The parsed header block (`HTTPMessage`), in arrival order.
#[derive(Debug, Default)]
pub(crate) struct Headers {
    fields: Vec<(String, String)>,
}

impl Headers {
    /// `Message.get(name)`: the first value.
    pub(crate) fn get(&self, name: &str) -> Option<&str> {
        self.fields
            .iter()
            .find(|(field, _)| field.to_lowercase() == name.to_lowercase())
            .map(|(_, value)| value.as_str())
    }

    /// `HTTPResponse.getheader(name)`: every value joined with `", "`.
    pub(crate) fn getheader(&self, name: &str) -> Option<String> {
        let values: Vec<&str> = self
            .fields
            .iter()
            .filter(|(field, _)| field.to_lowercase() == name.to_lowercase())
            .map(|(_, value)| value.as_str())
            .collect();
        (!values.is_empty()).then(|| values.join(", "))
    }
}

/// `email.feedparser` header-block parsing with the compat32 policy.
fn parse_headers(text: &str) -> Headers {
    // Universal-newline line splitting (NLCRE_crack), keeping the endings.
    let mut lines: Vec<&str> = Vec::new();
    let bytes = text.as_bytes();
    let mut start = 0;
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'\r' => {
                let end = if bytes.get(index + 1) == Some(&b'\n') {
                    index + 2
                } else {
                    index + 1
                };
                lines.push(&text[start..end]);
                start = end;
                index = end;
            }
            b'\n' => {
                lines.push(&text[start..=index]);
                start = index + 1;
                index += 1;
            }
            _ => index += 1,
        }
    }
    if start < text.len() {
        lines.push(&text[start..]);
    }
    // headerRE = ^(From |[\041-\071\073-\176]*:|[\t ])
    let header_like = |line: &str| {
        line.starts_with("From ")
            || line.starts_with(['\t', ' '])
            || line
                .find(':')
                .is_some_and(|colon| line[..colon].chars().all(|c| ('!'..='~').contains(&c)))
    };
    let mut header_lines = Vec::new();
    for line in lines {
        if !header_like(line) {
            break;
        }
        header_lines.push(line);
    }
    let mut headers = Headers::default();
    let mut current: Vec<&str> = Vec::new();
    let flush = |current: &mut Vec<&str>, headers: &mut Headers| {
        if let Some((first, rest)) = current.split_first() {
            let (name, value) = first.split_once(':').expect("header line has a colon");
            let mut value = value.trim_start_matches([' ', '\t']).to_string();
            for line in rest {
                value.push_str(line);
            }
            let value = value.trim_end_matches(['\r', '\n']).to_string();
            headers.fields.push((name.to_string(), value));
        }
        current.clear();
    };
    let count = header_lines.len();
    for (line_number, line) in header_lines.into_iter().enumerate() {
        if line.starts_with([' ', '\t']) {
            if !current.is_empty() {
                current.push(line);
            }
            continue;
        }
        flush(&mut current, &mut headers);
        if line.starts_with("From ") {
            if line_number == 0 || line_number != count - 1 {
                continue;
            }
            break;
        }
        match line.find(':') {
            Some(0) | None => continue,
            Some(_) => current.push(line),
        }
    }
    flush(&mut current, &mut headers);
    headers
}

/// `http.client._read_headers`: raw lines through the blank terminator.
fn read_header_lines(connection: &mut Connection) -> Result<Vec<u8>, ProtocolError> {
    let mut block = Vec::new();
    let mut count = 0;
    loop {
        let line = connection.readline(MAX_LINE + 1)?;
        if line.len() > MAX_LINE {
            return Err(ProtocolError);
        }
        count += 1;
        if count > MAX_HEADERS {
            return Err(ProtocolError);
        }
        let done = matches!(line.as_slice(), b"\r\n" | b"\n" | b"");
        block.extend_from_slice(&line);
        if done {
            return Ok(block);
        }
    }
}

/// `HTTPResponse._read_status`.
fn read_status(connection: &mut Connection) -> Result<(String, u16), ProtocolError> {
    let raw = connection.readline(MAX_LINE + 1)?;
    if raw.len() > MAX_LINE || raw.is_empty() {
        return Err(ProtocolError);
    }
    let line = latin1(&raw);
    let mut parts = split_whitespace_max(&line, 2);
    if parts.len() != 3 {
        parts = split_whitespace_max(&line, 1);
        if parts.len() != 2 {
            parts = vec![String::new()];
        }
    }
    if !parts[0].starts_with("HTTP/") {
        return Err(ProtocolError);
    }
    let status = py_int(&parts[1], 10).ok_or(ProtocolError)?;
    if !(100..=999).contains(&status) {
        return Err(ProtocolError);
    }
    Ok((parts[0].clone(), status as u16))
}

/// An `HTTPResponse` after `begin()`.
pub(crate) struct Response {
    pub status: u16,
    pub headers: Headers,
    chunked: bool,
    chunk_left: Option<i128>,
    length: Option<i128>,
    finished: bool,
}

impl Response {
    /// `HTTPResponse.begin()` for a GET.
    pub(crate) fn begin(connection: &mut Connection) -> Result<Self, ProtocolError> {
        let (version, status) = loop {
            let (version, status) = read_status(connection)?;
            if status != 100 {
                break (version, status);
            }
            read_header_lines(connection)?;
        };
        if !(version == "HTTP/1.0" || version == "HTTP/0.9" || version.starts_with("HTTP/1.")) {
            return Err(ProtocolError);
        }
        let headers = parse_headers(&latin1(&read_header_lines(connection)?));
        let chunked = headers
            .get("transfer-encoding")
            .is_some_and(|value| value.to_lowercase() == "chunked");
        let mut length = None;
        if let Some(value) = headers
            .get("content-length")
            .filter(|value| !value.is_empty())
        {
            if !chunked {
                length = py_int(value, 10).filter(|length| *length >= 0);
            }
        }
        if status == 204 || status == 304 || (100..200).contains(&status) {
            length = Some(0);
        }
        Ok(Self {
            status,
            headers,
            chunked,
            chunk_left: None,
            length,
            finished: false,
        })
    }

    /// `HTTPResponse.read1(n)`.
    pub(crate) fn read1(
        &mut self,
        connection: &mut Connection,
        n: usize,
    ) -> Result<Vec<u8>, ProtocolError> {
        if self.finished {
            return Ok(Vec::new());
        }
        if self.chunked {
            return self.read1_chunked(connection, n);
        }
        let mut n = n as i128;
        if let Some(length) = self.length {
            n = n.min(length);
        }
        let result = connection.read1(n as usize)?;
        if result.is_empty() && n > 0 {
            self.finished = true;
        } else if let Some(length) = self.length.as_mut() {
            *length -= result.len() as i128;
            if *length == 0 {
                self.finished = true;
            }
        }
        Ok(result)
    }

    fn read1_chunked(
        &mut self,
        connection: &mut Connection,
        n: usize,
    ) -> Result<Vec<u8>, ProtocolError> {
        let Some(chunk_left) = self.chunk_left(connection)? else {
            return Ok(Vec::new());
        };
        if n == 0 {
            return Ok(Vec::new());
        }
        let n = (n as i128).min(chunk_left) as usize;
        let read = connection.read1(n)?;
        self.chunk_left = Some(chunk_left - read.len() as i128);
        if read.is_empty() {
            return Err(ProtocolError);
        }
        Ok(read)
    }

    /// `_get_chunk_left`.
    fn chunk_left(&mut self, connection: &mut Connection) -> Result<Option<i128>, ProtocolError> {
        let mut chunk_left = self.chunk_left;
        if chunk_left.unwrap_or(0) == 0 {
            if chunk_left.is_some() {
                // Toss the CRLF at the end of the chunk (`_safe_read(2)`).
                if connection.read_exact_or_eof(2)?.len() < 2 {
                    return Err(ProtocolError);
                }
            }
            let line = connection.readline(MAX_LINE + 1)?;
            if line.len() > MAX_LINE {
                return Err(ProtocolError);
            }
            let line = match line.iter().position(|b| *b == b';') {
                Some(index) => &line[..index],
                None => &line[..],
            };
            let size = py_int(&latin1(line), 16).ok_or(ProtocolError)?;
            if size < 0 {
                return Err(ProtocolError);
            }
            if size == 0 {
                // `_read_and_discard_trailer`.
                loop {
                    let line = connection.readline(MAX_LINE + 1)?;
                    if line.len() > MAX_LINE {
                        return Err(ProtocolError);
                    }
                    if matches!(line.as_slice(), b"\r\n" | b"\n" | b"") {
                        break;
                    }
                }
                self.finished = true;
                chunk_left = None;
            } else {
                chunk_left = Some(size);
            }
            self.chunk_left = chunk_left;
        }
        Ok(chunk_left)
    }
}

/// The request bytes `HTTPConnection.request("GET", path, headers)` sends:
/// the automatic `Host` header (with `:port` whenever the port is not
/// HTTPConnection's default 80 â€” also for HTTPS on 443), then `headers`.
pub(crate) fn request_bytes(
    host: &str,
    port: u16,
    path: &str,
    headers: &[(&str, String)],
) -> Vec<u8> {
    let mut host_header = if host.contains(':') {
        format!("[{host}]")
    } else {
        host.to_string()
    };
    if port != 80 {
        host_header = format!("{host_header}:{port}");
    }
    let mut request = format!("GET {path} HTTP/1.1\r\nHost: {host_header}\r\n");
    for (name, value) in headers {
        request.push_str(&format!("{name}: {value}\r\n"));
    }
    request.push_str("\r\n");
    request.into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn headers_follow_feedparser() {
        let headers = parse_headers(
            "Content-Type: image/png\r\nLocation: /a\r\nX-Folded: a\r\n b\r\nlocation: /b\r\nbad line\r\nAfter: x\r\n\r\n",
        );
        assert_eq!(headers.get("content-type"), Some("image/png"));
        assert_eq!(headers.getheader("LOCATION").as_deref(), Some("/a, /b"));
        assert_eq!(headers.get("x-folded"), Some("a\r\n b"));
        assert_eq!(headers.get("after"), None);
        // A bare CR splits header lines like the email parser does.
        let headers = parse_headers("X: a\rLocation: /c\r\n\r\n");
        assert_eq!(headers.get("location"), Some("/c"));
    }

    #[test]
    fn python_int_and_split() {
        assert_eq!(py_int(" 1_0 ", 10), Some(10));
        assert_eq!(py_int("+5", 10), Some(5));
        assert_eq!(py_int("1__0", 10), None);
        assert_eq!(py_int("5, 5", 10), None);
        assert_eq!(py_int("0x1A", 16), Some(26));
        assert_eq!(py_int("1a \r\n", 16), Some(26));
        assert_eq!(
            split_whitespace_max("HTTP/1.1  200 OK fine\r\n", 2),
            vec!["HTTP/1.1", "200", "OK fine\r\n"]
        );
        assert_eq!(
            request_bytes("images.example", 443, "/a?b", &[("Accept", "x".into())]),
            b"GET /a?b HTTP/1.1\r\nHost: images.example:443\r\nAccept: x\r\n\r\n".to_vec()
        );
    }
}
