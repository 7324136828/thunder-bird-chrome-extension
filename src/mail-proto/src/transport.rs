//! Shared blocking socket transport: plain TCP or TLS (`native-tls`), with a
//! read buffer for CRLF line framing and literal reads.
//!
//! Mirrors the socket handling of `imaplib.IMAP4` / `imaplib.IMAP4_SSL` and
//! `poplib.POP3` / `poplib.POP3_SSL`: one connect timeout that is also used
//! for every subsequent socket read and write.

use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpStream};
use std::str::FromStr;
use std::time::Duration;

use native_tls::{HandshakeError, TlsConnector, TlsStream};

use crate::error::{ProtoError, Result};

/// Connection security mode (`imap_security` in the original server
/// profiles: `"ssl"`, `"starttls"`, `"none"`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Security {
    /// Implicit TLS from the first byte (`IMAP4_SSL`, port 993/995).
    Ssl,
    /// Plain connection upgraded with `STARTTLS` (IMAP) or `STLS` (POP3).
    StartTls,
    /// Plain text; only for local bridges and tests.
    None,
}

impl Security {
    /// Parse a profile value. Accepts the backend spellings (`ssl`,
    /// `starttls`, `none`) and the doctor spellings (`SSL/TLS`, `STARTTLS`,
    /// `NONE`), case-insensitively.
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "ssl" | "ssl/tls" | "tls" => Some(Security::Ssl),
            "starttls" => Some(Security::StartTls),
            "none" | "plain" => Some(Security::None),
            _ => None,
        }
    }

    /// The canonical backend spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            Security::Ssl => "ssl",
            Security::StartTls => "starttls",
            Security::None => "none",
        }
    }
}

impl FromStr for Security {
    type Err = ProtoError;

    fn from_str(value: &str) -> Result<Self> {
        Security::parse(value)
            .ok_or_else(|| ProtoError::Protocol(format!("unknown security mode {value:?}")))
    }
}

/// Build the default TLS connector (system trust store, hostname checks),
/// equivalent to `ssl.create_default_context()`.
pub(crate) fn default_connector() -> Result<TlsConnector> {
    TlsConnector::new().map_err(ProtoError::from)
}

/// A plain or TLS-wrapped TCP stream.
pub(crate) enum MailStream {
    Plain(TcpStream),
    Tls(Box<TlsStream<TcpStream>>),
    Closed,
}

impl MailStream {
    fn closed_error() -> io::Error {
        io::Error::new(io::ErrorKind::NotConnected, "connection is closed")
    }
}

impl Read for MailStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            MailStream::Plain(stream) => stream.read(buf),
            MailStream::Tls(stream) => stream.read(buf),
            MailStream::Closed => Err(Self::closed_error()),
        }
    }
}

impl Write for MailStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            MailStream::Plain(stream) => stream.write(buf),
            MailStream::Tls(stream) => stream.write(buf),
            MailStream::Closed => Err(Self::closed_error()),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            MailStream::Plain(stream) => stream.flush(),
            MailStream::Tls(stream) => stream.flush(),
            MailStream::Closed => Err(Self::closed_error()),
        }
    }
}

const READ_CHUNK: usize = 16 * 1024;

/// Buffered line/literal transport used by every client and fake server.
pub(crate) struct Transport {
    stream: MailStream,
    buf: Vec<u8>,
    pos: usize,
}

impl Transport {
    /// Wrap an already connected TCP stream.
    pub(crate) fn new(stream: TcpStream) -> Self {
        Transport {
            stream: MailStream::Plain(stream),
            buf: Vec::new(),
            pos: 0,
        }
    }

    /// Resolve `host` and connect with `timeout` (zero means no timeout),
    /// trying every resolved address like `socket.create_connection`.
    /// Resolution goes through [`crate::resolve`], which rides out short DNS
    /// outages.
    pub(crate) fn connect(host: &str, port: u16, timeout: Duration) -> Result<Self> {
        let addrs = crate::resolve::resolve(host, port)?;
        let mut last_error: Option<io::Error> = None;
        for addr in addrs {
            let attempt = if timeout.is_zero() {
                TcpStream::connect(addr)
            } else {
                TcpStream::connect_timeout(&addr, timeout)
            };
            match attempt {
                Ok(stream) => {
                    let limit = (!timeout.is_zero()).then_some(timeout);
                    stream.set_read_timeout(limit)?;
                    stream.set_write_timeout(limit)?;
                    let _ = stream.set_nodelay(true);
                    return Ok(Transport::new(stream));
                }
                Err(error) => last_error = Some(error),
            }
        }
        Err(last_error
            .unwrap_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("could not resolve host {host:?}"),
                )
            })
            .into())
    }

    /// True once a TLS session is active.
    pub(crate) fn is_tls(&self) -> bool {
        matches!(self.stream, MailStream::Tls(_))
    }

    /// True when unread bytes are buffered.
    pub(crate) fn has_buffered(&self) -> bool {
        self.pos < self.buf.len()
    }

    fn fill(&mut self) -> Result<()> {
        if self.pos == self.buf.len() {
            self.buf.clear();
            self.pos = 0;
        } else if self.pos > 64 * 1024 {
            self.buf.drain(..self.pos);
            self.pos = 0;
        }
        let mut chunk = [0u8; READ_CHUNK];
        let count = loop {
            match self.stream.read(&mut chunk) {
                Ok(count) => break count,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error.into()),
            }
        };
        if count == 0 {
            return Err(ProtoError::Closed(
                "the server closed the connection".to_string(),
            ));
        }
        self.buf.extend_from_slice(&chunk[..count]);
        Ok(())
    }

    /// Read one line, stripping the trailing CRLF (a bare LF is tolerated).
    pub(crate) fn read_line(&mut self, max_len: usize) -> Result<Vec<u8>> {
        let mut scanned = 0;
        loop {
            let start = self.pos + scanned;
            if let Some(offset) = self.buf[start..].iter().position(|&b| b == b'\n') {
                let end = start + offset;
                let mut line = self.buf[self.pos..end].to_vec();
                self.pos = end + 1;
                if line.last() == Some(&b'\r') {
                    line.pop();
                }
                return Ok(line);
            }
            scanned = self.buf.len() - self.pos;
            if scanned > max_len {
                return Err(ProtoError::Protocol(format!(
                    "got more than {max_len} bytes without a line break"
                )));
            }
            self.fill()?;
        }
    }

    /// Read exactly `count` bytes (an IMAP literal).
    pub(crate) fn read_exact_vec(&mut self, count: usize) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(count.min(1 << 20));
        let available = (self.buf.len() - self.pos).min(count);
        out.extend_from_slice(&self.buf[self.pos..self.pos + available]);
        self.pos += available;
        let mut chunk = vec![0u8; READ_CHUNK * 4];
        while out.len() < count {
            let want = (count - out.len()).min(chunk.len());
            match self.stream.read(&mut chunk[..want]) {
                Ok(0) => {
                    return Err(ProtoError::Closed(
                        "the server closed the connection inside a literal".to_string(),
                    ))
                }
                Ok(read) => out.extend_from_slice(&chunk[..read]),
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error.into()),
            }
        }
        Ok(out)
    }

    /// Write and flush.
    pub(crate) fn write_all(&mut self, data: &[u8]) -> Result<()> {
        self.stream.write_all(data)?;
        self.stream.flush()?;
        Ok(())
    }

    fn take_plain(&mut self) -> Result<TcpStream> {
        match std::mem::replace(&mut self.stream, MailStream::Closed) {
            MailStream::Plain(stream) => Ok(stream),
            other => {
                self.stream = other;
                Err(ProtoError::Protocol(
                    "TLS session already established".to_string(),
                ))
            }
        }
    }

    /// Upgrade a plain stream to TLS as a client.
    ///
    /// Bytes the server sent after its STARTTLS answer but before the
    /// handshake would be processed as if they were protected; refuse them
    /// (the "STARTTLS command injection" class of bugs).
    pub(crate) fn start_tls(&mut self, connector: &TlsConnector, domain: &str) -> Result<()> {
        if self.has_buffered() {
            self.stream = MailStream::Closed;
            return Err(ProtoError::Protocol(
                "the server sent unexpected data before the TLS handshake".to_string(),
            ));
        }
        let plain = self.take_plain()?;
        match connector.connect(domain, plain) {
            Ok(stream) => {
                self.stream = MailStream::Tls(Box::new(stream));
                Ok(())
            }
            Err(HandshakeError::Failure(error)) => Err(ProtoError::Tls(error.to_string())),
            Err(HandshakeError::WouldBlock(_)) => Err(ProtoError::Timeout),
        }
    }

    /// Upgrade a plain stream to TLS as a server (fake servers only).
    #[cfg(any(test, feature = "testkit"))]
    pub(crate) fn accept_tls(&mut self, acceptor: &native_tls::TlsAcceptor) -> Result<()> {
        if self.has_buffered() {
            self.stream = MailStream::Closed;
            return Err(ProtoError::Protocol(
                "the client sent data before the TLS handshake".to_string(),
            ));
        }
        let plain = self.take_plain()?;
        match acceptor.accept(plain) {
            Ok(stream) => {
                self.stream = MailStream::Tls(Box::new(stream));
                Ok(())
            }
            Err(HandshakeError::Failure(error)) => Err(ProtoError::Tls(error.to_string())),
            Err(HandshakeError::WouldBlock(_)) => Err(ProtoError::Timeout),
        }
    }

    /// Close the socket; further reads and writes fail.
    pub(crate) fn shutdown(&mut self) {
        match std::mem::replace(&mut self.stream, MailStream::Closed) {
            MailStream::Plain(stream) => {
                let _ = stream.shutdown(Shutdown::Both);
            }
            MailStream::Tls(mut stream) => {
                let _ = stream.shutdown();
                let _ = stream.get_ref().shutdown(Shutdown::Both);
            }
            MailStream::Closed => {}
        }
        self.buf.clear();
        self.pos = 0;
    }
}
