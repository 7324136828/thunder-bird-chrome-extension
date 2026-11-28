//! Blocking POP3 client modelled on Python's `poplib.POP3` / `POP3_SSL`.
//!
//! POP3 is not used by the original backend; it backs the compatibility
//! mode the port adds (unlock, list INBOX, read messages). Server errors
//! (`-ERR ...`, `poplib.error_proto`) become [`ProtoError::No`].

use std::time::Duration;

use native_tls::TlsConnector;

use crate::error::{ProtoError, Result};
use crate::transport::{default_connector, Security, Transport};

/// Maximum single line length accepted from the server. `poplib` uses
/// 2048, which real messages with long lines exceed; be more lenient.
const MAX_LINE: usize = 1024 * 1024;
/// Default cap for one multi-line response (a whole message).
pub const DEFAULT_MAX_RESPONSE: usize = 256 * 1024 * 1024;

/// One `LIST` entry: message number and size in octets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Pop3ListEntry {
    pub number: u32,
    pub size: u64,
}

/// One `UIDL` entry: message number and unique-id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pop3UidlEntry {
    pub number: u32,
    pub uid: String,
}

/// A connected POP3 session.
pub struct Pop3Connection {
    transport: Transport,
    connector: TlsConnector,
    host: String,
    greeting: String,
    closed: bool,
    max_response: usize,
}

impl std::fmt::Debug for Pop3Connection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Pop3Connection")
            .field("host", &self.host)
            .field("tls", &self.transport.is_tls())
            .field("closed", &self.closed)
            .finish()
    }
}

fn parse_number<T: std::str::FromStr>(word: Option<&str>, what: &str) -> Result<T> {
    word.and_then(|w| w.parse().ok())
        .ok_or_else(|| ProtoError::Protocol(format!("malformed POP3 {what} response")))
}

impl Pop3Connection {
    /// Connect and read the greeting; with [`Security::StartTls`] upgrade
    /// with `STLS` (RFC 2595) before returning.
    pub fn connect(host: &str, port: u16, security: Security, timeout: Duration) -> Result<Self> {
        Self::connect_with_tls(host, port, security, timeout, default_connector()?)
    }

    /// Like [`Pop3Connection::connect`] with a caller-supplied connector.
    pub fn connect_with_tls(
        host: &str,
        port: u16,
        security: Security,
        timeout: Duration,
        connector: TlsConnector,
    ) -> Result<Self> {
        let mut transport = Transport::connect(host, port, timeout)?;
        if security == Security::Ssl {
            transport.start_tls(&connector, host)?;
        }
        let mut connection = Pop3Connection {
            transport,
            connector,
            host: host.to_string(),
            greeting: String::new(),
            closed: false,
            max_response: DEFAULT_MAX_RESPONSE,
        };
        connection.greeting = connection.read_status()?;
        if security == Security::StartTls {
            connection.stls()?;
        }
        Ok(connection)
    }

    /// Greeting text after `+OK`.
    pub fn greeting(&self) -> &str {
        &self.greeting
    }

    /// True once TLS is active.
    pub fn is_tls(&self) -> bool {
        self.transport.is_tls()
    }

    /// Change the maximum size of one multi-line response.
    pub fn set_max_response_size(&mut self, bytes: usize) {
        self.max_response = bytes;
    }

    fn ensure_open(&self) -> Result<()> {
        if self.closed {
            return Err(ProtoError::Closed(
                "the POP3 connection is closed".to_string(),
            ));
        }
        Ok(())
    }

    fn read_line(&mut self) -> Result<Vec<u8>> {
        self.transport.read_line(MAX_LINE).inspect_err(|_| {
            self.closed = true;
        })
    }

    /// Read a `+OK` / `-ERR` status line, returning the text after `+OK`.
    fn read_status(&mut self) -> Result<String> {
        let line = self.read_line()?;
        let text = String::from_utf8_lossy(&line).into_owned();
        if let Some(rest) = text.strip_prefix("+OK") {
            Ok(rest.trim().to_string())
        } else if let Some(rest) = text.strip_prefix("-ERR") {
            Err(ProtoError::No(rest.trim().to_string()))
        } else {
            self.closed = true;
            Err(ProtoError::Protocol(format!(
                "unexpected POP3 response: {}",
                text.chars().take(200).collect::<String>()
            )))
        }
    }

    fn send(&mut self, line: &str) -> Result<()> {
        self.ensure_open()?;
        if line.bytes().any(|b| b == b'\r' || b == b'\n' || b == 0) {
            return Err(ProtoError::Encoding(
                "POP3 command arguments cannot contain line breaks".to_string(),
            ));
        }
        let mut data = line.as_bytes().to_vec();
        data.extend_from_slice(b"\r\n");
        self.transport.write_all(&data).inspect_err(|_| {
            self.closed = true;
        })
    }

    /// Send a command and read a single-line response.
    pub fn command(&mut self, line: &str) -> Result<String> {
        self.send(line)?;
        self.read_status()
    }

    /// Read the body of a multi-line response (after the status line):
    /// lines until `.`, dot-unstuffed, each terminated with CRLF.
    fn read_multiline(&mut self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        loop {
            let line = self.read_line()?;
            if line == b"." {
                return Ok(out);
            }
            let content = if line.starts_with(b"..") {
                &line[1..]
            } else {
                &line[..]
            };
            if out.len() + content.len() + 2 > self.max_response {
                self.closed = true;
                self.transport.shutdown();
                return Err(ProtoError::Protocol(format!(
                    "POP3 response exceeds {} bytes",
                    self.max_response
                )));
            }
            out.extend_from_slice(content);
            out.extend_from_slice(b"\r\n");
        }
    }

    /// Send a command expecting a multi-line response; returns the status
    /// text and the unstuffed body.
    pub fn command_multiline(&mut self, line: &str) -> Result<(String, Vec<u8>)> {
        let status = self.command(line)?;
        let body = self.read_multiline()?;
        Ok((status, body))
    }

    fn body_lines(body: &[u8]) -> Vec<String> {
        String::from_utf8_lossy(body)
            .split("\r\n")
            .filter(|line| !line.is_empty())
            .map(str::to_string)
            .collect()
    }

    /// `CAPA` (RFC 2449): capability lines, e.g. `["USER", "UIDL", "TOP"]`.
    pub fn capa(&mut self) -> Result<Vec<String>> {
        let (_, body) = self.command_multiline("CAPA")?;
        Ok(Self::body_lines(&body))
    }

    /// `STLS`: upgrade a plain connection to TLS.
    pub fn stls(&mut self) -> Result<()> {
        if self.transport.is_tls() {
            return Err(ProtoError::Protocol(
                "TLS session already established".to_string(),
            ));
        }
        self.command("STLS")?;
        let connector = self.connector.clone();
        let host = self.host.clone();
        self.transport
            .start_tls(&connector, &host)
            .inspect_err(|_| {
                self.closed = true;
            })
    }

    /// `USER` + `PASS`. The password never appears in errors.
    pub fn login(&mut self, user: &str, password: &str) -> Result<()> {
        self.user(user)?;
        self.pass(password).map(|_| ())
    }

    /// `USER name`.
    pub fn user(&mut self, user: &str) -> Result<String> {
        self.command(&format!("USER {user}"))
    }

    /// `PASS password`.
    pub fn pass(&mut self, password: &str) -> Result<String> {
        self.command(&format!("PASS {password}"))
    }

    /// `STAT`: `(message count, maildrop size)`.
    pub fn stat(&mut self) -> Result<(u32, u64)> {
        let text = self.command("STAT")?;
        let mut words = text.split_whitespace();
        Ok((
            parse_number(words.next(), "STAT")?,
            parse_number(words.next(), "STAT")?,
        ))
    }

    /// `LIST`: every message number and size.
    pub fn list(&mut self) -> Result<Vec<Pop3ListEntry>> {
        let (_, body) = self.command_multiline("LIST")?;
        Self::body_lines(&body)
            .iter()
            .map(|line| {
                let mut words = line.split_whitespace();
                Ok(Pop3ListEntry {
                    number: parse_number(words.next(), "LIST")?,
                    size: parse_number(words.next(), "LIST")?,
                })
            })
            .collect()
    }

    /// `LIST n`.
    pub fn list_one(&mut self, number: u32) -> Result<Pop3ListEntry> {
        let text = self.command(&format!("LIST {number}"))?;
        let mut words = text.split_whitespace();
        Ok(Pop3ListEntry {
            number: parse_number(words.next(), "LIST")?,
            size: parse_number(words.next(), "LIST")?,
        })
    }

    /// `UIDL`: every message number and unique-id.
    pub fn uidl(&mut self) -> Result<Vec<Pop3UidlEntry>> {
        let (_, body) = self.command_multiline("UIDL")?;
        Self::body_lines(&body)
            .iter()
            .map(|line| {
                let mut words = line.split_whitespace();
                Ok(Pop3UidlEntry {
                    number: parse_number(words.next(), "UIDL")?,
                    uid: words
                        .next()
                        .ok_or_else(|| ProtoError::Protocol("malformed POP3 UIDL response".into()))?
                        .to_string(),
                })
            })
            .collect()
    }

    /// `UIDL n`.
    pub fn uidl_one(&mut self, number: u32) -> Result<Pop3UidlEntry> {
        let text = self.command(&format!("UIDL {number}"))?;
        let mut words = text.split_whitespace();
        Ok(Pop3UidlEntry {
            number: parse_number(words.next(), "UIDL")?,
            uid: words
                .next()
                .ok_or_else(|| ProtoError::Protocol("malformed POP3 UIDL response".into()))?
                .to_string(),
        })
    }

    /// `RETR n`: the full message, dot-unstuffed, CRLF line endings.
    pub fn retr(&mut self, number: u32) -> Result<Vec<u8>> {
        Ok(self.command_multiline(&format!("RETR {number}"))?.1)
    }

    /// `TOP n lines`: headers, blank line and the first `lines` body lines.
    pub fn top(&mut self, number: u32, lines: u32) -> Result<Vec<u8>> {
        Ok(self.command_multiline(&format!("TOP {number} {lines}"))?.1)
    }

    /// `DELE n` (applied by the server on `QUIT`).
    pub fn dele(&mut self, number: u32) -> Result<String> {
        self.command(&format!("DELE {number}"))
    }

    /// `NOOP`.
    pub fn noop(&mut self) -> Result<String> {
        self.command("NOOP")
    }

    /// `RSET`: unmark deletions.
    pub fn rset(&mut self) -> Result<String> {
        self.command("RSET")
    }

    /// `QUIT` and close the socket.
    pub fn quit(&mut self) -> Result<String> {
        if self.closed {
            self.transport.shutdown();
            return Ok(String::new());
        }
        let result = self.command("QUIT");
        self.closed = true;
        self.transport.shutdown();
        result
    }
}

impl Drop for Pop3Connection {
    fn drop(&mut self) {
        self.transport.shutdown();
    }
}
