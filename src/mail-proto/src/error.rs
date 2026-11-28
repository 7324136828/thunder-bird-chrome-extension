//! Error type shared by the IMAP and POP3 clients.
//!
//! Mapping from the Python exceptions the original code caught:
//!
//! | Python                                   | [`ProtoError`]                 |
//! |------------------------------------------|--------------------------------|
//! | `OSError` (socket errors)                | [`ProtoError::Io`]             |
//! | `socket.timeout` / `TimeoutError`        | [`ProtoError::Timeout`]        |
//! | `ssl.SSLError`                           | [`ProtoError::Tls`]            |
//! | `imaplib.IMAP4.abort` / malformed data   | [`ProtoError::Protocol`] / [`ProtoError::Closed`] |
//! | status `"NO"` / `poplib.error_proto`     | [`ProtoError::No`]             |
//! | status `"BAD"` (`imaplib.IMAP4.error`)   | [`ProtoError::Bad`]            |
//! | `UnicodeEncodeError` on a command string | [`ProtoError::Encoding`]       |
//!
//! Every variant corresponds to an exception the Python code treated as
//! `(OSError, imaplib.IMAP4.error)`, so callers that do not need finer detail
//! can simply map any `ProtoError` to their operation error.

use std::io;

/// Result alias used throughout the crate.
pub type Result<T> = std::result::Result<T, ProtoError>;

/// Errors raised by the protocol clients.
#[derive(Debug, thiserror::Error)]
pub enum ProtoError {
    /// Socket-level failure (connection refused, reset, DNS failure, ...).
    #[error("{0}")]
    Io(io::Error),
    /// TLS handshake or certificate failure.
    #[error("TLS error: {0}")]
    Tls(String),
    /// The server sent something this client cannot interpret, or a client
    /// side protocol precondition failed (e.g. STARTTLS not advertised).
    #[error("{0}")]
    Protocol(String),
    /// The server closed the connection unexpectedly.
    #[error("{0}")]
    Closed(String),
    /// Tagged `NO` (IMAP) or `-ERR` (POP3) completion; carries the server
    /// text (including any `[CODE]`).
    #[error("{0}")]
    No(String),
    /// Tagged `BAD` completion; carries the server text.
    #[error("{0}")]
    Bad(String),
    /// A socket read or write timed out.
    #[error("timed out")]
    Timeout,
    /// A command argument cannot be sent in the current mode (for example a
    /// non-ASCII mailbox name before `ENABLE UTF8=ACCEPT`, or a line break).
    #[error("{0}")]
    Encoding(String),
}

impl ProtoError {
    /// True for [`ProtoError::Timeout`].
    pub fn is_timeout(&self) -> bool {
        matches!(self, ProtoError::Timeout)
    }

    /// True when the server answered `NO` / `-ERR` (as opposed to a
    /// connection or protocol failure).
    pub fn is_no(&self) -> bool {
        matches!(self, ProtoError::No(_))
    }

    /// True when the server answered `BAD`.
    pub fn is_bad(&self) -> bool {
        matches!(self, ProtoError::Bad(_))
    }

    /// True for a server completion (`NO` or `BAD`), i.e. the connection is
    /// still usable.
    pub fn is_server_response(&self) -> bool {
        matches!(self, ProtoError::No(_) | ProtoError::Bad(_))
    }
}

impl From<io::Error> for ProtoError {
    fn from(error: io::Error) -> Self {
        match error.kind() {
            io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock => ProtoError::Timeout,
            _ => ProtoError::Io(error),
        }
    }
}

impl From<native_tls::Error> for ProtoError {
    fn from(error: native_tls::Error) -> Self {
        ProtoError::Tls(error.to_string())
    }
}
