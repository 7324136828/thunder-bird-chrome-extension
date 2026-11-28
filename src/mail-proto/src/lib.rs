//! Blocking IMAP4rev1 / POP3 protocol clients in the style of Python's
//! `imaplib` and `poplib`, plus fake in-process servers for tests.
//!
//! The original backend (`backend/app/mail/imap_client.py`, `trash.py`,
//! `backend/app/doctor/services/mailbox_download.py`) talked to mail servers
//! through `imaplib` from FastAPI's thread pool. This crate provides the same
//! synchronous building blocks so the Rust port can mirror that code 1:1:
//!
//! * [`imap::ImapConnection`] — connect (`Ssl`/`StartTls`/`None`), capability
//!   tracking, `LOGIN`, `AUTHENTICATE XOAUTH2`, a generic tagged command
//!   executor and typed helpers (`SELECT`/`EXAMINE`, `UID SEARCH/FETCH/STORE/
//!   MOVE/COPY/EXPUNGE`, `APPEND`, `CREATE`, `LIST`, `ENABLE`, ...).
//! * [`imap::parser`] — FETCH / LIST / SEARCH response parsing with literals
//!   preserved as bytes.
//! * [`imap::utf7`] — RFC 3501 modified UTF-7 mailbox-name helpers.
//! * [`pop3::Pop3Connection`] — a `poplib`-style POP3 client.
//! * `testkit` (feature `testkit`) — fake IMAP, POP3 and SMTP servers on
//!   `127.0.0.1:0` for integration tests in other crates.
//!
//! Credentials are only ever held in memory and are never written to logs,
//! error messages or the fake servers' command logs.

pub mod error;
pub mod imap;
pub mod pop3;
pub mod resolve;
mod transport;

#[cfg(any(test, feature = "testkit"))]
pub mod testkit;

#[cfg(test)]
mod tests;

pub use error::{ProtoError, Result};
pub use transport::Security;

/// Timeout used by the original backend for every mail socket
/// (`imaplib.IMAP4(..., timeout=30)`).
pub const DEFAULT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
