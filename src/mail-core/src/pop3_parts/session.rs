//! Short-lived authenticated POP3 sessions and the maildrop snapshot used by
//! the compatibility mode (the POP3 counterpart of `imap_client.connect`,
//! `_select` and `_uid_validity`).

use std::collections::HashMap;

use mail_proto::pop3::{Pop3Connection, Pop3ListEntry};
use mail_proto::{ProtoError, Security, DEFAULT_TIMEOUT};
use native_tls::TlsConnector;
use sha2::{Digest, Sha256};

use crate::error::{MailError, Result};
use crate::servers::python_repr_str;
use crate::sessions::MailAccount;

/// Same text as `imap_client.connect` for rejected credentials.
pub(super) const SIGN_IN_FAILED: &str =
    "Mailbox sign-in failed. Check the password or use an app password.";

/// Largest value a synthetic `uid_validity` / message number may take.
pub(super) const MAX_UID: i64 = 4_294_967_295;

/// `MailOperationError(f"The server would not open folder {folder!r}")`.
pub(super) fn folder_error(folder: &str) -> MailError {
    MailError::operation(format!(
        "The server would not open folder {}",
        python_repr_str(folder)
    ))
}

/// An authenticated POP3 connection. Dropping it sends `QUIT` (best effort),
/// mirroring the `finally: _logout(conn)` blocks of the IMAP client. No
/// command that changes the maildrop (`DELE`) is ever sent.
pub(super) struct Session {
    conn: Pop3Connection,
    top_supported: bool,
    /// Header blocks already read in this session, by message number.
    headers: HashMap<u32, Vec<u8>>,
}

impl Drop for Session {
    fn drop(&mut self) {
        let _ = self.conn.quit();
    }
}

fn security(account: &MailAccount) -> Security {
    match account.imap_security().as_str() {
        "ssl" => Security::Ssl,
        "starttls" => Security::StartTls,
        _ => Security::None,
    }
}

fn connect_error(account: &MailAccount, error: &ProtoError) -> MailError {
    MailError::operation(format!(
        "Could not connect to {}:{}: {error}",
        account.incoming_server, account.incoming_port
    ))
}

#[cfg(test)]
thread_local! {
    /// TLS connector used by [`open`] on this thread (unit tests only, so
    /// the fake servers' self-signed certificate can be trusted).
    pub(super) static TEST_CONNECTOR: std::cell::RefCell<Option<TlsConnector>> =
        const { std::cell::RefCell::new(None) };
}

/// Open an authenticated session for `account` with the default TLS trust.
pub(super) fn open(account: &MailAccount) -> Result<Session> {
    #[cfg(test)]
    let connector = TEST_CONNECTOR.with(|cell| cell.borrow().clone());
    #[cfg(not(test))]
    let connector = None;
    connect(account, connector)
}

/// Open an authenticated session (`connect`). `connector` overrides the
/// default TLS trust settings (tests only).
///
/// Connection, TLS and `STLS` failures → "Could not connect to host:port: …";
/// rejected `USER`/`PASS` (or a server that hangs up instead of answering
/// `-ERR`) → [`SIGN_IN_FAILED`]. A socket failure during login is reported
/// as a connection failure (Python let that `OSError` escape as a 500).
pub(super) fn connect(account: &MailAccount, connector: Option<TlsConnector>) -> Result<Session> {
    let security = security(account);
    let host = account.incoming_server.as_str();
    let port = account.incoming_port;
    let connected = match connector {
        Some(connector) => {
            Pop3Connection::connect_with_tls(host, port, security, DEFAULT_TIMEOUT, connector)
        }
        None => Pop3Connection::connect(host, port, security, DEFAULT_TIMEOUT),
    };
    let mut conn = connected.map_err(|error| connect_error(account, &error))?;
    // Bound multi-line replies before any authenticated traffic.
    conn.set_max_response_size(super::MAX_RESPONSE_BYTES);
    if let Err(error) = conn.login(&account.email, &account.password) {
        let _ = conn.quit();
        return Err(match error {
            ProtoError::Io(_) | ProtoError::Timeout | ProtoError::Tls(_) => {
                connect_error(account, &error)
            }
            _ => MailError::operation(SIGN_IN_FAILED),
        });
    }
    Ok(Session {
        conn,
        top_supported: true,
        headers: HashMap::new(),
    })
}

/// The maildrop as seen by one session: message numbers with sizes, and the
/// synthetic mailbox epoch.
#[derive(Debug, Clone)]
pub(super) struct Maildrop {
    /// `LIST` entries sorted by message number.
    pub entries: Vec<Pop3ListEntry>,
    pub uid_validity: String,
}

impl Maildrop {
    /// Size in octets of message `number`, or `None` when it does not exist.
    pub fn size_of(&self, number: i64) -> Option<u64> {
        let number = u32::try_from(number).ok()?;
        self.entries
            .binary_search_by_key(&number, |entry| entry.number)
            .ok()
            .map(|index| self.entries[index].size)
    }

    /// Every message number, ascending.
    pub fn numbers(&self) -> Vec<u32> {
        self.entries.iter().map(|entry| entry.number).collect()
    }

    /// `max(numbers, default=0) + 1`: the first number a future message
    /// would receive (the POP3 analogue of UIDNEXT).
    pub fn next_number(&self) -> i64 {
        self.entries
            .last()
            .map_or(0, |entry| i64::from(entry.number))
            + 1
    }
}

/// A positive 32-bit decimal derived from a SHA-256 of `kind` and `lines`.
/// Stable across processes and platforms; any change to the lines changes
/// it (up to a 1 in 2^32 collision).
pub(super) fn synthetic_uid_validity<I>(kind: &str, lines: I) -> String
where
    I: IntoIterator,
    I::Item: AsRef<str>,
{
    let mut hasher = Sha256::new();
    hasher.update(b"pop3-");
    hasher.update(kind.as_bytes());
    hasher.update(b"\n");
    for line in lines {
        hasher.update(line.as_ref().as_bytes());
        hasher.update(b"\n");
    }
    let digest = hasher.finalize();
    let mut prefix = [0u8; 8];
    prefix.copy_from_slice(&digest[..8]);
    let value = u64::from_be_bytes(prefix) % (MAX_UID as u64) + 1;
    value.to_string()
}

/// Header block of a full message: everything up to and including the first
/// empty line (the whole input when there is no body separator).
pub(super) fn header_block(raw: &[u8]) -> Vec<u8> {
    match raw.windows(4).position(|window| window == b"\r\n\r\n") {
        Some(index) => raw[..index + 4].to_vec(),
        None => match raw.windows(2).position(|window| window == b"\n\n") {
            Some(index) => raw[..index + 2].to_vec(),
            None => raw.to_vec(),
        },
    }
}

impl Session {
    /// `STAT`, used to prove the maildrop can be opened. Any failure is
    /// reported with `message`.
    pub fn stat(&mut self, message: &str) -> Result<(u32, u64)> {
        self.conn
            .stat()
            .map_err(|_| MailError::operation(message.to_string()))
    }

    /// The POP3 `_select` + `_uid_validity`: only `INBOX` (any case) exists.
    /// Reads `LIST` and `UIDL` (falling back to the `LIST` sizes when the
    /// server answers `-ERR` to `UIDL`) and derives the synthetic epoch.
    pub fn open(&mut self, folder: &str) -> Result<Maildrop> {
        if !folder.eq_ignore_ascii_case("INBOX") {
            return Err(folder_error(folder));
        }
        let mut entries = self.conn.list().map_err(|_| folder_error(folder))?;
        entries.sort_by_key(|entry| entry.number);
        entries.dedup_by_key(|entry| entry.number);
        let uid_validity = match self.conn.uidl() {
            Ok(mut uidl) => {
                uidl.sort_by_key(|entry| entry.number);
                synthetic_uid_validity(
                    "uidl",
                    uidl.iter()
                        .map(|entry| format!("{} {}", entry.number, entry.uid)),
                )
            }
            Err(ProtoError::No(_)) => synthetic_uid_validity(
                "list",
                entries
                    .iter()
                    .map(|entry| format!("{} {}", entry.number, entry.size)),
            ),
            Err(_) => return Err(folder_error(folder)),
        };
        Ok(Maildrop {
            entries,
            uid_validity,
        })
    }

    /// Full message (`RETR`); also remembers its header block.
    pub fn retr(&mut self, number: u32) -> std::result::Result<Vec<u8>, ProtoError> {
        let raw = self.conn.retr(number)?;
        self.headers
            .entry(number)
            .or_insert_with(|| header_block(&raw));
        Ok(raw)
    }

    /// Header block of one message via `TOP n 0`; servers that answer `-ERR`
    /// to `TOP` (it is optional in RFC 1939) are read with `RETR` instead.
    pub fn headers(&mut self, number: u32) -> std::result::Result<Vec<u8>, ProtoError> {
        if let Some(headers) = self.headers.get(&number) {
            return Ok(headers.clone());
        }
        let headers = if self.top_supported {
            match self.conn.top(number, 0) {
                Ok(raw) => header_block(&raw),
                Err(ProtoError::No(_)) => {
                    self.top_supported = false;
                    header_block(&self.conn.retr(number)?)
                }
                Err(error) => return Err(error),
            }
        } else {
            header_block(&self.conn.retr(number)?)
        };
        self.headers.insert(number, headers.clone());
        Ok(headers)
    }
}
