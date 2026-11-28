//! Fake in-process mail servers for tests (feature `testkit`).
//!
//! Each server listens on `127.0.0.1:0` (an ephemeral port), serves every
//! connection on its own thread and keeps its state behind a mutex so a test
//! can inspect or change it while clients are connected. Servers stop
//! accepting connections when dropped.
//!
//! * [`FakeImapServer`] — in-memory folders/messages with UIDs, flags,
//!   INTERNALDATE, UIDVALIDITY and special-use attributes; configurable
//!   CAPABILITY; command log; failure injection and a response hook.
//! * [`FakePop3Server`] — a maildrop with `USER/PASS`, `STAT`, `LIST`,
//!   `UIDL`, `RETR`, `TOP`, `DELE`, `RSET`, `QUIT`.
//! * [`FakeSmtpServer`] — `EHLO`, `AUTH PLAIN/LOGIN`, `MAIL`, `RCPT`,
//!   `DATA`; records envelopes and raw messages.
//!
//! All servers speak plain TCP by default. [`TlsMode`] enables STARTTLS
//! (STLS for POP3) or implicit TLS with a bundled self-signed `localhost`
//! certificate; clients connect with [`test_connector`].
//!
//! ```no_run
//! use mail_proto::testkit::FakeImapServer;
//! use mail_proto::{imap::ImapConnection, Security};
//!
//! let server = FakeImapServer::builder()
//!     .credentials("user@example.com", "secret")
//!     .folder("Trash", &["\\Trash"])
//!     .message("INBOX", b"Subject: hi\r\n\r\nbody\r\n".to_vec())
//!     .start();
//! let mut conn = ImapConnection::connect(
//!     server.host(), server.port(), Security::None, mail_proto::DEFAULT_TIMEOUT,
//! ).unwrap();
//! conn.login("user@example.com", "secret").unwrap();
//! ```

mod imap;
mod pop3;
mod smtp;

use std::collections::{HashMap, VecDeque};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use native_tls::{Certificate, Identity, TlsAcceptor, TlsConnector};

pub use self::imap::{
    FakeFolder, FakeImapBuilder, FakeImapServer, FakeMessage, HookAction, ImapHook, ImapRequest,
};
pub use self::pop3::{FakePop3Builder, FakePop3Server};
pub use self::smtp::{FakeSmtpBuilder, FakeSmtpServer, ReceivedMail};

use crate::transport::Transport;

const TEST_CERT_PEM: &[u8] = include_bytes!("fixtures/test-cert.pem");
// Test-only key for the bundled self-signed `localhost` certificate. It
// protects nothing and must never be used outside tests.
const TEST_KEY_PEM: &[u8] = include_bytes!("fixtures/test-key.pem");

/// Server socket read timeout, so abandoned connections end their threads.
const SERVER_IDLE_TIMEOUT: Duration = Duration::from_secs(60);

/// The bundled self-signed certificate (CN/SAN `localhost`, `127.0.0.1`).
pub fn test_certificate() -> Certificate {
    Certificate::from_pem(TEST_CERT_PEM).expect("bundled test certificate is valid")
}

/// Server identity for the bundled certificate.
pub fn test_identity() -> Identity {
    Identity::from_pkcs8(TEST_CERT_PEM, TEST_KEY_PEM).expect("bundled test identity is valid")
}

/// A client connector that trusts the bundled test certificate only for
/// tests. It accepts the self-signed certificate (`danger_accept_invalid_
/// certs`) because platform trust stores differ in how they treat ad hoc
/// roots; never use it against real servers.
pub fn test_connector() -> TlsConnector {
    TlsConnector::builder()
        .add_root_certificate(test_certificate())
        .danger_accept_invalid_certs(true)
        .danger_accept_invalid_hostnames(true)
        .build()
        .expect("test TLS connector")
}

/// How a fake server offers TLS.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsMode {
    /// Plain connection that can be upgraded (`STARTTLS` / `STLS`).
    StartTls,
    /// TLS from the first byte.
    Implicit,
}

fn acceptor() -> TlsAcceptor {
    TlsAcceptor::new(test_identity()).expect("test TLS acceptor")
}

/// A failure to inject for the next occurrence of a command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Failure {
    /// Reply `NO text` (IMAP), `-ERR text` (POP3) or `550 text` (SMTP).
    No(String),
    /// Reply `BAD text` (IMAP), `-ERR text` (POP3) or `500 text` (SMTP).
    Bad(String),
    /// SMTP only: reply with this exact code and text (IMAP treats it as
    /// `NO`, POP3 as `-ERR`).
    Code(u16, String),
    /// Close the connection without replying.
    Disconnect,
}

impl Failure {
    /// `Failure::No` with a generic text.
    pub fn no() -> Self {
        Failure::No("Injected failure".to_string())
    }

    /// `Failure::Bad` with a generic text.
    pub fn bad() -> Self {
        Failure::Bad("Injected failure".to_string())
    }
}

/// One logged client command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoggedCommand {
    /// 1-based connection number.
    pub connection: usize,
    /// Uppercased command name, e.g. `UID FETCH`, `SELECT`, `RETR`, `MAIL`.
    pub name: String,
    /// The command line without the tag; literal contents are replaced by
    /// their `{n}` marker and credentials by `****`.
    pub line: String,
}

/// Per-command failure queues.
#[derive(Debug, Default)]
pub(crate) struct FailureQueue {
    queues: HashMap<String, VecDeque<Failure>>,
}

impl FailureQueue {
    pub(crate) fn push(&mut self, command: &str, failure: Failure) {
        self.queues
            .entry(command.trim().to_ascii_uppercase())
            .or_default()
            .push_back(failure);
    }

    pub(crate) fn take(&mut self, command: &str) -> Option<Failure> {
        self.queues.get_mut(command)?.pop_front()
    }

    pub(crate) fn clear(&mut self) {
        self.queues.clear();
    }
}

pub(crate) fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Listener thread shared by every fake server.
pub(crate) struct ServerCore {
    addr: SocketAddr,
    shutdown: Arc<AtomicBool>,
    accept: Option<JoinHandle<()>>,
}

impl ServerCore {
    pub(crate) fn spawn<H>(name: &str, implicit_tls: bool, handler: H) -> Self
    where
        H: Fn(Transport, usize) + Send + Sync + 'static,
    {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind fake server");
        let addr = listener.local_addr().expect("fake server address");
        let shutdown = Arc::new(AtomicBool::new(false));
        let stop = Arc::clone(&shutdown);
        let handler = Arc::new(handler);
        let tls = implicit_tls.then(acceptor);
        let thread_name = format!("fake-{name}-accept");
        let accept = thread::Builder::new()
            .name(thread_name)
            .spawn(move || {
                let mut connection = 0usize;
                for stream in listener.incoming() {
                    if stop.load(Ordering::SeqCst) {
                        break;
                    }
                    let Ok(stream) = stream else { continue };
                    connection += 1;
                    let _ = stream.set_read_timeout(Some(SERVER_IDLE_TIMEOUT));
                    let _ = stream.set_write_timeout(Some(SERVER_IDLE_TIMEOUT));
                    let handler = Arc::clone(&handler);
                    let tls = tls.clone();
                    let id = connection;
                    thread::spawn(move || {
                        let mut transport = Transport::new(stream);
                        if let Some(acceptor) = tls {
                            if transport.accept_tls(&acceptor).is_err() {
                                return;
                            }
                        }
                        handler(transport, id);
                    });
                }
            })
            .expect("spawn fake server");
        ServerCore {
            addr,
            shutdown,
            accept: Some(accept),
        }
    }

    pub(crate) fn addr(&self) -> SocketAddr {
        self.addr
    }
}

impl Drop for ServerCore {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::SeqCst);
        // Wake the blocking accept() so the thread sees the flag.
        let _ = TcpStream::connect_timeout(&self.addr, Duration::from_secs(1));
        if let Some(handle) = self.accept.take() {
            let _ = handle.join();
        }
    }
}

/// Days since 1970-01-01 to (year, month, day) — H. Hinnant's algorithm.
pub(crate) fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let year = yoe + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

/// (year, month, day) to days since 1970-01-01.
pub(crate) fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let yoe = year.rem_euclid(400);
    let month = i64::from(month);
    let doy = (153 * (if month > 2 { month - 3 } else { month + 9 }) + 2) / 5 + i64::from(day) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

pub(crate) const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

/// Current time as an IMAP date-time, `dd-Mon-yyyy hh:mm:ss +0000`.
pub fn now_internal_date() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let (year, month, day) = civil_from_days(secs.div_euclid(86_400));
    let rem = secs.rem_euclid(86_400);
    format!(
        "{:02}-{}-{:04} {:02}:{:02}:{:02} +0000",
        day,
        MONTHS[(month - 1) as usize],
        year,
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

/// Parse the date part of `d-Mon-yyyy[...]` into days since the epoch.
pub(crate) fn parse_imap_date(value: &str) -> Option<i64> {
    let date = value.split_whitespace().next()?;
    let mut fields = date.split('-');
    let day: u32 = fields.next()?.trim().parse().ok()?;
    let month_name = fields.next()?;
    let month = MONTHS
        .iter()
        .position(|m| m.eq_ignore_ascii_case(month_name))? as u32
        + 1;
    let year: i64 = fields.next()?.get(..4)?.parse().ok()?;
    if !(1..=31).contains(&day) {
        return None;
    }
    Some(days_from_civil(year, month, day))
}

/// Normalize line endings to CRLF.
pub(crate) fn crlf(raw: &[u8]) -> Vec<u8> {
    crate::imap::normalize_crlf(raw)
}
