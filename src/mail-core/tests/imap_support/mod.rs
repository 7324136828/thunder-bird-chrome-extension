//! Shared helpers for the `imap_*` integration tests (fake IMAP server
//! accounts and command-log filtering).

#![allow(dead_code)]

use mail_core::sessions::MailAccount;
use mail_proto::testkit::{FakeImapBuilder, FakeImapServer, FakeMessage};

pub const USER: &str = "user@example.com";
pub const PASSWORD: &str = "s3cret-imap-pass";

/// A builder that accepts [`USER`] / [`PASSWORD`].
pub fn server() -> FakeImapBuilder {
    FakeImapServer::builder().credentials(USER, PASSWORD)
}

/// An unlocked IMAP account pointing at the fake server (plain TCP).
pub fn account(server: &FakeImapServer) -> MailAccount {
    account_at(server.port())
}

pub fn account_at(port: u16) -> MailAccount {
    MailAccount::new(
        USER,
        PASSWORD,
        "127.0.0.1",
        port,
        "none",
        "smtp.example.com",
        587,
        "STARTTLS",
    )
}

/// A POP3 account (must never reach the IMAP code paths).
pub fn pop3_account() -> MailAccount {
    let mut account = account_at(1);
    account.incoming_mail_protocol = "pop3".into();
    account
}

/// A message with a fixed UID, flags and INTERNALDATE.
pub fn message(uid: u32, raw: impl Into<Vec<u8>>) -> FakeMessage {
    FakeMessage::new(raw)
        .with_uid(uid)
        .with_internal_date("01-Jan-2020 00:00:00 +0000")
}

/// Logged commands after authentication, without the connection
/// housekeeping the client adds (CAPABILITY refreshes, LOGIN, LOGOUT).
pub fn mail_commands(server: &FakeImapServer) -> Vec<String> {
    server
        .log()
        .into_iter()
        .filter(|c| !matches!(c.name.as_str(), "CAPABILITY" | "LOGIN" | "LOGOUT"))
        .map(|c| c.line)
        .collect()
}

/// Every logged command line (including CAPABILITY), after LOGIN.
pub fn commands_after_login(server: &FakeImapServer) -> Vec<String> {
    let log = server.log();
    let start = log
        .iter()
        .position(|c| c.name == "LOGIN")
        .map_or(0, |i| i + 1);
    log[start..]
        .iter()
        .filter(|c| c.name != "LOGOUT")
        .map(|c| c.line.clone())
        .collect()
}

/// UID sets of every `UID FETCH` command, in order.
pub fn fetch_sets(server: &FakeImapServer) -> Vec<String> {
    server
        .log()
        .into_iter()
        .filter(|c| c.name == "UID FETCH")
        .map(|c| {
            c.line
                .split_whitespace()
                .nth(2)
                .unwrap_or_default()
                .to_string()
        })
        .collect()
}

/// Item lists of every `UID FETCH` command, in order.
pub fn fetch_items(server: &FakeImapServer) -> Vec<String> {
    server
        .log()
        .into_iter()
        .filter(|c| c.name == "UID FETCH")
        .map(|c| c.line.splitn(4, ' ').nth(3).unwrap_or_default().to_string())
        .collect()
}

/// Lines of a given command name.
pub fn lines_named(server: &FakeImapServer, name: &str) -> Vec<String> {
    server
        .log()
        .into_iter()
        .filter(|c| c.name == name)
        .map(|c| c.line)
        .collect()
}
