//! In-memory mailbox credential sessions (port of `app/mail/sessions.py`).
//!
//! Passwords are held only in this process's memory. They are never written to
//! settings.json, mail-servers.json, logs, or any other file, so every backend
//! restart starts with an empty store and the user must unlock the account again.
//!
//! Python compared accounts by identity (`store.get(email) is not account`) to
//! detect that an account was locked or re-unlocked while a long operation was
//! running. Rust reproduces this with `Arc<MailAccount>` and [`SessionStore::is_current`].

use crate::error::{MailError, Result};
use crate::servers;
use indexmap::IndexMap;
use serde_json::{json, Value};
use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

/// Incoming mail protocol of an account. IMAP is full-featured; POP3 is a
/// compatibility mode (unlock, list and read INBOX only).
pub const PROTOCOL_IMAP: &str = "imap";
pub const PROTOCOL_POP3: &str = "pop3";

/// An unlocked account: connection attributes plus the in-memory password.
#[derive(Clone, PartialEq)]
pub struct MailAccount {
    pub email: String,
    pub password: String,
    pub incoming_server: String,
    pub incoming_port: u16,
    pub incoming_protocol: String,
    pub outgoing_server: String,
    pub outgoing_port: u16,
    pub outgoing_protocol: String,
    pub display_name: String,
    pub sender_profile_key: Option<String>,
    /// `"imap"` (default) or `"pop3"`.
    pub incoming_mail_protocol: String,
    pub unlocked_at: f64,
}

impl fmt::Debug for MailAccount {
    // Never print the password.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MailAccount")
            .field("email", &self.email)
            .field("password", &"<redacted>")
            .field("incoming_server", &self.incoming_server)
            .field("incoming_port", &self.incoming_port)
            .field("incoming_protocol", &self.incoming_protocol)
            .field("outgoing_server", &self.outgoing_server)
            .field("outgoing_port", &self.outgoing_port)
            .field("outgoing_protocol", &self.outgoing_protocol)
            .field("display_name", &self.display_name)
            .field("sender_profile_key", &self.sender_profile_key)
            .field("incoming_mail_protocol", &self.incoming_mail_protocol)
            .field("unlocked_at", &self.unlocked_at)
            .finish()
    }
}

impl MailAccount {
    /// Account with the Python dataclass defaults for optional fields.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        email: impl Into<String>,
        password: impl Into<String>,
        incoming_server: impl Into<String>,
        incoming_port: u16,
        incoming_protocol: impl Into<String>,
        outgoing_server: impl Into<String>,
        outgoing_port: u16,
        outgoing_protocol: impl Into<String>,
    ) -> Self {
        Self {
            email: email.into(),
            password: password.into(),
            incoming_server: incoming_server.into(),
            incoming_port,
            incoming_protocol: incoming_protocol.into(),
            outgoing_server: outgoing_server.into(),
            outgoing_port,
            outgoing_protocol: outgoing_protocol.into(),
            display_name: String::new(),
            sender_profile_key: None,
            incoming_mail_protocol: PROTOCOL_IMAP.into(),
            unlocked_at: now_epoch(),
        }
    }

    /// `'ssl'`, `'starttls'` or `'none'` for the incoming (IMAP/POP3) server.
    pub fn imap_security(&self) -> String {
        servers::normalize_protocol(&self.incoming_protocol, self.incoming_port)
    }

    /// `'ssl'`, `'starttls'` or `'none'` for the SMTP server.
    pub fn smtp_security(&self) -> String {
        servers::normalize_protocol(&self.outgoing_protocol, self.outgoing_port)
    }

    pub fn is_pop3(&self) -> bool {
        self.incoming_mail_protocol
            .eq_ignore_ascii_case(PROTOCOL_POP3)
    }

    /// Account details safe to expose - never includes the password.
    pub fn public_dict(&self) -> Value {
        json!({
            "email": self.email,
            "display_name": self.display_name,
            "incoming_server": self.incoming_server,
            "incoming_port": self.incoming_port,
            "incoming_protocol": self.incoming_protocol,
            "outgoing_server": self.outgoing_server,
            "outgoing_port": self.outgoing_port,
            "outgoing_protocol": self.outgoing_protocol,
            "incoming_mail_protocol": self.incoming_mail_protocol,
            "unlocked_at": self.unlocked_at,
        })
    }
}

pub fn now_epoch() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
}

/// Thread-safe map of account email -> MailAccount for this process.
///
/// Insertion-ordered like the Python dict: [`SessionStore::list`] returns the
/// accounts in first-unlock order; re-unlocking an account keeps its position
/// and forgetting one keeps the order of the others.
#[derive(Clone, Default)]
pub struct SessionStore {
    accounts: Arc<Mutex<IndexMap<String, Arc<MailAccount>>>>,
}

impl SessionStore {
    pub fn new() -> Self {
        Self::default()
    }

    fn key(email: &str) -> String {
        email.trim().to_lowercase()
    }

    pub fn unlock(&self, account: MailAccount) -> Arc<MailAccount> {
        let account = Arc::new(account);
        self.accounts
            .lock()
            .unwrap()
            .insert(Self::key(&account.email), account.clone());
        account
    }

    /// The unlocked account, or `MailError::CredentialRequired` (HTTP 401).
    pub fn require(&self, email: &str) -> Result<Arc<MailAccount>> {
        self.get(email)
            .ok_or_else(|| MailError::credential_required(email))
    }

    pub fn get(&self, email: &str) -> Option<Arc<MailAccount>> {
        self.accounts
            .lock()
            .unwrap()
            .get(&Self::key(email))
            .cloned()
    }

    /// True while `account` is still the very session object stored for its
    /// email (Python: `store.get(account.email) is account`).
    pub fn is_current(&self, account: &Arc<MailAccount>) -> bool {
        self.get(&account.email)
            .is_some_and(|current| Arc::ptr_eq(&current, account))
    }

    pub fn forget(&self, email: &str) -> bool {
        self.accounts
            .lock()
            .unwrap()
            .shift_remove(&Self::key(email))
            .is_some()
    }

    pub fn list(&self) -> Vec<Arc<MailAccount>> {
        self.accounts.lock().unwrap().values().cloned().collect()
    }

    pub fn clear(&self) {
        self.accounts.lock().unwrap().clear()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn account(email: &str) -> MailAccount {
        MailAccount::new(
            email,
            "secret",
            "imap.example.com",
            993,
            "SSL/TLS",
            "smtp.example.com",
            587,
            "STARTTLS",
        )
    }

    #[test]
    fn store_is_case_insensitive_and_identity_aware() {
        let store = SessionStore::new();
        assert!(
            matches!(store.require("a@b.c"), Err(MailError::CredentialRequired(e)) if e == "a@b.c")
        );
        let first = store.unlock(account("User@Example.com"));
        assert!(store.is_current(&first));
        assert!(store.get(" user@example.COM ").is_some());
        let second = store.unlock(account("user@example.com"));
        assert!(!store.is_current(&first));
        assert!(store.is_current(&second));
        assert_eq!(store.list().len(), 1);
        assert!(store.forget("USER@example.com"));
        assert!(!store.forget("user@example.com"));
        assert!(!store.is_current(&second));
    }

    #[test]
    fn list_keeps_python_dict_insertion_order() {
        let store = SessionStore::new();
        for email in ["c@example.com", "a@example.com", "b@example.com"] {
            store.unlock(account(email));
        }
        // Re-unlocking keeps the position; forgetting keeps the others' order.
        store.unlock(account("C@Example.com"));
        assert!(store.forget("a@example.com"));
        store.unlock(account("a@example.com"));
        let listed: Vec<String> = store.list().iter().map(|a| a.email.clone()).collect();
        assert_eq!(listed, ["C@Example.com", "b@example.com", "a@example.com"]);
    }

    #[test]
    fn public_dict_and_debug_hide_password() {
        let a = account("u@example.com");
        assert!(a.public_dict().get("password").is_none());
        assert!(!format!("{a:?}").contains("secret"));
        assert_eq!(a.imap_security(), "ssl");
        assert_eq!(a.smtp_security(), "starttls");
        assert!(!a.is_pop3());
    }
}
