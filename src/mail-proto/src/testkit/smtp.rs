//! Fake SMTP submission server (RFC 5321 subset, AUTH PLAIN/LOGIN,
//! STARTTLS). Compatible with `lettre`'s SMTP transport.

use std::sync::{Arc, Mutex};

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use native_tls::TlsAcceptor;

use super::{acceptor, lock, Failure, FailureQueue, LoggedCommand, ServerCore, TlsMode};
use crate::transport::Transport;

const MAX_LINE: usize = 1024 * 1024;
const MAX_MESSAGE: usize = 64 * 1024 * 1024;

/// One accepted message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceivedMail {
    /// Reverse path from `MAIL FROM:<...>` (without brackets).
    pub mail_from: String,
    /// `MAIL FROM` parameters such as `SMTPUTF8`, `BODY=8BITMIME`.
    pub mail_parameters: Vec<String>,
    /// Forward paths from accepted `RCPT TO:<...>` commands.
    pub rcpt_to: Vec<String>,
    /// Message data, dot-unstuffed, CRLF line endings.
    pub data: Vec<u8>,
    /// User that authenticated on the connection.
    pub authenticated_user: Option<String>,
    /// True when the session used TLS.
    pub tls: bool,
}

struct SmtpShared {
    users: Vec<(String, String)>,
    require_auth: bool,
    fail_auth: bool,
    extensions: Vec<String>,
    rejected_recipients: Vec<String>,
    tls: Option<TlsMode>,
    messages: Vec<ReceivedMail>,
    log: Vec<LoggedCommand>,
    failures: FailureQueue,
    connections: usize,
}

/// Builder for [`FakeSmtpServer`].
pub struct FakeSmtpBuilder {
    shared: SmtpShared,
}

impl FakeSmtpBuilder {
    /// Accept AUTH for this user; enables `require_auth`.
    pub fn credentials(mut self, user: &str, password: &str) -> Self {
        self.shared
            .users
            .push((user.to_string(), password.to_string()));
        self.shared.require_auth = true;
        self
    }

    /// Require AUTH before `MAIL` (default: true once credentials are set).
    pub fn require_auth(mut self, required: bool) -> Self {
        self.shared.require_auth = required;
        self
    }

    /// Reject every AUTH attempt with 535.
    pub fn fail_auth(mut self, fail: bool) -> Self {
        self.shared.fail_auth = fail;
        self
    }

    /// EHLO extensions (default `SIZE 35882577`, `8BITMIME`, `SMTPUTF8`,
    /// `AUTH PLAIN LOGIN`; `STARTTLS` is added when TLS is offered).
    pub fn extensions(mut self, extensions: &[&str]) -> Self {
        self.shared.extensions = extensions.iter().map(|e| e.to_string()).collect();
        self
    }

    /// Answer `RCPT TO` for this address with 550.
    pub fn reject_recipient(mut self, address: &str) -> Self {
        self.shared
            .rejected_recipients
            .push(address.to_ascii_lowercase());
        self
    }

    /// Offer TLS with the bundled test certificate.
    pub fn tls(mut self, mode: TlsMode) -> Self {
        self.shared.tls = Some(mode);
        self
    }

    /// Start serving.
    pub fn start(self) -> FakeSmtpServer {
        let tls = self.shared.tls;
        let state = Arc::new(Mutex::new(self.shared));
        let handler_state = Arc::clone(&state);
        let starttls = (tls == Some(TlsMode::StartTls)).then(acceptor);
        let core = ServerCore::spawn(
            "smtp",
            tls == Some(TlsMode::Implicit),
            move |transport, id| {
                SmtpSession {
                    transport,
                    id,
                    state: Arc::clone(&handler_state),
                    starttls: starttls.clone(),
                    greeted: false,
                    user: None,
                    transaction: None,
                }
                .run();
            },
        );
        FakeSmtpServer { core, state }
    }
}

/// A running fake SMTP server.
pub struct FakeSmtpServer {
    core: ServerCore,
    state: Arc<Mutex<SmtpShared>>,
}

impl FakeSmtpServer {
    /// Start building a server (no authentication required by default).
    pub fn builder() -> FakeSmtpBuilder {
        FakeSmtpBuilder {
            shared: SmtpShared {
                users: Vec::new(),
                require_auth: false,
                fail_auth: false,
                extensions: ["SIZE 35882577", "8BITMIME", "SMTPUTF8", "AUTH PLAIN LOGIN"]
                    .iter()
                    .map(|e| e.to_string())
                    .collect(),
                rejected_recipients: Vec::new(),
                tls: None,
                messages: Vec::new(),
                log: Vec::new(),
                failures: FailureQueue::default(),
                connections: 0,
            },
        }
    }

    pub fn host(&self) -> &'static str {
        "127.0.0.1"
    }

    pub fn port(&self) -> u16 {
        self.core.addr().port()
    }

    /// Messages accepted so far.
    pub fn messages(&self) -> Vec<ReceivedMail> {
        lock(&self.state).messages.clone()
    }

    /// Logged command lines (AUTH data redacted).
    pub fn commands(&self) -> Vec<String> {
        lock(&self.state)
            .log
            .iter()
            .map(|c| c.line.clone())
            .collect()
    }

    /// Logged command verbs (`EHLO`, `AUTH`, `MAIL`, `RCPT`, `DATA`, ...).
    pub fn command_names(&self) -> Vec<String> {
        lock(&self.state)
            .log
            .iter()
            .map(|c| c.name.clone())
            .collect()
    }

    /// Number of accepted connections.
    pub fn connection_count(&self) -> usize {
        lock(&self.state).connections
    }

    /// Fail the next occurrence of a verb (`"MAIL"`, `"RCPT"`, `"DATA"`,
    /// `"AUTH"`, ...). For `DATA` the failure is applied after the message
    /// data was received (the final reply).
    pub fn fail_next(&self, command: &str, failure: Failure) {
        lock(&self.state).failures.push(command, failure);
    }
}

struct Transaction {
    mail_from: String,
    parameters: Vec<String>,
    rcpt_to: Vec<String>,
}

struct SmtpSession {
    transport: Transport,
    id: usize,
    state: Arc<Mutex<SmtpShared>>,
    starttls: Option<TlsAcceptor>,
    greeted: bool,
    user: Option<String>,
    transaction: Option<Transaction>,
}

/// Extract `addr` from `FROM:<addr> PARAMS` / `TO:<addr>`.
fn parse_path(argument: &str, prefix: &str) -> Option<(String, Vec<String>)> {
    let rest = argument.get(prefix.len()..)?;
    if !argument[..prefix.len()].eq_ignore_ascii_case(prefix) {
        return None;
    }
    let rest = rest.trim_start();
    let rest = rest.strip_prefix('<')?;
    let end = rest.find('>')?;
    let address = rest[..end].to_string();
    let parameters = rest[end + 1..]
        .split_whitespace()
        .map(str::to_string)
        .collect();
    Some((address, parameters))
}

fn failure_reply(failure: &Failure) -> Option<String> {
    match failure {
        Failure::No(text) => Some(format!("550 {text}")),
        Failure::Bad(text) => Some(format!("500 {text}")),
        Failure::Code(code, text) => Some(format!("{code} {text}")),
        Failure::Disconnect => None,
    }
}

impl SmtpSession {
    fn send(&mut self, line: &str) -> bool {
        self.transport
            .write_all(format!("{line}\r\n").as_bytes())
            .is_ok()
    }

    fn read_line(&mut self) -> Option<String> {
        self.transport
            .read_line(MAX_LINE)
            .ok()
            .map(|line| String::from_utf8_lossy(&line).into_owned())
    }

    fn run(mut self) {
        lock(&self.state).connections += 1;
        if !self.send("220 fake.smtp ESMTP ready") {
            return;
        }
        while let Some(line) = self.read_line() {
            let (verb, argument) = match line.split_once(' ') {
                Some((verb, argument)) => (verb.to_ascii_uppercase(), argument.trim().to_string()),
                None => (line.trim().to_ascii_uppercase(), String::new()),
            };
            let logged = if verb == "AUTH" {
                let mechanism = argument.split_whitespace().next().unwrap_or_default();
                format!("AUTH {mechanism} ****").trim_end().to_string()
            } else {
                line.clone()
            };
            let failure = {
                let mut state = lock(&self.state);
                state.log.push(LoggedCommand {
                    connection: self.id,
                    name: verb.clone(),
                    line: logged,
                });
                if verb == "DATA" {
                    None
                } else {
                    state.failures.take(&verb)
                }
            };
            let keep_going = match failure {
                Some(failure) => match failure_reply(&failure) {
                    Some(reply) => self.send(&reply),
                    None => false,
                },
                None => self.dispatch(&verb, &argument),
            };
            if !keep_going {
                break;
            }
        }
        self.transport.shutdown();
    }

    fn dispatch(&mut self, verb: &str, argument: &str) -> bool {
        match verb {
            "EHLO" => {
                self.greeted = true;
                self.transaction = None;
                let (mut extensions, tls) = {
                    let state = lock(&self.state);
                    (state.extensions.clone(), state.tls)
                };
                if tls == Some(TlsMode::StartTls) && !self.transport.is_tls() {
                    extensions.push("STARTTLS".to_string());
                }
                let mut reply = String::new();
                let greeting = format!("fake.smtp Hello {argument}");
                let lines: Vec<&str> = std::iter::once(greeting.as_str())
                    .chain(extensions.iter().map(String::as_str))
                    .collect();
                for (index, line) in lines.iter().enumerate() {
                    let separator = if index + 1 == lines.len() { ' ' } else { '-' };
                    reply.push_str(&format!("250{separator}{line}\r\n"));
                }
                self.transport.write_all(reply.as_bytes()).is_ok()
            }
            "HELO" => {
                self.greeted = true;
                self.transaction = None;
                self.send("250 fake.smtp")
            }
            "STARTTLS" => match self.starttls.clone() {
                Some(acceptor) if !self.transport.is_tls() => {
                    if !self.send("220 2.0.0 Ready to start TLS") {
                        return false;
                    }
                    self.greeted = false;
                    self.user = None;
                    self.transaction = None;
                    self.transport.accept_tls(&acceptor).is_ok()
                }
                _ => self.send("502 5.5.1 STARTTLS not available"),
            },
            "AUTH" => self.auth(argument),
            "MAIL" => {
                if !self.greeted {
                    return self.send("503 5.5.1 Send EHLO first");
                }
                let require_auth = lock(&self.state).require_auth;
                if require_auth && self.user.is_none() {
                    return self.send("530 5.7.0 Authentication required");
                }
                match parse_path(argument, "FROM:") {
                    Some((mail_from, parameters)) => {
                        self.transaction = Some(Transaction {
                            mail_from,
                            parameters,
                            rcpt_to: Vec::new(),
                        });
                        self.send("250 2.1.0 Sender OK")
                    }
                    None => self.send("501 5.5.4 Syntax: MAIL FROM:<address>"),
                }
            }
            "RCPT" => {
                if self.transaction.is_none() {
                    return self.send("503 5.5.1 Need MAIL command");
                }
                match parse_path(argument, "TO:") {
                    Some((address, _)) => {
                        let rejected = lock(&self.state)
                            .rejected_recipients
                            .contains(&address.to_ascii_lowercase());
                        if rejected {
                            return self.send("550 5.1.1 Recipient rejected");
                        }
                        self.transaction
                            .as_mut()
                            .expect("transaction")
                            .rcpt_to
                            .push(address);
                        self.send("250 2.1.5 Recipient OK")
                    }
                    None => self.send("501 5.5.4 Syntax: RCPT TO:<address>"),
                }
            }
            "DATA" => self.data(),
            "RSET" => {
                self.transaction = None;
                self.send("250 2.0.0 OK")
            }
            "NOOP" => self.send("250 2.0.0 OK"),
            "QUIT" => {
                self.send("221 2.0.0 Bye");
                false
            }
            _ => self.send("502 5.5.2 Command not recognized"),
        }
    }

    fn decode(&self, text: &str) -> Option<String> {
        BASE64
            .decode(text.trim())
            .ok()
            .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
    }

    fn challenge(&mut self, prompt: &str) -> Option<String> {
        if !self.send(&format!("334 {prompt}")) {
            return None;
        }
        self.read_line()
    }

    fn auth(&mut self, argument: &str) -> bool {
        if !self.greeted {
            return self.send("503 5.5.1 Send EHLO first");
        }
        if self.user.is_some() {
            return self.send("503 5.5.1 Already authenticated");
        }
        let mut words = argument.split_whitespace();
        let mechanism = words.next().unwrap_or_default().to_ascii_uppercase();
        let initial = words.next().map(str::to_string);
        let credentials = match mechanism.as_str() {
            "PLAIN" => {
                let response = match initial {
                    Some(initial) => initial,
                    None => match self.challenge("") {
                        Some(line) => line,
                        None => return false,
                    },
                };
                if response.trim() == "*" {
                    return self.send("501 5.7.0 Authentication cancelled");
                }
                self.decode(&response).and_then(|decoded| {
                    let fields: Vec<&str> = decoded.split('\0').collect();
                    (fields.len() == 3).then(|| (fields[1].to_string(), fields[2].to_string()))
                })
            }
            "LOGIN" => {
                let user = match initial {
                    Some(initial) => initial,
                    None => match self.challenge("VXNlcm5hbWU6") {
                        Some(line) => line,
                        None => return false,
                    },
                };
                if user.trim() == "*" {
                    return self.send("501 5.7.0 Authentication cancelled");
                }
                let password = match self.challenge("UGFzc3dvcmQ6") {
                    Some(line) => line,
                    None => return false,
                };
                if password.trim() == "*" {
                    return self.send("501 5.7.0 Authentication cancelled");
                }
                match (self.decode(&user), self.decode(&password)) {
                    (Some(user), Some(password)) => Some((user, password)),
                    _ => None,
                }
            }
            _ => return self.send("504 5.5.4 Unrecognized authentication type"),
        };
        let accepted = {
            let state = lock(&self.state);
            !state.fail_auth
                && credentials.as_ref().is_some_and(|(user, password)| {
                    state.users.iter().any(|(u, p)| u == user && p == password)
                })
        };
        if accepted {
            self.user = credentials.map(|(user, _)| user);
            self.send("235 2.7.0 Authentication successful")
        } else {
            self.send("535 5.7.8 Authentication credentials invalid")
        }
    }

    fn data(&mut self) -> bool {
        match &self.transaction {
            Some(transaction) if !transaction.rcpt_to.is_empty() => {}
            Some(_) => return self.send("554 5.5.1 No valid recipients"),
            None => return self.send("503 5.5.1 Need MAIL command"),
        }
        if !self.send("354 Start mail input; end with <CRLF>.<CRLF>") {
            return false;
        }
        let mut data = Vec::new();
        loop {
            let Ok(line) = self.transport.read_line(MAX_LINE) else {
                return false;
            };
            if line == b"." {
                break;
            }
            let content = if line.starts_with(b"..") {
                &line[1..]
            } else {
                &line[..]
            };
            if data.len() + content.len() > MAX_MESSAGE {
                return self.send("552 5.3.4 Message too big");
            }
            data.extend_from_slice(content);
            data.extend_from_slice(b"\r\n");
        }
        let transaction = self.transaction.take().expect("transaction");
        let failure = lock(&self.state).failures.take("DATA");
        if let Some(failure) = failure {
            return match failure_reply(&failure) {
                Some(reply) => self.send(&reply),
                None => false,
            };
        }
        let mail = ReceivedMail {
            mail_from: transaction.mail_from,
            mail_parameters: transaction.parameters,
            rcpt_to: transaction.rcpt_to,
            data,
            authenticated_user: self.user.clone(),
            tls: self.transport.is_tls(),
        };
        lock(&self.state).messages.push(mail);
        self.send("250 2.0.0 OK: queued")
    }
}
