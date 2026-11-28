//! Fake POP3 server (RFC 1939 subset plus CAPA and STLS).

use std::sync::{Arc, Mutex};

use native_tls::TlsAcceptor;

use super::{acceptor, crlf, lock, Failure, FailureQueue, LoggedCommand, ServerCore, TlsMode};
use crate::transport::Transport;

const MAX_LINE: usize = 64 * 1024;

#[derive(Debug, Clone)]
struct Pop3Message {
    uid: String,
    raw: Vec<u8>,
}

struct Pop3Shared {
    users: Vec<(String, String)>,
    capabilities: Vec<String>,
    tls: Option<TlsMode>,
    messages: Vec<Pop3Message>,
    next_uid: u32,
    log: Vec<LoggedCommand>,
    failures: FailureQueue,
    connections: usize,
}

impl Pop3Shared {
    fn add(&mut self, raw: Vec<u8>, uid: Option<String>) -> String {
        let uid = uid.unwrap_or_else(|| {
            self.next_uid += 1;
            format!("uid-{}", self.next_uid)
        });
        self.messages.push(Pop3Message {
            uid: uid.clone(),
            raw: crlf(&raw),
        });
        uid
    }
}

/// Builder for [`FakePop3Server`].
pub struct FakePop3Builder {
    shared: Pop3Shared,
}

impl FakePop3Builder {
    /// Accept `USER`/`PASS` for this user (may be called repeatedly).
    pub fn credentials(mut self, user: &str, password: &str) -> Self {
        self.shared
            .users
            .push((user.to_string(), password.to_string()));
        self
    }

    /// `CAPA` lines (default `USER UIDL TOP`; `STLS` is added when TLS is
    /// offered).
    pub fn capabilities(mut self, capabilities: &[&str]) -> Self {
        self.shared.capabilities = capabilities.iter().map(|c| c.to_string()).collect();
        self
    }

    /// Offer TLS with the bundled test certificate.
    pub fn tls(mut self, mode: TlsMode) -> Self {
        self.shared.tls = Some(mode);
        self
    }

    /// Add a message with an automatic unique-id (`uid-1`, `uid-2`, ...).
    pub fn message(mut self, raw: impl Into<Vec<u8>>) -> Self {
        self.shared.add(raw.into(), None);
        self
    }

    /// Add a message with an explicit unique-id.
    pub fn message_with_uid(mut self, raw: impl Into<Vec<u8>>, uid: &str) -> Self {
        self.shared.add(raw.into(), Some(uid.to_string()));
        self
    }

    /// Start serving.
    pub fn start(self) -> FakePop3Server {
        let tls = self.shared.tls;
        let state = Arc::new(Mutex::new(self.shared));
        let handler_state = Arc::clone(&state);
        let stls = (tls == Some(TlsMode::StartTls)).then(acceptor);
        let core = ServerCore::spawn(
            "pop3",
            tls == Some(TlsMode::Implicit),
            move |transport, id| {
                Pop3Session {
                    transport,
                    id,
                    state: Arc::clone(&handler_state),
                    stls: stls.clone(),
                    user: None,
                    snapshot: None,
                    deleted: Vec::new(),
                }
                .run();
            },
        );
        FakePop3Server { core, state }
    }
}

/// A running fake POP3 server.
pub struct FakePop3Server {
    core: ServerCore,
    state: Arc<Mutex<Pop3Shared>>,
}

impl FakePop3Server {
    /// Start building a server with an empty maildrop.
    pub fn builder() -> FakePop3Builder {
        FakePop3Builder {
            shared: Pop3Shared {
                users: Vec::new(),
                capabilities: ["USER", "UIDL", "TOP"]
                    .iter()
                    .map(|c| c.to_string())
                    .collect(),
                tls: None,
                messages: Vec::new(),
                next_uid: 0,
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

    /// Raw messages currently in the maildrop (CRLF normalized).
    pub fn messages(&self) -> Vec<Vec<u8>> {
        lock(&self.state)
            .messages
            .iter()
            .map(|m| m.raw.clone())
            .collect()
    }

    /// Unique-ids currently in the maildrop.
    pub fn uids(&self) -> Vec<String> {
        lock(&self.state)
            .messages
            .iter()
            .map(|m| m.uid.clone())
            .collect()
    }

    /// Add a message while running; returns its unique-id.
    pub fn add_message(&self, raw: impl Into<Vec<u8>>) -> String {
        lock(&self.state).add(raw.into(), None)
    }

    /// Logged command lines (`PASS` redacted).
    pub fn commands(&self) -> Vec<String> {
        lock(&self.state)
            .log
            .iter()
            .map(|c| c.line.clone())
            .collect()
    }

    /// Logged command names.
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

    /// Fail the next occurrence of `command` (e.g. `"RETR"`, `"PASS"`).
    pub fn fail_next(&self, command: &str, failure: Failure) {
        lock(&self.state).failures.push(command, failure);
    }
}

struct Pop3Session {
    transport: Transport,
    id: usize,
    state: Arc<Mutex<Pop3Shared>>,
    stls: Option<TlsAcceptor>,
    user: Option<String>,
    /// Messages visible in the TRANSACTION state (snapshot at login).
    snapshot: Option<Vec<Pop3Message>>,
    deleted: Vec<bool>,
}

impl Pop3Session {
    fn send(&mut self, line: &str) -> bool {
        self.transport
            .write_all(format!("{line}\r\n").as_bytes())
            .is_ok()
    }

    fn send_multiline(&mut self, status: &str, body: &[u8]) -> bool {
        let mut out = format!("+OK {status}\r\n").into_bytes();
        for line in body.split_inclusive(|&b| b == b'\n') {
            if line.starts_with(b".") {
                out.push(b'.');
            }
            out.extend_from_slice(line);
            if !line.ends_with(b"\n") {
                out.extend_from_slice(b"\r\n");
            }
        }
        out.extend_from_slice(b".\r\n");
        self.transport.write_all(&out).is_ok()
    }

    fn run(mut self) {
        lock(&self.state).connections += 1;
        if !self.send("+OK Fake POP3 server ready <1896.697170952@fake.pop3>") {
            return;
        }
        while let Ok(line) = self.transport.read_line(MAX_LINE) {
            let text = String::from_utf8_lossy(&line).into_owned();
            let mut words = text.split_whitespace();
            let command = words.next().unwrap_or_default().to_ascii_uppercase();
            let args: Vec<String> = words.map(str::to_string).collect();
            let logged = if command == "PASS" {
                "PASS ****".to_string()
            } else {
                text.clone()
            };
            let failure = {
                let mut state = lock(&self.state);
                state.log.push(LoggedCommand {
                    connection: self.id,
                    name: command.clone(),
                    line: logged,
                });
                state.failures.take(&command)
            };
            let keep_going = match failure {
                Some(Failure::Disconnect) => false,
                Some(Failure::No(text) | Failure::Bad(text) | Failure::Code(_, text)) => {
                    self.send(&format!("-ERR {text}"))
                }
                None => self.dispatch(&command, &args),
            };
            if !keep_going {
                break;
            }
        }
        self.transport.shutdown();
    }

    fn message_index(&self, arg: Option<&String>) -> Option<usize> {
        let number: usize = arg?.parse().ok()?;
        let snapshot = self.snapshot.as_ref()?;
        (number >= 1 && number <= snapshot.len() && !self.deleted[number - 1]).then(|| number - 1)
    }

    fn dispatch(&mut self, command: &str, args: &[String]) -> bool {
        match command {
            "CAPA" => {
                let (mut caps, tls) = {
                    let state = lock(&self.state);
                    (state.capabilities.clone(), state.tls)
                };
                if tls == Some(TlsMode::StartTls) && !self.transport.is_tls() {
                    caps.push("STLS".to_string());
                }
                let body = caps.iter().map(|c| format!("{c}\r\n")).collect::<String>();
                self.send_multiline("Capability list follows", body.as_bytes())
            }
            "QUIT" => {
                if let Some(snapshot) = self.snapshot.take() {
                    let removed: Vec<String> = snapshot
                        .iter()
                        .zip(&self.deleted)
                        .filter(|(_, deleted)| **deleted)
                        .map(|(m, _)| m.uid.clone())
                        .collect();
                    lock(&self.state)
                        .messages
                        .retain(|m| !removed.contains(&m.uid));
                }
                self.send("+OK Fake POP3 server signing off");
                false
            }
            "NOOP" if self.snapshot.is_some() => self.send("+OK"),
            "STLS" => match self.stls.clone() {
                Some(acceptor) if !self.transport.is_tls() && self.snapshot.is_none() => {
                    self.send("+OK Begin TLS negotiation")
                        && self.transport.accept_tls(&acceptor).is_ok()
                }
                _ => self.send("-ERR STLS not available"),
            },
            "USER" if self.snapshot.is_none() => match args.first() {
                Some(user) => {
                    self.user = Some(user.clone());
                    self.send("+OK User accepted")
                }
                None => self.send("-ERR Missing user name"),
            },
            "PASS" if self.snapshot.is_none() => {
                let password = args.join(" ");
                let Some(user) = self.user.take() else {
                    return self.send("-ERR USER first");
                };
                let state = lock(&self.state);
                let ok = state
                    .users
                    .iter()
                    .any(|(u, p)| *u == user && *p == password);
                if ok {
                    let snapshot = state.messages.clone();
                    drop(state);
                    self.deleted = vec![false; snapshot.len()];
                    self.snapshot = Some(snapshot);
                    self.send("+OK Logged in")
                } else {
                    drop(state);
                    self.send("-ERR [AUTH] Invalid credentials")
                }
            }
            _ if self.snapshot.is_none() => self.send("-ERR Unknown command or not authenticated"),
            "STAT" => {
                let (count, size) = self
                    .visible()
                    .fold((0, 0), |(c, s), (_, m)| (c + 1, s + m.raw.len()));
                self.send(&format!("+OK {count} {size}"))
            }
            "LIST" | "UIDL" => {
                let describe = |number: usize, message: &Pop3Message| {
                    if command == "LIST" {
                        format!("{number} {}", message.raw.len())
                    } else {
                        format!("{number} {}", message.uid)
                    }
                };
                if args.is_empty() {
                    let body: String = self
                        .visible()
                        .map(|(i, m)| format!("{}\r\n", describe(i + 1, m)))
                        .collect();
                    let count = self.visible().count();
                    self.send_multiline(&format!("{count} messages"), body.as_bytes())
                } else {
                    match self.message_index(args.first()) {
                        Some(index) => {
                            let line = describe(
                                index + 1,
                                &self.snapshot.as_ref().expect("snapshot")[index],
                            );
                            self.send(&format!("+OK {line}"))
                        }
                        None => self.send("-ERR No such message"),
                    }
                }
            }
            "RETR" | "TOP" => {
                let Some(index) = self.message_index(args.first()) else {
                    return self.send("-ERR No such message");
                };
                let raw = self.snapshot.as_ref().expect("snapshot")[index].raw.clone();
                if command == "RETR" {
                    return self.send_multiline(&format!("{} octets", raw.len()), &raw);
                }
                let Some(lines) = args.get(1).and_then(|n| n.parse::<usize>().ok()) else {
                    return self.send("-ERR TOP expects a line count");
                };
                let split = raw
                    .windows(4)
                    .position(|w| w == b"\r\n\r\n")
                    .map_or(raw.len(), |i| i + 4);
                let mut out = raw[..split].to_vec();
                out.extend(
                    raw[split..]
                        .split_inclusive(|&b| b == b'\n')
                        .take(lines)
                        .flatten(),
                );
                self.send_multiline("Top of message follows", &out)
            }
            "DELE" => match self.message_index(args.first()) {
                Some(index) => {
                    self.deleted[index] = true;
                    self.send(&format!("+OK Message {} deleted", index + 1))
                }
                None => self.send("-ERR No such message"),
            },
            "RSET" => {
                self.deleted.iter_mut().for_each(|d| *d = false);
                self.send("+OK")
            }
            _ => self.send("-ERR Unknown command"),
        }
    }

    fn visible(&self) -> impl Iterator<Item = (usize, &Pop3Message)> {
        self.snapshot
            .iter()
            .flatten()
            .enumerate()
            .filter(|(i, _)| !self.deleted[*i])
    }
}
