//! Host name resolution that survives short DNS outages.
//!
//! Every mail operation opens a fresh connection (like the original
//! `imaplib`/`smtplib` code), so every operation needs a DNS answer. On
//! networks whose resolver hands out a TTL of 0 nothing is cached by the OS,
//! and one dropped DNS reply used to surface as
//! `Could not connect to host:port: No such host is known. (os error 11001)`.
//!
//! [`resolve`] therefore:
//!
//! 1. asks the system resolver, retrying a failed lookup twice
//!    ([`RETRY_DELAYS`], under one second in total);
//! 2. remembers the addresses of every successful lookup in memory;
//! 3. when all attempts fail, falls back to the addresses that worked for the
//!    same `host:port` within the last [`FALLBACK_TTL`].
//!
//! The fallback only ever reuses an answer the system resolver gave this
//! process earlier, and TLS still verifies the certificate against the host
//! name. IP literals are returned directly. Intentional deviation: Python's
//! `socket.create_connection` fails on the first resolver error.

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};

/// Pauses before the second and third lookup attempt.
pub const RETRY_DELAYS: [Duration; 2] = [Duration::from_millis(200), Duration::from_millis(600)];
/// How long a successful answer may stand in for a failing resolver.
pub const FALLBACK_TTL: Duration = Duration::from_secs(60 * 60);
/// Remembered `host:port` pairs (the oldest is dropped beyond this).
const MAX_ENTRIES: usize = 64;

type Key = (String, u16);

/// Last successful answers, keyed by lowercased host and port.
#[derive(Default)]
struct Resolver {
    known: HashMap<Key, (Instant, Vec<SocketAddr>)>,
}

impl Resolver {
    fn remember(&mut self, key: Key, now: Instant, addrs: &[SocketAddr]) {
        if self.known.len() >= MAX_ENTRIES && !self.known.contains_key(&key) {
            let oldest = self
                .known
                .iter()
                .min_by_key(|(_, (at, _))| *at)
                .map(|(key, _)| key.clone());
            if let Some(oldest) = oldest {
                self.known.remove(&oldest);
            }
        }
        self.known.insert(key, (now, addrs.to_vec()));
    }

    fn recall(&mut self, key: &Key, now: Instant) -> Option<Vec<SocketAddr>> {
        match self.known.get(key) {
            Some((at, addrs)) if now.saturating_duration_since(*at) <= FALLBACK_TTL => {
                Some(addrs.clone())
            }
            Some(_) => {
                self.known.remove(key);
                None
            }
            None => None,
        }
    }
}

static RESOLVER: LazyLock<Mutex<Resolver>> = LazyLock::new(Mutex::default);

fn system_lookup(host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
    Ok((host, port).to_socket_addrs()?.collect())
}

/// Resolve `host:port` with retries and the last-known-good fallback.
///
/// An empty `Ok` list means the resolver answered without addresses and no
/// earlier answer is known; callers report that like a failed lookup.
pub fn resolve(host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
    resolve_with(
        &RESOLVER,
        host,
        port,
        system_lookup,
        std::thread::sleep,
        Instant::now,
    )
}

fn resolve_with(
    resolver: &Mutex<Resolver>,
    host: &str,
    port: u16,
    mut lookup: impl FnMut(&str, u16) -> io::Result<Vec<SocketAddr>>,
    mut sleep: impl FnMut(Duration),
    mut now: impl FnMut() -> Instant,
) -> io::Result<Vec<SocketAddr>> {
    // Address literals need no resolver.
    if let Ok(address) = host.parse::<IpAddr>() {
        return Ok(vec![SocketAddr::new(address, port)]);
    }

    let key: Key = (host.to_ascii_lowercase(), port);
    let mut outcome = lookup(host, port);
    for delay in RETRY_DELAYS {
        if matches!(&outcome, Ok(addrs) if !addrs.is_empty()) {
            break;
        }
        sleep(delay);
        outcome = lookup(host, port);
    }

    let mut resolver = resolver
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    match outcome {
        Ok(addrs) if !addrs.is_empty() => {
            resolver.remember(key, now(), &addrs);
            Ok(addrs)
        }
        failed => match resolver.recall(&key, now()) {
            Some(addrs) => Ok(addrs),
            None => failed,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};

    fn addr(text: &str) -> SocketAddr {
        text.parse().unwrap()
    }

    fn not_found() -> io::Error {
        io::Error::other("No such host is known. (os error 11001)")
    }

    /// Run `resolve_with` over scripted lookup answers; returns the result,
    /// the number of lookups and the sleeps.
    fn run(
        resolver: &Mutex<Resolver>,
        host: &str,
        answers: Vec<io::Result<Vec<SocketAddr>>>,
        now: Instant,
    ) -> (io::Result<Vec<SocketAddr>>, usize, Vec<Duration>) {
        let answers = RefCell::new(answers.into_iter());
        let calls = Cell::new(0);
        let sleeps = RefCell::new(Vec::new());
        let result = resolve_with(
            resolver,
            host,
            993,
            |_, _| {
                calls.set(calls.get() + 1);
                answers.borrow_mut().next().expect("unexpected lookup")
            },
            |delay| sleeps.borrow_mut().push(delay),
            || now,
        );
        (result, calls.get(), sleeps.into_inner())
    }

    #[test]
    fn first_answer_is_used_without_delay() {
        let resolver = Mutex::default();
        let (result, calls, sleeps) = run(
            &resolver,
            "imap.example.com",
            vec![Ok(vec![addr("192.0.2.1:993")])],
            Instant::now(),
        );
        assert_eq!(result.unwrap(), vec![addr("192.0.2.1:993")]);
        assert_eq!(calls, 1);
        assert!(sleeps.is_empty());
    }

    #[test]
    fn transient_failure_is_retried() {
        let resolver = Mutex::default();
        let (result, calls, sleeps) = run(
            &resolver,
            "imap.example.com",
            vec![
                Err(not_found()),
                Ok(vec![]),
                Ok(vec![addr("192.0.2.1:993")]),
            ],
            Instant::now(),
        );
        assert_eq!(result.unwrap(), vec![addr("192.0.2.1:993")]);
        assert_eq!(calls, 3);
        assert_eq!(sleeps, RETRY_DELAYS.to_vec());
    }

    #[test]
    fn unknown_host_keeps_the_resolver_error() {
        let resolver = Mutex::default();
        let (result, calls, _) = run(
            &resolver,
            "typo.example.com",
            vec![Err(not_found()), Err(not_found()), Err(not_found())],
            Instant::now(),
        );
        assert!(result.unwrap_err().to_string().contains("No such host"));
        assert_eq!(calls, 3);
    }

    #[test]
    fn outage_falls_back_to_the_last_good_answer_until_it_expires() {
        let resolver = Mutex::default();
        let start = Instant::now();
        let good = vec![addr("192.0.2.1:993"), addr("[2001:db8::1]:993")];
        let _ = run(&resolver, "IMAP.example.com", vec![Ok(good.clone())], start);

        let down = || vec![Err(not_found()), Err(not_found()), Err(not_found())];
        // Same host in another case, within the hour: last answer is reused.
        let (result, _, _) = run(
            &resolver,
            "imap.example.com",
            down(),
            start + FALLBACK_TTL - Duration::from_secs(1),
        );
        assert_eq!(result.unwrap(), good);
        // Another port or host has no fallback.
        let other = resolve_with(
            &resolver,
            "imap.example.com",
            143,
            |_, _| Err(not_found()),
            |_| {},
            || start,
        );
        assert!(other.is_err());
        // Past the TTL the answer is forgotten.
        let (result, _, _) = run(
            &resolver,
            "imap.example.com",
            down(),
            start + FALLBACK_TTL + Duration::from_secs(1),
        );
        assert!(result.is_err());
        assert!(resolver.lock().unwrap().known.is_empty());
    }

    #[test]
    fn a_new_answer_replaces_the_remembered_one() {
        let resolver = Mutex::default();
        let start = Instant::now();
        let _ = run(
            &resolver,
            "imap.example.com",
            vec![Ok(vec![addr("192.0.2.1:993")])],
            start,
        );
        let _ = run(
            &resolver,
            "imap.example.com",
            vec![Ok(vec![addr("192.0.2.2:993")])],
            start,
        );
        let (result, _, _) = run(
            &resolver,
            "imap.example.com",
            vec![Err(not_found()), Err(not_found()), Err(not_found())],
            start,
        );
        assert_eq!(result.unwrap(), vec![addr("192.0.2.2:993")]);
    }

    #[test]
    fn ip_literals_skip_the_resolver() {
        let resolver = Mutex::default();
        for (host, expected) in [("127.0.0.1", "127.0.0.1:993"), ("::1", "[::1]:993")] {
            let (result, calls, _) = run(&resolver, host, vec![], Instant::now());
            assert_eq!(result.unwrap(), vec![addr(expected)]);
            assert_eq!(calls, 0);
        }
        assert!(resolver.lock().unwrap().known.is_empty());
    }

    #[test]
    fn the_memory_is_bounded() {
        let resolver = Mutex::default();
        let start = Instant::now();
        for index in 0..(MAX_ENTRIES + 5) {
            let _ = run(
                &resolver,
                &format!("host{index}.example.com"),
                vec![Ok(vec![addr("192.0.2.1:993")])],
                start + Duration::from_secs(index as u64),
            );
        }
        let resolver = resolver.lock().unwrap();
        assert_eq!(resolver.known.len(), MAX_ENTRIES);
        assert!(!resolver
            .known
            .contains_key(&("host0.example.com".to_string(), 993)));
    }

    #[test]
    fn localhost_resolves_through_the_system() {
        let addrs = resolve("localhost", 993).unwrap();
        assert!(addrs.iter().all(|addr| addr.ip().is_loopback()));
        assert!(!addrs.is_empty());
    }
}
