//! Discover local IPv4 URLs that a bound listener can serve
//! (port of `backend/network.py`).
//!
//! Python resolved `socket.gethostname()` with `getaddrinfo(AF_INET)`. Rust's
//! standard library has no `gethostname`, so the host name comes from the
//! operating system's usual sources (`COMPUTERNAME` on Windows,
//! `/proc/sys/kernel/hostname`, `/etc/hostname` or `HOSTNAME` elsewhere) and
//! is resolved through [`ToSocketAddrs`]. No external lookup service is used.
//!
//! The extension backend binds loopback only, so in practice these helpers
//! return no URLs; they are kept for parity with the Python launcher.

use std::collections::BTreeSet;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, ToSocketAddrs};

/// Python `_lan_address`: a usable LAN IPv4 address, or `None` for invalid,
/// loopback, unspecified, multicast and limited-broadcast addresses.
pub fn lan_address(value: &str) -> Option<Ipv4Addr> {
    let address: Ipv4Addr = value.parse().ok()?;
    if address.is_loopback()
        || address.is_unspecified()
        || address.is_multicast()
        || address == Ipv4Addr::BROADCAST
    {
        return None;
    }
    Some(address)
}

/// The local host name, or `None` when it cannot be determined.
pub fn host_name() -> Option<String> {
    let from_env = |name: &str| {
        std::env::var(name)
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
    };
    if cfg!(windows) {
        return from_env("COMPUTERNAME");
    }
    for file in ["/proc/sys/kernel/hostname", "/etc/hostname"] {
        if let Ok(text) = std::fs::read_to_string(file) {
            let name = text.trim();
            if !name.is_empty() {
                return Some(name.to_string());
            }
        }
    }
    from_env("HOSTNAME")
}

fn resolve_host(host: &str) -> io::Result<Vec<IpAddr>> {
    Ok((host, 0)
        .to_socket_addrs()?
        .map(|address| address.ip())
        .collect())
}

/// Python `discover_lan_ipv4`: distinct local IPv4 addresses (including
/// virtual adapters), numerically sorted. Lookup failures yield `[]`.
pub fn discover_lan_ipv4() -> Vec<String> {
    discover_lan_ipv4_with(host_name(), resolve_host)
}

/// [`discover_lan_ipv4`] with an injectable host name and resolver.
pub fn discover_lan_ipv4_with(
    host: Option<String>,
    resolve: impl FnOnce(&str) -> io::Result<Vec<IpAddr>>,
) -> Vec<String> {
    let Some(host) = host else {
        return Vec::new();
    };
    let Ok(records) = resolve(&host) else {
        return Vec::new();
    };
    let addresses: BTreeSet<Ipv4Addr> = records
        .into_iter()
        .filter_map(|record| match record {
            IpAddr::V4(address) => lan_address(&address.to_string()),
            IpAddr::V6(_) => None,
        })
        .collect();
    addresses.iter().map(Ipv4Addr::to_string).collect()
}

/// Python `lan_urls_for_host`: LAN origins for a numeric bind address and port.
pub fn lan_urls_for_host(host: &str, port: u16) -> Vec<String> {
    lan_urls_for_host_with(host, port, discover_lan_ipv4)
}

/// [`lan_urls_for_host`] with an injectable interface discovery function.
pub fn lan_urls_for_host_with(
    host: &str,
    port: u16,
    discover: impl FnOnce() -> Vec<String>,
) -> Vec<String> {
    let addresses = if host == "0.0.0.0" {
        discover()
    } else {
        lan_address(host)
            .map(|address| vec![address.to_string()])
            .unwrap_or_default()
    };
    addresses
        .into_iter()
        .map(|address| format!("http://{address}:{port}"))
        .collect()
}

/// Python `lan_urls`: LAN origins reachable through a listener's actual
/// binding. Pass `listener.local_addr()` (std or tokio). Only an IPv4
/// wildcard listener serves every discovered interface; loopback and IPv6
/// listeners never advertise IPv4 addresses, and an unavailable address
/// yields `[]`.
pub fn lan_urls(local_addr: io::Result<SocketAddr>) -> Vec<String> {
    lan_urls_with(local_addr, discover_lan_ipv4)
}

/// [`lan_urls`] with an injectable interface discovery function.
pub fn lan_urls_with(
    local_addr: io::Result<SocketAddr>,
    discover: impl FnOnce() -> Vec<String>,
) -> Vec<String> {
    match local_addr {
        Ok(SocketAddr::V4(address)) => {
            lan_urls_for_host_with(&address.ip().to_string(), address.port(), discover)
        }
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    fn records(addresses: &[&str]) -> Vec<IpAddr> {
        addresses
            .iter()
            .map(|address| address.parse().unwrap())
            .collect()
    }

    #[test]
    fn discovery_lists_distinct_physical_and_virtual_interfaces() {
        let found = discover_lan_ipv4_with(Some("desktop".into()), |host| {
            assert_eq!(host, "desktop");
            Ok(records(&[
                "192.168.56.1",
                "192.168.1.156",
                "192.168.56.1",
                "10.0.0.10",
                "10.0.0.2",
                "169.254.1.2",
            ]))
        });
        assert_eq!(
            found,
            [
                "10.0.0.2",
                "10.0.0.10",
                "169.254.1.2",
                "192.168.1.156",
                "192.168.56.1"
            ]
        );
    }

    #[test]
    fn discovery_excludes_addresses_that_are_not_lan_interfaces() {
        let found = discover_lan_ipv4_with(Some("desktop".into()), |_| {
            Ok(records(&[
                "127.0.0.1",
                "127.0.0.2",
                "0.0.0.0",
                "224.0.0.1",
                "255.255.255.255",
                "192.168.1.156",
                "::1",
            ]))
        });
        assert_eq!(found, ["192.168.1.156"]);
        assert_eq!(lan_address("invalid"), None);
        assert_eq!(lan_address("01.2.3.4"), None);
    }

    #[test]
    fn discovery_lookup_failure_does_not_prevent_startup() {
        let failed = discover_lan_ipv4_with(Some("desktop".into()), |_| {
            Err(io::Error::new(io::ErrorKind::NotFound, "gaierror"))
        });
        assert!(failed.is_empty());
        assert!(discover_lan_ipv4_with(None, |_| unreachable!()).is_empty());
    }

    #[test]
    fn wildcard_listener_advertises_each_interface_at_actual_port() {
        let urls = lan_urls_with(Ok("0.0.0.0:4321".parse().unwrap()), || {
            vec!["192.168.1.156".into(), "192.168.56.1".into()]
        });
        assert_eq!(
            urls,
            ["http://192.168.1.156:4321", "http://192.168.56.1:4321"]
        );
    }

    #[test]
    fn explicit_interface_only_advertises_its_bound_address() {
        let called = Cell::new(false);
        let urls = lan_urls_with(Ok("192.168.56.1:9876".parse().unwrap()), || {
            called.set(true);
            Vec::new()
        });
        assert_eq!(urls, ["http://192.168.56.1:9876"]);
        assert!(!called.get());
    }

    #[test]
    fn loopback_and_ipv6_listeners_do_not_advertise_ipv4_interfaces() {
        let called = Cell::new(false);
        for address in [
            "127.0.0.1:8000",
            "127.0.0.2:8000",
            "[::]:8000",
            "[::1]:8000",
            "[fe80::1%12]:8000",
        ] {
            let urls = lan_urls_with(Ok(address.parse().unwrap()), || {
                called.set(true);
                Vec::new()
            });
            assert!(urls.is_empty(), "{address}");
        }
        assert!(!called.get());
    }

    #[test]
    fn unavailable_socket_address_returns_no_urls() {
        let error = io::Error::new(io::ErrorKind::NotConnected, "closed");
        assert!(lan_urls_with(Err(error), || unreachable!()).is_empty());
    }

    #[test]
    fn resolved_host_urls_match_listener_urls() {
        let discover = || vec!["192.168.1.156".to_string()];
        assert_eq!(
            lan_urls_for_host_with("0.0.0.0", 4321, discover),
            ["http://192.168.1.156:4321"]
        );
        assert_eq!(
            lan_urls_for_host_with("192.168.56.1", 9876, discover),
            ["http://192.168.56.1:9876"]
        );
        for host in ["127.0.0.1", "::", "fe80::1%12", "localhost"] {
            assert!(
                lan_urls_for_host_with(host, 8000, discover).is_empty(),
                "{host}"
            );
        }
    }
}
