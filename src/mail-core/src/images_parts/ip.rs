//! The parts of Python's `ipaddress` module the image code relies on
//! (`ip_address()` parsing, `compressed`, and the `is_*` properties as of
//! Python 3.13/3.14, where IPv4-mapped IPv6 addresses delegate to their IPv4
//! address).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// `(network, prefix length)` pairs.
type V4Net = (u32, u32);
type V6Net = (u128, u32);

const fn v4(a: u8, b: u8, c: u8, d: u8) -> u32 {
    u32::from_be_bytes([a, b, c, d])
}

const fn v6(segments: [u16; 8]) -> u128 {
    let mut value = 0u128;
    let mut index = 0;
    while index < 8 {
        value = (value << 16) | segments[index] as u128;
        index += 1;
    }
    value
}

/// `_IPv4Constants._private_networks`.
const V4_PRIVATE: [V4Net; 14] = [
    (v4(0, 0, 0, 0), 8),
    (v4(10, 0, 0, 0), 8),
    (v4(127, 0, 0, 0), 8),
    (v4(169, 254, 0, 0), 16),
    (v4(172, 16, 0, 0), 12),
    (v4(192, 0, 0, 0), 24),
    (v4(192, 0, 0, 170), 31),
    (v4(192, 0, 2, 0), 24),
    (v4(192, 168, 0, 0), 16),
    (v4(198, 18, 0, 0), 15),
    (v4(198, 51, 100, 0), 24),
    (v4(203, 0, 113, 0), 24),
    (v4(240, 0, 0, 0), 4),
    (v4(255, 255, 255, 255), 32),
];
/// `_IPv4Constants._private_networks_exceptions`.
const V4_PRIVATE_EXCEPTIONS: [V4Net; 2] = [(v4(192, 0, 0, 9), 32), (v4(192, 0, 0, 10), 32)];
/// `_IPv4Constants._public_network` (shared address space).
const V4_SHARED: V4Net = (v4(100, 64, 0, 0), 10);
const V4_MULTICAST: V4Net = (v4(224, 0, 0, 0), 4);
const V4_RESERVED: V4Net = (v4(240, 0, 0, 0), 4);

/// `_IPv6Constants._private_networks`.
const V6_PRIVATE: [V6Net; 11] = [
    (v6([0, 0, 0, 0, 0, 0, 0, 1]), 128),
    (v6([0, 0, 0, 0, 0, 0, 0, 0]), 128),
    (v6([0, 0, 0, 0, 0, 0xffff, 0, 0]), 96),
    (v6([0x64, 0xff9b, 1, 0, 0, 0, 0, 0]), 48),
    (v6([0x100, 0, 0, 0, 0, 0, 0, 0]), 64),
    (v6([0x2001, 0, 0, 0, 0, 0, 0, 0]), 23),
    (v6([0x2001, 0xdb8, 0, 0, 0, 0, 0, 0]), 32),
    (v6([0x2002, 0, 0, 0, 0, 0, 0, 0]), 16),
    (v6([0x3fff, 0, 0, 0, 0, 0, 0, 0]), 20),
    (v6([0xfc00, 0, 0, 0, 0, 0, 0, 0]), 7),
    (v6([0xfe80, 0, 0, 0, 0, 0, 0, 0]), 10),
];
/// `_IPv6Constants._private_networks_exceptions`.
const V6_PRIVATE_EXCEPTIONS: [V6Net; 6] = [
    (v6([0x2001, 1, 0, 0, 0, 0, 0, 1]), 128),
    (v6([0x2001, 1, 0, 0, 0, 0, 0, 2]), 128),
    (v6([0x2001, 3, 0, 0, 0, 0, 0, 0]), 32),
    (v6([0x2001, 4, 0x112, 0, 0, 0, 0, 0]), 48),
    (v6([0x2001, 0x20, 0, 0, 0, 0, 0, 0]), 28),
    (v6([0x2001, 0x30, 0, 0, 0, 0, 0, 0]), 28),
];
/// `_IPv6Constants._reserved_networks`.
const V6_RESERVED: [V6Net; 15] = [
    (v6([0, 0, 0, 0, 0, 0, 0, 0]), 8),
    (v6([0x100, 0, 0, 0, 0, 0, 0, 0]), 8),
    (v6([0x200, 0, 0, 0, 0, 0, 0, 0]), 7),
    (v6([0x400, 0, 0, 0, 0, 0, 0, 0]), 6),
    (v6([0x800, 0, 0, 0, 0, 0, 0, 0]), 5),
    (v6([0x1000, 0, 0, 0, 0, 0, 0, 0]), 4),
    (v6([0x4000, 0, 0, 0, 0, 0, 0, 0]), 3),
    (v6([0x6000, 0, 0, 0, 0, 0, 0, 0]), 3),
    (v6([0x8000, 0, 0, 0, 0, 0, 0, 0]), 3),
    (v6([0xa000, 0, 0, 0, 0, 0, 0, 0]), 3),
    (v6([0xc000, 0, 0, 0, 0, 0, 0, 0]), 3),
    (v6([0xe000, 0, 0, 0, 0, 0, 0, 0]), 4),
    (v6([0xf000, 0, 0, 0, 0, 0, 0, 0]), 5),
    (v6([0xf800, 0, 0, 0, 0, 0, 0, 0]), 6),
    (v6([0xfe00, 0, 0, 0, 0, 0, 0, 0]), 9),
];
const V6_SITE_LOCAL: V6Net = (v6([0xfec0, 0, 0, 0, 0, 0, 0, 0]), 10);
const V6_MULTICAST: V6Net = (v6([0xff00, 0, 0, 0, 0, 0, 0, 0]), 8);
/// remote_images.py `_blocked_ipv6` (NAT64, Teredo and 6to4 transition
/// prefixes that can embed private IPv4 destinations).
const V6_BLOCKED: [V6Net; 4] = [
    (v6([0x64, 0xff9b, 0, 0, 0, 0, 0, 0]), 96),
    (v6([0x64, 0xff9b, 1, 0, 0, 0, 0, 0]), 48),
    (v6([0x2001, 0, 0, 0, 0, 0, 0, 0]), 32),
    (v6([0x2002, 0, 0, 0, 0, 0, 0, 0]), 16),
];

fn in_v4(ip: u32, (network, prefix): V4Net) -> bool {
    prefix == 0 || (ip ^ network) >> (32 - prefix) == 0
}

fn in_v6(ip: u128, (network, prefix): V6Net) -> bool {
    prefix == 0 || (ip ^ network) >> (128 - prefix) == 0
}

fn v4_is_private(ip: Ipv4Addr) -> bool {
    let ip = u32::from(ip);
    V4_PRIVATE.iter().any(|net| in_v4(ip, *net))
        && V4_PRIVATE_EXCEPTIONS.iter().all(|net| !in_v4(ip, *net))
}

fn v4_is_global(ip: Ipv4Addr) -> bool {
    !in_v4(u32::from(ip), V4_SHARED) && !v4_is_private(ip)
}

fn v4_is_multicast(ip: Ipv4Addr) -> bool {
    in_v4(u32::from(ip), V4_MULTICAST)
}

fn v4_is_reserved(ip: Ipv4Addr) -> bool {
    in_v4(u32::from(ip), V4_RESERVED)
}

/// `IPv6Address.ipv4_mapped`.
pub(crate) fn ipv4_mapped(ip: Ipv6Addr) -> Option<Ipv4Addr> {
    let value = u128::from(ip);
    (value >> 32 == 0xffff).then(|| Ipv4Addr::from(value as u32))
}

fn v6_is_private(ip: Ipv6Addr) -> bool {
    if let Some(mapped) = ipv4_mapped(ip) {
        return v4_is_private(mapped);
    }
    let value = u128::from(ip);
    V6_PRIVATE.iter().any(|net| in_v6(value, *net))
        && V6_PRIVATE_EXCEPTIONS.iter().all(|net| !in_v6(value, *net))
}

fn v6_is_global(ip: Ipv6Addr) -> bool {
    match ipv4_mapped(ip) {
        Some(mapped) => v4_is_global(mapped),
        None => !v6_is_private(ip),
    }
}

fn v6_is_multicast(ip: Ipv6Addr) -> bool {
    match ipv4_mapped(ip) {
        Some(mapped) => v4_is_multicast(mapped),
        None => in_v6(u128::from(ip), V6_MULTICAST),
    }
}

fn v6_is_reserved(ip: Ipv6Addr) -> bool {
    match ipv4_mapped(ip) {
        Some(mapped) => v4_is_reserved(mapped),
        None => V6_RESERVED.iter().any(|net| in_v6(u128::from(ip), *net)),
    }
}

fn v6_is_unspecified(ip: Ipv6Addr) -> bool {
    match ipv4_mapped(ip) {
        Some(mapped) => u32::from(mapped) == 0,
        None => u128::from(ip) == 0,
    }
}

/// remote_images.py `_public_address`: true only for globally reachable
/// unicast addresses outside the IPv6 transition prefixes.
pub(crate) fn public_address(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            v4_is_global(ip) && !v4_is_multicast(ip) && !v4_is_reserved(ip) && u32::from(ip) != 0
        }
        IpAddr::V6(ip) => {
            if !v6_is_global(ip)
                || v6_is_multicast(ip)
                || v6_is_reserved(ip)
                || v6_is_unspecified(ip)
            {
                return false;
            }
            let value = u128::from(ip);
            if in_v6(value, V6_SITE_LOCAL) || V6_BLOCKED.iter().any(|net| in_v6(value, *net)) {
                return false;
            }
            match ipv4_mapped(ip) {
                Some(mapped) => public_address(IpAddr::V4(mapped)),
                None => true,
            }
        }
    }
}

/// Python `ipaddress.ip_address(text)` for a string: a strict dotted-quad
/// IPv4 address or an IPv6 address with an optional `%scope` suffix.
pub(crate) fn parse_ip(text: &str) -> Option<(IpAddr, Option<&str>)> {
    if let Some(ip) = parse_ipv4(text) {
        return Some((IpAddr::V4(ip), None));
    }
    let (address, scope) = match text.split_once('%') {
        Some((address, scope)) => {
            if scope.is_empty() || scope.contains('%') {
                return None;
            }
            (address, Some(scope))
        }
        None => (text, None),
    };
    if !address.contains(':') {
        return None;
    }
    // Python allows an embedded IPv4 tail; std's parser does too. Reject the
    // forms Python rejects that std might accept (none known); keep ASCII.
    if !address.is_ascii() {
        return None;
    }
    address
        .parse::<Ipv6Addr>()
        .ok()
        .map(|ip| (IpAddr::V6(ip), scope))
}

/// `IPv4Address(text)`: four decimal octets, at most three digits each, no
/// leading zeros, each <= 255.
fn parse_ipv4(text: &str) -> Option<Ipv4Addr> {
    let parts: Vec<&str> = text.split('.').collect();
    if parts.len() != 4 {
        return None;
    }
    let mut octets = [0u8; 4];
    for (octet, part) in octets.iter_mut().zip(parts) {
        if part.is_empty() || part.len() > 3 || !part.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        if part.len() > 1 && part.starts_with('0') {
            return None;
        }
        *octet = part.parse::<u16>().ok().filter(|value| *value <= 255)? as u8;
    }
    Some(Ipv4Addr::from(octets))
}

/// `IPv6Address.compressed` (Python 3.13+: IPv4-mapped addresses keep their
/// dotted IPv4 tail; the scope id is appended after `%`).
pub(crate) fn ipv6_compressed(ip: Ipv6Addr, scope: Option<&str>) -> String {
    let text = match ipv4_mapped(ip) {
        Some(mapped) => format!("::ffff:{mapped}"),
        None => compress_hextets(&ip.segments()),
    };
    match scope {
        Some(scope) => format!("{text}%{scope}"),
        None => text,
    }
}

/// `ipaddress._compress_hextets`: the first longest run (> 1) of zero
/// hextets becomes `::`.
fn compress_hextets(segments: &[u16; 8]) -> String {
    let mut best_start = None;
    let mut best_len = 0;
    let mut run_start = None;
    let mut run_len = 0;
    for (index, segment) in segments.iter().enumerate() {
        if *segment == 0 {
            run_len += 1;
            let start = *run_start.get_or_insert(index);
            if run_len > best_len {
                best_len = run_len;
                best_start = Some(start);
            }
        } else {
            run_len = 0;
            run_start = None;
        }
    }
    let hextets: Vec<String> = segments.iter().map(|value| format!("{value:x}")).collect();
    match best_start {
        Some(start) if best_len > 1 => {
            let end = start + best_len;
            let head = hextets[..start].join(":");
            let tail = hextets[end..].join(":");
            format!("{head}::{tail}")
        }
        _ => hextets.join(":"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn public(text: &str) -> bool {
        parse_ip(text).is_some_and(|(ip, _)| public_address(ip))
    }

    #[test]
    fn public_address_matches_python_vectors() {
        for address in [
            "127.0.0.1",
            "10.0.0.1",
            "192.168.1.1",
            "172.16.1.1",
            "169.254.169.254",
            "0.0.0.0",
            "100.100.100.200",
            "224.0.0.1",
            "255.255.255.255",
            "::1",
            "fe80::1",
            "fc00::1",
            "ff02::1",
            "::ffff:127.0.0.1",
            "64:ff9b::7f00:1",
            "2002:7f00:1::",
            "2001:db8::1",
            "fec0::1",
            "100::1",
            "::1.2.3.4",
            "198.18.0.1",
            "3fff::1",
            "::",
            "not an address",
            "01.2.3.4",
            "fe80::1%12",
        ] {
            assert!(!public(address), "{address}");
        }
        for address in [
            "8.8.8.8",
            "2606:4700:4700::1111",
            "::ffff:8.8.8.8",
            "192.0.0.9",
            "2001:20::1",
            "2001:4:112::1",
            "192.88.99.1",
        ] {
            assert!(public(address), "{address}");
        }
    }

    #[test]
    fn compressed_matches_python() {
        let cases = [
            ("2001:db8:0:0:1:0:0:1", "2001:db8::1:0:0:1"),
            ("0:0:0:0:0:0:0:1", "::1"),
            ("1:0:0:0:0:0:0:0", "1::"),
            ("1:2:3:4:5:6:7:0", "1:2:3:4:5:6:7:0"),
            ("::ffff:1.2.3.4", "::ffff:1.2.3.4"),
            ("::", "::"),
        ];
        for (input, expected) in cases {
            let (ip, scope) = parse_ip(input).unwrap();
            let IpAddr::V6(ip) = ip else { panic!() };
            assert_eq!(ipv6_compressed(ip, scope), expected);
        }
        let (ip, scope) = parse_ip("FE80::1%eth0").unwrap();
        let IpAddr::V6(ip) = ip else { panic!() };
        assert_eq!(ipv6_compressed(ip, scope), "fe80::1%eth0");
    }
}
