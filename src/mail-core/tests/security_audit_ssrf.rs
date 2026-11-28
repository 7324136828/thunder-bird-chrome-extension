//! Security audit: SSRF resistance of the remote-image proxy. An email author
//! controls the image URLs, so every hop must reach public addresses only,
//! on ports 80/443, without credentials, and the proxy must never serve
//! active content.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use mail_core::remote_images::{
    image_type, public_address, request_headers, target, vet_records, FetcherConfig, ImageFetcher,
    Resolver,
};

#[test]
fn private_and_special_addresses_are_never_public() {
    for address in [
        "127.0.0.1",
        "127.255.255.254",
        "0.0.0.0",
        "10.1.2.3",
        "172.16.0.1",
        "192.168.1.1",
        "169.254.169.254",
        "100.64.0.1",
        "198.18.0.1",
        "224.0.0.1",
        "255.255.255.255",
        "240.0.0.1",
        "::1",
        "::",
        "::ffff:127.0.0.1",
        "::ffff:10.0.0.1",
        "::ffff:169.254.169.254",
        "64:ff9b::7f00:1",
        "64:ff9b:1::a00:1",
        "2002:7f00:1::1",
        "2001:0:4136:e378:8000:63bf:3fff:fdd2",
        "fc00::1",
        "fd12:3456::1",
        "fe80::1",
        "fec0::1",
        "ff02::1",
        "2001:db8::1",
    ] {
        assert!(!public_address(address), "{address} counted as public");
    }
    for address in ["93.184.216.34", "2606:2800:220:1:248:1893:25c8:1946"] {
        assert!(public_address(address), "{address}");
    }
}

#[test]
fn mixed_dns_answers_are_rejected_as_a_whole() {
    let public: SocketAddr = "93.184.216.34:443".parse().unwrap();
    let private: SocketAddr = "127.0.0.1:443".parse().unwrap();
    assert!(vet_records(&[public]).is_ok());
    assert!(vet_records(&[public, private]).is_err());
    assert!(vet_records(&[private, public]).is_err());
    assert!(vet_records(&[]).is_err());
}

#[test]
fn urls_with_credentials_odd_ports_or_internal_names_are_refused() {
    for url in [
        "http://localhost/x.png",
        "http://LOCALHOST./x.png",
        "http://printer.local/x.png",
        "http://metadata/computeMetadata",
        "http://metadata.google.internal/x",
        "http://router.lan/x.png",
        "http://nas.home/x.png",
        "http://a.localhost/x.png",
        "http://user:pw@example.com/x.png",
        "http://user@example.com/x.png",
        "http://example.com:8080/x.png",
        "http://example.com:22/x.png",
        "https://example.com:0/x.png",
        "ftp://example.com/x.png",
        "file:///etc/passwd",
        "gopher://example.com/",
        "data:image/png;base64,AAAA",
        "javascript:alert(1)",
        "http://example.com\\@127.0.0.1/x.png",
        "http://exa mple.com/x.png",
        "http://example.com/\r\nHost: 127.0.0.1",
        "http://[fe80::1%25eth0]/x.png",
        "",
    ] {
        assert!(target(url).is_err(), "{url:?} was accepted");
    }
    let accepted = target("https://images.example.com/a%20b.png?x=1#frag").unwrap();
    assert_eq!(accepted.port, 443);
    assert!(!accepted.path.contains(' '), "{}", accepted.path);
    assert!(!accepted.url.contains('#'), "{}", accepted.url);
}

#[test]
fn ip_literal_hosts_are_vetted_without_dns() {
    // A fetcher whose DNS lookup must never be consulted for IP literals
    // still refuses the private ones before connecting.
    let lookup_used = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let flag = lookup_used.clone();
    let fetcher = ImageFetcher::new(FetcherConfig {
        resolver: Resolver::Lookup(Arc::new(move |_host, _port| {
            flag.store(true, std::sync::atomic::Ordering::SeqCst);
            Ok(vec![SocketAddr::new(IpAddr::from([127, 0, 0, 1]), 80)])
        })),
        ..FetcherConfig::default()
    });
    for url in [
        "http://127.0.0.1/x.png",
        "http://[::1]/x.png",
        "http://[::ffff:7f00:1]/x.png",
        "http://169.254.169.254/latest/meta-data",
        "http://0.0.0.0/x.png",
    ] {
        assert!(fetcher.fetch(url, false).is_err(), "{url}");
    }
    assert!(!lookup_used.load(std::sync::atomic::Ordering::SeqCst));
    // A hostname answered with a loopback record (DNS rebinding) is refused.
    assert!(fetcher
        .fetch("http://rebind.example.com/x.png", false)
        .is_err());
    assert!(lookup_used.load(std::sync::atomic::Ordering::SeqCst));
}

#[test]
fn active_content_is_never_served_as_an_image() {
    for content in [
        &b"<svg xmlns=\"http://www.w3.org/2000/svg\"><script>alert(1)</script></svg>"[..],
        b"<!doctype html><script>alert(1)</script>",
        b"GIF89a<script>alert(1)</script>",
        b"\x89PNG\r\n\x1a\n<html><script>alert(1)</script></html>",
        b"",
    ] {
        assert!(image_type(content).is_err(), "{content:?}");
    }
}

#[test]
fn request_headers_carry_no_user_data() {
    let first = request_headers().unwrap();
    let second = request_headers().unwrap();
    for (name, _) in &first {
        assert!(
            !matches!(
                name.to_ascii_lowercase().as_str(),
                "referer" | "authorization" | "origin"
            ),
            "{name}"
        );
    }
    // Disposable per-request values: nothing correlates two downloads.
    let cookie = |headers: &[(&str, String)]| {
        headers
            .iter()
            .find(|(name, _)| *name == "Cookie")
            .map(|(_, value)| value.clone())
    };
    assert_ne!(cookie(&first), cookie(&second));
}
