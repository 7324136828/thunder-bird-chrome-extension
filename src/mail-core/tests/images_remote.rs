//! Port of `tests/test_remote_images.py` and
//! `tests/test_remote_image_transport.py`.
//!
//! Python replaced `_PinnedConnection` / `socket.getaddrinfo` / `_download`
//! with mocks. These tests drive the real downloader against local HTTP
//! servers on 127.0.0.1 instead, reached through
//! `Resolver::UnvettedForTests` (the analogue of patching `_resolve`), or a
//! `Resolver::Lookup` that replaces only DNS so the production vetting still
//! runs. Each test owns its `ImageFetcher`, so the module-level cache that
//! Python cleared in `setUp` is never shared between tests.

mod images_support;

use std::io::Write;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use images_support::{
    fetcher_for, fetcher_with, local_resolver, png, png_chunk, png_with, respond, respond_png,
    TestServer,
};
use mail_core::remote_images::{
    self, image_type, public_address, redirect_url, target, DownloadedImage, FetcherConfig,
    ImageFetcher, Resolver, MAX_CONCURRENT_DOWNLOADS, MAX_REDIRECTS,
};

const URL: &str = "http://images.example/image.png";
const TLS_URL: &str = "https://images.example/image.png";

fn expected() -> DownloadedImage {
    DownloadedImage {
        content: png(),
        content_type: "image/png".into(),
    }
}

fn png_server() -> TestServer {
    TestServer::start(|_, stream| respond_png(stream, &png()))
}

fn is_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

// ---------------------------------------------------------------------------
// test_remote_images.py
// ---------------------------------------------------------------------------

#[test]
fn fetches_image_using_disposable_headers_and_cookie() {
    let server = png_server();
    let result = fetcher_for(&server).fetch(URL, false).unwrap();
    assert_eq!(result, expected());
    let requests = server.requests();
    assert_eq!(requests.len(), 1);
    let request = &requests[0];
    assert!(request.head.starts_with("GET /image.png HTTP/1.1\r\n"));
    assert_eq!(request.header("Host").as_deref(), Some("images.example"));
    assert_eq!(
        request.header("Accept-Encoding").as_deref(),
        Some("identity")
    );
    assert_eq!(request.header("User-Agent").as_deref(), Some("Mozilla/5.0"));
    assert_eq!(request.header("Connection").as_deref(), Some("close"));
    assert!(is_hex(&request.header("X-Image-Request").unwrap(), 32));
    let cookie = request.header("Cookie").unwrap();
    assert!(is_hex(cookie.strip_prefix("image_session=").unwrap(), 48));
    for header in ["Authorization", "Referer", "Origin"] {
        assert_eq!(request.header(header), None, "{header}");
    }
    server.assert_closed(1);
}

#[test]
fn redirects_get_new_junk_values_and_never_replay_set_cookie() {
    let server = TestServer::start(|request, stream| {
        if request.path == "/image.png" {
            respond(
                stream,
                "302 Found",
                &[
                    ("Location", "http://cdn.example/final.png".into()),
                    ("Set-Cookie", "real_user=tracking".into()),
                    ("Content-Length", "0".into()),
                ],
                b"",
            );
        } else {
            respond_png(stream, &png());
        }
    });
    let result = fetcher_for(&server).fetch(URL, false).unwrap();
    assert_eq!(result.content, png());
    let requests = server.requests();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[1].header("Host").as_deref(), Some("cdn.example"));
    assert_eq!(requests[1].path, "/final.png");
    assert_ne!(requests[0].header("Cookie"), requests[1].header("Cookie"));
    assert_ne!(
        requests[0].header("X-Image-Request"),
        requests[1].header("X-Image-Request")
    );
    assert!(!format!("{requests:?}").contains("tracking"));
    server.assert_closed(2);
}

#[test]
fn relative_redirect_and_unicode_paths_are_encoded() {
    let next = redirect_url(
        "https://images.example/path/image.png",
        "../caf\u{e9}.png?name=\u{e9}t\u{e9}",
    )
    .unwrap();
    assert_eq!(
        target(&next).unwrap().path,
        "/caf%C3%A9.png?name=%C3%A9t%C3%A9"
    );
    // Over the wire, http.client decodes header bytes as Latin-1 before
    // joining, so raw UTF-8 in Location is re-encoded byte by byte.
    let server = TestServer::start(|request, stream| {
        if request.path == "/path/image.png" {
            let _ = stream.write_all(
                b"HTTP/1.1 301 Moved\r\nLocation: ../caf\xc3\xa9.png\r\nContent-Length: 0\r\n\r\n",
            );
        } else {
            respond_png(stream, &png());
        }
    });
    fetcher_for(&server)
        .fetch("http://images.example/path/image.png", false)
        .unwrap();
    assert_eq!(server.requests()[1].path, "/caf%C3%83%C2%A9.png");
}

#[test]
fn redirect_to_private_network_is_rejected_before_connecting() {
    let server = TestServer::start(|_, stream| {
        respond(
            stream,
            "302 Found",
            &[("Location", "http://127.0.0.1/image.png".into())],
            b"",
        )
    });
    let error = fetcher_for(&server).fetch(URL, false).unwrap_err();
    assert_eq!(error.0, "Private network image addresses are blocked.");
    assert_eq!(server.connection_count(), 1);
}

#[test]
fn redirect_limit() {
    let counter = Arc::new(AtomicUsize::new(0));
    let hops = counter.clone();
    let server = TestServer::start(move |_, stream| {
        let number = hops.fetch_add(1, Ordering::SeqCst);
        respond(
            stream,
            "302 Found",
            &[("Location", format!("/image-{number}.png"))],
            b"",
        )
    });
    let error = fetcher_for(&server).fetch(URL, false).unwrap_err();
    assert_eq!(error.0, "The image redirected too many times.");
    assert_eq!(server.connection_count(), MAX_REDIRECTS + 1);
}

#[test]
fn invalid_urls_and_private_named_hosts_are_blocked() {
    let lookups = Arc::new(AtomicUsize::new(0));
    let counter = lookups.clone();
    let fetcher = ImageFetcher::new(FetcherConfig {
        resolver: Resolver::Lookup(Arc::new(move |_, _| {
            counter.fetch_add(1, Ordering::SeqCst);
            Ok(vec!["8.8.8.8:443".parse().unwrap()])
        })),
        ..FetcherConfig::default()
    });
    for url in [
        "file:///tmp/image.png",
        "ftp://example.com/image.png",
        "data:image/png,a",
        "https://username:secret@example.com/image.png",
        "http://localhost/image.png",
        "http://metadata.google.internal/image",
        "http://machine.local/image",
        "http://example.com:8080/image.png",
        "http://example.com:0/image.png",
        "https://example.com/\r\nCookie:password",
        "http://example.com\\@127.0.0.1/image.png",
        "https://[fe80::1%12]/image.png",
        "",
    ] {
        assert!(fetcher.fetch(url, false).is_err(), "{url:?}");
    }
    assert_eq!(lookups.load(Ordering::SeqCst), 0);
    assert_eq!(fetcher.cache_len(), 0);
}

#[test]
fn private_reserved_and_transition_addresses_are_rejected() {
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
    ] {
        assert!(!public_address(address), "{address}");
    }
    assert!(public_address("8.8.8.8"));
    assert!(public_address("2606:4700:4700::1111"));
}

#[test]
fn mixed_dns_addresses_are_rejected_before_opening_socket() {
    let fetcher = ImageFetcher::new(FetcherConfig {
        resolver: Resolver::Lookup(Arc::new(|_, _| {
            Ok(vec![
                "8.8.8.8:443".parse().unwrap(),
                "192.168.1.1:443".parse().unwrap(),
            ])
        })),
        ..FetcherConfig::default()
    });
    let error = fetcher.fetch(TLS_URL, false).unwrap_err();
    assert_eq!(error.0, "Private network image addresses are blocked.");
}

#[test]
fn numeric_loopback_hostname_is_rejected_after_resolution() {
    let hosts = Arc::new(Mutex::new(Vec::new()));
    let seen = hosts.clone();
    let fetcher = ImageFetcher::new(FetcherConfig {
        resolver: Resolver::Lookup(Arc::new(move |host, port| {
            seen.lock().unwrap().push((host.to_string(), port));
            Ok(vec!["127.0.0.1:80".parse().unwrap()])
        })),
        ..FetcherConfig::default()
    });
    let error = fetcher
        .fetch("http://2130706433/image.png", false)
        .unwrap_err();
    assert_eq!(error.0, "Private network image addresses are blocked.");
    assert_eq!(*hosts.lock().unwrap(), vec![("2130706433".to_string(), 80)]);
}

#[test]
fn ip_literal_targets_are_vetted_without_a_lookup() {
    let lookups = Arc::new(AtomicUsize::new(0));
    let counter = lookups.clone();
    let fetcher = ImageFetcher::new(FetcherConfig {
        resolver: Resolver::Lookup(Arc::new(move |_, _| {
            counter.fetch_add(1, Ordering::SeqCst);
            Ok(vec![])
        })),
        ..FetcherConfig::default()
    });
    for url in [
        "http://127.0.0.1/a.png",
        "http://[::1]/a.png",
        "http://10.1.2.3/a.png",
    ] {
        assert_eq!(
            fetcher.fetch(url, false).unwrap_err().0,
            "Private network image addresses are blocked."
        );
    }
    assert_eq!(lookups.load(Ordering::SeqCst), 0);
}

#[test]
fn connection_pins_resolved_address_and_keeps_original_host() {
    let server = png_server();
    let calls = Arc::new(AtomicUsize::new(0));
    let fetcher = ImageFetcher::new(FetcherConfig {
        resolver: local_resolver(server.addr, calls.clone()),
        ..FetcherConfig::default()
    });
    fetcher.fetch(URL, false).unwrap();
    // One resolution, one connection to exactly that address, and the
    // request still names the original host.
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(server.connection_count(), 1);
    assert_eq!(
        server.requests()[0].header("Host").as_deref(),
        Some("images.example")
    );
}

#[test]
fn https_host_header_matches_http_client() {
    let target = target(TLS_URL).unwrap();
    assert_eq!(
        (target.scheme.as_str(), target.host.as_str(), target.port),
        ("https", "images.example", 443)
    );
    assert_eq!(target.url, TLS_URL);
}

#[test]
fn invalid_tls_certificate_is_not_bypassed() {
    // A TLS server presenting the self-signed test certificate (CN
    // localhost): untrusted, and not for images.example.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let handshakes = Arc::new(AtomicUsize::new(0));
    let attempts = handshakes.clone();
    std::thread::spawn(move || {
        let acceptor = native_tls::TlsAcceptor::new(mail_proto::testkit::test_identity()).unwrap();
        for stream in listener.incoming().flatten() {
            attempts.fetch_add(1, Ordering::SeqCst);
            let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
            if let Ok(mut tls) = acceptor.accept(stream) {
                let _ = tls.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
            }
        }
    });
    let fetcher = ImageFetcher::new(FetcherConfig {
        resolver: Resolver::UnvettedForTests(Arc::new(move |_| Some(vec![addr]))),
        ..FetcherConfig::default()
    });
    let error = fetcher.fetch(TLS_URL, false).unwrap_err();
    assert_eq!(error.0, "The image host could not be reached.");
    assert_eq!(handshakes.load(Ordering::SeqCst), 1);
}

#[test]
fn dns_timeout_is_bounded_even_if_os_resolver_is_slow() {
    let (release, released) = mpsc::channel::<()>();
    let released = Arc::new(Mutex::new(released));
    let fetcher = ImageFetcher::new(FetcherConfig {
        download_timeout: Duration::from_millis(50),
        resolver: Resolver::Lookup(Arc::new(move |_, _| {
            let _ = released
                .lock()
                .unwrap()
                .recv_timeout(Duration::from_secs(2));
            Ok(vec!["8.8.8.8:443".parse().unwrap()])
        })),
        ..FetcherConfig::default()
    });
    let started = Instant::now();
    let error = fetcher.fetch(TLS_URL, false).unwrap_err();
    assert_eq!(error.0, "The image download timed out.");
    assert!(started.elapsed() < Duration::from_secs(1));
    let _ = release.send(());
}

#[test]
fn overall_deadline_interrupts_trickling_response_headers() {
    let server = TestServer::start(|_, stream| {
        let _ = stream.write_all(b"HTTP/1.1 200 OK\r\n");
        for _ in 0..200 {
            std::thread::sleep(Duration::from_millis(10));
            if stream.write_all(b"X").is_err() {
                return;
            }
        }
    });
    let fetcher = fetcher_with(
        &server,
        FetcherConfig {
            download_timeout: Duration::from_millis(200),
            ..FetcherConfig::default()
        },
    );
    let started = Instant::now();
    assert!(fetcher.fetch(URL, false).is_err());
    let elapsed = started.elapsed();
    assert!(elapsed >= Duration::from_millis(150), "{elapsed:?}");
    assert!(elapsed < Duration::from_secs(1), "{elapsed:?}");
}

#[test]
fn socket_failure_is_safe_and_cached() {
    // The server closes without answering (Python: socket.timeout).
    let server = TestServer::start(|_, stream| {
        let _ = stream.shutdown(std::net::Shutdown::Both);
    });
    let fetcher = fetcher_for(&server);
    for _ in 0..2 {
        assert_eq!(
            fetcher.fetch(URL, false).unwrap_err().0,
            "The image download failed."
        );
    }
    assert_eq!(server.connection_count(), 1);
    assert_eq!(fetcher.pending_len(), 0);
}

#[test]
fn unreachable_host_is_reported_and_cached() {
    // Reserve a port, then close it so connecting is refused.
    let addr: SocketAddr = {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.local_addr().unwrap()
    };
    let fetcher = ImageFetcher::new(FetcherConfig {
        resolver: Resolver::UnvettedForTests(Arc::new(move |_| Some(vec![addr]))),
        ..FetcherConfig::default()
    });
    assert_eq!(
        fetcher.fetch(URL, false).unwrap_err().0,
        "The image host could not be reached."
    );
    assert_eq!(fetcher.cache_len(), 1);
}

#[test]
fn html_svg_truncated_or_mislabeled_images_are_rejected() {
    let image = png();
    type Case = (&'static str, Vec<(&'static str, String)>, Vec<u8>);
    let cases: Vec<Case> = vec![
        (
            "200 OK",
            vec![("Content-Type", "image/png".into())],
            b"<html>not an image</html>".to_vec(),
        ),
        (
            "200 OK",
            vec![("Content-Type", "image/svg+xml".into())],
            br#"<svg xmlns="http://www.w3.org/2000/svg"></svg>"#.to_vec(),
        ),
        (
            "200 OK",
            vec![("Content-Type", "image/png".into())],
            image[..image.len() - 5].to_vec(),
        ),
        (
            "200 OK",
            vec![("Content-Type", "text/html".into())],
            image.clone(),
        ),
        (
            "200 OK",
            vec![("Content-Encoding", "gzip".into())],
            image.clone(),
        ),
        (
            "200 OK",
            vec![("Content-Length", (image.len() + 1).to_string())],
            image.clone(),
        ),
        (
            "200 OK",
            vec![("Content-Type", "image/png".into())],
            Vec::new(),
        ),
        ("404 Not Found", vec![], Vec::new()),
        (
            "200 OK",
            vec![("Content-Length", "5, 5".into())],
            image.clone(),
        ),
    ];
    let cases = Arc::new(cases);
    let served = cases.clone();
    let server = TestServer::start(move |request, stream| {
        let number: usize = request
            .path
            .rsplit('=')
            .next()
            .and_then(|value| value.parse().ok())
            .unwrap();
        let (status, headers, body) = &served[number];
        let mut headers = headers.clone();
        headers.push(("Connection", "close".into()));
        respond(stream, status, &headers, body);
        // Close-delimited: never leave the client waiting for more bytes.
        let _ = stream.shutdown(std::net::Shutdown::Write);
    });
    let fetcher = fetcher_for(&server);
    for number in 0..cases.len() {
        assert!(
            fetcher
                .fetch(&format!("{URL}?case={number}"), false)
                .is_err(),
            "case {number}"
        );
    }
}

#[test]
fn image_types_follow_python_signatures() {
    let gif = {
        let mut gif = b"GIF89a".to_vec();
        gif.extend_from_slice(&[2, 0, 3, 0, 0, 0, 0, 0]);
        gif.push(b';');
        gif
    };
    assert_eq!(image_type(&gif), Ok("image/gif"));
    let jpeg = [
        0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x04, 0x00, 0x00, 0xFF, 0xC0, 0x00, 0x08, 0x08, 0x00, 0x02,
        0x00, 0x03, 0x00, 0xFF, 0xD9,
    ];
    assert_eq!(image_type(&jpeg), Ok("image/jpeg"));
    let mut webp = b"RIFF".to_vec();
    webp.extend_from_slice(&22u32.to_le_bytes());
    webp.extend_from_slice(b"WEBPVP8X");
    webp.extend_from_slice(&10u32.to_le_bytes());
    webp.extend_from_slice(&[0, 0, 0, 0, 1, 0, 0, 2, 0, 0]);
    assert_eq!(webp.len(), 30);
    assert_eq!(image_type(&webp), Ok("image/webp"));
    let mut bmp = vec![0u8; 60];
    bmp[..2].copy_from_slice(b"BM");
    bmp[2..6].copy_from_slice(&60u32.to_le_bytes());
    bmp[10..14].copy_from_slice(&54u32.to_le_bytes());
    bmp[14..18].copy_from_slice(&40u32.to_le_bytes());
    bmp[18..22].copy_from_slice(&2i32.to_le_bytes());
    bmp[22..26].copy_from_slice(&(-2i32).to_le_bytes());
    assert_eq!(image_type(&bmp), Ok("image/bmp"));
    assert_eq!(
        image_type(b"<svg/>").unwrap_err().0,
        "The response was not a supported image."
    );
    // A second IHDR, bad CRC or trailing bytes after IEND are rejected.
    let mut trailing = png();
    trailing.push(0);
    assert!(image_type(&trailing).is_err());
    let mut bad_crc = png();
    bad_crc[29] ^= 1;
    assert!(image_type(&bad_crc).is_err());
    let mut zero = png_with(0, 1);
    assert_eq!(
        image_type(&zero).unwrap_err().0,
        "The image dimensions are not permitted."
    );
    zero.clear();
    assert!(image_type(&zero).is_err());
    let mut second_header = png();
    let ihdr = png_chunk(b"IHDR", &second_header[16..29]);
    second_header.splice(33..33, ihdr);
    assert!(image_type(&second_header).is_err());
}

#[test]
fn size_limit_applies_to_declared_and_streamed_bytes() {
    let image = png();
    let declared = image.clone();
    let server = TestServer::start(move |request, stream| {
        if request.path.ends_with("size=0") {
            respond_png(stream, &declared);
        } else {
            respond(
                stream,
                "200 OK",
                &[("Connection", "close".into())],
                &declared,
            );
        }
    });
    let fetcher = fetcher_with(
        &server,
        FetcherConfig {
            max_image_bytes: image.len() - 1,
            ..FetcherConfig::default()
        },
    );
    assert_eq!(
        fetcher
            .fetch(&format!("{URL}?size=0"), false)
            .unwrap_err()
            .0,
        "The image size is not permitted."
    );
    assert_eq!(
        fetcher
            .fetch(&format!("{URL}?size=1"), false)
            .unwrap_err()
            .0,
        "The image is too large."
    );
}

#[test]
fn decompression_bomb_dimensions_are_blocked() {
    let server = TestServer::start(|_, stream| respond_png(stream, &png_with(100_000, 100_000)));
    assert_eq!(
        fetcher_for(&server).fetch(URL, false).unwrap_err().0,
        "The image dimensions are not permitted."
    );
}

#[test]
fn failure_is_cached_until_explicit_retry() {
    let served = Arc::new(AtomicUsize::new(0));
    let counter = served.clone();
    let server = TestServer::start(move |_, stream| {
        if counter.fetch_add(1, Ordering::SeqCst) == 0 {
            respond(
                stream,
                "404 Not Found",
                &[("Content-Length", "0".into())],
                b"",
            );
        } else {
            respond_png(stream, &png());
        }
    });
    let fetcher = fetcher_for(&server);
    for _ in 0..2 {
        assert!(fetcher.fetch(URL, false).is_err());
    }
    assert_eq!(served.load(Ordering::SeqCst), 1);
    assert_eq!(fetcher.fetch(URL, true).unwrap(), expected());
    assert_eq!(fetcher.fetch(URL, true).unwrap(), expected());
    assert_eq!(served.load(Ordering::SeqCst), 2);
}

#[test]
fn cache_expiration_and_clear_discard_image_bytes() {
    let server = png_server();
    let fetcher = fetcher_for(&server);
    fetcher.fetch(URL, false).unwrap();
    fetcher.fetch(URL, false).unwrap();
    assert_eq!(server.connection_count(), 1);
    fetcher.expire_cache_entry(URL);
    fetcher.fetch(URL, false).unwrap();
    assert_eq!(server.connection_count(), 2);
    assert_eq!(fetcher.cache_bytes(), png().len());
    fetcher.clear_cache();
    assert_eq!(fetcher.cache_bytes(), 0);
    assert_eq!(fetcher.cache_len(), 0);
}

#[test]
fn cache_is_bounded_by_entries_and_total_bytes() {
    let server = png_server();
    let fetcher = fetcher_with(
        &server,
        FetcherConfig {
            cache_max_entries: 3,
            cache_max_bytes: png().len() * 2,
            ..FetcherConfig::default()
        },
    );
    for number in 0..5 {
        fetcher
            .fetch(&format!("{URL}?entry={number}"), false)
            .unwrap();
    }
    assert_eq!(fetcher.cache_len(), 2);
    assert_eq!(fetcher.cache_bytes(), png().len() * 2);
    assert!(!fetcher.cache_contains(&format!("{URL}?entry=0")));
    assert!(fetcher.cache_contains(&format!("{URL}?entry=4")));
}

#[test]
fn clear_during_download_prevents_repopulating_cache() {
    for fail in [false, true] {
        let shared: Arc<OnceLock<Arc<ImageFetcher>>> = Arc::new(OnceLock::new());
        let inside = shared.clone();
        let server = TestServer::start(move |_, stream| {
            inside.get().unwrap().clear_cache();
            if fail {
                respond(
                    stream,
                    "404 Not Found",
                    &[("Content-Length", "0".into())],
                    b"",
                );
            } else {
                respond_png(stream, &png());
            }
        });
        let fetcher = Arc::new(fetcher_for(&server));
        shared.set(fetcher.clone()).unwrap();
        assert_eq!(fetcher.fetch(URL, false).is_err(), fail);
        assert_eq!(fetcher.cache_len(), 0);
        assert_eq!(fetcher.cache_bytes(), 0);
    }
}

#[test]
fn concurrent_fetches_of_same_url_only_download_once() {
    let (entered_tx, entered_rx) = mpsc::channel::<()>();
    let (release_tx, release_rx) = mpsc::channel::<()>();
    let entered_tx = Mutex::new(entered_tx);
    let release_rx = Mutex::new(release_rx);
    let server = TestServer::start(move |_, stream| {
        let _ = entered_tx.lock().unwrap().send(());
        let _ = release_rx
            .lock()
            .unwrap()
            .recv_timeout(Duration::from_secs(2));
        respond_png(stream, &png());
    });
    let fetcher = fetcher_for(&server);
    std::thread::scope(|scope| {
        let workers: Vec<_> = (0..8)
            .map(|_| scope.spawn(|| fetcher.fetch(URL, false)))
            .collect();
        entered_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        // Let the other workers reach the single-flight wait.
        std::thread::sleep(Duration::from_millis(100));
        release_tx.send(()).unwrap();
        for worker in workers {
            assert_eq!(worker.join().unwrap().unwrap(), expected());
        }
    });
    assert_eq!(server.connection_count(), 1);
    assert_eq!(fetcher.pending_len(), 0);
}

#[test]
fn concurrent_downloads_are_bounded() {
    let active = Arc::new(Mutex::new((0usize, 0usize)));
    let state = active.clone();
    let server = TestServer::start(move |_, stream| {
        {
            let mut guard = state.lock().unwrap();
            guard.0 += 1;
            guard.1 = guard.1.max(guard.0);
        }
        std::thread::sleep(Duration::from_millis(200));
        state.lock().unwrap().0 -= 1;
        respond_png(stream, &png());
    });
    let fetcher = fetcher_for(&server);
    std::thread::scope(|scope| {
        let workers: Vec<_> = (0..8)
            .map(|number| {
                let fetcher = &fetcher;
                scope.spawn(move || fetcher.fetch(&format!("{URL}?parallel={number}"), false))
            })
            .collect();
        for worker in workers {
            assert_eq!(worker.join().unwrap().unwrap(), expected());
        }
    });
    assert_eq!(active.lock().unwrap().1, MAX_CONCURRENT_DOWNLOADS);
    assert_eq!(fetcher.pending_len(), 0);
}

#[test]
fn module_level_cache_can_be_cleared() {
    // The process-wide fetcher only ever sees invalid URLs here (no network).
    assert!(remote_images::fetch_image("file:///x", false).is_err());
    remote_images::clear_cache();
    assert_eq!(remote_images::global_fetcher().cache_len(), 0);
}

// ---------------------------------------------------------------------------
// test_remote_image_transport.py (real connection ownership)
// ---------------------------------------------------------------------------

#[test]
fn connection_close_response_with_length_downloads_and_releases_socket() {
    let server = png_server();
    assert_eq!(fetcher_for(&server).fetch(URL, false).unwrap(), expected());
    server.assert_closed(1);
}

#[test]
fn close_delimited_response_downloads_until_eof() {
    let server = TestServer::start(|_, stream| {
        respond(
            stream,
            "200 OK",
            &[
                ("Content-Type", "image/png".into()),
                ("Connection", "close".into()),
            ],
            &png(),
        );
        let _ = stream.shutdown(std::net::Shutdown::Write);
    });
    assert_eq!(fetcher_for(&server).fetch(URL, false).unwrap(), expected());
    server.assert_closed(1);
}

#[test]
fn keepalive_response_still_releases_single_use_socket() {
    let server = TestServer::start(|_, stream| {
        let image = png();
        respond(
            stream,
            "200 OK",
            &[
                ("Content-Type", "image/png".into()),
                ("Connection", "keep-alive".into()),
                ("Content-Length", image.len().to_string()),
            ],
            &image,
        );
    });
    assert_eq!(fetcher_for(&server).fetch(URL, false).unwrap(), expected());
    server.assert_closed(1);
}

#[test]
fn chunked_and_continue_responses_are_decoded() {
    let server = TestServer::start(|_, stream| {
        let image = png();
        let (first, second) = image.split_at(10);
        let mut body = format!("HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Type: image/png\r\nTransfer-Encoding: chunked\r\n\r\n{:x};ext=1\r\n", first.len()).into_bytes();
        body.extend_from_slice(first);
        body.extend_from_slice(format!("\r\n{:X}\r\n", second.len()).as_bytes());
        body.extend_from_slice(second);
        body.extend_from_slice(b"\r\n0\r\nTrailer: x\r\n\r\n");
        let _ = stream.write_all(&body);
    });
    assert_eq!(fetcher_for(&server).fetch(URL, false).unwrap(), expected());
    server.assert_closed(1);
}

#[test]
fn redirect_releases_each_connection() {
    let server = TestServer::start(|request, stream| {
        if request.path != "/final.png" {
            respond(
                stream,
                "302 Found",
                &[
                    ("Location", "/final.png".into()),
                    ("Connection", "close".into()),
                    ("Content-Length", "0".into()),
                ],
                b"",
            );
        } else {
            respond_png(stream, &png());
        }
    });
    assert_eq!(fetcher_for(&server).fetch(URL, false).unwrap(), expected());
    server.assert_closed(2);
}

#[test]
fn invalid_response_headers_release_socket_after_failure() {
    let server = TestServer::start(|_, stream| {
        let _ = stream.write_all(b"This is not an HTTP status line\r\n\r\n");
    });
    assert_eq!(
        fetcher_for(&server).fetch(URL, false).unwrap_err().0,
        "The image download failed."
    );
    server.assert_closed(1);
}

#[test]
fn trickling_connection_close_body_obeys_total_deadline() {
    let server = TestServer::start(|_, stream| {
        let image = png();
        let head = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: image/png\r\nConnection: close\r\nContent-Length: {}\r\n\r\n",
            image.len()
        );
        if stream.write_all(head.as_bytes()).is_err() {
            return;
        }
        for byte in image {
            std::thread::sleep(Duration::from_millis(25));
            if stream.write_all(&[byte]).is_err() {
                return;
            }
        }
    });
    let fetcher = fetcher_with(
        &server,
        FetcherConfig {
            download_timeout: Duration::from_millis(250),
            ..FetcherConfig::default()
        },
    );
    let started = Instant::now();
    assert!(fetcher.fetch(URL, false).is_err());
    let elapsed = started.elapsed();
    assert!(elapsed > Duration::from_millis(150), "{elapsed:?}");
    assert!(elapsed < Duration::from_secs(1), "{elapsed:?}");
    // The client's socket is released (the server's next write fails or it
    // sees EOF).
    let deadline = Instant::now() + Duration::from_secs(4);
    while server.client_closed.load(Ordering::SeqCst) == 0 && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(server.client_closed.load(Ordering::SeqCst), 1);
}
