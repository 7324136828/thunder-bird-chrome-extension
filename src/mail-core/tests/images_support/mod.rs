//! Shared helpers for the `images_*` tests: PNG fixtures and a local HTTP
//! test server on 127.0.0.1 (Python's `ThreadingHTTPServer` fixtures).

#![allow(dead_code)]

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use mail_core::remote_images::{FetcherConfig, ImageFetcher, Resolver, Target};

/// `png_chunk(kind, data)`.
pub fn png_chunk(kind: &[u8], data: &[u8]) -> Vec<u8> {
    let mut hasher = crc32fast::Hasher::new();
    hasher.update(kind);
    hasher.update(data);
    let mut chunk = (data.len() as u32).to_be_bytes().to_vec();
    chunk.extend_from_slice(kind);
    chunk.extend_from_slice(data);
    chunk.extend_from_slice(&hasher.finalize().to_be_bytes());
    chunk
}

/// A minimal valid PNG of `width` x `height` (framing only; the IDAT bytes
/// are not decoded by the downloader).
pub fn png_with(width: u32, height: u32) -> Vec<u8> {
    let mut header = width.to_be_bytes().to_vec();
    header.extend_from_slice(&height.to_be_bytes());
    header.extend_from_slice(&[8, 6, 0, 0, 0]);
    let mut png = b"\x89PNG\r\n\x1a\n".to_vec();
    png.extend(png_chunk(b"IHDR", &header));
    // zlib.compress(b"\x00\xff\x00\x00\xff")
    png.extend(png_chunk(
        b"IDAT",
        &[
            0x78, 0x9c, 0x63, 0xf8, 0xcf, 0xc0, 0xf0, 0x1f, 0x00, 0x05, 0x00, 0x01, 0xff,
        ],
    ));
    png.extend(png_chunk(b"IEND", b""));
    png
}

/// The 1x1 `PNG` fixture.
pub fn png() -> Vec<u8> {
    png_with(1, 1)
}

/// One received request head.
#[derive(Debug, Clone)]
pub struct Request {
    pub head: String,
    pub path: String,
    pub index: usize,
}

impl Request {
    pub fn header(&self, name: &str) -> Option<String> {
        self.head.lines().skip(1).find_map(|line| {
            let (field, value) = line.split_once(':')?;
            field
                .eq_ignore_ascii_case(name)
                .then(|| value.trim().to_string())
        })
    }
}

type Handler = dyn Fn(&Request, &mut TcpStream) + Send + Sync;

/// A threaded HTTP test server; every connection runs `handler` once and
/// then records whether the client closed its socket.
pub struct TestServer {
    pub addr: SocketAddr,
    pub requests: Arc<Mutex<Vec<Request>>>,
    pub connections: Arc<AtomicUsize>,
    pub client_closed: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
}

impl TestServer {
    pub fn start(handler: impl Fn(&Request, &mut TcpStream) + Send + Sync + 'static) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test server");
        let addr = listener.local_addr().unwrap();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let connections = Arc::new(AtomicUsize::new(0));
        let client_closed = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let handler: Arc<Handler> = Arc::new(handler);
        {
            let (requests, connections, client_closed, stop) = (
                requests.clone(),
                connections.clone(),
                client_closed.clone(),
                stop.clone(),
            );
            std::thread::spawn(move || {
                for stream in listener.incoming() {
                    if stop.load(Ordering::SeqCst) {
                        break;
                    }
                    let Ok(mut stream) = stream else { continue };
                    let index = connections.fetch_add(1, Ordering::SeqCst);
                    let (requests, client_closed, handler) =
                        (requests.clone(), client_closed.clone(), handler.clone());
                    std::thread::spawn(move || {
                        let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
                        let Some(head) = read_head(&mut stream) else {
                            return;
                        };
                        let path = head
                            .split_whitespace()
                            .nth(1)
                            .unwrap_or_default()
                            .to_string();
                        let request = Request { head, path, index };
                        requests.lock().unwrap().push(request.clone());
                        handler(&request, &mut stream);
                        let _ = stream.flush();
                        // A single-use client closes its socket after the
                        // response; detect that EOF.
                        let _ = stream.set_read_timeout(Some(Duration::from_secs(3)));
                        let mut buffer = [0u8; 256];
                        loop {
                            match stream.read(&mut buffer) {
                                Ok(0) => {
                                    client_closed.fetch_add(1, Ordering::SeqCst);
                                    break;
                                }
                                Ok(_) => continue,
                                Err(error)
                                    if matches!(
                                        error.kind(),
                                        std::io::ErrorKind::ConnectionReset
                                            | std::io::ErrorKind::ConnectionAborted
                                    ) =>
                                {
                                    client_closed.fetch_add(1, Ordering::SeqCst);
                                    break;
                                }
                                Err(_) => break,
                            }
                        }
                    });
                }
            });
        }
        Self {
            addr,
            requests,
            connections,
            client_closed,
            stop,
        }
    }

    pub fn requests(&self) -> Vec<Request> {
        self.requests.lock().unwrap().clone()
    }

    pub fn connection_count(&self) -> usize {
        self.connections.load(Ordering::SeqCst)
    }

    /// Wait until `count` connections were closed by the client.
    pub fn assert_closed(&self, count: usize) {
        let deadline = Instant::now() + Duration::from_secs(4);
        while self.client_closed.load(Ordering::SeqCst) < count && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(self.connection_count(), count, "connections");
        assert_eq!(
            self.client_closed.load(Ordering::SeqCst),
            count,
            "connections closed by the client"
        );
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(self.addr);
    }
}

fn read_head(stream: &mut TcpStream) -> Option<String> {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        match stream.read(&mut byte) {
            Ok(1) => head.push(byte[0]),
            _ => return None,
        }
        if head.len() > 65536 {
            return None;
        }
    }
    Some(String::from_utf8_lossy(&head).into_owned())
}

/// Write a complete response.
pub fn respond(stream: &mut TcpStream, status: &str, headers: &[(&str, String)], body: &[u8]) {
    let mut response = format!("HTTP/1.1 {status}\r\n");
    for (name, value) in headers {
        response.push_str(&format!("{name}: {value}\r\n"));
    }
    response.push_str("\r\n");
    let mut bytes = response.into_bytes();
    bytes.extend_from_slice(body);
    let _ = stream.write_all(&bytes);
}

/// `200 OK` with `Content-Type: image/png`, a Content-Length and
/// `Connection: close`.
pub fn respond_png(stream: &mut TcpStream, body: &[u8]) {
    respond(
        stream,
        "200 OK",
        &[
            ("Content-Type", "image/png".to_string()),
            ("Content-Length", body.len().to_string()),
            ("Connection", "close".to_string()),
        ],
        body,
    );
}

/// A resolver sending every host except IP literals to `addr` without
/// vetting (Python tests patching `_resolve`), counting calls.
pub fn local_resolver(addr: SocketAddr, calls: Arc<AtomicUsize>) -> Resolver {
    Resolver::UnvettedForTests(Arc::new(move |target: &Target| {
        if target.host.parse::<std::net::IpAddr>().is_ok() {
            return None;
        }
        calls.fetch_add(1, Ordering::SeqCst);
        Some(vec![addr])
    }))
}

/// A fetcher routed to `server`.
pub fn fetcher_for(server: &TestServer) -> ImageFetcher {
    fetcher_with(server, FetcherConfig::default())
}

pub fn fetcher_with(server: &TestServer, config: FetcherConfig) -> ImageFetcher {
    ImageFetcher::new(FetcherConfig {
        resolver: local_resolver(server.addr, Arc::new(AtomicUsize::new(0))),
        ..config
    })
}
