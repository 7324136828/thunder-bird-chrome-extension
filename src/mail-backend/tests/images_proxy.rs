//! Port of `tests/test_image_proxy.py::ImageProxyApiTests` and
//! `tests/test_remote_image_transport.py::ImageProxyTransportApiTests`.
//!
//! Python patched `remote_images.fetch_image` / `imap_client.fetch_raw`.
//! Here the route runs the real downloader against a local HTTP server
//! (the process-wide fetcher is swapped for one whose test resolver routes
//! `images.example` to 127.0.0.1 — a debug-build-only hook) and reads mail
//! from the testkit fake IMAP server.

#![cfg(debug_assertions)]
#![allow(clippy::await_holding_lock)]

mod common;
#[path = "../../mail-core/tests/images_support/mod.rs"]
mod images_support;

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::Router;
use common::{call_router, test_app, Resp};
use images_support::{png, respond, respond_png, TestServer};
use mail_backend::AppState;
use mail_core::remote_images::{self, FetcherConfig, ImageFetcher, Resolver, Target};
use mail_core::MailAccount;
use mail_proto::testkit::{FakeImapServer, FakeMessage};
use serde_json::{json, Value};

const USER: &str = "user@example.com";
const PASSWORD: &str = "imap-test-password";
const IMAGE_URL: &str = "http://images.example/d/1NoNBoOQt2BCK3ki_4cUeRThRQz9Nrr5S=w1200";

/// The process-wide fetcher is shared by every test in this binary.
static SERIAL: Mutex<()> = Mutex::new(());

fn serial() -> MutexGuard<'static, ()> {
    SERIAL
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Install a fresh process-wide fetcher whose resolver sends every host to
/// `addr` (or refuses, counting calls) and runs `hook` on each resolution.
fn install_fetcher(
    addr: Option<SocketAddr>,
    hook: impl Fn() + Send + Sync + 'static,
) -> (Arc<ImageFetcher>, Arc<AtomicUsize>) {
    let calls = Arc::new(AtomicUsize::new(0));
    let counter = calls.clone();
    // Port 1 on loopback refuses connections immediately.
    let target_addr = addr.unwrap_or_else(|| "127.0.0.1:1".parse().unwrap());
    let fetcher = Arc::new(ImageFetcher::new(FetcherConfig {
        resolver: Resolver::UnvettedForTests(Arc::new(move |_: &Target| {
            counter.fetch_add(1, Ordering::SeqCst);
            hook();
            Some(vec![target_addr])
        })),
        ..FetcherConfig::default()
    }));
    remote_images::replace_global_fetcher_for_tests(fetcher.clone());
    (fetcher, calls)
}

fn account_at(port: u16) -> MailAccount {
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

/// Python `make_account()`: never reaches a server.
fn offline_account() -> MailAccount {
    account_at(1)
}

fn body(extra: Value) -> Value {
    let mut base = json!({"account": USER, "folder": "INBOX", "uid": 7, "url": IMAGE_URL});
    for (key, value) in extra.as_object().unwrap() {
        base[key] = value.clone();
    }
    base
}

async fn post_image(app: &Router, body: &Value, headers: &[(&str, &str)]) -> Resp {
    let mut request = Request::post("/api/mail/message/image")
        .header("host", "127.0.0.1:48101")
        .header("content-type", "application/json");
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    call_router(
        app.clone(),
        request.body(Body::from(body.to_string())).unwrap(),
    )
    .await
}

fn register(state: &AppState) {
    state.sessions.unlock(offline_account());
    state
        .image_sources
        .register(USER, "INBOX", 7, &format!(r#"<img src="{IMAGE_URL}">"#));
}

#[tokio::test]
async fn image_proxy_requires_an_unlocked_account_before_network_access() {
    let _serial = serial();
    let (_fetcher, calls) = install_fetcher(None, || {});
    let (app, _state, _temporary) = test_app();
    let response = post_image(&app, &body(json!({})), &[]).await;
    let detail = response.assert_json_error(StatusCode::UNAUTHORIZED);
    assert_eq!(detail, json!({"error": "password_required", "email": USER}));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn validation_errors_come_before_the_account_check() {
    let _serial = serial();
    let (app, _state, _temporary) = test_app();
    let response = post_image(&app, &body(json!({"uid": 0, "url": ""})), &[]).await;
    let detail = response.assert_json_error(StatusCode::UNPROCESSABLE_ENTITY);
    let locations: Vec<Value> = detail
        .as_array()
        .unwrap()
        .iter()
        .map(|issue| issue["loc"].clone())
        .collect();
    assert_eq!(
        locations,
        vec![json!(["body", "uid"]), json!(["body", "url"])]
    );
    let response = post_image(&app, &json!({"account": USER}), &[]).await;
    assert_eq!(response.status, StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn unsupported_urls_are_rejected_before_authorization() {
    let _serial = serial();
    let (_fetcher, calls) = install_fetcher(None, || {});
    let (app, state, _temporary) = test_app();
    register(&state);
    for url in [
        "data:image/png;base64,abc",
        "https://user:pw@images.example/a.png",
    ] {
        let response = post_image(&app, &body(json!({"url": url})), &[]).await;
        assert_eq!(
            response.assert_json_error(StatusCode::BAD_REQUEST),
            json!("The image URL is not a supported HTTP or HTTPS address")
        );
    }
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn opening_message_registers_sources_and_download_returns_only_local_image() {
    let _serial = serial();
    let raw =
        format!("Subject: Images\r\nContent-Type: text/html\r\n\r\n<img src=\"{IMAGE_URL}\">\r\n");
    let imap = FakeImapServer::builder()
        .credentials(USER, PASSWORD)
        .message_with("INBOX", FakeMessage::new(raw).with_uid(7))
        .start();
    let image_server = TestServer::start(|_, stream| respond_png(stream, &png()));
    let (_fetcher, _calls) = install_fetcher(Some(image_server.addr), || {});
    let (app, state, _temporary) = test_app();
    state.sessions.unlock(account_at(imap.port()));
    let opened = call_router(
        app.clone(),
        common::get(&format!("/api/mail/message?account={USER}&uid=7"))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(opened.status, StatusCode::OK, "{}", opened.text());
    let response = post_image(
        &app,
        &body(json!({"retry": true})),
        &[
            ("cookie", "browser_session=private"),
            ("authorization", "private"),
            ("referer", "http://mail.example/private"),
        ],
    )
    .await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text());
    assert_eq!(response.body, png());
    assert_eq!(response.header("content-type"), Some("image/png"));
    assert_eq!(response.header("cache-control"), Some("no-store"));
    assert_eq!(response.header("x-content-type-options"), Some("nosniff"));
    assert_eq!(
        response.header("content-security-policy"),
        Some("default-src 'none'; sandbox")
    );
    assert!(response.header("set-cookie").is_none());
    let requests = image_server.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(
        requests[0].path,
        "/d/1NoNBoOQt2BCK3ki_4cUeRThRQz9Nrr5S=w1200"
    );
    let head = requests[0].head.to_lowercase();
    for secret in ["browser_session", "authorization", "referer", "private"] {
        assert!(!head.contains(secret), "{secret} leaked upstream");
    }
}

#[tokio::test]
async fn unregistered_urls_cannot_turn_endpoint_into_arbitrary_proxy() {
    let _serial = serial();
    let (_fetcher, calls) = install_fetcher(None, || {});
    let (app, state, _temporary) = test_app();
    register(&state);
    let response = post_image(
        &app,
        &body(json!({"url": "https://other.example/image.png"})),
        &[],
    )
    .await;
    assert_eq!(
        response.assert_json_error(StatusCode::FORBIDDEN),
        json!("This image was not found in the selected email")
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn expired_sources_are_reverified_with_peek_without_marking_read() {
    let _serial = serial();
    let raw = format!("Content-Type: text/html\r\n\r\n<img src=\"{IMAGE_URL}\">");
    let imap = FakeImapServer::builder()
        .credentials(USER, PASSWORD)
        .message_with("INBOX", FakeMessage::new(raw).with_uid(7))
        .start();
    let image_server = TestServer::start(|_, stream| respond_png(stream, &png()));
    let (_fetcher, _calls) = install_fetcher(Some(image_server.addr), || {});
    let (app, state, _temporary) = test_app();
    state.sessions.unlock(account_at(imap.port()));
    let response = post_image(&app, &body(json!({})), &[]).await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text());
    assert_eq!(response.body, png());
    let commands = imap.commands().join("\n").to_uppercase();
    assert!(commands.contains("PEEK"), "{commands}");
    assert!(!commands.contains("STORE"), "{commands}");
    assert_eq!(imap.flags("INBOX", 7), Some(Vec::new()));
    assert!(state.image_sources.sources(USER, "INBOX", 7).is_some());
}

#[tokio::test]
async fn reverification_of_a_url_not_in_the_message_is_forbidden() {
    let _serial = serial();
    let imap = FakeImapServer::builder()
        .credentials(USER, PASSWORD)
        .message_with(
            "INBOX",
            FakeMessage::new("Content-Type: text/plain\r\n\r\nno images").with_uid(7),
        )
        .start();
    let (_fetcher, calls) = install_fetcher(None, || {});
    let (app, state, _temporary) = test_app();
    state.sessions.unlock(account_at(imap.port()));
    let response = post_image(&app, &body(json!({})), &[]).await;
    response.assert_json_error(StatusCode::FORBIDDEN);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn remote_failure_is_generic_and_never_discloses_url_or_cookie() {
    let _serial = serial();
    let image_server = TestServer::start(|_, stream| {
        respond(
            stream,
            "404 Not Found",
            &[("Content-Length", "15".into())],
            b"private details",
        )
    });
    let (_fetcher, _calls) = install_fetcher(Some(image_server.addr), || {});
    let (app, state, _temporary) = test_app();
    register(&state);
    let response = post_image(&app, &body(json!({})), &[]).await;
    assert_eq!(response.status, StatusCode::BAD_GATEWAY);
    assert_eq!(
        response.json(),
        json!({"detail": "The remote image could not be downloaded safely"})
    );
}

#[tokio::test]
async fn account_lock_forgets_image_authorization_and_clears_downloads() {
    let _serial = serial();
    let image_server = TestServer::start(|_, stream| respond_png(stream, &png()));
    let (fetcher, _calls) = install_fetcher(Some(image_server.addr), || {});
    let (app, state, _temporary) = test_app();
    register(&state);
    let response = post_image(&app, &body(json!({})), &[]).await;
    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(fetcher.cache_len(), 1);
    let locked = call_router(
        app.clone(),
        Request::delete("/api/accounts/user%40example.com")
            .header("host", "127.0.0.1:48101")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(locked.status, StatusCode::OK, "{}", locked.text());
    assert_eq!(state.image_sources.sources(USER, "INBOX", 7), None);
    assert_eq!(fetcher.cache_len(), 0);
}

#[tokio::test]
async fn account_lock_during_download_does_not_serve_mail_image() {
    let _serial = serial();
    let image_server = TestServer::start(|_, stream| respond_png(stream, &png()));
    let (app, state, _temporary) = test_app();
    let sessions = state.sessions.clone();
    let (fetcher, _calls) = install_fetcher(Some(image_server.addr), move || {
        sessions.forget(USER);
    });
    register(&state);
    let response = post_image(&app, &body(json!({})), &[]).await;
    let detail = response.assert_json_error(StatusCode::UNAUTHORIZED);
    assert_eq!(detail, json!({"error": "password_required", "email": USER}));
    assert!(!response.body.windows(4).any(|window| window == b"IHDR"));
    // The downloaded bytes were discarded with the cache.
    assert_eq!(fetcher.cache_len(), 0);
}

#[tokio::test]
async fn allow_download_returns_real_connection_close_image_bytes() {
    let _serial = serial();
    let image_server = TestServer::start(|_, stream| respond_png(stream, &png()));
    let (_fetcher, _calls) = install_fetcher(Some(image_server.addr), || {});
    let (app, state, _temporary) = test_app();
    register(&state);
    let response = post_image(&app, &body(json!({"retry": true})), &[]).await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text());
    assert_eq!(response.body, png());
    assert_eq!(response.header("content-type"), Some("image/png"));
    assert_eq!(response.header("cache-control"), Some("no-store"));
    image_server.assert_closed(1);
}
