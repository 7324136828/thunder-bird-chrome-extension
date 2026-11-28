//! Host / Origin guard and CORS (ported from the_editor's
//! `security_origin_and_host` test, adapted to this API).

mod common;

use axum::body::Body;
use axum::http::{header, HeaderValue, Method, Request, StatusCode};
use common::*;

#[tokio::test]
async fn web_origins_are_refused_without_cors_grant() {
    // A simple text/plain POST from a web page (no preflight) is refused
    // before any handler runs.
    let response = call(
        Request::post("/api/accounts/unlock")
            .header("host", "127.0.0.1:48101")
            .header("origin", "https://evil.example")
            .header("content-type", "text/plain")
            .body(Body::from("{}"))
            .unwrap(),
    )
    .await;
    let detail = response.assert_json_error(StatusCode::FORBIDDEN);
    assert!(
        detail.as_str().unwrap().starts_with("Forbidden"),
        "{detail}"
    );
    assert!(response
        .headers
        .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
        .is_none());

    // The old web frontend origin is no longer trusted either.
    let response = call(
        get("/api/health")
            .header("origin", "http://localhost:3741")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    response.assert_json_error(StatusCode::FORBIDDEN);

    // Preflight from a web origin: 403, no CORS grant.
    let preflight = Request::builder()
        .method(Method::OPTIONS)
        .uri("/api/mail/send")
        .header("origin", "https://evil.example")
        .header("access-control-request-method", "POST")
        .header("access-control-request-headers", "content-type")
        .body(Body::empty())
        .unwrap();
    let response = call(preflight).await;
    assert_eq!(response.status, StatusCode::FORBIDDEN);
    assert!(response
        .headers
        .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
        .is_none());

    // "null" origin (sandboxed iframes, file://) is refused.
    let response = call(
        get("/api/health")
            .header("origin", "null")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    response.assert_json_error(StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn foreign_host_is_refused() {
    // DNS rebinding: a foreign Host header.
    let response = call(
        Request::get("/api/health")
            .header("host", "attacker.example:48101")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    let detail = response.assert_json_error(StatusCode::FORBIDDEN);
    assert!(
        detail.as_str().unwrap().contains("attacker.example"),
        "{detail}"
    );

    // Even with an extension origin.
    let response = call(
        Request::get("/api/health")
            .header("host", "127.0.0.1.nip.io:48101")
            .header("origin", EXTENSION_ORIGIN)
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    response.assert_json_error(StatusCode::FORBIDDEN);

    // Loopback names with any port are fine.
    for host in [
        "localhost",
        "127.0.0.1:1",
        "127.0.0.2:48101",
        "[::1]:48101",
        "LOCALHOST:48101",
    ] {
        let response = call(
            Request::get("/api/health")
                .header("host", host)
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(response.status, StatusCode::OK, "{host}");
    }
}

#[tokio::test]
async fn extension_preflight_and_request_get_cors_headers() {
    let preflight = Request::builder()
        .method(Method::OPTIONS)
        .uri("/api/mail/message")
        .header("host", "localhost:48101")
        .header("origin", EXTENSION_ORIGIN)
        .header("access-control-request-method", "DELETE")
        .header("access-control-request-headers", "content-type")
        .body(Body::empty())
        .unwrap();
    let response = call(preflight).await;
    assert!(response.status.is_success(), "{}", response.status);
    assert_eq!(
        response.header("access-control-allow-origin"),
        Some(EXTENSION_ORIGIN)
    );
    let methods = response
        .header("access-control-allow-methods")
        .unwrap_or_default()
        .to_ascii_uppercase();
    for method in ["GET", "POST", "PUT", "DELETE"] {
        assert!(methods.contains(method), "{methods}");
    }
    let allowed = response
        .header("access-control-allow-headers")
        .unwrap_or_default()
        .to_ascii_lowercase();
    assert!(allowed.contains("content-type"), "{allowed}");

    let mut request = get("/api/health").body(Body::empty()).unwrap();
    request
        .headers_mut()
        .insert(header::ORIGIN, HeaderValue::from_static(EXTENSION_ORIGIN));
    let response = call(request).await;
    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(
        response.header("access-control-allow-origin"),
        Some(EXTENSION_ORIGIN)
    );
    let exposed = response
        .header("access-control-expose-headers")
        .unwrap_or_default()
        .to_ascii_lowercase();
    assert!(exposed.contains("content-disposition"), "{exposed}");

    // Errors produced for extension requests still carry CORS headers so the
    // frontend can read the JSON detail.
    let response = call(
        get("/api/does-not-exist")
            .header("origin", EXTENSION_ORIGIN)
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    response.assert_json_error(StatusCode::NOT_FOUND);
    assert_eq!(
        response.header("access-control-allow-origin"),
        Some(EXTENSION_ORIGIN)
    );
}

#[tokio::test]
async fn edge_extension_and_originless_tools_are_allowed() {
    // Edge derives the same pinned id from the manifest key.
    for origin in [
        EXTENSION_ORIGIN,
        "extension://hhhanbkdjaecdfoclhpoicmfhejdbkjl",
    ] {
        let response = call(
            get("/api/health")
                .header("origin", origin)
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(response.status, StatusCode::OK, "{origin}");
        assert_eq!(response.header("access-control-allow-origin"), Some(origin));
    }
    // Other extension ids, Edge's or Firefox's (random per-install UUIDs),
    // need MAIL_BACKEND_EXTENSION_IDS: refused by default, no CORS grant.
    for origin in [
        "extension://abcdef",
        "moz-extension://1b2c-3d",
        "chrome-extension://omagnaefngeklmcndepoihhodddomkgo",
    ] {
        let response = call(
            get("/api/health")
                .header("origin", origin)
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        response.assert_json_error(StatusCode::FORBIDDEN);
        assert!(response
            .headers
            .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
            .is_none());
    }
    // No Origin at all (MCP server, curl): allowed, no CORS headers.
    let response = call(get("/api/health").body(Body::empty()).unwrap()).await;
    assert_eq!(response.status, StatusCode::OK);
    assert!(response
        .headers
        .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
        .is_none());
    // No Host header at all (HTTP/1.0 tools, oneshot): allowed.
    let response = call(Request::get("/api/health").body(Body::empty()).unwrap()).await;
    assert_eq!(response.status, StatusCode::OK);
}

#[tokio::test]
async fn cross_site_probes_without_origin_are_refused() {
    // <img src="http://127.0.0.1:48101/api/health"> on a web page.
    for site in ["cross-site", "same-site", "Cross-Site"] {
        let response = call(
            get("/api/health")
                .header("sec-fetch-site", site)
                .header("sec-fetch-dest", "image")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        response.assert_json_error(StatusCode::FORBIDDEN);
    }
    // ...but the user opening the URL in a tab is fine.
    for site in ["none", "same-origin"] {
        let response = call(
            get("/api/health")
                .header("sec-fetch-site", site)
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(response.status, StatusCode::OK, "{site}");
    }
}

#[tokio::test]
async fn oauth_callback_exemption_is_narrow() {
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    // Cross-site subresource probes of the callback stay refused.
    for (method, path, mode, dest) in [
        ("GET", "/api/mail/oauth/google/callback", "no-cors", "image"),
        (
            "POST",
            "/api/mail/oauth/google/callback",
            "navigate",
            "document",
        ),
        (
            "GET",
            "/api/mail/oauth/google/x/callback",
            "navigate",
            "document",
        ),
        ("GET", "/api/jobs", "navigate", "document"),
    ] {
        let request = Request::builder()
            .method(method)
            .uri(path)
            .header("host", "127.0.0.1:48101")
            .header("sec-fetch-site", "cross-site")
            .header("sec-fetch-mode", mode)
            .header("sec-fetch-dest", dest)
            .body(Body::empty())
            .unwrap();
        let response = common::call(request).await;
        assert_eq!(
            response.status,
            StatusCode::FORBIDDEN,
            "{method} {path} {mode} {dest}"
        );
    }
}
