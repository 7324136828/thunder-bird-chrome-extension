//! Security audit: Host / Origin / Sec-Fetch guard, the OAuth callback
//! exemption, CORS and request-size limits.

mod common;

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use common::*;

const CALLBACK: &str = "/api/mail/oauth/google/callback?state=unknown&code=x";

fn with_headers(method: Method, uri: &str, headers: &[(&str, &str)]) -> Request<Body> {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header("host", "127.0.0.1:48101");
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    builder.body(Body::empty()).unwrap()
}

#[tokio::test]
async fn host_header_tricks_are_refused() {
    for host in [
        "localhost.",
        "127.0.0.1.",
        "127.1:48101",
        "2130706433:48101",
        "0x7f000001",
        "user@127.0.0.1:48101",
        "127.0.0.1:48101@evil.example",
        "127.0.0.1 evil.example",
        "[::ffff:127.0.0.1]:48101",
        "localhost:48101,evil.example",
    ] {
        let response = call(
            Request::get("/api/accounts")
                .header("host", host)
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(response.status, StatusCode::FORBIDDEN, "Host {host:?}");
    }
}

#[tokio::test]
async fn web_page_probes_without_origin_are_refused() {
    // <img src>/<script src>/<link> and no-cors fetches from a web page carry
    // no Origin on GET but do carry Sec-Fetch-Site.
    for uri in [
        "/api/accounts",
        "/api/mail/message/attachment?account=user@example.com&uid=1&index=0",
        "/api/jobs",
        "/api/mail/servers",
    ] {
        for site in ["cross-site", "same-site", "CROSS-SITE"] {
            let response = call(with_headers(
                Method::GET,
                uri,
                &[("sec-fetch-site", site), ("sec-fetch-mode", "no-cors")],
            ))
            .await;
            assert_eq!(response.status, StatusCode::FORBIDDEN, "{uri} {site}");
        }
    }
}

#[tokio::test]
async fn oauth_callback_exemption_only_covers_top_level_get_navigation() {
    // The provider's redirect of the sign-in window is let through.
    let response = call(with_headers(
        Method::GET,
        CALLBACK,
        &[
            ("sec-fetch-site", "cross-site"),
            ("sec-fetch-mode", "navigate"),
            ("sec-fetch-dest", "document"),
        ],
    ))
    .await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text());
    assert_eq!(response.header("cache-control"), Some("no-store"));
    assert_eq!(response.header("referrer-policy"), Some("no-referrer"));

    // Framing, sub-resource probes and other paths stay blocked.
    for (method, uri, mode, dest) in [
        (Method::GET, CALLBACK, "navigate", "iframe"),
        (Method::GET, CALLBACK, "no-cors", "image"),
        (Method::GET, CALLBACK, "cors", "empty"),
        (Method::POST, CALLBACK, "navigate", "document"),
        (
            Method::GET,
            "/api/mail/oauth/google/callback/../../../../api/accounts",
            "navigate",
            "document",
        ),
        (
            Method::GET,
            "/api/mail/oauth/x/y/callback",
            "navigate",
            "document",
        ),
        (Method::GET, "/api/accounts", "navigate", "document"),
    ] {
        let response = call(with_headers(
            method.clone(),
            uri,
            &[
                ("sec-fetch-site", "cross-site"),
                ("sec-fetch-mode", mode),
                ("sec-fetch-dest", dest),
            ],
        ))
        .await;
        assert_ne!(
            response.status,
            StatusCode::OK,
            "{method} {uri} {mode}/{dest} was let through"
        );
    }
}

#[tokio::test]
async fn oauth_callback_page_does_not_reflect_query_values() {
    let marker = "%3Cscript%3Ealert(1)%3C%2Fscript%3E";
    let response = call(with_headers(
        Method::GET,
        &format!("/api/mail/oauth/google/callback?state={marker}&code={marker}&error={marker}"),
        &[],
    ))
    .await;
    assert_eq!(response.status, StatusCode::OK);
    let page = response.text();
    assert!(!page.contains("<script>alert"), "{page}");
    assert!(!page.contains("alert(1)"), "{page}");
}

#[tokio::test]
async fn web_origin_preflight_never_gets_a_cors_grant() {
    for origin in [
        "https://evil.example",
        "http://127.0.0.1:48101",
        "null",
        "chrome-extension://",
        "chrome-extension://abc/../x",
        "chrome-extension://abc.evil.example:80",
        "chrome-extensionx://abc",
    ] {
        let response = call(with_headers(
            Method::OPTIONS,
            "/api/accounts/unlock",
            &[
                ("origin", origin),
                ("access-control-request-method", "POST"),
                ("access-control-request-headers", "content-type"),
            ],
        ))
        .await;
        assert!(
            response
                .headers
                .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .is_none(),
            "{origin} got a CORS grant"
        );
    }
}

/// Only this extension's pinned id is trusted by default: another installed
/// extension (even one with no host permission, which would otherwise rely
/// on the reflected CORS grant) must not be able to call
/// `GET /api/mail/messages`, read mail, send mail or empty Trash.
#[tokio::test]
async fn foreign_extension_origin_is_refused() {
    let foreign = "chrome-extension://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let response = call(with_headers(
        Method::GET,
        "/api/accounts",
        &[("origin", foreign)],
    ))
    .await;
    assert_eq!(
        response.status,
        StatusCode::FORBIDDEN,
        "a foreign extension read /api/accounts (ACAO: {:?})",
        response.header("access-control-allow-origin")
    );
}

/// A 422 whose echoed `input` is larger than 1 MiB on `/api/accounts/unlock`
/// or `/api/settings` (re-encoded by `error::reencode_ascii_validation`) is
/// still a 422, like Python, not a 500.
#[tokio::test]
async fn large_invalid_unlock_input_is_a_422_not_a_500() {
    let name = "a".repeat(2 * 1024 * 1024);
    let body =
        serde_json::json!({"email": "user@example.com", "password": "p", "display_name": name});
    for path in ["/api/settings", "/api/accounts/unlock"] {
        let method = if path == "/api/settings" {
            Method::PUT
        } else {
            Method::POST
        };
        let body = if path == "/api/settings" {
            serde_json::json!({"signature": "a".repeat(2 * 1024 * 1024)})
        } else {
            body.clone()
        };
        let response = call(
            Request::builder()
                .method(method)
                .uri(path)
                .header("host", "127.0.0.1:48101")
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await;
        assert_eq!(
            response.status,
            StatusCode::UNPROCESSABLE_ENTITY,
            "{path}: {}",
            response.text().chars().take(200).collect::<String>()
        );
    }
}

/// JSON routes without their own size layer are capped by the global default
/// body limit (`limits::DEFAULT_BODY_LIMIT`, 4 MiB): a larger body is a JSON
/// 413 instead of being buffered whole before validation rejects it.
#[tokio::test]
async fn oversized_json_bodies_are_rejected_before_buffering() {
    let padding = "a".repeat(16 * 1024 * 1024);
    let body = format!(
        "{{\"email\":\"user@example.com\",\"password\":\"p\",\"display_name\":\"{padding}\"}}"
    );
    let response = call(
        Request::post("/api/accounts/unlock")
            .header("host", "127.0.0.1:48101")
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap(),
    )
    .await;
    assert_eq!(
        response.assert_json_error(StatusCode::PAYLOAD_TOO_LARGE),
        serde_json::json!("Request exceeds maximum allowed size")
    );
}

/// FastAPI/pydantic echo `input` in 422 issues; for a missing field the
/// input is the whole body, so Python sends the password back in the error
/// (and for an over-long password, the password itself). The port redacts
/// it (intentional deviation): no UI or MCP layer that logs or displays
/// error details can expose the secret.
#[tokio::test]
async fn unlock_validation_errors_do_not_echo_the_password() {
    let secret = "Audit-Secret-Value-123";
    let mut leaks = Vec::new();
    for body in [
        serde_json::json!({"email": "ab", "password": secret}),
        serde_json::json!({"password": secret}),
        serde_json::json!({"email": 5, "password": secret}),
        serde_json::json!({"email": "user@example.com", "password": secret, "incoming_port": "x"}),
        serde_json::json!({"email": "user@example.com", "password": format!("{secret}{}", "x".repeat(4096))}),
    ] {
        let response = call(
            Request::post("/api/accounts/unlock")
                .header("host", "127.0.0.1:48101")
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await;
        assert_eq!(response.status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
        if response.text().contains(secret) {
            leaks.push(format!("{body} -> {}", response.text()));
        }
    }
    assert!(
        leaks.is_empty(),
        "422 echoes the password:
{}",
        leaks.join(
            "
"
        )
    );
}

/// Same as above for `POST /api/mail/jobs` (Inbox Doctor credentials).
#[tokio::test]
async fn doctor_credentials_validation_errors_do_not_echo_the_password() {
    let secret = "Audit-Secret-Value-456";
    let mut leaks = Vec::new();
    for body in [
        serde_json::json!({"password": secret}),
        serde_json::json!({"email": "user@example.com", "password": secret, "days": "x"}),
    ] {
        let response = call(
            Request::post("/api/mail/jobs")
                .header("host", "127.0.0.1:48101")
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await;
        assert_eq!(response.status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
        if response.text().contains(secret) {
            leaks.push(format!("{body} -> {}", response.text()));
        }
    }
    assert!(
        leaks.is_empty(),
        "422 echoes the password:
{}",
        leaks.join(
            "
"
        )
    );
}

/// Routes with a larger limit than the global default keep it: the pasted
/// message audit (64 MiB) and the JSON send (its own 8 MiB layer) accept
/// bodies above 4 MiB and answer from the handler, not with a 413.
#[tokio::test]
async fn route_specific_body_limits_override_the_default() {
    let content = format!(
        "From: a@example.com\r\nSubject: big\r\n\r\n{}",
        "line of text\r\n".repeat(5 * 1024 * 1024 / 14)
    );
    let response = call(
        Request::post("/api/audit/eml")
            .header("host", "127.0.0.1:48101")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::json!({ "content": content }).to_string(),
            ))
            .unwrap(),
    )
    .await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text());

    let body =
        serde_json::json!({"account": "user@example.com", "text": "a".repeat(5 * 1024 * 1024)});
    let response = call(
        Request::post("/api/mail/send")
            .header("host", "127.0.0.1:48101")
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap(),
    )
    .await;
    assert_ne!(response.status, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(response.status, StatusCode::UNPROCESSABLE_ENTITY);
}

/// FastAPI's `strict_content_type`: valid JSON sent without a Content-Type
/// is not parsed (422 `model_attributes_type` echoing the raw text).
#[tokio::test]
async fn json_without_content_type_is_a_model_attributes_422() {
    let raw = r#"{"account":"user@example.com","to":["a@example.com"],"subject":"x"}"#;
    let response = call(
        Request::post("/api/mail/send")
            .header("host", "127.0.0.1:48101")
            .body(Body::from(raw))
            .unwrap(),
    )
    .await;
    assert_eq!(
        response.assert_json_error(StatusCode::UNPROCESSABLE_ENTITY),
        serde_json::json!([{"type": "model_attributes_type", "loc": ["body"],
                "msg": "Input should be a valid dictionary or object to extract fields from",
                "input": raw}])
    );
}
