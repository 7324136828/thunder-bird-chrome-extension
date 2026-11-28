//! End-to-end: the extension reads `response.json().detail` for every
//! failed request (api.ts `request()` → `ApiError`, e.g. the
//! `password_required` re-unlock prompt). A browser hides the body of a
//! cross-origin response without `Access-Control-Allow-Origin`, so every
//! error status the extension can receive must carry the CORS headers.

mod e2e_support;

use axum::body::Body;
use axum::http::{Method, StatusCode};
use e2e_support::*;
use serde_json::json;

#[track_caller]
fn assert_cors(response: &Resp, status: StatusCode) {
    assert_eq!(response.status, status, "{}", response.text());
    assert_eq!(
        response.header("access-control-allow-origin"),
        Some(ORIGIN),
        "status {status} without CORS headers: {:?}",
        response.headers
    );
    assert!(
        response
            .header("content-type")
            .is_some_and(|value| value.starts_with("application/json")),
        "{:?}",
        response.headers
    );
}

#[tokio::test]
async fn every_error_status_carries_cors_headers_for_the_extension() {
    let app = E2e::new();

    // 401 password_required
    let response = app
        .get(
            "/api/mail/messages",
            &[("account", USER), ("folder", "INBOX")],
        )
        .await;
    assert_cors(&response, StatusCode::UNAUTHORIZED);
    response.assert_locked(USER);

    // 422 validation (query and body)
    let response = app.get("/api/mail/messages", &[]).await;
    assert_cors(&response, StatusCode::UNPROCESSABLE_ENTITY);
    let response = app
        .post_json("/api/accounts/unlock", &json!({"email": "x"}))
        .await;
    assert_cors(&response, StatusCode::UNPROCESSABLE_ENTITY);

    // 400 invalid email
    let response = app
        .post_json(
            "/api/accounts/unlock",
            &json!({"email": "no-at-sign", "password": "x"}),
        )
        .await;
    assert_cors(&response, StatusCode::BAD_REQUEST);

    // 404 unknown profile / route / unlocked account
    let response = app
        .post_json(
            "/api/accounts/unlock",
            &json!({"email": USER, "password": "x", "profile_key": "missing"}),
        )
        .await;
    assert_cors(&response, StatusCode::NOT_FOUND);
    let response = app.get("/api/does-not-exist", &[]).await;
    assert_cors(&response, StatusCode::NOT_FOUND);
    let response = app.delete(&format!("/api/accounts/{USER}"), &[]).await;
    assert_cors(&response, StatusCode::NOT_FOUND);

    // 405
    let response = app
        .send(
            E2e::builder(Method::PATCH, "/api/accounts")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_cors(&response, StatusCode::METHOD_NOT_ALLOWED);

    // 401 from unlock (server unreachable)
    let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = closed.local_addr().unwrap().port();
    drop(closed);
    let response = app
        .post_json(
            "/api/accounts/unlock",
            &json!({"email": USER, "password": "x", "incoming_server": "127.0.0.1",
                    "incoming_port": port, "incoming_protocol": "NONE"}),
        )
        .await;
    assert_cors(&response, StatusCode::UNAUTHORIZED);

    // 413 request too large (send JSON limit 8 MiB, by Content-Length)
    let response = app
        .send(
            E2e::builder(Method::POST, "/api/mail/send")
                .header("content-type", "application/json")
                .header("content-length", (9 * 1024 * 1024).to_string())
                .body(Body::from(vec![b' '; 9 * 1024 * 1024]))
                .unwrap(),
        )
        .await;
    assert_cors(&response, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(
        response.error(StatusCode::PAYLOAD_TOO_LARGE),
        "Request exceeds maximum allowed size"
    );

    // 400 malformed multipart
    let response = app
        .send(
            E2e::builder(Method::POST, "/api/mail/send/files")
                .header(
                    "content-type",
                    format!("multipart/form-data; boundary={BOUNDARY}"),
                )
                .body(Body::from("garbage without boundary"))
                .unwrap(),
        )
        .await;
    assert!(
        response.status.is_client_error(),
        "{} {}",
        response.status,
        response.text()
    );
    assert_eq!(response.header("access-control-allow-origin"), Some(ORIGIN));

    // 404 Doctor job
    let response = app.get("/api/jobs/does-not-exist", &[]).await;
    assert_cors(&response, StatusCode::NOT_FOUND);
    assert_eq!(response.error(StatusCode::NOT_FOUND), "Job not found");

    // 404 trash operation (after an unlock is required: 401 first)
    let response = app
        .post_json("/api/mail/trash/abc/empty", &json!({"account": USER}))
        .await;
    assert_cors(&response, StatusCode::UNAUTHORIZED);
}
