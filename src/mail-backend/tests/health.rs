//! `GET /api/health` (main.py `health`; Python tests assert
//! `client.get("/api/health").json() == {"status": "ok"}`).

mod common;

use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use common::*;
use serde_json::json;

#[tokio::test]
async fn health_returns_status_ok() {
    let response = call(get("/api/health").body(Body::empty()).unwrap()).await;
    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(response.json(), json!({"status": "ok"}));
    assert!(response
        .header("content-type")
        .is_some_and(|value| value.starts_with("application/json")));
}

#[tokio::test]
async fn health_answers_head_and_refuses_post() {
    let response = call(
        Request::builder()
            .method(Method::HEAD)
            .uri("/api/health")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(response.status, StatusCode::OK);

    let response = call(
        Request::post("/api/health")
            .header("host", "localhost:48101")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(
        response.assert_json_error(StatusCode::METHOD_NOT_ALLOWED),
        json!("Method Not Allowed")
    );
    let allow = response.header("allow").unwrap_or_default().to_uppercase();
    assert!(allow.contains("GET"), "allow: {allow}");
}

#[tokio::test]
async fn health_from_extension_gets_cors_headers() {
    let response = call(
        get("/api/health")
            .header("origin", EXTENSION_ORIGIN)
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(
        response.header("access-control-allow-origin"),
        Some(EXTENSION_ORIGIN)
    );
    assert_eq!(response.json(), json!({"status": "ok"}));
}
