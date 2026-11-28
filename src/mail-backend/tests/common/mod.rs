//! Shared helpers for the mail-backend integration tests.

#![allow(dead_code)]

use axum::body::Body;
use axum::http::{HeaderMap, Request, StatusCode};
use axum::Router;
use mail_backend::{build_app, AppState};
use serde_json::Value;
use tower::ServiceExt;

/// A buffered response.
pub struct Resp {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: Vec<u8>,
}

impl Resp {
    pub fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap_or_else(|error| {
            panic!(
                "not JSON ({error}): {:?}",
                String::from_utf8_lossy(&self.body)
            )
        })
    }

    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }

    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).and_then(|value| value.to_str().ok())
    }

    /// Assert a JSON error with `status`; returns the `detail`.
    pub fn assert_json_error(&self, status: StatusCode) -> Value {
        assert_eq!(self.status, status, "body: {}", self.text());
        assert!(
            self.header("content-type")
                .is_some_and(|value| value.starts_with("application/json")),
            "content-type: {:?}",
            self.header("content-type")
        );
        self.json()
            .get("detail")
            .cloned()
            .unwrap_or_else(|| panic!("no detail in {}", self.text()))
    }
}

/// Send one request through `app`.
pub async fn call_router(app: Router, request: Request<Body>) -> Resp {
    let response = app.oneshot(request).await.expect("infallible");
    let status = response.status();
    let headers = response.headers().clone();
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("read body")
        .to_vec();
    Resp {
        status,
        headers,
        body,
    }
}

/// A fresh production app over an isolated temporary state.
pub fn test_app() -> (Router, AppState, tempfile::TempDir) {
    let temporary = tempfile::tempdir().expect("tempdir");
    let state = AppState::for_tests(temporary.path());
    (build_app(state.clone()), state, temporary)
}

/// Send one request through a fresh production app.
pub async fn call(request: Request<Body>) -> Resp {
    let (app, _state, _temporary) = test_app();
    call_router(app, request).await
}

pub fn get(uri: &str) -> axum::http::request::Builder {
    Request::get(uri).header("host", "127.0.0.1:48101")
}

pub const EXTENSION_ORIGIN: &str = "chrome-extension://hhhanbkdjaecdfoclhpoicmfhejdbkjl";
