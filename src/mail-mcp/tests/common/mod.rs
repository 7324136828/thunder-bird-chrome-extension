//! A tiny mock of the mail-backend HTTP API for tests.
//!
//! Every request is recorded (method, raw path, decoded query pairs, content
//! type, body) and answered by a test-supplied responder closure.

#![allow(dead_code)]

use std::sync::{Arc, Mutex};

use axum::body::{Body, Bytes};
use axum::extract::{DefaultBodyLimit, FromRequest, Multipart, State};
use axum::http::{header, HeaderMap, Method, Request, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::Router;
use serde_json::Value;

/// One request received by the mock backend.
#[derive(Debug, Clone)]
pub struct Recorded {
    pub method: String,
    /// Raw (percent-encoded) path.
    pub path: String,
    /// Decoded query pairs in order.
    pub query: Vec<(String, String)>,
    pub content_type: Option<String>,
    pub origin: Option<String>,
    pub body: Vec<u8>,
}

impl Recorded {
    /// `"METHOD /path"`, handy for asserting call sequences.
    pub fn route(&self) -> String {
        format!("{} {}", self.method, self.path)
    }

    pub fn json(&self) -> Value {
        serde_json::from_slice(&self.body).expect("request body is JSON")
    }

    pub fn query_value(&self, name: &str) -> Option<&str> {
        self.query
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    }

    pub fn query_pairs(&self) -> Vec<(&str, &str)> {
        self.query
            .iter()
            .map(|(key, value)| (key.as_str(), value.as_str()))
            .collect()
    }
}

/// A canned response.
#[derive(Debug, Clone)]
pub struct MockResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl MockResponse {
    pub fn json(status: u16, value: Value) -> Self {
        Self {
            status,
            headers: vec![("content-type".into(), "application/json".into())],
            body: serde_json::to_vec(&value).unwrap(),
        }
    }

    pub fn ok(value: Value) -> Self {
        Self::json(200, value)
    }

    /// FastAPI-style error: `{"detail": detail}`.
    pub fn detail(status: u16, detail: Value) -> Self {
        Self::json(status, serde_json::json!({ "detail": detail }))
    }

    pub fn bytes(content_type: &str, body: Vec<u8>) -> Self {
        Self {
            status: 200,
            headers: vec![("content-type".into(), content_type.into())],
            body,
        }
    }

    pub fn with_header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }
}

pub type Responder = Arc<dyn Fn(&Recorded) -> MockResponse + Send + Sync>;

#[derive(Clone)]
struct MockState {
    responder: Responder,
    requests: Arc<Mutex<Vec<Recorded>>>,
}

/// A running mock backend.
pub struct MockBackend {
    pub url: String,
    requests: Arc<Mutex<Vec<Recorded>>>,
}

impl MockBackend {
    /// Start a mock backend on an ephemeral loopback port.
    pub async fn start(
        responder: impl Fn(&Recorded) -> MockResponse + Send + Sync + 'static,
    ) -> Self {
        let requests = Arc::new(Mutex::new(Vec::new()));
        let state = MockState {
            responder: Arc::new(responder),
            requests: requests.clone(),
        };
        let app = Router::new()
            .fallback(handle)
            .layer(DefaultBodyLimit::disable())
            .with_state(state);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        Self {
            url: format!("http://{address}"),
            requests,
        }
    }

    pub fn requests(&self) -> Vec<Recorded> {
        self.requests.lock().unwrap().clone()
    }

    pub fn routes(&self) -> Vec<String> {
        self.requests().iter().map(Recorded::route).collect()
    }
}

async fn handle(
    State(state): State<MockState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let query = uri
        .query()
        .map(|query| {
            url::form_urlencoded::parse(query.as_bytes())
                .map(|(key, value)| (key.into_owned(), value.into_owned()))
                .collect()
        })
        .unwrap_or_default();
    let header_text = |name| {
        headers
            .get(name)
            .and_then(|value: &header::HeaderValue| value.to_str().ok())
            .map(str::to_string)
    };
    let recorded = Recorded {
        method: method.to_string(),
        path: uri.path().to_string(),
        query,
        content_type: header_text(header::CONTENT_TYPE),
        origin: header_text(header::ORIGIN),
        body: body.to_vec(),
    };
    let reply = (state.responder)(&recorded);
    state.requests.lock().unwrap().push(recorded);
    let mut response = (StatusCode::from_u16(reply.status).unwrap(), reply.body).into_response();
    for (name, value) in reply.headers {
        response.headers_mut().insert(
            header::HeaderName::from_bytes(name.as_bytes()).unwrap(),
            header::HeaderValue::from_str(&value).unwrap(),
        );
    }
    response
}

/// One multipart field.
#[derive(Debug, Clone)]
pub struct Field {
    pub name: String,
    pub file_name: Option<String>,
    pub content_type: Option<String>,
    pub data: Vec<u8>,
}

/// Parse a recorded multipart/form-data body.
pub async fn multipart_fields(recorded: &Recorded) -> Vec<Field> {
    let request = Request::builder()
        .method("POST")
        .header(header::CONTENT_TYPE, recorded.content_type.clone().unwrap())
        .body(Body::from(recorded.body.clone()))
        .unwrap();
    let mut multipart = Multipart::from_request(request, &()).await.unwrap();
    let mut fields = Vec::new();
    while let Some(field) = multipart.next_field().await.unwrap() {
        let name = field.name().unwrap_or_default().to_string();
        let file_name = field.file_name().map(str::to_string);
        let content_type = field.content_type().map(str::to_string);
        let data = field.bytes().await.unwrap().to_vec();
        fields.push(Field {
            name,
            file_name,
            content_type,
            data,
        });
    }
    fields
}
