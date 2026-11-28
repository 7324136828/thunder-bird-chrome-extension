//! Multipart framing parity of `/api/mail/send/files` and
//! `PUT /api/mail/signature` with Starlette 1.x `Request.form()` over
//! python-multipart (outcomes recorded from the Python backend).

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::Router;
use common::*;
use mail_backend::AppState;
use mail_core::sessions::MailAccount;
use mail_core::settings::{scoped_settings_path, ScopedSettingsPath};
use mail_proto::testkit::{FakeImapServer, FakeSmtpServer};
use serde_json::{json, Value};

const USER: &str = "user@example.com";
const PASSWORD: &str = "s3cret-framing-pass";
const BOUNDARY: &str = "framing-boundary-1Zx9";
const SIGNATURE: &str = "/api/mail/signature?account=user@example.com";

struct Harness {
    app: Router,
    _state: AppState,
    smtp: FakeSmtpServer,
    _imap: FakeImapServer,
    _settings: ScopedSettingsPath,
    _temporary: tempfile::TempDir,
}

impl Harness {
    fn new() -> Self {
        let (app, state, temporary) = test_app();
        let settings = scoped_settings_path(temporary.path().join("settings.json"));
        let imap = FakeImapServer::builder()
            .folder("Sent", &["\\Sent"])
            .credentials(USER, PASSWORD)
            .start();
        let smtp = FakeSmtpServer::builder()
            .credentials(USER, PASSWORD)
            .start();
        state.sessions.unlock(MailAccount::new(
            USER,
            PASSWORD,
            "127.0.0.1",
            imap.port(),
            "none",
            "127.0.0.1",
            smtp.port(),
            "none",
        ));
        Self {
            app,
            _state: state,
            smtp,
            _imap: imap,
            _settings: settings,
            _temporary: temporary,
        }
    }

    async fn request(&self, method: &str, uri: &str, content_type: &str, body: Vec<u8>) -> Resp {
        let request = Request::builder()
            .method(method)
            .uri(uri)
            .header("host", "127.0.0.1:48101")
            .header("content-type", content_type)
            .header("content-length", body.len().to_string())
            .body(Body::from(body))
            .unwrap();
        call_router(self.app.clone(), request).await
    }

    async fn send_files(&self, content_type: &str, body: Vec<u8>) -> Resp {
        self.request("POST", "/api/mail/send/files", content_type, body)
            .await
    }

    async fn signature(&self, content_type: &str, body: Vec<u8>) -> Resp {
        self.request("PUT", SIGNATURE, content_type, body).await
    }
}

fn form(name: &str, value: &str) -> Vec<u8> {
    format!(
        "--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{value}\r\n--{BOUNDARY}--\r\n"
    )
    .into_bytes()
}

fn message_form() -> Vec<u8> {
    let message = json!({
        "account": USER, "to": ["to@example.com"], "subject": "Framing", "text": "Hello",
    });
    form("message", &message.to_string())
}

fn signature_form() -> Vec<u8> {
    form(
        "signature",
        &json!({"text": "<p>Regards</p>", "uploads": []}).to_string(),
    )
}

fn detail(response: &Resp, status: StatusCode) -> Value {
    response.assert_json_error(status)
}

#[tokio::test]
async fn unreadable_multipart_bodies_use_starlettes_message() {
    let h = Harness::new();
    let content_type = format!("multipart/form-data; boundary={BOUNDARY}");
    let response = h
        .send_files(&content_type, b"this is not multipart".to_vec())
        .await;
    assert_eq!(
        detail(&response, StatusCode::BAD_REQUEST),
        "Invalid multipart data."
    );
    let response = h.signature(&content_type, b"garbage".to_vec()).await;
    assert_eq!(
        detail(&response, StatusCode::BAD_REQUEST),
        "Invalid multipart data."
    );
    // `boundary=` (or `""`) is present but unusable: not "Missing boundary".
    for content_type in [
        "multipart/form-data; boundary=",
        "multipart/form-data; boundary=\"\"",
    ] {
        let response = h.send_files(content_type, b"x".to_vec()).await;
        assert_eq!(
            detail(&response, StatusCode::BAD_REQUEST),
            "Invalid multipart data.",
            "{content_type}"
        );
        let response = h.signature(content_type, b"x".to_vec()).await;
        assert_eq!(
            detail(&response, StatusCode::BAD_REQUEST),
            "Invalid multipart data.",
            "{content_type}"
        );
    }
    assert_eq!(h.smtp.connection_count(), 0);
}

#[tokio::test]
async fn mixed_case_media_type_with_parameters_reads_as_an_empty_form() {
    let h = Harness::new();
    // The routes lowercase the media type, but python-multipart keeps its
    // case once parameters follow, so `request.form()` is empty.
    let content_type = format!("Multipart/Form-Data; boundary={BOUNDARY}");
    let response = h.send_files(&content_type, message_form()).await;
    assert_eq!(
        detail(&response, StatusCode::BAD_REQUEST),
        "Provide one JSON message and its uploaded files"
    );
    let content_type = format!("MULTIPART/form-data; boundary={BOUNDARY}");
    let response = h.signature(&content_type, signature_form()).await;
    assert_eq!(
        detail(&response, StatusCode::BAD_REQUEST),
        "Provide one JSON signature and its uploaded images"
    );
    // Without parameters the media type is lowercased: the boundary is missing.
    let response = h.send_files("Multipart/Form-Data", b"x".to_vec()).await;
    assert_eq!(
        detail(&response, StatusCode::BAD_REQUEST),
        "Missing boundary in multipart."
    );
    assert_eq!(h.smtp.connection_count(), 0);
}

#[tokio::test]
async fn empty_bodies_are_forms_without_parts() {
    let h = Harness::new();
    let content_type = format!("multipart/form-data; boundary={BOUNDARY}");
    let response = h.send_files(&content_type, Vec::new()).await;
    assert_eq!(
        detail(&response, StatusCode::BAD_REQUEST),
        "Provide one JSON message and its uploaded files"
    );
    let response = h.signature(&content_type, Vec::new()).await;
    assert_eq!(
        detail(&response, StatusCode::BAD_REQUEST),
        "Provide one JSON signature and its uploaded images"
    );
}

#[tokio::test]
async fn boundary_parameter_spellings_python_multipart_accepts_still_parse() {
    let h = Harness::new();
    for content_type in [
        format!("multipart/form-data; Boundary={BOUNDARY}"),
        format!("multipart/form-data ; boundary = {BOUNDARY} "),
        format!("multipart/form-data; charset=utf-8; boundary=\"{BOUNDARY}\""),
    ] {
        let response = h.send_files(&content_type, message_form()).await;
        assert_eq!(
            response.status,
            StatusCode::OK,
            "{content_type}: {}",
            response.text()
        );
        assert_eq!(response.json()["sent"], true);
        let response = h.signature(&content_type, signature_form()).await;
        assert_eq!(
            response.status,
            StatusCode::OK,
            "{content_type}: {}",
            response.text()
        );
        assert_eq!(response.json()["text"], "<p>Regards</p>");
    }
    assert_eq!(h.smtp.messages().len(), 3);
}
