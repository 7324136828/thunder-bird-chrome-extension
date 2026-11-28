//! Port of `tests/test_send_files.py` (`SendFilesApiTests`) and the
//! request-size part of `tests/test_send_proxy.py`, against the real routes
//! with fake SMTP/IMAP servers instead of a mocked `smtp_client.send_message`.
//!
//! Python inspected the mocked `send_message` call; here the message the fake
//! SMTP server received is parsed. Python patched the size constants
//! (`MAX_SEND_FILE_BYTES = 10`, `MAX_SEND_REQUEST_BYTES = 100`); the Rust
//! limits are constants, so those tests use real-sized bodies.
//! `test_send_proxy.py` otherwise tests the packaged frontend proxy
//! (`create_frontend_app`), which has no counterpart: the extension calls
//! the backend directly.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::Router;
use common::*;
use mail_backend::AppState;
use mail_core::sessions::MailAccount;
use mail_core::settings::{scoped_settings_path, ScopedSettingsPath};
use mail_parser::{MessageParser, MimeHeaders};
use mail_proto::testkit::{Failure, FakeImapServer, FakeSmtpServer};
use serde_json::{json, Value};

const USER: &str = "user@example.com";
const PASSWORD: &str = "s3cret-send-pass";
const BOUNDARY: &str = "test-boundary-7MA4YWxkTrZu0gW";
const MIB: usize = 1024 * 1024;

fn png_chunk(kind: &[u8], data: &[u8]) -> Vec<u8> {
    let mut chunk = (data.len() as u32).to_be_bytes().to_vec();
    chunk.extend_from_slice(kind);
    chunk.extend_from_slice(data);
    let mut hasher = crc32fast::Hasher::new();
    hasher.update(kind);
    hasher.update(data);
    chunk.extend_from_slice(&hasher.finalize().to_be_bytes());
    chunk
}

fn png() -> Vec<u8> {
    let mut data = b"\x89PNG\r\n\x1a\n".to_vec();
    data.extend(png_chunk(b"IHDR", &[0, 0, 0, 1, 0, 0, 0, 1, 8, 6, 0, 0, 0]));
    data.extend(png_chunk(
        b"IDAT",
        b"x\x9cc\xf8\xcf\xc0\xf0\x1f\x00\x05\x00\x01\xff",
    ));
    data.extend(png_chunk(b"IEND", b""));
    data
}

/// One multipart form part.
struct FormPart {
    name: &'static str,
    filename: Option<String>,
    content_type: Option<&'static str>,
    data: Vec<u8>,
}

fn field(name: &'static str, value: &str) -> FormPart {
    FormPart {
        name,
        filename: None,
        content_type: None,
        data: value.as_bytes().to_vec(),
    }
}

fn file(filename: &str, data: &[u8], content_type: &'static str) -> FormPart {
    FormPart {
        name: "files",
        filename: Some(filename.to_string()),
        content_type: Some(content_type),
        data: data.to_vec(),
    }
}

fn message_part(body: &Value) -> FormPart {
    FormPart {
        name: "message",
        filename: None,
        content_type: Some("application/json"),
        data: body.to_string().into_bytes(),
    }
}

fn multipart(parts: &[FormPart]) -> Vec<u8> {
    let mut body = Vec::new();
    for part in parts {
        body.extend_from_slice(format!("--{BOUNDARY}\r\n").as_bytes());
        let mut disposition = format!("Content-Disposition: form-data; name=\"{}\"", part.name);
        if let Some(filename) = &part.filename {
            disposition.push_str(&format!("; filename=\"{filename}\""));
        }
        body.extend_from_slice(disposition.as_bytes());
        body.extend_from_slice(b"\r\n");
        if let Some(content_type) = part.content_type {
            body.extend_from_slice(format!("Content-Type: {content_type}\r\n").as_bytes());
        }
        body.extend_from_slice(b"\r\n");
        body.extend_from_slice(&part.data);
        body.extend_from_slice(b"\r\n");
    }
    body.extend_from_slice(format!("--{BOUNDARY}--\r\n").as_bytes());
    body
}

struct Harness {
    app: Router,
    state: AppState,
    smtp: FakeSmtpServer,
    imap: FakeImapServer,
    account: MailAccount,
    _settings: ScopedSettingsPath,
    _temporary: tempfile::TempDir,
}

impl Harness {
    fn new() -> Self {
        Self::with_imap(
            FakeImapServer::builder()
                .folder("Sent Items", &["\\Sent"])
                .credentials(USER, PASSWORD)
                .start(),
        )
    }

    fn with_imap(imap: FakeImapServer) -> Self {
        let (app, state, temporary) = test_app();
        let settings = scoped_settings_path(temporary.path().join("settings.json"));
        let smtp = FakeSmtpServer::builder()
            .credentials(USER, PASSWORD)
            .start();
        let account = MailAccount::new(
            USER,
            PASSWORD,
            "127.0.0.1",
            imap.port(),
            "none",
            "127.0.0.1",
            smtp.port(),
            "none",
        );
        state.sessions.unlock(account.clone());
        Self {
            app,
            state,
            smtp,
            imap,
            account,
            _settings: settings,
            _temporary: temporary,
        }
    }

    fn body(&self) -> Value {
        json!({
            "account": self.account.email, "to": ["to@example.com"], "subject": "Reply", "text": "Hello",
            "html": "<p>Hello<img src=\"cid:photo@draft\"></p>", "in_reply_to": "<original@example.com>",
            "uploads": [{"disposition": "inline", "content_id": "photo@draft"},
                        {"disposition": "attachment", "content_id": ""}],
        })
    }

    fn body_with(&self, changes: Value) -> Value {
        let mut body = self.body();
        for (key, value) in changes.as_object().unwrap() {
            body[key] = value.clone();
        }
        body
    }

    fn default_files() -> Vec<FormPart> {
        vec![
            file("photo.png", &png(), "image/png"),
            file("report.pdf", b"%PDF-test\x00\xff", "application/pdf"),
        ]
    }

    async fn post_raw(&self, uri: &str, content_type: Option<&str>, body: Vec<u8>) -> Resp {
        let mut request = Request::post(uri).header("host", "127.0.0.1:48101");
        if let Some(content_type) = content_type {
            request = request.header("content-type", content_type);
        }
        call_router(self.app.clone(), request.body(Body::from(body)).unwrap()).await
    }

    async fn post_form(&self, parts: &[FormPart]) -> Resp {
        self.post_raw(
            "/api/mail/send/files",
            Some(&format!("multipart/form-data; boundary={BOUNDARY}")),
            multipart(parts),
        )
        .await
    }

    async fn upload(&self, body: Option<Value>, files: Option<Vec<FormPart>>) -> Resp {
        let mut parts = vec![message_part(&body.unwrap_or_else(|| self.body()))];
        parts.extend(files.unwrap_or_else(Self::default_files));
        self.post_form(&parts).await
    }

    async fn send_json(&self, body: &Value) -> Resp {
        self.post_raw(
            "/api/mail/send",
            Some("application/json"),
            body.to_string().into_bytes(),
        )
        .await
    }

    fn assert_rejected(&self, response: &Resp) {
        assert!(
            [
                StatusCode::BAD_REQUEST,
                StatusCode::PAYLOAD_TOO_LARGE,
                StatusCode::UNPROCESSABLE_ENTITY
            ]
            .contains(&response.status),
            "{} {}",
            response.status,
            response.text()
        );
        assert_eq!(
            self.smtp.connection_count(),
            0,
            "SMTP must not be contacted"
        );
    }

    fn delivered(&self) -> Vec<u8> {
        self.smtp.messages().last().expect("delivered").data.clone()
    }
}

#[tokio::test]
async fn valid_inline_image_and_attachment_pass_exact_bytes_and_threading() {
    let h = Harness::new();
    let response = h.upload(None, None).await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text());
    assert_eq!(response.json()["sent"], Value::Bool(true));
    let raw = h.delivered();
    let message = MessageParser::default().parse(&raw).unwrap();
    assert_eq!(
        message.header_raw("In-Reply-To").map(str::trim),
        Some("<original@example.com>")
    );
    let image = message
        .parts
        .iter()
        .find(|part| part.content_id() == Some("photo@draft"))
        .unwrap();
    assert_eq!(image.contents(), png().as_slice());
    assert!(image.content_disposition().unwrap().is_inline());
    let attachment = message
        .parts
        .iter()
        .find(|part| part.attachment_name() == Some("report.pdf"))
        .unwrap();
    assert_eq!(attachment.contents(), b"%PDF-test\x00\xff");
    let ct = attachment.content_type().unwrap();
    assert_eq!((ct.ctype(), ct.subtype()), ("application", Some("pdf")));
    assert_eq!(
        h.smtp.messages()[0].authenticated_user.as_deref(),
        Some(USER)
    );
}

#[tokio::test]
async fn locked_account_never_sends() {
    let h = Harness::new();
    h.state.sessions.forget(USER);
    let response = h.upload(None, None).await;
    let detail = response.assert_json_error(StatusCode::UNAUTHORIZED);
    assert_eq!(detail, json!({"error": "password_required", "email": USER}));
    assert_eq!(h.smtp.connection_count(), 0);
    let response = h
        .send_json(&h.body_with(json!({"html": "<p>Hello</p>", "uploads": []})))
        .await;
    response.assert_json_error(StatusCode::UNAUTHORIZED);
    assert_eq!(h.smtp.connection_count(), 0);
}

#[tokio::test]
async fn both_send_endpoints_report_sent_copy_status_without_failing_delivery() {
    for saved in [true, false] {
        for with_files in [false, true] {
            let h = Harness::new();
            if !saved {
                h.imap.fail_next("APPEND", Failure::no());
            }
            let response = if with_files {
                h.upload(None, None).await
            } else {
                h.send_json(&h.body_with(json!({"html": "<p>Hello</p>", "uploads": []})))
                    .await
            };
            assert_eq!(response.status, StatusCode::OK, "{}", response.text());
            let body = response.json();
            let message_id = body["message_id"].as_str().unwrap().to_string();
            assert!(message_id.starts_with('<') && message_id.ends_with("@example.com>"));
            let mut expected = json!({
                "sent": true, "message_id": message_id, "from": USER,
                "sent_saved": saved, "sent_folder": "Sent Items",
            });
            if !saved {
                expected["warning"] = json!(mail_core::smtp::SENT_COPY_WARNING);
            }
            assert_eq!(body, expected, "saved={saved} with_files={with_files}");
        }
    }
}

#[tokio::test]
async fn pop3_accounts_send_and_report_the_missing_sent_copy() {
    let h = Harness::new();
    let mut account = h.account.clone();
    account.incoming_mail_protocol = "pop3".into();
    h.state.sessions.unlock(account);
    let response = h
        .send_json(&h.body_with(json!({"html": "", "uploads": []})))
        .await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text());
    let body = response.json();
    assert_eq!(body["sent_saved"], Value::Bool(false));
    assert_eq!(body["sent_folder"], Value::Null);
    assert_eq!(body["warning"], mail_core::smtp::SENT_COPY_WARNING);
    assert_eq!(h.imap.connection_count(), 0);
    assert_eq!(h.smtp.messages().len(), 1);
}

#[tokio::test]
async fn files_and_metadata_counts_must_match() {
    let h = Harness::new();
    let response = h
        .upload(Some(h.body_with(json!({"uploads": []}))), None)
        .await;
    h.assert_rejected(&response);
    assert_eq!(
        response.assert_json_error(StatusCode::BAD_REQUEST),
        "Uploaded files must match the message attachment metadata"
    );
    h.assert_rejected(&h.upload(None, Some(Vec::new())).await);
}

#[tokio::test]
async fn inline_references_must_match_valid_unique_content_ids() {
    let h = Harness::new();
    for body in [
        h.body_with(json!({"html": "<p>No image reference</p>"})),
        h.body_with(json!({"html": "<img src=\"cid:missing\">"})),
        h.body_with(json!({"uploads": [{"disposition": "inline", "content_id": "unsafe\r\nContent-Type: text/plain"},
                                       {"disposition": "attachment", "content_id": ""}]})),
        h.body_with(json!({"uploads": [{"disposition": "inline", "content_id": "same"},
                                       {"disposition": "inline", "content_id": "same"}]})),
        h.body_with(json!({"uploads": [{"disposition": "attachment", "content_id": "unexpected"},
                                       {"disposition": "attachment", "content_id": ""}]})),
    ] {
        h.assert_rejected(&h.upload(Some(body), None).await);
    }
    let response = h
        .upload(
            Some(h.body_with(json!({"html": "<p>No image reference</p>"}))),
            None,
        )
        .await;
    assert_eq!(
        response.assert_json_error(StatusCode::UNPROCESSABLE_ENTITY),
        "Every inline image must have a matching cid reference in the HTML message"
    );
    let response = h
        .upload(
            Some(h.body_with(
                json!({"uploads": [{"disposition": "inline", "content_id": "same"},
                                                {"disposition": "inline", "content_id": "same"}]}),
            )),
            None,
        )
        .await;
    assert_eq!(
        response.assert_json_error(StatusCode::UNPROCESSABLE_ENTITY),
        "Check the message recipients, headers, size, and attachment metadata"
    );
}

#[tokio::test]
async fn fake_images_and_mime_mismatches_are_rejected() {
    let h = Harness::new();
    for (filename, data, mime, detail) in [
        (
            "vector.svg",
            b"<svg/>".to_vec(),
            "image/svg+xml",
            "Inline images must be valid PNG, JPEG, GIF, WebP, or BMP images",
        ),
        (
            "fake.png",
            b"<html>not an image</html>".to_vec(),
            "image/png",
            "Inline images must be valid PNG, JPEG, GIF, WebP, or BMP images",
        ),
        (
            "wrong.jpg",
            png(),
            "image/jpeg",
            "The inline image content type does not match its bytes",
        ),
    ] {
        let response = h
            .upload(
                None,
                Some(vec![
                    file(filename, &data, mime),
                    file("report.pdf", b"%PDF", "application/pdf"),
                ]),
            )
            .await;
        h.assert_rejected(&response);
        assert_eq!(
            response.assert_json_error(StatusCode::UNPROCESSABLE_ENTITY),
            detail
        );
    }
}

#[tokio::test]
async fn sniffed_inline_type_accepts_generic_browser_mime() {
    let h = Harness::new();
    let response = h
        .upload(
            None,
            Some(vec![
                file("photo", &png(), "application/octet-stream"),
                file("report.pdf", b"%PDF", "application/pdf"),
            ]),
        )
        .await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text());
    let raw = h.delivered();
    let message = MessageParser::default().parse(&raw).unwrap();
    let image = message
        .parts
        .iter()
        .find(|part| part.content_id() == Some("photo@draft"))
        .unwrap();
    let ct = image.content_type().unwrap();
    assert_eq!((ct.ctype(), ct.subtype()), ("image", Some("png")));
}

#[tokio::test]
async fn filename_paths_are_normalized_without_losing_unicode() {
    let h = Harness::new();
    let response = h
        .upload(
            Some(h.body_with(
                json!({"html": "", "uploads": [{"disposition": "attachment", "content_id": ""}]}),
            )),
            Some(vec![file(
                "C:/private/folder/r\u{e9}sum\u{e9}.pdf",
                b"data",
                "application/pdf",
            )]),
        )
        .await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text());
    let raw = h.delivered();
    let message = MessageParser::default().parse(&raw).unwrap();
    assert_eq!(
        message.attachment(0).unwrap().attachment_name(),
        Some("r\u{e9}sum\u{e9}.pdf")
    );
    assert!(String::from_utf8_lossy(&raw).contains("filename*=utf-8''r%C3%A9sum%C3%A9.pdf"));
}

#[tokio::test]
async fn header_controls_recipient_lists_and_body_limit_are_rejected() {
    let h = Harness::new();
    for body in [
        h.body_with(json!({"subject": "Subject\r\nBcc: attacker@example.com"})),
        h.body_with(json!({"to": ["bad-address"]})),
        h.body_with(json!({"to": ["one@example.com, two@example.com"]})),
        h.body_with(json!({"text": "\u{e9}".repeat(512 * 1024), "html": "<p>extra</p>"})),
    ] {
        h.assert_rejected(&h.upload(Some(body), None).await);
    }
    // "Invalid Unicode \ud800": a lone surrogate escape in the JSON text.
    let text = h
        .body()
        .to_string()
        .replace("\"Reply\"", "\"Invalid Unicode \\ud800\"");
    let parts = [
        FormPart {
            name: "message",
            filename: None,
            content_type: Some("application/json"),
            data: text.into_bytes(),
        },
        file("photo.png", &png(), "image/png"),
        file("report.pdf", b"%PDF", "application/pdf"),
    ];
    let response = h.post_form(&parts).await;
    h.assert_rejected(&response);
    assert_eq!(
        response.assert_json_error(StatusCode::UNPROCESSABLE_ENTITY),
        "Check the message recipients, headers, size, and attachment metadata"
    );
}

#[tokio::test]
async fn per_file_and_aggregate_limits_are_enforced_before_smtp() {
    let h = Harness::new();
    let body = h.body_with(
        json!({"html": "", "uploads": [{"disposition": "attachment", "content_id": ""}]}),
    );
    let response = h
        .upload(
            Some(body),
            Some(vec![file(
                "big.bin",
                &vec![b'x'; 10 * MIB + 1],
                "application/octet-stream",
            )]),
        )
        .await;
    h.assert_rejected(&response);
    assert_eq!(
        response.assert_json_error(StatusCode::PAYLOAD_TOO_LARGE),
        "Each attachment must be no larger than 10 MiB"
    );
    let body = h.body_with(json!({"html": "", "uploads": vec![json!({"disposition": "attachment", "content_id": ""}); 3]}));
    let files = vec![
        file("one.bin", &vec![b'x'; 10 * MIB], "application/octet-stream"),
        file("two.bin", &vec![b'x'; 10 * MIB], "application/octet-stream"),
        file("three.bin", b"x", "application/octet-stream"),
    ];
    let response = h.upload(Some(body), Some(files)).await;
    h.assert_rejected(&response);
    assert_eq!(
        response.assert_json_error(StatusCode::PAYLOAD_TOO_LARGE),
        "Attachments exceed the 10 MiB per-file or 20 MiB total limit"
    );
}

#[tokio::test]
async fn extra_fields_duplicate_metadata_and_excess_files_are_rejected() {
    let h = Harness::new();
    let body = h.body();
    let cases: Vec<(Vec<FormPart>, &str)> = vec![
        (
            vec![message_part(&body), message_part(&body)],
            "Too many fields. Maximum number of fields is 1.",
        ),
        (
            vec![message_part(&body), field("unexpected", "value")],
            "Too many fields. Maximum number of fields is 1.",
        ),
        (
            std::iter::once(message_part(&body))
                .chain((0..21).map(|index| file(&format!("file-{index}.txt"), b"x", "text/plain")))
                .collect(),
            "Too many files. Maximum number of files is 20.",
        ),
        (
            vec![
                message_part(&body),
                file("photo.png", &png(), "image/png"),
                FormPart {
                    name: "attachments",
                    filename: Some("x.txt".into()),
                    content_type: Some("text/plain"),
                    data: b"x".to_vec(),
                },
            ],
            "Unexpected message upload field",
        ),
        (
            vec![file("photo.png", &png(), "image/png")],
            "Provide one JSON message and its uploaded files",
        ),
    ];
    for (parts, detail) in cases {
        let response = h.post_form(&parts).await;
        h.assert_rejected(&response);
        assert_eq!(response.assert_json_error(StatusCode::BAD_REQUEST), detail);
    }
}

#[tokio::test]
async fn non_multipart_and_missing_boundary_are_rejected() {
    let h = Harness::new();
    let response = h
        .post_raw(
            "/api/mail/send/files",
            Some("application/json"),
            h.body().to_string().into_bytes(),
        )
        .await;
    assert_eq!(
        response.assert_json_error(StatusCode::BAD_REQUEST),
        "Send attachments using multipart/form-data"
    );
    let response = h
        .post_raw(
            "/api/mail/send/files",
            Some("multipart/form-data"),
            b"--x--\r\n".to_vec(),
        )
        .await;
    assert_eq!(
        response.assert_json_error(StatusCode::BAD_REQUEST),
        "Missing boundary in multipart."
    );
    assert_eq!(h.smtp.connection_count(), 0);
}

#[tokio::test]
async fn declared_and_chunked_request_size_is_bounded_before_parser() {
    let h = Harness::new();
    let request = Request::post("/api/mail/send/files")
        .header("host", "127.0.0.1:48101")
        .header("content-length", (30 * MIB + 1).to_string())
        .body(Body::from("tiny"))
        .unwrap();
    let response = call_router(h.app.clone(), request).await;
    assert_eq!(
        response.assert_json_error(StatusCode::PAYLOAD_TOO_LARGE),
        "Request exceeds maximum allowed size"
    );
    // A streamed (chunked) body without Content-Length.
    let chunks = (0..31).map(|_| Ok::<_, std::io::Error>(vec![b'x'; MIB]));
    let request = Request::post("/api/mail/send/files")
        .header("host", "127.0.0.1:48101")
        .header("content-type", "multipart/form-data; boundary=example")
        .body(Body::from_stream(futures_util::stream::iter(chunks)))
        .unwrap();
    let response = call_router(h.app.clone(), request).await;
    assert_eq!(
        response.assert_json_error(StatusCode::PAYLOAD_TOO_LARGE),
        "Request exceeds maximum allowed size"
    );
    // The JSON endpoint is capped at 8 MiB.
    let request = Request::post("/api/mail/send")
        .header("host", "127.0.0.1:48101")
        .header("content-type", "application/json")
        .header("content-length", (8 * MIB + 1).to_string())
        .body(Body::from("{}"))
        .unwrap();
    let response = call_router(h.app.clone(), request).await;
    response.assert_json_error(StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(h.smtp.connection_count(), 0);
}

#[tokio::test]
async fn legacy_json_endpoint_still_sends_and_rejects_missing_file_data() {
    let h = Harness::new();
    let response = h
        .send_json(&h.body_with(json!({"html": "<p>Hello</p>", "uploads": []})))
        .await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text());
    let raw = h.delivered();
    let message = MessageParser::default().parse(&raw).unwrap();
    assert_eq!(message.attachment_count(), 0);
    assert_eq!(h.smtp.messages().len(), 1);

    drop(h);
    let h = Harness::new();
    let response = h.send_json(&h.body()).await;
    h.assert_rejected(&response);
    assert_eq!(
        response.assert_json_error(StatusCode::UNPROCESSABLE_ENTITY),
        "Use the attachment upload endpoint for messages with files"
    );
    let response = h.send_json(&h.body_with(json!({"uploads": []}))).await;
    h.assert_rejected(&response);
    assert_eq!(
        response.assert_json_error(StatusCode::UNPROCESSABLE_ENTITY),
        "Every inline image must have a matching cid reference in the HTML message"
    );
}

#[tokio::test]
async fn json_validation_errors_are_fastapi_shaped() {
    let h = Harness::new();
    let response = h.send_json(&json!({"to": ["to@example.com"]})).await;
    let detail = response.assert_json_error(StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(detail[0]["type"], "missing");
    assert_eq!(detail[0]["loc"], json!(["body", "account"]));
    let response = h
        .post_raw("/api/mail/send", Some("application/json"), Vec::new())
        .await;
    let detail = response.assert_json_error(StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(detail[0]["loc"], json!(["body"]));
    assert_eq!(h.smtp.connection_count(), 0);
}

#[tokio::test]
async fn smtp_failures_are_502_without_server_details() {
    let h = Harness::new();
    h.smtp.fail_next(
        "DATA",
        Failure::Code(554, "private recipient detail".into()),
    );
    let response = h
        .send_json(&h.body_with(json!({"html": "", "uploads": []})))
        .await;
    assert_eq!(
        response.assert_json_error(StatusCode::BAD_GATEWAY),
        "The outgoing mail server could not send the message."
    );
    let response = h.upload(None, None).await;
    assert_eq!(
        response.status,
        StatusCode::OK,
        "only the next DATA failed: {}",
        response.text()
    );

    drop(h);
    let h = Harness::new();
    let mut wrong = h.account.clone();
    wrong.password = "wrong-password".into();
    h.state.sessions.unlock(wrong);
    let response = h.upload(None, None).await;
    let detail = response.assert_json_error(StatusCode::BAD_GATEWAY);
    assert_eq!(
        detail,
        "SMTP sign-in failed. Check the password or use an app password."
    );
    assert!(!response.text().contains("wrong-password"));
}

#[tokio::test]
async fn sender_display_name_comes_from_saved_names_then_matching_profiles() {
    let h = Harness::new();
    let plain = h.body_with(json!({"html": "", "uploads": []}));
    let send = || h.send_json(&plain);
    let from_name = |h: &Harness| {
        let raw = h.delivered();
        let message = MessageParser::default().parse(&raw).unwrap();
        message
            .from()
            .and_then(|a| a.first())
            .and_then(|a| a.name())
            .map(str::to_string)
    };
    // A profile for this mailbox supplies the name.
    std::fs::write(
        &h.state.mail_servers_path,
        json!({"servers": {"example": {
            "incoming_server": "imap.example.com", "outgoing_server": "smtp.example.com",
            "email_address": USER, "display_name": "Profile Name"}}})
        .to_string(),
    )
    .unwrap();
    let response = send().await;
    assert_eq!(response.json()["from"], "Profile Name <user@example.com>");
    assert_eq!(from_name(&h).as_deref(), Some("Profile Name"));

    // Another mailbox owner's profile is never borrowed.
    let mut account = h.account.clone();
    account.sender_profile_key = Some("other".into());
    h.state.sessions.unlock(account.clone());
    std::fs::write(
        &h.state.mail_servers_path,
        json!({"servers": {"other": {
            "incoming_server": "imap.example.com", "outgoing_server": "smtp.example.com",
            "email_address": "someone@example.com", "display_name": "Someone Else"}}})
        .to_string(),
    )
    .unwrap();
    let response = send().await;
    assert_eq!(response.json()["from"], USER);

    // A saved name wins over everything.
    mail_core::display_names::save_name(USER, Some("Saved Name")).unwrap();
    let response = send().await;
    assert_eq!(response.json()["from"], "Saved Name <user@example.com>");

    // An unreadable profile file is a 500 with the error text.
    mail_core::display_names::save_name(USER, None).unwrap();
    std::fs::write(&h.state.mail_servers_path, "{not json").unwrap();
    let response = send().await;
    let detail = response.assert_json_error(StatusCode::INTERNAL_SERVER_ERROR);
    assert!(
        detail.as_str().unwrap().contains("mail server profiles"),
        "{detail}"
    );
}
