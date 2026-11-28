//! Shared harness for the end-to-end tests (`tests/e2e_*.rs`).
//!
//! The tests drive `build_app(AppState::for_tests)` with requests shaped
//! exactly like the extension's `api.ts` (Host `127.0.0.1:48101`, the
//! extension `Origin`, the same query parameters, JSON bodies and
//! `FormData` multipart bodies) against the `mail_proto::testkit` fake
//! IMAP/POP3/SMTP servers and a fake Ollama HTTP server on loopback.
//!
//! Every harness holds a `scoped_settings_path` guard, so nothing reads or
//! writes the real per-user `settings.json` (holders are serialized
//! process-wide, which also serializes the tests of one binary).

#![allow(dead_code)]

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use axum::body::Body;
use axum::http::{HeaderMap, Method, Request, StatusCode};
use axum::Router;
use mail_backend::{build_app, AppState};
use mail_core::settings::{scoped_settings_path, ScopedSettingsPath};
use mail_proto::testkit::FakeMessage;
use serde_json::{json, Value};
use tower::ServiceExt;

pub const USER: &str = "user@example.com";
pub const PASSWORD: &str = "e2e-Secret-Pass-7319";
pub const HOST: &str = "127.0.0.1:48101";
pub const ORIGIN: &str = "chrome-extension://hhhanbkdjaecdfoclhpoicmfhejdbkjl";
pub const BOUNDARY: &str = "----WebKitFormBoundaryE2eTest7MA4YWxk";

// ---------------------------------------------------------------------------
// Responses
// ---------------------------------------------------------------------------

/// A buffered response.
#[derive(Debug)]
pub struct Resp {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: Vec<u8>,
}

impl Resp {
    pub fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap_or_else(|error| {
            panic!(
                "not JSON ({error}), status {}: {:?}",
                self.status,
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

    /// Assert a 200 and return the JSON body.
    #[track_caller]
    pub fn ok(&self) -> Value {
        assert_eq!(self.status, StatusCode::OK, "body: {}", self.text());
        self.json()
    }

    /// Assert a JSON error with `status` and return its `detail`.
    #[track_caller]
    pub fn error(&self, status: StatusCode) -> Value {
        assert_eq!(self.status, status, "body: {}", self.text());
        assert!(
            self.header("content-type")
                .is_some_and(|value| value.starts_with("application/json")),
            "content-type {:?} for {}",
            self.header("content-type"),
            self.text()
        );
        self.json()
            .get("detail")
            .cloned()
            .unwrap_or_else(|| panic!("no detail in {}", self.text()))
    }

    /// The 401 `password_required` detail for `email`.
    #[track_caller]
    pub fn assert_locked(&self, email: &str) {
        assert_eq!(
            self.error(StatusCode::UNAUTHORIZED),
            json!({"error": "password_required", "email": email}),
        );
    }
}

/// Top-level keys of a JSON object, in order.
pub fn keys(value: &Value) -> Vec<String> {
    value
        .as_object()
        .unwrap_or_else(|| panic!("not an object: {value}"))
        .keys()
        .cloned()
        .collect()
}

// ---------------------------------------------------------------------------
// The application under test
// ---------------------------------------------------------------------------

/// One isolated backend (state directory + settings file), driven like the
/// extension drives it.
pub struct E2e {
    pub app: Router,
    pub state: AppState,
    pub root: PathBuf,
    // Dropped before `_temporary` so the override is released first.
    _settings: ScopedSettingsPath,
    _temporary: tempfile::TempDir,
}

impl Default for E2e {
    fn default() -> Self {
        Self::new()
    }
}

impl E2e {
    pub fn new() -> Self {
        let temporary = tempfile::tempdir().expect("tempdir");
        let root = temporary.path().to_path_buf();
        let settings = scoped_settings_path(root.join("settings.json"));
        let state = AppState::for_tests(&root);
        Self {
            app: build_app(state.clone()),
            state,
            root,
            _settings: settings,
            _temporary: temporary,
        }
    }

    /// Simulate a backend restart: shut the old state down (main.rs'
    /// graceful path) and serve a fresh state over the same files.
    pub fn restart(&mut self) {
        self.state.shutdown();
        self.state = AppState::for_tests(&self.root);
        self.app = build_app(self.state.clone());
    }

    pub fn settings_path(&self) -> PathBuf {
        self.root.join("settings.json")
    }

    pub fn trash_archive_dir(&self) -> PathBuf {
        self.state.data_directory.join("trash_archives")
    }

    /// Send a request the way the extension's `fetch` does (Host + Origin).
    pub async fn send(&self, request: Request<Body>) -> Resp {
        let response = self.app.clone().oneshot(request).await.expect("infallible");
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

    pub fn builder(method: Method, uri: &str) -> axum::http::request::Builder {
        Request::builder()
            .method(method)
            .uri(uri)
            .header("host", HOST)
            .header("origin", ORIGIN)
            .header("sec-fetch-site", "cross-site")
            .header("sec-fetch-mode", "cors")
    }

    pub async fn get(&self, path: &str, params: &[(&str, &str)]) -> Resp {
        let request = Self::builder(Method::GET, &with_query(path, params))
            .body(Body::empty())
            .unwrap();
        self.send(request).await
    }

    pub async fn delete(&self, path: &str, params: &[(&str, &str)]) -> Resp {
        let request = Self::builder(Method::DELETE, &with_query(path, params))
            .body(Body::empty())
            .unwrap();
        self.send(request).await
    }

    pub async fn json(&self, method: Method, path: &str, body: &Value) -> Resp {
        let request = Self::builder(method, path)
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(body).unwrap()))
            .unwrap();
        self.send(request).await
    }

    pub async fn post_json(&self, path: &str, body: &Value) -> Resp {
        self.json(Method::POST, path, body).await
    }

    pub async fn put_json(&self, path: &str, body: &Value) -> Resp {
        self.json(Method::PUT, path, body).await
    }

    /// `fetch(path, {method, body: FormData})`.
    pub async fn multipart(&self, method: Method, path: &str, parts: &[FormPart]) -> Resp {
        let request = Self::builder(method, path)
            .header(
                "content-type",
                format!("multipart/form-data; boundary={BOUNDARY}"),
            )
            .body(Body::from(multipart_body(parts)))
            .unwrap();
        self.send(request).await
    }

    /// `api.unlock(...)` against a fake server.
    pub async fn unlock(&self, body: Value) -> Resp {
        self.post_json("/api/accounts/unlock", &body).await
    }

    /// Poll `GET /api/jobs/{id}` until the job is terminal and its worker
    /// has exited.
    pub async fn wait_job(&self, job_id: &str) -> Value {
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            let job = self.get(&format!("/api/jobs/{job_id}"), &[]).await.ok();
            if matches!(
                job["status"].as_str(),
                Some("completed" | "healthy" | "failed" | "discarded")
            ) {
                let doctor = self.state.doctor.clone();
                tokio::task::spawn_blocking(move || doctor.wait_idle(Duration::from_secs(20)))
                    .await
                    .unwrap();
                return self.get(&format!("/api/jobs/{job_id}"), &[]).await.ok();
            }
            assert!(Instant::now() < deadline, "job did not finish: {job}");
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }

    /// True when `needle` occurs in any file under the state root.
    pub fn any_file_contains(&self, needle: &str) -> Option<PathBuf> {
        walk(&self.root).into_iter().find(|path| {
            std::fs::read(path)
                .map(|bytes| contains(&bytes, needle.as_bytes()))
                .unwrap_or(false)
        })
    }
}

/// `path?k=v&...` encoded like `URLSearchParams`.
pub fn with_query(path: &str, params: &[(&str, &str)]) -> String {
    if params.is_empty() {
        return path.to_string();
    }
    let query = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(params.iter())
        .finish();
    format!("{path}?{query}")
}

pub fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

/// Every file below `root`.
pub fn walk(root: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        let Ok(entries) = std::fs::read_dir(&directory) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                pending.push(path);
            } else {
                files.push(path);
            }
        }
    }
    files
}

// ---------------------------------------------------------------------------
// Multipart (`FormData`)
// ---------------------------------------------------------------------------

/// One `FormData` entry.
pub struct FormPart {
    pub name: String,
    pub filename: Option<String>,
    pub content_type: Option<String>,
    pub data: Vec<u8>,
}

/// `form.append(name, string)`: browsers send no Content-Type for it.
pub fn form_field(name: &str, value: &str) -> FormPart {
    FormPart {
        name: name.into(),
        filename: None,
        content_type: None,
        data: value.as_bytes().to_vec(),
    }
}

/// `form.append(name, file, file.name)`.
pub fn form_file(name: &str, filename: &str, content_type: &str, data: &[u8]) -> FormPart {
    FormPart {
        name: name.into(),
        filename: Some(filename.into()),
        content_type: Some(content_type.into()),
        data: data.to_vec(),
    }
}

pub fn multipart_body(parts: &[FormPart]) -> Vec<u8> {
    let mut body = Vec::new();
    for part in parts {
        body.extend_from_slice(format!("--{BOUNDARY}\r\n").as_bytes());
        let mut disposition = format!("Content-Disposition: form-data; name=\"{}\"", part.name);
        if let Some(filename) = &part.filename {
            disposition.push_str(&format!("; filename=\"{filename}\""));
        }
        body.extend_from_slice(disposition.as_bytes());
        body.extend_from_slice(b"\r\n");
        if let Some(content_type) = &part.content_type {
            body.extend_from_slice(format!("Content-Type: {content_type}\r\n").as_bytes());
        }
        body.extend_from_slice(b"\r\n");
        body.extend_from_slice(&part.data);
        body.extend_from_slice(b"\r\n");
    }
    body.extend_from_slice(format!("--{BOUNDARY}--\r\n").as_bytes());
    body
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/// A valid 1x1 PNG.
pub fn png() -> Vec<u8> {
    fn chunk(kind: &[u8], data: &[u8]) -> Vec<u8> {
        let mut out = (data.len() as u32).to_be_bytes().to_vec();
        out.extend_from_slice(kind);
        out.extend_from_slice(data);
        let mut hasher = crc32fast::Hasher::new();
        hasher.update(kind);
        hasher.update(data);
        out.extend_from_slice(&hasher.finalize().to_be_bytes());
        out
    }
    let mut data = b"\x89PNG\r\n\x1a\n".to_vec();
    data.extend(chunk(b"IHDR", &[0, 0, 0, 1, 0, 0, 0, 1, 8, 6, 0, 0, 0]));
    data.extend(chunk(
        b"IDAT",
        b"x\x9cc\xf8\xcf\xc0\xf0\x1f\x00\x05\x00\x01\xff",
    ));
    data.extend(chunk(b"IEND", b""));
    data
}

/// Bytes of the PDF attachment used by the fixtures.
pub const PDF_BYTES: &[u8] =
    b"%PDF-1.4\n% e2e fixture\n1 0 obj << >> endobj\ntrailer << >>\n%%EOF\n";

pub fn base64(data: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(data)
}

/// IMAP INTERNALDATE `days` days ago.
pub fn internal_date_days_ago(days: i64) -> String {
    (chrono::Utc::now() - chrono::Duration::days(days))
        .format("%d-%b-%Y %H:%M:%S +0000")
        .to_string()
}

/// RFC 2822 date `days` days ago.
pub fn rfc2822_days_ago(days: i64) -> String {
    (chrono::Utc::now() - chrono::Duration::days(days)).to_rfc2822()
}

/// A plain text message.
pub fn plain_message(from: &str, subject: &str, body: &str, days_ago: i64, id: &str) -> String {
    format!(
        "From: {from}\r\nTo: Example User <{USER}>\r\nSubject: {subject}\r\n\
         Date: {}\r\nMessage-ID: <{id}@example.com>\r\nMIME-Version: 1.0\r\n\
         Content-Type: text/plain; charset=utf-8\r\n\r\n{body}\r\n",
        rfc2822_days_ago(days_ago)
    )
}

/// An HTML newsletter with one remote image.
pub fn html_message(image_url: &str, days_ago: i64) -> String {
    format!(
        "From: Deals <news@shop.example.com>\r\nTo: {USER}\r\nSubject: Weekly deals\r\n\
         Date: {}\r\nMessage-ID: <deals@example.com>\r\nMIME-Version: 1.0\r\n\
         List-Unsubscribe: <https://shop.example.com/unsubscribe>\r\n\
         Content-Type: multipart/alternative; boundary=\"alt\"\r\n\r\n\
         --alt\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nBig sale this week.\r\n\
         --alt\r\nContent-Type: text/html; charset=utf-8\r\n\r\n\
         <html><body><p>Big sale this week.</p><img src=\"{image_url}\" alt=\"banner\"></body></html>\r\n\
         --alt--\r\n",
        rfc2822_days_ago(days_ago)
    )
}

/// A message with a PDF attachment.
pub fn attachment_message(days_ago: i64) -> String {
    format!(
        "From: Alice <alice@example.org>\r\nTo: {USER}\r\nCc: Carol <carol@example.org>\r\n\
         Subject: Project notes\r\nDate: {}\r\nMessage-ID: <notes@example.com>\r\n\
         MIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=\"mix\"\r\n\r\n\
         --mix\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nNotes attached.\r\n\
         --mix\r\nContent-Type: application/pdf; name=\"report.pdf\"\r\n\
         Content-Disposition: attachment; filename=\"report.pdf\"\r\n\
         Content-Transfer-Encoding: base64\r\n\r\n{}\r\n--mix--\r\n",
        rfc2822_days_ago(days_ago),
        base64(PDF_BYTES)
    )
}

pub fn fake_message(uid: u32, raw: &str, days_ago: i64, flags: &[&str]) -> FakeMessage {
    FakeMessage::new(raw.as_bytes().to_vec())
        .with_uid(uid)
        .with_internal_date(&internal_date_days_ago(days_ago))
        .with_flags(flags)
}

/// UIDs of a page response.
pub fn page_uids(page: &Value) -> Vec<u64> {
    page["messages"]
        .as_array()
        .unwrap_or_else(|| panic!("no messages in {page}"))
        .iter()
        .map(|message| message["uid"].as_u64().unwrap())
        .collect()
}

/// `{uid: summary}` of a page response.
pub fn by_uid(page: &Value) -> BTreeMap<u64, Value> {
    page["messages"]
        .as_array()
        .unwrap()
        .iter()
        .map(|message| (message["uid"].as_u64().unwrap(), message.clone()))
        .collect()
}

/// Entries of a ZIP archive: `{name: bytes}`.
pub fn zip_entries(bytes: &[u8]) -> BTreeMap<String, Vec<u8>> {
    let mut archive = zip::ZipArchive::new(std::io::Cursor::new(bytes)).expect("valid zip");
    let mut entries = BTreeMap::new();
    for index in 0..archive.len() {
        let mut file = archive.by_index(index).unwrap();
        let mut data = Vec::new();
        file.read_to_end(&mut data).unwrap();
        entries.insert(file.name().to_string(), data);
    }
    entries
}

/// CRLF-normalize like the fake servers store messages.
pub fn crlf(text: &str) -> Vec<u8> {
    text.replace("\r\n", "\n")
        .replace('\n', "\r\n")
        .into_bytes()
}

// ---------------------------------------------------------------------------
// Fake Ollama
// ---------------------------------------------------------------------------

/// One request seen by [`FakeOllama`].
#[derive(Debug, Clone)]
pub struct OllamaRequest {
    pub method: String,
    pub path: String,
    pub body: Vec<u8>,
}

impl OllamaRequest {
    pub fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap_or(Value::Null)
    }
}

type Handler = dyn Fn(&OllamaRequest) -> (u16, Value) + Send + Sync;

/// A minimal HTTP/1.1 server answering Ollama's `/api/tags`, `/api/show`
/// and `/api/chat` on an ephemeral loopback port.
pub struct FakeOllama {
    port: u16,
    pub requests: Arc<Mutex<Vec<OllamaRequest>>>,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl FakeOllama {
    /// A local, installed `model` whose chat answer is `category`.
    pub fn with_model(model: &str, category: &str, reason: &str) -> Self {
        let model = model.to_string();
        let answer = json!({
            "done": true,
            "model": model,
            "message": {"content": json!({"category": category, "reason": reason}).to_string()},
        });
        Self::start(move |request| match request.path.as_str() {
            "/api/tags" => (
                200,
                json!({"models": [{"name": model, "size": 2_000_000, "details": {"format": "gguf"}}]}),
            ),
            "/api/show" => (
                200,
                json!({
                    "details": {"format": "gguf"}, "capabilities": ["completion"],
                    "model_info": {"general.architecture": "llama", "general.file_type": 15,
                                   "general.parameter_count": 3_212_749_888u64},
                }),
            ),
            "/api/chat" => (200, answer.clone()),
            _ => (404, json!({"error": "not found"})),
        })
    }

    pub fn start(handler: impl Fn(&OllamaRequest) -> (u16, Value) + Send + Sync + 'static) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind fake ollama");
        let port = listener.local_addr().unwrap().port();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let handler: Arc<Handler> = Arc::new(handler);
        let thread = {
            let requests = Arc::clone(&requests);
            let stop = Arc::clone(&stop);
            std::thread::spawn(move || {
                for stream in listener.incoming() {
                    if stop.load(Ordering::SeqCst) {
                        break;
                    }
                    let Ok(stream) = stream else { continue };
                    let _ = serve_one(stream, &handler, &requests);
                }
            })
        };
        Self {
            port,
            requests,
            stop,
            thread: Some(thread),
        }
    }

    pub fn url(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }

    pub fn paths(&self) -> Vec<String> {
        self.requests
            .lock()
            .unwrap()
            .iter()
            .map(|request| request.path.clone())
            .collect()
    }
}

impl Drop for FakeOllama {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(("127.0.0.1", self.port));
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn serve_one(
    stream: TcpStream,
    handler: &Arc<Handler>,
    requests: &Arc<Mutex<Vec<OllamaRequest>>>,
) -> std::io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut line = String::new();
    reader.read_line(&mut line)?;
    let mut fields = line.split_whitespace();
    let method = fields.next().unwrap_or_default().to_string();
    let path = fields.next().unwrap_or_default().to_string();
    let mut length = 0usize;
    loop {
        let mut header = String::new();
        reader.read_line(&mut header)?;
        let header = header.trim_end();
        if header.is_empty() {
            break;
        }
        if let Some((name, value)) = header.split_once(':') {
            if name.eq_ignore_ascii_case("content-length") {
                length = value.trim().parse().unwrap_or(0);
            }
        }
    }
    let mut body = vec![0u8; length];
    reader.read_exact(&mut body)?;
    let request = OllamaRequest { method, path, body };
    requests.lock().unwrap().push(request.clone());
    let (status, value) = handler(&request);
    let payload = value.to_string();
    let mut stream = stream;
    write!(
        stream,
        "HTTP/1.1 {status} OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{payload}",
        payload.len()
    )?;
    stream.flush()
}
