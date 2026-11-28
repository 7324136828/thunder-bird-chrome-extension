//! Shared helpers for the Inbox Doctor / metrics HTTP tests (ports of the
//! `TestClient` fixtures of `backend/tests/test_doctor.py` and
//! `test_email_metrics*.py`).

#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::Router;
use mail_backend::{build_app, AppState};
use mail_doctor::config::DoctorSettings;
use serde_json::Value;

use crate::common::{call_router, Resp};

pub const HOST: &str = "127.0.0.1:48101";
pub const BOUNDARY: &str = "doctor-test-boundary-7f3a";

/// Python `test_doctor.message(index, sender=..., unsubscribe=...)`.
pub fn message(index: usize, sender: &str, unsubscribe: bool) -> String {
    let domain = sender.rsplit('@').next().unwrap_or_default();
    let mut headers = vec![
        format!("From: Newsletter <{sender}>"),
        "To: user@example.net".to_string(),
        format!("Subject: Weekly digest {index}"),
        format!("Date: {}", chrono::Utc::now().to_rfc2822()),
        format!("Message-ID: <doctor-{index}@{domain}>"),
        "Content-Type: text/plain; charset=\"utf-8\"".to_string(),
    ];
    if unsubscribe {
        headers.push(format!(
            "List-Unsubscribe: <https://example.com/unsubscribe/{index}>"
        ));
    }
    headers.push(String::new());
    headers.push(format!("Digest number {index}."));
    headers.join("\r\n")
}

pub fn news(index: usize) -> String {
    message(index, "news@mail.example.com", true)
}

/// A ZIP archive of `(name, data)` entries.
pub fn zip_bytes(entries: &[(&str, &[u8])], method: zip::CompressionMethod) -> Vec<u8> {
    use std::io::Write;
    let mut writer = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    let options = zip::write::SimpleFileOptions::default().compression_method(method);
    for (name, data) in entries {
        writer.start_file(*name, options).unwrap();
        writer.write_all(data).unwrap();
    }
    writer.finish().unwrap().into_inner()
}

/// A `multipart/form-data` body: `(field name, filename, data)` parts.
pub fn multipart(parts: &[(&str, Option<&str>, &[u8])]) -> Vec<u8> {
    let mut body = Vec::new();
    for (name, filename, data) in parts {
        body.extend_from_slice(format!("--{BOUNDARY}\r\n").as_bytes());
        match filename {
            Some(filename) => body.extend_from_slice(
                format!(
                    "Content-Disposition: form-data; name=\"{name}\"; filename=\"{filename}\"\r\n\
                     Content-Type: application/octet-stream\r\n\r\n"
                )
                .as_bytes(),
            ),
            None => body.extend_from_slice(
                format!("Content-Disposition: form-data; name=\"{name}\"\r\n\r\n").as_bytes(),
            ),
        }
        body.extend_from_slice(data);
        body.extend_from_slice(b"\r\n");
    }
    body.extend_from_slice(format!("--{BOUNDARY}--\r\n").as_bytes());
    body
}

/// Every regular file below `root`.
pub fn walk(root: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        for entry in std::fs::read_dir(&directory)
            .into_iter()
            .flatten()
            .flatten()
        {
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

/// One isolated application (Python `create_app(profiles, doctor_data_directory=...)`).
pub struct Ctx {
    pub app: Router,
    pub state: AppState,
    pub root: tempfile::TempDir,
    settings: DoctorSettings,
}

impl Ctx {
    pub fn new() -> Self {
        Self::with(|_| {})
    }

    /// An app whose Doctor settings are adjusted first (Python tests
    /// assigned `app.state.doctor.settings.*`).
    pub fn with(configure: impl FnOnce(&mut DoctorSettings)) -> Self {
        let root = tempfile::tempdir().unwrap();
        let mut settings = DoctorSettings::with_defaults(root.path().join("data"));
        configure(&mut settings);
        let (app, state) = Self::build(root.path(), settings.clone());
        Self {
            app,
            state,
            root,
            settings,
        }
    }

    fn build(root: &Path, settings: DoctorSettings) -> (Router, AppState) {
        let profiles = root.join("mail-servers.json");
        if !profiles.exists() {
            std::fs::write(&profiles, "{\"servers\": {}}\n").unwrap();
        }
        std::fs::create_dir_all(&settings.data_directory).unwrap();
        let state = AppState::with_doctor_settings(profiles, settings);
        (build_app(state.clone()), state)
    }

    /// A second application over the same files (a restart).
    pub fn restarted(&self) -> (Router, AppState) {
        Self::build(self.root.path(), self.settings.clone())
    }

    pub fn data(&self) -> PathBuf {
        self.root.path().join("data")
    }

    pub async fn send(&self, request: Request<Body>) -> Resp {
        call_router(self.app.clone(), request).await
    }

    pub async fn get(&self, uri: &str) -> Resp {
        send_to(&self.app, get(uri)).await
    }

    pub async fn post_json(&self, uri: &str, body: &Value) -> Resp {
        send_to(&self.app, post_json(uri, body)).await
    }

    pub async fn post_empty(&self, uri: &str) -> Resp {
        let request = Request::post(uri)
            .header("host", HOST)
            .body(Body::empty())
            .unwrap();
        self.send(request).await
    }

    pub async fn upload(&self, parts: &[(&str, Option<&str>, &[u8])]) -> Resp {
        self.send(upload_request(parts)).await
    }

    /// Poll `GET /api/jobs/{id}` until the job is terminal, then wait for
    /// its worker to exit (workspace purges happen there).
    pub async fn wait(&self, job_id: &str) -> Value {
        wait_job(&self.app, &self.state, job_id).await
    }

    /// `paste()` of test_doctor.py.
    pub async fn paste(&self) -> Value {
        let response = self
            .post_json(
                "/api/jobs/paste",
                &serde_json::json!({"content": news(0), "filename": "paste"}),
            )
            .await;
        assert_eq!(response.status, StatusCode::CREATED, "{}", response.text());
        let id = response.json()["id"].as_str().unwrap().to_string();
        self.wait(&id).await
    }

    pub fn files_with(&self, suffix: &str) -> Vec<PathBuf> {
        walk(&self.data())
            .into_iter()
            .filter(|path| path.to_string_lossy().to_lowercase().ends_with(suffix))
            .collect()
    }
}

pub fn get(uri: &str) -> Request<Body> {
    Request::get(uri)
        .header("host", HOST)
        .body(Body::empty())
        .unwrap()
}

pub fn post_json(uri: &str, body: &Value) -> Request<Body> {
    Request::post(uri)
        .header("host", HOST)
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

pub fn upload_request(parts: &[(&str, Option<&str>, &[u8])]) -> Request<Body> {
    Request::post("/api/jobs")
        .header("host", HOST)
        .header(
            "content-type",
            format!("multipart/form-data; boundary={BOUNDARY}"),
        )
        .body(Body::from(multipart(parts)))
        .unwrap()
}

pub async fn send_to(app: &Router, request: Request<Body>) -> Resp {
    call_router(app.clone(), request).await
}

pub async fn wait_job(app: &Router, state: &AppState, job_id: &str) -> Value {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let response = send_to(app, get(&format!("/api/jobs/{job_id}"))).await;
        assert_eq!(response.status, StatusCode::OK, "{}", response.text());
        let job = response.json();
        if matches!(
            job["status"].as_str(),
            Some("completed" | "healthy" | "failed" | "discarded")
        ) {
            let doctor = state.doctor.clone();
            tokio::task::spawn_blocking(move || doctor.wait_idle(Duration::from_secs(10)))
                .await
                .unwrap();
            let response = send_to(app, get(&format!("/api/jobs/{job_id}"))).await;
            return response.json();
        }
        assert!(Instant::now() < deadline, "job did not finish: {job}");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}
