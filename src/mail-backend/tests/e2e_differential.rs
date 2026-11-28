//! Differential end-to-end check: the same extension-shaped requests are
//! replayed against the Rust router and against the ORIGINAL Python backend
//! (`../original-project/20261011-thunderbird`, FastAPI `TestClient`), each
//! talking to its own identical fake IMAP server, and the responses (status,
//! content type, JSON body) are compared.
//!
//! Opt-in (needs Python 3 with fastapi/httpx/pydantic and the original
//! project next to the workspace):
//!
//! ```text
//! cargo test -p mail-backend --test e2e_differential -- --ignored
//! ```
//!
//! Only non-mutating requests (plus unlock) are replayed so both servers see
//! the same mailbox. Known, documented extension differences are normalized
//! away (`incoming_mail_protocol`, `unlocked_at`, the profile file path).

mod e2e_support;

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use axum::body::Body;
use axum::http::Method;
use e2e_support::*;
use mail_proto::testkit::{FakeImapServer, FakeMessage};
use serde_json::{json, Map, Value};

fn original_project() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../original-project/20261011-thunderbird")
}

/// Fixed INTERNALDATEs so both servers compute identical expirations.
fn server() -> FakeImapServer {
    let message = |uid: u32, raw: String, date: &str, flags: &[&str]| {
        FakeMessage::new(raw.into_bytes())
            .with_uid(uid)
            .with_internal_date(date)
            .with_flags(flags)
    };
    let fixed = |from: &str, subject: &str, extra: &str, body: &str, id: &str| {
        format!(
            "From: {from}\r\nTo: Example User <{USER}>\r\nSubject: {subject}\r\n\
             Date: Mon, 02 Nov 2026 08:00:00 +0100\r\nMessage-ID: <{id}@example.com>\r\n{extra}\
             MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n{body}\r\n"
        )
    };
    FakeImapServer::builder()
        .credentials(USER, PASSWORD)
        .folder("Sent", &[r"\Sent"])
        .folder("Trash", &[r"\Trash"])
        .folder("Archive/2025", &[])
        .uid_validity("INBOX", Some(4321))
        .message_with(
            "INBOX",
            message(
                1,
                fixed(
                    "Accounts <no-reply@accounts.example.com>",
                    "Your verification code is 123456",
                    "",
                    "Use this code to sign in.",
                    "v1",
                ),
                "01-Jun-2025 10:00:00 +0000",
                &["\\Seen"],
            ),
        )
        .message_with(
            "INBOX",
            message(
                2,
                attachment_message(10)
                    .replace(&rfc2822_days_ago(10), "Tue, 03 Nov 2026 09:15:00 -0800"),
                "03-Nov-2026 17:15:00 +0000",
                &["\\Seen", "\\Flagged"],
            ),
        )
        .message_with(
            "INBOX",
            message(
                3,
                html_message("https://img.example.com/banner.png?a=1&b=2", 0)
                    .replace(&rfc2822_days_ago(0), "Wed, 04 Nov 2026 12:00:00 +0000"),
                "04-Nov-2026 12:00:01 +0000",
                &[],
            ),
        )
        .message_with(
            "INBOX",
            message(
                4,
                fixed(
                    "Store <orders@store.example.com>",
                    "Your order has shipped",
                    "",
                    "Tracking number 1Z999.",
                    "o4",
                ),
                "05-Nov-2026 07:30:00 +0000",
                &["\\Answered"],
            ),
        )
        .message_with(
            "INBOX",
            message(
                5,
                fixed(
                    "=?utf-8?q?R=C3=A9sum=C3=A9_Bot?= <bot@xn--bcher-kva.example>",
                    "=?utf-8?b?V2Vla2x5IGRpZ2VzdA==?=",
                    "List-Id: <digest.example.org>\r\nList-Unsubscribe: <mailto:u@example.org>\r\n",
                    "Digest body",
                    "d5",
                ),
                "06-Nov-2026 07:30:00 +0000",
                &[],
            ),
        )
        .message_with(
            "INBOX",
            message(
                6,
                "From: broken\r\nSubject: \r\n\r\nno headers to speak of\r\n".to_string(),
                "07-Nov-2026 07:30:00 +0000",
                &[],
            ),
        )
        .start()
}

fn get(path: &str, params: &[(&str, &str)]) -> Value {
    json!({"method": "GET", "path": path,
           "params": params.iter().map(|(k, v)| json!([k, v])).collect::<Vec<_>>()})
}

fn body(method: &str, path: &str, value: Value) -> Value {
    json!({"method": method, "path": path, "params": [], "json": value})
}

fn raw(method: &str, path: &str, text: &str) -> Value {
    json!({"method": method, "path": path, "params": [], "raw": text,
           "content_type": "application/json"})
}

fn requests(port: u16) -> Vec<Value> {
    let a = ("account", USER);
    let inbox = ("folder", "INBOX");
    let mut list = vec![
        get("/api/health", &[]),
        get("/api/settings", &[]),
        body("PUT", "/api/settings", json!({"messages_per_page": 0})),
        body("PUT", "/api/settings", json!({"messages_per_page": "5"})),
        body(
            "PUT",
            "/api/settings",
            json!({"messages_per_page": 5, "extra": 1}),
        ),
        body(
            "PUT",
            "/api/settings",
            json!({"messages_per_page": 5, "category_expiration_days": {"spam": 3}}),
        ),
        body(
            "PUT",
            "/api/settings",
            json!({"messages_per_page": 5, "local_ai_model": "bad model name!"}),
        ),
        raw("PUT", "/api/settings", "{not json"),
        body("POST", "/api/accounts/unlock", json!({"email": "x"})),
        body(
            "POST",
            "/api/accounts/unlock",
            json!({"email": "no-at.example.com", "password": "p"}),
        ),
        body(
            "POST",
            "/api/accounts/unlock",
            json!({"email": USER, "password": "p", "incoming_port": 0, "display_name": "a\u{1}b"}),
        ),
        body(
            "POST",
            "/api/accounts/unlock",
            json!({"email": USER, "password": "p", "profile_key": "nope"}),
        ),
        body(
            "POST",
            "/api/accounts/unlock",
            json!({"email": USER, "password": "p"}),
        ),
        body(
            "POST",
            "/api/accounts/unlock",
            json!({"email": USER, "password": "wrong", "incoming_server": "127.0.0.1",
                   "incoming_port": port, "incoming_protocol": "NONE"}),
        ),
        get("/api/mail/folders", &[a]),
        body(
            "POST",
            "/api/accounts/unlock",
            json!({"email": USER, "password": PASSWORD, "incoming_server": "127.0.0.1",
                   "incoming_port": port, "incoming_protocol": "NONE",
                   "outgoing_server": "127.0.0.1", "outgoing_port": 2525,
                   "outgoing_protocol": "NONE", "display_name": "Example User"}),
        ),
        get("/api/accounts", &[]),
        get("/api/mail/servers", &[]),
        get("/api/mail/folders", &[a]),
        get("/api/mail/folders", &[]),
        get("/api/mail/messages", &[a]),
        get(
            "/api/mail/messages",
            &[a, inbox, ("offset", "0"), ("limit", "200"), ("query", "")],
        ),
        get(
            "/api/mail/messages",
            &[a, inbox, ("offset", "2"), ("limit", "2"), ("query", "")],
        ),
        get(
            "/api/mail/messages",
            &[a, inbox, ("offset", "9"), ("limit", "2")],
        ),
        get("/api/mail/messages", &[a, inbox, ("query", "order")]),
        get("/api/mail/messages", &[a, inbox, ("query", "  digest ")]),
        get("/api/mail/messages", &[a, inbox, ("read_status", "unread")]),
        get("/api/mail/messages", &[a, inbox, ("read_status", "read")]),
        get("/api/mail/messages", &[a, inbox, ("read_status", "bogus")]),
        get(
            "/api/mail/messages",
            &[a, inbox, ("sender_domain", "example.com")],
        ),
        get(
            "/api/mail/messages",
            &[a, inbox, ("sender_domain", "store.example.com")],
        ),
        get(
            "/api/mail/messages",
            &[
                a,
                inbox,
                ("sender_domain", "STORE.example.com"),
                ("sender_domain", "example.org"),
            ],
        ),
        get(
            "/api/mail/messages",
            &[a, inbox, ("sender_domain", "bücher.example")],
        ),
        get(
            "/api/mail/messages",
            &[a, inbox, ("sender_domain", "bad domain!")],
        ),
        get("/api/mail/messages", &[a, inbox, ("sender_domain", "")]),
        get("/api/mail/messages", &[a, inbox, ("expired_only", "true")]),
        get("/api/mail/messages", &[a, inbox, ("expired_only", "maybe")]),
        get("/api/mail/messages", &[a, inbox, ("limit", "0")]),
        get("/api/mail/messages", &[a, inbox, ("limit", "201")]),
        get("/api/mail/messages", &[a, inbox, ("offset", "-1")]),
        get(
            "/api/mail/messages",
            &[a, inbox, ("limit", "x"), ("offset", "y")],
        ),
        get(
            "/api/mail/messages",
            &[a, inbox, ("query", &"q".repeat(201))],
        ),
        get("/api/mail/messages", &[a, ("folder", "Nope")]),
        get("/api/mail/messages", &[a, ("folder", "Archive/2025")]),
        get(
            "/api/mail/messages",
            &[("account", "other@example.com"), inbox],
        ),
        get("/api/mail/message", &[a, inbox, ("uid", "0")]),
        get("/api/mail/message", &[a, inbox, ("uid", "abc")]),
        get("/api/mail/message", &[a, inbox]),
        get(
            "/api/mail/message",
            &[a, inbox, ("uid", "99"), ("mark_seen", "false")],
        ),
        get(
            "/api/mail/message",
            &[a, inbox, ("uid", "1"), ("mark_seen", "nope")],
        ),
        get(
            "/api/mail/message/attachment",
            &[a, inbox, ("uid", "2"), ("index", "0")],
        ),
        get(
            "/api/mail/message/attachment",
            &[a, inbox, ("uid", "2"), ("index", "9")],
        ),
        get(
            "/api/mail/message/attachment",
            &[a, inbox, ("uid", "2"), ("index", "-1")],
        ),
        get("/api/mail/message/eml", &[a, inbox, ("uid", "3")]),
        get("/api/mail/message/eml", &[a, inbox, ("uid", "77")]),
        get("/api/mail/sender-rules", &[a]),
        get("/api/mail/sender-rules", &[a, ("folder", "")]),
        json!({"method": "DELETE", "path": "/api/mail/sender-rules",
               "params": [["account", USER], ["folder", "INBOX"], ["sender", "not-an-address"]]}),
        json!({"method": "DELETE", "path": "/api/mail/sender-rules",
               "params": [["account", USER], ["folder", "INBOX"], ["sender", "Nobody@Example.com"]]}),
        json!({"method": "DELETE", "path": "/api/mail/sender-rules",
               "params": [["account", USER], ["sender", "x"]]}),
        body(
            "POST",
            "/api/mail/message/flags",
            json!({"account": USER, "folder": "", "uid": 0}),
        ),
        body(
            "POST",
            "/api/mail/message/flags",
            json!({"account": USER, "folder": "INBOX", "uid": "1", "seen": "maybe"}),
        ),
        body(
            "PUT",
            "/api/mail/message/retention",
            json!({"account": USER, "folder": "INBOX", "uid": 1, "uid_validity": "4321"}),
        ),
        body(
            "PUT",
            "/api/mail/message/retention",
            json!({"account": USER, "folder": "INBOX", "uid": "1", "uid_validity": "0123",
                   "category": "spam", "expiration_days": 100000}),
        ),
        body(
            "PUT",
            "/api/mail/message/retention",
            json!({"account": USER, "folder": "INBOX", "uid": 1, "uid_validity": "99999999999",
                   "category": "marketing"}),
        ),
        body(
            "POST",
            "/api/mail/message/classify",
            json!({"account": USER, "folder": "INBOX", "uid": 1, "uid_validity": 4321}),
        ),
        body(
            "POST",
            "/api/mail/message/sender-rule",
            json!({"account": USER, "folder": "INBOX", "uid": 1, "uid_validity": "4321",
                   "category": "verification", "expected_category_revision": -1}),
        ),
        body(
            "POST",
            "/api/mail/messages/delete",
            json!({"account": USER, "folder": "INBOX", "uids": []}),
        ),
        body(
            "POST",
            "/api/mail/messages/delete",
            json!({"account": USER, "folder": "INBOX", "uids": [0, "2", 4294967296u64]}),
        ),
        body(
            "POST",
            "/api/mail/trash/prepare",
            json!({"account": USER, "folder": "Trash", "archive": "true"}),
        ),
        body(
            "POST",
            "/api/mail/trash/prepare",
            json!({"account": USER, "folder": "Trash", "archive": false, "x": 1}),
        ),
        body(
            "POST",
            "/api/mail/trash/missing/empty",
            json!({"account": USER}),
        ),
        get("/api/mail/trash/missing/archive", &[a]),
        body(
            "POST",
            "/api/mail/send",
            json!({"account": USER, "to": ["not an address"], "subject": "a\r\nb"}),
        ),
        body(
            "POST",
            "/api/mail/send",
            json!({"account": USER, "to": ["a@example.com"], "uploads": [{"disposition": "inline"}]}),
        ),
        body(
            "POST",
            "/api/mail/send",
            json!({"account": USER, "to": ["a@example.com"],
                   "uploads": [{"content_id": "x", "disposition": "attachment"}]}),
        ),
        body(
            "POST",
            "/api/mail/send",
            json!({"account": USER, "to": ["a@example.com"], "html": "<img src=\"cid:x\">"}),
        ),
        body(
            "POST",
            "/api/mail/message/image",
            json!({"account": USER, "folder": "INBOX", "uid": 3, "url": "ftp://img.example.com/x.png"}),
        ),
        body(
            "POST",
            "/api/mail/message/image",
            json!({"account": USER, "folder": "INBOX", "uid": 3, "url": "https://img.example.com/other.png"}),
        ),
        body("POST", "/api/audit/eml", json!({"content": ""})),
        body(
            "PUT",
            "/api/mail/servers/%20%20",
            json!({"incoming_server": "imap.example.com", "outgoing_server": "smtp.example.com"}),
        ),
        body(
            "PUT",
            "/api/mail/servers/x",
            json!({"incoming_server": "", "outgoing_server": "s", "incoming_port": 70000}),
        ),
        json!({"method": "DELETE", "path": "/api/mail/servers/missing", "params": []}),
        json!({"method": "DELETE", "path": "/api/accounts/nobody@example.com", "params": []}),
        get("/api/nope", &[]),
        json!({"method": "PATCH", "path": "/api/accounts", "params": []}),
        get("/api/jobs/nope", &[]),
        body(
            "POST",
            "/api/mail/jobs/account",
            json!({"account": USER, "days": 0}),
        ),
        get("/api/mail/providers", &[("email", "someone@gmail.com")]),
        get("/api/email-metrics/schedule", &[]),
        get("/api/email-metrics", &[]),
        get("/api/email-metrics", &[("account", " User@Example.com ")]),
        get("/api/email-metrics", &[("account", "bad address")]),
        get("/api/jobs", &[]),
        body("POST", "/api/jobs/paste", json!({"content": ""})),
        body("POST", "/api/jobs/paste", json!({"filename": "x"})),
        body(
            "POST",
            "/api/mail/jobs",
            json!({"email": "a@outlook.com", "password": "x"}),
        ),
        body(
            "POST",
            "/api/mail/jobs",
            json!({"email": "x", "password": ""}),
        ),
        body(
            "POST",
            "/api/mail/jobs",
            json!({"email": "a@example.org", "password": "x", "incoming_protocol": "TLS"}),
        ),
        body(
            "POST",
            "/api/mail/oauth/start",
            json!({"provider": "yahoo", "email": "a@example.org"}),
        ),
        body(
            "POST",
            "/api/mail/oauth/start",
            json!({"provider": "google", "email": "a@outlook.com"}),
        ),
        get(
            "/api/mail/oauth/google/callback",
            &[("state", "unknown"), ("code", "abc")],
        ),
        get(
            "/api/mail/oauth/google/callback",
            &[("error", "access_denied")],
        ),
        get("/api/mail/providers", &[("email", "a@outlook.com")]),
        get("/api/mail/providers", &[("email", "a@proton.me")]),
        get("/api/mail/providers", &[("email", "a@example.org")]),
        get("/api/mail/providers", &[("email", "")]),
        get("/api/mail/providers", &[]),
        get("/api/mail/signature", &[a]),
        get("/api/mail/signature/image", &[a, ("content_id", "missing")]),
        get("/api/mail/signature/image", &[a, ("content_id", "../x")]),
        get("/api/mail/signature/image", &[a]),
        get("/api/mail/classifier/status", &[]),
        get("/api/mail/classifier/status", &[("model", "bad model!")]),
        body(
            "POST",
            "/api/accounts/unlock",
            json!({"email": " user@example.com ", "password": PASSWORD,
                   "incoming_server": " 127.0.0.1 ", "incoming_port": port,
                   "incoming_protocol": " none ", "display_name": "  Spaced Name  "}),
        ),
        get("/api/accounts", &[]),
        get("/api/mail/servers", &[]),
        json!({"method": "DELETE", "path": "/api/accounts/%20USER@example.com%20", "params": []}),
        get("/api/accounts", &[]),
        body(
            "POST",
            "/api/accounts/unlock",
            json!({"email": USER, "password": PASSWORD, "incoming_server": "127.0.0.1",
                   "incoming_port": port, "incoming_protocol": "NONE"}),
        ),
    ];
    for uid in ["1", "2", "3", "4", "5", "6"] {
        list.push(get(
            "/api/mail/message",
            &[a, inbox, ("uid", uid), ("mark_seen", "false")],
        ));
        list.push(get("/api/mail/audit", &[a, inbox, ("uid", uid)]));
    }
    for category in [
        "marketing",
        "transactional",
        "updates",
        "verification",
        "uncategorized",
        "spam",
    ] {
        list.push(get(
            "/api/mail/messages",
            &[a, inbox, ("category", category), ("limit", "50")],
        ));
    }
    list.push(body(
        "POST",
        "/api/audit/eml",
        json!({"content": String::from_utf8(crlf(&attachment_message(3).replace(
            &rfc2822_days_ago(3),
            "Thu, 05 Nov 2026 10:00:00 +0000",
        )))
        .unwrap()}),
    ));
    list
}

/// The `{operation_id}` placeholder: the last `operation_id` answered.
fn substitute(path: &str, operation: &Option<String>) -> String {
    match operation {
        Some(id) => path.replace("{operation_id}", id),
        None => path.to_string(),
    }
}

async fn rust_responses(app: &E2e, requests: &[Value]) -> Vec<Value> {
    let mut out = Vec::new();
    let mut operation: Option<String> = None;
    for item in requests {
        let params: Vec<(String, String)> = item["params"]
            .as_array()
            .map(|pairs| {
                pairs
                    .iter()
                    .map(|pair| {
                        (
                            pair[0].as_str().unwrap().to_string(),
                            pair[1].as_str().unwrap().to_string(),
                        )
                    })
                    .collect()
            })
            .unwrap_or_default();
        let pairs: Vec<(&str, &str)> = params
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        let path = substitute(item["path"].as_str().unwrap(), &operation);
        let uri = with_query(&path, &pairs);
        let method = Method::from_bytes(item["method"].as_str().unwrap().as_bytes()).unwrap();
        let builder = E2e::builder(method, &uri);
        let request = if let Some(value) = item.get("json") {
            builder
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(value).unwrap()))
        } else if let Some(text) = item.get("raw") {
            builder
                .header("content-type", item["content_type"].as_str().unwrap())
                .body(Body::from(text.as_str().unwrap().to_string()))
        } else if item.get("form").is_some() || item.get("files").is_some() {
            // httpx order: data fields first, then files.
            let mut parts = Vec::new();
            for field in item["form"].as_array().into_iter().flatten() {
                parts.push(form_field(
                    field[0].as_str().unwrap(),
                    field[1].as_str().unwrap(),
                ));
            }
            for file in item["files"].as_array().into_iter().flatten() {
                use base64::Engine;
                let data = base64::engine::general_purpose::STANDARD
                    .decode(file[3].as_str().unwrap())
                    .unwrap();
                parts.push(form_file(
                    file[0].as_str().unwrap(),
                    file[1].as_str().unwrap(),
                    file[2].as_str().unwrap(),
                    &data,
                ));
            }
            builder
                .header(
                    "content-type",
                    format!("multipart/form-data; boundary={BOUNDARY}"),
                )
                .body(Body::from(multipart_body(&parts)))
        } else {
            builder.body(Body::empty())
        }
        .unwrap();
        let response = app.send(request).await;
        let mut result = Map::new();
        result.insert("status".into(), json!(response.status.as_u16()));
        result.insert(
            "content_type".into(),
            json!(response.header("content-type")),
        );
        result.insert(
            "content_disposition".into(),
            json!(response.header("content-disposition")),
        );
        match serde_json::from_slice::<Value>(&response.body) {
            Ok(value) => {
                if let Some(id) = value.get("operation_id").and_then(Value::as_str) {
                    operation = Some(id.to_string());
                }
                result.insert("json".into(), value)
            }
            Err(_) => result.insert("text".into(), json!(response.text())),
        };
        out.push(Value::Object(result));
    }
    out
}

fn python_responses(requests: &[Value], env: &[(&str, String)]) -> Option<Vec<Value>> {
    let project = original_project();
    if !project.join("backend/app/main.py").is_file() {
        eprintln!("original project not found at {}", project.display());
        return None;
    }
    let state = tempfile::tempdir().unwrap();
    let script =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/e2e_support/python_driver.py");
    let mut command = Command::new("python");
    // `-B` + PYTHONDONTWRITEBYTECODE: original-project is read-only reference
    // material, so importing it must never write `__pycache__` into it.
    command
        .arg("-B")
        .arg(&script)
        .arg(&project)
        .arg(state.path())
        .current_dir(state.path())
        .env("APPDATA", state.path())
        .env("XDG_CONFIG_HOME", state.path())
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .env("PYTHONUTF8", "1")
        .env("PYTHONIOENCODING", "utf-8")
        .env("TEMP", state.path())
        .env("TMP", state.path())
        .env_remove("MAIL_SERVERS_PATH")
        .env_remove("CORS_ORIGINS")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (name, value) in env {
        command.env(name, value);
    }
    let mut child = command.spawn().ok()?;
    child
        .stdin
        .take()
        .unwrap()
        .write_all(serde_json::to_string(requests).unwrap().as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    if !output.status.success() {
        panic!(
            "python driver failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    if !stderr.trim().is_empty() {
        eprintln!("python driver stderr: {stderr}");
    }
    Some(serde_json::from_slice(&output.stdout).expect("driver JSON"))
}

/// Key-order-sensitive rendering (`Value` equality ignores map order).
fn ordered(value: &Value) -> String {
    serde_json::to_string(value).unwrap()
}

/// Drop documented extension differences and volatile values.
fn normalize(value: &mut Value) {
    match value {
        Value::Object(map) => {
            map.shift_remove("unlocked_at");
            map.shift_remove("incoming_mail_protocol");
            map.shift_remove("generated_at");
            map.shift_remove("created_at");
            map.shift_remove("operation_id");
            if map
                .get("filename")
                .and_then(Value::as_str)
                .is_some_and(|name| name.starts_with("trash-"))
            {
                map.insert("filename".into(), json!("trash-TIMESTAMP.zip"));
            }
            for item in map.values_mut() {
                normalize(item);
            }
        }
        Value::Array(items) => items.iter_mut().for_each(normalize),
        _ => {}
    }
}

/// Compare the two response lists; `ports` maps (python, rust) port pairs.
fn differences(
    requests: &[Value],
    python: &[Value],
    rust: &[Value],
    ports: &[(u16, u16)],
) -> Vec<String> {
    let mut found = Vec::new();
    for (index, request) in requests.iter().enumerate() {
        let mut expected = python[index].clone();
        let mut actual = rust[index].clone();
        normalize(&mut expected);
        normalize(&mut actual);
        // Documented deviation: the port redacts passwords in 422 issues.
        if let Some(issues) = expected
            .pointer_mut("/json/detail")
            .and_then(Value::as_array_mut)
        {
            issues.iter_mut().for_each(mail_core::schemas::redact_issue);
        }
        let mut expected_text = expected.to_string();
        let mut actual_text = actual.to_string();
        for (python_port, rust_port) in ports {
            expected_text = expected_text.replace(&python_port.to_string(), "0");
            actual_text = actual_text.replace(&rust_port.to_string(), "0");
        }
        let mut expected: Value = serde_json::from_str(&expected_text).unwrap();
        let mut actual: Value = serde_json::from_str(&actual_text).unwrap();
        let path = request["path"].as_str().unwrap();
        if path == "/api/mail/servers" && request["method"] == "GET" {
            expected["json"]["path"] = Value::Null;
            actual["json"]["path"] = Value::Null;
        }
        // Sent copies carry random Message-ID digits (make_msgid), so their
        // RFC822.SIZE varies by a byte or two between runs.
        if request["params"]
            .as_array()
            .is_some_and(|params| params.contains(&json!(["folder", "Sent"])))
        {
            for side in [&mut expected, &mut actual] {
                for message in side["json"]["messages"]
                    .as_array_mut()
                    .into_iter()
                    .flatten()
                {
                    let message = message.as_object_mut().unwrap();
                    for key in ["size", "date", "internal_date", "received_at"] {
                        message.shift_remove(key);
                    }
                }
            }
        }
        if path.starts_with("/api/mail/trash/") && request["method"] == "DELETE" {
            for side in [&mut expected, &mut actual] {
                if side["json"].get("discarded").is_some() {
                    side["json"]["discarded"] = json!("OPERATION");
                }
            }
        }
        if path.starts_with("/api/mail/send") {
            for side in [&mut expected, &mut actual] {
                if let Some(map) = side["json"].as_object_mut() {
                    map.shift_remove("message_id");
                }
            }
        }
        if path.ends_with("/archive") {
            // ZIP bytes carry timestamps; the entries are compared separately.
            for side in [&mut expected, &mut actual] {
                side.as_object_mut().unwrap().shift_remove("text");
                if let Some(value) = side["content_disposition"].as_str() {
                    if value.contains("trash-") {
                        side["content_disposition"] = json!("trash archive");
                    }
                }
            }
        }
        // The default backend port moved from 8741 to 48101 (DEFAULT_PORT).
        if let Some(url) = expected["json"]["oauth_callback_url"].as_str() {
            expected["json"]["oauth_callback_url"] =
                json!(url.replace("localhost:8741", "localhost:48101"));
        }
        // Order-sensitive: serde_json maps (preserve_order) compare as sets.
        if ordered(&expected) != ordered(&actual) {
            found.push(format!(
                "#{index} {} {} {}\n  python: {}\n  rust:   {}",
                request["method"].as_str().unwrap(),
                path,
                request
                    .get("params")
                    .map(Value::to_string)
                    .unwrap_or_default(),
                expected,
                actual
            ));
        }
    }
    found
}

#[tokio::test]
#[ignore = "differential: needs Python 3 + fastapi and ../original-project; run with --ignored"]
async fn rust_and_python_backends_answer_identically() {
    let python_server = server();
    // Ollama "not running" for both backends (a closed loopback port).
    let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let ollama = format!("http://127.0.0.1:{}", closed.local_addr().unwrap().port());
    drop(closed);
    let python = match python_responses(
        &requests(python_server.port()),
        &[("E2E_OLLAMA_URL", ollama.clone())],
    ) {
        Some(responses) => responses,
        None => return,
    };
    let rust_server = server();
    let rust_requests = requests(rust_server.port());
    let app = E2e::new();
    let rust = {
        let _url = mail_core::classifier::scoped_ollama_url(ollama);
        rust_responses(&app, &rust_requests).await
    };
    let found = differences(
        &rust_requests,
        &python,
        &rust,
        &[(python_server.port(), rust_server.port())],
    );
    assert!(
        found.is_empty(),
        "{} differences:\n{}",
        found.len(),
        found.join("\n")
    );
}

// ---------------------------------------------------------------------------
// Mutating flow: each backend gets its own identical IMAP + SMTP + Ollama.
// ---------------------------------------------------------------------------

struct Side {
    imap: FakeImapServer,
    smtp: mail_proto::testkit::FakeSmtpServer,
    ollama: FakeOllama,
}

impl Side {
    fn ollama_port(&self) -> u16 {
        self.ollama
            .url()
            .rsplit(':')
            .next()
            .unwrap()
            .parse()
            .unwrap()
    }
}

fn side() -> Side {
    Side {
        imap: server(),
        smtp: mail_proto::testkit::FakeSmtpServer::builder()
            .credentials(USER, PASSWORD)
            .start(),
        ollama: FakeOllama::with_model("llama3.2:latest", "transactional", "An order update"),
    }
}

fn delete(path: &str, params: &[(&str, &str)]) -> Value {
    let mut request = get(path, params);
    request["method"] = json!("DELETE");
    request
}

fn flow(side: &Side) -> Vec<Value> {
    let a = ("account", USER);
    let inbox = ("folder", "INBOX");
    let profile = json!({
        "incoming_server": "127.0.0.1", "incoming_port": side.imap.port(),
        "incoming_protocol": "NONE", "outgoing_server": "127.0.0.1",
        "outgoing_port": side.smtp.port(), "outgoing_protocol": "NONE",
        "email_address": USER, "display_name": "Profile Name",
    });
    let identity =
        |uid: u32| json!({"account": USER, "folder": "INBOX", "uid": uid, "uid_validity": "4321"});
    let with = |base: Value, extra: Value| {
        let mut map = base.as_object().unwrap().clone();
        map.extend(extra.as_object().unwrap().clone());
        Value::Object(map)
    };
    // `/api/mail/send/files` is not replayed: the original needs Starlette's
    // `request.form(max_part_size=...)` (newer than many installed
    // FastAPI/Starlette builds); the multipart send is covered by
    // e2e_imap_flow.rs. The drivers still support `form`/`files` requests.
    vec![
        body(
            "PUT",
            "/api/settings",
            json!({"messages_per_page": 3, "local_ai_model": "llama3.2:latest",
                   "category_expiration_days": {"marketing": 7, "transactional": 400,
                       "updates": 14, "verification": 1, "uncategorized": -1}}),
        ),
        get("/api/settings", &[]),
        body("PUT", "/api/mail/servers/Work%20Mail%21", profile),
        get("/api/mail/servers", &[]),
        body(
            "POST",
            "/api/accounts/unlock",
            json!({"email": USER, "password": PASSWORD, "profile_key": "work-mail",
                   "display_name": "Custom Name", "save_profile": true}),
        ),
        get("/api/accounts", &[]),
        get("/api/mail/servers", &[]),
        get("/api/mail/messages", &[a, inbox]),
        get("/api/mail/messages", &[a, inbox, ("offset", "3")]),
        get(
            "/api/mail/message",
            &[a, inbox, ("uid", "3"), ("mark_seen", "true")],
        ),
        get(
            "/api/mail/messages",
            &[a, inbox, ("read_status", "unread"), ("limit", "10")],
        ),
        body(
            "PUT",
            "/api/mail/message/retention",
            with(identity(1), json!({"category": "marketing"})),
        ),
        body(
            "PUT",
            "/api/mail/message/retention",
            with(identity(2), json!({"expiration_days": 1})),
        ),
        get(
            "/api/mail/messages",
            &[a, inbox, ("expired_only", "true"), ("limit", "10")],
        ),
        body(
            "PUT",
            "/api/mail/message/retention",
            with(
                identity(2),
                json!({"category": null, "expiration_days": null}),
            ),
        ),
        body(
            "PUT",
            "/api/mail/message/retention",
            json!({"account": USER, "folder": "INBOX", "uid": 1, "uid_validity": "1",
                   "category": "updates"}),
        ),
        get(
            "/api/mail/messages",
            &[a, inbox, ("expired_only", "true"), ("limit", "10")],
        ),
        get(
            "/api/mail/messages",
            &[a, inbox, ("category", "marketing"), ("limit", "10")],
        ),
        get("/api/mail/classifier/status", &[]),
        get("/api/mail/classifier/status", &[("model", "missing:1b")]),
        body("POST", "/api/mail/message/classify", identity(4)),
        get(
            "/api/mail/message",
            &[a, inbox, ("uid", "4"), ("mark_seen", "false")],
        ),
        body(
            "POST",
            "/api/mail/message/sender-rule",
            with(identity(4), json!({"category": "updates"})),
        ),
        body(
            "POST",
            "/api/mail/message/sender-rule",
            with(
                identity(4),
                json!({"category": "transactional", "expected_category_revision": 99}),
            ),
        ),
        body(
            "POST",
            "/api/mail/message/sender-rule",
            with(identity(4), json!({"category": "transactional"})),
        ),
        get("/api/mail/sender-rules", &[a]),
        get("/api/mail/sender-rules", &[a, inbox]),
        delete(
            "/api/mail/sender-rules",
            &[
                a,
                inbox,
                ("sender", "orders@store.example.com"),
                ("expected_revision", "99"),
            ],
        ),
        delete(
            "/api/mail/sender-rules",
            &[a, inbox, ("sender", "ORDERS@store.example.com")],
        ),
        delete(
            "/api/mail/sender-rules",
            &[a, inbox, ("sender", "orders@store.example.com")],
        ),
        body(
            "POST",
            "/api/mail/send",
            json!({"account": USER, "to": ["Friend <friend@example.net>"], "cc": ["c@example.org"],
                   "bcc": ["hidden@example.org"], "subject": "Gr\u{fc}\u{df}e", "text": "Hallo",
                   "html": "<p>Hallo</p>", "in_reply_to": "<o4@example.com>",
                   "references": "<o4@example.com>"}),
        ),
        get("/api/mail/folders", &[a]),
        get(
            "/api/mail/messages",
            &[a, ("folder", "Sent"), ("limit", "10")],
        ),
        delete(
            "/api/mail/message",
            &[
                a,
                inbox,
                ("uid", "5"),
                ("trash", "Trash"),
                ("uid_validity", "4321"),
            ],
        ),
        body(
            "POST",
            "/api/mail/messages/delete",
            json!({"account": USER, "folder": "INBOX", "uids": [6, 6], "trash": "Trash",
                   "uid_validity": "4321"}),
        ),
        get(
            "/api/mail/messages",
            &[a, ("folder", "Trash"), ("limit", "10")],
        ),
        get("/api/mail/messages", &[a, inbox, ("limit", "10")]),
        body(
            "POST",
            "/api/mail/trash/prepare",
            json!({"account": USER, "folder": "Trash", "archive": true}),
        ),
        body(
            "POST",
            "/api/mail/trash/{operation_id}/empty",
            json!({"account": USER}),
        ),
        get("/api/mail/trash/{operation_id}/archive", &[a]),
        body(
            "POST",
            "/api/mail/trash/{operation_id}/empty",
            json!({"account": USER}),
        ),
        body(
            "POST",
            "/api/mail/trash/{operation_id}/empty",
            json!({"account": USER}),
        ),
        get("/api/mail/messages", &[a, ("folder", "Trash")]),
        delete("/api/mail/trash/{operation_id}", &[a]),
        delete("/api/mail/trash/{operation_id}", &[a]),
        get("/api/mail/audit", &[a, inbox, ("uid", "4")]),
        delete("/api/accounts/USER%40example.com", &[]),
        get("/api/mail/folders", &[a]),
        get("/api/accounts", &[]),
        body(
            "POST",
            "/api/accounts/unlock",
            json!({"email": USER, "password": PASSWORD, "profile_key": "work-mail"}),
        ),
        get("/api/accounts", &[]),
    ]
}

/// MIME skeleton of a sent message: headers that must match and every leaf
/// part's type, disposition, file name, content id and decoded body.
fn skeleton(raw: &[u8]) -> Value {
    use mail_parser::{MessageParser, MimeHeaders};
    let message = MessageParser::default().parse(raw).unwrap();
    let kind = |part: &mail_parser::MessagePart| {
        part.content_type()
            .map(|ct| format!("{}/{}", ct.ctype(), ct.subtype().unwrap_or_default()))
    };
    let mut parts = Vec::new();
    for part in message.parts.iter() {
        if matches!(part.body, mail_parser::PartType::Multipart(_)) {
            parts.push(json!({"multipart": kind(part)}));
            continue;
        }
        parts.push(json!({
            "type": kind(part),
            "disposition": part.content_disposition().map(|d| d.ctype().to_string()),
            "filename": part.attachment_name(),
            "content_id": part.content_id(),
            "body": String::from_utf8_lossy(part.contents())
                .replace("\r\n", "\n")
                .trim_end()
                .to_string(),
        }));
    }
    json!({
        "subject": message.subject(),
        "from": format!("{:?}", message.from()),
        "to": format!("{:?}", message.to()),
        "cc": format!("{:?}", message.cc()),
        "bcc": format!("{:?}", message.bcc()),
        "in_reply_to": format!("{:?}", message.in_reply_to()),
        "references": format!("{:?}", message.references()),
        "mime_version": message.header_raw("MIME-Version").map(str::trim),
        "parts": parts,
    })
}

#[tokio::test]
#[ignore = "differential: needs Python 3 + fastapi and ../original-project; run with --ignored"]
async fn mutating_flow_matches_the_python_backend() {
    let python_side = side();
    let python = match python_responses(
        &flow(&python_side),
        &[("E2E_OLLAMA_URL", python_side.ollama.url())],
    ) {
        Some(responses) => responses,
        None => return,
    };
    let rust_side = side();
    let requests = flow(&rust_side);
    let app = E2e::new();
    let rust = {
        let _url = mail_core::classifier::scoped_ollama_url(rust_side.ollama.url());
        rust_responses(&app, &requests).await
    };
    let ports = [
        (python_side.imap.port(), rust_side.imap.port()),
        (python_side.smtp.port(), rust_side.smtp.port()),
        (python_side.ollama_port(), rust_side.ollama_port()),
    ];
    let mut found = differences(&requests, &python, &rust, &ports);

    // What reached the servers.
    let python_mail = python_side.smtp.messages();
    let rust_mail = rust_side.smtp.messages();
    if python_mail.len() != rust_mail.len() {
        found.push(format!(
            "SMTP message count: python {} / rust {}",
            python_mail.len(),
            rust_mail.len()
        ));
    }
    for (index, (expected, actual)) in python_mail.iter().zip(&rust_mail).enumerate() {
        if expected.rcpt_to != actual.rcpt_to || expected.mail_from != actual.mail_from {
            found.push(format!(
                "SMTP envelope #{index}: python {:?} {:?} / rust {:?} {:?}",
                expected.mail_from, expected.rcpt_to, actual.mail_from, actual.rcpt_to
            ));
        }
        let (expected, actual) = (skeleton(&expected.data), skeleton(&actual.data));
        // Order-sensitive: serde_json maps (preserve_order) compare as sets.
        if ordered(&expected) != ordered(&actual) {
            found.push(format!(
                "SMTP message #{index}:\n  python: {expected}\n  rust:   {actual}"
            ));
        }
    }
    for folder in ["INBOX", "Sent", "Trash"] {
        let expected = python_side.imap.folder(folder).unwrap();
        let actual = rust_side.imap.folder(folder).unwrap();
        let summary = |f: &mail_proto::testkit::FakeFolder| {
            f.messages
                .iter()
                .map(|m| (m.uid, m.flags.clone()))
                .collect::<Vec<_>>()
        };
        if summary(&expected) != summary(&actual) {
            found.push(format!(
                "IMAP folder {folder}: python {:?} / rust {:?}",
                summary(&expected),
                summary(&actual)
            ));
        }
        if folder == "Sent" {
            for (index, (e, a)) in expected.messages.iter().zip(&actual.messages).enumerate() {
                let (e, a) = (skeleton(&e.raw), skeleton(&a.raw));
                if e != a {
                    found.push(format!("Sent copy #{index}:\n  python: {e}\n  rust:   {a}"));
                }
            }
        }
    }
    assert!(
        found.is_empty(),
        "{} differences:\n{}",
        found.len(),
        found.join("\n")
    );
}
