//! A minimal fake Ollama HTTP server for the classifier tests (the Python
//! tests replaced `httpx.Client` with an `httpx.MockTransport`).
//!
//! Every request is recorded; replies come from a handler closure, so a test
//! can also change other state "during inference" from the `/api/chat`
//! handler. Each connection serves one request and is then closed.
//!
//! Shared with mail-backend's classifier tests via `#[path]`.

#![allow(dead_code)]

use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use serde_json::{json, Value};

pub const MODEL: &str = "llama3.2:latest";

/// `LOCAL_TAG`.
pub fn local_tag() -> Value {
    json!({"name": MODEL, "size": 2_019_393_189u64,
           "details": {"format": "gguf", "quantization_level": "Q4_K_M"}})
}

/// A verified local tag entry for `name`.
pub fn tag(name: &str) -> Value {
    json!({"name": name, "size": 1_000_000, "details": {"format": "gguf"}})
}

/// `LOCAL_SHOW`.
pub fn local_show() -> Value {
    json!({
        "details": {"format": "gguf"}, "capabilities": ["completion", "tools"],
        "model_info": {"general.architecture": "llama", "general.file_type": 15,
                       "general.parameter_count": 3_212_749_888u64},
    })
}

/// A successful `/api/chat` answer.
pub fn chat_answer(category: &str, reason: &str, model: &str) -> Value {
    json!({
        "done": true, "model": model,
        "message": {"content": json!({"category": category, "reason": reason}).to_string()},
    })
}

/// One recorded HTTP request.
#[derive(Debug, Clone)]
pub struct Recorded {
    pub method: String,
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Recorded {
    pub fn json(&self) -> Value {
        serde_json::from_slice(&self.body).expect("JSON request body")
    }

    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

/// What the fake answers.
pub enum Reply {
    Json(u16, Value),
    Raw {
        status: u16,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
    },
    /// Never answer (until the client gives up).
    Hang,
}

impl Reply {
    pub fn ok(value: Value) -> Self {
        Reply::Json(200, value)
    }
}

type HandlerFn = dyn Fn(&Recorded) -> Reply + Send + Sync;

pub struct FakeOllama {
    port: u16,
    requests: Arc<Mutex<Vec<Recorded>>>,
    stop: Arc<AtomicBool>,
}

impl FakeOllama {
    pub fn start(handler: impl Fn(&Recorded) -> Reply + Send + Sync + 'static) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind fake Ollama");
        let port = listener.local_addr().unwrap().port();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let handler: Arc<HandlerFn> = Arc::new(handler);
        {
            let requests = requests.clone();
            let stop = stop.clone();
            thread::spawn(move || {
                for stream in listener.incoming() {
                    if stop.load(Ordering::SeqCst) {
                        break;
                    }
                    let Ok(stream) = stream else { continue };
                    let requests = requests.clone();
                    let handler = handler.clone();
                    let stop = stop.clone();
                    thread::spawn(move || serve(stream, &requests, &*handler, &stop));
                }
            });
        }
        FakeOllama {
            port,
            requests,
            stop,
        }
    }

    /// The standard local model fixture with optional overrides.
    pub fn standard(tags: Option<Value>, show: Option<Value>, chat: Option<Value>) -> Self {
        Self::start(move |request| match request.path.as_str() {
            "/api/tags" => {
                Reply::ok(json!({"models": tags.clone().unwrap_or_else(|| json!([local_tag()]))}))
            }
            "/api/show" => Reply::ok(show.clone().unwrap_or_else(local_show)),
            "/api/chat" => {
                Reply::ok(chat.clone().unwrap_or_else(|| {
                    chat_answer("transactional", "Receipt for a purchase", MODEL)
                }))
            }
            other => panic!("unexpected request to {other}"),
        })
    }

    pub fn url(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }

    pub fn requests(&self) -> Vec<Recorded> {
        self.requests.lock().unwrap().clone()
    }

    pub fn paths(&self) -> Vec<String> {
        self.requests().into_iter().map(|r| r.path).collect()
    }
}

impl Drop for FakeOllama {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(("127.0.0.1", self.port));
    }
}

fn serve(
    mut stream: TcpStream,
    requests: &Mutex<Vec<Recorded>>,
    handler: &HandlerFn,
    stop: &AtomicBool,
) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 8192];
    let header_end = loop {
        if let Some(index) = buffer.windows(4).position(|w| w == b"\r\n\r\n") {
            break index + 4;
        }
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => return,
            Ok(count) => buffer.extend_from_slice(&chunk[..count]),
        }
    };
    let head = String::from_utf8_lossy(&buffer[..header_end]).into_owned();
    let mut lines = head.split("\r\n");
    let mut first = lines.next().unwrap_or_default().split(' ');
    let method = first.next().unwrap_or_default().to_string();
    let path = first.next().unwrap_or_default().to_string();
    let headers: Vec<(String, String)> = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        .collect();
    let length: usize = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, v)| v.parse().ok())
        .unwrap_or(0);
    let mut body = buffer[header_end..].to_vec();
    while body.len() < length {
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(count) => body.extend_from_slice(&chunk[..count]),
        }
    }
    let recorded = Recorded {
        method,
        path,
        headers,
        body,
    };
    requests.lock().unwrap().push(recorded.clone());
    let (status, extra, payload) = match handler(&recorded) {
        Reply::Json(status, value) => (status, Vec::new(), serde_json::to_vec(&value).unwrap()),
        Reply::Raw {
            status,
            headers,
            body,
        } => (status, headers, body),
        Reply::Hang => {
            while !stop.load(Ordering::SeqCst) {
                thread::sleep(Duration::from_millis(50));
                if stream.peek(&mut [0u8; 1]).is_ok_and(|n| n == 0) {
                    break;
                }
            }
            return;
        }
    };
    let mut response = format!(
        "HTTP/1.1 {status} Status\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n",
        payload.len()
    );
    for (name, value) in extra {
        response.push_str(&format!("{name}: {value}\r\n"));
    }
    response.push_str("\r\n");
    let _ = stream.write_all(response.as_bytes());
    let _ = stream.write_all(&payload);
    let _ = stream.flush();
    let _ = stream.shutdown(Shutdown::Both);
}

/// A loopback URL where nothing listens (connection refused).
pub fn closed_url() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    format!("http://127.0.0.1:{port}")
}
