//! End-to-end: the real `mail-backend` executable + `mail_proto::testkit`
//! fake IMAP/SMTP servers + the real `mail-mcp` executable speaking MCP over
//! stdio.
//!
//! * The backend binary is built with `cargo build -p mail-backend` (or taken
//!   from `MAIL_BACKEND_BIN`), copied into a temporary directory (so a running
//!   test never locks the workspace's `target/` copy on Windows) and started
//!   on `--port 0` with every settings/profile/data path isolated under that
//!   directory.
//! * The account is unlocked through the backend HTTP API exactly like the
//!   extension does it; the MCP server never sees the password.
//! * Every MCP tool is called through `tools/call` and its effect is checked
//!   on the fake servers (flags, moved/expunged messages, delivered mail,
//!   Sent copy).

use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::mpsc;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use mail_proto::testkit::{FakeImapServer, FakePop3Server, FakeSmtpServer};
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader as AsyncBufReader, Lines};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};

const USER: &str = "user@example.com";
const PASSWORD: &str = "mcp-E2e-Secret-Pass-4821";
/// The extension's real Origin: the id is pinned by the manifest "key" and is
/// the only one the backend's default allow-list accepts.
const ORIGIN: &str = "chrome-extension://hhhanbkdjaecdfoclhpoicmfhejdbkjl";
const ATTACHMENT_TEXT: &[u8] = b"Agenda: budget, roadmap.\n";

// ---------------------------------------------------------------------------
// The backend executable
// ---------------------------------------------------------------------------

/// Path of a freshly built `mail-backend` executable (built once per run).
fn backend_binary() -> PathBuf {
    static BINARY: OnceLock<PathBuf> = OnceLock::new();
    BINARY
        .get_or_init(|| {
            if let Some(path) = std::env::var_os("MAIL_BACKEND_BIN") {
                return PathBuf::from(path);
            }
            let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
                .parent()
                .expect("workspace root")
                .to_path_buf();
            let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
            let output = std::process::Command::new(cargo)
                .args([
                    "build",
                    "-p",
                    "mail-backend",
                    "--bin",
                    "mail-backend",
                    "--message-format=json-render-diagnostics",
                ])
                .current_dir(&workspace)
                .stdin(Stdio::null())
                .output()
                .expect("run cargo build for mail-backend");
            assert!(
                output.status.success(),
                "building mail-backend failed:\n{}",
                String::from_utf8_lossy(&output.stderr)
            );
            String::from_utf8_lossy(&output.stdout)
                .lines()
                .filter_map(|line| serde_json::from_str::<Value>(line).ok())
                .filter(|message| {
                    message["reason"] == "compiler-artifact"
                        && message["target"]["name"] == "mail-backend"
                })
                .find_map(|message| message["executable"].as_str().map(PathBuf::from))
                .expect("cargo reported no mail-backend executable")
        })
        .clone()
}

/// A running backend process (killed on drop).
struct Backend {
    child: std::process::Child,
    url: String,
    output: Arc<Mutex<String>>,
}

impl Backend {
    fn start(root: &Path) -> Backend {
        let source = backend_binary();
        let bin_dir = root.join("bin");
        std::fs::create_dir_all(&bin_dir).unwrap();
        let binary = bin_dir.join(source.file_name().unwrap());
        std::fs::copy(&source, &binary).expect("copy the backend binary");
        let appdata = root.join("backend-appdata");
        std::fs::create_dir_all(&appdata).unwrap();
        let mut child = std::process::Command::new(&binary)
            .args(["--port", "0"])
            .env("WEBMAIL_SETTINGS_PATH", root.join("settings.json"))
            .env("MAIL_SERVERS_PATH", root.join("mail-servers.json"))
            .env("DATA_DIRECTORY", root.join("data"))
            .env("APPDATA", &appdata)
            .env("LOCALAPPDATA", &appdata)
            .env("XDG_CONFIG_HOME", &appdata)
            .env("XDG_DATA_HOME", &appdata)
            .env("HOME", &appdata)
            .env("RUST_LOG", "debug")
            .env_remove("MAIL_BACKEND_ADDR")
            .env_remove("MAIL_BACKEND_EXTENSION_IDS")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn mail-backend");
        let output = Arc::new(Mutex::new(String::new()));
        let (sender, receiver) = mpsc::channel::<String>();
        let stdout = child.stdout.take().unwrap();
        let stderr = child.stderr.take().unwrap();
        for (stream, sender) in [
            (
                Box::new(stdout) as Box<dyn std::io::Read + Send>,
                sender.clone(),
            ),
            (Box::new(stderr) as Box<dyn std::io::Read + Send>, sender),
        ] {
            let output = Arc::clone(&output);
            std::thread::spawn(move || {
                for line in BufReader::new(stream).lines().map_while(Result::ok) {
                    output.lock().unwrap().push_str(&format!("{line}\n"));
                    let _ = sender.send(line);
                }
            });
        }
        loop {
            match receiver.recv_timeout(Duration::from_secs(60)) {
                Ok(line) => {
                    if let Some(rest) = line.trim().strip_prefix("Backend:") {
                        let url = rest.split_whitespace().next().unwrap().to_string();
                        return Backend { child, url, output };
                    }
                }
                Err(_) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    panic!(
                        "mail-backend did not start:\n{}",
                        output.lock().unwrap().clone()
                    );
                }
            }
        }
    }

    fn output(&self) -> String {
        self.output.lock().unwrap().clone()
    }

    fn kill(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Drop for Backend {
    fn drop(&mut self) {
        self.kill();
    }
}

/// HTTP client used for the extension's side of the story (unlock, lock,
/// settings): it sends the extension `Origin` like the React app does.
fn http() -> reqwest::Client {
    reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(60))
        .build()
        .unwrap()
}

async fn extension_request(
    method: reqwest::Method,
    url: String,
    body: Option<Value>,
) -> (u16, Value) {
    let mut request = http().request(method, url).header("origin", ORIGIN);
    if let Some(body) = body {
        request = request.json(&body);
    }
    let response = request.send().await.expect("backend request");
    let status = response.status().as_u16();
    let text = response.text().await.unwrap();
    let value = serde_json::from_str(&text).unwrap_or(Value::String(text));
    (status, value)
}

// ---------------------------------------------------------------------------
// The MCP executable
// ---------------------------------------------------------------------------

struct Mcp {
    child: Child,
    stdin: Option<ChildStdin>,
    stdout: Lines<AsyncBufReader<ChildStdout>>,
    stderr: Arc<Mutex<String>>,
    next_id: u64,
}

impl Mcp {
    fn spawn(backend_url: &str, cwd: &Path, home: &Path) -> Mcp {
        let mut child = Command::new(env!("CARGO_BIN_EXE_mail-mcp"))
            .current_dir(cwd)
            .env("MAIL_BACKEND_URL", backend_url)
            .env("RUST_LOG", "trace")
            .env("APPDATA", home)
            .env("LOCALAPPDATA", home)
            .env("XDG_CONFIG_HOME", home)
            .env("XDG_DATA_HOME", home)
            .env("HOME", home)
            .env("USERPROFILE", home)
            .env("TMP", home)
            .env("TEMP", home)
            .env("TMPDIR", home)
            .env_remove("MAIL_MCP_ALLOW_NON_LOOPBACK")
            .env_remove("MAIL_BACKEND_TIMEOUT_SECS")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .expect("spawn mail-mcp");
        let stdin = child.stdin.take();
        let stdout = AsyncBufReader::new(child.stdout.take().unwrap()).lines();
        let stderr = Arc::new(Mutex::new(String::new()));
        let mut stream = child.stderr.take().unwrap();
        let sink = Arc::clone(&stderr);
        tokio::spawn(async move {
            let mut buffer = [0u8; 4096];
            while let Ok(read) = stream.read(&mut buffer).await {
                if read == 0 {
                    break;
                }
                sink.lock()
                    .unwrap()
                    .push_str(&String::from_utf8_lossy(&buffer[..read]));
            }
        });
        Mcp {
            child,
            stdin,
            stdout,
            stderr,
            next_id: 1,
        }
    }

    async fn send(&mut self, message: Value) {
        let mut line = serde_json::to_string(&message).unwrap();
        line.push('\n');
        let stdin = self.stdin.as_mut().expect("stdin open");
        stdin.write_all(line.as_bytes()).await.unwrap();
        stdin.flush().await.unwrap();
    }

    async fn request(&mut self, method: &str, params: Value) -> Value {
        let id = self.next_id;
        self.next_id += 1;
        self.send(json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}))
            .await;
        loop {
            let line = tokio::time::timeout(Duration::from_secs(120), self.stdout.next_line())
                .await
                .unwrap_or_else(|_| panic!("timed out waiting for {method}"))
                .unwrap()
                .expect("mail-mcp closed stdout");
            let message: Value = serde_json::from_str(&line)
                .unwrap_or_else(|_| panic!("stdout line is not JSON-RPC: {line}"));
            assert_eq!(message["jsonrpc"], "2.0", "{message}");
            if message.get("id") == Some(&json!(id)) {
                return message;
            }
        }
    }

    /// `tools/call`: `(isError, parsed JSON payload, raw response)`.
    async fn call(&mut self, name: &str, arguments: Value) -> (bool, Value) {
        let response = self
            .request("tools/call", json!({"name": name, "arguments": arguments}))
            .await;
        assert!(
            response.get("error").is_none(),
            "{name} produced a protocol error: {response}"
        );
        let result = &response["result"];
        let text = result["content"][0]["text"]
            .as_str()
            .unwrap_or_else(|| panic!("{name}: no text content: {response}"));
        assert!(
            !text.contains(PASSWORD),
            "{name} leaked the password: {text}"
        );
        let payload = serde_json::from_str(text)
            .unwrap_or_else(|_| panic!("{name}: content is not JSON: {text}"));
        (result["isError"] == json!(true), payload)
    }

    /// A successful tool call's payload.
    async fn ok(&mut self, name: &str, arguments: Value) -> Value {
        let (is_error, payload) = self.call(name, arguments).await;
        assert!(!is_error, "{name} failed: {payload:#}");
        payload
    }

    /// A failed tool call's payload.
    async fn error(&mut self, name: &str, arguments: Value) -> Value {
        let (is_error, payload) = self.call(name, arguments).await;
        assert!(is_error, "{name} unexpectedly succeeded: {payload:#}");
        assert!(
            payload["error"]
                .as_str()
                .is_some_and(|text| !text.is_empty()),
            "{payload}"
        );
        payload
    }

    fn stderr(&self) -> String {
        self.stderr.lock().unwrap().clone()
    }
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

fn crlf(text: &str) -> Vec<u8> {
    text.replace("\r\n", "\n")
        .replace('\n', "\r\n")
        .into_bytes()
}

fn newsletter() -> Vec<u8> {
    crlf(
        "From: Shop News <news@shop.example.com>\n\
         To: user@example.com\n\
         Subject: Autumn newsletter\n\
         Date: Tue, 24 Nov 2026 09:00:00 +0000\n\
         Message-ID: <letter-1@shop.example.com>\n\
         MIME-Version: 1.0\n\
         Content-Type: text/plain; charset=utf-8\n\
         \n\
         New products are in the shop this week.\n",
    )
}

fn notes_with_attachment() -> Vec<u8> {
    let encoded = STANDARD.encode(ATTACHMENT_TEXT);
    crlf(&format!(
        "From: Friend <friend@example.org>\n\
         To: user@example.com\n\
         Subject: Notes for the meeting\n\
         Date: Wed, 25 Nov 2026 10:00:00 +0000\n\
         Message-ID: <notes-2@example.org>\n\
         MIME-Version: 1.0\n\
         Content-Type: multipart/mixed; boundary=\"mix\"\n\
         \n\
         --mix\n\
         Content-Type: multipart/alternative; boundary=\"alt\"\n\
         \n\
         --alt\n\
         Content-Type: text/plain; charset=utf-8\n\
         \n\
         Hi, the meeting notes are attached.\n\
         --alt\n\
         Content-Type: text/html; charset=utf-8\n\
         \n\
         <p>Hi, the meeting notes are <b>attached</b>.</p>\n\
         --alt--\n\
         --mix\n\
         Content-Type: text/plain; charset=utf-8\n\
         Content-Disposition: attachment; filename*=UTF-8''r%C3%A9sum%C3%A9.txt\n\
         Content-Transfer-Encoding: base64\n\
         \n\
         {encoded}\n\
         --mix--\n"
    ))
}

fn verification_code() -> Vec<u8> {
    crlf(
        "From: Accounts <no-reply@accounts.example.com>\n\
         To: user@example.com\n\
         Subject: Your verification code\n\
         Date: Thu, 26 Nov 2026 11:00:00 +0000\n\
         Message-ID: <code-3@accounts.example.com>\n\
         MIME-Version: 1.0\n\
         Content-Type: text/plain; charset=utf-8\n\
         \n\
         Your code is 123456.\n",
    )
}

fn subjects(listing: &Value) -> Vec<String> {
    listing["messages"]
        .as_array()
        .unwrap_or_else(|| panic!("no messages array: {listing}"))
        .iter()
        .map(|message| message["subject"].as_str().unwrap_or_default().to_string())
        .collect()
}

fn uid_of(listing: &Value, subject: &str) -> u64 {
    listing["messages"]
        .as_array()
        .unwrap()
        .iter()
        .find(|message| message["subject"] == subject)
        .and_then(|message| message["uid"].as_u64())
        .unwrap_or_else(|| panic!("no message {subject:?} in {listing}"))
}

fn dir_is_empty(path: &Path) -> bool {
    std::fs::read_dir(path).unwrap().next().is_none()
}

// ---------------------------------------------------------------------------
// The test
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn mcp_tools_against_the_real_backend_and_fake_servers() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().to_path_buf();
    let imap = FakeImapServer::builder()
        .credentials(USER, PASSWORD)
        .folder("Sent", &["\\Sent"])
        .folder("Trash", &["\\Trash"])
        .uid_validity("INBOX", Some(1234))
        .message("INBOX", newsletter())
        .message("INBOX", notes_with_attachment())
        .message("INBOX", verification_code())
        .start();
    let smtp = FakeSmtpServer::builder()
        .credentials(USER, PASSWORD)
        .start();

    let mut backend = Backend::start(&root);
    let base = backend.url.clone();

    // Use a model name that cannot exist, so classification fails fast and
    // deterministically even when a local Ollama happens to be running.
    let (status, settings) = extension_request(
        reqwest::Method::PUT,
        format!("{base}/api/settings"),
        Some(json!({"messages_per_page": 50, "local_ai_model": "mcp-e2e-missing-model:latest"})),
    )
    .await;
    assert_eq!(status, 200, "{settings}");

    let mcp_cwd = root.join("mcp-cwd");
    let mcp_home = root.join("mcp-home");
    std::fs::create_dir_all(&mcp_cwd).unwrap();
    std::fs::create_dir_all(&mcp_home).unwrap();
    let mut mcp = Mcp::spawn(&base, &mcp_cwd, &mcp_home);

    // --- MCP handshake -----------------------------------------------------
    let initialized = mcp
        .request(
            "initialize",
            json!({
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "mail-mcp-e2e", "version": "0.0.1"}
            }),
        )
        .await;
    let result = &initialized["result"];
    assert_eq!(result["serverInfo"]["name"], "mail-mcp", "{initialized}");
    assert!(result["capabilities"]["tools"].is_object(), "{initialized}");
    mcp.send(json!({"jsonrpc": "2.0", "method": "notifications/initialized"}))
        .await;

    let listed = mcp.request("tools/list", json!({})).await;
    let tools = listed["result"]["tools"].as_array().expect("tools").clone();
    assert_eq!(tools.len(), 17, "{listed}");
    // MCP never asks for credentials: no tool takes a password/secret/token.
    for tool in &tools {
        let schema = tool["inputSchema"].to_string().to_lowercase();
        for word in ["password", "secret", "token", "credential"] {
            assert!(
                !schema.contains(&format!("\"{word}")),
                "{} asks for a {word}: {schema}",
                tool["name"]
            );
        }
    }

    // --- Nothing unlocked yet -------------------------------------------------
    let accounts = mcp.ok("mail_list_accounts", json!({})).await;
    assert_eq!(accounts, json!({"accounts": []}));
    let none = mcp.error("mail_list_folders", json!({})).await;
    assert_eq!(none["code"], "invalid_arguments");
    assert!(none["error"]
        .as_str()
        .unwrap()
        .contains("No mail account is unlocked"));
    let locked = mcp
        .error("mail_list_messages", json!({"account": USER}))
        .await;
    assert_eq!(locked["code"], "password_required", "{locked}");
    assert_eq!(locked["status"], 401);
    assert_eq!(locked["email"], USER);
    assert!(locked["error"]
        .as_str()
        .unwrap()
        .contains(&format!("{USER} is locked")));

    // --- The extension unlocks the account ------------------------------------
    let (status, unlocked) = extension_request(
        reqwest::Method::POST,
        format!("{base}/api/accounts/unlock"),
        Some(json!({
            "email": USER, "password": PASSWORD, "display_name": "Example User",
            "incoming_server": "127.0.0.1", "incoming_port": imap.port(),
            "incoming_protocol": "NONE", "outgoing_server": "127.0.0.1",
            "outgoing_port": smtp.port(), "outgoing_protocol": "NONE",
            "save_profile": false,
        })),
    )
    .await;
    assert_eq!(status, 200, "{unlocked}");

    // --- Read-only tools -----------------------------------------------------
    let accounts = mcp.ok("mail_list_accounts", json!({})).await;
    assert_eq!(accounts["accounts"][0]["email"], USER, "{accounts}");
    assert_eq!(accounts["accounts"][0]["display_name"], "Example User");

    let settings = mcp.ok("mail_get_settings", json!({})).await;
    assert_eq!(settings["messages_per_page"], 50, "{settings}");
    assert_eq!(settings["local_ai_model"], "mcp-e2e-missing-model:latest");

    let folders = mcp.ok("mail_list_folders", json!({})).await;
    let folder_list = folders["folders"].as_array().expect("folders");
    let trash = folder_list
        .iter()
        .find(|folder| folder["special"] == "trash")
        .expect("Trash folder");
    assert_eq!(trash["name"], "Trash");
    assert_eq!(trash["selectable"], true);

    let listing = mcp.ok("mail_list_messages", json!({})).await;
    assert_eq!(listing["total"], 3, "{listing}");
    assert_eq!(listing["limit"], 50);
    let letter = uid_of(&listing, "Autumn newsletter");
    let notes = uid_of(&listing, "Notes for the meeting");
    let code = uid_of(&listing, "Your verification code");
    for message in listing["messages"].as_array().unwrap() {
        assert_eq!(message["uid_validity"], "1234", "{message}");
        assert_eq!(message["seen"], false);
    }

    let paged = mcp
        .ok(
            "mail_list_messages",
            json!({"account": USER, "folder": "INBOX", "limit": 1, "offset": 1}),
        )
        .await;
    assert_eq!(paged["total"], 3);
    assert_eq!(paged["messages"].as_array().unwrap().len(), 1);

    let searched = mcp
        .ok("mail_list_messages", json!({"query": "verification"}))
        .await;
    assert_eq!(subjects(&searched), ["Your verification code"]);

    let by_domain = mcp
        .ok(
            "mail_list_messages",
            json!({"sender_domain": ["example.org"], "read_status": "unread"}),
        )
        .await;
    assert_eq!(subjects(&by_domain), ["Notes for the meeting"]);

    let invalid = mcp.error("mail_list_messages", json!({"limit": 500})).await;
    assert_eq!(invalid["status"], 422, "{invalid}");
    assert!(
        invalid["error"].as_str().unwrap().contains("limit"),
        "{invalid}"
    );

    // Reading does not mark the message as seen unless asked.
    let message = mcp.ok("mail_read_message", json!({"uid": notes})).await;
    assert_eq!(message["subject"], "Notes for the meeting", "{message}");
    assert!(message["text_body"]
        .as_str()
        .unwrap()
        .contains("meeting notes are attached"));
    assert_eq!(message["html_body_omitted"], true);
    assert!(message.get("html_body").is_none());
    assert_eq!(message["uid_validity"], "1234");
    assert_eq!(message["attachments"][0]["filename"], "résumé.txt");
    let flags = imap.flags("INBOX", notes as u32).unwrap();
    assert!(!flags.iter().any(|flag| flag == "\\Seen"), "{flags:?}");

    let with_html = mcp
        .ok(
            "mail_read_message",
            json!({"uid": notes, "include_html": true}),
        )
        .await;
    assert!(with_html["html_body"]
        .as_str()
        .unwrap()
        .contains("attached"));

    let raw = mcp.ok("mail_get_raw_message", json!({"uid": notes})).await;
    assert_eq!(raw["truncated"], false, "{raw}");
    assert!(raw["eml"]
        .as_str()
        .unwrap()
        .contains("Subject: Notes for the meeting"));
    let excerpt = mcp
        .ok(
            "mail_get_raw_message",
            json!({"uid": notes, "max_bytes": 10}),
        )
        .await;
    assert_eq!(excerpt["truncated"], true);
    assert_eq!(excerpt["returned_bytes"], 10);

    // The backend sends the file name Latin-1 encoded, like Starlette.
    let attachment = mcp
        .ok("mail_get_attachment", json!({"uid": notes, "index": 0}))
        .await;
    assert_eq!(attachment["filename"], "résumé.txt", "{attachment}");
    assert_eq!(
        STANDARD
            .decode(attachment["content_base64"].as_str().unwrap())
            .unwrap(),
        ATTACHMENT_TEXT
    );
    assert!(attachment["content_type"]
        .as_str()
        .unwrap()
        .starts_with("text/plain"));
    let refused = mcp
        .error(
            "mail_get_attachment",
            json!({"uid": notes, "index": 0, "max_bytes": 4}),
        )
        .await;
    assert_eq!(refused["code"], "invalid_arguments");

    let missing = mcp.error("mail_read_message", json!({"uid": 999})).await;
    assert_eq!(missing["status"], 502, "{missing}");

    let audit = mcp.ok("mail_audit_message", json!({"uid": code})).await;
    assert!(audit.get("verdict").is_some(), "{audit}");
    assert!(audit.get("risk_score").is_some(), "{audit}");

    // --- Flags ----------------------------------------------------------------
    let flagged = mcp
        .ok(
            "mail_set_flags",
            json!({"folder": "INBOX", "uid": letter, "seen": true, "flagged": true}),
        )
        .await;
    assert_eq!(flagged["seen"], true, "{flagged}");
    assert_eq!(flagged["flagged"], true);
    let flags = imap.flags("INBOX", letter as u32).unwrap();
    assert!(flags.iter().any(|flag| flag == "\\Seen"), "{flags:?}");
    assert!(flags.iter().any(|flag| flag == "\\Flagged"), "{flags:?}");
    let unflagged = mcp
        .ok(
            "mail_set_flags",
            json!({"folder": "INBOX", "uid": letter, "flagged": false}),
        )
        .await;
    assert_eq!(unflagged["flagged"], false);
    assert_eq!(unflagged["seen"], true);
    let unread = mcp
        .ok("mail_list_messages", json!({"read_status": "unread"}))
        .await;
    assert_eq!(unread["total"], 2, "{unread}");

    // --- Categories, retention and sender rules ---------------------------------
    let categorized = mcp
        .ok(
            "mail_categorize",
            json!({
                "folder": "INBOX", "uid": notes, "uid_validity": "1234",
                "category": "updates", "expiration_days": 30
            }),
        )
        .await;
    assert_eq!(categorized["category"], "updates", "{categorized}");
    assert_eq!(categorized["category_source"], "manual");
    assert_eq!(categorized["expiration_days"], 30);
    assert_eq!(categorized["uid"], notes);
    let updates = mcp
        .ok("mail_list_messages", json!({"category": "updates"}))
        .await;
    assert!(subjects(&updates).contains(&"Notes for the meeting".to_string()));

    let reset = mcp
        .ok(
            "mail_categorize",
            json!({
                "folder": "INBOX", "uid": notes, "uid_validity": 1234,
                "expiration_days": null
            }),
        )
        .await;
    assert_eq!(reset["category"], "updates", "{reset}");
    assert_ne!(reset["expiration_source"], "manual", "{reset}");

    let conflict = mcp
        .error(
            "mail_categorize",
            json!({
                "folder": "INBOX", "uid": notes, "uid_validity": "999",
                "category": "marketing"
            }),
        )
        .await;
    assert_eq!(conflict["status"], 409, "{conflict}");

    let no_change = mcp
        .error(
            "mail_categorize",
            json!({"folder": "INBOX", "uid": notes, "uid_validity": "1234"}),
        )
        .await;
    assert_eq!(no_change["code"], "invalid_arguments");

    let wrong_category = mcp
        .error(
            "mail_sender_rule_create",
            json!({"folder": "INBOX", "uid": notes, "uid_validity": "1234", "category": "marketing"}),
        )
        .await;
    assert_eq!(wrong_category["status"], 409, "{wrong_category}");

    let rule = mcp
        .ok(
            "mail_sender_rule_create",
            json!({"folder": "INBOX", "uid": notes, "uid_validity": "1234", "category": "updates"}),
        )
        .await;
    assert_eq!(rule["rule"]["sender"], "friend@example.org", "{rule}");
    assert_eq!(rule["rule"]["category"], "updates");
    let rules = mcp.ok("mail_sender_rule_list", json!({})).await;
    assert_eq!(rules["rules"].as_array().unwrap().len(), 1, "{rules}");
    let revision = rules["rules"][0]["revision"].as_u64().unwrap();
    let folder_rules = mcp
        .ok("mail_sender_rule_list", json!({"folder": "Sent"}))
        .await;
    assert_eq!(folder_rules, json!({"rules": []}));
    let deleted = mcp
        .ok(
            "mail_sender_rule_delete",
            json!({"folder": "INBOX", "sender": "friend@example.org", "expected_revision": revision}),
        )
        .await;
    assert_eq!(deleted, json!({"deleted": true}));
    let again = mcp
        .ok(
            "mail_sender_rule_delete",
            json!({"folder": "INBOX", "sender": "friend@example.org"}),
        )
        .await;
    assert_eq!(again, json!({"deleted": false}));
    assert_eq!(
        mcp.ok("mail_sender_rule_list", json!({})).await,
        json!({"rules": []})
    );

    // Local AI: the configured model does not exist -> a clear tool error.
    let classified = mcp
        .error(
            "mail_classify_with_local_ai",
            json!({"folder": "INBOX", "uid": notes, "uid_validity": "1234"}),
        )
        .await;
    assert_eq!(classified["status"], 502, "{classified}");

    // --- Sending ----------------------------------------------------------------
    let sent = mcp
        .ok(
            "mail_send",
            json!({
                "to": ["Friend <friend@example.org>"],
                "subject": "Plain hello from the assistant",
                "text": "Hello there."
            }),
        )
        .await;
    assert_eq!(sent["sent"], true, "{sent}");
    assert_eq!(sent["sent_saved"], true, "{sent}");
    assert_eq!(sent["sent_folder"], "Sent");
    let attachment_name = "quarterly report é.txt";
    let sent_files = mcp
        .ok(
            "mail_send",
            json!({
                "to": ["friend@example.org"],
                "cc": ["colleague@example.net"],
                "subject": "Report with attachment",
                "text": "See the attached report.",
                "html": "<p>See the attached <b>report</b>.</p>",
                "attachments": [{
                    "filename": attachment_name,
                    "content_type": "text/plain",
                    "content_base64": STANDARD.encode(ATTACHMENT_TEXT)
                }]
            }),
        )
        .await;
    assert_eq!(sent_files["sent"], true, "{sent_files}");
    let delivered = smtp.messages();
    assert_eq!(delivered.len(), 2, "{delivered:?}");
    assert_eq!(delivered[0].mail_from, USER);
    assert_eq!(delivered[0].rcpt_to, ["friend@example.org"]);
    assert_eq!(delivered[0].authenticated_user.as_deref(), Some(USER));
    let first = String::from_utf8_lossy(&delivered[0].data);
    assert!(
        first.contains("Subject: Plain hello from the assistant"),
        "{first}"
    );
    assert!(first.contains("Hello there."), "{first}");
    assert_eq!(
        delivered[1].rcpt_to,
        ["friend@example.org", "colleague@example.net"]
    );
    let second = String::from_utf8_lossy(&delivered[1].data);
    assert!(
        second.contains("Subject: Report with attachment"),
        "{second}"
    );
    assert!(
        second.contains(&STANDARD.encode(ATTACHMENT_TEXT)),
        "{second}"
    );
    assert!(second.contains("quarterly"), "{second}");
    assert_eq!(imap.uids("Sent").len(), 2, "Sent copies");

    let bad_name = mcp
        .error(
            "mail_send",
            json!({
                "to": ["friend@example.org"], "subject": "x", "text": "x",
                "attachments": [{"filename": "a\r\nb.txt", "content_base64": "aGk="}]
            }),
        )
        .await;
    assert_eq!(bad_name["code"], "invalid_arguments");
    let bad_recipient = mcp
        .error(
            "mail_send",
            json!({"to": ["not an address"], "subject": "x", "text": "x"}),
        )
        .await;
    assert_eq!(bad_recipient["status"], 422, "{bad_recipient}");
    assert_eq!(smtp.messages().len(), 2);

    // --- Trash ------------------------------------------------------------------
    let moved = mcp
        .ok(
            "mail_move_to_trash",
            json!({"folder": "INBOX", "uids": [code], "uid_validity": "1234"}),
        )
        .await;
    assert_eq!(moved["deleted"], json!([code]), "{moved}");
    assert_eq!(moved["trash_folder"], "Trash");
    assert!(!imap.uids("INBOX").contains(&(code as u32)));
    assert_eq!(imap.uids("Trash").len(), 1);

    let stale = mcp
        .error(
            "mail_move_to_trash",
            json!({"folder": "INBOX", "uids": [letter], "uid_validity": "77"}),
        )
        .await;
    assert!(
        stale["status"].as_u64().is_some_and(|status| status >= 400),
        "{stale}"
    );
    assert!(imap.uids("INBOX").contains(&(letter as u32)));

    let from_trash = mcp
        .error(
            "mail_move_to_trash",
            json!({"folder": "Trash", "uids": [1]}),
        )
        .await;
    assert_eq!(from_trash["code"], "invalid_arguments");

    let unconfirmed = mcp.error("mail_empty_trash", json!({})).await;
    assert_eq!(unconfirmed["code"], "invalid_arguments");
    let mismatch = mcp
        .error(
            "mail_empty_trash",
            json!({"confirm": true, "expected_count": 5}),
        )
        .await;
    assert!(mismatch["error"]
        .as_str()
        .unwrap()
        .contains("not the expected 5"));
    assert_eq!(imap.uids("Trash").len(), 1);

    let emptied = mcp
        .ok(
            "mail_empty_trash",
            json!({"confirm": true, "expected_count": 1}),
        )
        .await;
    assert_eq!(emptied["trash_folder"], "Trash", "{emptied}");
    assert_eq!(emptied["deleted"], 1, "{emptied}");
    assert_eq!(emptied["remaining"], 0);
    assert!(imap.uids("Trash").is_empty());
    let empty_again = mcp.ok("mail_empty_trash", json!({"confirm": true})).await;
    assert_eq!(empty_again["deleted"], 0, "{empty_again}");

    // --- Locking the account in the extension -----------------------------------
    let (status, locked_body) = extension_request(
        reqwest::Method::DELETE,
        format!("{base}/api/accounts/{USER}"),
        None,
    )
    .await;
    assert_eq!(status, 200, "{locked_body}");
    let locked = mcp
        .error("mail_read_message", json!({"account": USER, "uid": notes}))
        .await;
    assert_eq!(locked["code"], "password_required", "{locked}");
    assert!(locked["error"]
        .as_str()
        .unwrap()
        .contains("unlock it in the Thunderbird extension"));
    let locked_send = mcp
        .error(
            "mail_send",
            json!({"account": USER, "to": ["friend@example.org"], "subject": "x", "text": "x"}),
        )
        .await;
    assert_eq!(locked_send["code"], "password_required", "{locked_send}");
    assert_eq!(smtp.messages().len(), 2);
    let implicit = mcp.error("mail_list_messages", json!({})).await;
    assert!(implicit["error"]
        .as_str()
        .unwrap()
        .contains("No mail account is unlocked"));

    // --- Backend gone -----------------------------------------------------------
    backend.kill();
    let unreachable = mcp.error("mail_list_accounts", json!({})).await;
    assert_eq!(unreachable["code"], "backend_unreachable", "{unreachable}");

    // --- Clean shutdown, nothing persisted, no secrets in any log ----------------
    drop(mcp.stdin.take());
    let status = tokio::time::timeout(Duration::from_secs(15), mcp.child.wait())
        .await
        .expect("mail-mcp did not exit after stdin closed")
        .unwrap();
    assert!(status.success(), "{status:?}");
    tokio::time::sleep(Duration::from_millis(200)).await;
    let mcp_log = mcp.stderr();
    assert!(!mcp_log.contains(PASSWORD), "MCP log leaked the password");
    assert!(
        !backend.output().contains(PASSWORD),
        "backend log leaked the password"
    );
    assert!(
        dir_is_empty(&mcp_cwd),
        "mail-mcp wrote into its working directory"
    );
    assert!(
        dir_is_empty(&mcp_home),
        "mail-mcp wrote into its home/config dirs"
    );
}

/// MCP handshake shared by the tests.
async fn handshake(mcp: &mut Mcp) {
    let initialized = mcp
        .request(
            "initialize",
            json!({
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "mail-mcp-e2e", "version": "0.0.1"}
            }),
        )
        .await;
    assert_eq!(
        initialized["result"]["serverInfo"]["name"], "mail-mcp",
        "{initialized}"
    );
    mcp.send(json!({"jsonrpc": "2.0", "method": "notifications/initialized"}))
        .await;
}

/// POP3 compatibility mode through MCP: INBOX list/read work, mailbox
/// mutations are refused with clear tool errors, and with two unlocked
/// accounts the `account` argument becomes mandatory.
#[tokio::test(flavor = "multi_thread")]
async fn pop3_compatibility_and_account_selection_through_mcp() {
    const POP_USER: &str = "pop@example.com";
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().to_path_buf();
    let pop = FakePop3Server::builder()
        .credentials(POP_USER, PASSWORD)
        .message(newsletter())
        .message(verification_code())
        .start();
    let imap = FakeImapServer::builder()
        .credentials(USER, PASSWORD)
        .folder("Trash", &["\\Trash"])
        .message("INBOX", notes_with_attachment())
        .start();

    let backend = Backend::start(&root);
    let base = backend.url.clone();
    for (email, port, protocol) in [(POP_USER, pop.port(), "pop3"), (USER, imap.port(), "imap")] {
        let (status, unlocked) = extension_request(
            reqwest::Method::POST,
            format!("{base}/api/accounts/unlock"),
            Some(json!({
                "email": email, "password": PASSWORD,
                "incoming_server": "127.0.0.1", "incoming_port": port,
                "incoming_protocol": "NONE", "incoming_mail_protocol": protocol,
                "outgoing_server": "127.0.0.1", "outgoing_port": 2525,
                "outgoing_protocol": "NONE", "save_profile": false,
            })),
        )
        .await;
        assert_eq!(status, 200, "{unlocked}");
    }

    let home = root.join("mcp-home");
    std::fs::create_dir_all(&home).unwrap();
    let mut mcp = Mcp::spawn(&base, &home, &home);
    handshake(&mut mcp).await;

    let accounts = mcp.ok("mail_list_accounts", json!({})).await;
    let emails: Vec<&str> = accounts["accounts"]
        .as_array()
        .unwrap()
        .iter()
        .map(|account| account["email"].as_str().unwrap())
        .collect();
    assert_eq!(emails, [POP_USER, USER], "{accounts}");
    let ambiguous = mcp.error("mail_list_folders", json!({})).await;
    assert_eq!(ambiguous["code"], "invalid_arguments");
    assert!(ambiguous["error"]
        .as_str()
        .unwrap()
        .contains("Several accounts are unlocked"));

    let folders = mcp
        .ok("mail_list_folders", json!({"account": POP_USER}))
        .await;
    let names: Vec<&str> = folders["folders"]
        .as_array()
        .unwrap()
        .iter()
        .map(|folder| folder["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["INBOX"], "{folders}");

    let listing = mcp
        .ok("mail_list_messages", json!({"account": POP_USER}))
        .await;
    assert_eq!(listing["total"], 2, "{listing}");
    let code = uid_of(&listing, "Your verification code");
    let message = mcp
        .ok(
            "mail_read_message",
            json!({"account": POP_USER, "uid": code}),
        )
        .await;
    assert!(message["text_body"]
        .as_str()
        .unwrap()
        .contains("Your code is 123456."));

    let flags = mcp
        .error(
            "mail_set_flags",
            json!({"account": POP_USER, "folder": "INBOX", "uid": code, "seen": true}),
        )
        .await;
    assert_eq!(flags["status"], 400, "{flags}");
    assert!(flags["error"]
        .as_str()
        .unwrap()
        .contains("requires an IMAP account"));
    let trash = mcp
        .error(
            "mail_move_to_trash",
            json!({"account": POP_USER, "folder": "INBOX", "uids": [code]}),
        )
        .await;
    assert_eq!(trash["code"], "invalid_arguments", "{trash}");
    let empty = mcp
        .error(
            "mail_empty_trash",
            json!({"account": POP_USER, "confirm": true}),
        )
        .await;
    assert_eq!(empty["code"], "invalid_arguments", "{empty}");
    assert_eq!(pop.messages().len(), 2, "POP3 maildrop untouched");

    // The IMAP account is still reachable by name.
    let imap_listing = mcp.ok("mail_list_messages", json!({"account": USER})).await;
    assert_eq!(subjects(&imap_listing), ["Notes for the meeting"]);
    assert!(!mcp.stderr().contains(PASSWORD));
}
