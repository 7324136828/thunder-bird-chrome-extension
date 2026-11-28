//! End-to-end against the real `mail-backend` executable over real TCP:
//! start-up with isolated settings/profile/data paths, `/api/health`,
//! Host / Origin / Sec-Fetch-Site refusals, CORS preflight from an extension
//! origin, and "killing or restarting the process locks every account".
//!
//! Cargo builds the binary for integration tests
//! (`CARGO_BIN_EXE_mail-backend`); every instance listens on `--port 0`
//! (an ephemeral loopback port) with all state under a temporary directory,
//! so the user's real settings are never touched.

mod e2e_support;

use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use e2e_support::{ORIGIN, PASSWORD, USER};
use mail_proto::testkit::FakeImapServer;
use reqwest::blocking::{Client, Response};
use reqwest::StatusCode;
use serde_json::{json, Value};

/// A running backend process (killed on drop).
struct Backend {
    child: Child,
    url: String,
    port: u16,
    output: Arc<Mutex<String>>,
}

impl Backend {
    fn start(root: &Path, args: &[&str]) -> Backend {
        Self::try_start(root, args)
            .unwrap_or_else(|output| panic!("backend did not start:\n{output}"))
    }

    /// Start the binary; `Err(output)` when it exits before listening.
    fn try_start(root: &Path, args: &[&str]) -> Result<Backend, String> {
        Self::try_start_with_env(root, args, &[])
    }

    /// [`Backend::try_start`] with extra environment variables.
    fn try_start_with_env(
        root: &Path,
        args: &[&str],
        envs: &[(&str, &str)],
    ) -> Result<Backend, String> {
        let appdata = root.join("appdata");
        std::fs::create_dir_all(&appdata).unwrap();
        let mut command = Command::new(env!("CARGO_BIN_EXE_mail-backend"));
        command
            .args(args)
            .env("WEBMAIL_SETTINGS_PATH", root.join("settings.json"))
            .env("MAIL_SERVERS_PATH", root.join("mail-servers.json"))
            .env("DATA_DIRECTORY", root.join("data"))
            .env("APPDATA", &appdata)
            .env("LOCALAPPDATA", &appdata)
            .env("XDG_CONFIG_HOME", &appdata)
            .env("XDG_DATA_HOME", &appdata)
            .env("HOME", &appdata)
            .env("RUST_LOG", "info")
            .env_remove("MAIL_BACKEND_ADDR")
            .env_remove("MAIL_BACKEND_EXTENSION_IDS")
            .env_remove("PUBLIC_BACKEND_URL")
            .env_remove("BACKEND_PORT")
            .env_remove("HTTP_PROXY")
            .env_remove("HTTPS_PROXY")
            .envs(envs.iter().copied())
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = command.spawn().expect("spawn mail-backend");
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
                        let port = url.rsplit(':').next().unwrap().parse().unwrap();
                        return Ok(Backend {
                            child,
                            url,
                            port,
                            output,
                        });
                    }
                }
                Err(_) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(output.lock().unwrap().clone());
                }
            }
        }
    }

    fn get(&self, path: &str) -> reqwest::blocking::RequestBuilder {
        client().get(format!("{}{path}", self.url))
    }

    fn post_json(&self, path: &str, body: &Value) -> Response {
        client()
            .post(format!("{}{path}", self.url))
            .header("origin", ORIGIN)
            .json(body)
            .send()
            .expect("request")
    }

    /// Hard kill (Windows `TerminateProcess` / SIGKILL): no graceful path.
    fn kill(mut self) -> String {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let output = self.output.lock().unwrap().clone();
        output
    }
}

impl Drop for Backend {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn client() -> Client {
    Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(30))
        .build()
        .unwrap()
}

fn json_of(response: Response) -> (StatusCode, reqwest::header::HeaderMap, Value) {
    let status = response.status();
    let headers = response.headers().clone();
    let text = response.text().unwrap();
    let value = serde_json::from_str(&text)
        .unwrap_or_else(|error| panic!("not JSON ({error}), status {status}: {text}"));
    (status, headers, value)
}

fn header<'a>(headers: &'a reqwest::header::HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|value| value.to_str().ok())
}

fn tempdir() -> (tempfile::TempDir, PathBuf) {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().to_path_buf();
    (temporary, root)
}

#[test]
fn health_guard_and_cors_over_real_tcp() {
    let (_temporary, root) = tempdir();
    let backend = Backend::start(&root, &["--port", "0"]);

    // Health without Origin (curl / MCP) and from the extension.
    let (status, _, body) = json_of(backend.get("/api/health").send().unwrap());
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, json!({"status": "ok"}));
    let (status, headers, _) = json_of(
        backend
            .get("/api/health")
            .header("origin", ORIGIN)
            .send()
            .unwrap(),
    );
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        header(&headers, "access-control-allow-origin"),
        Some(ORIGIN)
    );

    // `localhost` and `[::1]`-style Host headers are loopback too.
    let (status, _, _) = json_of(
        backend
            .get("/api/health")
            .header("host", format!("localhost:{}", backend.port))
            .send()
            .unwrap(),
    );
    assert_eq!(status, StatusCode::OK);

    // DNS rebinding: a foreign Host is refused.
    let (status, headers, body) = json_of(
        backend
            .get("/api/health")
            .header("host", format!("evil.example:{}", backend.port))
            .send()
            .unwrap(),
    );
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(body["detail"]
        .as_str()
        .unwrap()
        .starts_with("Forbidden: requests must be addressed to 127.0.0.1 or localhost"));
    assert!(header(&headers, "access-control-allow-origin").is_none());

    // Web-page origins are refused, also for simple GETs.
    for origin in [
        "https://evil.example",
        "http://127.0.0.1:3741",
        "null",
        "chrome-extension://",
    ] {
        let (status, headers, body) = json_of(
            backend
                .get("/api/accounts")
                .header("origin", origin)
                .send()
                .unwrap(),
        );
        assert_eq!(status, StatusCode::FORBIDDEN, "{origin}");
        assert!(body["detail"].as_str().unwrap().starts_with("Forbidden"));
        assert!(header(&headers, "access-control-allow-origin").is_none());
    }
    // No Origin, but issued by another site (<img>/<script> probe).
    for site in ["cross-site", "same-site"] {
        let (status, _, _) = json_of(
            backend
                .get("/api/accounts")
                .header("sec-fetch-site", site)
                .send()
                .unwrap(),
        );
        assert_eq!(status, StatusCode::FORBIDDEN, "{site}");
    }
    let (status, _, _) = json_of(
        backend
            .get("/api/accounts")
            .header("sec-fetch-site", "none")
            .send()
            .unwrap(),
    );
    assert_eq!(status, StatusCode::OK);

    // CORS preflight from the extension (Chrome adds the Private Network
    // Access header when an extension page calls 127.0.0.1).
    let response = client()
        .request(
            reqwest::Method::OPTIONS,
            format!("{}/api/accounts/unlock", backend.url),
        )
        .header("origin", ORIGIN)
        .header("access-control-request-method", "POST")
        .header("access-control-request-headers", "content-type")
        .header("access-control-request-private-network", "true")
        .send()
        .unwrap();
    assert!(response.status().is_success(), "{}", response.status());
    let headers = response.headers();
    assert_eq!(header(headers, "access-control-allow-origin"), Some(ORIGIN));
    let methods = header(headers, "access-control-allow-methods")
        .unwrap()
        .to_uppercase();
    for method in ["GET", "POST", "PUT", "DELETE"] {
        assert!(methods.contains(method), "{methods}");
    }
    assert!(header(headers, "access-control-allow-headers")
        .unwrap()
        .to_lowercase()
        .contains("content-type"));
    assert_eq!(
        header(headers, "access-control-allow-private-network"),
        Some("true")
    );
    // Preflight from a web page: refused before any CORS headers.
    let response = client()
        .request(
            reqwest::Method::OPTIONS,
            format!("{}/api/accounts/unlock", backend.url),
        )
        .header("origin", "https://evil.example")
        .header("access-control-request-method", "POST")
        .send()
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert!(header(response.headers(), "access-control-allow-origin").is_none());

    // JSON 404 for unknown routes.
    let (status, _, body) = json_of(backend.get("/api/nope").send().unwrap());
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body, json!({"detail": "Not Found"}));

    // The isolated paths were used.
    assert!(root.join("mail-servers.json").is_file());
    let output = backend.kill();
    assert!(
        output.contains(&root.join("mail-servers.json").display().to_string()),
        "{output}"
    );
}

#[test]
fn killing_or_restarting_the_process_locks_every_account() {
    let imap = FakeImapServer::builder()
        .credentials(USER, PASSWORD)
        .message(
            "INBOX",
            b"Subject: hi\r\nFrom: a@example.org\r\n\r\nbody\r\n".to_vec(),
        )
        .start();
    let (_temporary, root) = tempdir();
    let backend = Backend::start(&root, &["--port", "0"]);

    let unlock = json!({
        "email": USER, "password": PASSWORD, "incoming_server": "127.0.0.1",
        "incoming_port": imap.port(), "incoming_protocol": "NONE",
        "outgoing_server": "127.0.0.1", "outgoing_port": 2525, "outgoing_protocol": "NONE",
        "display_name": "Example User", "save_profile": true,
    });
    let mut wrong = unlock.clone();
    wrong["password"] = json!("Wrong-Password-4411");
    let (status, _, body) = json_of(backend.post_json("/api/accounts/unlock", &wrong));
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert!(!body.to_string().contains("Wrong-Password-4411"));
    let (status, _, body) = json_of(backend.post_json("/api/accounts/unlock", &unlock));
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(!body.to_string().contains(PASSWORD));
    let (status, _, accounts) = json_of(backend.get("/api/accounts").send().unwrap());
    assert_eq!(status, StatusCode::OK);
    assert_eq!(accounts["accounts"].as_array().unwrap().len(), 1);
    let (status, _, folders) = json_of(
        backend
            .get(&format!("/api/mail/folders?account={USER}"))
            .header("origin", ORIGIN)
            .send()
            .unwrap(),
    );
    assert_eq!(status, StatusCode::OK, "{folders}");

    let output = backend.kill();
    assert!(!output.contains(PASSWORD), "password in the log output");
    assert!(
        !output.contains("Wrong-Password-4411"),
        "password in the log output"
    );
    // Request logs carry the path only: account addresses in query strings
    // are not logged.
    assert!(output.contains("GET /api/mail/folders 200"), "{output}");
    assert!(!output.contains("account="), "{output}");
    for file in e2e_support::walk(&root) {
        let bytes = std::fs::read(&file).unwrap_or_default();
        assert!(
            !e2e_support::contains(&bytes, PASSWORD.as_bytes()),
            "password persisted in {}",
            file.display()
        );
    }

    // A restart starts with an empty session store; profiles and display
    // names (non-secret) survive.
    let backend = Backend::start(&root, &["--port", "0"]);
    let (_, _, accounts) = json_of(backend.get("/api/accounts").send().unwrap());
    assert_eq!(accounts, json!({"accounts": []}));
    let (status, _, body) = json_of(
        backend
            .get(&format!("/api/mail/messages?account={USER}&folder=INBOX"))
            .header("origin", ORIGIN)
            .send()
            .unwrap(),
    );
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        body,
        json!({"detail": {"error": "password_required", "email": USER}})
    );
    let (_, _, servers) = json_of(backend.get("/api/mail/servers").send().unwrap());
    assert_eq!(
        servers["servers"]["user-example.com"]["incoming_port"],
        imap.port()
    );
    assert_eq!(servers["display_names"][USER], "Example User", "{servers}");

    // Unlocking again works against the saved profile.
    let (status, _, body) = json_of(backend.post_json(
        "/api/accounts/unlock",
        &json!({"email": USER, "password": PASSWORD, "profile_key": "user-example.com"}),
    ));
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["account"]["display_name"], "Example User");
    backend.kill();
}

#[test]
fn second_instance_on_a_busy_port_fails_with_a_helpful_message() {
    let (_temporary, root) = tempdir();
    let backend = Backend::start(&root, &["--port", "0"]);
    let port = backend.port.to_string();
    let error = match Backend::try_start(&root, &["--port", &port]) {
        Ok(_) => panic!("second instance started on a busy port"),
        Err(output) => output,
    };
    assert!(error.contains("already in use"), "{error}");
    backend.kill();
}

#[test]
fn non_loopback_listen_addresses_are_refused() {
    let output = Command::new(env!("CARGO_BIN_EXE_mail-backend"))
        .args(["--addr", "0.0.0.0:0"])
        .env("WEBMAIL_SETTINGS_PATH", "unused-settings.json")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("non-loopback"), "{stderr}");
}

/// `--addr 127.0.0.2:PORT` is accepted by the CLI (it is loopback) and the
/// Host guard accepts every `127.0.0.0/8` literal, so requests a browser
/// sends to `http://127.0.0.2:PORT` (Host `127.0.0.2:PORT`) are served.
#[test]
fn listening_on_another_loopback_address_serves_requests() {
    let (_temporary, root) = tempdir();
    let backend = match Backend::try_start(&root, &["--addr", "127.0.0.2:0"]) {
        Ok(backend) => backend,
        // Some systems only route 127.0.0.1.
        Err(output) if output.contains("not available") => return,
        Err(output) => panic!("{output}"),
    };
    let response = backend.get("/api/health").send().unwrap();
    assert_eq!(response.status(), StatusCode::OK, "{:?}", response.text());
    backend.kill();
}

/// `MAIL_BACKEND_EXTENSION_IDS` replaces the built-in allow-list: a listed
/// Firefox per-install UUID is served with a CORS grant, the default id is
/// then refused, and the start-up log names the allowed ids.
#[test]
fn extension_id_allow_list_comes_from_the_environment() {
    let (_temporary, root) = tempdir();
    let firefox = "moz-extension://1b2c3d4e-0000-4000-8000-123456789abc";
    let backend = Backend::try_start_with_env(
        &root,
        &["--port", "0"],
        &[(
            "MAIL_BACKEND_EXTENSION_IDS",
            "1B2C3D4E-0000-4000-8000-123456789ABC, other-id",
        )],
    )
    .unwrap_or_else(|output| {
        panic!(
            "backend did not start:
{output}"
        )
    });
    let response = backend
        .get("/api/health")
        .header("origin", firefox)
        .send()
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get("access-control-allow-origin")
            .and_then(|value| value.to_str().ok()),
        Some(firefox)
    );
    let response = backend
        .get("/api/health")
        .header("origin", ORIGIN)
        .send()
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let output = backend.kill();
    assert!(
        output.contains("Allowed extension ids: 1b2c3d4e-0000-4000-8000-123456789abc, other-id"),
        "{output}"
    );

    // Default: only the pinned id, which the log names.
    let backend = Backend::start(&root, &["--port", "0"]);
    let response = backend
        .get("/api/health")
        .header("origin", firefox)
        .send()
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let output = backend.kill();
    assert!(
        output.contains("Allowed extension ids: hhhanbkdjaecdfoclhpoicmfhejdbkjl"),
        "{output}"
    );
}
