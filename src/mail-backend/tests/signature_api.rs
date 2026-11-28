//! Signature routes: port of `SignatureApiTests` (tests/test_signatures.py).
//!
//! Deviations from the Python tests (no `unittest.mock.patch` in Rust):
//! * size limits are exercised with real-size bodies instead of patching
//!   `MAX_SIGNATURE_HTML_BYTES` / `MAX_SEND_FILE_BYTES` /
//!   `MAX_SEND_FILES_BYTES` / `MAX_SIGNATURE_REQUEST_BYTES`;
//! * a failed settings publish is produced by holding `settings.json` open
//!   without delete sharing (Windows) / a read-only settings folder (Unix)
//!   instead of patching `settings._write_json`;
//! * a failed asset write is produced by a file squatting on the account's
//!   image folder instead of patching `Path.write_bytes`;
//! * the "settings endpoint preserves signatures" test saves preferences
//!   through `mail_core::settings::save_mail_preferences` (what
//!   `PUT /api/settings` calls).
//!
//! `tests/test_signature_proxy.py` covers the packaged frontend's reverse
//! proxy, which the extension build does not have; its size-limit half is
//! covered by `limits_reject_before_disk_changes` here.

mod common;
mod mail_support;

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use common::{call_router, Resp};
use mail_core::MailAccount;
use mail_support::{offline_account, with_query, Harness};
use serde_json::{json, Value};

const BOUNDARY: &str = "signature-boundary-5d1a7c";
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

/// `test_remote_images.PNG`: a valid 1x1 PNG.
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

/// One multipart part: `(name, filename, content type, data)`.
type Part = (&'static str, Option<String>, Option<String>, Vec<u8>);

fn metadata_part(body: &Value) -> Part {
    (
        "signature",
        None,
        Some("application/json".into()),
        body.to_string().into_bytes(),
    )
}

fn file_part(filename: &str, data: Vec<u8>, content_type: &str) -> Part {
    (
        "files",
        Some(filename.into()),
        Some(content_type.into()),
        data,
    )
}

fn multipart(parts: &[Part]) -> Vec<u8> {
    let mut body = Vec::new();
    for (name, filename, content_type, data) in parts {
        body.extend(format!("--{BOUNDARY}\r\n").into_bytes());
        let mut disposition = format!("Content-Disposition: form-data; name=\"{name}\"");
        if let Some(filename) = filename {
            disposition.push_str(&format!("; filename=\"{filename}\""));
        }
        body.extend(disposition.into_bytes());
        body.extend(b"\r\n");
        if let Some(content_type) = content_type {
            body.extend(format!("Content-Type: {content_type}\r\n").into_bytes());
        }
        body.extend(b"\r\n");
        body.extend_from_slice(data);
        body.extend(b"\r\n");
    }
    body.extend(format!("--{BOUNDARY}--\r\n").into_bytes());
    body
}

const DEFAULT_TEXT: &str = "<p><b>Thanks</b> \u{1f642}<img src=\"cid:attach1\"></p>";

fn default_images() -> Vec<(String, Vec<u8>, String)> {
    vec![("logo.png".into(), png(), "image/png".into())]
}

struct Fixture {
    harness: Harness,
    account: MailAccount,
    other: MailAccount,
}

impl Fixture {
    fn new() -> Self {
        let harness = Harness::new();
        let account = offline_account("User@Example.com");
        let other = offline_account("other@example.com");
        harness.unlock(account.clone());
        harness.unlock(other.clone());
        std::fs::write(
            harness.settings_path(),
            json!({"data_directory": "kept", "messages_per_page": 19, "unrelated": {"a": 1}})
                .to_string(),
        )
        .unwrap();
        Fixture {
            harness,
            account,
            other,
        }
    }

    fn root(&self) -> &Path {
        &self.harness.root
    }

    fn settings(&self) -> PathBuf {
        self.harness.settings_path()
    }

    fn read_settings(&self) -> Value {
        serde_json::from_slice(&std::fs::read(self.settings()).unwrap()).unwrap()
    }

    async fn put_parts(&self, account: &str, parts: &[Part]) -> Resp {
        let uri = with_query("/api/mail/signature", &[("account", account)]);
        let request = Request::builder()
            .method(Method::PUT)
            .uri(uri)
            .header("host", "127.0.0.1:48101")
            .header(
                "content-type",
                format!("multipart/form-data; boundary={BOUNDARY}"),
            )
            .body(Body::from(multipart(parts)))
            .unwrap();
        call_router(self.harness.app.clone(), request).await
    }

    /// Python `save(text, images, account=..., body=...)`.
    async fn save_with(
        &self,
        text: &str,
        images: Vec<(String, Vec<u8>, String)>,
        account: Option<&str>,
        body: Option<Value>,
    ) -> Resp {
        let body = body.unwrap_or_else(|| {
            let uploads: Vec<Value> = (0..images.len())
                .map(|index| json!({"content_id": format!("attach{}", index + 1)}))
                .collect();
            json!({"text": text, "uploads": uploads})
        });
        let mut parts = vec![metadata_part(&body)];
        for (filename, data, content_type) in images {
            parts.push(file_part(&filename, data, &content_type));
        }
        self.put_parts(account.unwrap_or(&self.account.email), &parts)
            .await
    }

    async fn save(&self) -> Resp {
        self.save_with(DEFAULT_TEXT, default_images(), None, None)
            .await
    }

    async fn save_text(&self, text: &str) -> Resp {
        self.save_with(text, Vec::new(), None, None).await
    }

    async fn get(&self, account: Option<&str>) -> Resp {
        self.harness
            .get(
                "/api/mail/signature",
                &[("account", account.unwrap_or(&self.account.email))],
            )
            .await
    }

    async fn get_url(&self, url: &str) -> Resp {
        let request = Request::get(url)
            .header("host", "127.0.0.1:48101")
            .body(Body::empty())
            .unwrap();
        call_router(self.harness.app.clone(), request).await
    }

    async fn image(&self, account: &str, content_id: &str, revision: &str) -> Resp {
        self.harness
            .get(
                "/api/mail/signature/image",
                &[
                    ("account", account),
                    ("content_id", content_id),
                    ("revision", revision),
                ],
            )
            .await
    }

    fn image_tree(&self) -> BTreeSet<PathBuf> {
        let mut found = BTreeSet::new();
        let mut pending = vec![self.root().join("signature-images")];
        while let Some(directory) = pending.pop() {
            let Ok(entries) = std::fs::read_dir(&directory) else {
                continue;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    pending.push(path.clone());
                }
                found.insert(path);
            }
        }
        found
    }

    fn images_exist(&self) -> bool {
        self.root().join("signature-images").exists()
    }
}

fn ok_json(response: &Resp) -> Value {
    assert_eq!(response.status, StatusCode::OK, "{}", response.text());
    response.json()
}

fn revision_of(relative: &str) -> String {
    Path::new(relative)
        .parent()
        .and_then(Path::file_name)
        .unwrap()
        .to_string_lossy()
        .into_owned()
}

#[tokio::test]
async fn saves_exact_requested_json_and_confined_image_bytes_preserving_settings() {
    let f = Fixture::new();
    let result = ok_json(&f.save().await);
    assert_eq!(result["account"], "user@example.com");
    let stored = f.read_settings();
    assert_eq!(stored["unrelated"], json!({"a": 1}));
    assert_eq!(stored["messages_per_page"], 19);
    assert_eq!(stored["data_directory"], "kept");
    assert_eq!(
        stored["emails_signatures"],
        json!({"user@example.com": {"text": result["text"], "multipart-path": result["multipart-path"]}})
    );
    assert_eq!(
        result["text"],
        "<p><b>Thanks</b> \u{1f642}<img src=\"cid:attach1\"></p>"
    );
    let relative = result["multipart-path"]["attach1"].as_str().unwrap();
    let pattern = regex_like(relative);
    assert!(pattern, "{relative}");
    assert_eq!(std::fs::read(f.root().join(relative)).unwrap(), png());
    let image = result["images"][0].as_object().unwrap();
    let keys: BTreeSet<&str> = image.keys().map(String::as_str).collect();
    assert_eq!(
        keys,
        BTreeSet::from(["content_id", "filename", "content_type", "url"])
    );
    assert_eq!(image["content_type"], "image/png");
    assert_eq!(image["filename"], "attach1.png");
    assert_eq!(
        image["url"],
        format!(
            "/api/mail/signature/image?account=user%40example.com&content_id=attach1&revision={}",
            revision_of(relative)
        )
    );
    assert_eq!(ok_json(&f.get(None).await), result);
}

/// `^signature-images/[0-9a-f]{64}/[0-9a-f]{32}/attach1\.png$`
fn regex_like(relative: &str) -> bool {
    let parts: Vec<&str> = relative.split('/').collect();
    let hex = |s: &str, n: usize| {
        s.len() == n
            && s.bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    };
    parts.len() == 4
        && parts[0] == "signature-images"
        && hex(parts[1], 64)
        && hex(parts[2], 32)
        && parts[3] == "attach1.png"
}

#[tokio::test]
async fn restart_requires_unlock_and_restores_saved_account_configuration() {
    let f = Fixture::new();
    let saved = ok_json(&f.save().await);
    let restarted = f.harness.restarted();
    let response = restarted
        .get("/api/mail/signature", &[("account", &f.account.email)])
        .await;
    assert_eq!(response.status, StatusCode::UNAUTHORIZED);
    restarted.unlock(f.account.clone());
    let response = restarted
        .get("/api/mail/signature", &[("account", "USER@example.com")])
        .await;
    assert_eq!(ok_json(&response), saved);
    let url = saved["images"][0]["url"].as_str().unwrap();
    let request = Request::get(url)
        .header("host", "127.0.0.1:48101")
        .body(Body::empty())
        .unwrap();
    let image = call_router(restarted.app.clone(), request).await;
    assert_eq!(image.body, png());
}

#[tokio::test]
async fn signature_and_image_endpoints_require_unlocked_account() {
    let f = Fixture::new();
    let saved = ok_json(&f.save().await);
    f.harness.state.sessions.forget(&f.account.email);
    let before = std::fs::read(f.settings()).unwrap();
    let detail = f
        .get(None)
        .await
        .assert_json_error(StatusCode::UNAUTHORIZED);
    assert_eq!(
        detail,
        json!({"error": "password_required", "email": "user@example.com"})
    );
    assert_eq!(f.save().await.status, StatusCode::UNAUTHORIZED);
    let url = saved["images"][0]["url"].as_str().unwrap();
    assert_eq!(f.get_url(url).await.status, StatusCode::UNAUTHORIZED);
    assert_eq!(std::fs::read(f.settings()).unwrap(), before);
}

#[tokio::test]
async fn accounts_have_independent_signatures_and_cannot_read_each_others_assets() {
    let f = Fixture::new();
    let first = ok_json(&f.save().await);
    let second = ok_json(
        &f.save_with(
            "<div>Other \u{1f680}<img src=\"cid:attach1\"></div>",
            default_images(),
            Some(&f.other.email),
            None,
        )
        .await,
    );
    assert_ne!(first["multipart-path"], second["multipart-path"]);
    assert_eq!(ok_json(&f.get(None).await), first);
    assert_eq!(ok_json(&f.get(Some(&f.other.email)).await), second);
    let revision = revision_of(first["multipart-path"]["attach1"].as_str().unwrap());
    let response = f.image(&f.other.email, "attach1", &revision).await;
    assert_eq!(
        response.assert_json_error(StatusCode::NOT_FOUND),
        "Signature image not found"
    );
    let accounts: BTreeSet<String> = f.read_settings()["emails_signatures"]
        .as_object()
        .unwrap()
        .keys()
        .cloned()
        .collect();
    assert_eq!(
        accounts,
        BTreeSet::from([
            "user@example.com".to_string(),
            "other@example.com".to_string()
        ])
    );
}

#[tokio::test]
async fn image_endpoint_serves_bytes_and_detected_mime_with_safe_headers() {
    let f = Fixture::new();
    let saved = ok_json(
        &f.save_with(
            DEFAULT_TEXT,
            vec![(
                "browser-upload".into(),
                png(),
                "application/octet-stream".into(),
            )],
            None,
            None,
        )
        .await,
    );
    let response = f.get_url(saved["images"][0]["url"].as_str().unwrap()).await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text());
    assert_eq!(response.body, png());
    assert_eq!(response.header("content-type"), Some("image/png"));
    assert_eq!(response.header("x-content-type-options"), Some("nosniff"));
    assert_eq!(response.header("cache-control"), Some("no-store"));
    assert_eq!(
        response.header("content-security-policy"),
        Some("default-src 'none'; sandbox")
    );
    let current = f
        .harness
        .get(
            "/api/mail/signature/image",
            &[("account", &f.account.email), ("content_id", "attach1")],
        )
        .await;
    assert_eq!(current.body, png());
}

#[tokio::test]
async fn active_markup_sources_styles_and_handlers_are_removed() {
    let f = Fixture::new();
    let markup = concat!(
        "<script>alert(1)</script><style>body{display:none}</style><iframe>Hidden</iframe>",
        "<svg><a href=\"javascript:alert(1)\">Danger</a></svg>",
        "<p style=\"color:red\" onclick=\"alert(1)\"><b>Bold</b> \u{1f680} ",
        "<a href=\"javascript:alert(1)\">Name</a><a href=\"https://example.com\">Link</a>",
        "<img src=\"https://tracking.example.com/logo.png\" onerror=\"alert(1)\">",
        "<img src=\"cid:attach1\" onerror=\"alert(1)\" width=\"200\" height=\"50\" alt=\"Logo\"></p>"
    );
    let response = f.save_with(markup, default_images(), None, None).await;
    let text = ok_json(&response)["text"].as_str().unwrap().to_string();
    assert!(text.contains("<b>Bold</b> \u{1f680}"));
    assert!(text.contains("href=\"https://example.com\""));
    assert!(text.contains("<img src=\"cid:attach1\" width=\"200\" height=\"50\" alt=\"Logo\">"));
    for forbidden in [
        "script",
        "style",
        "iframe",
        "svg",
        "javascript",
        "onclick",
        "onerror",
        "tracking.example",
        "Hidden",
        "Danger",
    ] {
        assert!(!text.contains(forbidden), "{forbidden} in {text}");
    }
    assert_eq!(
        text,
        "<p><b>Bold</b> \u{1f680} <a>Name</a><a href=\"https://example.com\" rel=\"noopener noreferrer\">Link</a><img src=\"cid:attach1\" width=\"200\" height=\"50\" alt=\"Logo\"></p>"
    );
    assert_eq!(
        f.read_settings()["emails_signatures"]["user@example.com"]["text"],
        text
    );
}

#[tokio::test]
async fn blank_markup_disables_and_is_explicitly_persisted() {
    let f = Fixture::new();
    ok_json(&f.save().await);
    let response = f.save_text("<p><br></p><div>\u{a0}</div>").await;
    assert_eq!(
        ok_json(&response),
        json!({"account": "user@example.com", "text": "", "multipart-path": {}, "images": []})
    );
    assert_eq!(
        f.read_settings()["emails_signatures"]["user@example.com"],
        json!({"text": "", "multipart-path": {}})
    );
}

#[tokio::test]
async fn retained_revision_image_urls_remain_valid_for_open_drafts() {
    let f = Fixture::new();
    let first = ok_json(&f.save().await);
    let second = ok_json(
        &f.save_with(
            "<div>New<img src=\"cid:attach1\"></div>",
            default_images(),
            None,
            None,
        )
        .await,
    );
    let first_url = first["images"][0]["url"].as_str().unwrap();
    assert_ne!(first_url, second["images"][0]["url"].as_str().unwrap());
    assert_eq!(f.get_url(first_url).await.body, png());
    ok_json(&f.save_text("").await);
    assert_eq!(f.get_url(first_url).await.body, png());
}

#[tokio::test]
async fn failed_settings_publish_preserves_prior_signature_and_removes_staged_assets() {
    let f = Fixture::new();
    let first = ok_json(&f.save().await);
    let before = std::fs::read(f.settings()).unwrap();
    let assets = f.image_tree();
    let response = {
        let _blocker = block_settings_publish(&f.settings());
        f.save_with(
            "<div>Changed<img src=\"cid:attach1\"></div>",
            default_images(),
            None,
            None,
        )
        .await
    };
    assert_eq!(
        response.assert_json_error(StatusCode::INTERNAL_SERVER_ERROR),
        "Cannot save the email signature"
    );
    assert_eq!(std::fs::read(f.settings()).unwrap(), before);
    assert_eq!(f.image_tree(), assets);
    assert_eq!(ok_json(&f.get(None).await), first);
}

/// Keep `settings.json` readable while making the atomic replace fail.
#[cfg(windows)]
fn block_settings_publish(path: &Path) -> impl Drop {
    use std::os::windows::fs::OpenOptionsExt;
    const FILE_SHARE_READ: u32 = 1;
    struct Guard(#[allow(dead_code)] std::fs::File);
    impl Drop for Guard {
        fn drop(&mut self) {}
    }
    Guard(
        std::fs::OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ)
            .open(path)
            .unwrap(),
    )
}

#[cfg(unix)]
fn block_settings_publish(path: &Path) -> impl Drop {
    use std::os::unix::fs::PermissionsExt;
    struct Guard(PathBuf);
    impl Drop for Guard {
        fn drop(&mut self) {
            let _ = std::fs::set_permissions(&self.0, std::fs::Permissions::from_mode(0o755));
        }
    }
    let folder = path.parent().unwrap().to_path_buf();
    std::fs::set_permissions(&folder, std::fs::Permissions::from_mode(0o555)).unwrap();
    Guard(folder)
}

#[tokio::test]
async fn failed_asset_write_preserves_prior_signature_and_removes_staged_directory() {
    let f = Fixture::new();
    let before = std::fs::read(f.settings()).unwrap();
    // A file where the account's image folder must be created.
    let account_root = mail_core::signatures::account_root_for(&f.settings(), &f.account.email);
    std::fs::create_dir_all(account_root.parent().unwrap()).unwrap();
    std::fs::write(&account_root, b"not a folder").unwrap();
    let assets = f.image_tree();
    let response = f.save().await;
    assert_eq!(
        response.assert_json_error(StatusCode::INTERNAL_SERVER_ERROR),
        "Cannot save the email signature"
    );
    assert_eq!(std::fs::read(f.settings()).unwrap(), before);
    assert_eq!(f.image_tree(), assets);
}

#[tokio::test]
async fn legacy_plaintext_is_migrated_escaped_per_account_once() {
    let f = Fixture::new();
    let mut values = f.read_settings();
    values["signature"] = json!("Thanks <b>Alex</b>\r\n\u{1f642}");
    std::fs::write(f.settings(), values.to_string()).unwrap();
    let response = f.get(None).await;
    let expected = "<div>Thanks &lt;b&gt;Alex&lt;/b&gt;<br>\u{1f642}</div>";
    assert_eq!(ok_json(&response)["text"], expected);
    assert_eq!(
        f.read_settings()["emails_signatures"]["user@example.com"],
        json!({"text": expected, "multipart-path": {}})
    );
    let before = std::fs::read(f.settings()).unwrap();
    assert_eq!(ok_json(&f.get(None).await), response.json());
    assert_eq!(std::fs::read(f.settings()).unwrap(), before);
    assert_eq!(
        ok_json(&f.get(Some(&f.other.email)).await)["text"],
        expected
    );
    // Explicit blank beats the old global signature on future sign-ins.
    ok_json(&f.save_text("").await);
    assert_eq!(ok_json(&f.get(None).await)["text"], "");
}

#[tokio::test]
async fn saving_preferences_preserves_per_account_signatures() {
    let f = Fixture::new();
    let saved = ok_json(&f.save().await);
    let update = mail_core::settings::MailPreferencesUpdate {
        signature: Some(json!("legacy")),
        ..Default::default()
    };
    mail_core::settings::save_mail_preferences(&json!(7), &update).unwrap();
    assert_eq!(ok_json(&f.get(None).await), saved);
    assert_eq!(f.read_settings()["messages_per_page"], 7);
}

#[tokio::test]
async fn missing_and_mismatched_cid_references_reject_without_mutation() {
    let f = Fixture::new();
    let before = std::fs::read(f.settings()).unwrap();
    let cases = [
        (
            json!({"text": "<img src=\"cid:missing\">", "uploads": []}),
            vec![],
            "Every inline image must have a matching cid reference in the HTML message",
        ),
        (
            json!({"text": "No image", "uploads": [{"content_id": "attach1"}]}),
            vec![("logo.png".to_string(), png(), "image/png".to_string())],
            "Every inline image must have a matching cid reference in the HTML message",
        ),
        (
            json!({"text": "<img src=\"cid:attach1\">", "uploads": [{"content_id": "attach1"}, {"content_id": "attach1"}]}),
            vec![
                ("one.png".to_string(), png(), "image/png".to_string()),
                ("two.png".to_string(), png(), "image/png".to_string()),
            ],
            "Check the signature HTML, size, and image metadata",
        ),
    ];
    for (body, files, message) in cases {
        let response = f.save_with("", files, None, Some(body.clone())).await;
        assert_eq!(
            response.assert_json_error(StatusCode::UNPROCESSABLE_ENTITY),
            message,
            "{body}"
        );
    }
    assert_eq!(std::fs::read(f.settings()).unwrap(), before);
    assert!(!f.images_exist());
}

#[tokio::test]
async fn images_require_real_raster_bytes_and_matching_mime() {
    let f = Fixture::new();
    let cases = [
        (
            "fake.png",
            b"<html>fake</html>".to_vec(),
            "image/png",
            "Inline images must be valid PNG, JPEG, GIF, WebP, or BMP images",
        ),
        (
            "vector.svg",
            b"<svg/>".to_vec(),
            "image/svg+xml",
            "Inline images must be valid PNG, JPEG, GIF, WebP, or BMP images",
        ),
        (
            "wrong.jpg",
            png(),
            "image/jpeg",
            "The inline image content type does not match its bytes",
        ),
    ];
    for (name, data, kind, message) in cases {
        let response = f
            .save_with(
                DEFAULT_TEXT,
                vec![(name.into(), data, kind.into())],
                None,
                None,
            )
            .await;
        assert_eq!(
            response.assert_json_error(StatusCode::UNPROCESSABLE_ENTITY),
            message,
            "{name}"
        );
    }
    assert!(!f.images_exist());
}

#[tokio::test]
async fn metadata_is_exact_counts_match_and_control_characters_reject() {
    let f = Fixture::new();
    let bodies = [
        json!({"text": "Hello", "uploads": [], "multipart-path": {"attach1": "../secret"}}),
        Value::String("lone surrogate".into()), // replaced below with raw JSON
        json!({"text": "\u{1}", "uploads": []}),
        json!({"text": "<img src=\"cid:attach1\">", "uploads": [{"content_id": "../secret"}]}),
        json!({"text": "<img src=\"cid:attach1\">", "uploads": [{"content_id": "unsafe\r\nheader"}]}),
        json!({"text": "<img src=\"cid:CON\">", "uploads": [{"content_id": "CON"}]}),
        json!({"text": "<img src=\"cid:nul.logo\">", "uploads": [{"content_id": "nul.logo"}]}),
        json!({"text": "<img src=\"cid:attach1\">", "uploads": [{"content_id": "attach1", "disposition": "inline"}]}),
    ];
    for body in bodies {
        let response = if body.is_string() {
            // {"text": "\ud800", "uploads": []} (not representable as a Rust string).
            let raw = br#"{"text": "\ud800", "uploads": []}"#.to_vec();
            f.put_parts(
                &f.account.email,
                &[("signature", None, Some("application/json".into()), raw)],
            )
            .await
        } else {
            f.save_with("", Vec::new(), None, Some(body.clone())).await
        };
        assert_eq!(
            response.assert_json_error(StatusCode::UNPROCESSABLE_ENTITY),
            "Check the signature HTML, size, and image metadata",
            "{body}"
        );
    }
    // One uploaded image but no declared upload.
    let response = f
        .save_with(
            "",
            default_images(),
            None,
            Some(json!({"text": "No images", "uploads": []})),
        )
        .await;
    assert_eq!(
        response.assert_json_error(StatusCode::BAD_REQUEST),
        "Uploaded images must match the signature metadata"
    );
    // Count mismatch: metadata declares an image that was not uploaded.
    let response = f
        .save_with(
            "",
            Vec::new(),
            None,
            Some(json!({"text": "<img src=\"cid:attach1\">", "uploads": [{"content_id": "attach1"}]})),
        )
        .await;
    assert_eq!(
        response.assert_json_error(StatusCode::BAD_REQUEST),
        "Uploaded images must match the signature metadata"
    );
}

#[tokio::test]
async fn case_insensitive_disk_filename_collisions_are_rejected() {
    let f = Fixture::new();
    let response = f
        .save_with(
            "",
            vec![
                ("one.png".into(), png(), "image/png".into()),
                ("two.png".into(), png(), "image/png".into()),
            ],
            None,
            Some(
                json!({"text": "<img src=\"cid:attach1\"><img src=\"cid:Attach1\">",
                        "uploads": [{"content_id": "attach1"}, {"content_id": "Attach1"}]}),
            ),
        )
        .await;
    assert_eq!(response.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(!f.images_exist());
}

#[tokio::test]
async fn malformed_or_duplicate_json_extra_fields_and_excess_images_reject() {
    let f = Fixture::new();
    let metadata = metadata_part(&json!({"text": "", "uploads": []}));
    let mut excess = vec![metadata.clone()];
    for index in 0..21 {
        excess.push(file_part(&format!("image-{index}.png"), png(), "image/png"));
    }
    let cases: Vec<(Vec<Part>, StatusCode, &str)> = vec![
        (
            vec![metadata.clone(), metadata.clone()],
            StatusCode::BAD_REQUEST,
            "Too many fields. Maximum number of fields is 1.",
        ),
        (
            vec![metadata.clone(), ("files", None, None, b"value".to_vec())],
            StatusCode::BAD_REQUEST,
            "Too many fields. Maximum number of fields is 1.",
        ),
        (
            vec![
                ("unexpected", Some("x.png".into()), None, b"value".to_vec()),
                metadata.clone(),
            ],
            StatusCode::BAD_REQUEST,
            "Unexpected signature upload field",
        ),
        (
            vec![("signature", None, None, b"broken json".to_vec())],
            StatusCode::UNPROCESSABLE_ENTITY,
            "Check the signature HTML, size, and image metadata",
        ),
        (
            excess,
            StatusCode::BAD_REQUEST,
            "Too many files. Maximum number of files is 20.",
        ),
        (
            vec![file_part("a.png", png(), "image/png")],
            StatusCode::BAD_REQUEST,
            "Provide one JSON signature and its uploaded images",
        ),
    ];
    for (parts, status, message) in cases {
        let response = f.put_parts(&f.account.email, &parts).await;
        assert_eq!(response.assert_json_error(status), message);
    }
    // Not multipart at all.
    let request = Request::builder()
        .method(Method::PUT)
        .uri(with_query(
            "/api/mail/signature",
            &[("account", &f.account.email)],
        ))
        .header("host", "127.0.0.1:48101")
        .header("content-type", "application/json")
        .body(Body::from(r#"{"text": "", "uploads": []}"#))
        .unwrap();
    let response = call_router(f.harness.app.clone(), request).await;
    assert_eq!(
        response.assert_json_error(StatusCode::BAD_REQUEST),
        "Save signatures using multipart/form-data"
    );
    assert!(!f.images_exist());
}

#[tokio::test]
async fn limits_reject_before_disk_changes() {
    let f = Fixture::new();
    // HTML larger than 256 KiB.
    let response = f
        .save_text(&"x".repeat(mail_core::signatures::MAX_SIGNATURE_HTML_BYTES + 1))
        .await;
    assert_eq!(
        response.assert_json_error(StatusCode::UNPROCESSABLE_ENTITY),
        "Check the signature HTML, size, and image metadata"
    );
    // One image above 10 MiB.
    let response = f
        .save_with(
            DEFAULT_TEXT,
            vec![(
                "big.png".into(),
                vec![0u8; 10 * MIB + 1],
                "image/png".into(),
            )],
            None,
            None,
        )
        .await;
    assert_eq!(
        response.assert_json_error(StatusCode::PAYLOAD_TOO_LARGE),
        "Each signature image must be no larger than 10 MiB"
    );
    // Images above 20 MiB together.
    let response = f
        .save_with(
            "<img src=\"cid:attach1\"><img src=\"cid:attach2\"><img src=\"cid:attach3\">",
            vec![
                ("one.png".into(), vec![0u8; 10 * MIB], "image/png".into()),
                ("two.png".into(), vec![0u8; 10 * MIB], "image/png".into()),
                ("three.png".into(), vec![0u8; 1], "image/png".into()),
            ],
            None,
            None,
        )
        .await;
    assert_eq!(
        response.assert_json_error(StatusCode::PAYLOAD_TOO_LARGE),
        "Signature images exceed the 10 MiB per-image or 20 MiB total limit"
    );
    // Declared Content-Length above the request limit (before the account).
    let limit = mail_core::signatures::MAX_SIGNATURE_REQUEST_BYTES;
    let request = Request::builder()
        .method(Method::PUT)
        .uri(with_query(
            "/api/mail/signature",
            &[("account", "locked@example.com")],
        ))
        .header("host", "127.0.0.1:48101")
        .header("content-length", (limit + 1).to_string())
        .body(Body::from("small"))
        .unwrap();
    let response = call_router(f.harness.app.clone(), request).await;
    assert_eq!(
        response.assert_json_error(StatusCode::PAYLOAD_TOO_LARGE),
        "Signature request exceeds maximum allowed size"
    );
    let request = Request::builder()
        .method(Method::PUT)
        .uri(with_query(
            "/api/mail/signature",
            &[("account", "locked@example.com")],
        ))
        .header("host", "127.0.0.1:48101")
        .header("content-length", "-1")
        .body(Body::from("small"))
        .unwrap();
    let response = call_router(f.harness.app.clone(), request).await;
    assert_eq!(
        response.assert_json_error(StatusCode::BAD_REQUEST),
        "Invalid request size"
    );
    // Streamed (no Content-Length) body above the limit.
    let chunk = vec![b'x'; MIB];
    let chunks: Vec<Result<Vec<u8>, std::io::Error>> =
        (0..=limit / MIB + 1).map(|_| Ok(chunk.clone())).collect();
    let request = Request::builder()
        .method(Method::PUT)
        .uri(with_query(
            "/api/mail/signature",
            &[("account", &f.account.email)],
        ))
        .header("host", "127.0.0.1:48101")
        .header("content-type", "multipart/form-data; boundary=example")
        .body(Body::from_stream(futures_util::stream::iter(chunks)))
        .unwrap();
    let response = call_router(f.harness.app.clone(), request).await;
    assert_eq!(
        response.assert_json_error(StatusCode::PAYLOAD_TOO_LARGE),
        "Signature request exceeds maximum allowed size"
    );
    assert!(!f.images_exist());
}

#[tokio::test]
async fn untrusted_identifier_and_persisted_traversal_paths_never_read_arbitrary_files() {
    let f = Fixture::new();
    let saved = ok_json(&f.save().await);
    for (identifier, revision, status) in [
        ("../secret", "", StatusCode::BAD_REQUEST),
        ("attach1", "../revision", StatusCode::BAD_REQUEST),
        (
            "attach1",
            &*format!("{}x", "a".repeat(32)),
            StatusCode::UNPROCESSABLE_ENTITY,
        ),
        ("missing", "", StatusCode::NOT_FOUND),
        ("attach1", &*"a".repeat(32), StatusCode::NOT_FOUND),
    ] {
        let response = f.image(&f.account.email, identifier, revision).await;
        assert_eq!(
            response.status,
            status,
            "{identifier} {revision}: {}",
            response.text()
        );
    }
    let mut values = f.read_settings();
    let other_root = mail_core::signatures::account_root_for(&f.settings(), &f.other.email);
    let other_root = other_root
        .file_name()
        .unwrap()
        .to_string_lossy()
        .into_owned();
    let relative = saved["multipart-path"]["attach1"]
        .as_str()
        .unwrap()
        .to_string();
    let revision = revision_of(&relative);
    let absolute = f.root().join("secret.png").to_string_lossy().into_owned();
    for (bad, message) in [
        (
            "../secret.png".to_string(),
            "Signature image path does not belong to this account",
        ),
        (absolute, "Invalid signature image path"),
        (
            format!("signature-images/{other_root}/{revision}/attach1.png"),
            "Signature image path does not belong to this account",
        ),
        (
            relative.replace("attach1.png", "../attach1.png"),
            "Signature image path does not belong to this account",
        ),
        (
            relative.replace("attach1.png", "attach1.svg"),
            "Invalid signature image filename",
        ),
    ] {
        values["emails_signatures"]["user@example.com"]["multipart-path"]["attach1"] = json!(bad);
        std::fs::write(f.settings(), values.to_string()).unwrap();
        // An absolute POSIX path has no backslash and fails the ownership check.
        let expected = if message == "Invalid signature image path" && !bad.contains('\\') {
            "Signature image path does not belong to this account"
        } else {
            message
        };
        assert_eq!(
            f.get(None)
                .await
                .assert_json_error(StatusCode::INTERNAL_SERVER_ERROR),
            expected,
            "{bad}"
        );
        let response = f
            .harness
            .get(
                "/api/mail/signature/image",
                &[("account", &f.account.email), ("content_id", "attach1")],
            )
            .await;
        assert_eq!(response.status, StatusCode::INTERNAL_SERVER_ERROR, "{bad}");
    }
}

#[tokio::test]
async fn modified_saved_asset_is_revalidated_before_serving() {
    let f = Fixture::new();
    let saved = ok_json(&f.save().await);
    let asset = f
        .root()
        .join(saved["multipart-path"]["attach1"].as_str().unwrap());
    std::fs::write(&asset, b"<script>not an image</script>").unwrap();
    let response = f.get_url(saved["images"][0]["url"].as_str().unwrap()).await;
    assert_eq!(
        response.assert_json_error(StatusCode::INTERNAL_SERVER_ERROR),
        "Cannot read saved signature image"
    );
    assert_eq!(
        f.get(None)
            .await
            .assert_json_error(StatusCode::INTERNAL_SERVER_ERROR),
        "Cannot read saved signature image"
    );
}

#[tokio::test]
async fn missing_account_parameter_is_a_validation_error() {
    let f = Fixture::new();
    let response = f.harness.get("/api/mail/signature", &[]).await;
    let detail = response.assert_json_error(StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(detail[0]["loc"], json!(["query", "account"]));
    let response = f
        .harness
        .get(
            "/api/mail/signature/image",
            &[("account", &f.account.email)],
        )
        .await;
    let detail = response.assert_json_error(StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(detail[0]["loc"], json!(["query", "content_id"]));
}
