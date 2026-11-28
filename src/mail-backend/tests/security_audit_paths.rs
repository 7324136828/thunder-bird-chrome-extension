//! Security audit: path traversal (doctor job files, signature images) and
//! response-header injection (attachment `Content-Disposition`).

mod common;
mod mail_support;

use std::time::{Duration, Instant};

use axum::http::StatusCode;
use mail_support::{account, message, server, Harness, USER};
use serde_json::json;

const EML: &str = "From: News <news@example.com>\r\nTo: user@example.com\r\n\
Subject: Weekly\r\nDate: Mon, 13 Oct 2026 09:59:40 +0000\r\nMessage-ID: <w@example.com>\r\n\
\r\nHello.\r\n";

async fn completed_paste_job(h: &Harness) -> String {
    let job = h
        .post_json(
            "/api/jobs/paste",
            &json!({"content": EML, "filename": "../../evil.eml"}),
        )
        .await;
    assert_eq!(job.status, StatusCode::CREATED, "{}", job.text());
    let id = job.json()["id"].as_str().unwrap().to_string();
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let status = h.get(&format!("/api/jobs/{id}"), &[]).await.json();
        match status["status"].as_str().unwrap_or("") {
            "completed" => return id,
            "queued" | "in_progress" => {}
            other => panic!("job ended as {other}: {status}"),
        }
        assert!(Instant::now() < deadline, "doctor job did not finish");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

#[tokio::test]
async fn doctor_job_files_cannot_escape_the_job_folder() {
    let h = Harness::new();
    let id = completed_paste_job(&h).await;
    // The upload name never escapes the inputs folder.
    assert!(!h.root.join("evil.eml").exists());
    assert!(!h.root.join("data").join("evil.eml").exists());

    let listed = h.get(&format!("/api/jobs/{id}/files"), &[]).await;
    assert_eq!(listed.status, StatusCode::OK, "{}", listed.text());
    let files = listed.json()["files"].clone();
    let first = files[0].as_str().expect("an output file").to_string();
    let ok = h.get(&format!("/api/jobs/{id}/files/{first}"), &[]).await;
    assert_eq!(ok.status, StatusCode::OK);
    assert_eq!(ok.header("x-content-type-options"), Some("nosniff"));

    for path in [
        "..%2F..%2F..%2Fmail-servers.json",
        "../../../mail-servers.json",
        "..%5C..%5C..%5Cmail-servers.json",
        "%2E%2E/%2E%2E/%2E%2E/mail-servers.json",
        "..%252F..%252Fmail-servers.json",
        "inputs/../../inputs/evil.eml",
        "..%2Finputs%2Fevil.eml",
        "%2Fetc%2Fpasswd",
        "C:%5CWindows%5Cwin.ini",
        "C:/Windows/win.ini",
        "report%00.html",
        "inbox_audit.html::$DATA",
    ] {
        for kind in ["files", "snapshot-files"] {
            let response = h.get(&format!("/api/jobs/{id}/{kind}/{path}"), &[]).await;
            assert_ne!(
                response.status,
                StatusCode::OK,
                "{kind}/{path} escaped the job folder: {}",
                response.text().chars().take(200).collect::<String>()
            );
        }
    }
    // Job ids are looked up in the database, never joined as paths.
    for id in ["..", "..%2F..", "%2E%2E"] {
        let response = h.get(&format!("/api/jobs/{id}/files/x"), &[]).await;
        assert_eq!(response.status, StatusCode::NOT_FOUND, "{id}");
    }

    // HTML reports are served sandboxed.
    let report = files
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|file| file.as_str())
        .find(|file| file.ends_with(".html"))
        .map(str::to_string);
    if let Some(report) = report {
        let response = h.get(&format!("/api/jobs/{id}/files/{report}"), &[]).await;
        let csp = response.header("content-security-policy").unwrap_or("");
        assert!(csp.contains("sandbox"), "{csp}");
    }
}

#[tokio::test]
async fn signature_image_identifiers_cannot_traverse() {
    let h = Harness::new();
    h.unlock(mail_support::offline_account(USER));
    for (content_id, revision) in [
        ("../../settings", ""),
        ("..", ""),
        ("a/../../b", ""),
        ("a\\..\\b", ""),
        ("logo", "../../../../.."),
        ("logo", "0123456789abcdef0123456789abcde/"),
        ("logo:stream", ""),
        ("CON", ""),
        ("logo", "0123456789ABCDEF0123456789ABCDEF"),
    ] {
        let response = h
            .get(
                "/api/mail/signature/image",
                &[
                    ("account", USER),
                    ("content_id", content_id),
                    ("revision", revision),
                ],
            )
            .await;
        assert!(
            matches!(
                response.status,
                StatusCode::BAD_REQUEST | StatusCode::NOT_FOUND | StatusCode::UNPROCESSABLE_ENTITY
            ),
            "{content_id:?}/{revision:?}: {} {}",
            response.status,
            response.text()
        );
    }
}

fn attachment_message(disposition: &str) -> String {
    format!(
        "From: a@example.com\r\nTo: user@example.com\r\nSubject: att\r\n\
MIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=\"B\"\r\n\r\n\
--B\r\nContent-Type: text/plain\r\n\r\nbody\r\n\
--B\r\nContent-Type: text/html\r\nContent-Disposition: {disposition}\r\n\
Content-Transfer-Encoding: base64\r\n\r\nPHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==\r\n--B--\r\n"
    )
}

#[tokio::test]
async fn attachment_filenames_cannot_inject_response_headers() {
    let dispositions = [
        "attachment; filename=\"evil\\\".html\"",
        "attachment; filename*=utf-8''a%0D%0ASet-Cookie%3A%20x%3D1.html",
        "attachment; filename*=utf-8''a%22%3B%20filename%3Devil.html",
        "attachment; filename*=utf-8''a%5C%22.html",
    ];
    let mut builder = server();
    for (index, disposition) in dispositions.iter().enumerate() {
        builder = builder.message_with(
            "INBOX",
            message(index as u32 + 1, attachment_message(disposition)),
        );
    }
    let imap = builder.start();
    let h = Harness::new();
    h.unlock(account(&imap));
    let mut served = Vec::new();
    for uid in 1..=dispositions.len() {
        let uid = uid.to_string();
        let response = h
            .get(
                "/api/mail/message/attachment",
                &[("account", USER), ("uid", &uid), ("index", "0")],
            )
            .await;
        if response.status != StatusCode::OK {
            // Refusing an unencodable name is safe too.
            continue;
        }
        assert!(response.header("set-cookie").is_none());
        let value = response.header("content-disposition").unwrap_or("");
        assert!(value.starts_with("attachment;"), "{value}");
        // Exactly one quoted filename: no quote or backslash inside it.
        let inner = value
            .strip_prefix("attachment; filename=\"")
            .and_then(|rest| rest.strip_suffix('"'))
            .unwrap_or_else(|| panic!("unexpected disposition {value:?}"));
        assert!(
            !inner.contains('"') && !inner.contains('\\') && !inner.contains('\r'),
            "{value}"
        );
        served.push(format!(
            "{} | {value}",
            response.header("content-type").unwrap_or("")
        ));
    }
    assert!(!served.is_empty(), "no attachment was served at all");
}
