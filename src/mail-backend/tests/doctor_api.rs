//! HTTP tests of the Inbox Doctor routes (ports of `backend/tests/test_doctor.py`
//! and the route-level parts of `test_doctor_mailbox.py`), driving the real
//! report pipeline end to end. Mailbox audits connect to the in-process fake
//! IMAP server from `mail_proto::testkit`; where the Python tests patched
//! `download_inbox` / `run_pipeline` to force a situation the fake server
//! cannot produce (or to block a worker), the runner's hooks are replaced.

mod common;
mod doctor_support;

use std::io::Read;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use mail_core::MailAccount;
use mail_doctor::db::NewJob;
use mail_doctor::mailbox_download::{DownloadError, DownloadHooks, DownloadOptions};
use mail_doctor::pipeline::PipelineEvent;
use mail_doctor::runner::{PipelineHook, RunnerHooks, CAPACITY_MESSAGE};
use mail_proto::testkit::{FakeImapServer, FakeMessage};
use serde_json::{json, Value};

use common::EXTENSION_ORIGIN;
use doctor_support::{message, news, zip_bytes, Ctx, BOUNDARY, HOST};

fn id_of(response: &common::Resp) -> String {
    assert_eq!(response.status, StatusCode::CREATED, "{}", response.text());
    response.json()["id"].as_str().unwrap().to_string()
}

#[tokio::test]
async fn zip_audit_produces_sender_actions_reports_and_downloads() {
    let ctx = Ctx::new();
    let mut entries: Vec<(String, Vec<u8>)> = (0..12)
        .map(|index| (format!("mail/news-{index}.eml"), news(index).into_bytes()))
        .collect();
    entries.push((
        "mail/human.eml".into(),
        message(20, "alice@friends.org", false).into_bytes(),
    ));
    let refs: Vec<(&str, &[u8])> = entries
        .iter()
        .map(|(name, data)| (name.as_str(), data.as_slice()))
        .collect();
    let archive = zip_bytes(&refs, zip::CompressionMethod::Stored);
    let response = ctx.upload(&[("files", Some("inbox.zip"), &archive)]).await;
    let created = response.json();
    assert_eq!(created["status"], "queued", "{created}");
    assert_eq!(created["filename"], "inbox.zip");
    assert_eq!(created["file_size"], archive.len());
    let job = ctx.wait(&id_of(&response)).await;
    assert_eq!(job["status"], "completed", "{}", job["log"]);
    assert_eq!(job["progress"], 100);
    assert!(!job["log"].as_str().unwrap().is_empty());
    let prefix = format!("/api/jobs/{}", job["id"].as_str().unwrap());

    let summary = ctx
        .get(&format!("{prefix}/files/report/summary.json"))
        .await;
    assert_eq!(summary.status, StatusCode::OK);
    assert_eq!(summary.header("content-type"), Some("application/json"));
    assert_eq!(summary.header("x-content-type-options"), Some("nosniff"));
    assert_eq!(summary.header("cache-control"), Some("no-store"));
    // Deviation: every job file is sandboxed, not only `.html` reports.
    assert_eq!(
        summary.header("content-security-policy"),
        Some("sandbox; default-src 'none'; style-src 'unsafe-inline'; img-src data:")
    );
    let summary = summary.json();
    assert_eq!(summary["total_messages"], 13);
    assert_eq!(summary["unique_senders"], 2);

    let worklist = ctx
        .get(&format!("{prefix}/files/worklist.json"))
        .await
        .json();
    let mut actions: Vec<(String, String)> = worklist["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| {
            (
                item["sender_group"].as_str().unwrap().to_string(),
                item["recommended_action"].as_str().unwrap().to_string(),
            )
        })
        .collect();
    actions.sort();
    assert_eq!(
        actions,
        [
            (
                "example.com".to_string(),
                "unsubscribe_and_purge".to_string()
            ),
            ("friends.org".to_string(), "keep".to_string()),
        ]
    );
    let briefing = ctx
        .get(&format!("{prefix}/files/report/email_briefing.md"))
        .await;
    assert_eq!(
        briefing.header("content-type"),
        Some("text/plain; charset=utf-8")
    );
    assert!(briefing.text().contains("Weekly digest"));
    let html = ctx.get(&format!("{prefix}/files/inbox_audit.html")).await;
    assert_eq!(
        html.header("content-type"),
        Some("text/html; charset=utf-8")
    );
    assert_eq!(
        html.header("content-security-policy"),
        Some("sandbox; default-src 'none'; style-src 'unsafe-inline'; img-src data:")
    );
    let csv = ctx.get(&format!("{prefix}/files/report/senders.csv")).await;
    assert_eq!(csv.header("content-type"), Some("text/csv; charset=utf-8"));
    for response in [&briefing, &csv] {
        assert_eq!(response.header("x-content-type-options"), Some("nosniff"));
        assert_eq!(response.header("cache-control"), Some("no-store"));
        assert!(response
            .header("content-security-policy")
            .is_some_and(|csp| csp.starts_with("sandbox;")));
    }

    let download = ctx.get(&format!("{prefix}/download-zip")).await;
    assert_eq!(download.status, StatusCode::OK);
    assert_eq!(download.header("content-type"), Some("application/zip"));
    assert_eq!(
        download.header("content-disposition"),
        Some("attachment; filename*=utf-8''inbox_audit.zip")
    );
    assert_eq!(download.header("cache-control"), Some("no-store"));
    assert_eq!(download.header("x-content-type-options"), Some("nosniff"));
    let mut bundle = zip::ZipArchive::new(std::io::Cursor::new(download.body)).unwrap();
    let names: Vec<String> = bundle.file_names().map(str::to_string).collect();
    for expected in [
        "inbox_audit.html",
        "report/recent_emails.csv",
        "messages_grouped.jsonl",
    ] {
        assert!(names.contains(&expected.to_string()), "{names:?}");
    }
    // The archive and the file route serve the same bytes.
    let mut zipped = String::new();
    bundle
        .by_name("report/summary.md")
        .unwrap()
        .read_to_string(&mut zipped)
        .unwrap();
    assert_eq!(
        zipped,
        ctx.get(&format!("{prefix}/files/report/summary.md"))
            .await
            .text()
    );

    let files = ctx.get(&format!("{prefix}/files")).await.json();
    assert_eq!(files["files"].as_array().unwrap().len(), 12, "{files}");
    assert_eq!(job["output_files"], files["files"]);
    let history = ctx.get("/api/jobs").await.json();
    let row = history
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["id"] == job["id"])
        .expect("job listed");
    assert_eq!(row["log"], "");
    assert_eq!(row["output_files"], json!([]));
    // Upload jobs never have a snapshot.
    let snapshot = ctx.get(&format!("{prefix}/snapshot-files")).await;
    assert_eq!(
        snapshot.assert_json_error(StatusCode::NOT_FOUND),
        "No audit snapshot is available yet"
    );
    // Starlette's `path` convertor also matches the empty relative path.
    let empty = ctx.get(&format!("{prefix}/files/")).await;
    assert_eq!(
        empty.assert_json_error(StatusCode::NOT_FOUND),
        "File not found"
    );
}

#[tokio::test]
async fn multi_file_upload_honors_aliases_and_action_annotations() {
    let ctx = Ctx::new();
    let one = message(1, "news@updates.vendor.net", true);
    let two = message(2, "news@vendor.org", true);
    let aliases = json!({"updates.vendor.net": "vendor.org"}).to_string();
    let annotations =
        json!({"vendor.org": {"action": "keep", "note": "Paid subscription"}}).to_string();
    let response = ctx
        .upload(&[
            ("files", Some("one.eml"), one.as_bytes()),
            ("files", Some("two.eml"), two.as_bytes()),
            ("files", Some("aliases.json"), aliases.as_bytes()),
            ("files", Some("annotations.json"), annotations.as_bytes()),
        ])
        .await;
    assert_eq!(
        response.json()["filename"],
        "one.eml, two.eml, aliases.json, annotations.json"
    );
    let job = ctx.wait(&id_of(&response)).await;
    assert_eq!(job["status"], "completed", "{}", job["log"]);
    let worklist = ctx
        .get(&format!(
            "/api/jobs/{}/files/worklist.json",
            job["id"].as_str().unwrap()
        ))
        .await
        .json();
    let items = worklist["items"].as_array().unwrap();
    assert_eq!(items.len(), 1, "{worklist}");
    assert_eq!(items[0]["sender_group"], "vendor.org");
    assert_eq!(items[0]["message_count"], 2);
    assert_eq!(items[0]["recommended_action"], "keep");
    assert_eq!(items[0]["note"], "Paid subscription");
}

/// Python `mailbox.mbox` output for `messages` (LF line endings, `From `
/// separator lines, `>From` quoting).
fn mbox(messages: &[String]) -> Vec<u8> {
    let mut out = String::new();
    for raw in messages {
        out.push_str("From MAILER-DAEMON Thu Oct  1 12:00:00 2026\n");
        for line in raw.split("\r\n") {
            if line.starts_with("From ") {
                out.push('>');
            }
            out.push_str(line);
            out.push('\n');
        }
        out.push('\n');
    }
    out.into_bytes()
}

#[tokio::test]
async fn mbox_upload_and_paste_are_supported() {
    let ctx = Ctx::new();
    let data = mbox(&[news(0), news(1), news(2)]);
    let response = ctx.upload(&[("files", Some("export.mbox"), &data)]).await;
    let job = ctx.wait(&id_of(&response)).await;
    assert_eq!(job["status"], "completed", "{}", job["log"]);
    let summary = ctx
        .get(&format!(
            "/api/jobs/{}/files/report/summary.json",
            job["id"].as_str().unwrap()
        ))
        .await
        .json();
    assert_eq!(summary["total_messages"], 3);
    let pasted = ctx.paste().await;
    assert_eq!(pasted["status"], "completed", "{}", pasted["log"]);
    assert_eq!(pasted["filename"], "paste.eml");
}

#[tokio::test]
async fn large_uploads_are_spooled_to_temporary_files_and_staged() {
    let ctx = Ctx::new();
    let mut raw = news(1);
    raw.push_str(&"\r\nfiller line for a large message".repeat(60_000));
    assert!(raw.len() > 1024 * 1024);
    let response = ctx
        .upload(&[("files", Some("Large.EML"), raw.as_bytes())])
        .await;
    let created = response.json();
    assert_eq!(created["filename"], "Large.eml");
    assert_eq!(created["file_size"], raw.len());
    let job = ctx.wait(&id_of(&response)).await;
    assert_eq!(job["status"], "completed", "{}", job["log"]);
    let staged = ctx.files_with("large.eml");
    assert_eq!(staged.len(), 1);
    assert_eq!(std::fs::read(&staged[0]).unwrap(), raw.as_bytes());
}

#[tokio::test]
async fn history_and_report_files_survive_new_application_instance() {
    let ctx = Ctx::new();
    let job = ctx.paste().await;
    let id = job["id"].as_str().unwrap();
    let (app, _state) = ctx.restarted();
    let history = doctor_support::send_to(&app, doctor_support::get("/api/jobs"))
        .await
        .json();
    assert!(history
        .as_array()
        .unwrap()
        .iter()
        .any(|row| row["id"] == id));
    let summary = doctor_support::send_to(
        &app,
        doctor_support::get(&format!("/api/jobs/{id}/files/report/summary.json")),
    )
    .await
    .json();
    assert_eq!(summary["total_messages"], 1);
}

#[tokio::test]
async fn interrupted_jobs_are_reported_as_failed_after_restart() {
    let ctx = Ctx::new();
    let job_id = "a".repeat(32);
    ctx.state
        .doctor
        .db()
        .create_job(NewJob::new(&job_id, "interrupted.eml", 1, ""))
        .unwrap();
    let (app, _state) = ctx.restarted();
    let job = doctor_support::send_to(&app, doctor_support::get(&format!("/api/jobs/{job_id}")))
        .await
        .json();
    assert_eq!(job["status"], "failed");
    assert!(job["error_message"].as_str().unwrap().contains("stopped"));
}

#[tokio::test]
async fn invalid_uploads_and_empty_source_are_rejected() {
    let ctx = Ctx::new();
    for (filename, data, detail) in [
        (
            "run.exe",
            &b"MZ"[..],
            "Unsupported file type: run.exe. Accepted: .eml, .zip, .mbox, .json",
        ),
        (
            "aliases.json",
            &b"{}"[..],
            "Upload must include at least one .eml, .zip, or .mbox file",
        ),
    ] {
        let response = ctx.upload(&[("files", Some(filename), data)]).await;
        assert_eq!(response.assert_json_error(StatusCode::BAD_REQUEST), detail);
    }
    let empty = ctx
        .post_json("/api/jobs/paste", &json!({"content": ""}))
        .await;
    assert_eq!(
        empty.assert_json_error(StatusCode::UNPROCESSABLE_ENTITY),
        json!([{
            "type": "string_too_short", "loc": ["body", "content"],
            "msg": "String should have at least 1 character", "input": "",
            "ctx": {"min_length": 1},
        }])
    );
    assert_eq!(
        ctx.get("/api/jobs/missing")
            .await
            .assert_json_error(StatusCode::NOT_FOUND),
        "Job not found"
    );
    assert_eq!(
        ctx.post_empty("/api/jobs/missing/discard")
            .await
            .assert_json_error(StatusCode::NOT_FOUND),
        "Job not found"
    );
    // FastAPI routes GET /api/jobs/paste to `get_job("paste")`.
    assert_eq!(
        ctx.get("/api/jobs/paste")
            .await
            .assert_json_error(StatusCode::NOT_FOUND),
        "Job not found"
    );
    assert_eq!(ctx.get("/api/jobs").await.json(), json!([]));
    assert!(ctx.files_with(".exe").is_empty());
}

#[tokio::test]
async fn upload_form_errors_match_fastapi() {
    let ctx = Ctx::new();
    let missing = json!([{
        "type": "missing", "loc": ["body", "files"], "msg": "Field required", "input": null,
    }]);
    // A JSON body is not a form: `files` is missing.
    let response = ctx.post_json("/api/jobs", &json!({"files": "x"})).await;
    assert_eq!(
        response.assert_json_error(StatusCode::UNPROCESSABLE_ENTITY),
        missing
    );
    // A multipart form without `files` parts.
    let response = ctx.upload(&[("other", Some("a.eml"), b"x")]).await;
    assert_eq!(
        response.assert_json_error(StatusCode::UNPROCESSABLE_ENTITY),
        missing
    );
    // A plain text value is not an UploadFile.
    let response = ctx
        .upload(&[
            ("files", Some("a.eml"), news(0).as_bytes()),
            ("files", None, b"text"),
        ])
        .await;
    assert_eq!(
        response.assert_json_error(StatusCode::UNPROCESSABLE_ENTITY),
        json!([{
            "type": "value_error", "loc": ["body", "files", 1],
            "msg": "Value error, Expected UploadFile, received: <class 'str'>",
            "input": "text", "ctx": {"error": {}},
        }])
    );
    let request = Request::post("/api/jobs")
        .header("host", HOST)
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from("files=abc"))
        .unwrap();
    let response = ctx.send(request).await;
    assert_eq!(
        response.assert_json_error(StatusCode::UNPROCESSABLE_ENTITY)[0]["input"],
        "abc"
    );
    // Malformed multipart framing.
    let request = Request::post("/api/jobs")
        .header("host", HOST)
        .header("content-type", "multipart/form-data")
        .body(Body::from("--x\r\n"))
        .unwrap();
    assert_eq!(
        ctx.send(request)
            .await
            .assert_json_error(StatusCode::BAD_REQUEST),
        "There was an error parsing the body"
    );
    let request = Request::post("/api/jobs")
        .header("host", HOST)
        .header(
            "content-type",
            format!("multipart/form-data; boundary={BOUNDARY}"),
        )
        .body(Body::from(format!("--{BOUNDARY}\r\nbroken")))
        .unwrap();
    assert_eq!(
        ctx.send(request)
            .await
            .assert_json_error(StatusCode::BAD_REQUEST),
        "There was an error parsing the body"
    );
    assert!(ctx.files_with(".eml").is_empty());
}

#[tokio::test]
async fn report_reads_cannot_escape_output_directory() {
    let ctx = Ctx::new();
    let job = ctx.paste().await;
    let id = job["id"].as_str().unwrap();
    for path in [
        "%2e%2e%2finputs%2fpaste.eml",
        "%2e%2e%5cinputs%5cpaste.eml",
        "C%3A%5cWindows%5cwin.ini",
        "..%2f..%2f..%2fmail-servers.json",
        "missing.txt",
    ] {
        let response = ctx.get(&format!("/api/jobs/{id}/files/{path}")).await;
        assert!(
            matches!(response.status.as_u16(), 400 | 404),
            "{path}: {}",
            response.status
        );
    }
}

#[tokio::test]
async fn upload_limit_applies_to_combined_files() {
    let raw = news(0);
    let limit = raw.len() as u64 + 5;
    let ctx = Ctx::with(|settings| settings.max_upload_bytes = limit);
    let response = ctx
        .upload(&[
            ("files", Some("first.eml"), raw.as_bytes()),
            ("files", Some("second.eml"), raw.as_bytes()),
        ])
        .await;
    assert_eq!(
        response.assert_json_error(StatusCode::BAD_REQUEST),
        "Upload exceeds the total maximum allowed size"
    );
    assert_eq!(ctx.get("/api/jobs").await.json(), json!([]));
    assert!(ctx.files_with(".eml").is_empty());
    let paste = ctx
        .post_json(
            "/api/jobs/paste",
            &json!({"content": "x".repeat(limit as usize + 1)}),
        )
        .await;
    assert_eq!(
        paste.assert_json_error(StatusCode::BAD_REQUEST),
        "Pasted source exceeds maximum allowed size"
    );
}

#[tokio::test]
async fn oversized_request_bodies_are_rejected_with_413() {
    let ctx = Ctx::with(|settings| settings.max_upload_bytes = 16);
    let big = vec![b'x'; 1024 * 1024 + 64];
    let response = ctx.upload(&[("files", Some("big.eml"), &big)]).await;
    assert_eq!(
        response.assert_json_error(StatusCode::PAYLOAD_TOO_LARGE),
        "Request exceeds maximum allowed size"
    );
    let content = "y".repeat(1024 * 1024 + 64);
    let response = ctx
        .post_json("/api/jobs/paste", &json!({"content": content}))
        .await;
    assert_eq!(
        response.assert_json_error(StatusCode::PAYLOAD_TOO_LARGE),
        "Request exceeds maximum allowed size"
    );
    assert_eq!(ctx.get("/api/jobs").await.json(), json!([]));
    assert!(ctx.files_with(".eml").is_empty());
}

#[tokio::test]
async fn capacity_is_reported_as_429() {
    let ctx = Ctx::with(|settings| settings.max_active_jobs = 0);
    let response = ctx
        .upload(&[("files", Some("a.eml"), news(0).as_bytes())])
        .await;
    assert_eq!(
        response.assert_json_error(StatusCode::TOO_MANY_REQUESTS),
        CAPACITY_MESSAGE
    );
    let response = ctx
        .post_json("/api/jobs/paste", &json!({"content": news(0)}))
        .await;
    assert_eq!(
        response.assert_json_error(StatusCode::TOO_MANY_REQUESTS),
        CAPACITY_MESSAGE
    );
    let response = ctx
        .post_json(
            "/api/mail/jobs",
            &json!({"email": "user@example.net", "password": "pw"}),
        )
        .await;
    assert_eq!(
        response.assert_json_error(StatusCode::TOO_MANY_REQUESTS),
        CAPACITY_MESSAGE
    );
    assert_eq!(ctx.get("/api/jobs").await.json(), json!([]));
}

#[tokio::test]
async fn zip_expansion_limit_fails_job_before_parsing() {
    let ctx = Ctx::with(|settings| settings.max_expanded_bytes = 100);
    let archive = zip_bytes(
        &[("large.eml", news(0).as_bytes())],
        zip::CompressionMethod::Deflated,
    );
    let response = ctx.upload(&[("files", Some("large.zip"), &archive)]).await;
    let job = ctx.wait(&id_of(&response)).await;
    assert_eq!(job["status"], "failed", "{}", job["log"]);
    assert!(job["error_message"]
        .as_str()
        .unwrap()
        .to_lowercase()
        .contains("size"));
    let id = job["id"].as_str().unwrap();
    assert_eq!(
        ctx.get(&format!("/api/jobs/{id}/download-zip"))
            .await
            .assert_json_error(StatusCode::BAD_REQUEST),
        "Job is not completed"
    );
    assert_eq!(
        ctx.get(&format!("/api/jobs/{id}/files"))
            .await
            .assert_json_error(StatusCode::BAD_REQUEST),
        "Job is not completed"
    );
}

#[tokio::test]
async fn zip_traversal_does_not_write_outside_inputs() {
    let ctx = Ctx::new();
    let archive = zip_bytes(
        &[("../../../outside.eml", news(0).as_bytes())],
        zip::CompressionMethod::Stored,
    );
    let response = ctx.upload(&[("files", Some("unsafe.zip"), &archive)]).await;
    if response.status == StatusCode::CREATED {
        let job = ctx.wait(&id_of(&response)).await;
        assert_eq!(job["status"], "failed", "{}", job["log"]);
    } else {
        assert_eq!(
            response.status,
            StatusCode::BAD_REQUEST,
            "{}",
            response.text()
        );
    }
    assert!(!ctx.data().join("outside.eml").exists());
    assert!(!ctx.root.path().join("outside.eml").exists());
}

// ---------------------------------------------------------------------------
// Mailbox audits
// ---------------------------------------------------------------------------

const MAILBOX: &str = "user@example.net";

fn imap_now() -> String {
    chrono::Utc::now()
        .format("%d-%b-%Y %H:%M:%S +0000")
        .to_string()
}

fn recent_server(password: &str, count: usize) -> FakeImapServer {
    let mut builder = FakeImapServer::builder().credentials(MAILBOX, password);
    for index in 0..count {
        builder = builder.message_with(
            "INBOX",
            FakeMessage::new(news(index).into_bytes())
                .with_uid(41 + index as u32)
                .with_internal_date(&imap_now()),
        );
    }
    builder.start()
}

fn unlock(ctx: &Ctx, secret: &str, port: u16) {
    ctx.state.sessions.unlock(MailAccount::new(
        MAILBOX,
        secret,
        "127.0.0.1",
        port,
        "NONE",
        "smtp.example.net",
        587,
        "STARTTLS",
    ));
}

#[tokio::test]
async fn unlocked_account_audit_reuses_connection_and_does_not_persist_password() {
    let secret = "doctor-ephemeral-password";
    let server = recent_server(secret, 2);
    let ctx = Ctx::new();
    unlock(&ctx, secret, server.port());
    let response = ctx
        .post_json(
            "/api/mail/jobs/account",
            &json!({"account": "User@Example.net", "days": 5}),
        )
        .await;
    let created = response.json();
    assert_eq!(created["source_kind"], "mailbox");
    assert_eq!(created["account_email"], MAILBOX);
    assert_eq!(created["days"], 5);
    assert_eq!(created["filename"], "user@example.net INBOX (5 days)");
    let job = ctx.wait(&id_of(&response)).await;
    assert_eq!(job["status"], "completed", "{}", job["log"]);
    assert_eq!(job["downloaded_messages"], 2);
    assert_eq!(job["total_messages"], 2);
    assert_eq!(job["snapshot_available"], true);
    // The fake server saw the session's password and a read-only INBOX.
    let commands = server.commands();
    assert!(commands.iter().any(|line| line.contains("LOGIN")));
    assert!(
        commands.iter().any(|line| line.contains("EXAMINE")),
        "{commands:?}"
    );
    assert!(!job.to_string().contains(secret));
    for path in doctor_support::walk(ctx.root.path()) {
        let bytes = std::fs::read(&path).unwrap_or_default();
        assert!(
            !bytes.windows(secret.len()).any(|w| w == secret.as_bytes()),
            "{}",
            path.display()
        );
    }
    let id = job["id"].as_str().unwrap();
    let snapshot = ctx
        .get(&format!("/api/jobs/{id}/snapshot-files"))
        .await
        .json();
    assert!(
        snapshot["files"]
            .as_array()
            .unwrap()
            .contains(&json!("report/summary.json")),
        "{snapshot}"
    );
    let summary = ctx
        .get(&format!(
            "/api/jobs/{id}/snapshot-files/report/summary.json"
        ))
        .await;
    assert_eq!(summary.status, StatusCode::OK);
    assert_eq!(summary.json()["total_messages"], 2);
}

#[tokio::test]
async fn account_audits_require_unlock_and_google_fallback_is_explicit() {
    let ctx = Ctx::new();
    let response = ctx
        .post_json(
            "/api/mail/jobs/account",
            &json!({"account": " Locked@Example.net ", "days": 5}),
        )
        .await;
    assert_eq!(
        response.assert_json_error(StatusCode::UNAUTHORIZED),
        json!({"error": "password_required", "email": "locked@example.net"})
    );
    for (body, detail) in [
        (
            json!({"email": "user@gmail.com", "password": "unused", "days": 7}),
            "Google accounts must use OAuth or explicitly choose the app-password fallback.",
        ),
        (
            json!({"email": "user@gmail.com", "password": "abc", "use_app_password": true}),
            "A Google app password must contain 16 characters (letters or digits).",
        ),
        (
            json!({"email": "user@outlook.com", "password": "x"}),
            "Microsoft accounts must use the permission-based OAuth button.",
        ),
        (
            json!({"email": "not an address", "password": "x"}),
            "Enter a valid email address",
        ),
    ] {
        let response = ctx.post_json("/api/mail/jobs", &body).await;
        assert_eq!(response.assert_json_error(StatusCode::BAD_REQUEST), detail);
    }
    let provider = ctx
        .get("/api/mail/providers?email=user@proton.me")
        .await
        .json();
    assert_eq!(provider["imap_port"], 1143);
    assert_eq!(provider["use_ssl"], false);
    assert_eq!(provider["oauth_configured"], Value::Null);
    assert_eq!(provider["oauth_callback_url"], Value::Null);
    let gmail = ctx
        .get("/api/mail/providers?email=%20user%40gmail.com%20")
        .await
        .json();
    assert_eq!(gmail["provider"], "google");
    assert_eq!(gmail["imap_server"], "imap.gmail.com");
    assert_eq!(gmail["oauth_configured"], false);
    assert_eq!(
        gmail["oauth_callback_url"],
        "http://localhost:48101/api/mail/oauth/google/callback"
    );
    let unknown = ctx.get("/api/mail/providers").await.json();
    assert_eq!(unknown["provider"], "credentials");
    let too_long = format!("/api/mail/providers?email={}", "a".repeat(321));
    let issues = ctx
        .get(&too_long)
        .await
        .assert_json_error(StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(issues[0]["loc"], json!(["query", "email"]));
    assert_eq!(issues[0]["type"], "string_too_long");
    // Body validation runs before the session lookup.
    let response = ctx
        .post_json(
            "/api/mail/jobs/account",
            &json!({"account": "x", "days": 0}),
        )
        .await;
    let issues = response.assert_json_error(StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(issues.as_array().unwrap().len(), 2, "{issues}");
}

#[tokio::test]
async fn pop3_accounts_cannot_start_mailbox_audits() {
    let ctx = Ctx::new();
    let mut account = MailAccount::new(
        "pop@example.net",
        "pw",
        "pop.example.net",
        995,
        "SSL/TLS",
        "smtp.example.net",
        465,
        "SSL/TLS",
    );
    account.incoming_mail_protocol = "pop3".into();
    ctx.state.sessions.unlock(account);
    let response = ctx
        .post_json(
            "/api/mail/jobs/account",
            &json!({"account": "pop@example.net"}),
        )
        .await;
    assert_eq!(
        response.assert_json_error(StatusCode::BAD_REQUEST),
        "Inbox Doctor mailbox audits require an IMAP account."
    );
    assert_eq!(ctx.get("/api/jobs").await.json(), json!([]));
}

#[tokio::test]
async fn empty_inbox_window_finishes_healthy_and_survives_restart() {
    let password = "memory-only-password";
    // Only an old message: the SINCE search of the 7-day window is empty.
    let server = FakeImapServer::builder()
        .credentials(MAILBOX, password)
        .message_with(
            "INBOX",
            FakeMessage::new(news(0).into_bytes())
                .with_uid(7)
                .with_internal_date("01-Jan-2020 00:00:00 +0000"),
        )
        .start();
    let ctx = Ctx::new();
    let response = ctx
        .post_json(
            "/api/mail/jobs",
            &json!({
                "email": MAILBOX, "password": password, "days": 7,
                "imap_server": "127.0.0.1", "imap_port": server.port(),
                "incoming_protocol": "NONE",
            }),
        )
        .await;
    let job = ctx.wait(&id_of(&response)).await;
    assert_eq!(job["status"], "healthy", "{}", job["log"]);
    assert_eq!(job["stage"], "healthy");
    assert_eq!(job["progress"], 100);
    assert_eq!(job["error_message"], Value::Null);
    assert!(job["completed_at"].is_string());
    assert_eq!(job["total_messages"], 0);
    assert_eq!(job["downloaded_messages"], 0);
    assert_eq!(job["snapshot_available"], false);
    assert_eq!(job["output_files"], json!([]));
    let log = job["log"].as_str().unwrap();
    assert!(log.contains("No INBOX messages were found in the last 7 day(s)."));
    assert!(!log.contains("Audit failed"));
    // Neither the pipeline nor the packaging ran.
    assert!(ctx.files_with(".html").is_empty());
    assert!(ctx.files_with(".zip").is_empty());
    assert!(!server
        .commands()
        .iter()
        .any(|line| line.contains("BODY.PEEK[]")));
    let id = job["id"].as_str().unwrap();
    let (app, _state) = ctx.restarted();
    let restarted =
        doctor_support::send_to(&app, doctor_support::get(&format!("/api/jobs/{id}"))).await;
    assert_eq!(restarted.json()["status"], "healthy");
    let history = doctor_support::send_to(&app, doctor_support::get("/api/jobs")).await;
    assert_eq!(history.json()[0]["status"], "healthy");
}

/// A downloader reporting `downloaded` of `total` messages without saving any.
fn counting_download(downloaded: usize, total: usize) -> RunnerHooks {
    RunnerHooks {
        pipeline: RunnerHooks::real_pipeline(),
        download: Arc::new(
            move |_: &DownloadOptions<'_>, hooks: &mut DownloadHooks<'_>| {
                (hooks.progress)(0, total)?;
                Ok::<_, DownloadError>((downloaded, total))
            },
        ),
    }
}

#[tokio::test]
async fn found_messages_that_cannot_be_downloaded_still_fail() {
    let ctx = Ctx::new();
    ctx.state.doctor.replace_hooks(counting_download(0, 2));
    let response = ctx
        .post_json(
            "/api/mail/jobs",
            &json!({"email": MAILBOX, "password": "unused", "days": 7}),
        )
        .await;
    let job = ctx.wait(&id_of(&response)).await;
    assert_eq!(job["status"], "failed", "{}", job["log"]);
    assert_eq!(job["total_messages"], 2);
    assert!(job["error_message"]
        .as_str()
        .unwrap()
        .contains("none could be downloaded"));
}

#[tokio::test]
async fn mailbox_login_failures_are_reported_without_the_password() {
    let secret = "wrong-but-secret-password";
    let server = recent_server("the-real-password", 1);
    let ctx = Ctx::new();
    let response = ctx
        .post_json(
            "/api/mail/jobs",
            &json!({
                "email": MAILBOX, "password": secret, "imap_server": "127.0.0.1",
                "imap_port": server.port(), "incoming_protocol": "NONE",
            }),
        )
        .await;
    let job = ctx.wait(&id_of(&response)).await;
    assert_eq!(job["status"], "failed", "{}", job["log"]);
    assert!(!job.to_string().contains(secret));
    assert!(job["log"].as_str().unwrap().contains("Audit failed:"));
}

#[tokio::test]
async fn discard_stops_worker_and_purges_reports() {
    let ctx = Ctx::new();
    let (entered_tx, entered_rx) = std::sync::mpsc::channel::<()>();
    let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
    let entered_tx = Mutex::new(entered_tx);
    let release_rx = Mutex::new(release_rx);
    let blocking: PipelineHook = Arc::new(move |_, _, event, _, _| {
        entered_tx.lock().unwrap().send(()).unwrap();
        let _ = release_rx
            .lock()
            .unwrap()
            .recv_timeout(Duration::from_secs(3));
        event(PipelineEvent::Stage("extract".into()))?;
        Ok(())
    });
    ctx.state.doctor.replace_hooks(RunnerHooks {
        pipeline: blocking,
        download: RunnerHooks::real_download(),
    });
    let response = ctx
        .post_json("/api/jobs/paste", &json!({"content": news(0)}))
        .await;
    let job_id = id_of(&response);
    tokio::task::spawn_blocking(move || entered_rx.recv_timeout(Duration::from_secs(2)))
        .await
        .unwrap()
        .expect("pipeline entered");
    let unblock = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(50));
        let _ = release_tx.send(());
    });
    let response = ctx.post_empty(&format!("/api/jobs/{job_id}/discard")).await;
    unblock.join().unwrap();
    assert_eq!(response.status, StatusCode::OK, "{}", response.text());
    assert_eq!(response.json()["status"], "discarded");
    let job = ctx.wait(&job_id).await;
    assert_eq!(job["status"], "discarded");
    assert!(!job["log"].as_str().unwrap().contains("stage: Parsing"));
    let download = ctx.get(&format!("/api/jobs/{job_id}/download-zip")).await;
    assert!(matches!(download.status.as_u16(), 400 | 404 | 409 | 410));
    assert!(ctx.files_with(".eml").is_empty());
    assert_eq!(
        ctx.post_empty(&format!("/api/jobs/{job_id}/discard"))
            .await
            .assert_json_error(StatusCode::BAD_REQUEST),
        "Job was already discarded"
    );
}

#[tokio::test]
async fn completed_audit_can_be_discarded_without_losing_history() {
    let ctx = Ctx::new();
    let job = ctx.paste().await;
    let id = job["id"].as_str().unwrap();
    let response = ctx.post_empty(&format!("/api/jobs/{id}/discard")).await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text());
    assert_eq!(response.json()["status"], "discarded");
    assert!(ctx.files_with(".eml").is_empty());
    assert!(ctx.files_with("inbox_audit.html").is_empty());
    let history = ctx.get("/api/jobs").await.json();
    assert_eq!(history[0]["id"], id);
    assert_eq!(history[0]["status"], "discarded");
    assert_eq!(
        ctx.get(&format!("/api/jobs/{id}/snapshot-files"))
            .await
            .assert_json_error(StatusCode::NOT_FOUND),
        "No audit snapshot is available yet"
    );
}

// ---------------------------------------------------------------------------
// OAuth
// ---------------------------------------------------------------------------

fn oauth_ctx() -> Ctx {
    Ctx::with(|settings| {
        settings.google_oauth_client_id = "google-client".into();
        settings.google_oauth_client_secret = "google-secret".into();
        settings.microsoft_oauth_client_id = "microsoft-client".into();
    })
}

fn start_request(body: &Value, origin: Option<&str>) -> Request<Body> {
    let mut builder = Request::post("/api/mail/oauth/start")
        .header("host", HOST)
        .header("content-type", "application/json");
    if let Some(origin) = origin {
        builder = builder.header("origin", origin);
    }
    builder.body(Body::from(body.to_string())).unwrap()
}

async fn start(ctx: &Ctx, origin: Option<&str>) -> Value {
    let response = ctx
        .send(start_request(
            &json!({"provider": "google", "email": "user@gmail.com", "days": 3}),
            origin,
        ))
        .await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text());
    response.json()
}

fn assert_callback_page(response: &common::Resp) -> String {
    assert_eq!(response.status, StatusCode::OK, "{}", response.text());
    assert_eq!(
        response.header("content-type"),
        Some("text/html; charset=utf-8")
    );
    assert_eq!(response.header("cache-control"), Some("no-store"));
    assert_eq!(response.header("referrer-policy"), Some("no-referrer"));
    response.text()
}

#[tokio::test]
async fn oauth_start_validates_and_reports_configuration() {
    let ctx = Ctx::new();
    for (body, status, detail) in [
        (
            json!({"provider": "google", "email": "not an address"}),
            StatusCode::BAD_REQUEST,
            "Enter a valid email address",
        ),
        (
            json!({"provider": "yahoo", "email": "user@yahoo.com"}),
            StatusCode::BAD_REQUEST,
            "Unsupported OAuth provider",
        ),
        (
            json!({"provider": "microsoft", "email": "user@gmail.com"}),
            StatusCode::BAD_REQUEST,
            "The OAuth provider does not match this email address",
        ),
        (
            json!({"provider": "google", "email": "user@gmail.com"}),
            StatusCode::SERVICE_UNAVAILABLE,
            "OAuth is not configured; set GOOGLE_OAUTH_CLIENT_ID and GOOGLE_OAUTH_CLIENT_SECRET in .env",
        ),
    ] {
        let response = ctx.send(start_request(&body, None)).await;
        assert_eq!(response.assert_json_error(status), detail, "{body}");
    }
    let busy = Ctx::with(|settings| {
        settings.google_oauth_client_id = "id".into();
        settings.google_oauth_client_secret = "secret".into();
        settings.max_active_jobs = 0;
    });
    let response = busy
        .send(start_request(
            &json!({"provider": "google", "email": "user@gmail.com"}),
            None,
        ))
        .await;
    assert_eq!(
        response.assert_json_error(StatusCode::TOO_MANY_REQUESTS),
        CAPACITY_MESSAGE
    );
}

#[tokio::test]
async fn oauth_callback_posts_to_the_extension_origin_that_started_the_flow() {
    let ctx = oauth_ctx();
    let started = start(&ctx, Some(EXTENSION_ORIGIN)).await;
    // The opener validates messages against the backend origin.
    assert_eq!(started["message_origin"], "http://localhost:48101");
    let url = url::Url::parse(started["authorization_url"].as_str().unwrap()).unwrap();
    assert_eq!(url.host_str(), Some("accounts.google.com"));
    let state = started["state"].as_str().unwrap();
    assert!(url
        .query_pairs()
        .any(|(key, value)| key == "state" && value == state));

    let page = assert_callback_page(
        &ctx.get(&format!(
            "/api/mail/oauth/google/callback?state={state}&error=access_denied"
        ))
        .await,
    );
    assert!(page.contains("<title>Could not connect mailbox</title>"));
    assert!(page.contains(&format!(
            "window.opener.postMessage({{\"type\": \"email-doctor-oauth\", \"error\": \"Permission was not granted by the mailbox provider\"}},\"{EXTENSION_ORIGIN}\");"
        )), "{page}");
    // The state was consumed.
    let page = assert_callback_page(
        &ctx.get(&format!(
            "/api/mail/oauth/google/callback?state={state}&code=c"
        ))
        .await,
    );
    assert!(page.contains("OAuth request is missing, expired, or invalid"));
    assert!(page.contains(",\"http://localhost:3741\");"), "{page}");
}

#[tokio::test]
async fn oauth_callback_without_extension_origin_uses_frontend_url() {
    let ctx = oauth_ctx();
    let started = start(&ctx, None).await;
    let state = started["state"].as_str().unwrap();
    let page = assert_callback_page(
        &ctx.get(&format!("/api/mail/oauth/google/callback?state={state}"))
            .await,
    );
    assert!(page.contains("The OAuth callback was incomplete"));
    assert!(page.contains(",\"http://localhost:3741\");"), "{page}");
    let page = assert_callback_page(&ctx.get("/api/mail/oauth/google/callback").await);
    assert!(page.contains(
        "{\"type\": \"email-doctor-oauth\", \"error\": \"The OAuth callback was incomplete\"}"
    ));
    let long_state = format!("/api/mail/oauth/google/callback?state={}", "s".repeat(201));
    let issues = ctx
        .get(&long_state)
        .await
        .assert_json_error(StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(issues[0]["loc"], json!(["query", "state"]));
}

/// A one-shot token endpoint answering `body` (the provider's token URL).
fn token_server(body: &'static str) -> (String, std::thread::JoinHandle<String>) {
    use std::io::Write;
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}/token", listener.local_addr().unwrap());
    let handle = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut request = Vec::new();
        let mut buffer = [0u8; 4096];
        loop {
            let read = stream.read(&mut buffer).unwrap_or(0);
            request.extend_from_slice(&buffer[..read]);
            let text = String::from_utf8_lossy(&request).to_string();
            if let Some(end) = text.find("\r\n\r\n") {
                let length = text
                    .lines()
                    .find_map(|line| {
                        line.to_ascii_lowercase()
                            .strip_prefix("content-length:")
                            .map(|value| value.trim().parse::<usize>().unwrap())
                    })
                    .unwrap_or(0);
                if request.len() >= end + 4 + length {
                    break;
                }
            }
            if read == 0 {
                break;
            }
        }
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        stream.write_all(response.as_bytes()).unwrap();
        String::from_utf8_lossy(&request).into_owned()
    });
    (url, handle)
}

#[tokio::test]
async fn oauth_code_exchange_starts_a_mailbox_job_with_a_memory_only_token() {
    let ctx = oauth_ctx();
    let used_token = Arc::new(AtomicBool::new(false));
    let seen = used_token.clone();
    ctx.state.doctor.replace_hooks(RunnerHooks {
        pipeline: RunnerHooks::real_pipeline(),
        download: Arc::new(
            move |options: &DownloadOptions<'_>, hooks: &mut DownloadHooks<'_>| {
                seen.store(
                    options.auth.access_token.as_deref() == Some("memory-token")
                        && options.auth.password.is_none()
                        && options.email == "user@gmail.com"
                        && options.days == 3,
                    Ordering::SeqCst,
                );
                (hooks.progress)(0, 0)?;
                Ok::<_, DownloadError>((0, 0))
            },
        ),
    });
    let (token_url, token_request) =
        token_server(r#"{"access_token": "memory-token", "expires_in": 3600}"#);
    ctx.state
        .doctor
        .oauth()
        .override_token_url("google", &token_url);
    let started = start(&ctx, Some(EXTENSION_ORIGIN)).await;
    let state = started["state"].as_str().unwrap();
    let page = assert_callback_page(
        &ctx.get(&format!(
            "/api/mail/oauth/google/callback?state={state}&code=the%20code"
        ))
        .await,
    );
    assert!(page.contains("<h2>Permission granted</h2>"), "{page}");
    let request = token_request.join().unwrap();
    assert!(request.contains("code=the+code"));
    assert!(request.contains("grant_type=authorization_code"));
    let marker = "\"jobId\": \"";
    let start_index = page.find(marker).expect("job id in page") + marker.len();
    let job_id = &page[start_index..start_index + 32];
    assert!(page.contains(&format!(
        "{{\"type\": \"email-doctor-oauth\", \"jobId\": \"{job_id}\"}},\"{EXTENSION_ORIGIN}\");"
    )));
    let job = ctx.wait(job_id).await;
    assert_eq!(job["status"], "healthy", "{}", job["log"]);
    assert_eq!(job["account_email"], "user@gmail.com");
    assert!(used_token.load(Ordering::SeqCst));
    for path in doctor_support::walk(ctx.root.path()) {
        let bytes = std::fs::read(&path).unwrap_or_default();
        assert!(!bytes.windows(12).any(|w| w == b"memory-token"));
    }
}

#[tokio::test]
async fn foreign_origins_never_reach_the_oauth_routes() {
    let ctx = oauth_ctx();
    let response = ctx
        .send(start_request(
            &json!({"provider": "google", "email": "user@gmail.com"}),
            Some("https://evil.example"),
        ))
        .await;
    assert_eq!(response.status, StatusCode::FORBIDDEN);
    assert_eq!(ctx.state.doctor.oauth().pending_flows(), 0);
}

/// The provider redirects the sign-in window to the callback: a top-level
/// cross-site navigation (`Sec-Fetch-Site: cross-site`, no `Origin`). The
/// page must load, or the extension never receives the result.
#[tokio::test]
async fn oauth_callback_accepts_the_provider_redirect_navigation() {
    let ctx = oauth_ctx();
    let started = start(&ctx, Some(EXTENSION_ORIGIN)).await;
    let state = started["state"].as_str().unwrap();
    let request = Request::get(format!(
        "/api/mail/oauth/google/callback?state={state}&error=access_denied"
    ))
    .header("host", "localhost:48101")
    .header("sec-fetch-site", "cross-site")
    .header("sec-fetch-mode", "navigate")
    .header("sec-fetch-dest", "document")
    .body(Body::empty())
    .unwrap();
    let page = assert_callback_page(&ctx.send(request).await);
    assert!(page.contains(EXTENSION_ORIGIN));
}
