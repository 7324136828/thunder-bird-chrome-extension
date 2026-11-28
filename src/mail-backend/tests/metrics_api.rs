//! HTTP tests of `GET /api/email-metrics` and `GET /api/email-metrics/schedule`
//! (ports of the API parts of `backend/tests/test_email_metrics.py` and
//! `test_email_metrics_integration.py`). Store-level behavior is covered by
//! `mail-doctor/tests/infra_db_metrics.rs` and `infra_scheduler.rs`.

mod common;
mod doctor_support;

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::http::StatusCode;
use mail_core::MailAccount;
use mail_doctor::db::{JobField, NewJob};
use mail_doctor::mailbox_download::{DownloadError, DownloadHooks, DownloadOptions, MailboxAuth};
use mail_doctor::runner::RunnerHooks;
use serde_json::{json, Value};

use doctor_support::{message, Ctx};

/// Python `wait_for_metrics(job_id)`.
async fn wait_for_metrics(ctx: &Ctx, job_id: &str) -> Value {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let response = ctx.get("/api/email-metrics").await;
        assert_eq!(response.status, StatusCode::OK, "{}", response.text());
        if let Some(run) = response.json()["runs"]
            .as_array()
            .unwrap()
            .iter()
            .find(|run| run["id"] == job_id)
        {
            return run.clone();
        }
        let job = ctx.get(&format!("/api/jobs/{job_id}")).await.json();
        assert_ne!(job["status"], "failed", "{}", job["log"]);
        assert!(Instant::now() < deadline, "no metrics published: {job}");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// A completed mailbox job whose outputs hold `records`, captured into the
/// metrics store (Python `self.job(...)` + `metrics.capture`).
fn captured_job(ctx: &Ctx, index: usize, account: &str, records: &[Value]) {
    let runner = &ctx.state.doctor;
    let job_id = format!("{index:032x}");
    let directory = runner.create_job_dirs(&job_id).unwrap();
    runner
        .db()
        .create_job(
            NewJob::new(&job_id, "mailbox", 0, directory.to_string_lossy()).mailbox(account, 7),
        )
        .unwrap();
    runner
        .db()
        .update_job(
            &job_id,
            &[
                JobField::status("completed"),
                JobField::CompletedAt(Some("2026-10-10T22:01:00+00:00".into())),
            ],
            false,
        )
        .unwrap();
    let lines: Vec<String> = records.iter().map(Value::to_string).collect();
    std::fs::write(directory.join("outputs/messages.jsonl"), lines.join("\n")).unwrap();
    let job = runner.db().get_job(&job_id).unwrap().unwrap();
    assert!(runner.metrics().capture(&job, &directory).unwrap());
}

#[tokio::test]
async fn api_filters_accounts_without_requiring_mailbox_credentials() {
    let ctx = Ctx::new();
    captured_job(
        &ctx,
        1,
        "First@Example.COM",
        &[json!({"from_domain": "first.org", "size_bytes": 100})],
    );
    captured_job(
        &ctx,
        2,
        "second@example.com",
        &[json!({"from_domain": "second.org", "size_bytes": 100})],
    );
    let all = ctx.get("/api/email-metrics").await;
    assert_eq!(all.status, StatusCode::OK);
    assert_eq!(all.header("content-type"), Some("application/json"));
    assert_eq!(all.json()["runs"].as_array().unwrap().len(), 2);

    let filtered = ctx
        .get("/api/email-metrics?account=%20FIRST%40EXAMPLE.COM%20")
        .await;
    assert_eq!(filtered.status, StatusCode::OK);
    let result = filtered.json();
    assert_eq!(result["runs"].as_array().unwrap().len(), 1);
    assert_eq!(result["domains"], json!(["first.org"]));
    assert_eq!(
        result["accounts"],
        json!(["first@example.com", "second@example.com"])
    );
    let run = &result["runs"][0];
    assert_eq!(run["account_email"], "first@example.com");
    assert_eq!(
        run["domains"],
        json!([{"domain": "first.org", "message_count": 1, "size_bytes": 100}])
    );
    // A blank account is "no filter".
    let blank = ctx.get("/api/email-metrics?account=%20%20").await.json();
    assert_eq!(blank["runs"].as_array().unwrap().len(), 2);
    assert_eq!(
        ctx.get("/api/email-metrics?account=missing@example.com")
            .await
            .json()["runs"],
        json!([])
    );
    for invalid in [
        "invalid%20address",
        "a%40b%40example.com",
        "a%01%40example.com",
    ] {
        let response = ctx
            .get(&format!("/api/email-metrics?account={invalid}"))
            .await;
        assert_eq!(
            response.assert_json_error(StatusCode::BAD_REQUEST),
            "Enter a valid account email address",
            "{invalid}"
        );
    }
    let long = "a".repeat(321);
    let response = ctx.get(&format!("/api/email-metrics?account={long}")).await;
    assert_eq!(
        response.assert_json_error(StatusCode::UNPROCESSABLE_ENTITY),
        json!([{
            "type": "string_too_long", "loc": ["query", "account"],
            "msg": "String should have at most 320 characters", "input": long,
            "ctx": {"max_length": 320},
        }])
    );
}

#[tokio::test]
async fn completed_worker_records_metrics_that_survive_discard_and_app_restart() {
    let ctx = Ctx::new();
    let raw = "From: Weekly <weekly@updates.example.org>\r\nTo: user@example.com\r\n\
               Subject: Weekly digest\r\n\r\nDigest contents.";
    let response = ctx
        .post_json(
            "/api/jobs/paste",
            &json!({"content": raw, "filename": "digest.eml"}),
        )
        .await;
    assert_eq!(response.status, StatusCode::CREATED, "{}", response.text());
    let job_id = response.json()["id"].as_str().unwrap().to_string();
    let run = wait_for_metrics(&ctx, &job_id).await;
    let job = ctx.get(&format!("/api/jobs/{job_id}")).await.json();
    assert_eq!(run["total_messages"], 1);
    assert_eq!(run["total_size_bytes"], job["file_size"]);
    assert_eq!(run["domains"][0]["domain"], "updates.example.org");
    let runs = ctx.get("/api/email-metrics").await.json()["runs"].clone();
    assert_eq!(runs.as_array().unwrap().len(), 1);
    doctor_support::wait_job(&ctx.app, &ctx.state, &job_id).await;
    let discard = ctx.post_empty(&format!("/api/jobs/{job_id}/discard")).await;
    assert_eq!(discard.status, StatusCode::OK, "{}", discard.text());
    assert_eq!(ctx.get("/api/email-metrics").await.json()["runs"], runs);
    let (app, _state) = ctx.restarted();
    let restarted = doctor_support::send_to(&app, doctor_support::get("/api/email-metrics")).await;
    assert_eq!(restarted.json()["runs"], runs);
}

#[tokio::test]
async fn ad_hoc_metrics_survive_discard_and_restart_without_message_files() {
    let ctx = Ctx::new();
    let raw = message(1, "news@updates.vendor.net", true);
    let response = ctx
        .post_json("/api/jobs/paste", &json!({"content": raw}))
        .await;
    assert_eq!(response.status, StatusCode::CREATED, "{}", response.text());
    let job_id = response.json()["id"].as_str().unwrap().to_string();
    let run = wait_for_metrics(&ctx, &job_id).await;
    assert_eq!(run["run_kind"], "adhoc");
    assert_eq!(run["source_kind"], "upload");
    assert_eq!(run["total_messages"], 1);
    assert_eq!(
        run["domains"],
        json!([{
            "domain": "updates.vendor.net", "message_count": 1, "size_bytes": raw.len(),
        }])
    );
    assert_eq!(run["total_size_bytes"], raw.len());
    doctor_support::wait_job(&ctx.app, &ctx.state, &job_id).await;
    let discard = ctx.post_empty(&format!("/api/jobs/{job_id}/discard")).await;
    assert_eq!(discard.status, StatusCode::OK);
    assert!(ctx.files_with(".eml").is_empty());
    let (app, _state) = ctx.restarted();
    let restarted = doctor_support::send_to(&app, doctor_support::get("/api/email-metrics")).await;
    assert_eq!(restarted.json()["runs"], json!([run]));
}

type Windows = Arc<Mutex<Vec<(Option<String>, Option<String>)>>>;

/// A downloader recording the window and writing `raw` messages.
fn recording_download(raw: Vec<Vec<u8>>, total: usize, windows: Windows) -> RunnerHooks {
    RunnerHooks {
        pipeline: RunnerHooks::real_pipeline(),
        download: Arc::new(
            move |options: &DownloadOptions<'_>, hooks: &mut DownloadHooks<'_>| {
                windows.lock().unwrap().push((
                    options.window_start.map(str::to_string),
                    options.window_end.map(str::to_string),
                ));
                if !raw.is_empty() {
                    std::fs::create_dir_all(options.output_dir)?;
                }
                for (index, data) in raw.iter().enumerate() {
                    std::fs::write(options.output_dir.join(format!("{}.eml", index + 1)), data)?;
                }
                (hooks.progress)(raw.len(), total)?;
                Ok::<_, DownloadError>((raw.len(), total))
            },
        ),
    }
}

fn scheduled_job(ctx: &Ctx, job_id: &str, start: Option<&str>, end: Option<&str>) {
    let runner = &ctx.state.doctor;
    let directory = runner.create_job_dirs(job_id).unwrap();
    let mut job = NewJob::new(job_id, "weekly", 0, directory.to_string_lossy())
        .mailbox("user@example.net", 7);
    job.run_kind = "scheduled".into();
    job.scheduled_for = end.map(str::to_string);
    job.window_start = start.map(str::to_string);
    job.window_end = end.map(str::to_string);
    runner.db().create_job(job).unwrap();
}

fn password(secret: &str) -> MailboxAuth {
    let mut auth = MailboxAuth::default();
    auth.password = Some(secret.into());
    auth
}

#[tokio::test]
async fn scheduled_catchup_uses_the_original_window_and_publishes_zero_metrics() {
    let ctx = Ctx::new();
    let start = "2026-09-05T22:00:00+00:00";
    let end = "2026-09-12T22:00:00+00:00";
    let job_id = "b".repeat(32);
    scheduled_job(&ctx, &job_id, Some(start), Some(end));
    let windows: Windows = Arc::default();
    ctx.state
        .doctor
        .replace_hooks(recording_download(Vec::new(), 0, windows.clone()));
    ctx.state
        .doctor
        .start_mailbox_job(&job_id, password("memory-only"))
        .unwrap();
    let run = wait_for_metrics(&ctx, &job_id).await;
    assert_eq!(
        windows.lock().unwrap().as_slice(),
        [(Some(start.to_string()), Some(end.to_string()))]
    );
    assert_eq!(run["run_kind"], "scheduled");
    assert_eq!(run["scheduled_for"], end);
    assert_eq!(run["window_start"], start);
    assert_eq!(run["window_end"], end);
    assert_eq!(
        (
            &run["total_messages"],
            &run["total_size_bytes"],
            &run["domains"]
        ),
        (&json!(0), &json!(0), &json!([]))
    );
    let all = ctx.get("/api/email-metrics").await.text();
    assert!(!all.contains("memory-only"));
    let job = doctor_support::wait_job(&ctx.app, &ctx.state, &job_id).await;
    assert_eq!(job["status"], "healthy");
    assert!(job["log"].as_str().unwrap().contains(&format!(
        "No INBOX messages were found in [{start}, {end})."
    )));
}

#[tokio::test]
async fn old_catchup_messages_remain_in_the_audit_briefing() {
    let ctx = Ctx::new();
    let job_id = "c".repeat(32);
    scheduled_job(
        &ctx,
        &job_id,
        Some("2020-09-05T22:00:00+00:00"),
        Some("2020-09-12T22:00:00+00:00"),
    );
    let raw = b"From: sender@old.example\r\nTo: user@example.net\r\n\
Date: Tue, 08 Sep 2020 12:00:00 +0000\r\nSubject: Historical weekly message\r\n\r\nOld mail."
        .to_vec();
    let windows: Windows = Arc::default();
    ctx.state
        .doctor
        .replace_hooks(recording_download(vec![raw.clone()], 1, windows));
    ctx.state
        .doctor
        .start_mailbox_job(&job_id, password("memory-only"))
        .unwrap();
    let run = wait_for_metrics(&ctx, &job_id).await;
    assert_eq!(run["total_messages"], 1);
    assert_eq!(run["total_size_bytes"], raw.len());
    let briefing = ctx
        .get(&format!(
            "/api/jobs/{job_id}/files/report/recent_emails.csv"
        ))
        .await;
    assert_eq!(briefing.status, StatusCode::OK, "{}", briefing.text());
    assert!(briefing.text().contains("Historical weekly message"));
}

#[tokio::test]
async fn incomplete_weekly_download_fails_without_publishing_a_metric() {
    let ctx = Ctx::new();
    let job_id = "d".repeat(32);
    scheduled_job(&ctx, &job_id, None, None);
    let windows: Windows = Arc::default();
    let raw = message(1, "news@example.org", false).into_bytes();
    ctx.state
        .doctor
        .replace_hooks(recording_download(vec![raw], 2, windows));
    ctx.state
        .doctor
        .start_mailbox_job(&job_id, password("memory-only"))
        .unwrap();
    let job = doctor_support::wait_job(&ctx.app, &ctx.state, &job_id).await;
    assert_eq!(job["status"], "failed", "{}", job["log"]);
    assert!(job["error_message"]
        .as_str()
        .unwrap()
        .contains("will be retried"));
    assert_eq!(
        ctx.get("/api/email-metrics").await.json()["runs"],
        json!([])
    );
}

#[tokio::test]
async fn unlock_registers_a_persistent_schedule_and_restart_shows_locked() {
    let ctx = Ctx::new();
    // What `POST /api/accounts/unlock` does after verifying the login.
    ctx.state.sessions.unlock(MailAccount::new(
        "user@example.net",
        "memory-only",
        "imap.example.net",
        993,
        "SSL/TLS",
        "smtp.example.net",
        587,
        "STARTTLS",
    ));
    ctx.state
        .audit_scheduler
        .register("user@example.net", None)
        .unwrap();
    let response = ctx.get("/api/email-metrics/schedule").await;
    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(response.header("content-type"), Some("application/json"));
    let schedule = response.json();
    assert_eq!(schedule["enabled"], true);
    assert_eq!(
        (&schedule["weekday"], &schedule["hour"], &schedule["minute"]),
        (&json!(5), &json!(18), &json!(0))
    );
    assert_eq!(schedule["timezone"], "America/New_York");
    let accounts = schedule["accounts"].as_array().unwrap();
    assert_eq!(accounts.len(), 1);
    let account = &accounts[0];
    assert_eq!(account["email"], "user@example.net");
    assert_eq!(account["unlocked"], true);
    assert_eq!(account["pending_runs"], 0);
    assert_eq!(account["last_run_at"], Value::Null);
    assert_eq!(account["last_error"], Value::Null);
    // Field order of Python's dict.
    let text = response.text();
    let positions: Vec<usize> = [
        r#""email""#,
        r#""next_run_at""#,
        r#""last_run_at""#,
        r#""pending_runs""#,
        r#""unlocked""#,
        r#""last_error""#,
    ]
    .iter()
    .map(|key| text.find(key).unwrap())
    .collect();
    assert!(positions.windows(2).all(|pair| pair[0] < pair[1]), "{text}");
    let (app, _state) = ctx.restarted();
    let restarted =
        doctor_support::send_to(&app, doctor_support::get("/api/email-metrics/schedule")).await;
    let stored = restarted.json()["accounts"][0].clone();
    assert_eq!(stored["next_run_at"], account["next_run_at"]);
    assert_eq!(stored["unlocked"], false);
    assert!(!stored.to_string().contains("memory-only"));
}

#[tokio::test]
async fn empty_schedule_and_metrics_need_no_session() {
    let ctx = Ctx::new();
    assert_eq!(
        ctx.get("/api/email-metrics").await.json(),
        json!({"runs": [], "domains": [], "accounts": []})
    );
    assert_eq!(
        ctx.get("/api/email-metrics/schedule").await.json(),
        json!({
            "enabled": true, "timezone": "America/New_York", "weekday": 5,
            "hour": 18, "minute": 0, "accounts": [],
        })
    );
}
