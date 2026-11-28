//! Job registry and durable metrics (ports of `backend/tests/test_email_metrics.py`
//! and the database parts of `test_doctor.py`).

use mail_doctor::config::DoctorSettings;
use mail_doctor::db::{parse_aware_utc, JobField, JobRecord, JobStore, NewJob};
use mail_doctor::metrics::{validate_account_query, DomainMetric, MetricStore};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};

struct Fixture {
    _directory: tempfile::TempDir,
    settings: DoctorSettings,
    db: JobStore,
    metrics: MetricStore,
    next_id: u32,
}

impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let settings = DoctorSettings::with_defaults(directory.path());
        let db = JobStore::new(&settings);
        db.init_db().unwrap();
        let metrics = MetricStore::new(db.clone());
        metrics.init_db().unwrap();
        Self {
            _directory: directory,
            settings,
            db,
            metrics,
            next_id: 0,
        }
    }

    fn job_dir_for(&self, job_id: &str) -> PathBuf {
        self.settings.jobs_root().join(job_id)
    }

    /// Python `EmailMetricsTests.job`: a mailbox job with `created_at`
    /// overridden and optional `messages.jsonl` records.
    fn job(&mut self, records: Option<&[Value]>, status: &str) -> (JobRecord, PathBuf) {
        self.next_id += 1;
        let job_id = format!("{:032x}", self.next_id);
        let directory = self.job_dir_for(&job_id);
        for name in ["inputs", "work", "outputs", "archive"] {
            std::fs::create_dir_all(directory.join(name)).unwrap();
        }
        self.db
            .create_job(
                NewJob::new(&job_id, "mailbox", 0, directory.to_string_lossy())
                    .mailbox("user@example.com", 7),
            )
            .unwrap();
        self.db
            .update_job(
                &job_id,
                &[
                    JobField::status(status),
                    JobField::CompletedAt(Some("2026-10-10T22:01:00+00:00".into())),
                ],
                false,
            )
            .unwrap();
        let mut job = self.db.get_job(&job_id).unwrap().unwrap();
        job.created_at = "2026-10-10T22:00:00+00:00".into();
        if let Some(records) = records {
            write(&directory, records, "messages.jsonl");
        }
        (job, directory)
    }
}

fn write(directory: &Path, records: &[Value], filename: &str) {
    let text: Vec<String> = records.iter().map(Value::to_string).collect();
    std::fs::write(directory.join("outputs").join(filename), text.join("\n")).unwrap();
}

fn domain(name: &str, count: i64, size: i64) -> DomainMetric {
    DomainMetric {
        domain: name.into(),
        message_count: count,
        size_bytes: size,
    }
}

#[test]
fn exact_sender_domains_sizes_and_unknown_are_counted() {
    let mut f = Fixture::new();
    let (job, directory) = f.job(
        Some(&[
            json!({"from_domain": "Mail.Example.COM.", "sender_group": "alias.org", "size_bytes": 400}),
            json!({"from_domain": "mail.example.com", "size_bytes": 60}),
            json!({"from_domain": "example.com", "size_bytes": 40}),
            json!({"from_domain": "BÜCHER.example", "size_bytes": 25}),
            json!({"from_domain": "xn--bcher-kva.example", "size_bytes": 15}),
            json!({"sender_domain": "Other.Example", "sender_group": "alias.org", "size_bytes": 10}),
            json!({"from_domain": "", "size_bytes": 5}),
        ]),
        "completed",
    );
    assert!(f.metrics.capture(&job, &directory).unwrap());
    let result = f.metrics.list_metrics(None).unwrap();
    let run = &result.runs[0];
    assert_eq!((run.total_messages, run.total_size_bytes), (7, 555));
    assert_eq!(
        run.domains,
        [
            domain("(unknown)", 1, 5),
            domain("example.com", 1, 40),
            domain("mail.example.com", 2, 460),
            domain("other.example", 1, 10),
            domain("xn--bcher-kva.example", 2, 40),
        ]
    );
    assert!(!result.domains.contains(&"alias.org".to_string()));
    assert_eq!(run.run_kind, "adhoc");
}

#[test]
fn grouped_artifact_fallback_still_uses_actual_sender_domain() {
    let mut f = Fixture::new();
    let (job, directory) = f.job(None, "completed");
    write(
        &directory,
        &[
            json!({"from_domain": "sub.example.com", "sender_domain": "sub.example.com", "sender_group": "example.com", "size_bytes": 512}),
        ],
        "messages_grouped.jsonl",
    );
    assert!(f.metrics.capture(&job, &directory).unwrap());
    assert_eq!(
        f.metrics.list_metrics(None).unwrap().domains,
        ["sub.example.com"]
    );
}

#[test]
fn extraction_artifact_is_preferred_to_grouped_artifact() {
    let mut f = Fixture::new();
    let (job, directory) = f.job(
        Some(&[json!({"from_domain": "original.example", "size_bytes": 100})]),
        "completed",
    );
    write(
        &directory,
        &[json!({"sender_domain": "other.example", "size_bytes": 999})],
        "messages_grouped.jsonl",
    );
    f.metrics.capture(&job, &directory).unwrap();
    assert_eq!(
        f.metrics.list_metrics(None).unwrap().domains,
        ["original.example"]
    );
}

#[test]
fn healthy_audit_records_a_real_zero_without_artifacts() {
    let mut f = Fixture::new();
    let (mut job, directory) = f.job(None, "healthy");
    job.total_messages = Some(0);
    job.downloaded_messages = 0;
    std::fs::remove_dir_all(&directory).unwrap();
    assert!(f.metrics.capture(&job, &directory).unwrap());
    let run = &f.metrics.list_metrics(None).unwrap().runs[0];
    assert_eq!(
        (run.total_messages, run.total_size_bytes, run.domains.len()),
        (0, 0, 0)
    );
}

#[test]
fn inconsistent_healthy_state_is_not_charted_as_zero() {
    let mut f = Fixture::new();
    let (mut job, directory) = f.job(None, "healthy");
    job.total_messages = Some(2);
    assert!(!f.metrics.capture(&job, &directory).unwrap());
    assert!(f.metrics.list_metrics(None).unwrap().runs.is_empty());
}

#[test]
fn completed_partial_mailbox_and_truncated_artifact_are_omitted() {
    let mut f = Fixture::new();
    for downloaded in [1, 2] {
        let (mut job, directory) = f.job(
            Some(&[json!({"from_domain": "example.org", "size_bytes": 10})]),
            "completed",
        );
        job.total_messages = Some(2);
        job.downloaded_messages = downloaded;
        assert!(
            !f.metrics.capture(&job, &directory).unwrap(),
            "{downloaded}"
        );
    }
    assert!(f.metrics.list_metrics(None).unwrap().runs.is_empty());
}

#[test]
fn snapshot_survives_workspace_discard_and_restart() {
    let mut f = Fixture::new();
    let (job, directory) = f.job(
        Some(&[json!({"from_domain": "example.org", "size_bytes": 4096})]),
        "completed",
    );
    assert!(f.metrics.capture(&job, &directory).unwrap());
    f.db.update_job(&job.id, &[JobField::status("discarded")], false)
        .unwrap();
    std::fs::remove_dir_all(&directory).unwrap();
    let restarted = MetricStore::new(JobStore::new(&f.settings));
    restarted.init_db().unwrap();
    let run = &restarted.list_metrics(None).unwrap().runs[0];
    assert_eq!(
        (run.id.as_str(), run.total_messages, run.total_size_bytes),
        (job.id.as_str(), 1, 4096)
    );
}

#[test]
fn capture_is_idempotent_even_after_source_changes() {
    let mut f = Fixture::new();
    let (job, directory) = f.job(
        Some(&[json!({"from_domain": "example.org", "size_bytes": 4})]),
        "completed",
    );
    assert!(f.metrics.capture(&job, &directory).unwrap());
    write(
        &directory,
        &[json!({"from_domain": "example.org", "size_bytes": 9000})],
        "messages.jsonl",
    );
    assert!(!f.metrics.capture(&job, &directory).unwrap());
    let runs = f.metrics.list_metrics(None).unwrap().runs;
    assert_eq!(runs.len(), 1);
    assert_eq!(runs[0].total_size_bytes, 4);
}

#[test]
fn concurrent_captures_store_one_snapshot() {
    let mut f = Fixture::new();
    let (job, directory) = f.job(
        Some(&[json!({"from_domain": "example.org", "size_bytes": 10})]),
        "completed",
    );
    let outcomes: Vec<bool> = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..5)
            .map(|_| scope.spawn(|| f.metrics.capture(&job, &directory).unwrap()))
            .collect();
        handles.into_iter().map(|h| h.join().unwrap()).collect()
    });
    assert_eq!(outcomes.iter().filter(|stored| **stored).count(), 1);
    let run = &f.metrics.list_metrics(None).unwrap().runs[0];
    assert_eq!(run.domains, [domain("example.org", 1, 10)]);
}

#[test]
fn backfill_skips_failed_partial_discarded_and_unavailable_runs() {
    let mut f = Fixture::new();
    let (complete, _) = f.job(
        Some(&[json!({"from_domain": "example.org", "size_bytes": 20})]),
        "completed",
    );
    let (mut healthy, _) = f.job(None, "healthy");
    healthy.total_messages = Some(0);
    let (missing, _) = f.job(None, "completed");
    let mut jobs = vec![complete.clone(), healthy.clone(), missing];
    for status in ["failed", "in_progress", "queued", "discarded"] {
        jobs.push(
            f.job(
                Some(&[json!({"from_domain": "example.org", "size_bytes": 10})]),
                status,
            )
            .0,
        );
    }
    let dirs = |id: &str| Some(f.job_dir_for(id));
    assert_eq!(f.metrics.backfill(&jobs, dirs).unwrap(), 2);
    assert_eq!(
        f.metrics
            .backfill(&[complete.clone(), healthy.clone()], dirs)
            .unwrap(),
        0
    );
    let mut ids: Vec<String> = f
        .metrics
        .list_metrics(None)
        .unwrap()
        .runs
        .into_iter()
        .map(|r| r.id)
        .collect();
    ids.sort();
    let mut expected = vec![complete.id, healthy.id];
    expected.sort();
    assert_eq!(ids, expected);
    // An invalid job directory is skipped, not an error.
    assert_eq!(f.metrics.backfill(&jobs, |_| None).unwrap(), 0);
}

#[test]
fn malformed_or_incomplete_artifact_is_omitted_not_partially_counted() {
    let mut f = Fixture::new();
    let bad: Vec<Vec<Value>> = vec![
        vec![json!({"from_domain": "example.org", "size_bytes": -1})],
        vec![json!({"from_domain": "example.org"})],
        vec![json!({"from_domain": "example.org", "size_bytes": true})],
        vec![json!({"from_domain": "example.org", "size_bytes": 1.5})],
        vec![json!({"from_domain": "example.org", "size_bytes": 9223372036854775808u64})],
        vec![
            json!({"from_domain": "example.org", "size_bytes": 1}),
            json!({"from_domain": "example.org"}),
        ],
        vec![],
    ];
    for records in bad {
        let (job, directory) = f.job(Some(&records), "completed");
        assert!(!f.metrics.capture(&job, &directory).unwrap(), "{records:?}");
    }
    let (job, directory) = f.job(None, "completed");
    std::fs::write(
        directory.join("outputs/messages.jsonl"),
        "{\"size_bytes\":10}\n{",
    )
    .unwrap();
    assert!(!f.metrics.capture(&job, &directory).unwrap());
    assert!(f.metrics.list_metrics(None).unwrap().runs.is_empty());
}

#[test]
fn scheduled_metadata_is_persisted_and_runs_are_in_chronological_order() {
    let mut f = Fixture::new();
    let (mut later, later_dir) = f.job(
        Some(&[json!({"from_domain": "example.org", "size_bytes": 1})]),
        "completed",
    );
    later.completed_at = Some("2026-10-17T22:01:00+00:00".into());
    later.run_kind = "scheduled".into();
    later.scheduled_for = Some("2026-10-17T18:00:00-04:00".into());
    later.window_start = Some("2026-10-10T22:00:00+00:00".into());
    later.window_end = Some("2026-10-17T22:00:00+00:00".into());
    let (mut earlier, earlier_dir) = f.job(
        Some(&[json!({"from_domain": "example.org", "size_bytes": 2})]),
        "completed",
    );
    earlier.completed_at = Some("2026-10-10T18:01:00-04:00".into());
    f.metrics.capture(&later, &later_dir).unwrap();
    f.metrics.capture(&earlier, &earlier_dir).unwrap();
    let runs = f.metrics.list_metrics(None).unwrap().runs;
    assert_eq!(
        [runs[0].id.as_str(), runs[1].id.as_str()],
        [earlier.id.as_str(), later.id.as_str()]
    );
    let run = &runs[1];
    assert_eq!(run.run_kind, "scheduled");
    assert_eq!(run.created_at, later.created_at);
    assert_eq!(run.completed_at, later.completed_at);
    assert_eq!(run.scheduled_for, later.scheduled_for);
    assert_eq!(run.window_start, later.window_start);
    assert_eq!(run.window_end, later.window_end);
    assert_eq!(run.days, later.days);
    assert_eq!(run.source_kind, later.source_kind);
}

#[test]
fn accounts_are_filtered_and_normalized() {
    let mut f = Fixture::new();
    for (account, domain_name) in [
        ("First@Example.COM", "first.org"),
        ("second@example.com", "second.org"),
    ] {
        let (mut job, directory) = f.job(
            Some(&[json!({"from_domain": domain_name, "size_bytes": 100})]),
            "completed",
        );
        job.account_email = Some(account.into());
        f.metrics.capture(&job, &directory).unwrap();
    }
    assert_eq!(f.metrics.list_metrics(None).unwrap().runs.len(), 2);
    let account = validate_account_query(Some(" FIRST@EXAMPLE.COM ")).unwrap();
    let result = f.metrics.list_metrics(account.as_deref()).unwrap();
    assert_eq!(result.runs.len(), 1);
    assert_eq!(result.domains, ["first.org"]);
    assert_eq!(result.accounts, ["first@example.com", "second@example.com"]);
    assert!(f
        .metrics
        .list_metrics(Some("missing@example.com"))
        .unwrap()
        .runs
        .is_empty());
    assert_eq!(
        validate_account_query(Some("invalid address"))
            .unwrap_err()
            .status(),
        400
    );
    assert_eq!(
        validate_account_query(Some(&"a".repeat(321)))
            .unwrap_err()
            .status(),
        422
    );
    let body = serde_json::to_value(&result).unwrap();
    assert_eq!(body["runs"][0]["account_email"], "first@example.com");
    assert_eq!(
        body["runs"][0]["domains"],
        json!([{"domain": "first.org", "message_count": 1, "size_bytes": 100}])
    );
}

// ---------------------------------------------------------------------------
// Job registry (db.py)
// ---------------------------------------------------------------------------

#[test]
fn interrupted_jobs_are_reported_as_failed_after_restart() {
    let f = Fixture::new();
    let job_id = "a".repeat(32);
    f.db.create_job(NewJob::new(&job_id, "interrupted.eml", 1, ""))
        .unwrap();
    JobStore::new(&f.settings).init_db().unwrap();
    let job = f.db.get_job(&job_id).unwrap().unwrap();
    assert_eq!(job.status, "failed");
    assert_eq!(job.stage.as_deref(), Some("interrupted"));
    assert!(job.error_message.unwrap().contains("stopped"));
    assert!(job
        .log
        .ends_with("Audit interrupted by application restart.\n"));
    assert!(job.completed_at.is_some());
}

#[test]
fn restart_normalizes_only_previous_empty_mailbox_failures() {
    let f = Fixture::new();
    let error = "No INBOX messages were found in the last 7 day(s).";
    let cases = [
        ("mailbox", 0, error),
        ("mailbox", 2, error),
        ("upload", 0, error),
        ("mailbox", 0, "Mailbox sign-in failed."),
        (
            "mailbox",
            0,
            "No INBOX messages were found in the last 3 day(s).",
        ),
    ];
    for (index, (source_kind, total, message)) in cases.iter().enumerate() {
        let job_id = index.to_string().repeat(32);
        let mut job = NewJob::new(&job_id, "previous audit", 0, "");
        job.source_kind = source_kind.to_string();
        job.days = Some(7);
        f.db.create_job(job).unwrap();
        f.db.update_job(
            &job_id,
            &[
                JobField::status("failed"),
                JobField::stage("failed"),
                JobField::TotalMessages(Some(*total)),
                JobField::ErrorMessage(Some(message.to_string())),
            ],
            false,
        )
        .unwrap();
        f.db.append_log(&job_id, &format!("Audit failed: {message}"), false)
            .unwrap();
    }
    JobStore::new(&f.settings).init_db().unwrap();
    let normalized = f.db.get_job(&"0".repeat(32)).unwrap().unwrap();
    assert_eq!(normalized.status, "healthy");
    assert_eq!(normalized.progress, 100);
    assert_eq!(normalized.error_message, None);
    assert!(!normalized.log.contains("Audit failed"));
    assert!(normalized.log.contains(error));
    for index in 1..5 {
        let job =
            f.db.get_job(&index.to_string().repeat(32))
                .unwrap()
                .unwrap();
        assert_eq!(job.status, "failed", "{index}");
    }
}

#[test]
fn mailbox_jobs_get_a_default_window_and_list_newest_first() {
    let f = Fixture::new();
    let first =
        f.db.create_job(NewJob::new("1".repeat(32), "x", 0, "").mailbox("u@example.com", 3))
            .unwrap();
    let start = parse_aware_utc(first.window_start.as_deref().unwrap()).unwrap();
    let end = parse_aware_utc(first.window_end.as_deref().unwrap()).unwrap();
    assert_eq!(first.window_end.as_deref(), Some(first.created_at.as_str()));
    assert_eq!((end - start).num_days(), 3);
    let upload =
        f.db.create_job(NewJob::new("2".repeat(32), "y", 5, ""))
            .unwrap();
    assert_eq!((upload.window_start, upload.window_end), (None, None));
    assert_eq!(
        (upload.status.as_str(), upload.run_kind.as_str()),
        ("queued", "adhoc")
    );
    let ids: Vec<String> =
        f.db.list_jobs()
            .unwrap()
            .into_iter()
            .map(|job| job.id)
            .collect();
    assert_eq!(ids, ["2".repeat(32), "1".repeat(32)]);
}

#[test]
fn active_only_updates_and_logs_skip_terminal_jobs() {
    let f = Fixture::new();
    let job_id = "b".repeat(32);
    f.db.create_job(NewJob::new(&job_id, "x", 0, "")).unwrap();
    assert!(f
        .db
        .update_job(&job_id, &[JobField::Progress(5)], true)
        .unwrap());
    assert!(!f.db.update_job(&job_id, &[], false).unwrap());
    f.db.update_job(&job_id, &[JobField::status("discarded")], false)
        .unwrap();
    assert!(!f
        .db
        .update_job(&job_id, &[JobField::Progress(50)], true)
        .unwrap());
    f.db.append_log(&job_id, "ignored", true).unwrap();
    f.db.append_log(&job_id, "kept\n\n", false).unwrap();
    let job = f.db.get_job(&job_id).unwrap().unwrap();
    assert_eq!((job.progress, job.log.as_str()), (5, "kept\n"));
    assert!(!f
        .db
        .update_job("missing", &[JobField::Progress(1)], false)
        .unwrap());
    f.db.append_log("missing", "nothing", false).unwrap();
}

#[test]
fn logs_keep_the_last_cap_characters() {
    let directory = tempfile::tempdir().unwrap();
    let mut settings = DoctorSettings::with_defaults(directory.path());
    settings.log_char_cap = 10;
    let db = JobStore::new(&settings);
    db.init_db().unwrap();
    let job_id = "c".repeat(32);
    db.create_job(NewJob::new(&job_id, "x", 0, "")).unwrap();
    db.append_log(&job_id, "0123456789", false).unwrap();
    db.append_log(&job_id, "abc", false).unwrap();
    assert_eq!(db.get_job(&job_id).unwrap().unwrap().log, "56789\nabc\n");
}
