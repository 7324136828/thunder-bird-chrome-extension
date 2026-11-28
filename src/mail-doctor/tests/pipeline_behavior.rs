//! Behavior tests for the report pipeline and workspace helpers, ported from
//! `backend/tests/test_doctor.py` and `email-doctor/backend/tests/test_pipeline.py`.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;

use mail_doctor::cancellation::{cancellation_context, AuditCancelled};
use mail_doctor::pipeline::{
    run_pipeline, try_run_pipeline, PipelineError, PipelineEvent, DEFAULT_MAX_ARCHIVE_MEMBERS,
    DEFAULT_MAX_EXPANDED_BYTES, NO_MESSAGES_ERROR,
};
use mail_doctor::temp_manager::{
    list_output_files, package_outputs, prepare_inputs, resolve_output, stage_stream, stage_text,
    Workspace, WorkspaceError, SUBDIRS,
};
use zip::write::SimpleFileOptions;

const SAMPLE_EML: &str = "From: Newsletter Bot <news@mail.example.com>
To: user@test.local
Subject: Weekly digest {n}
Date: Mon, 05 Aug 2024 10:0{n}:00 +0000
Message-ID: <msg{n}@mail.example.com>
List-Unsubscribe: <https://mail.example.com/unsub?token={n}>
MIME-Version: 1.0
Content-Type: text/plain; charset=\"utf-8\"

Hello, here is your weekly digest number {n}.
";

const HUMAN_EML: &str = "From: Alice Smith <alice@friends.org>
To: user@test.local
Subject: Lunch on Friday?
Date: Tue, 06 Aug 2024 09:15:00 +0000
Message-ID: <lunch@friends.org>
MIME-Version: 1.0
Content-Type: text/plain; charset=\"utf-8\"

Are you still up for lunch on Friday?
";

fn sample(n: usize) -> String {
    SAMPLE_EML.replace("{n}", &n.to_string())
}

/// `backend/tests/test_doctor.py::message`.
fn message(index: usize, sender: &str, unsubscribe: bool) -> String {
    let domain = sender.rsplit('@').next().unwrap();
    let mut headers = vec![
        format!("From: Newsletter <{sender}>"),
        "To: user@example.net".to_owned(),
        format!("Subject: Weekly digest {index}"),
        format!("Date: {}", chrono::Utc::now().to_rfc2822()),
        format!("Message-ID: <doctor-{index}@{domain}>"),
        "Content-Type: text/plain; charset=\"utf-8\"".to_owned(),
    ];
    if unsubscribe {
        headers.push(format!(
            "List-Unsubscribe: <https://example.com/unsubscribe/{index}>"
        ));
    }
    format!("{}\r\n\r\nDigest number {index}.", headers.join("\r\n"))
}

fn job_dir(base: &Path) -> PathBuf {
    let job = base.join("job1");
    for sub in SUBDIRS {
        fs::create_dir_all(job.join(sub)).unwrap();
    }
    job
}

fn seed_inputs(job: &Path, count: usize) {
    for i in 0..count {
        fs::write(job.join("inputs").join(format!("news_{i}.eml")), sample(i)).unwrap();
    }
    fs::write(job.join("inputs/human.eml"), HUMAN_EML).unwrap();
}

fn run(job: &Path) -> Result<Vec<PipelineEvent>, PipelineError> {
    let mut events = Vec::new();
    run_pipeline(
        job,
        None,
        &mut |e| events.push(e),
        DEFAULT_MAX_EXPANDED_BYTES,
        DEFAULT_MAX_ARCHIVE_MEMBERS,
    )?;
    Ok(events)
}

fn json(path: &Path) -> serde_json::Value {
    serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap()
}

fn zip_bytes(entries: &[(&str, &[u8])], method: zip::CompressionMethod) -> Vec<u8> {
    let mut writer = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    for (name, data) in entries {
        if name.ends_with('/') {
            writer
                .add_directory(name.trim_end_matches('/'), SimpleFileOptions::default())
                .unwrap();
        } else {
            writer
                .start_file(
                    *name,
                    SimpleFileOptions::default().compression_method(method),
                )
                .unwrap();
            writer.write_all(data).unwrap();
        }
    }
    writer.finish().unwrap().into_inner()
}

#[test]
fn run_pipeline_produces_all_outputs() {
    let temp = tempfile::tempdir().unwrap();
    let job = job_dir(temp.path());
    seed_inputs(&job, 12);
    run(&job).unwrap();
    let outputs = job.join("outputs");
    for rel in [
        "messages.jsonl",
        "messages_grouped.jsonl",
        "_domain_aliases.json",
        "report/senders.csv",
        "report/summary.json",
        "report/summary.md",
        "report/email_briefing.md",
        "report/recent_emails.csv",
        "report/unsubscribe.csv",
        "inbox_cleanup_worklist.csv",
        "worklist.json",
        "inbox_audit.html",
    ] {
        assert!(outputs.join(rel).is_file(), "{rel}");
    }
    let summary = json(&outputs.join("report/summary.json"));
    assert_eq!(summary["total_messages"], 13);
    assert_eq!(summary["unique_senders"], 2);
    let worklist = json(&outputs.join("worklist.json"));
    let action = |group: &str| {
        worklist["items"]
            .as_array()
            .unwrap()
            .iter()
            .find(|i| i["sender_group"] == group)
            .unwrap()["recommended_action"]
            .clone()
    };
    assert_eq!(action("example.com"), "unsubscribe_and_purge");
    assert_eq!(action("friends.org"), "keep");
    let html = fs::read_to_string(outputs.join("inbox_audit.html")).unwrap();
    assert!(html.contains("example.com") && html.contains("unsubscribe_and_purge"));
    let briefing = fs::read_to_string(outputs.join("report/email_briefing.md")).unwrap();
    assert!(briefing.contains("Weekly digest") && briefing.contains("Lunch on Friday"));
    assert_eq!(list_output_files(&job).len(), 12);
}

#[test]
fn zip_audit_produces_sender_actions_and_package() {
    let temp = tempfile::tempdir().unwrap();
    let job = job_dir(temp.path());
    let messages: Vec<(String, String)> = (0..12)
        .map(|i| {
            (
                format!("mail/news-{i}.eml"),
                message(i, "news@mail.example.com", true),
            )
        })
        .chain([(
            "mail/human.eml".to_owned(),
            message(20, "alice@friends.org", false),
        )])
        .collect();
    let entries: Vec<(&str, &[u8])> = messages
        .iter()
        .map(|(n, d)| (n.as_str(), d.as_bytes()))
        .collect();
    fs::write(
        job.join("inputs/inbox.zip"),
        zip_bytes(&entries, zip::CompressionMethod::Stored),
    )
    .unwrap();
    let events = run(&job).unwrap();
    assert!(events.contains(&PipelineEvent::Log("Parsed 13 messages".into())));
    assert_eq!(events.last(), Some(&PipelineEvent::Progress(97)));

    let summary = json(&job.join("outputs/report/summary.json"));
    assert_eq!(summary["total_messages"], 13);
    assert_eq!(summary["unique_senders"], 2);
    let worklist = json(&job.join("outputs/worklist.json"));
    let actions: Vec<(String, String)> = worklist["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| {
            (
                i["sender_group"].as_str().unwrap().into(),
                i["recommended_action"].as_str().unwrap().into(),
            )
        })
        .collect();
    assert_eq!(
        actions,
        vec![
            ("example.com".into(), "unsubscribe_and_purge".into()),
            ("friends.org".into(), "keep".into())
        ]
    );
    assert!(
        fs::read_to_string(job.join("outputs/report/email_briefing.md"))
            .unwrap()
            .contains("Weekly digest")
    );

    let archive = package_outputs(&job).unwrap();
    assert_eq!(archive, job.join("archive/audit_output.zip"));
    let mut zip = zip::ZipArchive::new(fs::File::open(&archive).unwrap()).unwrap();
    let names: Vec<String> = zip.file_names().map(str::to_owned).collect();
    for expected in [
        "inbox_audit.html",
        "report/recent_emails.csv",
        "messages_grouped.jsonl",
        "report/summary.json",
    ] {
        assert!(
            names.contains(&expected.to_owned()),
            "{expected} in {names:?}"
        );
    }
    assert_eq!(names.len(), 12);
    let mut html = String::new();
    std::io::Read::read_to_string(&mut zip.by_name("inbox_audit.html").unwrap(), &mut html)
        .unwrap();
    assert_eq!(
        html,
        fs::read_to_string(job.join("outputs/inbox_audit.html")).unwrap()
    );
    assert!(!job.join("archive/audit_output.zip.part").exists());
}

#[test]
fn aliases_and_annotations_are_honored() {
    let temp = tempfile::tempdir().unwrap();
    let job = job_dir(temp.path());
    fs::write(
        job.join("inputs/one.eml"),
        message(1, "news@updates.vendor.net", true),
    )
    .unwrap();
    fs::write(
        job.join("inputs/two.eml"),
        message(2, "news@vendor.org", true),
    )
    .unwrap();
    fs::write(
        job.join("inputs/aliases.json"),
        r#"{"updates.vendor.net": "vendor.org"}"#,
    )
    .unwrap();
    fs::write(
        job.join("inputs/annotations.json"),
        r#"{"vendor.org": {"action": "keep", "note": "Paid subscription"}}"#,
    )
    .unwrap();
    let events = run(&job).unwrap();
    assert!(events.contains(&PipelineEvent::Log(
        "Applied 1 custom sender aliases".into()
    )));
    let worklist = json(&job.join("outputs/worklist.json"));
    let items = worklist["items"].as_array().unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["sender_group"], "vendor.org");
    assert_eq!(items[0]["message_count"], 2);
    assert_eq!(items[0]["recommended_action"], "keep");
    assert_eq!(items[0]["note"], "Paid subscription");
}

#[test]
fn invalid_alias_files_are_logged_and_ignored() {
    let temp = tempfile::tempdir().unwrap();
    let job = job_dir(temp.path());
    seed_inputs(&job, 1);
    fs::write(job.join("inputs/aliases.json"), "{not json").unwrap();
    fs::write(job.join("inputs/annotations.json"), "[1, 2]").unwrap();
    let events = run(&job).unwrap();
    assert!(events.iter().any(|e| matches!(e, PipelineEvent::Log(m) if m.starts_with("Ignoring invalid aliases file aliases.json: "))));
}

#[test]
fn alias_limits_raise_value_errors() {
    let temp = tempfile::tempdir().unwrap();
    let job = job_dir(temp.path());
    seed_inputs(&job, 1);
    fs::write(
        job.join("inputs/aliases.json"),
        format!(r#"{{"{}": "x.com"}}"#, "d".repeat(254)),
    )
    .unwrap();
    let error = run(&job).unwrap_err();
    assert_eq!(
        error.to_string(),
        "Sender aliases exceed the maximum domain or group length (253 / 320 characters)"
    );
    fs::write(job.join("inputs/aliases.json"), "{}").unwrap();
    fs::write(
        job.join("inputs/annotations.json"),
        format!(r#"{{"x.com": {{"note": "{}"}}}}"#, "n".repeat(4001)),
    )
    .unwrap();
    assert_eq!(
        run(&job).unwrap_err().to_string(),
        "Sender annotation notes exceed the maximum of 4000 characters"
    );
}

#[test]
fn mbox_input_is_parsed() {
    let temp = tempfile::tempdir().unwrap();
    let job = job_dir(temp.path());
    // mailbox.mbox.add() writes "From MAILER-DAEMON <date>" separators and a blank line after each message.
    let mut mbox = String::new();
    for i in 0..3 {
        mbox.push_str("From MAILER-DAEMON Mon Aug  5 10:00:00 2024\n");
        mbox.push_str(&sample(i));
        mbox.push('\n');
    }
    fs::write(job.join("inputs/list.mbox"), mbox).unwrap();
    run(&job).unwrap();
    let summary = json(&job.join("outputs/report/summary.json"));
    assert_eq!(summary["total_messages"], 3);
    let first_line = fs::read_to_string(job.join("outputs/messages.jsonl"))
        .unwrap()
        .lines()
        .next()
        .unwrap()
        .to_owned();
    assert!(first_line.contains("\"mbox_index\": 0"));
}

#[test]
fn pasted_text_is_staged_and_audited() {
    let temp = tempfile::tempdir().unwrap();
    let job = job_dir(temp.path());
    let path = stage_text(
        &job,
        Some("paste.eml"),
        &message(0, "news@mail.example.com", true),
    )
    .unwrap();
    assert_eq!(path.file_name().unwrap(), "paste.eml");
    let again = stage_text(&job, Some("paste.eml"), "x").unwrap();
    assert_eq!(again.file_name().unwrap(), "paste_1.eml");
    fs::remove_file(again).unwrap();
    run(&job).unwrap();
    assert_eq!(
        json(&job.join("outputs/report/summary.json"))["total_messages"],
        1
    );
}

#[test]
fn empty_inputs_fail_with_pipeline_error() {
    let temp = tempfile::tempdir().unwrap();
    let job = job_dir(temp.path());
    match run(&job) {
        Err(PipelineError::Failed(message)) => assert_eq!(message, NO_MESSAGES_ERROR),
        other => panic!("unexpected {other:?}"),
    }
}

#[test]
fn zip_expansion_limit_fails_before_parsing() {
    let temp = tempfile::tempdir().unwrap();
    let job = job_dir(temp.path());
    let raw = message(0, "news@mail.example.com", true);
    fs::write(
        job.join("inputs/large.zip"),
        zip_bytes(
            &[("large.eml", raw.as_bytes())],
            zip::CompressionMethod::Deflated,
        ),
    )
    .unwrap();
    let mut events = Vec::new();
    let error = run_pipeline(
        &job,
        None,
        &mut |e| events.push(e),
        100,
        DEFAULT_MAX_ARCHIVE_MEMBERS,
    )
    .unwrap_err();
    assert_eq!(
        error.to_string(),
        "Expanded ZIP content exceeds the maximum allowed size"
    );
    assert!(error.to_string().to_lowercase().contains("size"));
    assert!(!job.join("work/messages.jsonl").exists());
}

#[test]
fn zip_traversal_is_rejected_without_writing_outside_inputs() {
    for name in [
        "../../../outside.eml",
        "/abs.eml",
        "C:/x.eml",
        "a/../../b.eml",
    ] {
        let temp = tempfile::tempdir().unwrap();
        let job = job_dir(temp.path());
        let raw = message(0, "news@mail.example.com", true);
        fs::write(
            job.join("inputs/unsafe.zip"),
            zip_bytes(&[(name, raw.as_bytes())], zip::CompressionMethod::Stored),
        )
        .unwrap();
        match prepare_inputs(
            &job,
            DEFAULT_MAX_EXPANDED_BYTES,
            DEFAULT_MAX_ARCHIVE_MEMBERS,
        ) {
            Err(WorkspaceError::Invalid(message)) => assert_eq!(
                message, "ZIP archive contains an unsafe file path",
                "{name}"
            ),
            other => panic!("{name}: unexpected {other:?}"),
        }
        assert!(!temp.path().join("outside.eml").exists());
        assert!(!job.join("outside.eml").exists());
    }
}

#[test]
fn zip_member_cap_and_unreadable_archives() {
    let temp = tempfile::tempdir().unwrap();
    let job = job_dir(temp.path());
    let entries: Vec<(String, Vec<u8>)> = (0..5)
        .map(|i| (format!("{i}.txt"), b"x".to_vec()))
        .collect();
    let refs: Vec<(&str, &[u8])> = entries
        .iter()
        .map(|(n, d)| (n.as_str(), d.as_slice()))
        .collect();
    fs::write(
        job.join("inputs/many.zip"),
        zip_bytes(&refs, zip::CompressionMethod::Stored),
    )
    .unwrap();
    match prepare_inputs(&job, DEFAULT_MAX_EXPANDED_BYTES, 4) {
        Err(WorkspaceError::Invalid(message)) => {
            assert_eq!(message, "ZIP archives contain too many entries")
        }
        other => panic!("unexpected {other:?}"),
    }

    let job2 = job_dir(&temp.path().join("other"));
    fs::write(
        job2.join("inputs/broken.zip"),
        b"PK\x03\x04 not really a zip",
    )
    .unwrap();
    match prepare_inputs(
        &job2,
        DEFAULT_MAX_EXPANDED_BYTES,
        DEFAULT_MAX_ARCHIVE_MEMBERS,
    ) {
        Err(WorkspaceError::Invalid(message)) => {
            assert_eq!(message, "Cannot read the uploaded ZIP archive")
        }
        other => panic!("unexpected {other:?}"),
    }
    assert!(job2.join("inputs/broken_extracted").is_dir());
}

#[test]
fn zip_extraction_filters_flattens_and_dedupes() {
    let temp = tempfile::tempdir().unwrap();
    let job = job_dir(temp.path());
    let data = zip_bytes(
        &[
            ("dir/", b""),
            ("dir/a.eml", b"Subject: 1\n\nx"),
            ("other/a.eml", b"Subject: 2\n\nx"),
            ("x.MBOX", b"From a\nSubject: 3\n\nx\n"),
            ("skip.txt", b"x"),
            ("nested.zip", b"PK"),
        ],
        zip::CompressionMethod::Deflated,
    );
    fs::write(job.join("inputs/in.zip"), &data).unwrap();
    fs::create_dir(job.join("inputs/in_extracted")).unwrap();
    prepare_inputs(
        &job,
        DEFAULT_MAX_EXPANDED_BYTES,
        DEFAULT_MAX_ARCHIVE_MEMBERS,
    )
    .unwrap();
    let mut names: Vec<String> = fs::read_dir(job.join("inputs/in_extracted_1"))
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    assert_eq!(names, vec!["a.eml", "a_1.eml", "x.mbox"]);
}

#[test]
fn stage_stream_enforces_the_combined_limit_and_cleans_up() {
    let temp = tempfile::tempdir().unwrap();
    let job = job_dir(temp.path());
    let raw = message(0, "news@mail.example.com", true).into_bytes();
    let target = stage_stream(
        &job,
        Some("C:\\fake\\First.EML"),
        raw.as_slice(),
        raw.len() as i64 + 5,
    )
    .unwrap();
    assert_eq!(target.file_name().unwrap(), "First.eml");
    match stage_stream(&job, Some("second.eml"), raw.as_slice(), 5) {
        Err(WorkspaceError::Invalid(message)) => {
            assert_eq!(message, "Upload exceeds the total maximum allowed size")
        }
        other => panic!("unexpected {other:?}"),
    }
    assert!(!job.join("inputs/second.eml").exists());
}

#[test]
fn report_reads_cannot_escape_the_output_directory() {
    let temp = tempfile::tempdir().unwrap();
    let job = job_dir(temp.path());
    seed_inputs(&job, 1);
    run(&job).unwrap();
    assert!(resolve_output(&job, "report/summary.json").is_some());
    for path in [
        "../inputs/human.eml",
        "..\\inputs\\human.eml",
        "C:\\Windows\\win.ini",
        "report",
        "",
        "missing.json",
        "a\0b",
    ] {
        assert!(resolve_output(&job, path).is_none(), "{path:?}");
    }
}

#[test]
fn message_limit_is_enforced() {
    let temp = tempfile::tempdir().unwrap();
    let job = job_dir(temp.path());
    seed_inputs(&job, 3);
    let result: Result<Vec<PipelineEvent>, PipelineError> =
        cancellation_context(Arc::new(|| false), 2, || run(&job));
    assert_eq!(
        result.unwrap_err().to_string(),
        "The audit exceeds the maximum allowed message count"
    );
}

#[test]
fn cancellation_stops_the_pipeline() {
    let temp = tempfile::tempdir().unwrap();
    let job = job_dir(temp.path());
    seed_inputs(&job, 3);
    let flag = Arc::new(AtomicBool::new(false));
    let seen = Arc::new(AtomicUsize::new(0));
    let (flag2, seen2) = (flag.clone(), seen.clone());
    let result: Result<(), PipelineError> = cancellation_context(
        Arc::new(move || flag2.load(Ordering::SeqCst)),
        50_000,
        || {
            let mut event = |e: PipelineEvent| {
                seen2.fetch_add(1, Ordering::SeqCst);
                if e == PipelineEvent::Stage("group".into()) {
                    flag.store(true, Ordering::SeqCst);
                }
            };
            run_pipeline(
                &job,
                None,
                &mut event,
                DEFAULT_MAX_EXPANDED_BYTES,
                DEFAULT_MAX_ARCHIVE_MEMBERS,
            )
        },
    );
    assert!(matches!(
        result,
        Err(PipelineError::Cancelled(AuditCancelled))
    ));
    assert!(!job.join("outputs/inbox_audit.html").exists());
    assert!(seen.load(Ordering::SeqCst) >= 5);
}

#[test]
fn a_failing_event_callback_aborts_the_run() {
    let temp = tempfile::tempdir().unwrap();
    let job = job_dir(temp.path());
    seed_inputs(&job, 1);
    let mut event = |e: PipelineEvent| match e {
        PipelineEvent::Stage(name) if name == "summarize" => {
            Err(PipelineError::Cancelled(AuditCancelled))
        }
        _ => Ok(()),
    };
    let result = try_run_pipeline(
        &job,
        None,
        &mut event,
        DEFAULT_MAX_EXPANDED_BYTES,
        DEFAULT_MAX_ARCHIVE_MEMBERS,
    );
    assert!(matches!(result, Err(PipelineError::Cancelled(_))));
    assert!(job.join("work/messages_grouped.jsonl").exists());
    assert!(!job.join("outputs/report/summary.json").exists());
}

#[test]
fn workspace_round_trip() {
    let temp = tempfile::tempdir().unwrap();
    let workspace = Workspace::new(temp.path().join("doctor/jobs"));
    let id = "0123456789abcdef0123456789abcdef";
    let dir = workspace.create_job_dirs(id).unwrap();
    assert_eq!(dir, workspace.job_dir_for(id).unwrap());
    assert!(workspace
        .job_dir_for("0123456789ABCDEF0123456789ABCDEF")
        .is_err());
    let outside = temp.path().join("0123456789abcdef0123456789abcdee");
    fs::create_dir_all(&outside).unwrap();
    assert!(workspace.purge_job_dir(&outside).is_err());
    assert!(outside.exists());
    workspace.purge_job_dir(&dir).unwrap();
    assert!(!dir.exists());
}
