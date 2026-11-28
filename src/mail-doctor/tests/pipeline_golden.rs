//! Golden-output parity tests for the Inbox Doctor report pipeline.
//!
//! `tests/fixtures/pipeline/<case>/expected/` was produced by running the
//! ORIGINAL Python stages (`backend/app/doctor/services/pipeline.py`, copied
//! read-only into a scratch package) on the same `inputs/`, with POSIX
//! semantics (`mailbox.linesep = b"\n"`, LF text files). Only timestamps that
//! depend on "now" are masked before comparing.

use std::fs;
use std::path::{Path, PathBuf};

use mail_doctor::pipeline::{
    run_pipeline, PipelineEvent, DEFAULT_MAX_ARCHIVE_MEMBERS, DEFAULT_MAX_EXPANDED_BYTES,
};
use mail_doctor::temp_manager::{list_files_under, list_output_files};
use regex::Regex;

fn fixture(case: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/pipeline")
        .join(case)
}

fn copy_dir(src: &Path, dst: &Path) {
    fs::create_dir_all(dst).unwrap();
    for entry in fs::read_dir(src).unwrap() {
        let entry = entry.unwrap();
        let target = dst.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_dir(&entry.path(), &target);
        } else {
            fs::copy(entry.path(), target).unwrap();
        }
    }
}

fn mask(text: &str) -> String {
    let generated_json = Regex::new(r#""generated_at": "[^"]*""#).unwrap();
    let generated_html = Regex::new(r"<p>Generated [^ ]* &middot;").unwrap();
    let text = generated_json.replace_all(text, r#""generated_at": "<now>""#);
    generated_html
        .replace_all(&text, "<p>Generated <now> &middot;")
        .into_owned()
}

fn run_case(case: &str) -> (tempfile::TempDir, Vec<PipelineEvent>) {
    let temp = tempfile::tempdir().unwrap();
    let job = temp.path().join("job");
    copy_dir(&fixture(case).join("inputs"), &job.join("inputs"));
    let mut events = Vec::new();
    run_pipeline(
        &job,
        None,
        &mut |e| events.push(e),
        DEFAULT_MAX_EXPANDED_BYTES,
        DEFAULT_MAX_ARCHIVE_MEMBERS,
    )
    .expect("pipeline succeeds");
    (temp, events)
}

fn expected_events(case: &str) -> Vec<PipelineEvent> {
    let raw: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(fixture(case).join("events.json")).unwrap())
            .unwrap();
    raw.as_array()
        .unwrap()
        .iter()
        .map(|pair| match pair[0].as_str().unwrap() {
            "STAGE" => PipelineEvent::Stage(pair[1].as_str().unwrap().into()),
            "PROGRESS" => PipelineEvent::Progress(pair[1].as_i64().unwrap()),
            _ => PipelineEvent::Log(pair[1].as_str().unwrap().into()),
        })
        .collect()
}

fn assert_case_matches_python(case: &str) {
    let (temp, events) = run_case(case);
    let job = temp.path().join("job");
    let expected_dir = fixture(case).join("expected");

    let expected_files = list_files_under(&fixture(case), "expected");
    assert_eq!(list_output_files(&job), expected_files, "output file set");
    for name in &expected_files {
        let expected = fs::read(expected_dir.join(name)).unwrap();
        let actual = fs::read(job.join("outputs").join(name)).unwrap();
        let (expected, actual) = (
            String::from_utf8(expected).unwrap(),
            String::from_utf8(actual).unwrap(),
        );
        assert_eq!(
            mask(&actual),
            mask(&expected),
            "{case}: {name} differs from the Python golden output"
        );
    }
    assert_eq!(events, expected_events(case), "{case}: event stream");

    let inputs_after: Vec<String> =
        serde_json::from_str(&fs::read_to_string(fixture(case).join("inputs_after.json")).unwrap())
            .unwrap();
    assert_eq!(
        list_files_under(&job, "inputs"),
        inputs_after,
        "{case}: staged/extracted inputs"
    );
}

#[test]
fn basic_case_matches_python_byte_for_byte() {
    assert_case_matches_python("basic");
}

#[test]
fn mixed_case_matches_python_byte_for_byte() {
    // .eml (CRLF, RFC 2047, multipart, base64/QP, digest, raw 8-bit), .mbox
    // (folded and raw 8-bit headers, long headers), aliases.json,
    // annotations.json and a .zip with nested/ignored members.
    assert_case_matches_python("mixed");
}

#[test]
fn edge_case_matches_python_byte_for_byte() {
    // multipart/report with message/delivery-status, multipart/signed (no
    // refolding), RFC 2231 filenames, windows-1252 QP, a multipart without a
    // boundary, a missing close boundary with an unknown charset, broken
    // base64, a header-less file, an attached message/rfc822, a CRLF mbox
    // (long headers refolded, missing blank separators), non-dict alias files
    // and non-dict annotation values.
    assert_case_matches_python("edge");
}

#[test]
fn work_directory_holds_the_intermediate_files() {
    let (temp, _) = run_case("basic");
    let job = temp.path().join("job");
    for name in [
        "messages.jsonl",
        "messages_grouped.jsonl",
        "_domain_aliases.json",
    ] {
        assert_eq!(
            fs::read(job.join("work").join(name)).unwrap(),
            fs::read(job.join("outputs").join(name)).unwrap()
        );
    }
}
