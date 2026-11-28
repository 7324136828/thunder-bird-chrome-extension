//! `.eml` extraction with malformed MIME headers, against the original
//! `eml_extract.run` (CPython 3.12 `policy.default`) on the fixtures in
//! `tests/fixtures/doctor/eml_mime/`.

use std::fs;
use std::path::Path;

use mail_doctor::stages::eml_extract;

#[test]
fn malformed_mime_headers_extract_like_python() {
    let inputs = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/doctor/eml_mime");
    let work = tempfile::tempdir().unwrap();
    let out = work.path().join("messages.jsonl");
    let mut logs = Vec::new();
    let count = eml_extract::run(&inputs, &out, &mut |line| {
        logs.push(line);
        Ok(())
    })
    .unwrap();
    // A Content-Type whose parse raises fails `BytesParser` (file skipped).
    assert_eq!(count, 3);
    assert_eq!(logs, ["Skipping unparseable file: ct_crash.eml"]);
    let records: Vec<serde_json::Value> = fs::read_to_string(&out)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    let summary: Vec<(String, bool, String)> = records
        .iter()
        .map(|record| {
            (
                record["source_file"].as_str().unwrap().to_string(),
                record["has_attachments"].as_bool().unwrap(),
                record["snippet"].as_str().unwrap().to_string(),
            )
        })
        .collect();
    assert_eq!(
        summary,
        [
            // The failing Content-Disposition makes `_has_attachments`
            // return False; `_snippet` never reads it for the PDF part.
            ("cd_crash.eml".to_string(), false, "later text".to_string()),
            // `.cte` ignores the unterminated comment; the charset quote is
            // closed by the header parser.
            (
                "cte_comment.eml".to_string(),
                false,
                "hello world".to_string()
            ),
            // The unquoted boundary parses as `----`, so no part matches.
            ("unquoted_boundary.eml".to_string(), false, String::new()),
        ]
    );
}
