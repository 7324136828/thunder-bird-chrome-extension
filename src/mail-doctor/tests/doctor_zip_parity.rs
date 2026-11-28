//! ZIP ingestion parity with `temp_manager.prepare_inputs` of the original
//! Python (fixtures under `tests/fixtures/doctor/` were written by CPython's
//! `zipfile` on Windows, where entries are marked as DOS-made).

use std::fs;
use std::path::{Path, PathBuf};

use mail_doctor::temp_manager::{prepare_inputs, WorkspaceError};

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/doctor")
        .join(name)
}

fn job_with(archive: &str) -> tempfile::TempDir {
    let temp = tempfile::tempdir().unwrap();
    fs::create_dir_all(temp.path().join("inputs")).unwrap();
    fs::copy(
        fixture(archive),
        temp.path().join("inputs").join("upload.zip"),
    )
    .unwrap();
    temp
}

fn failure(archive: &str) -> String {
    let job = job_with(archive);
    match prepare_inputs(job.path(), 400 * 1024 * 1024, 10_000) {
        Err(WorkspaceError::Invalid(message)) => message,
        other => panic!("expected a ValueError for {archive}, got {other:?}"),
    }
}

#[test]
fn symlink_mode_bits_are_rejected_even_for_dos_made_entries() {
    // Python checks `stat.S_ISLNK(member.external_attr >> 16)` regardless of
    // `create_system`; this entry has create_system 0 and mode 0o120777.
    assert_eq!(
        failure("dos_symlink.zip"),
        "ZIP archive contains a symbolic link"
    );
}

#[test]
fn bzip2_members_are_extracted_like_python_zipfile() {
    let job = job_with("bzip2.zip");
    prepare_inputs(job.path(), 400 * 1024 * 1024, 10_000).unwrap();
    let extracted = fs::read_to_string(job.path().join("inputs/upload_extracted/x.eml")).unwrap();
    assert!(extracted.starts_with("From: z@zip.example"), "{extracted}");
}

#[test]
fn unsupported_compression_is_an_unreadable_archive() {
    // zipfile raises NotImplementedError("That compression method is not
    // supported"), a RuntimeError, which prepare_inputs reports as
    // "Cannot read the uploaded ZIP archive".
    assert_eq!(
        failure("deflate64_method.zip"),
        "Cannot read the uploaded ZIP archive"
    );
}

/// `(name, size, sha256 prefix)` of every extracted file, sorted by name.
fn extracted(job: &tempfile::TempDir) -> Vec<(String, usize, String)> {
    use sha2::Digest;
    let mut files: Vec<_> = fs::read_dir(job.path().join("inputs/upload_extracted"))
        .unwrap()
        .map(|entry| {
            let entry = entry.unwrap();
            let body = fs::read(entry.path()).unwrap();
            let digest = hex::encode(sha2::Sha256::digest(&body));
            (
                entry.file_name().to_string_lossy().into_owned(),
                body.len(),
                digest[..16].to_string(),
            )
        })
        .collect();
    files.sort();
    files
}

fn expect(files: &[(&str, usize, &str)]) -> Vec<(String, usize, String)> {
    files
        .iter()
        .map(|(name, size, digest)| (name.to_string(), *size, digest.to_string()))
        .collect()
}

// The expected listings below are the output of the original
// `temp_manager.prepare_inputs` (CPython 3.12 `zipfile`) on these fixtures,
// which CPython's `zipfile` wrote.

#[test]
fn lzma_members_are_extracted_like_python_zipfile() {
    let job = job_with("lzma.zip");
    prepare_inputs(job.path(), 400 * 1024 * 1024, 10_000).unwrap();
    assert_eq!(
        extracted(&job),
        expect(&[
            ("empty.eml", 0, "e3b0c44298fc1c14"),
            ("x.eml", 111, "2dbe2c4324acb0ee"),
            ("y.eml", 256_111, "6f52d45b37468e83"),
        ])
    );
}

#[test]
fn every_python_compression_method_is_extracted() {
    let job = job_with("mixed_methods.zip");
    prepare_inputs(job.path(), 400 * 1024 * 1024, 10_000).unwrap();
    assert_eq!(
        extracted(&job),
        expect(&[
            ("bzip2.eml", 111, "0394ad4e817b0c99"),
            ("deflated.eml", 111, "8ddf9a195cd89e9b"),
            ("lzma.eml", 111, "24f9f1633b7ad388"),
            ("stored.eml", 111, "6ea281843fa3333a"),
        ])
    );
}

#[test]
fn duplicate_entry_names_are_all_extracted_with_counters() {
    let job = job_with("duplicates.zip");
    prepare_inputs(job.path(), 400 * 1024 * 1024, 10_000).unwrap();
    assert_eq!(
        extracted(&job),
        expect(&[
            ("x.eml", 111, "ee96ab34c64cb372"),
            ("x_1.eml", 111, "5585b24c5e83a249"),
            ("x_2.eml", 111, "010f7dcece0c244b"),
        ])
    );
}

#[test]
fn duplicate_entries_count_toward_the_member_cap() {
    let job = job_with("duplicates.zip");
    match prepare_inputs(job.path(), 400 * 1024 * 1024, 2) {
        Err(WorkspaceError::Invalid(message)) => {
            assert_eq!(message, "ZIP archives contain too many entries")
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn lzma_crc_mismatch_is_an_unreadable_archive() {
    assert_eq!(
        failure("lzma_bad_crc.zip"),
        "Cannot read the uploaded ZIP archive"
    );
}

#[test]
fn lzma_expansion_is_capped_by_the_declared_size() {
    // `expanded + member.file_size > max_expanded_bytes` before decoding.
    let job = job_with("lzma.zip");
    match prepare_inputs(job.path(), 1000, 10_000) {
        Err(WorkspaceError::Invalid(message)) => assert_eq!(
            message,
            "Expanded ZIP content exceeds the maximum allowed size"
        ),
        other => panic!("{other:?}"),
    }
}
