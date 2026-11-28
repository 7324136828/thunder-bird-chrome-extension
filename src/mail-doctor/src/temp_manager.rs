//! Bounded ingestion and file access in UUID-named audit workspaces
//! (port of `backend/app/doctor/utils/temp_manager.py`).
//!
//! Layout of a job directory: `inputs/` (uploads, `*_extracted/` ZIP
//! expansions), `work/` (intermediate JSONL), `outputs/` (published reports)
//! and `archive/` (`audit_output.zip`).

use std::fs;
use std::io::{self, Read, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::OnceLock;

use regex::Regex;

use crate::cancellation::{check_cancel, AuditCancelled};
use crate::pipeline::PipelineError;
use crate::pyzip::{self, PyZipError};

pub const SUBDIRS: [&str; 4] = ["inputs", "work", "outputs", "archive"];
pub const ZIP_NAME: &str = "audit_output.zip";

const CHUNK: usize = 1024 * 1024;

/// Errors of the workspace helpers. `Invalid` mirrors Python's `ValueError`
/// (the HTTP layer answers it with 400 and `str(error)` as detail).
#[derive(Debug, thiserror::Error)]
pub enum WorkspaceError {
    #[error("{0}")]
    Invalid(String),
    #[error(transparent)]
    Cancelled(#[from] AuditCancelled),
    #[error("{0}")]
    Io(#[from] io::Error),
}

impl From<WorkspaceError> for PipelineError {
    fn from(error: WorkspaceError) -> Self {
        match error {
            WorkspaceError::Invalid(message) => PipelineError::Failed(message),
            WorkspaceError::Cancelled(cancelled) => PipelineError::Cancelled(cancelled),
            WorkspaceError::Io(error) => PipelineError::Io(error),
        }
    }
}

fn invalid(message: &str) -> WorkspaceError {
    WorkspaceError::Invalid(message.to_owned())
}

/// `PurePath.suffix` for a single name (`""` for dot-files and names
/// without an extension).
pub fn py_suffix(name: &str) -> &str {
    let chars = name.chars().count();
    match name.rfind('.') {
        Some(i) => {
            let char_index = name[..i].chars().count();
            if char_index > 0 && char_index < chars - 1 {
                &name[i..]
            } else {
                ""
            }
        }
        None => "",
    }
}

/// `PurePath.stem` for a single name.
pub fn py_stem(name: &str) -> &str {
    let suffix = py_suffix(name);
    &name[..name.len() - suffix.len()]
}

fn take_chars(value: &str, n: usize) -> String {
    value.chars().take(n).collect()
}

fn reserved_names() -> &'static [String] {
    static NAMES: OnceLock<Vec<String>> = OnceLock::new();
    NAMES.get_or_init(|| {
        let mut names: Vec<String> = ["CON", "PRN", "AUX", "NUL"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        names.extend((1..10).map(|i| format!("COM{i}")));
        names.extend((1..10).map(|i| format!("LPT{i}")));
        names
    })
}

/// `temp_manager.safe_filename(name, fallback)`.
pub fn safe_filename(name: Option<&str>, fallback: &str) -> String {
    let replaced = name.unwrap_or("").replace('\\', "/");
    let base = replaced.rsplit('/').next().unwrap_or("");
    let substituted: String = base
        .chars()
        .map(|c| {
            if (c as u32) < 0x20 || "<>:\"/\\|?*".contains(c) {
                '_'
            } else {
                c
            }
        })
        .collect();
    let mut cleaned = substituted.trim_matches([' ', '.']).to_owned();
    let upper = cleaned.to_uppercase();
    let head = upper.split('.').next().unwrap_or("");
    if reserved_names().iter().any(|reserved| reserved == head) {
        cleaned = format!("_{cleaned}");
    }
    if cleaned.chars().count() > 180 {
        let suffix = take_chars(py_suffix(&cleaned), 20);
        cleaned = take_chars(&cleaned, 160) + &suffix;
    }
    let suffix = py_suffix(&cleaned).to_owned();
    let result = if suffix.is_empty() {
        cleaned
    } else {
        format!(
            "{}{}",
            &cleaned[..cleaned.len() - suffix.len()],
            suffix.to_lowercase()
        )
    };
    if result.is_empty() {
        fallback.to_owned()
    } else {
        result
    }
}

/// `temp_manager._dedupe(directory, name)`.
fn dedupe(directory: &Path, name: &str) -> PathBuf {
    let mut candidate = directory.join(name);
    let stem = py_stem(name).to_owned();
    let suffix = py_suffix(name).to_owned();
    let mut i = 1;
    while candidate.exists() {
        candidate = directory.join(format!("{stem}_{i}{suffix}"));
        i += 1;
    }
    candidate
}

/// `temp_manager.stage_stream`: copy an upload into `inputs/`, enforcing `max_bytes`.
pub fn stage_stream<R: Read>(
    job_dir: &Path,
    filename: Option<&str>,
    mut stream: R,
    max_bytes: i64,
) -> Result<PathBuf, WorkspaceError> {
    let target = dedupe(&job_dir.join("inputs"), &safe_filename(filename, "upload"));
    let result = (|| -> Result<(), WorkspaceError> {
        let mut output = fs::File::create(&target)?;
        let mut written: i64 = 0;
        let mut buffer = vec![0u8; CHUNK];
        loop {
            let read = stream.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            written += read as i64;
            if written > max_bytes {
                return Err(invalid("Upload exceeds the total maximum allowed size"));
            }
            output.write_all(&buffer[..read])?;
        }
        output.flush()?;
        Ok(())
    })();
    match result {
        Ok(()) => Ok(target),
        Err(error) => {
            let _ = fs::remove_file(&target);
            Err(error)
        }
    }
}

/// `temp_manager.stage_text`: write pasted text into `inputs/` (UTF-8, no newline translation).
pub fn stage_text(
    job_dir: &Path,
    filename: Option<&str>,
    content: &str,
) -> Result<PathBuf, WorkspaceError> {
    let target = dedupe(
        &job_dir.join("inputs"),
        &safe_filename(filename, "pasted.eml"),
    );
    fs::write(&target, content.as_bytes())?;
    Ok(target)
}

/// `PurePosixPath(raw).parts` without the root.
fn posix_parts(raw: &str) -> Vec<&str> {
    raw.split('/')
        .filter(|part| !part.is_empty() && *part != ".")
        .collect()
}

fn top_level_zip_archives(inputs: &Path) -> io::Result<Vec<PathBuf>> {
    let mut archives: Vec<PathBuf> = Vec::new();
    for entry in fs::read_dir(inputs)? {
        let entry = entry?;
        if entry.file_name().to_string_lossy().ends_with(".zip") {
            archives.push(entry.path());
        }
    }
    archives.sort_by_key(|path| path.file_name().map(|n| n.to_string_lossy().into_owned()));
    Ok(archives)
}

fn cannot_read() -> WorkspaceError {
    invalid("Cannot read the uploaded ZIP archive")
}

/// Python wraps `zipfile.BadZipFile` and `RuntimeError` (including the
/// `NotImplementedError` "That compression method is not supported") into
/// "Cannot read the uploaded ZIP archive"; plain I/O failures stay `OSError`.
fn zip_error(error: PyZipError) -> WorkspaceError {
    match error {
        PyZipError::Io(error) => WorkspaceError::Io(error),
        PyZipError::BadZipFile(_) | PyZipError::NotImplemented(_) => cannot_read(),
    }
}

/// `temp_manager.prepare_inputs`: expand top-level `.zip` uploads with caps.
///
/// Archives are read by [`crate::pyzip`], a port of CPython's `zipfile`
/// reader, so every central directory entry is visited in order, duplicate
/// names included (the second `x.eml` becomes `x_1.eml` and both count
/// toward `max_archive_members`), and the stored, deflate, bzip2, LZMA and
/// Zstandard (Python 3.14) methods are decoded with `zipfile`'s truncation
/// to `file_size` and CRC-32 check.
pub fn prepare_inputs(
    job_dir: &Path,
    max_expanded_bytes: u64,
    max_archive_members: usize,
) -> Result<(), WorkspaceError> {
    let inputs = job_dir.join("inputs");
    let mut expanded: u64 = 0;
    let mut members_seen: usize = 0;
    for archive_path in top_level_zip_archives(&inputs)? {
        check_cancel()?;
        let archive_name = archive_path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let dest = dedupe(&inputs, &format!("{}_extracted", py_stem(&archive_name)));
        fs::create_dir(&dest)?;
        let mut archive = pyzip::ZipFile::new(fs::File::open(&archive_path)?).map_err(zip_error)?;
        for index in 0..archive.infolist().len() {
            check_cancel()?;
            members_seen += 1;
            if members_seen > max_archive_members {
                return Err(invalid("ZIP archives contain too many entries"));
            }
            let member = archive.infolist()[index].clone();
            let raw_name = member.filename.replace('\\', "/");
            let parts = posix_parts(&raw_name);
            if raw_name.starts_with('/')
                || parts.contains(&"..")
                || parts.iter().any(|part| part.contains(':'))
            {
                return Err(invalid("ZIP archive contains an unsafe file path"));
            }
            // `stat.S_ISLNK(member.external_attr >> 16)`, whatever system
            // made the entry.
            if (member.external_attr >> 16) & 0o170000 == 0o120000 {
                return Err(invalid("ZIP archive contains a symbolic link"));
            }
            if member.is_dir() {
                continue;
            }
            let leaf = parts.last().copied().unwrap_or("");
            if !matches!(
                py_suffix(leaf).to_lowercase().as_str(),
                ".eml" | ".mbox" | ".json"
            ) {
                continue;
            }
            if member.flag_bits & 1 != 0 {
                return Err(invalid("Encrypted ZIP entries are not supported"));
            }
            if expanded.saturating_add(member.file_size) > max_expanded_bytes {
                return Err(invalid(
                    "Expanded ZIP content exceeds the maximum allowed size",
                ));
            }
            let target = dedupe(&dest, &safe_filename(Some(&raw_name), "upload"));
            let mut output = fs::File::create(&target)?;
            archive
                .extract(index, |chunk| -> Result<(), WorkspaceError> {
                    check_cancel()?;
                    expanded += chunk.len() as u64;
                    if expanded > max_expanded_bytes {
                        return Err(invalid(
                            "Expanded ZIP content exceeds the maximum allowed size",
                        ));
                    }
                    output.write_all(chunk)?;
                    Ok(())
                })
                .map_err(|error| match error {
                    pyzip::ExtractError::Sink(error) => error,
                    pyzip::ExtractError::Zip(error) => zip_error(error),
                })?;
        }
    }
    Ok(())
}

fn collect_files(root: &Path, dir: &Path, out: &mut Vec<String>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let Ok(kind) = entry.file_type() else {
            continue;
        };
        let path = entry.path();
        if kind.is_symlink() {
            continue;
        }
        if kind.is_dir() {
            collect_files(root, &path, out);
        } else if kind.is_file() {
            if let Ok(relative) = path.strip_prefix(root) {
                let parts: Vec<String> = relative
                    .components()
                    .filter_map(|c| match c {
                        Component::Normal(part) => Some(part.to_string_lossy().into_owned()),
                        _ => None,
                    })
                    .collect();
                out.push(parts.join("/"));
            }
        }
    }
}

/// Every regular file below `root` (Python `root.rglob("*")` filtered by
/// `is_file()`); symbolic links are neither followed nor listed. Order is
/// unspecified.
pub fn walk_files(root: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        let Ok(entries) = fs::read_dir(&directory) else {
            continue;
        };
        for entry in entries.flatten() {
            let Ok(kind) = entry.file_type() else {
                continue;
            };
            if kind.is_dir() {
                pending.push(entry.path());
            } else if kind.is_file() {
                files.push(entry.path());
            }
        }
    }
    files
}

/// `temp_manager.list_files_under`: sorted POSIX relative paths of regular files.
pub fn list_files_under(job_dir: &Path, folder: &str) -> Vec<String> {
    let root = job_dir.join(folder);
    if !root.is_dir() {
        return Vec::new();
    }
    let mut files = Vec::new();
    collect_files(&root, &root, &mut files);
    files.sort();
    files
}

/// `temp_manager.list_output_files`.
pub fn list_output_files(job_dir: &Path) -> Vec<String> {
    list_files_under(job_dir, "outputs")
}

/// `temp_manager.resolve_file`: a file inside `job_dir/folder`, or `None`.
pub fn resolve_file(job_dir: &Path, folder: &str, rel_path: &str) -> Option<PathBuf> {
    if rel_path.contains(['\0', '\\', ':']) {
        return None;
    }
    let root = fs::canonicalize(job_dir.join(folder)).ok()?;
    let candidate = fs::canonicalize(root.join(rel_path)).ok()?;
    candidate.strip_prefix(&root).ok()?;
    candidate.is_file().then_some(candidate)
}

/// `temp_manager.resolve_output`.
pub fn resolve_output(job_dir: &Path, rel_path: &str) -> Option<PathBuf> {
    resolve_file(job_dir, "outputs", rel_path)
}

/// `temp_manager.resolve_snapshot_output`.
pub fn resolve_snapshot_output(job_dir: &Path, rel_path: &str) -> Option<PathBuf> {
    resolve_file(job_dir, "snapshot_outputs", rel_path)
}

fn zip_timestamp(path: &Path) -> zip::DateTime {
    use chrono::{Datelike, Local, Timelike};
    let modified = fs::metadata(path).and_then(|m| m.modified()).ok();
    modified
        .map(chrono::DateTime::<Local>::from)
        .and_then(|local| {
            zip::DateTime::from_date_and_time(
                u16::try_from(local.year()).ok()?,
                local.month() as u8,
                local.day() as u8,
                local.hour() as u8,
                local.minute() as u8,
                local.second() as u8,
            )
            .ok()
        })
        .unwrap_or_default()
}

/// `temp_manager.package_outputs`: zip every output file into `archive/audit_output.zip`.
pub fn package_outputs(job_dir: &Path) -> Result<PathBuf, WorkspaceError> {
    let destination = job_dir.join("archive").join(ZIP_NAME);
    fs::create_dir_all(job_dir.join("archive"))?;
    let partial = job_dir.join("archive").join(format!("{ZIP_NAME}.part"));
    {
        let mut writer = zip::ZipWriter::new(fs::File::create(&partial)?);
        for name in list_output_files(job_dir) {
            check_cancel()?;
            let Some(target) = resolve_output(job_dir, &name) else {
                continue;
            };
            let size = fs::metadata(&target)?.len();
            let options = zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Deflated)
                .last_modified_time(zip_timestamp(&target))
                .unix_permissions(0o644)
                .large_file(size >= u32::MAX as u64);
            writer
                .start_file(name.as_str(), options)
                .map_err(|error| io::Error::other(error.to_string()))?;
            io::copy(&mut fs::File::open(&target)?, &mut writer)?;
        }
        writer
            .finish()
            .map_err(|error| io::Error::other(error.to_string()))?;
    }
    check_cancel()?;
    fs::rename(&partial, &destination)?;
    Ok(destination)
}

fn job_id_pattern() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^[a-f0-9]{32}$").expect("valid regex"))
}

/// `Path.resolve()` (non-strict): canonicalize what exists, keep the rest.
fn resolve_lenient(path: &Path) -> PathBuf {
    if let Ok(resolved) = fs::canonicalize(path) {
        return resolved;
    }
    match (path.parent(), path.file_name()) {
        (Some(parent), Some(name)) if !parent.as_os_str().is_empty() => {
            resolve_lenient(parent).join(name)
        }
        _ => std::path::absolute(path).unwrap_or_else(|_| path.to_path_buf()),
    }
}

/// `temp_manager.Workspace`: the managed jobs root (`DoctorSettings.jobs_root`).
#[derive(Debug, Clone)]
pub struct Workspace {
    jobs_root: PathBuf,
}

impl Workspace {
    /// Python takes `DoctorSettings` and uses `settings.jobs_root`
    /// (`<data_directory>/doctor/jobs`); pass that directory here.
    pub fn new(jobs_root: impl Into<PathBuf>) -> Self {
        Self {
            jobs_root: jobs_root.into(),
        }
    }

    pub fn jobs_root(&self) -> &Path {
        &self.jobs_root
    }

    /// `Workspace.job_dir_for`: validates the 32-hex job id.
    pub fn job_dir_for(&self, job_id: &str) -> Result<PathBuf, WorkspaceError> {
        if !job_id_pattern().is_match(job_id) {
            return Err(invalid("Invalid job ID"));
        }
        Ok(self.jobs_root.join(job_id))
    }

    /// `Workspace.create_job_dirs`.
    pub fn create_job_dirs(&self, job_id: &str) -> Result<PathBuf, WorkspaceError> {
        let directory = self.job_dir_for(job_id)?;
        for name in SUBDIRS {
            fs::create_dir_all(directory.join(name))?;
        }
        Ok(directory)
    }

    /// `Workspace.purge_job_dir`: delete exactly one managed UUID directory.
    pub fn purge_job_dir(&self, job_dir: &Path) -> Result<(), WorkspaceError> {
        let resolved = resolve_lenient(job_dir);
        let root = resolve_lenient(&self.jobs_root);
        let name = resolved
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        if resolved.parent() != Some(root.as_path()) || !job_id_pattern().is_match(&name) {
            return Err(invalid("Purge target is outside the managed jobs root"));
        }
        let _ = fs::remove_dir_all(&resolved);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safe_filename_matches_python_golden_cases() {
        let cases: serde_json::Value =
            serde_json::from_str(include_str!("../tests/fixtures/pipeline/unit_cases.json"))
                .unwrap();
        for case in cases["safe_filename"].as_array().unwrap() {
            assert_eq!(
                safe_filename(case[0].as_str(), "upload"),
                case[1].as_str().unwrap(),
                "input {:?}",
                case[0]
            );
        }
        for case in cases["safe_filename_fallback"].as_array().unwrap() {
            assert_eq!(
                safe_filename(case[0].as_str(), "pasted.eml"),
                case[1].as_str().unwrap(),
                "input {:?}",
                case[0]
            );
        }
    }

    #[test]
    fn suffix_and_stem_follow_purepath() {
        assert_eq!(py_suffix("a.tar.gz"), ".gz");
        assert_eq!(py_suffix(".hidden"), "");
        assert_eq!(py_suffix("trailing."), "");
        assert_eq!(py_stem("inbox.zip"), "inbox");
        assert_eq!(py_stem("noext"), "noext");
    }

    #[test]
    fn dedupe_appends_counters() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.eml"), b"").unwrap();
        fs::write(dir.path().join("a_1.eml"), b"").unwrap();
        assert_eq!(dedupe(dir.path(), "a.eml"), dir.path().join("a_2.eml"));
        assert_eq!(dedupe(dir.path(), "b.eml"), dir.path().join("b.eml"));
    }

    #[test]
    fn job_ids_are_validated_and_purge_is_confined() {
        let dir = tempfile::tempdir().unwrap();
        let workspace = Workspace::new(dir.path().join("jobs"));
        assert!(
            matches!(workspace.job_dir_for("../x"), Err(WorkspaceError::Invalid(m)) if m == "Invalid job ID")
        );
        let job = workspace.create_job_dirs(&"a".repeat(32)).unwrap();
        for sub in SUBDIRS {
            assert!(job.join(sub).is_dir());
        }
        assert!(workspace.purge_job_dir(dir.path()).is_err());
        workspace.purge_job_dir(&job).unwrap();
        assert!(!job.exists());
    }
}
