//! Email audit pipeline orchestrator (port of `services/pipeline.py`).
//!
//! Runs the stages against an isolated job directory and reports progress
//! through an event callback (`("STAGE", name)`, `("PROGRESS", percent)`,
//! `("LOG", text)`). The backend runs this inside worker threads
//! (`tokio::task::spawn_blocking`), with a [`crate::cancellation`] context
//! installed on that thread.
//!
//! Output layout (identical to Python):
//! * `work/messages.jsonl`, `work/messages_grouped.jsonl`, `work/_domain_aliases.json`
//! * `outputs/report/{senders.csv,unsubscribe.csv,summary.json,summary.md,recent_emails.csv,email_briefing.md}`
//! * `outputs/{inbox_cleanup_worklist.csv,worklist.json,inbox_audit.html}`
//! * copies of the three `work/` files in `outputs/`.
//!
//! Text files are written with `\n` line endings (Python's behavior on POSIX;
//! CSV files always use `\r\n` record terminators).

use std::fs;
use std::path::Path;

use crate::stages::{email_briefing, eml_extract, gen_report, inbox_summary, rebrand, worklist};
use crate::temp_manager::prepare_inputs;

pub const DEFAULT_MAX_EXPANDED_BYTES: u64 = 400 * 1024 * 1024;
pub const DEFAULT_MAX_ARCHIVE_MEMBERS: usize = 10_000;

/// User-facing message when no message could be parsed.
pub const NO_MESSAGES_ERROR: &str = "No parseable .eml or .mbox messages were found in the upload.";

/// Progress events, mirroring Python's `event(kind, msg)` callback:
/// `("STAGE", name)`, `("PROGRESS", percent)`, `("LOG", text)`.
#[derive(Debug, Clone, PartialEq)]
pub enum PipelineEvent {
    Stage(String),
    Progress(i64),
    Log(String),
}

impl PipelineEvent {
    /// The Python event kind (`"STAGE"`, `"PROGRESS"` or `"LOG"`).
    pub fn kind(&self) -> &'static str {
        match self {
            PipelineEvent::Stage(_) => "STAGE",
            PipelineEvent::Progress(_) => "PROGRESS",
            PipelineEvent::Log(_) => "LOG",
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum PipelineError {
    /// Python `PipelineError` or a stage's `ValueError` (user-facing message).
    #[error("{0}")]
    Failed(String),
    #[error(transparent)]
    Cancelled(#[from] crate::cancellation::AuditCancelled),
    #[error("{0}")]
    Io(#[from] std::io::Error),
}

/// Run every stage for `job_dir` (`inputs/` → `work/` → `outputs/report/`).
///
/// `event` cannot fail; use [`try_run_pipeline`] when the callback must be able
/// to abort the run (Python's runner raises `AuditCancelled` from its callback).
pub fn run_pipeline(
    job_dir: &Path,
    days: Option<i64>,
    event: &mut dyn FnMut(PipelineEvent),
    max_expanded_bytes: u64,
    max_archive_members: usize,
) -> Result<(), PipelineError> {
    let mut fallible = |e: PipelineEvent| {
        event(e);
        Ok(())
    };
    try_run_pipeline(
        job_dir,
        days,
        &mut fallible,
        max_expanded_bytes,
        max_archive_members,
    )
}

/// [`run_pipeline`] with a fallible event callback: an `Err` returned by the
/// callback aborts the pipeline and is propagated unchanged.
pub fn try_run_pipeline(
    job_dir: &Path,
    days: Option<i64>,
    event: &mut dyn FnMut(PipelineEvent) -> Result<(), PipelineError>,
    max_expanded_bytes: u64,
    max_archive_members: usize,
) -> Result<(), PipelineError> {
    let inputs = job_dir.join("inputs");
    let work = job_dir.join("work");
    let outputs = job_dir.join("outputs");
    let report_dir = outputs.join("report");
    for dir in [&inputs, &work, &outputs, &report_dir] {
        fs::create_dir_all(dir)?;
    }

    event(PipelineEvent::Stage("extract".into()))?;
    event(PipelineEvent::Progress(5))?;
    prepare_inputs(job_dir, max_expanded_bytes, max_archive_members)?;

    let mut log = |message: String| event(PipelineEvent::Log(message));
    let count = eml_extract::run(&inputs, &work.join("messages.jsonl"), &mut log)?;
    if count == 0 {
        return Err(PipelineError::Failed(NO_MESSAGES_ERROR.into()));
    }
    log(format!("Parsed {count} messages"))?;
    drop(log);
    event(PipelineEvent::Progress(40))?;

    event(PipelineEvent::Stage("group".into()))?;
    {
        let mut log = |message: String| event(PipelineEvent::Log(message));
        rebrand::run(
            &inputs,
            &work.join("messages.jsonl"),
            &work.join("messages_grouped.jsonl"),
            &work.join("_domain_aliases.json"),
            &mut log,
        )?;
    }
    event(PipelineEvent::Progress(55))?;

    event(PipelineEvent::Stage("summarize".into()))?;
    {
        let mut log = |message: String| event(PipelineEvent::Log(message));
        inbox_summary::run(&work.join("messages_grouped.jsonl"), &report_dir, &mut log)?;
        email_briefing::run(
            &work.join("messages_grouped.jsonl"),
            &report_dir,
            days,
            &mut log,
        )?;
    }
    event(PipelineEvent::Progress(75))?;

    event(PipelineEvent::Stage("worklist".into()))?;
    {
        let mut log = |message: String| event(PipelineEvent::Log(message));
        worklist::run(
            &inputs,
            &work.join("messages_grouped.jsonl"),
            &outputs,
            &mut log,
        )?;
    }
    event(PipelineEvent::Progress(88))?;

    event(PipelineEvent::Stage("report".into()))?;
    {
        let mut log = |message: String| event(PipelineEvent::Log(message));
        gen_report::run(
            &report_dir.join("summary.json"),
            &outputs.join("worklist.json"),
            &outputs.join("inbox_audit.html"),
            &mut log,
        )?;
    }

    // Publish intermediate artifacts alongside the reports (shutil.copy2).
    for name in [
        "messages.jsonl",
        "messages_grouped.jsonl",
        "_domain_aliases.json",
    ] {
        let src = work.join(name);
        if src.is_file() {
            copy_preserving_mtime(&src, &outputs.join(name))?;
        }
    }
    event(PipelineEvent::Progress(97))?;
    Ok(())
}

/// `shutil.copy2`: copy contents and the modification time.
fn copy_preserving_mtime(src: &Path, dst: &Path) -> std::io::Result<()> {
    fs::copy(src, dst)?;
    if let Ok(modified) = fs::metadata(src).and_then(|m| m.modified()) {
        if let Ok(file) = fs::OpenOptions::new().write(true).open(dst) {
            let _ = file.set_modified(modified);
        }
    }
    Ok(())
}
