//! Pipeline stages (port of `services/stages/*.py`).
//!
//! Every stage mirrors the Python module of the same name. The `py_*` helper
//! modules emulate the parts of the Python standard library (`email`,
//! `mailbox`, `json`) whose exact behavior shapes the report artifacts.

pub mod csv_safety;
pub mod email_briefing;
pub mod eml_extract;
pub mod gen_report;
pub mod inbox_summary;
pub mod rebrand;
pub mod worklist;

pub(crate) mod py_addr;
pub(crate) mod py_email;
pub(crate) mod py_header;
pub(crate) mod py_hvp;
pub mod pyjson;

use crate::pipeline::PipelineError;

/// The `log=` callback the Python stages receive (`pipeline_log`). It may fail
/// because the runner's event callback raises when a job is cancelled.
pub type LogFn<'a> = dyn FnMut(String) -> Result<(), PipelineError> + 'a;

/// Python's `ValueError(message)` raised by a stage.
pub(crate) fn value_error(message: &str) -> PipelineError {
    PipelineError::Failed(message.to_owned())
}

/// `str(error)` for a failed `json.loads` on a JSONL line, surfaced like Python's
/// uncaught `json.JSONDecodeError`.
pub(crate) fn json_error(error: impl std::fmt::Display) -> PipelineError {
    PipelineError::Failed(error.to_string())
}
