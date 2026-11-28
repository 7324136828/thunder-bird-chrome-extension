//! Inbox Doctor (port of `backend/app/doctor`): upload/paste/mailbox audit jobs,
//! the report pipeline, SQLite job state, email metrics and the weekly scheduler.
//!
//! | Rust module          | Python source                               |
//! |----------------------|---------------------------------------------|
//! | `config`             | `doctor/config.py` (`DoctorSettings`)       |
//! | `db`                 | `doctor/db.py`                              |
//! | `metrics`            | `doctor/metrics.py`                         |
//! | `schemas`            | `doctor/schemas/job.py`                     |
//! | `scheduler`          | `doctor/scheduler.py`                       |
//! | `cancellation`       | `doctor/services/cancellation.py`           |
//! | `mailbox_download`   | `doctor/services/mailbox_download.py`       |
//! | `oauth`              | `doctor/services/oauth.py`                  |
//! | `pipeline`           | `doctor/services/pipeline.py`               |
//! | `pyzip`              | CPython `zipfile` (reading, for uploads)    |
//! | `runner`             | `doctor/services/runner.py`                 |
//! | `stages::*`          | `doctor/services/stages/*.py`               |
//! | `temp_manager`       | `doctor/utils/temp_manager.py`              |
//!
//! HTTP routes (`doctor/router.py`, `doctor/metrics_router.py`) live in `mail-backend`.

pub mod cancellation;
pub mod config;
pub mod db;
pub mod mailbox_download;
pub mod metrics;
pub mod oauth;
pub mod pipeline;
pub mod pyzip;
pub mod runner;
pub mod scheduler;
pub mod schemas;
pub mod stages;
pub mod temp_manager;
