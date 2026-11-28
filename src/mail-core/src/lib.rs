//! mail-core: blocking (synchronous) port of the original Python backend's
//! mail logic (`backend/settings.py`, `backend/network.py`, `backend/app/mail/*`,
//! and `backend/app/doctor/config.py`).
//!
//! Everything here is synchronous, mirroring the Python code that FastAPI ran
//! in a thread pool. The axum backend calls into it via `tokio::task::spawn_blocking`.
//!
//! Module ↔ Python source map:
//!
//! | Rust module        | Python source                          |
//! |--------------------|----------------------------------------|
//! | `error`            | exception classes across the backend   |
//! | `model`            | shared constants (settings.py, schemas.py) |
//! | `settings`         | `backend/settings.py`                  |
//! | `network`          | `backend/network.py`                   |
//! | `doctor`           | `backend/app/doctor/config.py`         |
//! | `servers`          | `app/mail/servers.py`                  |
//! | `sessions`         | `app/mail/sessions.py`                 |
//! | `display_names`    | `app/mail/display_names.py`            |
//! | `schemas`          | `app/mail/schemas.py`                  |
//! | `parsing`          | `app/mail/parsing.py`                  |
//! | `retention`        | `app/mail/retention.py`                |
//! | `audit`            | `app/mail/audit.py`                    |
//! | `imap`             | `app/mail/imap_client.py`              |
//! | `pop3`             | (new) POP3 compatibility mode          |
//! | `smtp`             | `app/mail/smtp_client.py`              |
//! | `send_uploads`     | `app/mail/send_uploads.py`             |
//! | `classifier`       | `app/mail/local_classifier.py`         |
//! | `image_sources`    | `app/mail/image_sources.py`            |
//! | `remote_images`    | `app/mail/remote_images.py`            |
//! | `signatures`       | `app/mail/signatures.py`               |
//! | `trash`            | `app/mail/trash.py`                    |

pub mod audit;
pub mod classifier;
pub mod display_names;
pub mod doctor;
pub mod error;
pub mod image_sources;
pub mod imap;
pub mod model;
pub mod network;
pub mod parsing;
pub mod pop3;
pub mod remote_images;
pub mod retention;
pub mod schemas;
pub mod send_uploads;
pub mod servers;
pub mod sessions;
pub mod settings;
pub mod signatures;
pub mod smtp;
pub mod trash;

pub use error::{MailError, Result};
pub use sessions::{MailAccount, SessionStore};
