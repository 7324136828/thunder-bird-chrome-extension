//! Shared application state (port of the `application.state.*` attributes set
//! up by the `lifespan` context manager in `backend/app/main.py`).
//!
//! | Python `app.state`        | Rust                                  |
//! |---------------------------|---------------------------------------|
//! | `sessions`                | [`AppStateInner::sessions`]           |
//! | `mail_servers_path`       | [`AppStateInner::mail_servers_path`]  |
//! | `doctor.settings.data_directory` | [`AppStateInner::data_directory`] |
//! | `image_sources`           | [`AppStateInner::image_sources`]      |
//! | `retention`               | [`AppStateInner::retention`]          |
//! | `trash`                   | [`AppStateInner::trash`]              |
//! | `doctor`                  | [`AppStateInner::doctor`]             |
//! | `audit_scheduler`         | [`AppStateInner::audit_scheduler`]    |

use std::ops::Deref;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use mail_core::image_sources::ImageSources;
use mail_core::retention::RetentionStore;
use mail_core::trash::TrashOperations;
use mail_core::{MailError, SessionStore};
use mail_doctor::config::DoctorSettings;
use mail_doctor::runner::JobRunner;
use mail_doctor::scheduler::WeeklyAuditScheduler;

/// Environment variable overriding the server-profile file (main.py `lifespan`).
pub const MAIL_SERVERS_PATH_ENV: &str = "MAIL_SERVERS_PATH";

/// Cheaply clonable handle to the backend state (`Arc` inside).
#[derive(Clone)]
pub struct AppState {
    inner: Arc<AppStateInner>,
}

/// The state itself; reach it through `AppState`'s `Deref`.
pub struct AppStateInner {
    /// In-memory unlocked accounts. Passwords never leave this store.
    pub sessions: SessionStore,
    /// `mail-servers.json` (server profiles; never contains passwords).
    pub mail_servers_path: PathBuf,
    /// Data directory shared by Inbox Doctor, retention and trash archives.
    pub data_directory: PathBuf,
    /// Remote image URLs each rendered message may load.
    pub image_sources: ImageSources,
    /// Categories / expiration overrides / sender rules (SQLite).
    pub retention: RetentionStore,
    /// Prepared Trash-emptying operations (`<data>/trash_archives`).
    pub trash: TrashOperations,
    /// Inbox Doctor job runner (also the metrics store owner).
    pub doctor: JobRunner,
    /// Weekly unlocked-account audit scheduler.
    pub audit_scheduler: WeeklyAuditScheduler,
}

impl Deref for AppState {
    type Target = AppStateInner;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl std::fmt::Debug for AppState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppState")
            .field("mail_servers_path", &self.mail_servers_path)
            .field("data_directory", &self.data_directory)
            .field("unlocked_accounts", &self.sessions.list().len())
            .finish()
    }
}

impl AppState {
    /// State with an empty session store over the given files, building
    /// every service like main.py's `lifespan` (the scheduler is created but
    /// not started; [`AppState::initialize`] starts it).
    pub fn new(mail_servers_path: PathBuf, data_directory: PathBuf) -> Self {
        Self::with_doctor_settings(mail_servers_path, DoctorSettings::new(data_directory))
    }

    /// Like [`AppState::new`] with explicit Doctor settings (tests use
    /// `DoctorSettings::with_defaults` to avoid environment races).
    pub fn with_doctor_settings(mail_servers_path: PathBuf, settings: DoctorSettings) -> Self {
        let data_directory = settings.data_directory.clone();
        let sessions = SessionStore::new();
        let doctor = JobRunner::new(settings);
        if let Err(error) = doctor.initialize() {
            tracing::error!("Inbox Doctor initialization failed: {error}");
        }
        let retention = RetentionStore::new(&data_directory);
        let audit_scheduler =
            WeeklyAuditScheduler::new(std::sync::Arc::new(doctor.clone()), sessions.clone());
        let trash = TrashOperations::new(data_directory.join("trash_archives"));
        Self {
            inner: Arc::new(AppStateInner {
                sessions,
                mail_servers_path,
                data_directory,
                image_sources: ImageSources::new(),
                retention,
                trash,
                doctor,
                audit_scheduler,
            }),
        }
    }

    /// Production start-up, mirroring main.py's `lifespan`:
    /// `MAIL_SERVERS_PATH` (expanded and resolved) or the appdata
    /// `mail-servers.json` is created if missing via
    /// `settings::initialize_mail_servers`, and the data directory comes from
    /// `doctor.config.data_directory()`.
    ///
    /// Errors are `MailError::Settings` (Python raised `RuntimeError` and the
    /// server refused to start).
    pub fn initialize() -> Result<Self, MailError> {
        Self::initialize_listening_on(None)
    }

    /// [`AppState::initialize`] for a server listening on `listen_port`:
    /// when neither `PUBLIC_BACKEND_URL` nor `BACKEND_PORT` is set, Inbox
    /// Doctor's `public_backend_url` (OAuth redirect URI and the callback
    /// page's `message_origin`) becomes `http://localhost:<listen_port>`, so
    /// it follows `--port` / `--addr` instead of the fixed default 48101.
    /// No environment variable is modified.
    pub fn initialize_listening_on(listen_port: Option<u16>) -> Result<Self, MailError> {
        let target = std::env::var(MAIL_SERVERS_PATH_ENV)
            .ok()
            .filter(|value| !value.trim().is_empty())
            .map(|value| {
                let expanded = mail_core::settings::expand_user(&value);
                mail_core::settings::resolve_path(&expanded).unwrap_or(expanded)
            });
        let mail_servers_path =
            mail_core::settings::initialize_mail_servers(None, target.as_deref())?;
        let data_directory = mail_core::doctor::data_directory(None);
        let mut settings = DoctorSettings::new(data_directory);
        if let Some(url) =
            listen_port_backend_url(|name| std::env::var_os(name).is_some(), listen_port)
        {
            settings.public_backend_url = url;
        }
        let state = Self::with_doctor_settings(mail_servers_path, settings);
        state.audit_scheduler.start()?;
        Ok(state)
    }

    /// Isolated state for tests: `<root>/mail-servers.json` (created with an
    /// empty `{"servers": {}}` document if missing) and `<root>/data`.
    ///
    /// Not `#[cfg(test)]` so integration tests under `tests/` can use it.
    pub fn for_tests(root: &Path) -> Self {
        let mail_servers_path = root.join("mail-servers.json");
        if !mail_servers_path.exists() {
            std::fs::create_dir_all(root).expect("create test root");
            std::fs::write(&mail_servers_path, "{\"servers\": {}}\n")
                .expect("write test mail-servers.json");
        }
        let data_directory = root.join("data");
        std::fs::create_dir_all(&data_directory).expect("create test data directory");
        Self::with_doctor_settings(
            mail_servers_path,
            DoctorSettings::with_defaults(data_directory),
        )
    }

    /// Graceful shutdown (the `finally:` block of main.py's lifespan): lock
    /// every account so no password outlives the process' serving phase.
    pub fn shutdown(&self) {
        self.audit_scheduler.close();
        self.doctor.close();
        self.trash.close();
        self.retention.close();
        self.sessions.clear();
        self.image_sources.clear();
        mail_core::remote_images::clear_cache();
    }
}

/// `http://localhost:<listen_port>` when the listen port is known and
/// neither `PUBLIC_BACKEND_URL` nor `BACKEND_PORT` is set (`is_set` reports
/// whether a variable is present, as `DoctorSettings` reads them); `None`
/// keeps `DoctorSettings`' own value.
pub fn listen_port_backend_url(
    is_set: impl Fn(&str) -> bool,
    listen_port: Option<u16>,
) -> Option<String> {
    let port = listen_port?;
    if is_set("PUBLIC_BACKEND_URL") || is_set("BACKEND_PORT") {
        return None;
    }
    Some(format!("http://localhost:{port}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use mail_core::MailAccount;

    #[test]
    fn public_backend_url_follows_the_listen_port_unless_configured() {
        let unset = |_: &str| false;
        assert_eq!(
            listen_port_backend_url(unset, Some(5000)),
            Some("http://localhost:5000".into())
        );
        assert_eq!(listen_port_backend_url(unset, None), None);
        for configured in ["PUBLIC_BACKEND_URL", "BACKEND_PORT"] {
            assert_eq!(
                listen_port_backend_url(|name| name == configured, Some(5000)),
                None,
                "{configured}"
            );
        }
    }

    #[test]
    fn for_tests_creates_isolated_files_and_shutdown_locks_accounts() {
        let temporary = tempfile::tempdir().unwrap();
        let state = AppState::for_tests(temporary.path());
        assert!(state.mail_servers_path.is_file());
        assert!(state.data_directory.is_dir());
        let text = std::fs::read_to_string(&state.mail_servers_path).unwrap();
        assert!(!text.to_lowercase().contains("password"));

        let clone = state.clone();
        clone.sessions.unlock(MailAccount::new(
            "user@example.com",
            "secret",
            "imap.example.com",
            993,
            "SSL/TLS",
            "smtp.example.com",
            587,
            "STARTTLS",
        ));
        assert_eq!(state.sessions.list().len(), 1);
        state.shutdown();
        assert!(clone.sessions.list().is_empty());
        assert!(!format!("{state:?}").contains("secret"));
    }
}
