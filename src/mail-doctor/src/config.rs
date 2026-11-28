//! Inbox Doctor configuration scoped to one application instance (port of
//! `backend/app/doctor/config.py`, `DoctorSettings`).
//!
//! Secrets (OAuth client secrets) stay in memory; nothing here is persisted.
//! `data_directory()` and `env_integer()` live in [`mail_core::doctor`].

use mail_core::doctor::{data_directory, env_integer};
use std::path::{Path, PathBuf};

/// Default backend port of the Rust port (the Python app used 8741).
pub const DEFAULT_BACKEND_PORT: &str = "48101";
/// Default frontend port used to build `FRONTEND_URL` when it is not set.
pub const DEFAULT_FRONTEND_PORT: &str = "3741";

/// File extensions accepted for uploads (`allowed_extensions`).
pub const ALLOWED_EXTENSIONS: [&str; 4] = [".eml", ".zip", ".mbox", ".json"];

/// Python `DoctorSettings`. Every limit can be overridden through the same
/// environment variables as the original.
#[derive(Clone, PartialEq, Eq)]
pub struct DoctorSettings {
    pub data_directory: PathBuf,
    /// `MAX_UPLOAD_BYTES` (default 200 MiB).
    pub max_upload_bytes: u64,
    /// `MAX_EXPANDED_BYTES` (default 400 MiB).
    pub max_expanded_bytes: u64,
    /// `MAX_ARCHIVE_MEMBERS` (default 10000).
    pub max_archive_members: usize,
    /// `MAX_AUDIT_MESSAGES` (default 50000).
    pub max_messages: usize,
    /// `JOB_LOG_CHAR_CAP` (default 200000 characters).
    pub log_char_cap: usize,
    /// `MAIL_SNAPSHOT_EVERY_MESSAGES` (default 25).
    pub snapshot_every_messages: usize,
    /// Maximum number of queued or running audits (20).
    pub max_active_jobs: usize,
    /// `PUBLIC_BACKEND_URL`, else `http://localhost:{BACKEND_PORT}` (no trailing `/`).
    pub public_backend_url: String,
    /// `FRONTEND_URL`, else `http://localhost:{FRONTEND_PORT}` (no trailing `/`).
    pub frontend_url: String,
    pub google_oauth_client_id: String,
    pub google_oauth_client_secret: String,
    pub microsoft_oauth_client_id: String,
    pub microsoft_oauth_client_secret: String,
}

impl std::fmt::Debug for DoctorSettings {
    // Never print OAuth client secrets.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let redacted = |value: &str| if value.is_empty() { "" } else { "<redacted>" };
        f.debug_struct("DoctorSettings")
            .field("data_directory", &self.data_directory)
            .field("max_upload_bytes", &self.max_upload_bytes)
            .field("max_expanded_bytes", &self.max_expanded_bytes)
            .field("max_archive_members", &self.max_archive_members)
            .field("max_messages", &self.max_messages)
            .field("log_char_cap", &self.log_char_cap)
            .field("snapshot_every_messages", &self.snapshot_every_messages)
            .field("max_active_jobs", &self.max_active_jobs)
            .field("public_backend_url", &self.public_backend_url)
            .field("frontend_url", &self.frontend_url)
            .field("google_oauth_client_id", &self.google_oauth_client_id)
            .field(
                "google_oauth_client_secret",
                &redacted(&self.google_oauth_client_secret),
            )
            .field("microsoft_oauth_client_id", &self.microsoft_oauth_client_id)
            .field(
                "microsoft_oauth_client_secret",
                &redacted(&self.microsoft_oauth_client_secret),
            )
            .finish()
    }
}

fn env_string(name: &str, default: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| default.to_string())
}

fn env_limit(name: &str, default: i64) -> i64 {
    env_integer(name, default, 1)
}

fn local_url(url_variable: &str, port_variable: &str, default_port: &str) -> String {
    let fallback = format!(
        "http://localhost:{}",
        env_string(port_variable, default_port)
    );
    env_string(url_variable, &fallback)
        .trim_end_matches('/')
        .to_string()
}

impl DoctorSettings {
    /// `DoctorSettings(data_directory)`: limits, URLs and OAuth clients come
    /// from the environment exactly like the Python dataclass defaults.
    pub fn new(data_directory: impl Into<PathBuf>) -> Self {
        Self {
            data_directory: data_directory.into(),
            max_upload_bytes: env_limit("MAX_UPLOAD_BYTES", 200 * 1024 * 1024) as u64,
            max_expanded_bytes: env_limit("MAX_EXPANDED_BYTES", 400 * 1024 * 1024) as u64,
            max_archive_members: env_limit("MAX_ARCHIVE_MEMBERS", 10_000) as usize,
            max_messages: env_limit("MAX_AUDIT_MESSAGES", 50_000) as usize,
            log_char_cap: env_limit("JOB_LOG_CHAR_CAP", 200_000) as usize,
            snapshot_every_messages: env_limit("MAIL_SNAPSHOT_EVERY_MESSAGES", 25) as usize,
            max_active_jobs: 20,
            public_backend_url: local_url(
                "PUBLIC_BACKEND_URL",
                "BACKEND_PORT",
                DEFAULT_BACKEND_PORT,
            ),
            frontend_url: local_url("FRONTEND_URL", "FRONTEND_PORT", DEFAULT_FRONTEND_PORT),
            google_oauth_client_id: env_string("GOOGLE_OAUTH_CLIENT_ID", ""),
            google_oauth_client_secret: env_string("GOOGLE_OAUTH_CLIENT_SECRET", ""),
            microsoft_oauth_client_id: env_string("MICROSOFT_OAUTH_CLIENT_ID", ""),
            microsoft_oauth_client_secret: env_string("MICROSOFT_OAUTH_CLIENT_SECRET", ""),
        }
    }

    /// `DoctorSettings(data_directory(override))`, as in `create_app`.
    pub fn from_environment(override_directory: Option<&Path>) -> Self {
        Self::new(data_directory(override_directory))
    }

    /// Settings with the built-in defaults only (no environment lookups).
    /// Useful for tests, where process-wide variables would race.
    pub fn with_defaults(data_directory: impl Into<PathBuf>) -> Self {
        Self {
            data_directory: data_directory.into(),
            max_upload_bytes: 200 * 1024 * 1024,
            max_expanded_bytes: 400 * 1024 * 1024,
            max_archive_members: 10_000,
            max_messages: 50_000,
            log_char_cap: 200_000,
            snapshot_every_messages: 25,
            max_active_jobs: 20,
            public_backend_url: format!("http://localhost:{DEFAULT_BACKEND_PORT}"),
            frontend_url: format!("http://localhost:{DEFAULT_FRONTEND_PORT}"),
            google_oauth_client_id: String::new(),
            google_oauth_client_secret: String::new(),
            microsoft_oauth_client_id: String::new(),
            microsoft_oauth_client_secret: String::new(),
        }
    }

    /// `jobs_root`: `<data>/doctor/jobs`.
    pub fn jobs_root(&self) -> PathBuf {
        self.data_directory.join("doctor").join("jobs")
    }

    /// `db_path`: `<data>/doctor/jobs.sqlite3`.
    pub fn db_path(&self) -> PathBuf {
        self.data_directory.join("doctor").join("jobs.sqlite3")
    }

    /// `suffix in settings.allowed_extensions` (the suffix includes the dot).
    pub fn is_allowed_extension(&self, suffix: &str) -> bool {
        ALLOWED_EXTENSIONS.contains(&suffix)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_and_defaults() {
        let settings = DoctorSettings::with_defaults("/data");
        assert_eq!(settings.jobs_root(), Path::new("/data/doctor/jobs"));
        assert_eq!(settings.db_path(), Path::new("/data/doctor/jobs.sqlite3"));
        assert_eq!(settings.max_upload_bytes, 200 * 1024 * 1024);
        assert_eq!(settings.max_active_jobs, 20);
        assert!(settings.is_allowed_extension(".mbox"));
        assert!(!settings.is_allowed_extension(".exe"));
        assert!(!settings.is_allowed_extension(".EML"));
    }

    #[test]
    fn debug_hides_client_secrets() {
        let mut settings = DoctorSettings::with_defaults("/data");
        settings.google_oauth_client_secret = "very-secret".into();
        assert!(!format!("{settings:?}").contains("very-secret"));
    }

    #[test]
    fn urls_strip_trailing_slashes() {
        std::env::set_var("DOCTOR_CONFIG_TEST_URL", "https://example.test///");
        assert_eq!(
            local_url("DOCTOR_CONFIG_TEST_URL", "DOCTOR_CONFIG_TEST_PORT", "1"),
            "https://example.test"
        );
        std::env::set_var("DOCTOR_CONFIG_TEST_PORT2", "9999");
        assert_eq!(
            local_url(
                "DOCTOR_CONFIG_TEST_MISSING",
                "DOCTOR_CONFIG_TEST_PORT2",
                "1"
            ),
            "http://localhost:9999"
        );
    }
}
