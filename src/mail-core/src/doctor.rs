//! Inbox Doctor configuration helpers (port of the module-level functions of
//! `backend/app/doctor/config.py`).
//!
//! Only `data_directory`, `default_data_directory` and `env_integer` live
//! here; `DoctorSettings` itself belongs to the `mail-doctor` crate.

use crate::schemas::parse_python_int;
use crate::settings::{
    expand_user, expand_vars, read_utf8_sig, resolve_configured_directory, resolve_path,
};
use serde_json::Value;
use std::path::{Path, PathBuf};

pub use crate::settings::default_data_directory;

/// Environment variable that overrides the data directory.
pub const DATA_DIRECTORY_ENV: &str = "DATA_DIRECTORY";

/// Python `data_directory(override)`.
///
/// Resolution order: the explicit override, `$DATA_DIRECTORY`, the
/// `data_directory` of an existing settings.json (read without creating or
/// changing it; unreadable or invalid files are ignored), and finally
/// [`default_data_directory`].
pub fn data_directory(override_directory: Option<&Path>) -> PathBuf {
    let configured = match override_directory {
        Some(path) if !path.as_os_str().is_empty() => Some(path.to_string_lossy().into_owned()),
        _ => std::env::var(DATA_DIRECTORY_ENV)
            .ok()
            .filter(|value| !value.is_empty()),
    };
    if let Some(configured) = configured {
        let expanded = expand_user(&expand_vars(&configured));
        return resolve_path(&expanded).unwrap_or(expanded);
    }
    // Launchers initialize settings, while API tests can supply an isolated directory.
    let path = crate::settings::settings_path();
    if path.exists() {
        if let Some(directory) = configured_directory(&path) {
            return directory;
        }
    }
    default_data_directory()
}

fn configured_directory(settings_file: &Path) -> Option<PathBuf> {
    let text = read_utf8_sig(settings_file).ok()?;
    let values: Value = serde_json::from_str(&text).ok()?;
    match values.as_object()?.get("data_directory")? {
        Value::String(value) if !value.trim().is_empty() && !value.contains('\0') => {
            resolve_configured_directory(value, settings_file).ok()
        }
        _ => None,
    }
}

/// Python `env_integer(name, default, minimum=1)`: the variable parsed like
/// `int()`, raised to at least `minimum`; an unparsable value returns
/// `default` unchanged (without applying `minimum`, as in Python).
pub fn env_integer(name: &str, default: i64, minimum: i64) -> i64 {
    match std::env::var(name) {
        Err(_) => default.max(minimum),
        Ok(value) => match parse_python_int(&value) {
            Some(number) => number
                .clamp(i64::MIN as i128, i64::MAX as i128)
                .max(minimum as i128) as i64,
            None => default,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::settings::{resolve_path, scoped_settings_path};
    use std::fs;

    #[test]
    fn env_integer_parses_like_python_int() {
        std::env::set_var("DOCTOR_TEST_INT_VALID", " 1_000 ");
        std::env::set_var("DOCTOR_TEST_INT_SMALL", "-5");
        std::env::set_var("DOCTOR_TEST_INT_BAD", "12abc");
        assert_eq!(env_integer("DOCTOR_TEST_INT_VALID", 5, 1), 1000);
        assert_eq!(env_integer("DOCTOR_TEST_INT_SMALL", 5, 1), 1);
        assert_eq!(env_integer("DOCTOR_TEST_INT_BAD", 5, 10), 5);
        assert_eq!(env_integer("DOCTOR_TEST_INT_MISSING", 0, 3), 3);
        assert_eq!(env_integer("DOCTOR_TEST_INT_MISSING", 25, 1), 25);
    }

    #[test]
    fn data_directory_prefers_override_then_settings_then_default() {
        let temporary = tempfile::tempdir().unwrap();
        let root = resolve_path(temporary.path()).unwrap();
        let settings_file = root.join("cfg").join("settings.json");
        let _scope = scoped_settings_path(&settings_file);
        if std::env::var_os(DATA_DIRECTORY_ENV).is_some() {
            return; // The environment pins the directory; nothing else to check.
        }

        let explicit = root.join("explicit");
        assert_eq!(data_directory(Some(&explicit)), explicit);

        // No settings file: the default, and nothing is created.
        assert_eq!(data_directory(None), default_data_directory());
        assert!(!settings_file.exists());

        fs::create_dir_all(settings_file.parent().unwrap()).unwrap();
        fs::write(&settings_file, r#"{"data_directory": "../relative-data"}"#).unwrap();
        assert_eq!(data_directory(None), root.join("relative-data"));

        for invalid in [
            "{broken",
            "[]",
            r#"{"data_directory": 5}"#,
            r#"{"data_directory": "  "}"#,
        ] {
            fs::write(&settings_file, invalid).unwrap();
            assert_eq!(data_directory(None), default_data_directory(), "{invalid}");
        }
    }
}
