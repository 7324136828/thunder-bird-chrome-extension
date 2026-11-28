//! Persistent sender-name overrides, scoped to an email address
//! (port of `app/mail/display_names.py`).
//!
//! Names are stored in settings.json under `email_display_names`, keyed by
//! the trimmed, lowercased email address. Passwords are never stored here.
//! The mapping keeps the file (insertion) order, like the Python dict.

use crate::error::{MailError, Result};
use crate::schemas::header_safe;
use crate::settings::{read_settings_object, settings_lock, settings_path, write_json};
use indexmap::IndexMap;
use serde_json::{Map, Value};
use std::fs;

/// Maximum display-name length (characters), as in `UnlockIn.display_name`.
pub const MAX_DISPLAY_NAME_LENGTH: usize = 200;

fn valid_name(name: &str) -> bool {
    name.chars().count() <= MAX_DISPLAY_NAME_LENGTH && header_safe(name)
}

/// Python `_names`: validate the stored mapping and normalize its keys.
fn names(values: &Map<String, Value>) -> Result<IndexMap<String, String>> {
    let invalid = || MailError::Settings("Invalid email_display_names in settings".into());
    let stored = match values.get("email_display_names") {
        None => return Ok(IndexMap::new()),
        Some(Value::Object(stored)) => stored,
        Some(_) => return Err(invalid()),
    };
    let mut result = IndexMap::new();
    for (email, name) in stored {
        match name {
            Value::String(name) if !email.trim().is_empty() && valid_name(name) => {
                result.insert(email.trim().to_lowercase(), name.clone());
            }
            _ => return Err(invalid()),
        }
    }
    Ok(result)
}

/// Python `load_names`: saved sender names keyed by lowercased email.
pub fn load_names() -> Result<IndexMap<String, String>> {
    let path = settings_path();
    let _guard = settings_lock();
    names(&read_settings_object(&path)?)
}

/// Python `save_name`: `None` restores the profile default; an empty string
/// explicitly hides the name. Unchanged values are not rewritten.
///
/// An invalid name is a `ValueError` in Python; here it is a 422
/// [`MailError::validation`].
pub fn save_name(email: &str, name: Option<&str>) -> Result<()> {
    if let Some(name) = name {
        if !valid_name(name) {
            return Err(MailError::validation(
                "Display name must not contain control characters",
            ));
        }
    }
    let email = email.trim().to_lowercase();
    let path = settings_path();
    let _guard = settings_lock();
    let mut values = read_settings_object(&path)?;
    let mut current = names(&values)?;
    match name {
        None => {
            if current.shift_remove(&email).is_none() {
                return Ok(());
            }
        }
        Some(name) => {
            if current.get(&email).map(String::as_str) == Some(name) {
                return Ok(());
            }
            current.insert(email, name.to_string());
        }
    }
    values.insert(
        "email_display_names".into(),
        serde_json::to_value(current).expect("string map serializes"),
    );
    let write = || -> std::io::Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        write_json(&path, &Value::Object(values), true)
    };
    write().map_err(|_| {
        MailError::Settings("Could not save the display name. Reconnect to try again.".into())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::settings::{resolve_path, scoped_settings_path};
    use serde_json::json;

    struct Fixture {
        path: std::path::PathBuf,
        _temporary: tempfile::TempDir,
        _scope: crate::settings::ScopedSettingsPath,
    }

    fn fixture() -> Fixture {
        let temporary = tempfile::tempdir().unwrap();
        let path = resolve_path(temporary.path())
            .unwrap()
            .join("settings.json");
        let scope = scoped_settings_path(&path);
        Fixture {
            path,
            _temporary: temporary,
            _scope: scope,
        }
    }

    fn read(path: &std::path::Path) -> Value {
        serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap()
    }

    #[test]
    fn names_round_trip_and_preserve_other_settings() {
        let fixture = fixture();
        assert!(load_names().unwrap().is_empty());
        assert!(!fixture.path.exists());

        let original = json!({
            "messages_per_page": 37,
            "emails_signatures": {"user@example.com": {"text": "<p>Signature</p>", "multipart-path": {}}},
            "data_directory": "retained-data",
        });
        fs::write(&fixture.path, original.to_string()).unwrap();
        save_name("  User@Example.com ", Some("Persistent Sender")).unwrap();
        let saved = read(&fixture.path);
        for key in ["messages_per_page", "emails_signatures", "data_directory"] {
            assert_eq!(saved[key], original[key]);
        }
        assert_eq!(
            saved["email_display_names"],
            json!({"user@example.com": "Persistent Sender"})
        );
        assert_eq!(
            load_names().unwrap()["user@example.com"],
            "Persistent Sender"
        );

        // An explicit empty name is kept; None removes the override.
        save_name("user@example.com", Some("")).unwrap();
        assert_eq!(load_names().unwrap()["user@example.com"], "");
        save_name("user@example.com", None).unwrap();
        assert!(load_names().unwrap().is_empty());
        assert_eq!(read(&fixture.path)["email_display_names"], json!({}));
    }

    #[test]
    fn names_keep_file_order_like_a_python_dict() {
        let fixture = fixture();
        fs::write(
            &fixture.path,
            r#"{"email_display_names": {"z@example.com": "Z", " M@Example.com ": "M1", "a@example.com": "A", "m@example.com": "M2"}, "messages_per_page": 9}"#,
        )
        .unwrap();
        let names = load_names().unwrap();
        let listed: Vec<(&str, &str)> = names
            .iter()
            .map(|(email, name)| (email.as_str(), name.as_str()))
            .collect();
        // Duplicate normalized keys keep the first position and the last value.
        assert_eq!(
            listed,
            [
                ("z@example.com", "Z"),
                ("m@example.com", "M2"),
                ("a@example.com", "A")
            ]
        );
        save_name("b@example.com", Some("B")).unwrap();
        save_name("z@example.com", None).unwrap();
        let text = fs::read_to_string(&fixture.path).unwrap();
        let saved = read(&fixture.path);
        let keys: Vec<&String> = saved["email_display_names"]
            .as_object()
            .unwrap()
            .keys()
            .collect();
        assert_eq!(keys, ["m@example.com", "a@example.com", "b@example.com"]);
        // The existing settings key keeps its position in the file.
        assert!(
            text.find("email_display_names").unwrap() < text.find("messages_per_page").unwrap()
        );
    }

    #[test]
    fn unchanged_names_are_not_rewritten() {
        let fixture = fixture();
        save_name("a@example.com", Some("Name")).unwrap();
        let before = fs::read(&fixture.path).unwrap();
        save_name("A@example.com", Some("Name")).unwrap();
        save_name("b@example.com", None).unwrap();
        assert_eq!(fs::read(&fixture.path).unwrap(), before);
    }

    #[test]
    fn invalid_names_are_rejected() {
        let fixture = fixture();
        for name in ["Name\r\nBcc: x@y.z", "tab\tname", &"x".repeat(201)] {
            let error = save_name("a@example.com", Some(name)).unwrap_err();
            assert_eq!(error.status(), 422);
        }
        assert!(!fixture.path.exists());
        assert!(save_name("a@example.com", Some(&"x".repeat(200))).is_ok());
    }

    #[test]
    fn invalid_stored_names_are_settings_errors() {
        let fixture = fixture();
        for stored in [
            json!([]),
            json!({"a@example.com": 5}),
            json!({"  ": "Name"}),
            json!({"a@example.com": "bad\u{1}"}),
            json!({"a@example.com": "x".repeat(201)}),
        ] {
            let content = json!({"email_display_names": stored}).to_string();
            fs::write(&fixture.path, &content).unwrap();
            let error = load_names().unwrap_err();
            assert_eq!(error.to_string(), "Invalid email_display_names in settings");
            assert_eq!(error.status(), 500);
            assert!(save_name("a@example.com", Some("x")).is_err());
            assert_eq!(fs::read_to_string(&fixture.path).unwrap(), content);
        }
        fs::write(&fixture.path, "{broken").unwrap();
        assert!(matches!(load_names(), Err(MailError::Settings(_))));
    }
}
