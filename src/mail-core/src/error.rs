//! Error type shared by every mail-core module.
//!
//! The Python backend raised distinct exception classes that `main.py` mapped
//! to HTTP statuses. Each variant here corresponds to one of those classes so
//! the Rust backend can reproduce the same status codes and `{"detail": ...}`
//! response bodies:
//!
//! | Python                                   | Variant               | HTTP |
//! |------------------------------------------|-----------------------|------|
//! | `imap_client.MailOperationError`         | `Operation`           | 502  |
//! | `imap_client.SentCopyError`              | `SentCopy`            | 502  |
//! | `trash.TrashOperationError`              | `Operation`           | 502  |
//! | `trash.TrashOperationNotFound`           | `TrashNotFound`       | 404  |
//! | `smtp_client.MailSendError`              | `Send`                | 502  |
//! | `settings.SettingsError`, `MailServersError` | `Settings`        | 500  |
//! | `retention.RetentionConflictError`       | `RetentionConflict`   | 409  |
//! | `retention.RetentionError`               | `Retention`           | 500  |
//! | `local_classifier.LocalClassifierError`  | `Classifier`          | 502  |
//! | `sessions.CredentialRequiredError`       | `CredentialRequired`  | 401 `{"error":"password_required","email":...}` |
//! | `HTTPException(status, detail)` / `ValueError` → 422 | `Http`    | any  |

use serde_json::{json, Value};

pub type Result<T, E = MailError> = std::result::Result<T, E>;

#[derive(Debug, thiserror::Error)]
pub enum MailError {
    /// IMAP/POP3 operation failure (`MailOperationError`) → 502.
    #[error("{0}")]
    Operation(String),
    /// Delivery succeeded but the Sent copy could not be saved (`SentCopyError`) → 502.
    #[error("{message}")]
    SentCopy {
        folder: Option<String>,
        message: String,
    },
    /// SMTP failure (`MailSendError`) → 502.
    #[error("{0}")]
    Send(String),
    /// Unreadable/invalid persisted configuration (`SettingsError`, `MailServersError`) → 500.
    #[error("{0}")]
    Settings(String),
    /// Mailbox epoch / revision changed (`RetentionConflictError`) → 409.
    #[error("{0}")]
    RetentionConflict(String),
    /// Retention database failure (`RetentionError`) → 500.
    #[error("{0}")]
    Retention(String),
    /// Local Ollama classifier failure (`LocalClassifierError`) → 502.
    #[error("{0}")]
    Classifier(String),
    /// Unknown or expired prepared trash operation (`TrashOperationNotFound`) → 404.
    #[error("{0}")]
    TrashNotFound(String),
    /// The account is not unlocked in this process → 401 password_required.
    /// Holds the normalized (trimmed, lowercased) email.
    #[error("password_required")]
    CredentialRequired(String),
    /// Explicit `HTTPException(status_code, detail)`.
    #[error("{}", detail_text(.detail))]
    Http { status: u16, detail: Value },
}

fn detail_text(detail: &Value) -> String {
    match detail {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

impl MailError {
    pub fn operation(message: impl Into<String>) -> Self {
        Self::Operation(message.into())
    }
    pub fn http(status: u16, detail: impl Into<Value>) -> Self {
        Self::Http {
            status,
            detail: detail.into(),
        }
    }
    /// 400 Bad Request with a string detail.
    pub fn bad_request(message: impl Into<String>) -> Self {
        Self::http(400, message.into())
    }
    /// 403 Forbidden with a string detail.
    pub fn forbidden(message: impl Into<String>) -> Self {
        Self::http(403, message.into())
    }
    /// 404 Not Found with a string detail.
    pub fn not_found(message: impl Into<String>) -> Self {
        Self::http(404, message.into())
    }
    /// 413 Payload Too Large with a string detail.
    pub fn too_large(message: impl Into<String>) -> Self {
        Self::http(413, message.into())
    }
    /// 422 with a string detail (Python `ValueError` → `HTTPException(422, str(error))`).
    pub fn validation(message: impl Into<String>) -> Self {
        Self::http(422, message.into())
    }
    pub fn credential_required(email: &str) -> Self {
        Self::CredentialRequired(email.trim().to_lowercase())
    }

    /// HTTP status code the backend must answer with.
    pub fn status(&self) -> u16 {
        match self {
            Self::Operation(_) | Self::SentCopy { .. } | Self::Send(_) | Self::Classifier(_) => 502,
            Self::Settings(_) | Self::Retention(_) => 500,
            Self::RetentionConflict(_) => 409,
            Self::TrashNotFound(_) => 404,
            Self::CredentialRequired(_) => 401,
            Self::Http { status, .. } => *status,
        }
    }

    /// Value of the JSON `detail` field of the error response.
    pub fn detail(&self) -> Value {
        match self {
            Self::CredentialRequired(email) => {
                json!({"error": "password_required", "email": email})
            }
            Self::Http { detail, .. } => detail.clone(),
            other => Value::String(other.to_string()),
        }
    }

    /// Full JSON response body: `{"detail": ...}`.
    pub fn body(&self) -> Value {
        json!({"detail": self.detail()})
    }
}

impl From<rusqlite::Error> for MailError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Retention(error.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn statuses_and_bodies() {
        let e = MailError::credential_required("  User@Example.COM ");
        assert_eq!(e.status(), 401);
        assert_eq!(
            e.body(),
            json!({"detail": {"error": "password_required", "email": "user@example.com"}})
        );
        assert_eq!(MailError::operation("boom").status(), 502);
        assert_eq!(
            MailError::operation("boom").body(),
            json!({"detail": "boom"})
        );
        assert_eq!(MailError::RetentionConflict("x".into()).status(), 409);
        assert_eq!(MailError::TrashNotFound("x".into()).status(), 404);
        assert_eq!(MailError::Settings("x".into()).status(), 500);
        assert_eq!(MailError::validation("bad").status(), 422);
        assert_eq!(
            MailError::http(400, json!({"a": 1})).to_string(),
            "{\"a\":1}"
        );
    }
}
