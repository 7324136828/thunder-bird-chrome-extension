//! Tool-level errors.
//!
//! Every failure a tool can hit (bad arguments, an unreachable backend, an
//! HTTP error from the backend) becomes a [`ToolError`]. The MCP layer turns it
//! into a `CallToolResult` with `isError: true` so the model sees the message,
//! instead of an opaque JSON-RPC protocol error.
//!
//! HTTP error bodies follow the original FastAPI contract
//! (`backend/app/main.py`): `{"detail": "..."}` for most errors,
//! `{"detail": {"error": "password_required", "email": "..."}}` for locked
//! accounts (status 401), and `{"detail": [{"loc": [...], "msg": "..."}]}`
//! for request validation errors (status 422).

use serde_json::{json, Value};

/// A failure that should be reported to the model as a tool error.
#[derive(Debug, Clone, PartialEq)]
pub enum ToolError {
    /// The tool arguments were rejected before any request was sent.
    InvalidArguments(String),
    /// The backend answered 401 `password_required`: the account is locked.
    PasswordRequired { email: String },
    /// The backend answered with a non-success HTTP status.
    Backend { status: u16, detail: Value },
    /// The backend could not be reached (connection refused, timeout, ...).
    Unreachable { url: String, reason: String },
    /// The backend answered, but not with what the API contract promises.
    InvalidResponse(String),
}

impl ToolError {
    /// Shorthand for [`ToolError::InvalidArguments`].
    pub fn invalid(message: impl Into<String>) -> Self {
        Self::InvalidArguments(message.into())
    }

    /// Classify an error response from the backend.
    ///
    /// `detail` is the `detail` member of the JSON error body (or the whole
    /// body / text when the backend did not follow the FastAPI shape).
    pub fn from_status(status: u16, detail: Value) -> Self {
        if status == 401 {
            if let Some(object) = detail.as_object() {
                if object.get("error").and_then(Value::as_str) == Some("password_required") {
                    let email = object
                        .get("email")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_string();
                    return Self::PasswordRequired { email };
                }
            }
        }
        Self::Backend { status, detail }
    }

    /// HTTP status of the backend response, when there was one.
    pub fn status(&self) -> Option<u16> {
        match self {
            Self::PasswordRequired { .. } => Some(401),
            Self::Backend { status, .. } => Some(*status),
            _ => None,
        }
    }

    /// Human-readable explanation suitable for the model and the user.
    pub fn message(&self) -> String {
        match self {
            Self::InvalidArguments(message) => message.clone(),
            Self::PasswordRequired { email } => {
                let who = if email.is_empty() {
                    "This mail account".to_string()
                } else {
                    format!("The mail account {email}")
                };
                format!(
                    "{who} is locked. Ask the user to unlock it in the Thunderbird \
                     extension, then retry. This MCP server never receives mailbox \
                     passwords, so it cannot unlock accounts itself."
                )
            }
            Self::Backend { status, detail } => {
                format!("{} (HTTP {status})", detail_text(detail))
            }
            Self::Unreachable { url, reason } => format!(
                "Cannot reach the mail backend at {url}: {reason}. Make sure the \
                 Thunderbird extension's local backend is running, or point \
                 MAIL_BACKEND_URL at it."
            ),
            Self::InvalidResponse(message) => {
                format!("The mail backend returned an unexpected response: {message}")
            }
        }
    }

    /// JSON payload placed in the error tool result.
    pub fn to_json(&self) -> Value {
        let mut payload = json!({ "error": self.message() });
        match self {
            Self::PasswordRequired { email } => {
                payload["status"] = json!(401);
                payload["code"] = json!("password_required");
                payload["email"] = json!(email);
            }
            Self::Backend { status, detail } => {
                payload["status"] = json!(status);
                payload["detail"] = detail.clone();
            }
            Self::InvalidArguments(_) => payload["code"] = json!("invalid_arguments"),
            Self::Unreachable { .. } => payload["code"] = json!("backend_unreachable"),
            Self::InvalidResponse(_) => payload["code"] = json!("invalid_response"),
        }
        payload
    }
}

impl std::fmt::Display for ToolError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message())
    }
}

impl std::error::Error for ToolError {}

/// Render a FastAPI `detail` value as one line of text.
///
/// Strings are used as-is; validation error lists are joined as
/// `"field: message"` entries; anything else is shown as compact JSON.
pub fn detail_text(detail: &Value) -> String {
    match detail {
        Value::String(text) if !text.trim().is_empty() => text.clone(),
        Value::Array(items) if !items.is_empty() => {
            let parts: Vec<String> = items.iter().map(validation_item_text).collect();
            parts.join("; ")
        }
        Value::Null | Value::String(_) => "The mail backend request failed".to_string(),
        other => other.to_string(),
    }
}

fn validation_item_text(item: &Value) -> String {
    let Some(message) = item.get("msg").and_then(Value::as_str) else {
        return match item {
            Value::String(text) => text.clone(),
            other => other.to_string(),
        };
    };
    let field = item
        .get("loc")
        .and_then(Value::as_array)
        .map(|location| {
            location
                .iter()
                .filter(|part| part.as_str() != Some("body") && part.as_str() != Some("query"))
                .map(|part| match part {
                    Value::String(text) => text.clone(),
                    other => other.to_string(),
                })
                .collect::<Vec<_>>()
                .join(".")
        })
        .unwrap_or_default();
    if field.is_empty() {
        message.to_string()
    } else {
        format!("{field}: {message}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_required_is_recognised_only_for_401() {
        let detail = json!({"error": "password_required", "email": "a@example.com"});
        assert_eq!(
            ToolError::from_status(401, detail.clone()),
            ToolError::PasswordRequired {
                email: "a@example.com".into()
            }
        );
        assert!(matches!(
            ToolError::from_status(403, detail),
            ToolError::Backend { status: 403, .. }
        ));
        // A plain-string 401 (failed unlock) is not "password required".
        assert!(matches!(
            ToolError::from_status(401, json!("Login failed")),
            ToolError::Backend { status: 401, .. }
        ));
    }

    #[test]
    fn password_required_message_points_to_the_extension() {
        let error = ToolError::PasswordRequired {
            email: "a@example.com".into(),
        };
        let message = error.message();
        assert!(message.contains("a@example.com is locked"));
        assert!(message.contains("unlock it in the Thunderbird extension"));
        let payload = error.to_json();
        assert_eq!(payload["code"], "password_required");
        assert_eq!(payload["status"], 401);
    }

    #[test]
    fn detail_text_formats_fastapi_shapes() {
        assert_eq!(
            detail_text(&json!("Profile not found")),
            "Profile not found"
        );
        assert_eq!(
            detail_text(&json!([
                {"loc": ["query", "limit"], "msg": "Input should be less than or equal to 200"},
                {"loc": ["body"], "msg": "Value error, Choose a category or expiration to update"}
            ])),
            "limit: Input should be less than or equal to 200; \
             Value error, Choose a category or expiration to update"
        );
        assert_eq!(detail_text(&Value::Null), "The mail backend request failed");
        assert_eq!(detail_text(&json!({"a": 1})), "{\"a\":1}");
    }

    #[test]
    fn backend_error_message_includes_status_and_detail() {
        let error = ToolError::from_status(502, json!("IMAP login failed"));
        assert_eq!(error.message(), "IMAP login failed (HTTP 502)");
        assert_eq!(error.to_json()["detail"], "IMAP login failed");
        assert_eq!(error.status(), Some(502));
    }
}
