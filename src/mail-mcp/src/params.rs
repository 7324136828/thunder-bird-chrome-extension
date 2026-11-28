//! Tool argument types.
//!
//! Field names, defaults and limits mirror the original request models in
//! `backend/app/mail/schemas.py` and the query parameters in
//! `backend/app/main.py`. The JSON schemas advertised in `tools/list` are
//! generated from these types (doc comments become descriptions).
//!
//! Every mail tool takes an optional `account`. When it is omitted and exactly
//! one account is unlocked in the extension, that account is used.

use schemars::JsonSchema;
use serde::{Deserialize, Deserializer, Serialize};

/// Largest raw message excerpt `mail_get_raw_message` returns.
pub const MAX_RAW_MESSAGE_BYTES: usize = 4 * 1024 * 1024;
/// Default raw message excerpt size.
pub const DEFAULT_RAW_MESSAGE_BYTES: usize = 256 * 1024;
/// Largest attachment `mail_get_attachment` returns (before base64).
pub const MAX_ATTACHMENT_BYTES: usize = 10 * 1024 * 1024;
/// Default attachment cap.
pub const DEFAULT_ATTACHMENT_BYTES: usize = 2 * 1024 * 1024;

fn default_folder() -> String {
    "INBOX".to_string()
}

/// The five email categories (`EMAIL_CATEGORIES` in `backend/settings.py`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum Category {
    Marketing,
    Transactional,
    Updates,
    Verification,
    Uncategorized,
}

impl Category {
    /// The wire value.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Marketing => "marketing",
            Self::Transactional => "transactional",
            Self::Updates => "updates",
            Self::Verification => "verification",
            Self::Uncategorized => "uncategorized",
        }
    }
}

/// Read-status filter for message lists.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum ReadStatus {
    #[default]
    All,
    Unread,
    Read,
}

impl ReadStatus {
    /// The wire value.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::All => "all",
            Self::Unread => "unread",
            Self::Read => "read",
        }
    }
}

/// Accept a UID validity given either as a decimal string (the API format) or
/// as a JSON integer, and normalise it to the string form.
fn uid_validity_string<'de, D: Deserializer<'de>>(deserializer: D) -> Result<String, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Raw {
        Text(String),
        Number(u64),
    }
    Ok(match Raw::deserialize(deserializer)? {
        Raw::Text(text) => text,
        Raw::Number(number) => number.to_string(),
    })
}

fn optional_uid_validity<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<String>, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Raw {
        Text(String),
        Number(u64),
    }
    Ok(match Option::<Raw>::deserialize(deserializer)? {
        None => None,
        Some(Raw::Text(text)) if text.trim().is_empty() => None,
        Some(Raw::Text(text)) => Some(text),
        Some(Raw::Number(number)) => Some(number.to_string()),
    })
}

/// Distinguish "field absent" (`None`) from "field set to null"
/// (`Some(None)`), as the retention endpoint does via `model_fields_set`.
fn present<'de, D, T>(deserializer: D) -> Result<Option<Option<T>>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer).map(Some)
}

/// Schema transform: drop the `"default": null` that `#[serde(default)]`
/// adds, because for these fields null means "reset", not "keep".
/// `shift_remove` (not `remove`, which is `swap_remove` under serde_json's
/// `preserve_order`) keeps the remaining schema keys in their order.
fn without_default(schema: &mut schemars::Schema) {
    if let Some(object) = schema.as_object_mut() {
        object.shift_remove("default");
    }
}

/// Arguments that only select an account.
#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
pub struct AccountParams {
    /// Email address of an account unlocked in the extension. Optional when
    /// exactly one account is unlocked.
    #[serde(default)]
    pub account: Option<String>,
}

/// Arguments for `mail_list_messages` (`GET /api/mail/messages`).
#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct ListMessagesParams {
    /// Email address of an unlocked account. Optional when exactly one account is unlocked.
    #[serde(default)]
    pub account: Option<String>,
    /// Folder name exactly as returned by mail_list_folders.
    #[serde(default = "default_folder")]
    pub folder: String,
    /// Number of matching messages to skip (newest first).
    #[serde(default)]
    pub offset: Option<u32>,
    /// Page size, 1-200. Defaults to the user's "messages per page" setting.
    #[serde(default)]
    #[schemars(range(min = 1, max = 200))]
    pub limit: Option<u32>,
    /// Free-text search over the messages (max 200 characters).
    #[serde(default)]
    pub query: Option<String>,
    /// Only unread or only read messages.
    #[serde(default)]
    pub read_status: Option<ReadStatus>,
    /// Only messages whose sender belongs to one of these domains.
    #[serde(default)]
    pub sender_domain: Option<Vec<String>>,
    /// Only messages in this category.
    #[serde(default)]
    pub category: Option<Category>,
    /// Only messages whose retention period has expired.
    #[serde(default)]
    pub expired_only: bool,
}

/// Arguments identifying one message (`folder` + `uid`).
#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct MessageParams {
    /// Email address of an unlocked account. Optional when exactly one account is unlocked.
    #[serde(default)]
    pub account: Option<String>,
    /// Folder name exactly as returned by mail_list_folders.
    #[serde(default = "default_folder")]
    pub folder: String,
    /// Message UID from mail_list_messages.
    #[schemars(range(min = 1))]
    pub uid: u32,
}

/// Arguments for `mail_read_message` (`GET /api/mail/message`).
#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct ReadMessageParams {
    /// Email address of an unlocked account. Optional when exactly one account is unlocked.
    #[serde(default)]
    pub account: Option<String>,
    /// Folder name exactly as returned by mail_list_folders.
    #[serde(default = "default_folder")]
    pub folder: String,
    /// Message UID from mail_list_messages.
    #[schemars(range(min = 1))]
    pub uid: u32,
    /// Mark the message as read on the server. Defaults to false so that
    /// reading through the assistant does not change the mailbox.
    #[serde(default)]
    pub mark_seen: bool,
    /// Include the sanitized HTML body. When false (default) and a plain-text
    /// body exists, html_body is omitted to keep the result small.
    #[serde(default)]
    pub include_html: bool,
}

/// Arguments for `mail_get_raw_message` (`GET /api/mail/message/eml`).
#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct RawMessageParams {
    /// Email address of an unlocked account. Optional when exactly one account is unlocked.
    #[serde(default)]
    pub account: Option<String>,
    /// Folder name exactly as returned by mail_list_folders.
    #[serde(default = "default_folder")]
    pub folder: String,
    /// Message UID from mail_list_messages.
    #[schemars(range(min = 1))]
    pub uid: u32,
    /// Maximum number of bytes of the .eml source to return (default 262144,
    /// max 4194304). Longer messages are truncated.
    #[serde(default)]
    #[schemars(range(min = 1, max = 4194304))]
    pub max_bytes: Option<usize>,
}

/// Arguments for `mail_get_attachment` (`GET /api/mail/message/attachment`).
#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct AttachmentParams {
    /// Email address of an unlocked account. Optional when exactly one account is unlocked.
    #[serde(default)]
    pub account: Option<String>,
    /// Folder name exactly as returned by mail_list_folders.
    #[serde(default = "default_folder")]
    pub folder: String,
    /// Message UID from mail_list_messages.
    #[schemars(range(min = 1))]
    pub uid: u32,
    /// Attachment index from the message's attachments list.
    pub index: u32,
    /// Refuse attachments larger than this many bytes (default 2097152, max 10485760).
    #[serde(default)]
    #[schemars(range(min = 1, max = 10485760))]
    pub max_bytes: Option<usize>,
}

/// A file to attach to an outgoing message.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct SendAttachment {
    /// File name shown to the recipient.
    pub filename: String,
    /// MIME type, e.g. "application/pdf". Defaults to application/octet-stream.
    #[serde(default)]
    pub content_type: Option<String>,
    /// File contents, base64 encoded.
    pub content_base64: String,
}

/// Arguments for `mail_send` (`POST /api/mail/send` or `/api/mail/send/files`).
#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct SendParams {
    /// Sending account (an unlocked account). Optional when exactly one account is unlocked.
    #[serde(default)]
    pub account: Option<String>,
    /// Recipients ("a@example.com" or "Name <a@example.com>"), one address per entry.
    #[serde(default)]
    pub to: Vec<String>,
    /// Carbon-copy recipients.
    #[serde(default)]
    pub cc: Vec<String>,
    /// Blind carbon-copy recipients.
    #[serde(default)]
    pub bcc: Vec<String>,
    /// Subject line.
    #[serde(default)]
    pub subject: String,
    /// Plain-text body.
    #[serde(default)]
    pub text: String,
    /// Optional HTML body (sent as multipart/alternative with the text).
    #[serde(default)]
    pub html: Option<String>,
    /// Message-ID of the message being replied to.
    #[serde(default)]
    pub in_reply_to: Option<String>,
    /// References header for replies (space-separated Message-IDs).
    #[serde(default)]
    pub references: Option<String>,
    /// Files to attach (max 20 files, 10 MiB each, 20 MiB in total).
    #[serde(default)]
    pub attachments: Vec<SendAttachment>,
}

/// Arguments for `mail_move_to_trash` (`POST /api/mail/messages/delete`).
#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct MoveToTrashParams {
    /// Email address of an unlocked account. Optional when exactly one account is unlocked.
    #[serde(default)]
    pub account: Option<String>,
    /// Folder that currently contains the messages.
    pub folder: String,
    /// UIDs of the messages to move (1-500).
    #[schemars(length(min = 1, max = 500), inner(range(min = 1)))]
    pub uids: Vec<u32>,
    /// The uid_validity reported by mail_list_messages for these messages.
    /// Strongly recommended: the move is refused if the mailbox identity changed.
    #[serde(default, deserialize_with = "optional_uid_validity")]
    #[schemars(with = "Option<String>")]
    pub uid_validity: Option<String>,
}

/// Arguments for `mail_set_flags` (`POST /api/mail/message/flags`).
#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct SetFlagsParams {
    /// Email address of an unlocked account. Optional when exactly one account is unlocked.
    #[serde(default)]
    pub account: Option<String>,
    /// Folder name exactly as returned by mail_list_folders.
    pub folder: String,
    /// Message UID.
    #[schemars(range(min = 1))]
    pub uid: u32,
    /// true marks the message read, false marks it unread; omit to keep.
    #[serde(default)]
    pub seen: Option<bool>,
    /// true stars/flags the message, false removes the flag; omit to keep.
    #[serde(default)]
    pub flagged: Option<bool>,
}

/// Arguments for `mail_categorize` (`PUT /api/mail/message/retention`).
#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct CategorizeParams {
    /// Email address of an unlocked account. Optional when exactly one account is unlocked.
    #[serde(default)]
    pub account: Option<String>,
    /// Folder name exactly as returned by mail_list_folders.
    pub folder: String,
    /// Message UID.
    #[schemars(range(min = 1))]
    pub uid: u32,
    /// The message's uid_validity from mail_list_messages / mail_read_message.
    #[serde(deserialize_with = "uid_validity_string")]
    #[schemars(with = "String", regex(pattern = r"^[1-9][0-9]{0,9}$"))]
    pub uid_validity: String,
    /// New category. null resets to the automatic category; omit to keep.
    #[serde(default, deserialize_with = "present")]
    #[schemars(with = "Option<Category>", transform = without_default)]
    pub category: Option<Option<Category>>,
    /// Retention in days (negative = never expire, max 365000). null resets to
    /// the category default; omit to keep.
    #[serde(default, deserialize_with = "present")]
    #[schemars(with = "Option<i64>", transform = without_default)]
    pub expiration_days: Option<Option<i64>>,
}

/// Arguments for `mail_classify_with_local_ai` (`POST /api/mail/message/classify`).
#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct ClassifyParams {
    /// Email address of an unlocked account. Optional when exactly one account is unlocked.
    #[serde(default)]
    pub account: Option<String>,
    /// Folder name exactly as returned by mail_list_folders.
    pub folder: String,
    /// Message UID.
    #[schemars(range(min = 1))]
    pub uid: u32,
    /// The message's uid_validity from mail_list_messages / mail_read_message.
    #[serde(deserialize_with = "uid_validity_string")]
    #[schemars(with = "String", regex(pattern = r"^[1-9][0-9]{0,9}$"))]
    pub uid_validity: String,
}

/// Arguments for `mail_sender_rule_create` (`POST /api/mail/message/sender-rule`).
#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct SenderRuleCreateParams {
    /// Email address of an unlocked account. Optional when exactly one account is unlocked.
    #[serde(default)]
    pub account: Option<String>,
    /// Folder the rule applies to.
    pub folder: String,
    /// UID of a message from the sender.
    #[schemars(range(min = 1))]
    pub uid: u32,
    /// The message's uid_validity.
    #[serde(deserialize_with = "uid_validity_string")]
    #[schemars(with = "String", regex(pattern = r"^[1-9][0-9]{0,9}$"))]
    pub uid_validity: String,
    /// Category for this sender. Must equal the message's current category
    /// (change it first with mail_categorize if needed).
    pub category: Category,
    /// Optional optimistic-concurrency guard: the message's category revision
    /// (0 for a message whose category was never changed). Usually omitted;
    /// the rule is refused with a conflict if the category changed meanwhile.
    #[serde(default)]
    #[schemars(range(min = 0))]
    pub expected_category_revision: Option<u64>,
}

/// Arguments for `mail_sender_rule_list` (`GET /api/mail/sender-rules`).
#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct SenderRuleListParams {
    /// Email address of an unlocked account. Optional when exactly one account is unlocked.
    #[serde(default)]
    pub account: Option<String>,
    /// Only rules for this folder; omit for all folders.
    #[serde(default)]
    pub folder: Option<String>,
}

/// Arguments for `mail_sender_rule_delete` (`DELETE /api/mail/sender-rules`).
#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct SenderRuleDeleteParams {
    /// Email address of an unlocked account. Optional when exactly one account is unlocked.
    #[serde(default)]
    pub account: Option<String>,
    /// Folder of the rule.
    pub folder: String,
    /// Sender address of the rule.
    pub sender: String,
    /// Optional revision guard from mail_sender_rule_list.
    #[serde(default)]
    #[schemars(range(min = 1))]
    pub expected_revision: Option<u64>,
}

/// Arguments for `mail_empty_trash`.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct EmptyTrashParams {
    /// Email address of an unlocked account. Optional when exactly one account is unlocked.
    #[serde(default)]
    pub account: Option<String>,
    /// Must be true. Only set it after the user explicitly confirmed that every
    /// message in the server Trash should be permanently deleted.
    #[serde(default)]
    pub confirm: bool,
    /// Optional safety check: abort without deleting anything unless Trash
    /// contains exactly this many messages.
    #[serde(default)]
    pub expected_count: Option<u64>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn folder_defaults_to_inbox() {
        let params: MessageParams = serde_json::from_value(json!({"uid": 4})).unwrap();
        assert_eq!(params.folder, "INBOX");
        assert_eq!(params.account, None);
    }

    #[test]
    fn categorize_distinguishes_absent_and_null() {
        let absent: CategorizeParams =
            serde_json::from_value(json!({"folder": "INBOX", "uid": 1, "uid_validity": "7"}))
                .unwrap();
        assert_eq!(absent.category, None);
        assert_eq!(absent.expiration_days, None);

        let reset: CategorizeParams = serde_json::from_value(json!({
            "folder": "INBOX", "uid": 1, "uid_validity": 7,
            "category": null, "expiration_days": 30
        }))
        .unwrap();
        assert_eq!(reset.uid_validity, "7");
        assert_eq!(reset.category, Some(None));
        assert_eq!(reset.expiration_days, Some(Some(30)));
    }

    #[test]
    fn categories_and_read_status_use_wire_names() {
        let params: ListMessagesParams = serde_json::from_value(json!({
            "category": "verification", "read_status": "unread"
        }))
        .unwrap();
        assert_eq!(params.category, Some(Category::Verification));
        assert_eq!(params.read_status, Some(ReadStatus::Unread));
        assert!(serde_json::from_value::<ListMessagesParams>(json!({"category": "spam"})).is_err());
    }

    #[test]
    fn move_to_trash_accepts_numeric_or_blank_uid_validity() {
        let numeric: MoveToTrashParams = serde_json::from_value(json!({
            "folder": "INBOX", "uids": [1], "uid_validity": 42
        }))
        .unwrap();
        assert_eq!(numeric.uid_validity.as_deref(), Some("42"));
        let blank: MoveToTrashParams = serde_json::from_value(json!({
            "folder": "INBOX", "uids": [1], "uid_validity": ""
        }))
        .unwrap();
        assert_eq!(blank.uid_validity, None);
    }
}
