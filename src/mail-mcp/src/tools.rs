//! Tool implementations: each tool is one or a few calls to the mail-backend.
//!
//! Request shapes follow the original FastAPI routes (`backend/app/main.py`)
//! and the way the original React client calls them
//! (`frontend/src/api.ts`, `frontend/src/App.tsx`,
//! `frontend/src/components/TrashActionsModal.tsx`). Successful results are the
//! backend's JSON, occasionally annotated with extra fields (documented per
//! tool); failures are [`ToolError`]s.

use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use base64::Engine;
use percent_encoding::percent_decode_str;
use reqwest::multipart::{Form, Part};
use reqwest::Method;
use serde_json::{json, Map, Value};

use crate::backend::{BackendClient, Query};
use crate::error::ToolError;
use crate::params::*;

/// Most files one message may carry (`MAX_SEND_FILES` in schemas.py).
pub const MAX_SEND_FILES: usize = 20;
/// Largest single attachment (`MAX_SEND_FILE_BYTES` in schemas.py).
pub const MAX_SEND_FILE_BYTES: usize = 10 * 1024 * 1024;
/// Largest combined attachment size (`MAX_SEND_FILES_BYTES` in schemas.py).
pub const MAX_SEND_FILES_BYTES: usize = 20 * 1024 * 1024;
/// Most UIDs per bulk delete (`DeleteMessagesIn.uids` max_length).
pub const MAX_DELETE_UIDS: usize = 500;

/// The mail tools, backed by the loopback mail-backend.
#[derive(Debug, Clone)]
pub struct MailTools {
    client: BackendClient,
}

impl MailTools {
    /// Wrap a backend client.
    pub fn new(client: BackendClient) -> Self {
        Self { client }
    }

    /// The underlying backend client.
    pub fn client(&self) -> &BackendClient {
        &self.client
    }

    /// Resolve the account to act on.
    ///
    /// An explicit address is used as given (trimmed). Without one, the
    /// unlocked accounts are listed and the single unlocked account is used.
    pub async fn resolve_account(&self, account: Option<&str>) -> Result<String, ToolError> {
        if let Some(account) = account.map(str::trim).filter(|value| !value.is_empty()) {
            return Ok(account.to_string());
        }
        let listed = self.list_accounts().await?;
        let emails: Vec<String> = listed
            .get("accounts")
            .and_then(Value::as_array)
            .map(|accounts| {
                accounts
                    .iter()
                    .filter_map(|account| account.get("email").and_then(Value::as_str))
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default();
        match emails.as_slice() {
            [single] => Ok(single.clone()),
            [] => Err(ToolError::invalid(
                "No mail account is unlocked. Ask the user to unlock an account in the \
                 Thunderbird extension first; this MCP server never handles passwords.",
            )),
            many => Err(ToolError::invalid(format!(
                "Several accounts are unlocked ({}); pass the `account` argument.",
                many.join(", ")
            ))),
        }
    }

    /// `mail_list_accounts`: `GET /api/accounts`.
    pub async fn list_accounts(&self) -> Result<Value, ToolError> {
        self.client.get_json(&["api", "accounts"], &[]).await
    }

    /// `mail_get_settings`: `GET /api/settings`.
    pub async fn get_settings(&self) -> Result<Value, ToolError> {
        self.client.get_json(&["api", "settings"], &[]).await
    }

    /// `mail_list_folders`: `GET /api/mail/folders?account=`.
    pub async fn list_folders(&self, params: AccountParams) -> Result<Value, ToolError> {
        let account = self.resolve_account(params.account.as_deref()).await?;
        self.folders(&account).await
    }

    async fn folders(&self, account: &str) -> Result<Value, ToolError> {
        self.client
            .get_json(
                &["api", "mail", "folders"],
                &[("account", account.to_string())],
            )
            .await
    }

    /// `mail_list_messages`: `GET /api/mail/messages` with the same query
    /// parameters the React client builds (`messageQuery` in api.ts).
    pub async fn list_messages(&self, params: ListMessagesParams) -> Result<Value, ToolError> {
        let account = self.resolve_account(params.account.as_deref()).await?;
        let query = list_messages_query(&account, &params);
        self.client
            .get_json(&["api", "mail", "messages"], &query)
            .await
    }

    /// `mail_read_message`: `GET /api/mail/message`. `mark_seen` is always
    /// sent explicitly because the backend defaults it to true.
    pub async fn read_message(&self, params: ReadMessageParams) -> Result<Value, ToolError> {
        let account = self.resolve_account(params.account.as_deref()).await?;
        let query: Query = vec![
            ("account", account),
            ("folder", params.folder),
            ("uid", params.uid.to_string()),
            ("mark_seen", params.mark_seen.to_string()),
        ];
        let message = self
            .client
            .get_json(&["api", "mail", "message"], &query)
            .await?;
        Ok(if params.include_html {
            message
        } else {
            omit_redundant_html(message)
        })
    }

    /// `mail_get_raw_message`: `GET /api/mail/message/eml`, returned as text
    /// (lossy UTF-8) and truncated to `max_bytes`.
    pub async fn get_raw_message(&self, params: RawMessageParams) -> Result<Value, ToolError> {
        let max_bytes = cap(
            params.max_bytes,
            DEFAULT_RAW_MESSAGE_BYTES,
            MAX_RAW_MESSAGE_BYTES,
        )?;
        let account = self.resolve_account(params.account.as_deref()).await?;
        let query: Query = vec![
            ("account", account.clone()),
            ("folder", params.folder.clone()),
            ("uid", params.uid.to_string()),
        ];
        let download = self
            .client
            .get_bytes(&["api", "mail", "message", "eml"], &query, max_bytes)
            .await?;
        let size = if download.truncated {
            download
                .content_length
                .map(Value::from)
                .unwrap_or(Value::Null)
        } else {
            Value::from(download.data.len())
        };
        Ok(json!({
            "account": account,
            "folder": params.folder,
            "uid": params.uid,
            "size": size,
            "returned_bytes": download.data.len(),
            "truncated": download.truncated,
            "eml": String::from_utf8_lossy(&download.data),
        }))
    }

    /// `mail_get_attachment`: `GET /api/mail/message/attachment`, returned as
    /// base64. Attachments over `max_bytes` are refused rather than truncated.
    pub async fn get_attachment(&self, params: AttachmentParams) -> Result<Value, ToolError> {
        let max_bytes = cap(
            params.max_bytes,
            DEFAULT_ATTACHMENT_BYTES,
            MAX_ATTACHMENT_BYTES,
        )?;
        let account = self.resolve_account(params.account.as_deref()).await?;
        let query: Query = vec![
            ("account", account.clone()),
            ("folder", params.folder.clone()),
            ("uid", params.uid.to_string()),
            ("index", params.index.to_string()),
        ];
        let download = self
            .client
            .get_bytes(&["api", "mail", "message", "attachment"], &query, max_bytes)
            .await?;
        if download.truncated {
            let size = download
                .content_length
                .map(|length| format!("{length} bytes"))
                .unwrap_or_else(|| format!("more than {max_bytes} bytes"));
            return Err(ToolError::invalid(format!(
                "The attachment is {size}, which exceeds max_bytes ({max_bytes}). Retry with a \
                 larger max_bytes (up to {MAX_ATTACHMENT_BYTES}) if the content is really needed."
            )));
        }
        let filename = download
            .content_disposition
            .as_deref()
            .and_then(disposition_filename)
            .unwrap_or_else(|| "attachment".to_string());
        let content_type = download
            .content_type
            .unwrap_or_else(|| "application/octet-stream".to_string());
        Ok(json!({
            "account": account,
            "folder": params.folder,
            "uid": params.uid,
            "index": params.index,
            "filename": filename,
            "content_type": content_type,
            "size": download.data.len(),
            "content_base64": STANDARD.encode(&download.data),
        }))
    }

    /// `mail_send`: JSON `POST /api/mail/send`, or multipart
    /// `POST /api/mail/send/files` when there are attachments (the exact
    /// FormData layout the React client uses: one `message` JSON field with
    /// `uploads` metadata, then one `files` part per attachment).
    pub async fn send(&self, params: SendParams) -> Result<Value, ToolError> {
        let files = decode_attachments(&params.attachments)?;
        let account = self.resolve_account(params.account.as_deref()).await?;
        let mut body = send_body(&account, &params);
        if files.is_empty() {
            return self
                .client
                .json_request(Method::POST, &["api", "mail", "send"], &[], Some(&body))
                .await;
        }
        body["uploads"] = Value::Array(
            files
                .iter()
                .map(|_| json!({"content_id": "", "disposition": "attachment"}))
                .collect(),
        );
        let mut form = Form::new().text("message", body.to_string());
        for file in files {
            let part = Part::bytes(file.data)
                .file_name(file.filename)
                .mime_str(&file.content_type)
                .map_err(|_| ToolError::invalid("The attachment content type is invalid"))?;
            form = form.part("files", part);
        }
        self.client
            .post_multipart(&["api", "mail", "send", "files"], form)
            .await
    }

    /// `mail_move_to_trash`: resolve the account's Trash folder the way the
    /// React client does (`folders.find(f => f.special === 'trash' &&
    /// f.selectable)`), then `POST /api/mail/messages/delete` with it.
    ///
    /// Unlike the backend (which deletes permanently when `trash` is empty),
    /// this tool never deletes without a server Trash folder.
    pub async fn move_to_trash(&self, params: MoveToTrashParams) -> Result<Value, ToolError> {
        let mut uids = Vec::with_capacity(params.uids.len());
        for uid in &params.uids {
            if *uid == 0 {
                return Err(ToolError::invalid("Message UIDs must be positive integers"));
            }
            if !uids.contains(uid) {
                uids.push(*uid);
            }
        }
        if uids.is_empty() {
            return Err(ToolError::invalid(
                "Choose at least one message UID to move to Trash",
            ));
        }
        if uids.len() > MAX_DELETE_UIDS {
            return Err(ToolError::invalid(format!(
                "Move at most {MAX_DELETE_UIDS} messages at a time"
            )));
        }
        let account = self.resolve_account(params.account.as_deref()).await?;
        let trash = self.require_trash_folder(&account).await?;
        if trash == params.folder {
            return Err(ToolError::invalid(format!(
                "The messages are already in the Trash folder \"{trash}\". Nothing was changed; \
                 use mail_empty_trash to delete Trash permanently."
            )));
        }
        let mut body = json!({
            "account": account,
            "folder": params.folder,
            "uids": uids,
            "trash": trash,
        });
        if let Some(uid_validity) = &params.uid_validity {
            body["uid_validity"] = json!(uid_validity);
        }
        let mut result = self
            .client
            .json_request(
                Method::POST,
                &["api", "mail", "messages", "delete"],
                &[],
                Some(&body),
            )
            .await?;
        if let Some(object) = result.as_object_mut() {
            object.insert("trash_folder".into(), json!(trash));
        }
        Ok(result)
    }

    /// `mail_set_flags`: `POST /api/mail/message/flags`.
    pub async fn set_flags(&self, params: SetFlagsParams) -> Result<Value, ToolError> {
        if params.seen.is_none() && params.flagged.is_none() {
            return Err(ToolError::invalid("Choose seen and/or flagged to update"));
        }
        let account = self.resolve_account(params.account.as_deref()).await?;
        let mut body = json!({"account": account, "folder": params.folder, "uid": params.uid});
        if let Some(seen) = params.seen {
            body["seen"] = json!(seen);
        }
        if let Some(flagged) = params.flagged {
            body["flagged"] = json!(flagged);
        }
        self.client
            .json_request(
                Method::POST,
                &["api", "mail", "message", "flags"],
                &[],
                Some(&body),
            )
            .await
    }

    /// `mail_categorize`: `PUT /api/mail/message/retention`. Only the fields
    /// the caller supplied are sent; `null` resets a field, as in the UI.
    pub async fn categorize(&self, params: CategorizeParams) -> Result<Value, ToolError> {
        if params.category.is_none() && params.expiration_days.is_none() {
            // Same message as MessageRetentionIn.require_change.
            return Err(ToolError::invalid(
                "Choose a category or expiration to update",
            ));
        }
        let account = self.resolve_account(params.account.as_deref()).await?;
        let mut body = json!({
            "account": account,
            "folder": params.folder,
            "uid": params.uid,
            "uid_validity": params.uid_validity,
        });
        if let Some(category) = params.category {
            body["category"] = json!(category.map(Category::as_str));
        }
        if let Some(days) = params.expiration_days {
            body["expiration_days"] = json!(days);
        }
        self.client
            .json_request(
                Method::PUT,
                &["api", "mail", "message", "retention"],
                &[],
                Some(&body),
            )
            .await
    }

    /// `mail_classify_with_local_ai`: `POST /api/mail/message/classify`.
    pub async fn classify(&self, params: ClassifyParams) -> Result<Value, ToolError> {
        let account = self.resolve_account(params.account.as_deref()).await?;
        let body = json!({
            "account": account,
            "folder": params.folder,
            "uid": params.uid,
            "uid_validity": params.uid_validity,
        });
        self.client
            .json_request(
                Method::POST,
                &["api", "mail", "message", "classify"],
                &[],
                Some(&body),
            )
            .await
    }

    /// `mail_sender_rule_create`: `POST /api/mail/message/sender-rule`.
    pub async fn sender_rule_create(
        &self,
        params: SenderRuleCreateParams,
    ) -> Result<Value, ToolError> {
        let account = self.resolve_account(params.account.as_deref()).await?;
        let mut body = json!({
            "account": account,
            "folder": params.folder,
            "uid": params.uid,
            "uid_validity": params.uid_validity,
            "category": params.category.as_str(),
        });
        if let Some(revision) = params.expected_category_revision {
            body["expected_category_revision"] = json!(revision);
        }
        self.client
            .json_request(
                Method::POST,
                &["api", "mail", "message", "sender-rule"],
                &[],
                Some(&body),
            )
            .await
    }

    /// `mail_sender_rule_list`: `GET /api/mail/sender-rules`.
    pub async fn sender_rule_list(&self, params: SenderRuleListParams) -> Result<Value, ToolError> {
        let account = self.resolve_account(params.account.as_deref()).await?;
        let mut query: Query = vec![("account", account)];
        if let Some(folder) = params.folder.filter(|folder| !folder.is_empty()) {
            query.push(("folder", folder));
        }
        self.client
            .get_json(&["api", "mail", "sender-rules"], &query)
            .await
    }

    /// `mail_sender_rule_delete`: `DELETE /api/mail/sender-rules`.
    pub async fn sender_rule_delete(
        &self,
        params: SenderRuleDeleteParams,
    ) -> Result<Value, ToolError> {
        let account = self.resolve_account(params.account.as_deref()).await?;
        let mut query: Query = vec![
            ("account", account),
            ("folder", params.folder),
            ("sender", params.sender),
        ];
        if let Some(revision) = params.expected_revision {
            query.push(("expected_revision", revision.to_string()));
        }
        self.client
            .json_request(
                Method::DELETE,
                &["api", "mail", "sender-rules"],
                &query,
                None,
            )
            .await
    }

    /// `mail_audit_message`: `GET /api/mail/audit`.
    pub async fn audit_message(&self, params: MessageParams) -> Result<Value, ToolError> {
        let account = self.resolve_account(params.account.as_deref()).await?;
        let query: Query = vec![
            ("account", account),
            ("folder", params.folder),
            ("uid", params.uid.to_string()),
        ];
        self.client
            .get_json(&["api", "mail", "audit"], &query)
            .await
    }

    /// `mail_empty_trash`: the UI's "Empty trash bin" flow without the ZIP
    /// archive: `POST /api/mail/trash/prepare` (archive=false) for the
    /// verified Trash folder, `POST /api/mail/trash/{id}/empty`, and finally
    /// `DELETE /api/mail/trash/{id}` to release the operation (the modal does
    /// this when it closes). Requires `confirm=true`.
    pub async fn empty_trash(&self, params: EmptyTrashParams) -> Result<Value, ToolError> {
        if !params.confirm {
            return Err(ToolError::invalid(
                "Emptying Trash permanently deletes every message in it and cannot be undone. \
                 Ask the user to confirm, then call again with confirm=true. Nothing was deleted.",
            ));
        }
        let account = self.resolve_account(params.account.as_deref()).await?;
        let trash = self.require_trash_folder(&account).await?;
        let prepared = self
            .client
            .json_request(
                Method::POST,
                &["api", "mail", "trash", "prepare"],
                &[],
                Some(&json!({"account": account, "folder": trash, "archive": false})),
            )
            .await?;
        let operation_id = prepared
            .get("operation_id")
            .and_then(Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| ToolError::InvalidResponse("the Trash operation has no id".into()))?;
        let count = prepared.get("count").and_then(Value::as_u64).unwrap_or(0);

        if let Some(expected) = params.expected_count {
            if expected != count {
                self.discard_trash_operation(&account, &operation_id).await;
                return Err(ToolError::invalid(format!(
                    "Trash now contains {count} messages, not the expected {expected}. \
                     Nothing was deleted."
                )));
            }
        }
        if count == 0 {
            self.discard_trash_operation(&account, &operation_id).await;
            return Ok(json!({"trash_folder": trash, "deleted": 0, "remaining": 0}));
        }

        let emptied = self
            .client
            .json_request(
                Method::POST,
                &["api", "mail", "trash", &operation_id, "empty"],
                &[],
                Some(&json!({"account": account})),
            )
            .await;
        // Release the snapshot whatever happened; a retry prepares a new
        // snapshot of whatever is still in Trash.
        self.discard_trash_operation(&account, &operation_id).await;
        let emptied = emptied?;
        let mut result = Map::new();
        result.insert("trash_folder".into(), json!(trash));
        if let Value::Object(fields) = emptied {
            result.extend(fields);
        }
        Ok(Value::Object(result))
    }

    async fn discard_trash_operation(&self, account: &str, operation_id: &str) {
        let outcome = self
            .client
            .json_request(
                Method::DELETE,
                &["api", "mail", "trash", operation_id],
                &[("account", account.to_string())],
                None,
            )
            .await;
        if let Err(error) = outcome {
            tracing::debug!("discarding the Trash operation failed: {error}");
        }
    }

    async fn require_trash_folder(&self, account: &str) -> Result<String, ToolError> {
        let folders = self.folders(account).await?;
        trash_folder(&folders).ok_or_else(|| {
            ToolError::invalid(
                "This account has no selectable server Trash folder (special-use \\Trash), so \
                 messages cannot be moved to or emptied from Trash. Nothing was changed.",
            )
        })
    }
}

/// The first selectable folder whose special use is `trash`.
pub fn trash_folder(folders: &Value) -> Option<String> {
    folders
        .get("folders")?
        .as_array()?
        .iter()
        .find(|folder| {
            folder.get("special").and_then(Value::as_str) == Some("trash")
                && folder.get("selectable").and_then(Value::as_bool) == Some(true)
        })
        .and_then(|folder| folder.get("name").and_then(Value::as_str))
        .filter(|name| !name.is_empty())
        .map(str::to_string)
}

/// Query string for `GET /api/mail/messages`, in the order the UI builds it.
pub fn list_messages_query(account: &str, params: &ListMessagesParams) -> Query {
    let mut query: Query = vec![
        ("account", account.to_string()),
        ("folder", params.folder.clone()),
    ];
    if let Some(offset) = params.offset {
        query.push(("offset", offset.to_string()));
    }
    if let Some(limit) = params.limit {
        query.push(("limit", limit.to_string()));
    }
    if let Some(text) = &params.query {
        query.push(("query", text.clone()));
    }
    for domain in params.sender_domain.iter().flatten() {
        query.push(("sender_domain", domain.clone()));
    }
    if let Some(status) = params
        .read_status
        .filter(|status| *status != ReadStatus::All)
    {
        query.push(("read_status", status.as_str().to_string()));
    }
    if let Some(category) = params.category {
        query.push(("category", category.as_str().to_string()));
    }
    if params.expired_only {
        query.push(("expired_only", "true".to_string()));
    }
    query
}

/// JSON body for `/api/mail/send` (`SendMessage` in api.ts).
pub fn send_body(account: &str, params: &SendParams) -> Value {
    let mut body = json!({
        "account": account,
        "to": params.to,
        "cc": params.cc,
        "bcc": params.bcc,
        "subject": params.subject,
        "text": params.text,
    });
    if let Some(html) = &params.html {
        body["html"] = json!(html);
    }
    if let Some(in_reply_to) = &params.in_reply_to {
        body["in_reply_to"] = json!(in_reply_to);
    }
    if let Some(references) = &params.references {
        body["references"] = json!(references);
    }
    body
}

/// A decoded outgoing attachment.
#[derive(Debug, Clone, PartialEq)]
pub struct DecodedAttachment {
    pub filename: String,
    pub content_type: String,
    pub data: Vec<u8>,
}

/// Decode and size-check outgoing attachments before contacting the backend.
/// Limit messages match `validate_files` in send_uploads.py.
pub fn decode_attachments(
    attachments: &[SendAttachment],
) -> Result<Vec<DecodedAttachment>, ToolError> {
    if attachments.len() > MAX_SEND_FILES {
        return Err(ToolError::invalid("Attach no more than 20 files"));
    }
    let mut total = 0usize;
    let mut decoded = Vec::with_capacity(attachments.len());
    for (position, attachment) in attachments.iter().enumerate() {
        let data = decode_base64(&attachment.content_base64).ok_or_else(|| {
            ToolError::invalid(format!(
                "Attachment {} ({}) is not valid base64",
                position + 1,
                attachment.filename
            ))
        })?;
        total += data.len();
        if data.len() > MAX_SEND_FILE_BYTES {
            return Err(ToolError::invalid(
                "Each attachment must be no larger than 10 MiB",
            ));
        }
        if total > MAX_SEND_FILES_BYTES {
            return Err(ToolError::invalid(
                "Attachments must total no more than 20 MiB",
            ));
        }
        let content_type = attachment
            .content_type
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or("application/octet-stream")
            .to_string();
        // The backend refuses control characters (`normalize_filename` in
        // send_uploads.py). Check here: reqwest only backslash-escapes CR/LF
        // in the part header, leaving a raw line break that breaks the
        // multipart framing (400 "Invalid multipart data.") instead of
        // producing the backend's clear message.
        if !header_safe(&attachment.filename) {
            return Err(ToolError::invalid(
                "Attachment filenames cannot contain control characters",
            ));
        }
        if let Some(content_type) = &attachment.content_type {
            if !header_safe(content_type) {
                return Err(ToolError::invalid(
                    "Attachment content types cannot contain control characters",
                ));
            }
        }
        let filename = if attachment.filename.trim().is_empty() {
            "attachment".to_string()
        } else {
            attachment.filename.clone()
        };
        decoded.push(DecodedAttachment {
            filename,
            content_type,
            data,
        });
    }
    Ok(decoded)
}

/// No ASCII control characters (`header_safe` in schemas.py).
fn header_safe(value: &str) -> bool {
    !value.chars().any(|c| c.is_ascii_control())
}

fn decode_base64(value: &str) -> Option<Vec<u8>> {
    let compact: String = value.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    // Tolerate data: URLs, which models sometimes produce.
    let compact = match compact.split_once(";base64,") {
        Some((prefix, rest)) if prefix.starts_with("data:") => rest.to_string(),
        _ => compact,
    };
    [STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD]
        .iter()
        .find_map(|engine| engine.decode(&compact).ok())
}

/// Drop `html_body` when a plain-text body is available, marking the omission.
///
/// `serde_json` is built with `preserve_order`, where `Map::remove` is
/// `swap_remove` and would move the last key (for example `attachments`) into
/// `html_body`'s slot. `shift_remove` keeps the backend's key order, and
/// `html_body_omitted` is appended at the end.
fn omit_redundant_html(mut message: Value) -> Value {
    let has_text = message
        .get("text_body")
        .and_then(Value::as_str)
        .is_some_and(|text| !text.trim().is_empty());
    let has_html = message
        .get("html_body")
        .and_then(Value::as_str)
        .is_some_and(|html| !html.is_empty());
    if has_text && has_html {
        if let Some(object) = message.as_object_mut() {
            object.shift_remove("html_body");
            object.insert("html_body_omitted".into(), Value::Bool(true));
        }
    }
    message
}

fn cap(requested: Option<usize>, default: usize, max: usize) -> Result<usize, ToolError> {
    match requested {
        None => Ok(default),
        Some(0) => Err(ToolError::invalid("max_bytes must be at least 1")),
        Some(value) if value > max => Err(ToolError::invalid(format!(
            "max_bytes must be no greater than {max}"
        ))),
        Some(value) => Ok(value),
    }
}

/// File name from a `Content-Disposition` header (`filename*=` preferred).
pub fn disposition_filename(header: &str) -> Option<String> {
    let mut plain = None;
    for parameter in header.split(';').skip(1) {
        let Some((name, value)) = parameter.split_once('=') else {
            continue;
        };
        let name = name.trim().to_ascii_lowercase();
        let value = value.trim();
        if name == "filename*" {
            // RFC 5987: charset'language'percent-encoded-value
            let encoded = value.splitn(3, '\'').nth(2).unwrap_or(value);
            let decoded = percent_decode_str(encoded).decode_utf8_lossy().into_owned();
            if !decoded.is_empty() {
                return Some(decoded);
            }
        } else if name == "filename" {
            let unquoted = value
                .strip_prefix('"')
                .and_then(|inner| inner.strip_suffix('"'))
                .unwrap_or(value);
            if !unquoted.is_empty() {
                plain = Some(unquoted.to_string());
            }
        }
    }
    plain
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trash_folder_requires_selectable_special_use() {
        let folders = json!({"folders": [
            {"name": "INBOX", "special": "inbox", "selectable": true},
            {"name": "Old Trash", "special": "trash", "selectable": false},
            {"name": "Deleted Items", "special": "trash", "selectable": true},
        ]});
        assert_eq!(trash_folder(&folders).as_deref(), Some("Deleted Items"));
        assert_eq!(
            trash_folder(
                &json!({"folders": [{"name": "INBOX", "special": "", "selectable": true}]})
            ),
            None
        );
        assert_eq!(trash_folder(&json!({})), None);
    }

    #[test]
    fn list_query_matches_the_ui_query_builder() {
        let params: ListMessagesParams = serde_json::from_value(json!({
            "folder": "Work", "offset": 10, "limit": 25, "query": "invoice",
            "sender_domain": ["a.com", "b.org"], "read_status": "unread",
            "category": "marketing", "expired_only": true
        }))
        .unwrap();
        let query = list_messages_query("me@example.com", &params);
        assert_eq!(
            query,
            vec![
                ("account", "me@example.com".to_string()),
                ("folder", "Work".to_string()),
                ("offset", "10".to_string()),
                ("limit", "25".to_string()),
                ("query", "invoice".to_string()),
                ("sender_domain", "a.com".to_string()),
                ("sender_domain", "b.org".to_string()),
                ("read_status", "unread".to_string()),
                ("category", "marketing".to_string()),
                ("expired_only", "true".to_string()),
            ]
        );
        let minimal: ListMessagesParams =
            serde_json::from_value(json!({"read_status": "all"})).unwrap();
        assert_eq!(
            list_messages_query("me@example.com", &minimal),
            vec![
                ("account", "me@example.com".to_string()),
                ("folder", "INBOX".to_string())
            ]
        );
    }

    #[test]
    fn attachments_are_decoded_and_limited() {
        let attachment = |data: &str| SendAttachment {
            filename: "a.txt".into(),
            content_type: None,
            content_base64: data.into(),
        };
        let decoded = decode_attachments(&[attachment("aGVs\nbG8=")]).unwrap();
        assert_eq!(decoded[0].data, b"hello");
        assert_eq!(decoded[0].content_type, "application/octet-stream");
        assert_eq!(
            decode_attachments(&[attachment("data:text/plain;base64,aGk")]).unwrap()[0].data,
            b"hi"
        );
        assert!(decode_attachments(&[attachment("***")])
            .unwrap_err()
            .message()
            .contains("not valid base64"));
        let many = vec![attachment("aGk="); 21];
        assert_eq!(
            decode_attachments(&many).unwrap_err().message(),
            "Attach no more than 20 files"
        );
        let big = STANDARD.encode(vec![0u8; MAX_SEND_FILE_BYTES + 1]);
        assert_eq!(
            decode_attachments(&[attachment(&big)])
                .unwrap_err()
                .message(),
            "Each attachment must be no larger than 10 MiB"
        );
        let nine = STANDARD.encode(vec![0u8; 9 * 1024 * 1024]);
        assert_eq!(
            decode_attachments(&[attachment(&nine), attachment(&nine), attachment(&nine)])
                .unwrap_err()
                .message(),
            "Attachments must total no more than 20 MiB"
        );
    }

    #[test]
    fn attachment_names_with_control_characters_are_refused() {
        let named = |filename: &str, content_type: Option<&str>| SendAttachment {
            filename: filename.into(),
            content_type: content_type.map(str::to_string),
            content_base64: "aGk=".into(),
        };
        assert_eq!(
            decode_attachments(&[named("a\r\nX-Evil: 1.txt", None)])
                .unwrap_err()
                .message(),
            "Attachment filenames cannot contain control characters"
        );
        assert_eq!(
            decode_attachments(&[named("a.txt", Some("text/plain\r\nX: y"))])
                .unwrap_err()
                .message(),
            "Attachment content types cannot contain control characters"
        );
        assert_eq!(
            decode_attachments(&[named("résumé report.txt", Some("text/plain"))]).unwrap()[0]
                .filename,
            "résumé report.txt"
        );
    }

    #[test]
    fn content_disposition_filenames() {
        assert_eq!(
            disposition_filename(r#"attachment; filename="report.pdf""#).as_deref(),
            Some("report.pdf")
        );
        assert_eq!(
            disposition_filename("attachment; filename=plain.txt").as_deref(),
            Some("plain.txt")
        );
        assert_eq!(
            disposition_filename(
                r#"attachment; filename="r_sum_.pdf"; filename*=UTF-8''r%C3%A9sum%C3%A9.pdf"#
            )
            .as_deref(),
            Some("résumé.pdf")
        );
        assert_eq!(disposition_filename("attachment"), None);
    }

    #[test]
    fn html_is_omitted_only_when_text_exists() {
        let both = omit_redundant_html(json!({"text_body": "hi", "html_body": "<p>hi</p>"}));
        assert_eq!(both, json!({"text_body": "hi", "html_body_omitted": true}));
        let html_only = omit_redundant_html(json!({"text_body": "", "html_body": "<p>hi</p>"}));
        assert_eq!(html_only["html_body"], "<p>hi</p>");
    }

    #[test]
    fn omitting_html_keeps_the_key_order() {
        let message = json!({
            "uid": 7, "subject": "s", "text_body": "hi", "html_body": "<p>hi</p>",
            "attachments": [], "category": "updates", "expires_at": null
        });
        let keys: Vec<String> = omit_redundant_html(message)
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect();
        assert_eq!(
            keys,
            [
                "uid",
                "subject",
                "text_body",
                "attachments",
                "category",
                "expires_at",
                "html_body_omitted"
            ]
        );
    }

    #[test]
    fn caps_are_validated() {
        assert_eq!(cap(None, 5, 10).unwrap(), 5);
        assert_eq!(cap(Some(10), 5, 10).unwrap(), 10);
        assert!(cap(Some(11), 5, 10).is_err());
        assert!(cap(Some(0), 5, 10).is_err());
    }
}
