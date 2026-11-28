//! Request building and response mapping of every tool, against a mock
//! backend that speaks the original FastAPI contract (backend/app/main.py).

mod common;

use std::time::Duration;

use base64::Engine;
use common::{multipart_fields, MockBackend, MockResponse, Recorded};
use mail_mcp::params::*;
use mail_mcp::server::into_result;
use mail_mcp::{BackendClient, MailTools, ToolError};
use serde_json::{json, Value};

const ME: &str = "me@example.com";

fn tools(backend: &MockBackend) -> MailTools {
    MailTools::new(BackendClient::new(&backend.url, false, Duration::from_secs(10)).unwrap())
}

fn params<T: serde::de::DeserializeOwned>(value: Value) -> T {
    serde_json::from_value(value).expect("valid tool arguments")
}

fn accounts(emails: &[&str]) -> Value {
    json!({ "accounts": emails.iter().map(|email| json!({
        "email": email, "display_name": "", "incoming_server": "imap.example.com",
        "incoming_port": 993, "incoming_protocol": "SSL/TLS", "outgoing_server": "smtp.example.com",
        "outgoing_port": 587, "outgoing_protocol": "STARTTLS", "unlocked_at": 1
    })).collect::<Vec<_>>() })
}

fn folders_with_trash() -> Value {
    json!({"folders": [
        {"name": "INBOX", "delimiter": "/", "flags": [], "special": "inbox", "selectable": true},
        {"name": "Sent", "delimiter": "/", "flags": ["\\Sent"], "special": "sent", "selectable": true},
        {"name": "Trash", "delimiter": "/", "flags": ["\\Trash"], "special": "trash", "selectable": true},
    ]})
}

fn locked() -> MockResponse {
    MockResponse::detail(401, json!({"error": "password_required", "email": ME}))
}

#[tokio::test]
async fn list_accounts_and_settings_pass_through() {
    let backend = MockBackend::start(|request| match request.path.as_str() {
        "/api/accounts" => MockResponse::ok(accounts(&[ME])),
        "/api/settings" => MockResponse::ok(json!({"messages_per_page": 5, "signature": ""})),
        _ => MockResponse::detail(404, json!("Not Found")),
    })
    .await;
    let tools = tools(&backend);
    assert_eq!(tools.list_accounts().await.unwrap(), accounts(&[ME]));
    assert_eq!(tools.get_settings().await.unwrap()["messages_per_page"], 5);
    assert_eq!(backend.routes(), ["GET /api/accounts", "GET /api/settings"]);
    // Local process: no Origin header is sent.
    assert!(backend
        .requests()
        .iter()
        .all(|request| request.origin.is_none()));
}

#[tokio::test]
async fn account_is_resolved_when_exactly_one_is_unlocked() {
    let backend = MockBackend::start(|request| match request.path.as_str() {
        "/api/accounts" => MockResponse::ok(accounts(&[ME])),
        "/api/mail/folders" => MockResponse::ok(folders_with_trash()),
        _ => MockResponse::detail(404, json!("Not Found")),
    })
    .await;
    let result = tools(&backend)
        .list_folders(params(json!({})))
        .await
        .unwrap();
    assert_eq!(result, folders_with_trash());
    let requests = backend.requests();
    assert_eq!(
        backend.routes(),
        ["GET /api/accounts", "GET /api/mail/folders"]
    );
    assert_eq!(requests[1].query_pairs(), [("account", ME)]);
}

#[tokio::test]
async fn account_resolution_fails_for_zero_or_many_accounts() {
    let none = MockBackend::start(|_| MockResponse::ok(accounts(&[]))).await;
    let error = tools(&none)
        .list_folders(params(json!({})))
        .await
        .unwrap_err();
    assert!(
        error.message().contains("No mail account is unlocked"),
        "{error}"
    );

    let many = MockBackend::start(|_| MockResponse::ok(accounts(&[ME, "b@example.com"]))).await;
    let error = tools(&many)
        .list_folders(params(json!({})))
        .await
        .unwrap_err();
    assert!(
        error.message().contains("me@example.com, b@example.com"),
        "{error}"
    );
    assert!(error.message().contains("`account`"));
    assert_eq!(many.routes(), ["GET /api/accounts"]);
}

#[tokio::test]
async fn explicit_account_is_used_without_listing() {
    let backend = MockBackend::start(|_| MockResponse::ok(folders_with_trash())).await;
    tools(&backend)
        .list_folders(params(json!({"account": "  Other@Example.com "})))
        .await
        .unwrap();
    let requests = backend.requests();
    assert_eq!(backend.routes(), ["GET /api/mail/folders"]);
    assert_eq!(
        requests[0].query_value("account"),
        Some("Other@Example.com")
    );
}

#[tokio::test]
async fn list_messages_builds_the_ui_query() {
    let page = json!({"total": 1, "offset": 0, "limit": 25, "messages": [{"uid": 9, "uid_validity": "77"}]});
    let reply = page.clone();
    let backend = MockBackend::start(move |_| MockResponse::ok(reply.clone())).await;
    let result = tools(&backend)
        .list_messages(params(json!({
            "account": ME, "folder": "Work/Clients", "offset": 0, "limit": 25,
            "query": "invoice & co", "sender_domain": ["a.com", "bücher.de"],
            "read_status": "unread", "category": "transactional", "expired_only": true
        })))
        .await
        .unwrap();
    assert_eq!(result, page);
    let request = &backend.requests()[0];
    assert_eq!(request.path, "/api/mail/messages");
    assert_eq!(
        request.query_pairs(),
        [
            ("account", ME),
            ("folder", "Work/Clients"),
            ("offset", "0"),
            ("limit", "25"),
            ("query", "invoice & co"),
            ("sender_domain", "a.com"),
            ("sender_domain", "bücher.de"),
            ("read_status", "unread"),
            ("category", "transactional"),
            ("expired_only", "true"),
        ]
    );
}

#[tokio::test]
async fn read_message_never_marks_seen_by_default_and_trims_html() {
    let backend = MockBackend::start(|_| {
        MockResponse::ok(
            json!({"uid": 3, "text_body": "Hello", "html_body": "<p>Hello</p>", "attachments": []}),
        )
    })
    .await;
    let tools = tools(&backend);
    let message = tools
        .read_message(params(json!({"account": ME, "uid": 3})))
        .await
        .unwrap();
    assert_eq!(message["text_body"], "Hello");
    assert!(message.get("html_body").is_none());
    assert_eq!(message["html_body_omitted"], true);

    let full = tools
        .read_message(params(json!({"account": ME, "folder": "Archive", "uid": 3, "mark_seen": true, "include_html": true})))
        .await
        .unwrap();
    assert_eq!(full["html_body"], "<p>Hello</p>");

    let requests = backend.requests();
    assert_eq!(
        requests[0].query_pairs(),
        [
            ("account", ME),
            ("folder", "INBOX"),
            ("uid", "3"),
            ("mark_seen", "false")
        ]
    );
    assert_eq!(requests[1].query_value("mark_seen"), Some("true"));
    assert_eq!(requests[1].query_value("folder"), Some("Archive"));
}

#[tokio::test]
async fn password_required_becomes_an_unlock_hint_tool_error() {
    let backend = MockBackend::start(|_| locked()).await;
    let error = tools(&backend)
        .list_messages(params(json!({"account": ME})))
        .await
        .unwrap_err();
    assert_eq!(error, ToolError::PasswordRequired { email: ME.into() });

    let result = into_result(Err(error)).unwrap();
    assert_eq!(result.is_error, Some(true));
    let text = serde_json::to_value(&result).unwrap()["content"][0]["text"]
        .as_str()
        .unwrap()
        .to_string();
    let payload: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(payload["code"], "password_required");
    assert!(payload["error"]
        .as_str()
        .unwrap()
        .contains("unlock it in the Thunderbird extension"));
}

#[tokio::test]
async fn http_errors_keep_status_and_detail() {
    let backend = MockBackend::start(|request| match request.path.as_str() {
        "/api/mail/messages" => MockResponse::detail(
            422,
            json!([{"type": "less_than_equal", "loc": ["query", "limit"], "msg": "Input should be less than or equal to 200"}]),
        ),
        "/api/mail/message" => MockResponse::detail(502, json!("The mail server closed the connection")),
        _ => MockResponse {
            status: 500,
            headers: vec![("content-type".into(), "text/plain".into())],
            body: b"Internal Server Error".to_vec(),
        },
    })
    .await;
    let tools = tools(&backend);
    let error = tools
        .list_messages(params(json!({"account": ME, "limit": 500})))
        .await
        .unwrap_err();
    assert_eq!(error.status(), Some(422));
    assert_eq!(
        error.message(),
        "limit: Input should be less than or equal to 200 (HTTP 422)"
    );

    let error = tools
        .read_message(params(json!({"account": ME, "uid": 1})))
        .await
        .unwrap_err();
    assert_eq!(
        error.message(),
        "The mail server closed the connection (HTTP 502)"
    );

    let error = tools.get_settings().await.unwrap_err();
    assert_eq!(error.message(), "Internal Server Error (HTTP 500)");

    let result = serde_json::to_value(into_result(Err(error)).unwrap()).unwrap();
    assert_eq!(result["isError"], true);
}

#[tokio::test]
async fn raw_message_is_text_and_truncated() {
    let eml = b"From: a@example.com\r\nSubject: Hi\r\n\r\nBody text".to_vec();
    let reply = eml.clone();
    let backend = MockBackend::start(move |_| {
        MockResponse::bytes("message/rfc822", reply.clone()).with_header(
            "content-disposition",
            "attachment; filename=\"message-5.eml\"",
        )
    })
    .await;
    let tools = tools(&backend);
    let full = tools
        .get_raw_message(params(json!({"account": ME, "uid": 5})))
        .await
        .unwrap();
    assert_eq!(full["eml"], String::from_utf8(eml.clone()).unwrap());
    assert_eq!(full["truncated"], false);
    assert_eq!(full["size"], eml.len());

    let cut = tools
        .get_raw_message(params(json!({"account": ME, "uid": 5, "max_bytes": 10})))
        .await
        .unwrap();
    assert_eq!(cut["eml"], "From: a@ex");
    assert_eq!(cut["truncated"], true);
    assert_eq!(cut["returned_bytes"], 10);

    assert_eq!(backend.requests()[0].path, "/api/mail/message/eml");
    assert_eq!(
        backend.requests()[0].query_pairs(),
        [("account", ME), ("folder", "INBOX"), ("uid", "5")]
    );
    let error = tools
        .get_raw_message(params(
            json!({"account": ME, "uid": 5, "max_bytes": 999999999}),
        ))
        .await
        .unwrap_err();
    assert!(matches!(error, ToolError::InvalidArguments(_)));
}

#[tokio::test]
async fn attachment_is_base64_with_metadata_and_capped() {
    let data = vec![0u8, 1, 2, 3, 254, 255];
    let reply = data.clone();
    let backend = MockBackend::start(move |_| {
        MockResponse::bytes("application/pdf", reply.clone())
            .with_header("content-disposition", "attachment; filename=\"report.pdf\"")
    })
    .await;
    let tools = tools(&backend);
    let result = tools
        .get_attachment(params(
            json!({"account": ME, "folder": "INBOX", "uid": 8, "index": 1}),
        ))
        .await
        .unwrap();
    assert_eq!(result["filename"], "report.pdf");
    assert_eq!(result["content_type"], "application/pdf");
    assert_eq!(result["size"], 6);
    assert_eq!(
        base64::engine::general_purpose::STANDARD
            .decode(result["content_base64"].as_str().unwrap())
            .unwrap(),
        data
    );
    let request = &backend.requests()[0];
    assert_eq!(request.path, "/api/mail/message/attachment");
    assert_eq!(
        request.query_pairs(),
        [
            ("account", ME),
            ("folder", "INBOX"),
            ("uid", "8"),
            ("index", "1")
        ]
    );

    let error = tools
        .get_attachment(params(
            json!({"account": ME, "uid": 8, "index": 1, "max_bytes": 4}),
        ))
        .await
        .unwrap_err();
    assert!(error.message().contains("exceeds max_bytes (4)"), "{error}");
}

#[tokio::test]
async fn send_without_attachments_posts_json() {
    let backend = MockBackend::start(|_| {
        MockResponse::ok(json!({"sent": true, "message_id": "<x@y>", "from": ME, "sent_saved": true, "sent_folder": "Sent"}))
    })
    .await;
    let result = tools(&backend)
        .send(params(json!({
            "account": ME, "to": ["Ann <ann@example.com>"], "cc": ["c@example.com"],
            "subject": "Hello", "text": "Hi Ann", "in_reply_to": "<orig@example.com>"
        })))
        .await
        .unwrap();
    assert_eq!(result["sent"], true);
    let request = &backend.requests()[0];
    assert_eq!(request.route(), "POST /api/mail/send");
    assert!(request
        .content_type
        .as_deref()
        .unwrap()
        .starts_with("application/json"));
    assert_eq!(
        request.json(),
        json!({
            "account": ME, "to": ["Ann <ann@example.com>"], "cc": ["c@example.com"], "bcc": [],
            "subject": "Hello", "text": "Hi Ann", "in_reply_to": "<orig@example.com>"
        })
    );
}

#[tokio::test]
async fn send_with_attachments_uses_the_ui_multipart_layout() {
    let backend = MockBackend::start(|_| {
        MockResponse::ok(json!({"sent": true, "message_id": "<x@y>", "from": ME}))
    })
    .await;
    let encode = |data: &[u8]| base64::engine::general_purpose::STANDARD.encode(data);
    tools(&backend)
        .send(params(json!({
            "account": ME, "to": ["ann@example.com"], "subject": "Files", "text": "See attached",
            "html": "<p>See attached</p>",
            "attachments": [
                {"filename": "notes.txt", "content_type": "text/plain", "content_base64": encode(b"hello")},
                {"filename": "blob.bin", "content_base64": encode(&[0, 159, 146, 150])}
            ]
        })))
        .await
        .unwrap();
    let request = &backend.requests()[0];
    assert_eq!(request.route(), "POST /api/mail/send/files");
    assert!(request
        .content_type
        .as_deref()
        .unwrap()
        .starts_with("multipart/form-data; boundary="));

    let fields = multipart_fields(request).await;
    let names: Vec<&str> = fields.iter().map(|field| field.name.as_str()).collect();
    assert_eq!(names, ["message", "files", "files"]);
    assert_eq!(fields[0].file_name, None);
    let message: Value = serde_json::from_slice(&fields[0].data).unwrap();
    assert_eq!(
        message,
        json!({
            "account": ME, "to": ["ann@example.com"], "cc": [], "bcc": [],
            "subject": "Files", "text": "See attached", "html": "<p>See attached</p>",
            "uploads": [
                {"content_id": "", "disposition": "attachment"},
                {"content_id": "", "disposition": "attachment"}
            ]
        })
    );
    assert_eq!(fields[1].file_name.as_deref(), Some("notes.txt"));
    assert_eq!(fields[1].content_type.as_deref(), Some("text/plain"));
    assert_eq!(fields[1].data, b"hello");
    assert_eq!(fields[2].file_name.as_deref(), Some("blob.bin"));
    assert_eq!(
        fields[2].content_type.as_deref(),
        Some("application/octet-stream")
    );
    assert_eq!(fields[2].data, [0, 159, 146, 150]);
}

#[tokio::test]
async fn send_rejects_bad_attachments_before_any_request() {
    let backend = MockBackend::start(|_| MockResponse::ok(json!({}))).await;
    let error = tools(&backend)
        .send(params(json!({
            "account": ME, "to": ["ann@example.com"],
            "attachments": [{"filename": "x", "content_base64": "%%%"}]
        })))
        .await
        .unwrap_err();
    assert!(error.message().contains("not valid base64"));
    assert!(backend.requests().is_empty());
}

#[tokio::test]
async fn move_to_trash_resolves_the_trash_folder_like_the_ui() {
    let backend = MockBackend::start(|request| match request.path.as_str() {
        "/api/mail/folders" => MockResponse::ok(folders_with_trash()),
        "/api/mail/messages/delete" => MockResponse::ok(json!({"deleted": [4, 5]})),
        _ => MockResponse::detail(404, json!("Not Found")),
    })
    .await;
    let result = tools(&backend)
        .move_to_trash(params(
            json!({"account": ME, "folder": "INBOX", "uids": [4, 5, 4], "uid_validity": "1700"}),
        ))
        .await
        .unwrap();
    assert_eq!(result, json!({"deleted": [4, 5], "trash_folder": "Trash"}));
    let requests = backend.requests();
    assert_eq!(
        backend.routes(),
        ["GET /api/mail/folders", "POST /api/mail/messages/delete"]
    );
    assert_eq!(
        requests[1].json(),
        json!({"account": ME, "folder": "INBOX", "uids": [4, 5], "trash": "Trash", "uid_validity": "1700"})
    );
}

#[tokio::test]
async fn move_to_trash_never_deletes_without_a_trash_folder() {
    let backend = MockBackend::start(|request| match request.path.as_str() {
        "/api/mail/folders" => MockResponse::ok(json!({"folders": [
            {"name": "INBOX", "delimiter": "", "flags": [], "special": "inbox", "selectable": true}
        ]})),
        _ => MockResponse::ok(json!({"deleted": []})),
    })
    .await;
    let tools = tools(&backend);
    let error = tools
        .move_to_trash(params(
            json!({"account": ME, "folder": "INBOX", "uids": [1]}),
        ))
        .await
        .unwrap_err();
    assert!(error
        .message()
        .contains("no selectable server Trash folder"));
    assert_eq!(backend.routes(), ["GET /api/mail/folders"]);

    let error = tools
        .move_to_trash(params(
            json!({"account": ME, "folder": "INBOX", "uids": []}),
        ))
        .await
        .unwrap_err();
    assert!(matches!(error, ToolError::InvalidArguments(_)));
}

#[tokio::test]
async fn move_to_trash_refuses_messages_already_in_trash() {
    let backend = MockBackend::start(|_| MockResponse::ok(folders_with_trash())).await;
    let error = tools(&backend)
        .move_to_trash(params(
            json!({"account": ME, "folder": "Trash", "uids": [1]}),
        ))
        .await
        .unwrap_err();
    assert!(error.message().contains("already in the Trash folder"));
    assert_eq!(backend.routes(), ["GET /api/mail/folders"]);
}

#[tokio::test]
async fn flags_categorize_classify_and_audit_bodies() {
    let backend =
        MockBackend::start(|request| MockResponse::ok(json!({"path": request.path}))).await;
    let tools = tools(&backend);
    tools
        .set_flags(params(
            json!({"account": ME, "folder": "INBOX", "uid": 2, "flagged": true}),
        ))
        .await
        .unwrap();
    tools
        .categorize(params(json!({"account": ME, "folder": "INBOX", "uid": 2, "uid_validity": 99, "category": null})))
        .await
        .unwrap();
    tools
        .categorize(params(json!({"account": ME, "folder": "INBOX", "uid": 2, "uid_validity": "99", "category": "updates", "expiration_days": -1})))
        .await
        .unwrap();
    tools
        .classify(params(
            json!({"account": ME, "folder": "INBOX", "uid": 2, "uid_validity": "99"}),
        ))
        .await
        .unwrap();
    tools
        .audit_message(params(json!({"account": ME, "uid": 2})))
        .await
        .unwrap();

    let requests = backend.requests();
    assert_eq!(
        backend.routes(),
        [
            "POST /api/mail/message/flags",
            "PUT /api/mail/message/retention",
            "PUT /api/mail/message/retention",
            "POST /api/mail/message/classify",
            "GET /api/mail/audit",
        ]
    );
    assert_eq!(
        requests[0].json(),
        json!({"account": ME, "folder": "INBOX", "uid": 2, "flagged": true})
    );
    assert_eq!(
        requests[1].json(),
        json!({"account": ME, "folder": "INBOX", "uid": 2, "uid_validity": "99", "category": null})
    );
    assert_eq!(
        requests[2].json(),
        json!({"account": ME, "folder": "INBOX", "uid": 2, "uid_validity": "99", "category": "updates", "expiration_days": -1})
    );
    assert_eq!(
        requests[3].json(),
        json!({"account": ME, "folder": "INBOX", "uid": 2, "uid_validity": "99"})
    );
    assert_eq!(
        requests[4].query_pairs(),
        [("account", ME), ("folder", "INBOX"), ("uid", "2")]
    );
}

#[tokio::test]
async fn categorize_and_flags_require_a_change() {
    let backend = MockBackend::start(|_| MockResponse::ok(json!({}))).await;
    let tools = tools(&backend);
    let error = tools
        .categorize(params(
            json!({"account": ME, "folder": "INBOX", "uid": 2, "uid_validity": "9"}),
        ))
        .await
        .unwrap_err();
    assert_eq!(error.message(), "Choose a category or expiration to update");
    let error = tools
        .set_flags(params(json!({"account": ME, "folder": "INBOX", "uid": 2})))
        .await
        .unwrap_err();
    assert_eq!(error.message(), "Choose seen and/or flagged to update");
    assert!(backend.requests().is_empty());
}

#[tokio::test]
async fn sender_rule_routes() {
    let backend = MockBackend::start(|request: &Recorded| match request.method.as_str() {
        "DELETE" => MockResponse::ok(json!({"deleted": true})),
        "GET" => MockResponse::ok(json!({"rules": []})),
        _ => MockResponse::detail(
            409,
            json!("The email category changed. Refresh the message before saving a sender rule."),
        ),
    })
    .await;
    let tools = tools(&backend);
    let error = tools
        .sender_rule_create(params(json!({
            "account": ME, "folder": "INBOX", "uid": 3, "uid_validity": "5", "category": "marketing",
            "expected_category_revision": 0
        })))
        .await
        .unwrap_err();
    assert_eq!(error.status(), Some(409));
    tools
        .sender_rule_list(params(json!({"account": ME, "folder": "INBOX"})))
        .await
        .unwrap();
    tools
        .sender_rule_list(params(json!({"account": ME})))
        .await
        .unwrap();
    let deleted = tools
        .sender_rule_delete(params(json!({"account": ME, "folder": "INBOX", "sender": "news@shop.example", "expected_revision": 2})))
        .await
        .unwrap();
    assert_eq!(deleted, json!({"deleted": true}));

    let requests = backend.requests();
    assert_eq!(requests[0].route(), "POST /api/mail/message/sender-rule");
    assert_eq!(
        requests[0].json(),
        json!({"account": ME, "folder": "INBOX", "uid": 3, "uid_validity": "5", "category": "marketing", "expected_category_revision": 0})
    );
    assert_eq!(requests[1].route(), "GET /api/mail/sender-rules");
    assert_eq!(
        requests[1].query_pairs(),
        [("account", ME), ("folder", "INBOX")]
    );
    assert_eq!(requests[2].query_pairs(), [("account", ME)]);
    assert_eq!(requests[3].route(), "DELETE /api/mail/sender-rules");
    assert_eq!(
        requests[3].query_pairs(),
        [
            ("account", ME),
            ("folder", "INBOX"),
            ("sender", "news@shop.example"),
            ("expected_revision", "2")
        ]
    );
}

fn trash_backend(
    count: u64,
    empty: MockResponse,
) -> impl Fn(&Recorded) -> MockResponse + Send + Sync {
    move |request| match (request.method.as_str(), request.path.as_str()) {
        ("GET", "/api/mail/folders") => MockResponse::ok(folders_with_trash()),
        ("POST", "/api/mail/trash/prepare") => MockResponse::ok(json!({
            "operation_id": "op/1", "count": count, "archive": false, "filename": null
        })),
        ("POST", "/api/mail/trash/op%2F1/empty") => empty.clone(),
        ("DELETE", "/api/mail/trash/op%2F1") => MockResponse::ok(json!({"discarded": "op/1"})),
        _ => MockResponse::detail(404, json!("Not Found")),
    }
}

#[tokio::test]
async fn empty_trash_requires_confirmation() {
    let backend = MockBackend::start(trash_backend(3, MockResponse::ok(json!({})))).await;
    let error = tools(&backend)
        .empty_trash(params(json!({"account": ME})))
        .await
        .unwrap_err();
    assert!(error.message().contains("confirm=true"));
    assert!(backend.requests().is_empty());
}

#[tokio::test]
async fn empty_trash_prepares_empties_and_releases_the_snapshot() {
    let backend = MockBackend::start(trash_backend(
        3,
        MockResponse::ok(json!({"deleted": 3, "remaining": 1})),
    ))
    .await;
    let result = tools(&backend)
        .empty_trash(params(
            json!({"account": ME, "confirm": true, "expected_count": 3}),
        ))
        .await
        .unwrap();
    assert_eq!(
        result,
        json!({"trash_folder": "Trash", "deleted": 3, "remaining": 1})
    );
    let requests = backend.requests();
    assert_eq!(
        backend.routes(),
        [
            "GET /api/mail/folders",
            "POST /api/mail/trash/prepare",
            "POST /api/mail/trash/op%2F1/empty",
            "DELETE /api/mail/trash/op%2F1",
        ]
    );
    assert_eq!(
        requests[1].json(),
        json!({"account": ME, "folder": "Trash", "archive": false})
    );
    assert_eq!(requests[2].json(), json!({"account": ME}));
    assert_eq!(requests[3].query_pairs(), [("account", ME)]);
}

#[tokio::test]
async fn empty_trash_with_nothing_to_delete_or_unexpected_count_deletes_nothing() {
    let backend = MockBackend::start(trash_backend(0, MockResponse::ok(json!({})))).await;
    let result = tools(&backend)
        .empty_trash(params(json!({"account": ME, "confirm": true})))
        .await
        .unwrap();
    assert_eq!(
        result,
        json!({"trash_folder": "Trash", "deleted": 0, "remaining": 0})
    );
    assert_eq!(
        backend.routes(),
        [
            "GET /api/mail/folders",
            "POST /api/mail/trash/prepare",
            "DELETE /api/mail/trash/op%2F1"
        ]
    );

    let backend = MockBackend::start(trash_backend(5, MockResponse::ok(json!({})))).await;
    let error = tools(&backend)
        .empty_trash(params(
            json!({"account": ME, "confirm": true, "expected_count": 2}),
        ))
        .await
        .unwrap_err();
    assert!(error
        .message()
        .contains("contains 5 messages, not the expected 2"));
    assert!(!backend
        .routes()
        .iter()
        .any(|route| route.ends_with("/empty")));
    assert_eq!(
        backend.routes().last().unwrap(),
        "DELETE /api/mail/trash/op%2F1"
    );
}

#[tokio::test]
async fn empty_trash_failure_is_reported_and_snapshot_released() {
    let backend = MockBackend::start(trash_backend(
        2,
        MockResponse::detail(
            502,
            json!("The server could not empty Trash. No messages were deleted."),
        ),
    ))
    .await;
    let error = tools(&backend)
        .empty_trash(params(json!({"account": ME, "confirm": true})))
        .await
        .unwrap_err();
    assert_eq!(error.status(), Some(502));
    assert!(error.message().contains("No messages were deleted"));
    assert_eq!(
        backend.routes().last().unwrap(),
        "DELETE /api/mail/trash/op%2F1"
    );
}

#[tokio::test]
async fn locked_account_during_trash_lookup_is_reported() {
    let backend = MockBackend::start(|_| locked()).await;
    let error = tools(&backend)
        .move_to_trash(params(
            json!({"account": ME, "folder": "INBOX", "uids": [1]}),
        ))
        .await
        .unwrap_err();
    assert_eq!(error, ToolError::PasswordRequired { email: ME.into() });
}

#[test]
fn categorize_schema_is_documented() {
    let schema = serde_json::to_value(schemars::schema_for!(CategorizeParams)).unwrap();
    let properties = &schema["properties"];
    assert!(properties["uid_validity"]["description"].as_str().is_some());
    // null means "reset", so the schema must not advertise null as default.
    assert!(properties["category"].get("default").is_none());
    assert!(properties["expiration_days"].get("default").is_none());
    let trash = serde_json::to_value(schemars::schema_for!(MoveToTrashParams)).unwrap();
    assert_eq!(trash["properties"]["uids"]["items"]["minimum"], 1);
    assert_eq!(trash["properties"]["uids"]["maxItems"], 500);
    assert!(schema["required"]
        .as_array()
        .unwrap()
        .contains(&json!("uid_validity")));
}
