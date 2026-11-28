//! Error responses: exception-handler mapping, Starlette 404/405, panics,
//! FastAPI validation errors, the per-route request size limits and the
//! global default body limit.

mod common;

use axum::body::{Body, Bytes};
use axum::extract::Path;
use axum::handler::Handler;
use axum::http::{Method, Request, StatusCode};
use axum::routing::{self, post};
use axum::{Json, Router};
use common::*;
use mail_backend::extract::{JsonObject, QueryParams};
use mail_backend::limits::{self, RequestSizeLimitLayer};
use mail_backend::{apply_middleware, run_blocking, ApiError, ApiResult};
use mail_core::MailError;
use serde_json::{json, Value};

async fn mail_error(Path(kind): Path<String>) -> ApiResult<Json<Value>> {
    let error = match kind.as_str() {
        "operation" => MailError::operation("IMAP connection failed"),
        "send" => MailError::Send("SMTP refused".into()),
        "settings" => MailError::Settings("settings.json is invalid".into()),
        "conflict" => MailError::RetentionConflict("Mailbox changed".into()),
        "retention" => MailError::Retention("database locked".into()),
        "classifier" => MailError::Classifier("Ollama is not running".into()),
        "trash" => MailError::TrashNotFound("Trash operation not found".into()),
        "locked" => MailError::credential_required("User@Example.com"),
        "validation" => MailError::validation("Choose a valid email category"),
        _ => MailError::http(418, json!({"custom": true})),
    };
    Err(error.into())
}

async fn panics() -> &'static str {
    panic!("handler exploded")
}

async fn blocking_panic() -> ApiResult<Json<Value>> {
    run_blocking(|| -> Result<Json<Value>, MailError> { panic!("worker exploded") }).await
}

async fn blocking_ok() -> ApiResult<Json<Value>> {
    run_blocking(|| Ok::<_, MailError>(Json(json!({"ok": true})))).await
}

async fn echo_object(JsonObject(body): JsonObject) -> Json<Value> {
    Json(Value::Object(body))
}

async fn validated_query(query: QueryParams) -> ApiResult<Json<Value>> {
    let mut q = query.validator();
    let account = q.string("account").required();
    if let (Some(account), true) = (account.as_deref(), q.is_ok()) {
        if account == "locked@example.com" {
            return Err(MailError::credential_required(account).into());
        }
    }
    let folder = q.string("folder").max_length(500).default("INBOX");
    let uid = q.integer("uid").ge(1).required();
    let domains = q.list("sender_domain");
    q.finish()?;
    Ok(Json(json!({
        "account": account, "folder": folder, "uid": uid.expect("validated"),
        "sender_domain": domains,
    })))
}

async fn read_body(body: Bytes) -> Json<Value> {
    Json(json!({ "received": body.len() }))
}

/// Reads the body but answers 400 on any read error, like FastAPI turning a
/// parser exception into "There was an error parsing the body".
async fn read_body_lenient(body: Body) -> ApiResult<Json<Value>> {
    match axum::body::to_bytes(body, usize::MAX).await {
        Ok(bytes) => Ok(Json(json!({ "received": bytes.len() }))),
        Err(_) => Err(ApiError::bad_request("There was an error parsing the body")),
    }
}

fn test_router() -> Router {
    let small = RequestSizeLimitLayer::new(100, limits::REQUEST_TOO_LARGE);
    let signature = RequestSizeLimitLayer::new(100, limits::SIGNATURE_TOO_LARGE);
    let doctor =
        RequestSizeLimitLayer::new(100, limits::REQUEST_TOO_LARGE).without_declared_length_check();
    apply_middleware(
        Router::new()
            .route("/test/mail-error/{kind}", routing::get(mail_error))
            .route("/test/panic", routing::get(panics))
            .route("/test/blocking-panic", routing::get(blocking_panic))
            .route("/test/blocking-ok", routing::get(blocking_ok))
            .route("/test/echo", post(echo_object))
            .route("/api/accounts/unlock", post(echo_object))
            .route("/test/query", routing::get(validated_query))
            .route("/test/send", post(read_body).layer(small.clone()))
            .route("/test/send-lenient", post(read_body_lenient).layer(small))
            .route(
                "/test/signature",
                routing::get(|| async { "ok" }).put(read_body.layer(signature)),
            )
            .route("/test/doctor", post(read_body).layer(doctor))
            .route("/test/unlimited", post(read_body)),
    )
}

async fn send(request: Request<Body>) -> Resp {
    call_router(test_router(), request).await
}

fn post_json(uri: &str, body: &str) -> Request<Body> {
    Request::post(uri)
        .header("host", "127.0.0.1:48101")
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

fn chunked(chunks: Vec<&'static [u8]>) -> Body {
    let stream = futures_util::stream::iter(
        chunks
            .into_iter()
            .map(|chunk| Ok::<_, std::io::Error>(Bytes::from_static(chunk))),
    );
    Body::from_stream(stream)
}

#[tokio::test]
async fn mail_errors_use_python_exception_handler_statuses() {
    let cases = [
        (
            "operation",
            StatusCode::BAD_GATEWAY,
            json!("IMAP connection failed"),
        ),
        ("send", StatusCode::BAD_GATEWAY, json!("SMTP refused")),
        (
            "settings",
            StatusCode::INTERNAL_SERVER_ERROR,
            json!("settings.json is invalid"),
        ),
        ("conflict", StatusCode::CONFLICT, json!("Mailbox changed")),
        (
            "retention",
            StatusCode::INTERNAL_SERVER_ERROR,
            json!("database locked"),
        ),
        (
            "classifier",
            StatusCode::BAD_GATEWAY,
            json!("Ollama is not running"),
        ),
        (
            "trash",
            StatusCode::NOT_FOUND,
            json!("Trash operation not found"),
        ),
        (
            "locked",
            StatusCode::UNAUTHORIZED,
            json!({"error": "password_required", "email": "user@example.com"}),
        ),
        (
            "validation",
            StatusCode::UNPROCESSABLE_ENTITY,
            json!("Choose a valid email category"),
        ),
        ("teapot", StatusCode::IM_A_TEAPOT, json!({"custom": true})),
    ];
    for (kind, status, detail) in cases {
        let response = send(
            get(&format!("/test/mail-error/{kind}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(response.assert_json_error(status), detail, "{kind}");
    }
}

#[tokio::test]
async fn unknown_paths_and_methods_are_starlette_json() {
    let response = call(get("/api/nope").body(Body::empty()).unwrap()).await;
    assert_eq!(response.status, StatusCode::NOT_FOUND);
    assert_eq!(response.json(), json!({"detail": "Not Found"}));

    let response = call(Request::delete("/api/health").body(Body::empty()).unwrap()).await;
    assert_eq!(response.status, StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(response.json(), json!({"detail": "Method Not Allowed"}));
    assert!(response.header("allow").is_some());

    let response = call(
        Request::builder()
            .method(Method::PUT)
            .uri("/")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(response.json(), json!({"detail": "Not Found"}));
}

#[tokio::test]
async fn panics_become_json_500_and_server_keeps_running() {
    let app = test_router();
    let response = call_router(app.clone(), get("/test/panic").body(Body::empty()).unwrap()).await;
    assert_eq!(
        response.assert_json_error(StatusCode::INTERNAL_SERVER_ERROR),
        json!("Internal Server Error")
    );
    let response = call_router(
        app.clone(),
        get("/test/blocking-panic").body(Body::empty()).unwrap(),
    )
    .await;
    assert_eq!(
        response.assert_json_error(StatusCode::INTERNAL_SERVER_ERROR),
        json!("Internal Server Error")
    );
    let response = call_router(app, get("/test/blocking-ok").body(Body::empty()).unwrap()).await;
    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(response.json(), json!({"ok": true}));
}

#[tokio::test]
async fn json_body_errors_match_fastapi() {
    let response = send(post_json("/test/echo", "")).await;
    assert_eq!(
        response.assert_json_error(StatusCode::UNPROCESSABLE_ENTITY),
        json!([{"type": "missing", "loc": ["body"], "msg": "Field required", "input": null}])
    );
    let response = send(post_json("/test/echo", "{\"a\": ")).await;
    let detail = response.assert_json_error(StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(detail[0]["type"], "json_invalid");
    assert_eq!(detail[0]["loc"][0], "body");
    assert_eq!(detail[0]["msg"], "JSON decode error");
    let response = send(post_json("/test/echo", "[1, 2]")).await;
    assert_eq!(
        response.assert_json_error(StatusCode::UNPROCESSABLE_ENTITY),
        json!([{"type": "model_attributes_type", "loc": ["body"],
                "msg": "Input should be a valid dictionary or object to extract fields from",
                "input": [1, 2]}])
    );
    let response = send(post_json("/test/echo", r#"{"email": "u@example.com"}"#)).await;
    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(response.json(), json!({"email": "u@example.com"}));
}

#[tokio::test]
async fn unlock_and_settings_validation_errors_are_ascii_encoded() {
    // main.py `settings_validation_error`: json.dumps(..., ensure_ascii=True).
    let non_ascii = String::from_utf8(vec![0x22, 0xC3, 0xA9, 0x22]).unwrap(); // "\"é\""
    let response = send(
        Request::post("/api/accounts/unlock")
            .header("host", "127.0.0.1:48101")
            .header("content-type", "text/plain")
            .body(Body::from(non_ascii.clone()))
            .unwrap(),
    )
    .await;
    assert_eq!(response.status, StatusCode::UNPROCESSABLE_ENTITY);
    let text = response.text();
    assert!(text.is_ascii(), "{text}");
    assert!(text.contains("u00e9"), "{text}");
    assert!(text.starts_with("{\"detail\": [{"), "{text}");
    assert_eq!(response.json()["detail"][0]["input"], json!(non_ascii));

    // Other paths keep compact UTF-8 JSON.
    let response = send(
        Request::post("/test/echo")
            .header("content-type", "text/plain")
            .body(Body::from(non_ascii))
            .unwrap(),
    )
    .await;
    assert_eq!(response.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(!response.text().is_ascii());
}

#[tokio::test]
async fn query_validation_and_dependency_order() {
    // Missing dependency parameter is reported with the endpoint's issues.
    let response = send(get("/test/query?uid=abc").body(Body::empty()).unwrap()).await;
    assert_eq!(
        response.assert_json_error(StatusCode::UNPROCESSABLE_ENTITY),
        json!([
            {"type": "missing", "loc": ["query", "account"], "msg": "Field required", "input": null},
            {"type": "int_parsing", "loc": ["query", "uid"],
             "msg": "Input should be a valid integer, unable to parse string as an integer",
             "input": "abc"},
        ])
    );
    // A locked account answers 401 before the other parameters are checked.
    let response = send(
        get("/test/query?account=locked%40example.com&uid=0")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(
        response.assert_json_error(StatusCode::UNAUTHORIZED),
        json!({"error": "password_required", "email": "locked@example.com"})
    );
    let response = send(
        get("/test/query?account=a%40b.c&uid=7&sender_domain=x.example&sender_domain=y.example")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(
        response.json(),
        json!({"account": "a@b.c", "folder": "INBOX", "uid": 7,
               "sender_domain": ["x.example", "y.example"]})
    );
}

#[tokio::test]
async fn declared_request_size_is_bounded_before_the_handler() {
    // test_send_files: declared Content-Length above the limit → 413.
    let response = send(
        Request::post("/test/send")
            .header("content-length", "101")
            .body(Body::from("tiny"))
            .unwrap(),
    )
    .await;
    assert_eq!(
        response.assert_json_error(StatusCode::PAYLOAD_TOO_LARGE),
        json!("Request exceeds maximum allowed size")
    );
    for bad in ["-1", "ten"] {
        let response = send(
            Request::post("/test/send")
                .header("content-length", bad)
                .body(Body::from("tiny"))
                .unwrap(),
        )
        .await;
        assert_eq!(
            response.assert_json_error(StatusCode::BAD_REQUEST),
            json!("Invalid request size"),
            "{bad}"
        );
    }
    // test_signatures: the signature route has its own message.
    let response = send(
        Request::put("/test/signature")
            .header("content-length", "101")
            .body(Body::from("small"))
            .unwrap(),
    )
    .await;
    assert_eq!(
        response.assert_json_error(StatusCode::PAYLOAD_TOO_LARGE),
        json!("Signature request exceeds maximum allowed size")
    );
    // The GET on the same path is not limited.
    let response = send(get("/test/signature").body(Body::empty()).unwrap()).await;
    assert_eq!(response.status, StatusCode::OK);
    // Within the limit passes through.
    let response = send(
        Request::post("/test/send")
            .body(Body::from(vec![b'x'; 100]))
            .unwrap(),
    )
    .await;
    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(response.json(), json!({"received": 100}));
}

#[tokio::test]
async fn chunked_request_size_is_bounded_while_streaming() {
    // test_send_files: iter([b"x" * 60, b"x" * 60]) without Content-Length.
    let response = send(
        Request::post("/test/send")
            .header("content-type", "multipart/form-data; boundary=example")
            .body(chunked(vec![&[b'x'; 60], &[b'x'; 60]]))
            .unwrap(),
    )
    .await;
    assert_eq!(
        response.assert_json_error(StatusCode::PAYLOAD_TOO_LARGE),
        json!("Request exceeds maximum allowed size")
    );
    // Even when the handler maps the read failure to its own error.
    let response = send(
        Request::post("/test/send-lenient")
            .body(chunked(vec![&[b'x'; 60], &[b'x'; 60]]))
            .unwrap(),
    )
    .await;
    assert_eq!(
        response.assert_json_error(StatusCode::PAYLOAD_TOO_LARGE),
        json!("Request exceeds maximum allowed size")
    );
    let response = send(
        Request::put("/test/signature")
            .body(chunked(vec![b"first", &[b'x'; 100]]))
            .unwrap(),
    )
    .await;
    assert_eq!(
        response.assert_json_error(StatusCode::PAYLOAD_TOO_LARGE),
        json!("Signature request exceeds maximum allowed size")
    );
    // Doctor uploads skip the declared-length check but still count bytes.
    let response = send(
        Request::post("/test/doctor")
            .header("content-length", "999999")
            .body(Body::from("small"))
            .unwrap(),
    )
    .await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text());
    let response = send(
        Request::post("/test/doctor")
            .body(chunked(vec![&[b'x'; 60], &[b'x'; 60]]))
            .unwrap(),
    )
    .await;
    assert_eq!(
        response.assert_json_error(StatusCode::PAYLOAD_TOO_LARGE),
        json!("Request exceeds maximum allowed size")
    );
}

#[tokio::test]
async fn global_default_body_limit_replaces_axums_2_mb_limit() {
    // axum's 2 MB DefaultBodyLimit is disabled; the backend's own default
    // (4 MiB, a deviation: Python had no cap) applies instead.
    let response = send(
        Request::post("/test/unlimited")
            .body(Body::from(vec![b'x'; 3 * 1024 * 1024]))
            .unwrap(),
    )
    .await;
    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(response.json(), json!({"received": 3 * 1024 * 1024}));
    let over = limits::DEFAULT_BODY_LIMIT as usize + 1;
    // Streamed (no Content-Length) and declared bodies alike.
    let response = send(
        Request::post("/test/unlimited")
            .body(Body::from(vec![b'x'; over]))
            .unwrap(),
    )
    .await;
    assert_eq!(
        response.assert_json_error(StatusCode::PAYLOAD_TOO_LARGE),
        json!(limits::REQUEST_TOO_LARGE)
    );
    let response = send(
        Request::post("/test/unlimited")
            .header("content-length", over.to_string())
            .body(Body::from(vec![b'x'; over]))
            .unwrap(),
    )
    .await;
    response.assert_json_error(StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn json_without_content_type_is_not_parsed() {
    // FastAPI's strict_content_type: valid JSON without a Content-Type is
    // validated as raw text; an empty body is still the missing body.
    let response = send(
        Request::post("/test/echo")
            .header("host", "127.0.0.1:48101")
            .body(Body::from(r#"{"email":"u@example.com"}"#))
            .unwrap(),
    )
    .await;
    assert_eq!(
        response.assert_json_error(StatusCode::UNPROCESSABLE_ENTITY),
        json!([{"type": "model_attributes_type", "loc": ["body"],
                "msg": "Input should be a valid dictionary or object to extract fields from",
                "input": "{\"email\":\"u@example.com\"}"}])
    );
    let response = send(
        Request::post("/test/echo")
            .header("host", "127.0.0.1:48101")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(
        response.assert_json_error(StatusCode::UNPROCESSABLE_ENTITY),
        json!([{"type": "missing", "loc": ["body"], "msg": "Field required", "input": null}])
    );
}
