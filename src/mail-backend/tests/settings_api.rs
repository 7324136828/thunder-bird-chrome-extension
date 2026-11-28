//! Port of the HTTP tests of `tests/test_settings.py::MailPreferencesTests`
//! (`test_api_*`) plus checks of the `ensure_ascii` 422 serialization that
//! main.py's `settings_validation_error` handler applies to `/api/settings`.

mod accounts_support;
mod common;

use accounts_support::{default_expiration, preferences, read_json, Harness};
use axum::http::{Method, StatusCode};
use serde_json::{json, Value};

#[tokio::test]
async fn api_settings_persist_after_application_restart() {
    let harness = Harness::new();
    harness.write_settings(r#"{"backend_port":4320,"data_directory":"../data","theme":"dark"}"#);
    let response = harness.get("/api/settings").await;
    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(response.json(), preferences(5, ""));
    let response = harness
        .put_json(
            "/api/settings",
            &json!({"messages_per_page": 23, "signature": "Thanks,\nAlex"}),
        )
        .await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text());
    assert_eq!(response.json(), preferences(23, "Thanks,\nAlex"));

    let restarted = harness.restarted();
    assert_eq!(
        restarted.get("/api/settings").await.json(),
        preferences(23, "Thanks,\nAlex")
    );
    assert_eq!(
        read_json(&harness.settings_path),
        json!({
            "backend_port": 4320, "data_directory": "../data", "theme": "dark",
            "messages_per_page": 23, "signature": "Thanks,\nAlex",
        })
    );
}

#[tokio::test]
async fn api_page_size_only_update_preserves_signature_and_empty_signature_disables_it() {
    let harness = Harness::new();
    harness.write_settings(
        &json!({"messages_per_page": 5, "signature": "Saved signature", "theme": "dark"})
            .to_string(),
    );
    let response = harness
        .put_json("/api/settings", &json!({"messages_per_page": 20}))
        .await;
    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(response.json(), preferences(20, "Saved signature"));
    assert_eq!(harness.get("/api/settings").await.json(), response.json());
    let response = harness
        .put_json(
            "/api/settings",
            &json!({"messages_per_page": 20, "signature": ""}),
        )
        .await;
    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(response.json(), preferences(20, ""));
    assert_eq!(
        read_json(&harness.settings_path),
        json!({"messages_per_page": 20, "signature": "", "theme": "dark"})
    );
}

#[tokio::test]
async fn api_accepts_multiline_signature_and_rejects_invalid_signature_without_writing() {
    let harness = Harness::new();
    let valid = "Thanks,\nAlex\tExample Co.\r\n\u{e9}";
    let response = harness
        .put_json(
            "/api/settings",
            &json!({"messages_per_page": 5, "signature": valid}),
        )
        .await;
    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(response.json()["signature"], valid);
    let previous = std::fs::read(&harness.settings_path).unwrap();

    let long = format!("\"{}\"", "a".repeat(10_001));
    let invalid: [&str; 10] = [
        "null",
        "true",
        "42",
        "[]",
        "{}",
        &long,
        r#""bad\u0000text""#,
        r#""bad\u0001text""#,
        r#""bad\u007ftext""#,
        r#""bad\ud800text""#,
    ];
    for signature in invalid {
        let body = format!(r#"{{"messages_per_page": 10, "signature": {signature}}}"#);
        let response = harness
            .raw(Method::PUT, "/api/settings", Some("application/json"), body)
            .await;
        assert_eq!(
            response.status,
            StatusCode::UNPROCESSABLE_ENTITY,
            "{signature}: {}",
            response.text()
        );
        assert_eq!(std::fs::read(&harness.settings_path).unwrap(), previous);
    }
}

#[tokio::test]
async fn api_rejects_noninteger_out_of_range_and_unrelated_settings() {
    let harness = Harness::new();
    for count in [
        json!(null),
        json!(true),
        json!(false),
        json!(0),
        json!(-1),
        json!(201),
        json!(5.5),
        json!("5"),
        json!([]),
        json!({}),
    ] {
        let response = harness
            .put_json("/api/settings", &json!({"messages_per_page": count}))
            .await;
        assert_eq!(
            response.status,
            StatusCode::UNPROCESSABLE_ENTITY,
            "{count}: {}",
            response.text()
        );
    }
    for body in [
        json!({}),
        json!({"messages_per_page": 5, "data_directory": "elsewhere"}),
        json!({"messages_per_page": 5, "password": "secret"}),
    ] {
        let response = harness.put_json("/api/settings", &body).await;
        assert_eq!(response.status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
        // The rejected secret is echoed as `input` only for the extra key
        // itself; nothing reaches disk.
    }
    assert!(!harness.settings_path.exists());
}

#[tokio::test]
async fn api_reports_corrupt_file_without_overwriting_it() {
    let harness = Harness::new();
    harness.write_settings("{broken");
    let response = harness.get("/api/settings").await;
    let detail = response.assert_json_error(StatusCode::INTERNAL_SERVER_ERROR);
    assert!(
        detail.as_str().unwrap().contains("settings.json"),
        "{detail}"
    );
    let response = harness
        .put_json("/api/settings", &json!({"messages_per_page": 10}))
        .await;
    response.assert_json_error(StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(std::fs::read(&harness.settings_path).unwrap(), b"{broken");
}

#[tokio::test]
async fn validation_errors_are_ascii_encoded_with_python_separators() {
    let harness = Harness::new();
    let response = harness
        .put_json(
            "/api/settings",
            &json!({"messages_per_page": 5, "signature": "Zo\u{eb}\u{1}"}),
        )
        .await;
    assert_eq!(response.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(response.header("content-type"), Some("application/json"));
    let text = response.text();
    assert!(text.is_ascii(), "{text}");
    // Python separators; key order is serde_json's (sorted), see open issues.
    assert!(text.starts_with(r#"{"detail": [{"#), "{text}");
    assert!(text.contains(r#""loc": ["body", "signature"]"#), "{text}");
    let bs = char::from(92u8);
    let expected = format!(r#""input": "Zo{bs}u00eb{bs}u0001""#);
    assert!(text.contains(&expected), "{text}");
    let detail = response.json()["detail"].clone();
    assert_eq!(detail[0]["loc"], json!(["body", "signature"]));
    assert_eq!(detail[0]["type"], "value_error");
    assert!(!harness.settings_path.exists());
}

#[tokio::test]
async fn malformed_bodies_use_fastapi_errors() {
    let harness = Harness::new();
    let response = harness
        .raw(Method::PUT, "/api/settings", Some("application/json"), "")
        .await;
    assert_eq!(response.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(
        response.json(),
        json!({"detail": [{"type": "missing", "loc": ["body"], "msg": "Field required", "input": null}]})
    );
    let response = harness
        .raw(
            Method::PUT,
            "/api/settings",
            Some("application/json"),
            "[5]",
        )
        .await;
    assert_eq!(response.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(
        response.json()["detail"][0]["type"],
        "model_attributes_type"
    );
    let response = harness
        .put_json("/api/settings", &json!({"messages_per_page": 300}))
        .await;
    assert_eq!(
        response.json(),
        json!({"detail": [{
            "type": "less_than_equal", "loc": ["body", "messages_per_page"],
            "msg": "Input should be less than or equal to 200", "input": 300,
            "ctx": {"le": 200},
        }]})
    );
}

#[tokio::test]
async fn expiration_and_local_model_updates_are_partial() {
    let harness = Harness::new();
    let mut expiration = default_expiration();
    expiration["marketing"] = json!(7);
    let response = harness
        .put_json(
            "/api/settings",
            &json!({
                "messages_per_page": 9,
                "category_expiration_days": expiration,
                "local_ai_model": "qwen2.5:7b",
            }),
        )
        .await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text());
    let expected = json!({
        "messages_per_page": 9, "signature": "",
        "category_expiration_days": expiration, "local_ai_model": "qwen2.5:7b",
    });
    assert_eq!(response.json(), expected);
    // Omitted fields keep their stored values.
    let response = harness
        .put_json("/api/settings", &json!({"messages_per_page": 11}))
        .await;
    let mut updated = expected.clone();
    updated["messages_per_page"] = json!(11);
    assert_eq!(response.json(), updated);
    let stored: Value = read_json(&harness.settings_path);
    assert_eq!(stored["category_expiration_days"], expiration);
    assert_eq!(stored["local_ai_model"], "qwen2.5:7b");

    for body in [
        json!({"messages_per_page": 5, "category_expiration_days": null}),
        json!({"messages_per_page": 5, "category_expiration_days": {"marketing": 1}}),
        json!({"messages_per_page": 5, "local_ai_model": null}),
        json!({"messages_per_page": 5, "local_ai_model": "bad model"}),
    ] {
        let response = harness.put_json("/api/settings", &body).await;
        assert_eq!(response.status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    }
    assert_eq!(read_json(&harness.settings_path), stored);
}
