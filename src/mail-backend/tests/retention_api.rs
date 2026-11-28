//! Retention routes: port of `RetentionMailApiTests` and
//! `RetentionFlowApiTests` (tests/test_retention_api.py).
//!
//! The Python tests patched `imap_client.list_messages` / `fetch_message` /
//! `update_retention` / `delete_message(s)` and asserted the forwarded
//! arguments (store, policies, filters, epoch). Here the real IMAP code runs
//! against the fake IMAP server, so the forwarding is verified through its
//! observable effects: the computed retention fields (policies + store), the
//! server command log (filters) and the mailbox state (epoch guards).
//! `RetentionSettingsApiTests` belong to the settings routes and are not
//! ported here. Policies are persisted by writing `settings.json` (what
//! `PUT /api/settings` saves) so these tests do not depend on that route.

mod common;
mod mail_support;

use axum::http::StatusCode;
use chrono::Duration;
use mail_support::*;
use serde_json::{json, Value};

fn identity(email: &str) -> Value {
    json!({"account": email, "folder": "INBOX", "uid_validity": "1234"})
}

fn merge(base: &Value, extra: Value) -> Value {
    let mut merged = base.as_object().unwrap().clone();
    for (key, value) in extra.as_object().unwrap() {
        merged.insert(key.clone(), value.clone());
    }
    Value::Object(merged)
}

fn without(base: &Value, key: &str) -> Value {
    let mut copy = base.as_object().unwrap().clone();
    copy.remove(key);
    Value::Object(copy)
}

fn policies_with(changes: Value) -> Value {
    merge(&default_policies(), changes)
}

// ---------------------------------------------------------------------------
// RetentionMailApiTests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn retention_routes_require_an_unlocked_account() {
    let harness = Harness::new();
    let email = USER;
    let responses = [
        harness
            .get(
                "/api/mail/messages",
                &[
                    ("account", email),
                    ("category", "marketing"),
                    ("expired_only", "true"),
                ],
            )
            .await,
        harness
            .get("/api/mail/message", &[("account", email), ("uid", "7")])
            .await,
        harness
            .put_json(
                "/api/mail/message/retention",
                &json!({"account": email, "folder": "INBOX", "uid": 7,
                        "uid_validity": "1234", "category": "transactional"}),
            )
            .await,
    ];
    for response in responses {
        let detail = response.assert_json_error(StatusCode::UNAUTHORIZED);
        assert_eq!(detail["error"], "password_required");
    }
}

#[tokio::test]
async fn listing_forwards_filters_and_current_persisted_policies() {
    let received = now_seconds() - Duration::days(10);
    let server = server()
        .folder("Offers", &[])
        .message_with(
            "Offers",
            retention_message(
                1,
                "Special offer: new offers",
                &["News <news@example.com>"],
                received,
            ),
        )
        .message_with(
            "Offers",
            retention_message(
                2,
                "Special offer: new offers",
                &["News <news@example.com>"],
                received,
            )
            .with_flags(&["\\Seen"]),
        )
        .start();
    let harness = Harness::new();
    let account = harness.unlock(account(&server));
    harness.write_preferences(15, Some(policies_with(json!({"marketing": 7}))));

    let response = harness
        .get(
            "/api/mail/messages",
            &[
                ("account", &account.email),
                ("folder", "Offers"),
                ("query", " offers "),
                ("sender_domain", "EXAMPLE.COM"),
                ("read_status", "unread"),
                ("category", "marketing"),
                ("expired_only", "true"),
            ],
        )
        .await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text());
    let page = response.json();
    assert_eq!(page["limit"], 15);
    assert_eq!(page["total"], 1);
    assert_eq!(page_uids(&page), vec![1]);
    let summary = &page["messages"][0];
    assert_eq!(summary["category"], "marketing");
    // The saved policy (7 days), not the default 30, made it expire.
    assert_eq!(summary["expiration_days"], 7);
    assert_eq!(summary["expired"], true);
    let searches: Vec<String> = server
        .log()
        .into_iter()
        .filter(|command| command.name == "UID SEARCH")
        .map(|command| command.line)
        .collect();
    assert!(
        searches[0].ends_with(r#"TEXT "offers" UNSEEN FROM "example.com""#),
        "{searches:?}"
    );
    assert!(server
        .log()
        .iter()
        .any(|command| command.name == "EXAMINE" && command.line.contains("Offers")));

    let response = harness
        .get(
            "/api/mail/messages",
            &[
                ("account", &account.email),
                ("folder", "Offers"),
                ("offset", "10"),
            ],
        )
        .await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text());
    assert_eq!(
        response.json(),
        json!({"total": 2, "offset": 10, "limit": 15, "messages": []})
    );
}

#[tokio::test]
async fn default_listing_still_receives_the_retention_store_and_policies() {
    let received = now_seconds() - Duration::days(60);
    let server = retention_server(received);
    let harness = Harness::new();
    let account = harness.unlock(account(&server));
    let response = harness
        .get("/api/mail/messages", &[("account", &account.email)])
        .await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text());
    let page = response.json();
    assert_eq!(page["limit"], 5);
    assert_eq!(page["offset"], 0);
    let items = by_uid(&page);
    assert_eq!(items[&1]["expiration_days"], 30);
    assert_eq!(items[&2]["expiration_days"], -1);
}

#[tokio::test]
async fn invalid_category_filter_is_rejected_before_contacting_server() {
    let server = retention_server(now_seconds());
    let harness = Harness::new();
    let account = harness.unlock(account(&server));
    for category in ["", "Marketing", "other", "marketing,updates"] {
        let response = harness
            .get(
                "/api/mail/messages",
                &[("account", &account.email), ("category", category)],
            )
            .await;
        response.assert_json_error(StatusCode::UNPROCESSABLE_ENTITY);
    }
    assert_eq!(server.connection_count(), 0);
}

#[tokio::test]
async fn reader_receives_store_and_policies_and_preserves_metadata() {
    let received = now_seconds() - Duration::days(60);
    let server = server()
        .folder("Updates", &[])
        .uid_validity("Updates", Some(1234))
        .message_with(
            "Updates",
            retention_message(7, "Your verification code", &["news@example.com"], received),
        )
        .start();
    let harness = Harness::new();
    let account = harness.unlock(account(&server));
    let params = [
        ("account", account.email.as_str()),
        ("folder", "Updates"),
        ("uid", "7"),
        ("mark_seen", "false"),
    ];
    let response = harness.get("/api/mail/message", &params).await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text());
    let view = response.json();
    assert_eq!(view["uid"], 7);
    assert_eq!(view["folder"], "Updates");
    assert_eq!(view["category"], "verification");
    assert_eq!(view["expiration_days"], 30);
    assert_eq!(view["expires_at"], isoformat(received + Duration::days(30)));
    assert_eq!(view["expired"], true);
    assert_eq!(view["uid_validity"], "1234");
    assert!(view["html_body"].is_string());
    assert_eq!(mutations(&server), Vec::<String>::new());

    // The store is consulted: a saved manual choice shows in the reader.
    let response = harness
        .put_json(
            "/api/mail/message/retention",
            &json!({"account": account.email, "folder": "Updates", "uid": 7,
                    "uid_validity": "1234", "category": "updates"}),
        )
        .await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text());
    let view = harness.get("/api/mail/message", &params).await.json();
    assert_eq!(view["category"], "updates");
    assert_eq!(view["category_source"], "manual");
    assert_ready_only_flags(&server);
}

fn assert_ready_only_flags(server: &mail_proto::testkit::FakeImapServer) {
    assert!(server.flags("Updates", 7).unwrap().is_empty());
}

#[tokio::test]
async fn manual_category_and_expiration_edit_returns_metadata() {
    let received = now_seconds() - Duration::days(1);
    let server = retention_server(received);
    let harness = Harness::new();
    let account = harness.unlock(account(&server));
    let response = harness
        .put_json(
            "/api/mail/message/retention",
            &merge(
                &identity(&account.email),
                json!({"uid": 1, "category": "transactional", "expiration_days": 60}),
            ),
        )
        .await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text());
    let result = response.json();
    assert_eq!(result["uid"], 1);
    assert_eq!(result["folder"], "INBOX");
    assert_eq!(result["category"], "transactional");
    assert_eq!(result["category_source"], "manual");
    assert_eq!(result["expiration_days"], 60);
    assert_eq!(result["expiration_source"], "manual");
    assert_eq!(
        result["expires_at"],
        isoformat(received + Duration::days(60))
    );
    assert_eq!(result["expired"], false);
    assert_eq!(result["uid_validity"], "1234");
    assert_eq!(mutations(&server), Vec::<String>::new());
}

#[tokio::test]
async fn category_only_edit_does_not_reset_existing_expiration_override() {
    let server = retention_server(now_seconds() - Duration::days(1));
    let harness = Harness::new();
    let account = harness.unlock(account(&server));
    let base = merge(&identity(&account.email), json!({"uid": 1}));
    let first = harness
        .put_json(
            "/api/mail/message/retention",
            &merge(&base, json!({"expiration_days": 45})),
        )
        .await;
    assert_eq!(first.status, StatusCode::OK, "{}", first.text());
    let response = harness
        .put_json(
            "/api/mail/message/retention",
            &merge(&base, json!({"category": "transactional"})),
        )
        .await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text());
    let result = response.json();
    assert_eq!(result["category"], "transactional");
    assert_eq!(result["expiration_days"], 45);
    assert_eq!(result["expiration_source"], "manual");
}

#[tokio::test]
async fn expiration_only_edit_normalizes_negative_and_does_not_change_category() {
    let server = retention_server(now_seconds() - Duration::days(1));
    let harness = Harness::new();
    let account = harness.unlock(account(&server));
    let response = harness
        .put_json(
            "/api/mail/message/retention",
            &merge(
                &identity(&account.email),
                json!({"uid": 1, "expiration_days": -23}),
            ),
        )
        .await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text());
    let result = response.json();
    assert_eq!(result["expiration_days"], -1);
    assert_eq!(result["expires_at"], -1);
    assert_eq!(result["category"], "marketing");
    assert_eq!(result["category_source"], "automatic");
}

#[tokio::test]
async fn explicit_nulls_restore_automatic_category_and_category_expiration() {
    let server = retention_server(now_seconds() - Duration::days(1));
    let harness = Harness::new();
    let account = harness.unlock(account(&server));
    let base = merge(&identity(&account.email), json!({"uid": 1}));
    let first = harness
        .put_json(
            "/api/mail/message/retention",
            &merge(&base, json!({"category": "updates", "expiration_days": 90})),
        )
        .await;
    assert_eq!(first.status, StatusCode::OK, "{}", first.text());
    let response = harness
        .put_json(
            "/api/mail/message/retention",
            &merge(&base, json!({"category": null, "expiration_days": null})),
        )
        .await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text());
    let result = response.json();
    assert_eq!(result["category"], "marketing");
    assert_eq!(result["category_source"], "automatic");
    assert_eq!(result["expiration_days"], 30);
    assert_eq!(result["expiration_source"], "category");
}

#[tokio::test]
async fn invalid_manual_edit_is_rejected_before_contacting_server() {
    let server = retention_server(now_seconds());
    let harness = Harness::new();
    let account = harness.unlock(account(&server));
    let body = json!({"account": account.email, "folder": "INBOX", "uid": 7,
                      "uid_validity": "1234", "category": "transactional"});
    let mut invalid: Vec<Value> = Vec::new();
    for value in [
        json!(""),
        json!("Marketing"),
        json!("other"),
        json!([]),
        json!(true),
    ] {
        invalid.push(merge(&body, json!({"category": value})));
    }
    for value in [
        json!(true),
        json!(false),
        json!("30"),
        json!(30.5),
        json!([]),
        json!({}),
        json!(365001),
    ] {
        invalid.push(merge(&body, json!({"expiration_days": value})));
    }
    for value in [
        json!(0),
        json!(-1),
        json!(true),
        json!("7"),
        json!(1.5),
        json!(4_294_967_296u64),
    ] {
        invalid.push(merge(&body, json!({"uid": value})));
    }
    for value in [
        json!(null),
        json!(""),
        json!("0"),
        json!("-1"),
        json!("1.5"),
        json!("4294967296"),
        json!(1234),
    ] {
        invalid.push(merge(&body, json!({"uid_validity": value})));
    }
    invalid.push(without(&body, "uid_validity"));
    invalid.push(merge(&body, json!({"extra": "ignored?"})));
    // Neither category nor expiration supplied (model validator).
    invalid.push(without(&body, "category"));
    for body in invalid {
        let response = harness.put_json("/api/mail/message/retention", &body).await;
        assert_eq!(
            response.status,
            StatusCode::UNPROCESSABLE_ENTITY,
            "{body}: {}",
            response.text()
        );
        assert!(response.json()["detail"].is_array(), "{body}");
    }
    assert_eq!(server.connection_count(), 0);
}

#[tokio::test]
async fn invalid_body_is_reported_before_the_lock_check() {
    let harness = Harness::new();
    let response = harness
        .put_json(
            "/api/mail/message/retention",
            &json!({"account": "a@b.c", "folder": "INBOX", "uid": 0, "uid_validity": "1"}),
        )
        .await;
    response.assert_json_error(StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn stale_uid_validity_returns_conflict() {
    let server = retention_server(now_seconds());
    set_uid_validity(&server, "INBOX", 5678);
    let harness = Harness::new();
    let account = harness.unlock(account(&server));
    let response = harness
        .put_json(
            "/api/mail/message/retention",
            &merge(
                &identity(&account.email),
                json!({"uid": 1, "category": "transactional"}),
            ),
        )
        .await;
    let detail = response.assert_json_error(StatusCode::CONFLICT);
    assert!(
        detail.as_str().unwrap().to_lowercase().contains("refresh"),
        "{detail}"
    );
}

#[tokio::test]
async fn guarded_bulk_and_single_cleanup_forward_mailbox_epoch() {
    let server = retention_server(now_seconds());
    let harness = Harness::new();
    let account = harness.unlock(account(&server));
    let response = harness
        .post_json(
            "/api/mail/messages/delete",
            &json!({"account": account.email, "folder": "INBOX", "uids": [1, 2],
                    "trash": "Trash", "uid_validity": "1234"}),
        )
        .await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text());
    assert_eq!(response.json(), json!({"deleted": [1, 2]}));
    let response = harness
        .delete(
            "/api/mail/message",
            &[
                ("account", &account.email),
                ("folder", "INBOX"),
                ("uid", "3"),
                ("trash", "Trash"),
                ("uid_validity", "1234"),
            ],
        )
        .await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text());
    assert_eq!(response.json(), json!({"deleted": 3}));
    assert!(server.uids("INBOX").is_empty());
    assert_eq!(server.uids("Trash").len(), 3);
}

#[tokio::test]
async fn stale_cleanup_epoch_returns_conflict_for_bulk_and_single_requests() {
    let server = retention_server(now_seconds());
    set_uid_validity(&server, "INBOX", 5678);
    let harness = Harness::new();
    let account = harness.unlock(account(&server));
    let response = harness
        .post_json(
            "/api/mail/messages/delete",
            &json!({"account": account.email, "folder": "INBOX", "uids": [1],
                    "uid_validity": "1234"}),
        )
        .await;
    let detail = response.assert_json_error(StatusCode::CONFLICT);
    assert!(detail.as_str().unwrap().to_lowercase().contains("refresh"));
    let response = harness
        .delete(
            "/api/mail/message",
            &[
                ("account", &account.email),
                ("folder", "INBOX"),
                ("uid", "1"),
                ("uid_validity", "1234"),
            ],
        )
        .await;
    let detail = response.assert_json_error(StatusCode::CONFLICT);
    assert!(detail.as_str().unwrap().to_lowercase().contains("refresh"));
    assert_eq!(server.uids("INBOX"), vec![1, 2, 3]);
    assert_eq!(mutations(&server), Vec::<String>::new());
}

// ---------------------------------------------------------------------------
// RetentionFlowApiTests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn real_retention_flow_persists_overrides_and_applies_current_policies() {
    let received = now_seconds() - Duration::days(60);
    let server = retention_server(received);
    let harness = Harness::new();
    let account_template = account(&server);
    harness.unlock(account_template.clone());
    let email = account_template.email.clone();
    let identity = identity(&email);

    async fn messages(client: &Client, email: &str, filters: &[(&str, &str)]) -> Value {
        let mut params = vec![("account", email)];
        params.extend_from_slice(filters);
        let response = client.get("/api/mail/messages", &params).await;
        assert_eq!(response.status, StatusCode::OK, "{}", response.text());
        response.json()
    }
    async fn edit(client: &Client, identity: &Value, uid: u32, changes: Value) -> Value {
        let mut body = merge(identity, json!({"uid": uid}));
        body = merge(&body, changes);
        let response = client.put_json("/api/mail/message/retention", &body).await;
        assert_eq!(response.status, StatusCode::OK, "{}", response.text());
        response.json()
    }
    async fn detail(client: &Client, email: &str, uid: u32) -> Value {
        let uid = uid.to_string();
        let response = client
            .get(
                "/api/mail/message",
                &[("account", email), ("uid", &uid), ("mark_seen", "false")],
            )
            .await;
        assert_eq!(response.status, StatusCode::OK, "{}", response.text());
        response.json()
    }

    let client = harness.client();
    let initial = by_uid(&messages(&client, &email, &[]).await);
    assert_eq!(initial[&1]["category"], "marketing");
    assert_eq!(initial[&1]["expiration_days"], 30);
    assert_eq!(initial[&1]["expired"], true);
    assert_eq!(
        initial[&1]["expires_at"],
        isoformat(received + Duration::days(30))
    );
    assert_eq!(initial[&2]["category"], "uncategorized");
    assert_eq!(initial[&2]["expires_at"], -1);
    assert_eq!(initial[&2]["expired"], false);

    let recategorized = edit(&client, &identity, 1, json!({"category": "transactional"})).await;
    assert_eq!(recategorized["category_source"], "manual");
    assert_eq!(recategorized["expiration_source"], "category");
    let protected = edit(&client, &identity, 1, json!({"expiration_days": -9})).await;
    assert_eq!(protected["category"], "transactional");
    assert_eq!(protected["expiration_days"], -1);
    assert_eq!(protected["expiration_source"], "manual");
    assert_eq!(protected["expired"], false);
    edit(&client, &identity, 2, json!({"category": "updates"})).await;

    harness.write_preferences(
        5,
        Some(policies_with(
            json!({"marketing": 5, "transactional": 10, "updates": 90}),
        )),
    );
    let current = by_uid(&messages(&client, &email, &[]).await);
    assert_eq!(current[&1]["category"], "transactional");
    assert_eq!(current[&1]["expires_at"], -1);
    assert_eq!(current[&2]["expiration_days"], 90);
    assert_eq!(
        current[&2]["expires_at"],
        isoformat(received + Duration::days(90))
    );
    assert_eq!(current[&2]["expired"], false);
    assert_eq!(current[&3]["expiration_days"], 10);
    let expired = messages(&client, &email, &[("expired_only", "true")]).await;
    assert_eq!(expired["total"], 1);
    assert_eq!(page_uids(&expired), vec![3]);
    let selected = messages(&client, &email, &[("category", "updates")]).await;
    assert_eq!(selected["total"], 1);
    assert_eq!(page_uids(&selected), vec![2]);
    let reader = detail(&client, &email, 1).await;
    for field in [
        "category",
        "category_source",
        "expiration_days",
        "expiration_source",
        "expires_at",
        "expired",
        "uid_validity",
    ] {
        assert_eq!(reader[field], current[&1][field], "{field}");
    }

    {
        let restarted = harness.restarted();
        restarted.unlock(account_template.clone());
        let persisted = detail(&restarted, &email, 1).await;
        assert_eq!(persisted["category"], "transactional");
        assert_eq!(persisted["expiration_days"], -1);
        assert_eq!(
            messages(&restarted, &email, &[("expired_only", "true")]).await["total"],
            1
        );
        let inherited = edit(&restarted, &identity, 1, json!({"expiration_days": null})).await;
        assert_eq!(inherited["category"], "transactional");
        assert_eq!(inherited["expiration_days"], 10);
        assert_eq!(inherited["expiration_source"], "category");
        assert_eq!(inherited["expired"], true);
        let automatic = edit(&restarted, &identity, 1, json!({"category": null})).await;
        assert_eq!(automatic["category"], "marketing");
        assert_eq!(automatic["category_source"], "automatic");
        assert_eq!(automatic["expiration_days"], 5);
    }

    // A mailbox rebuild reuses message UIDs in a new epoch. Both cleanup
    // routes must reject the old snapshot before a mutation.
    set_uid_validity(&server, "INBOX", 5678);
    let stale_edit = client
        .put_json(
            "/api/mail/message/retention",
            &merge(&identity, json!({"uid": 1, "expiration_days": -1})),
        )
        .await;
    assert_eq!(
        stale_edit.status,
        StatusCode::CONFLICT,
        "{}",
        stale_edit.text()
    );
    let stale_bulk = client
        .post_json(
            "/api/mail/messages/delete",
            &merge(&identity, json!({"uids": [1, 3], "trash": "Trash"})),
        )
        .await;
    assert_eq!(
        stale_bulk.status,
        StatusCode::CONFLICT,
        "{}",
        stale_bulk.text()
    );
    let stale_single = client
        .delete(
            "/api/mail/message",
            &[
                ("account", &email),
                ("folder", "INBOX"),
                ("uid_validity", "1234"),
                ("uid", "3"),
                ("trash", "Trash"),
            ],
        )
        .await;
    assert_eq!(
        stale_single.status,
        StatusCode::CONFLICT,
        "{}",
        stale_single.text()
    );
    let refreshed = detail(&client, &email, 1).await;
    assert_eq!(refreshed["uid_validity"], "5678");
    assert_eq!(refreshed["category_source"], "automatic");
    assert_eq!(refreshed["expiration_days"], 5);

    assert_eq!(mutations(&server), Vec::<String>::new());
    assert_eq!(server.uids("INBOX"), vec![1, 2, 3]);
}
