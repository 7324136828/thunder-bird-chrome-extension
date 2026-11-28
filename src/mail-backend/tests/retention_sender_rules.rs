//! Sender-rule routes: port of `SenderRuleApiTests`
//! (tests/test_sender_rules_api.py).
//!
//! Python replaced only `imap_client.connect` with `SenderRuleMailbox`; here
//! the real IMAP client talks to the fake IMAP server (UIDVALIDITY 1234,
//! UIDNEXT 4, three messages received 60 days ago) and parsing/SQLite stay
//! real, as in Python.
//!
//! Tests that relied on patching internals are adapted:
//! * "lock during preparation" uses a server hook that locks the account
//!   when the preparation's connection logs out (the same point in time);
//! * "expiration edit before commit" edits the store from that hook;
//! * the UIDNEXT variants cover the values the fake server can report
//!   (stale `1`/`2`); missing or unparsable UIDNEXT is covered by
//!   mail-core's IMAP tests;
//! * "boundary failure" injects a `NO` for the UID SEARCH the stale UIDNEXT
//!   forces (Python patched `_search_uids`).
//!
//! Not portable without monkeypatching `RetentionStore.save_sender_rule`
//! (they live in mail-core's retention store tests as revision checks):
//! `test_category_change_and_restore_before_commit_does_not_create_stale_rule`,
//! `test_newer_sender_rule_before_commit_is_not_overwritten`,
//! `test_storage_failure_preserves_existing_rule_and_message_overrides`.
//! The AI step of `test_manual_and_ai_email_choices_override_rule_and_keep_expiration`
//! needs the classifier route and a local model; the manual part is ported.

mod common;
mod mail_support;

use axum::http::StatusCode;
use chrono::{DateTime, Duration, Utc};
use mail_core::retention::{Patch, RetentionStore};
use mail_proto::testkit::{Failure, FakeImapServer, HookAction};
use mail_support::*;
use serde_json::{json, Value};

const DEFAULT_FROM: &str = "News <NEWS@EXAMPLE.COM>";

/// One test: the app, the mailbox and the rule identity.
struct Ctx {
    harness: Harness,
    server: FakeImapServer,
    received: DateTime<Utc>,
    identity: Value,
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

impl Ctx {
    fn new() -> Self {
        let received = now_seconds() - Duration::days(60);
        let mut builder = server()
            .credentials("other@example.com", PASSWORD)
            .uid_validity("INBOX", Some(1234))
            .folder("Archive", &[])
            .uid_validity("Archive", Some(1234));
        for (uid, subject) in [
            (1, "Special offer"),
            (2, "Dinner next week"),
            (3, "Order confirmation"),
        ] {
            builder = builder.message_with(
                "INBOX",
                retention_message(uid, subject, &[DEFAULT_FROM], received),
            );
        }
        let server = builder.start();
        let harness = Harness::new();
        let identity = json!({"account": USER, "folder": "INBOX", "uid": 1,
                              "uid_validity": "1234", "category": "marketing"});
        Self {
            harness,
            server,
            received,
            identity,
        }
    }

    fn account(&self) -> mail_core::MailAccount {
        account(&self.server)
    }

    fn unlock(&self) {
        self.harness.unlock(self.account());
    }

    fn client(&self) -> Client {
        self.harness.client()
    }

    /// Replace (or add) a message in INBOX.
    fn put_message(&self, folder: &str, uid: u32, subject: &str, from: &[&str], at: DateTime<Utc>) {
        let message = retention_message(uid, subject, from, at);
        self.server.with_folders(|folders| {
            let folder = folders
                .iter_mut()
                .find(|item| item.name.eq_ignore_ascii_case(folder))
                .expect("folder exists");
            folder.messages.retain(|item| item.uid != uid);
            folder.insert(message);
        });
    }

    /// `SenderRuleMailbox.arrive`: a new message received just now.
    fn arrive(&self, uid: u32, subject: &str, sender: &str) {
        let at = now_seconds() + Duration::seconds(2);
        self.put_message("INBOX", uid, subject, &[sender], at);
    }

    fn arrive_default(&self, uid: u32) {
        self.arrive(uid, "Verification code", "news@example.com");
    }

    fn set_from(&self, uid: u32, from: &[&str]) {
        let subject = match uid {
            1 => "Special offer",
            2 => "Dinner next week",
            _ => "Order confirmation",
        };
        self.put_message("INBOX", uid, subject, from, self.received);
    }

    async fn create_rule_with(&self, client: &Client, changes: Value) -> Value {
        let response = client
            .post_json(
                "/api/mail/message/sender-rule",
                &merge(&self.identity, changes),
            )
            .await;
        assert_eq!(response.status, StatusCode::OK, "{}", response.text());
        response.json()
    }

    async fn create_rule(&self, changes: Value) -> Value {
        self.create_rule_with(&self.client(), changes).await
    }

    async fn rules_with(&self, client: &Client, params: &[(&str, &str)]) -> Value {
        let mut all = vec![("account", USER)];
        // Later duplicates win, like dict merging in Python.
        all.extend_from_slice(params);
        let response = client.get("/api/mail/sender-rules", &all).await;
        assert_eq!(response.status, StatusCode::OK, "{}", response.text());
        response.json()["rules"].clone()
    }

    async fn rules(&self) -> Value {
        self.rules_with(&self.client(), &[]).await
    }

    async fn detail_with(&self, client: &Client, uid: u32, params: &[(&str, &str)]) -> Value {
        let uid = uid.to_string();
        let mut all = vec![
            ("account", USER),
            ("folder", "INBOX"),
            ("uid", uid.as_str()),
            ("mark_seen", "false"),
        ];
        all.extend_from_slice(params);
        let response = client.get("/api/mail/message", &all).await;
        assert_eq!(response.status, StatusCode::OK, "{}", response.text());
        response.json()
    }

    async fn detail(&self, uid: u32) -> Value {
        self.detail_with(&self.client(), uid, &[]).await
    }

    async fn messages(&self, params: &[(&str, &str)]) -> Value {
        let mut all = vec![("account", USER), ("folder", "INBOX")];
        all.extend_from_slice(params);
        let response = self.client().get("/api/mail/messages", &all).await;
        assert_eq!(response.status, StatusCode::OK, "{}", response.text());
        response.json()
    }

    async fn edit(&self, uid: u32, changes: Value) -> Value {
        let body = merge(&without(&self.identity, "category"), json!({"uid": uid}));
        let response = self
            .client()
            .put_json("/api/mail/message/retention", &merge(&body, changes))
            .await;
        assert_eq!(response.status, StatusCode::OK, "{}", response.text());
        response.json()
    }

    async fn remove(&self, params: &[(&str, &str)]) -> common::Resp {
        let mut all = vec![
            ("account", USER),
            ("folder", "INBOX"),
            ("sender", "news@example.com"),
        ];
        all.extend_from_slice(params);
        self.client().delete("/api/mail/sender-rules", &all).await
    }
}

fn get_field<'a>(value: &'a Value, field: &str) -> &'a Value {
    value.get(field).unwrap_or(&Value::Null)
}

#[tokio::test]
async fn all_routes_require_unlock_before_transport() {
    let ctx = Ctx::new();
    let responses = [
        ctx.client()
            .post_json("/api/mail/message/sender-rule", &ctx.identity)
            .await,
        ctx.client()
            .get("/api/mail/sender-rules", &[("account", USER)])
            .await,
        ctx.remove(&[]).await,
    ];
    for response in responses {
        let detail = response.assert_json_error(StatusCode::UNAUTHORIZED);
        assert_eq!(detail["error"], "password_required");
    }
    assert_eq!(ctx.server.connection_count(), 0);
    assert!(!ctx.harness.state.retention.path().exists());
}

#[tokio::test]
async fn invalid_identity_and_category_are_rejected_before_access() {
    let ctx = Ctx::new();
    ctx.unlock();
    let mut invalid = Vec::new();
    for value in [
        json!(null),
        json!(""),
        json!("Marketing"),
        json!("other"),
        json!(true),
        json!([]),
    ] {
        invalid.push(merge(&ctx.identity, json!({"category": value})));
    }
    for value in [
        json!(0),
        json!(-1),
        json!(true),
        json!("1"),
        json!(1.5),
        json!(4_294_967_296u64),
    ] {
        invalid.push(merge(&ctx.identity, json!({"uid": value})));
    }
    for value in [
        json!(null),
        json!(""),
        json!("0"),
        json!("-1"),
        json!("4294967296"),
        json!(1234),
    ] {
        invalid.push(merge(&ctx.identity, json!({"uid_validity": value})));
    }
    invalid.push(without(&ctx.identity, "uid_validity"));
    invalid.push(merge(
        &ctx.identity,
        json!({"sender": "forged@example.com"}),
    ));
    invalid.push(merge(
        &ctx.identity,
        json!({"expected_category_revision": -1}),
    ));
    for body in invalid {
        let response = ctx
            .client()
            .post_json("/api/mail/message/sender-rule", &body)
            .await;
        assert_eq!(
            response.status,
            StatusCode::UNPROCESSABLE_ENTITY,
            "{body}: {}",
            response.text()
        );
    }
    assert_eq!(ctx.server.connection_count(), 0);
    assert_eq!(ctx.rules().await, json!([]));
}

#[tokio::test]
async fn sender_rules_query_validation() {
    let ctx = Ctx::new();
    ctx.unlock();
    let response = ctx
        .client()
        .get(
            "/api/mail/sender-rules",
            &[("account", USER), ("folder", "")],
        )
        .await;
    let detail = response.assert_json_error(StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(detail[0]["type"], "string_too_short");
    let response = ctx
        .client()
        .delete(
            "/api/mail/sender-rules",
            &[
                ("account", USER),
                ("sender", "ab"),
                ("expected_revision", "0"),
            ],
        )
        .await;
    let detail = response.assert_json_error(StatusCode::UNPROCESSABLE_ENTITY);
    let types: Vec<&str> = detail
        .as_array()
        .unwrap()
        .iter()
        .map(|issue| issue["type"].as_str().unwrap())
        .collect();
    assert_eq!(types, ["string_too_short", "missing", "greater_than_equal"]);
    // normalize_sender_address' ValueError is a string detail.
    let response = ctx.remove(&[("sender", "News <news@example.com")]).await;
    assert!(response
        .assert_json_error(StatusCode::UNPROCESSABLE_ENTITY)
        .is_string());
    // Removing an absent rule needs no mailbox request.
    let response = ctx.remove(&[]).await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text());
    assert_eq!(response.json(), json!({"deleted": false}));
    assert_eq!(ctx.server.connection_count(), 0);
}

#[tokio::test]
async fn rule_saves_exact_sender_and_category_without_changing_existing_messages() {
    let ctx = Ctx::new();
    ctx.unlock();
    let before = ctx.detail(2).await;
    let protected = ctx
        .edit(1, json!({"category": "updates", "expiration_days": -1}))
        .await;
    let result = ctx.create_rule(json!({"category": "updates"})).await;
    let rule = &result["rule"];
    assert_eq!(rule["sender"], "news@example.com");
    assert_eq!(rule["category"], "updates");
    assert_eq!(rule["uid_validity"], "1234");
    assert_eq!(rule["first_uid"], 4);
    assert_eq!(rule["folder"], "INBOX");
    assert!(DateTime::parse_from_rfc3339(rule["created_at"].as_str().unwrap()).is_ok());
    assert_eq!(result["uid"], 1);
    assert_eq!(result["folder"], "INBOX");
    assert_eq!(result["category"], "updates");
    assert_eq!(result["category_source"], "manual");
    assert_eq!(result["expiration_days"], -1);
    assert_eq!(result["expiration_source"], "manual");
    assert_eq!(ctx.detail(1).await["expires_at"], protected["expires_at"]);
    let old = ctx.detail(2).await;
    for field in [
        "category",
        "category_source",
        "expiration_days",
        "expires_at",
    ] {
        assert_eq!(old[field], before[field], "{field}");
    }
    assert_eq!(old["sender_rule"]["category"], "updates");
    assert_eq!(ctx.rules().await[0]["folder"], "INBOX");
    assert_read_only(&ctx.server);
}

#[tokio::test]
async fn future_arrival_uses_rule_in_reader_listing_and_category_expiration_filters() {
    let ctx = Ctx::new();
    ctx.unlock();
    let mut policies = default_policies();
    policies["marketing"] = json!(0);
    ctx.harness.write_preferences(10, Some(policies));
    ctx.create_rule(json!({})).await;
    ctx.put_message(
        "INBOX",
        4,
        "Your verification code",
        &["news@example.com"],
        now_seconds() - Duration::minutes(1),
    );
    let future = ctx.detail(4).await;
    assert_eq!(future["category"], "marketing");
    assert_eq!(future["category_source"], "sender_rule");
    assert_eq!(future["expiration_days"], 0);
    assert_eq!(future["expiration_source"], "category");
    assert_eq!(future["expired"], true);
    let listed = by_uid(&ctx.messages(&[]).await);
    for field in [
        "category",
        "category_source",
        "expiration_days",
        "expires_at",
        "sender_rule",
    ] {
        assert_eq!(
            get_field(&listed[&4], field),
            get_field(&future, field),
            "{field}"
        );
    }
    assert_eq!(
        page_uids(&ctx.messages(&[("category", "marketing")]).await),
        vec![4, 1]
    );
    assert_eq!(
        page_uids(
            &ctx.messages(&[("category", "marketing"), ("expired_only", "true")])
                .await
        ),
        vec![4, 1]
    );
    assert_eq!(ctx.detail(2).await["category"], "uncategorized");
    assert_read_only(&ctx.server);
}

#[tokio::test]
async fn exact_sender_match_does_not_include_same_domain_or_display_name() {
    let ctx = Ctx::new();
    ctx.unlock();
    ctx.create_rule(json!({})).await;
    ctx.arrive(4, "Verification code", "Other News <other@example.com>");
    ctx.arrive(5, "Verification code", "News <news@elsewhere.example>");
    ctx.arrive(
        6,
        "Verification code",
        "Different Display <NeWs@ExAmPlE.CoM>",
    );
    for uid in [4, 5] {
        let view = ctx.detail(uid).await;
        assert_eq!(view["category"], "verification");
        assert_eq!(view["category_source"], "automatic");
        assert!(get_field(&view, "sender_rule").is_null());
    }
    let view = ctx.detail(6).await;
    assert_eq!(view["category"], "marketing");
    assert_eq!(view["category_source"], "sender_rule");
    assert_read_only(&ctx.server);
}

#[tokio::test]
async fn manual_email_choices_override_rule_and_keep_expiration() {
    let ctx = Ctx::new();
    ctx.unlock();
    ctx.create_rule(json!({})).await;
    ctx.arrive_default(4);
    let chosen = ctx
        .edit(
            4,
            json!({"category": "transactional", "expiration_days": -9}),
        )
        .await;
    assert_eq!(chosen["category_source"], "manual");
    assert_eq!(chosen["expires_at"], -1);
    let restored = ctx.edit(4, json!({"category": null})).await;
    assert_eq!(restored["category"], "marketing");
    assert_eq!(restored["category_source"], "sender_rule");
    assert_eq!(restored["expiration_days"], -1);
    assert_read_only(&ctx.server);
}

#[tokio::test]
async fn rule_survives_restart_and_is_scoped_to_account_server_and_folder() {
    let ctx = Ctx::new();
    ctx.unlock();
    ctx.create_rule(json!({})).await;
    ctx.arrive_default(4);
    let at = now_seconds() + Duration::seconds(2);
    ctx.put_message("Archive", 4, "Verification code", &["news@example.com"], at);

    let restarted = ctx.harness.restarted();
    restarted.unlock(ctx.account());
    assert_eq!(
        ctx.rules_with(&restarted, &[]).await[0]["sender"],
        "news@example.com"
    );
    assert_eq!(
        ctx.detail_with(&restarted, 4, &[]).await["category_source"],
        "sender_rule"
    );
    assert_eq!(
        ctx.rules_with(&restarted, &[("folder", "Archive")]).await,
        json!([])
    );
    assert_eq!(
        ctx.detail_with(&restarted, 4, &[("folder", "Archive")])
            .await["category_source"],
        "automatic"
    );
    let other = account_at("other@example.com", ctx.server.port());
    restarted.unlock(other);
    assert_eq!(
        ctx.rules_with(&restarted, &[("account", "other@example.com")])
            .await,
        json!([])
    );
    assert_eq!(
        ctx.detail_with(&restarted, 4, &[("account", "other@example.com")])
            .await["category_source"],
        "automatic"
    );
    // Same mailbox owner on a different server name: a different identity.
    let mut moved = ctx.account();
    moved.incoming_server = "localhost".into();
    restarted.unlock(moved);
    assert_eq!(ctx.rules_with(&restarted, &[]).await, json!([]));
    assert_eq!(
        ctx.detail_with(&restarted, 4, &[]).await["category_source"],
        "automatic"
    );
    assert_read_only(&ctx.server);
}

#[tokio::test]
async fn mailbox_epoch_reset_retains_rule_and_uses_received_date_cutoff() {
    let ctx = Ctx::new();
    ctx.unlock();
    let rule = ctx.create_rule(json!({})).await["rule"].clone();
    set_uid_validity(&ctx.server, "INBOX", 5678);
    let created: DateTime<Utc> = DateTime::parse_from_rfc3339(rule["created_at"].as_str().unwrap())
        .unwrap()
        .with_timezone(&Utc);
    let created =
        created - Duration::nanoseconds(i64::from(chrono::Timelike::nanosecond(&created)));
    ctx.put_message(
        "INBOX",
        1,
        "Verification code",
        &[DEFAULT_FROM],
        created - Duration::days(1),
    );
    ctx.put_message(
        "INBOX",
        2,
        "Verification code",
        &[DEFAULT_FROM],
        created + Duration::seconds(2),
    );
    ctx.put_message(
        "INBOX",
        3,
        "Verification code",
        &[DEFAULT_FROM],
        ctx.received,
    );
    let first = ctx.detail(1).await;
    assert_eq!(first["category_source"], "automatic");
    assert_eq!(first["category"], "verification");
    let second = ctx.detail(2).await;
    assert_eq!(second["category_source"], "sender_rule");
    assert_eq!(second["category"], "marketing");
    assert_eq!(ctx.detail(3).await["category_source"], "automatic");
    assert_eq!(ctx.rules().await[0]["uid_validity"], "1234");
    assert_read_only(&ctx.server);
}

#[tokio::test]
async fn remove_rule_is_idempotent_and_preserves_individual_expiration_and_category() {
    let ctx = Ctx::new();
    ctx.unlock();
    let before = ctx
        .edit(1, json!({"category": "marketing", "expiration_days": -1}))
        .await;
    ctx.create_rule(json!({})).await;
    ctx.arrive_default(4);
    ctx.edit(4, json!({"expiration_days": 45})).await;
    ctx.arrive_default(5);
    ctx.edit(
        5,
        json!({"category": "transactional", "expiration_days": -1}),
    )
    .await;
    let response = ctx.remove(&[]).await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text());
    assert_eq!(response.json(), json!({"deleted": true}));
    assert_eq!(ctx.rules().await, json!([]));
    // Removing a rule stops future matching and retains the category
    // assigned while the rule was active.
    let fourth = ctx.detail(4).await;
    assert_eq!(fourth["category"], "marketing");
    assert_eq!(fourth["category_source"], "sender_rule");
    assert_eq!(fourth["expiration_days"], 45);
    let fifth = ctx.detail(5).await;
    assert_eq!(fifth["category"], "transactional");
    assert_eq!(fifth["expires_at"], -1);
    let first = ctx.detail(1).await;
    for field in [
        "category",
        "category_source",
        "expiration_days",
        "expires_at",
    ] {
        assert_eq!(first[field], before[field], "{field}");
    }
    let again = ctx.remove(&[]).await;
    assert_eq!(again.status, StatusCode::OK, "{}", again.text());
    assert_eq!(again.json(), json!({"deleted": false}));
    ctx.arrive_default(6);
    let sixth = ctx.detail(6).await;
    assert_eq!(sixth["category"], "verification");
    assert_eq!(sixth["category_source"], "automatic");
    assert_read_only(&ctx.server);
}

#[tokio::test]
async fn stale_epoch_category_and_missing_message_do_not_create_rule() {
    let ctx = Ctx::new();
    ctx.unlock();
    set_uid_validity(&ctx.server, "INBOX", 5678);
    let response = ctx
        .client()
        .post_json("/api/mail/message/sender-rule", &ctx.identity)
        .await;
    assert_eq!(response.status, StatusCode::CONFLICT, "{}", response.text());
    assert_eq!(ctx.rules().await, json!([]));
    set_uid_validity(&ctx.server, "INBOX", 1234);
    ctx.edit(
        1,
        json!({"category": "transactional", "expiration_days": 45}),
    )
    .await;
    let response = ctx
        .client()
        .post_json("/api/mail/message/sender-rule", &ctx.identity)
        .await;
    assert_eq!(
        response.assert_json_error(StatusCode::CONFLICT),
        json!("The email category changed. Refresh the message before saving a sender rule.")
    );
    assert_eq!(ctx.rules().await, json!([]));
    let view = ctx.detail(1).await;
    assert_eq!(view["category"], "transactional");
    assert_eq!(view["expiration_days"], 45);
    ctx.server.with_folders(|folders| {
        folders[0].messages.retain(|item| item.uid != 1);
    });
    let response = ctx
        .client()
        .post_json(
            "/api/mail/message/sender-rule",
            &merge(&ctx.identity, json!({"category": "transactional"})),
        )
        .await;
    assert!(
        [
            StatusCode::NOT_FOUND,
            StatusCode::CONFLICT,
            StatusCode::BAD_GATEWAY
        ]
        .contains(&response.status),
        "{}",
        response.text()
    );
    assert_eq!(ctx.rules().await, json!([]));
    assert_read_only(&ctx.server);
}

#[tokio::test]
async fn expected_category_revision_mismatch_is_a_conflict() {
    let ctx = Ctx::new();
    ctx.unlock();
    let response = ctx
        .client()
        .post_json(
            "/api/mail/message/sender-rule",
            &merge(&ctx.identity, json!({"expected_category_revision": 3})),
        )
        .await;
    response.assert_json_error(StatusCode::CONFLICT);
    assert_eq!(ctx.rules().await, json!([]));
    let created = ctx
        .create_rule(json!({"expected_category_revision": 0}))
        .await;
    assert_eq!(created["rule"]["category"], "marketing");
}

#[tokio::test]
async fn missing_malformed_and_multiple_from_addresses_are_rejected() {
    let ctx = Ctx::new();
    ctx.unlock();
    let invalid: Vec<Vec<&str>> = vec![
        vec![],
        vec![""],
        vec!["not-an-address"],
        vec!["news@example.com, another@example.com"],
        vec!["news@example.com", "another@example.com"],
        vec!["News <news@example.com"],
        vec!["group: news@example.com;"],
    ];
    for headers in invalid {
        ctx.set_from(1, &headers);
        let response = ctx
            .client()
            .post_json("/api/mail/message/sender-rule", &ctx.identity)
            .await;
        assert!(
            [StatusCode::BAD_REQUEST, StatusCode::UNPROCESSABLE_ENTITY].contains(&response.status),
            "{headers:?}: {}",
            response.text()
        );
        assert_eq!(ctx.rules().await, json!([]));
    }
    assert_read_only(&ctx.server);
}

#[tokio::test]
async fn stale_uidnext_uses_whole_mailbox_future_boundary() {
    let ctx = Ctx::new();
    ctx.unlock();
    for next_uid in [1u32, 2] {
        ctx.server
            .with_folders(|folders| folders[0].uid_next = next_uid);
        let created = ctx.create_rule(json!({})).await;
        assert_eq!(created["rule"]["first_uid"], 4, "UIDNEXT {next_uid}");
        assert_eq!(ctx.detail(2).await["category"], "uncategorized");
        assert_eq!(ctx.detail(3).await["category"], "transactional");
    }
    assert_read_only(&ctx.server);
}

#[tokio::test]
async fn mailbox_boundary_failure_does_not_change_existing_rule() {
    let ctx = Ctx::new();
    ctx.unlock();
    ctx.create_rule(json!({})).await;
    let before = ctx.rules().await;
    ctx.server.with_folders(|folders| folders[0].uid_next = 1);
    ctx.server
        .fail_next("UID SEARCH", Failure::No("Search failed".into()));
    let response = ctx
        .client()
        .post_json("/api/mail/message/sender-rule", &ctx.identity)
        .await;
    assert_eq!(
        response.status,
        StatusCode::BAD_GATEWAY,
        "{}",
        response.text()
    );
    assert_eq!(ctx.rules().await, before);
    assert_read_only(&ctx.server);
}

#[tokio::test]
async fn expiration_edit_before_rule_commit_is_preserved() {
    let ctx = Ctx::new();
    ctx.unlock();
    let data_directory = ctx.harness.state.data_directory.clone();
    let account = ctx.account();
    ctx.server.set_hook(move |request| {
        if request.command == "LOGOUT" {
            let store = RetentionStore::new(&data_directory);
            store
                .update(&account, "INBOX", 1, "1234", Patch::Unset, Patch::Set(-1))
                .expect("update expiration");
        }
        HookAction::Continue
    });
    let response = ctx
        .client()
        .post_json("/api/mail/message/sender-rule", &ctx.identity)
        .await;
    ctx.server.clear_hook();
    assert_eq!(response.status, StatusCode::OK, "{}", response.text());
    let view = ctx.detail(1).await;
    assert_eq!(view["expiration_days"], -1);
    assert_eq!(view["expiration_source"], "manual");
    assert_read_only(&ctx.server);
}

#[tokio::test]
async fn lock_during_rule_preparation_discards_write() {
    let ctx = Ctx::new();
    ctx.unlock();
    let sessions = ctx.harness.state.sessions.clone();
    ctx.server.set_hook(move |request| {
        if request.command == "LOGOUT" {
            sessions.forget(USER);
        }
        HookAction::Continue
    });
    let response = ctx
        .client()
        .post_json("/api/mail/message/sender-rule", &ctx.identity)
        .await;
    ctx.server.clear_hook();
    assert_eq!(
        response.assert_json_error(StatusCode::UNAUTHORIZED),
        json!({"error": "password_required", "email": USER})
    );
    ctx.unlock();
    assert_eq!(ctx.rules().await, json!([]));
    assert_read_only(&ctx.server);
}

#[tokio::test]
async fn lock_during_removal_preparation_preserves_rule() {
    let ctx = Ctx::new();
    ctx.unlock();
    ctx.create_rule(json!({})).await;
    let before = ctx.rules().await;
    let sessions = ctx.harness.state.sessions.clone();
    ctx.server.set_hook(move |request| {
        if request.command == "LOGOUT" {
            sessions.forget(USER);
        }
        HookAction::Continue
    });
    let response = ctx.remove(&[]).await;
    ctx.server.clear_hook();
    response.assert_json_error(StatusCode::UNAUTHORIZED);
    ctx.unlock();
    assert_eq!(ctx.rules().await, before);
    assert_read_only(&ctx.server);
}

#[tokio::test]
async fn stale_removal_revision_preserves_newer_rule() {
    let ctx = Ctx::new();
    ctx.unlock();
    let before = ctx.create_rule(json!({})).await["rule"].clone();
    ctx.edit(1, json!({"category": "updates"})).await;
    let newer = ctx.create_rule(json!({"category": "updates"})).await["rule"].clone();
    let revision = before["revision"].to_string();
    let response = ctx.remove(&[("expected_revision", &revision)]).await;
    response.assert_json_error(StatusCode::CONFLICT);
    assert_eq!(ctx.rules().await, json!([newer]));
    assert_read_only(&ctx.server);
}

#[tokio::test]
async fn rule_updates_and_removal_keep_historical_categories_for_unopened_mail() {
    let ctx = Ctx::new();
    ctx.unlock();
    ctx.create_rule(json!({})).await;
    ctx.arrive_default(4);
    // UID 4 is intentionally never fetched while the original rule is
    // active. Its category must not depend on when the reader opens it.
    ctx.edit(1, json!({"category": "updates"})).await;
    let changed = ctx.create_rule(json!({"category": "updates"})).await["rule"].clone();
    assert_eq!(changed["first_uid"], 5);
    ctx.arrive_default(5);
    let revision = changed["revision"].to_string();
    let response = ctx.remove(&[("expected_revision", &revision)]).await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text());
    ctx.arrive_default(6);
    let fourth = ctx.detail(4).await;
    assert_eq!(fourth["category"], "marketing");
    assert_eq!(fourth["category_source"], "sender_rule");
    let fifth = ctx.detail(5).await;
    assert_eq!(fifth["category"], "updates");
    assert_eq!(fifth["category_source"], "sender_rule");
    let sixth = ctx.detail(6).await;
    assert_eq!(sixth["category"], "verification");
    assert_eq!(sixth["category_source"], "automatic");
    assert!(fourth["sender_rule"].is_null());
    assert!(fifth["sender_rule"].is_null());
    assert_eq!(
        page_uids(&ctx.messages(&[("category", "updates")]).await),
        vec![5, 1]
    );
    assert_read_only(&ctx.server);
}

#[tokio::test]
async fn uncategorized_rule_gives_future_mail_never_expiring_category_default() {
    let ctx = Ctx::new();
    ctx.unlock();
    ctx.create_rule(json!({"uid": 2, "category": "uncategorized"}))
        .await;
    ctx.arrive_default(4);
    let future = ctx.detail(4).await;
    assert_eq!(future["category"], "uncategorized");
    assert_eq!(future["category_source"], "sender_rule");
    assert_eq!(future["expiration_days"], -1);
    assert_eq!(future["expires_at"], -1);
    assert_eq!(future["expired"], false);
    assert_read_only(&ctx.server);
}
