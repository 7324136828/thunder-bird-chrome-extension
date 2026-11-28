//! POP3 compatibility mode: unlock, folders and message listing against the
//! fake POP3 server (mail_proto::testkit). The listing tests mirror
//! `tests/test_mail_pagination.py` with IMAP-only expectations (SEARCH
//! criteria, FETCH batches) replaced by the observable POP3 behaviour.

use std::collections::BTreeSet;

use mail_core::imap::ListMessagesOptions;
use mail_core::pop3;
use mail_core::sessions::{MailAccount, PROTOCOL_POP3};
use mail_core::MailError;
use mail_proto::testkit::{Failure, FakePop3Server};
use serde_json::{json, Value};

const EMAIL: &str = "user@example.com";
const PASSWORD: &str = "pop-secret-123";

fn account_for(server: &FakePop3Server, password: &str) -> MailAccount {
    let mut account = MailAccount::new(
        EMAIL,
        password,
        server.host(),
        server.port(),
        "none",
        "smtp.example.com",
        587,
        "starttls",
    );
    account.incoming_mail_protocol = PROTOCOL_POP3.into();
    account
}

fn account(server: &FakePop3Server) -> MailAccount {
    account_for(server, PASSWORD)
}

fn server_with(messages: &[Vec<u8>]) -> FakePop3Server {
    messages
        .iter()
        .fold(
            FakePop3Server::builder().credentials(EMAIL, PASSWORD),
            |builder, raw| builder.message(raw.clone()),
        )
        .start()
}

fn numbered(count: u32) -> Vec<Vec<u8>> {
    (1..=count)
        .map(|n| format!("From: user@example.com\r\nSubject: {n}\r\n\r\nBody {n}\r\n").into_bytes())
        .collect()
}

fn uids(page: &Value) -> Vec<u64> {
    page["messages"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m["uid"].as_u64().unwrap())
        .collect()
}

fn list(server: &FakePop3Server, options: &ListMessagesOptions<'_>) -> Value {
    pop3::list_messages(&account(server), "INBOX", options).expect("list_messages")
}

fn count(server: &FakePop3Server, name: &str) -> usize {
    server
        .command_names()
        .iter()
        .filter(|c| c.as_str() == name)
        .count()
}

fn assert_quit_and_no_dele(server: &FakePop3Server) {
    let names = server.command_names();
    assert!(!names.iter().any(|n| n == "DELE"), "{names:?}");
    assert_eq!(
        count(server, "QUIT"),
        server.connection_count(),
        "{names:?}"
    );
}

fn operation_message(error: MailError) -> String {
    match error {
        MailError::Operation(message) => message,
        other => panic!("expected an operation error, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Unlock / folders
// ---------------------------------------------------------------------------

#[test]
fn verify_login_accepts_valid_credentials_and_quits() {
    let server = server_with(&numbered(2));
    pop3::verify_login(&account(&server)).unwrap();
    assert_eq!(server.command_names(), ["USER", "PASS", "STAT", "QUIT"]);
    // The password never reaches the server log in clear text.
    assert!(server.commands().iter().all(|c| !c.contains(PASSWORD)));
}

#[test]
fn verify_login_rejects_bad_password_with_imap_message() {
    let server = server_with(&numbered(1));
    let error = pop3::verify_login(&account_for(&server, "wrong-password")).unwrap_err();
    assert_eq!(error.status(), 502);
    let message = operation_message(error);
    assert_eq!(
        message,
        "Mailbox sign-in failed. Check the password or use an app password."
    );
    assert!(!message.contains("wrong-password"));
}

#[test]
fn connection_failure_names_the_server() {
    let server = server_with(&[]);
    let mut account = account(&server);
    drop(server);
    // Nothing listens on a port that was just released.
    account.incoming_port = {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.local_addr().unwrap().port()
    };
    let message = operation_message(pop3::verify_login(&account).unwrap_err());
    assert!(
        message.starts_with(&format!(
            "Could not connect to 127.0.0.1:{}: ",
            account.incoming_port
        )),
        "{message}"
    );
    assert!(!message.contains(PASSWORD));
}

#[test]
fn stat_failure_reports_inbox_unavailable() {
    let server = server_with(&numbered(1));
    server.fail_next("STAT", Failure::no());
    let message = operation_message(pop3::verify_login(&account(&server)).unwrap_err());
    assert_eq!(message, "The server would not open the INBOX folder");
}

#[test]
fn starttls_without_stls_support_is_a_connection_error() {
    let server = server_with(&numbered(1));
    let mut account = account(&server);
    account.incoming_protocol = "starttls".into();
    let message = operation_message(pop3::verify_login(&account).unwrap_err());
    assert!(
        message.starts_with("Could not connect to 127.0.0.1:"),
        "{message}"
    );
    assert!(!server.command_names().iter().any(|c| c == "USER"));
}

#[test]
fn list_folders_returns_only_inbox_in_imap_shape() {
    let server = server_with(&numbered(3));
    let folders = pop3::list_folders(&account(&server)).unwrap();
    assert_eq!(
        folders,
        vec![json!({
            "name": "INBOX",
            "delimiter": "",
            "flags": [],
            "special": "inbox",
            "selectable": true,
        })]
    );
    assert_quit_and_no_dele(&server);
}

#[test]
fn list_folders_requires_working_credentials() {
    let server = server_with(&numbered(1));
    let error = pop3::list_folders(&account_for(&server, "nope")).unwrap_err();
    assert_eq!(
        operation_message(error),
        "Mailbox sign-in failed. Check the password or use an app password."
    );
}

#[test]
fn imap_only_is_a_400_with_stable_detail() {
    let error = pop3::imap_only();
    assert_eq!(error.status(), 400);
    assert_eq!(error.body(), json!({"detail": pop3::IMAP_ONLY_MESSAGE}));
}

// ---------------------------------------------------------------------------
// Listing
// ---------------------------------------------------------------------------

#[test]
fn default_page_lists_five_newest_with_header_only_reads() {
    let server = server_with(&numbered(11));
    let page = list(&server, &ListMessagesOptions::default());
    assert_eq!(
        (&page["total"], &page["offset"], &page["limit"]),
        (&json!(11), &json!(0), &json!(5))
    );
    assert_eq!(uids(&page), [11, 10, 9, 8, 7]);
    let tops: Vec<String> = server
        .commands()
        .into_iter()
        .filter(|c| c.starts_with("TOP"))
        .collect();
    assert_eq!(
        tops,
        ["TOP 11 0", "TOP 10 0", "TOP 9 0", "TOP 8 0", "TOP 7 0"]
    );
    assert_eq!(count(&server, "RETR"), 0);
    assert_quit_and_no_dele(&server);
}

#[test]
fn summaries_have_the_imap_keys_and_pop3_values() {
    let raw =
        b"Received: from mx.example.org by pop.example.com; Tue, 14 Oct 2025 10:00:00 +0200\r\n\
From: \"Sender Name\" <Sender@Example.org>\r\nTo: user@example.com\r\n\
Subject: =?utf-8?q?Caf=C3=A9?=\r\nDate: Mon, 13 Oct 2025 08:00:00 +0000\r\n\r\nHello\r\n"
            .to_vec();
    let server = server_with(&[raw]);
    let page = list(&server, &ListMessagesOptions::default());
    let summary = &page["messages"][0];
    let keys: BTreeSet<&str> = summary
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    let expected: BTreeSet<&str> = [
        "uid",
        "flags",
        "seen",
        "flagged",
        "answered",
        "size",
        "internal_date",
        "subject",
        "from",
        "to",
        "date",
        "category",
        "category_source",
        "category_reason",
        "category_model",
        "expiration_days",
        "expiration_source",
        "expires_at",
        "expired",
        "received_at",
        "uid_validity",
        "sender_rule",
    ]
    .into_iter()
    .collect();
    assert_eq!(keys, expected);
    assert_eq!(summary["uid"], 1);
    assert_eq!(summary["flags"], json!([]));
    assert_eq!(summary["seen"], false);
    assert_eq!(summary["flagged"], false);
    assert_eq!(summary["answered"], false);
    assert_eq!(
        summary["size"].as_u64().unwrap(),
        server.messages()[0].len() as u64
    );
    assert_eq!(summary["subject"], "Café");
    assert_eq!(summary["to"], "user@example.com");
    // INTERNALDATE stand-in: the topmost Received header.
    assert_eq!(summary["internal_date"], "2025-10-14T10:00:00+02:00");
    assert_eq!(summary["received_at"], "2025-10-14T08:00:00+00:00");
    assert_eq!(summary["date"], "2025-10-13T08:00:00+00:00");
    assert_eq!(summary["category_source"], "automatic");
    let epoch = summary["uid_validity"].as_str().unwrap();
    let value: u64 = epoch.parse().unwrap();
    assert!((1..=4_294_967_295).contains(&value));
    assert_eq!(summary["sender_rule"], Value::Null);
}

#[test]
fn received_date_falls_back_to_date_header_then_null() {
    let server = server_with(&[
        b"From: a@example.com\r\nDate: Wed, 1 Jan 2025 12:00:00 +0100\r\n\r\nx\r\n".to_vec(),
        b"From: a@example.com\r\nSubject: undated\r\n\r\nx\r\n".to_vec(),
    ]);
    let page = list(&server, &ListMessagesOptions::default());
    let undated = &page["messages"][0];
    let dated = &page["messages"][1];
    assert_eq!(dated["internal_date"], "2025-01-01T12:00:00+01:00");
    assert_eq!(dated["received_at"], "2025-01-01T11:00:00+00:00");
    assert_eq!(undated["internal_date"], Value::Null);
    assert_eq!(undated["date"], Value::Null);
    assert_eq!(undated["received_at"], Value::Null);
    assert_eq!(undated["expired"], false);
}

#[test]
fn offset_beyond_total_returns_empty_page_without_header_reads() {
    let server = server_with(&numbered(1));
    let page = list(
        &server,
        &ListMessagesOptions {
            offset: 5,
            limit: 5,
            ..Default::default()
        },
    );
    assert_eq!(
        page,
        json!({"total": 1, "offset": 5, "limit": 5, "messages": []})
    );
    assert_eq!(count(&server, "TOP"), 0);
}

#[test]
fn read_status_unread_matches_everything_and_read_matches_nothing() {
    let server = server_with(&numbered(12));
    let page = list(
        &server,
        &ListMessagesOptions {
            read_status: "unread",
            offset: 1,
            limit: 2,
            ..Default::default()
        },
    );
    assert_eq!(page["total"], 12);
    assert_eq!(uids(&page), [11, 10]);
    assert!(page["messages"]
        .as_array()
        .unwrap()
        .iter()
        .all(|m| m["seen"] == false));

    let server = server_with(&numbered(3));
    let page = list(
        &server,
        &ListMessagesOptions {
            read_status: "read",
            ..Default::default()
        },
    );
    assert_eq!(
        page,
        json!({"total": 0, "offset": 0, "limit": 5, "messages": []})
    );
    assert_eq!(count(&server, "TOP"), 0);
}

fn domain_messages() -> Vec<Vec<u8>> {
    [
        "From: First <a@example.com>\r\nSubject: offers\r\n\r\n",
        "From: <a@ExAmPle.COM>\r\nSubject: offers\r\n\r\n",
        "From: <a@news.example.com>\r\nSubject: offers\r\n\r\n",
        "From: <a@notexample.com>\r\nSubject: offers\r\n\r\n",
        "From: \"example.com <a@example.com>\" <a@evil.test>\r\nSubject: offers\r\n\r\n",
        "From: <a@evil.test>\r\nReply-To: <a@example.com>\r\nSubject: offers\r\n\r\n",
        "From: <a@evil.test>\r\nSubject: example.com offers\r\n\r\n",
        "From: <a@example.com.evil.test>\r\nSubject: offers\r\n\r\n",
        "From: Alice <a@other.test>, Bob <b@example.com>\r\nSubject: hello\r\n\r\n",
        "From: <a@other.test>\r\nSubject: offers\r\n\r\n",
    ]
    .iter()
    .map(|m| m.as_bytes().to_vec())
    .collect()
}

#[test]
fn sender_domain_filter_checks_addresses_before_total_and_pagination() {
    let server = server_with(&domain_messages());
    let domains = vec!["EXAMPLE.com.".to_string()];
    let page = list(
        &server,
        &ListMessagesOptions {
            sender_domains: &domains,
            offset: 1,
            limit: 2,
            ..Default::default()
        },
    );
    assert_eq!(page["total"], 4);
    assert_eq!(uids(&page), [3, 2]);
    // Headers only: every candidate's TOP once (cached for the page).
    assert_eq!(count(&server, "TOP"), 10);
    assert_eq!(count(&server, "RETR"), 0);
}

#[test]
fn multiple_domains_are_or_combined_and_text_query_is_and_combined() {
    let server = server_with(&domain_messages());
    let domains = vec!["example.com".to_string(), "other.test".to_string()];
    let page = list(
        &server,
        &ListMessagesOptions {
            sender_domains: &domains,
            query: "offers",
            limit: 10,
            ..Default::default()
        },
    );
    assert_eq!(page["total"], 4);
    assert_eq!(uids(&page), [10, 3, 2, 1]);
}

#[test]
fn read_status_composes_with_text_and_domains() {
    let server = server_with(&domain_messages());
    let domains = vec!["example.com".to_string(), "other.test".to_string()];
    let unread = list(
        &server,
        &ListMessagesOptions {
            sender_domains: &domains,
            query: "offers",
            read_status: "unread",
            limit: 10,
            ..Default::default()
        },
    );
    assert_eq!(uids(&unread), [10, 3, 2, 1]);
    let read = list(
        &server,
        &ListMessagesOptions {
            sender_domains: &domains,
            query: "offers",
            read_status: "read",
            limit: 10,
            ..Default::default()
        },
    );
    assert_eq!(read["total"], 0);
}

#[test]
fn international_domain_matches_unicode_and_punycode_addresses() {
    let server = server_with(&[
        "From: user@b\u{fc}cher.example\r\n\r\n".as_bytes().to_vec(),
        b"From: user@xn--bcher-kva.example\r\n\r\n".to_vec(),
        b"From: user@other.example\r\n\r\n".to_vec(),
    ]);
    let domains = vec!["b\u{fc}cher.example".to_string()];
    let page = list(
        &server,
        &ListMessagesOptions {
            sender_domains: &domains,
            has_unicode_input: true,
            ..Default::default()
        },
    );
    assert_eq!(page["total"], 2);
    assert_eq!(uids(&page), [2, 1]);
}

#[test]
fn unicode_mapped_to_plain_ascii_matches_both_spellings() {
    for query in ["", "offers"] {
        let server = server_with(&[
            "From: user@fa\u{df}.de\r\nSubject: offers\r\n\r\n"
                .as_bytes()
                .to_vec(),
            b"From: user@fass.de\r\nSubject: offers\r\n\r\n".to_vec(),
            b"From: user@other.de\r\nSubject: hello\r\n\r\n".to_vec(),
        ]);
        let domains = vec!["fa\u{df}.de".to_string()];
        let page = list(
            &server,
            &ListMessagesOptions {
                sender_domains: &domains,
                query,
                ..Default::default()
            },
        );
        assert_eq!(page["total"], 2, "query={query:?}");
        assert_eq!(uids(&page), [2, 1]);
    }
}

#[test]
fn no_domain_matches_reads_no_summaries() {
    let server = server_with(&[b"From: \"example.com\" <user@evil.test>\r\n\r\n".to_vec()]);
    let domains = vec!["example.com".to_string()];
    let page = list(
        &server,
        &ListMessagesOptions {
            sender_domains: &domains,
            ..Default::default()
        },
    );
    assert_eq!(page["total"], 0);
    assert_eq!(page["messages"], json!([]));
    assert_eq!(count(&server, "TOP"), 1);
}

#[test]
fn domain_header_failure_reports_filter_error() {
    let server = server_with(&numbered(1));
    server.fail_next("TOP", Failure::Disconnect);
    let domains = vec!["example.com".to_string()];
    let error = pop3::list_messages(
        &account(&server),
        "INBOX",
        &ListMessagesOptions {
            sender_domains: &domains,
            ..Default::default()
        },
    )
    .unwrap_err();
    assert_eq!(
        operation_message(error),
        "The server could not filter messages by sender domain"
    );
}

#[test]
fn invalid_domains_are_rejected_before_connecting() {
    let server = server_with(&numbered(1));
    let many = vec!["a.example".to_string(); 201];
    let cases: Vec<(Vec<String>, &str)> = vec![
        (
            vec![String::new()],
            "Sender domains must be non-empty domain names up to 253 characters",
        ),
        (
            vec!["user@example.com".into()],
            "Enter a valid sender domain without an email address or URL",
        ),
        (
            vec!["example.com\" ALL".into()],
            "Enter a valid sender domain without an email address or URL",
        ),
        (
            vec!["https://example.com".into()],
            "Enter a valid sender domain without an email address or URL",
        ),
        (vec!["a..com".into()], "Enter a valid sender domain"),
        (many, "Choose at most 200 sender domains"),
    ];
    for (domains, message) in cases {
        let error = pop3::list_messages(
            &account(&server),
            "INBOX",
            &ListMessagesOptions {
                sender_domains: &domains,
                ..Default::default()
            },
        )
        .unwrap_err();
        assert_eq!(error.status(), 422);
        assert_eq!(error.body(), json!({"detail": message}));
    }
    assert_eq!(server.connection_count(), 0);
}

#[test]
fn invalid_read_status_and_category_are_rejected_before_connecting() {
    let server = server_with(&numbered(1));
    for read_status in ["", "READ", "unread ALL", "seen"] {
        let error = pop3::list_messages(
            &account(&server),
            "INBOX",
            &ListMessagesOptions {
                read_status,
                ..Default::default()
            },
        )
        .unwrap_err();
        assert_eq!(
            error.body(),
            json!({"detail": "Read status must be all, unread, or read"})
        );
        assert_eq!(error.status(), 422);
    }
    let error = pop3::list_messages(
        &account(&server),
        "INBOX",
        &ListMessagesOptions {
            category: Some("custom"),
            ..Default::default()
        },
    )
    .unwrap_err();
    assert_eq!(
        error.body(),
        json!({"detail": "Choose a valid email category"})
    );
    assert_eq!(server.connection_count(), 0);
}

#[test]
fn text_query_searches_headers_and_bodies_case_insensitively() {
    let server = server_with(&[
        b"From: a@example.com\r\nSubject: Weekly\r\n\r\nYour Verification code is 1234\r\n".to_vec(),
        b"From: a@example.com\r\nSubject: =?utf-8?q?Caf=C3=A9_menu?=\r\n\r\nnothing\r\n".to_vec(),
        b"From: a@example.com\r\nSubject: other\r\nContent-Type: text/html\r\n\r\n<p>Big <b>SALE</b> today</p>\r\n"
            .to_vec(),
        b"From: a@example.com\r\nSubject: plain\r\n\r\nnothing here\r\n".to_vec(),
    ]);
    let search = |query: &str| {
        uids(&list(
            &server,
            &ListMessagesOptions {
                query,
                ..Default::default()
            },
        ))
    };
    assert_eq!(search("verification CODE"), [1]);
    assert_eq!(search("café"), [2]);
    assert_eq!(search("sale"), [3]);
    assert_eq!(search("a@example.com"), [4, 3, 2, 1]);
    assert!(search("absent-term").is_empty());
    // Quotes are blanked exactly like the IMAP search argument.
    assert_eq!(search("\"weekly\""), [1]);
    assert_eq!(search("\""), [4, 3, 2, 1]);
}

#[test]
fn search_failure_reports_search_error() {
    let server = server_with(&numbered(2));
    server.fail_next("RETR", Failure::no());
    let error = pop3::list_messages(
        &account(&server),
        "INBOX",
        &ListMessagesOptions {
            query: "body",
            ..Default::default()
        },
    )
    .unwrap_err();
    assert_eq!(
        operation_message(error),
        "The server could not search this folder"
    );
}

#[test]
fn other_folders_do_not_exist_and_inbox_is_case_insensitive() {
    let server = server_with(&numbered(2));
    let error = pop3::list_messages(&account(&server), "Sent", &ListMessagesOptions::default())
        .unwrap_err();
    assert_eq!(error.status(), 502);
    assert_eq!(
        operation_message(error),
        "The server would not open folder 'Sent'"
    );
    let error = pop3::list_messages(&account(&server), "it's", &ListMessagesOptions::default())
        .unwrap_err();
    assert_eq!(
        operation_message(error),
        "The server would not open folder \"it's\""
    );
    let page =
        pop3::list_messages(&account(&server), "inbox", &ListMessagesOptions::default()).unwrap();
    assert_eq!(page["total"], 2);
}

#[test]
fn list_failure_reports_folder_error() {
    let server = server_with(&numbered(2));
    server.fail_next("LIST", Failure::no());
    let error = pop3::list_messages(&account(&server), "INBOX", &ListMessagesOptions::default())
        .unwrap_err();
    assert_eq!(
        operation_message(error),
        "The server would not open folder 'INBOX'"
    );
}

#[test]
fn summary_read_failure_reports_list_error() {
    let server = server_with(&numbered(2));
    server.fail_next("TOP", Failure::Disconnect);
    let error = pop3::list_messages(&account(&server), "INBOX", &ListMessagesOptions::default())
        .unwrap_err();
    assert_eq!(
        operation_message(error),
        "The server could not list messages in this folder"
    );
}

#[test]
fn servers_without_top_are_read_with_retr() {
    let server = server_with(&numbered(3));
    server.fail_next("TOP", Failure::No("TOP not supported".into()));
    let page = list(&server, &ListMessagesOptions::default());
    assert_eq!(uids(&page), [3, 2, 1]);
    assert_eq!(page["messages"][0]["subject"], "3");
    assert_eq!(page["messages"][2]["subject"], "1");
    // One refused TOP, then RETR for every message.
    assert_eq!(count(&server, "TOP"), 1);
    assert_eq!(count(&server, "RETR"), 3);
}

#[test]
fn uid_validity_is_stable_and_changes_with_the_maildrop() {
    let server = server_with(&numbered(3));
    let epoch = |server: &FakePop3Server| {
        list(server, &ListMessagesOptions::default())["messages"][0]["uid_validity"]
            .as_str()
            .unwrap()
            .to_string()
    };
    let first = epoch(&server);
    assert_eq!(first, epoch(&server));
    server.add_message(b"From: new@example.com\r\nSubject: new\r\n\r\nx\r\n".to_vec());
    let second = epoch(&server);
    assert_ne!(first, second);
    assert_eq!(second, epoch(&server));
}

#[test]
fn uid_validity_falls_back_to_sizes_without_uidl() {
    let server = server_with(&numbered(3));
    let with_uidl =
        list(&server, &ListMessagesOptions::default())["messages"][0]["uid_validity"].clone();
    let without = || {
        server.fail_next("UIDL", Failure::No("UIDL not supported".into()));
        list(&server, &ListMessagesOptions::default())["messages"][0]["uid_validity"].clone()
    };
    let first = without();
    assert_eq!(first, without());
    assert_ne!(first, with_uidl);
    let value: u64 = first.as_str().unwrap().parse().unwrap();
    assert!((1..=4_294_967_295).contains(&value));
}

#[test]
fn uidl_connection_failure_is_not_mistaken_for_missing_support() {
    let server = server_with(&numbered(1));
    server.fail_next("UIDL", Failure::Disconnect);
    let error = pop3::list_messages(&account(&server), "INBOX", &ListMessagesOptions::default())
        .unwrap_err();
    assert_eq!(
        operation_message(error),
        "The server would not open folder 'INBOX'"
    );
}

#[test]
fn empty_maildrop_lists_nothing() {
    let server = server_with(&[]);
    let page = list(&server, &ListMessagesOptions::default());
    assert_eq!(
        page,
        json!({"total": 0, "offset": 0, "limit": 5, "messages": []})
    );
}
