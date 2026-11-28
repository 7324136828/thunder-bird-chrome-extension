//! Port of `MailPaginationTests` (tests/test_mail_pagination.py) against
//! the fake IMAP server. The Python fake recorded `conn.uid(...)` calls; here
//! the server's command log provides the same evidence.

mod imap_support;

use imap_support::{account, fetch_items, fetch_sets, lines_named, message, server};
use mail_core::error::MailError;
use mail_core::imap::{self, ListMessagesOptions};
use mail_proto::testkit::{Failure, FakeImapServer};
use serde_json::{json, Value};

fn start(headers: Vec<(u32, Vec<u8>)>, seen: &[u32]) -> FakeImapServer {
    let mut builder = server();
    for (uid, raw) in headers {
        let mut fake = message(uid, raw);
        if seen.contains(&uid) {
            fake = fake.with_flags(&["\\Seen"]);
        }
        builder = builder.message_with("INBOX", fake);
    }
    builder.start()
}

fn list(server: &FakeImapServer, options: ListMessagesOptions<'_>) -> Value {
    let result = imap::list_messages(&account(server), "INBOX", &options).unwrap();
    assert_eq!(server.logout_count(), 1);
    result
}

fn uids(page: &Value) -> Vec<u64> {
    page["messages"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m["uid"].as_u64().unwrap())
        .collect()
}

fn search(server: &FakeImapServer) -> String {
    lines_named(server, "UID SEARCH").remove(0)
}

fn numbered(range: std::ops::RangeInclusive<u32>) -> Vec<(u32, Vec<u8>)> {
    range
        .map(|uid| {
            (
                uid,
                format!("From: user@example.com\r\nSubject: {uid}\r\n\r\n").into_bytes(),
            )
        })
        .collect()
}

fn domain_headers() -> Vec<(u32, Vec<u8>)> {
    [
        (1, "From: First <a@example.com>\r\nSubject: offers\r\n\r\n"),
        (2, "From: <a@ExAmPle.COM>\r\nSubject: offers\r\n\r\n"),
        (3, "From: <a@news.example.com>\r\nSubject: offers\r\n\r\n"),
        (4, "From: <a@notexample.com>\r\nSubject: offers\r\n\r\n"),
        (
            5,
            "From: \"example.com <a@example.com>\" <a@evil.test>\r\nSubject: offers\r\n\r\n",
        ),
        (
            6,
            "From: <a@evil.test>\r\nReply-To: <a@example.com>\r\nSubject: offers\r\n\r\n",
        ),
        (
            7,
            "From: <a@evil.test>\r\nSubject: example.com offers\r\n\r\n",
        ),
        (
            8,
            "From: <a@example.com.evil.test>\r\nSubject: offers\r\n\r\n",
        ),
        (
            9,
            "From: Alice <a@other.test>, Bob <b@example.com>\r\nSubject: hello\r\n\r\n",
        ),
        (10, "From: <a@other.test>\r\nSubject: offers\r\n\r\n"),
    ]
    .into_iter()
    .map(|(uid, raw)| (uid, raw.as_bytes().to_vec()))
    .collect()
}

fn international() -> Vec<(u32, Vec<u8>)> {
    vec![
        (
            1,
            "From: user@b\u{fc}cher.example\r\n\r\n".as_bytes().to_vec(),
        ),
        (2, b"From: user@xn--bcher-kva.example\r\n\r\n".to_vec()),
        (3, b"From: user@other.example\r\n\r\n".to_vec()),
    ]
}

fn owned(values: &[&str]) -> Vec<String> {
    values.iter().map(|v| v.to_string()).collect()
}

#[test]
fn default_page_fetches_only_five_headers_newest_first() {
    let server = start(numbered(1..=11), &[]);
    let page = list(&server, ListMessagesOptions::default());
    assert_eq!(
        (&page["total"], &page["offset"], &page["limit"]),
        (&json!(11), &json!(0), &json!(5))
    );
    assert_eq!(uids(&page), [11, 10, 9, 8, 7]);
    assert_eq!(lines_named(&server, "EXAMINE"), ["EXAMINE \"INBOX\""]);
    assert_eq!(search(&server), "UID SEARCH ALL");
    assert_eq!(fetch_sets(&server), ["11,10,9,8,7"]);
    assert!(fetch_items(&server)[0].contains("BODY.PEEK[HEADER.FIELDS"));
    let first = &page["messages"][0];
    assert_eq!(first["subject"], "11");
    assert_eq!(first["from"], "user@example.com");
    assert_eq!(first["seen"], false);
    assert_eq!(first["internal_date"], "2020-01-01T00:00:00+00:00");
    assert_eq!(first["date"], "2020-01-01T00:00:00+00:00");
    assert_eq!(first["uid_validity"], "1");
    assert!(first["size"].as_u64().unwrap() > 0);
}

#[test]
fn offset_beyond_total_returns_empty_page_without_fetch() {
    let server = start(vec![(7, b"From: a@example.com\r\n\r\n".to_vec())], &[]);
    let page = list(
        &server,
        ListMessagesOptions {
            offset: 5,
            limit: 5,
            ..Default::default()
        },
    );
    assert_eq!(
        page,
        json!({"total": 1, "offset": 5, "limit": 5, "messages": []})
    );
    assert!(fetch_sets(&server).is_empty());
}

#[test]
fn read_status_filters_before_total_and_pagination() {
    for (read_status, criterion, expected) in
        [("unread", "UNSEEN", [9u64, 7]), ("read", "SEEN", [10, 8])]
    {
        let server = start(numbered(1..=12), &[2, 4, 6, 8, 10, 12]);
        let page = list(
            &server,
            ListMessagesOptions {
                read_status,
                offset: 1,
                limit: 2,
                ..Default::default()
            },
        );
        assert_eq!(
            (&page["total"], &page["offset"], &page["limit"]),
            (&json!(6), &json!(1), &json!(2))
        );
        assert_eq!(uids(&page), expected);
        assert!(page["messages"]
            .as_array()
            .unwrap()
            .iter()
            .all(|m| m["seen"] == json!(read_status == "read")));
        assert_eq!(search(&server), format!("UID SEARCH {criterion}"));
        assert_eq!(
            fetch_sets(&server),
            [expected.map(|u| u.to_string()).join(",")]
        );
    }
}

#[test]
fn empty_read_status_result_does_not_fetch_headers() {
    let server = start(vec![(7, b"From: a@example.com\r\n\r\n".to_vec())], &[7]);
    let page = list(
        &server,
        ListMessagesOptions {
            read_status: "unread",
            ..Default::default()
        },
    );
    assert_eq!(
        page,
        json!({"total": 0, "offset": 0, "limit": 5, "messages": []})
    );
    assert!(fetch_sets(&server).is_empty());
}

#[test]
fn sender_domain_filter_checks_addresses_before_total_and_pagination() {
    let server = start(domain_headers(), &[]);
    let domains = owned(&["EXAMPLE.com."]);
    let page = list(
        &server,
        ListMessagesOptions {
            sender_domains: &domains,
            offset: 1,
            limit: 2,
            ..Default::default()
        },
    );
    assert_eq!(page["total"], 4);
    assert_eq!(uids(&page), [3, 2]);
    assert_eq!(search(&server), "UID SEARCH FROM \"example.com\"");
    let items = fetch_items(&server);
    assert_eq!(items[0], "(UID BODY.PEEK[HEADER.FIELDS (FROM)])");
    assert_eq!(fetch_sets(&server)[1], "3,2");
    assert_eq!(items.len(), 2);
}

#[test]
fn multiple_domains_are_or_combined_and_text_query_is_and_combined() {
    let server = start(domain_headers(), &[]);
    let domains = owned(&["example.com", "other.test"]);
    let page = list(
        &server,
        ListMessagesOptions {
            sender_domains: &domains,
            query: "offers",
            limit: 10,
            ..Default::default()
        },
    );
    assert_eq!(page["total"], 4);
    assert_eq!(uids(&page), [10, 3, 2, 1]);
    assert_eq!(
        search(&server),
        "UID SEARCH TEXT \"offers\" OR FROM \"example.com\" FROM \"other.test\""
    );
}

#[test]
fn read_status_composes_with_text_and_multiple_sender_domains() {
    for (read_status, criterion, expected) in
        [("unread", "UNSEEN", [3u64, 1]), ("read", "SEEN", [10, 2])]
    {
        let server = start(domain_headers(), &[2, 4, 8, 9, 10]);
        let domains = owned(&["example.com", "other.test"]);
        let page = list(
            &server,
            ListMessagesOptions {
                sender_domains: &domains,
                query: "offers",
                read_status,
                limit: 10,
                ..Default::default()
            },
        );
        assert_eq!(page["total"], 2);
        assert_eq!(uids(&page), expected);
        assert_eq!(
            search(&server),
            format!(
                "UID SEARCH TEXT \"offers\" {criterion} OR FROM \"example.com\" FROM \"other.test\""
            )
        );
    }
}

#[test]
fn read_status_remains_applied_when_international_domains_skip_server_domain_search() {
    let server = start(international(), &[1]);
    let domains = owned(&["b\u{fc}cher.example"]);
    let page = list(
        &server,
        ListMessagesOptions {
            sender_domains: &domains,
            read_status: "unread",
            ..Default::default()
        },
    );
    assert_eq!(page["total"], 1);
    assert_eq!(uids(&page), [2]);
    assert_eq!(search(&server), "UID SEARCH UNSEEN");
}

#[test]
fn domain_header_fetches_use_bounded_batches_and_summary_fetch_is_page_only() {
    let headers = (1..=451)
        .map(|uid| (uid, b"From: user@example.com\r\n\r\n".to_vec()))
        .collect();
    let server = start(headers, &[]);
    let domains = owned(&["example.com"]);
    let page = list(
        &server,
        ListMessagesOptions {
            sender_domains: &domains,
            offset: 5,
            ..Default::default()
        },
    );
    assert_eq!(page["total"], 451);
    assert_eq!(uids(&page), [446, 445, 444, 443, 442]);
    let sizes: Vec<usize> = fetch_sets(&server)
        .iter()
        .map(|set| set.split(',').count())
        .collect();
    assert_eq!(sizes, [200, 200, 51, 5]);
    assert!(fetch_items(&server)
        .iter()
        .all(|items| items.contains("BODY.PEEK[HEADER.FIELDS")));
}

#[test]
fn no_domain_matches_avoids_summary_fetch() {
    let server = start(
        vec![(
            1,
            b"From: \"example.com\" <user@evil.test>\r\n\r\n".to_vec(),
        )],
        &[],
    );
    let domains = owned(&["example.com"]);
    let page = list(
        &server,
        ListMessagesOptions {
            sender_domains: &domains,
            ..Default::default()
        },
    );
    assert_eq!(page["total"], 0);
    assert_eq!(page["messages"], json!([]));
    assert_eq!(fetch_sets(&server).len(), 1);
}

#[test]
fn international_domain_matches_unicode_and_punycode_addresses() {
    let server = start(international(), &[]);
    let domains = owned(&["b\u{fc}cher.example"]);
    let page = list(
        &server,
        ListMessagesOptions {
            sender_domains: &domains,
            ..Default::default()
        },
    );
    assert_eq!(page["total"], 2);
    assert_eq!(uids(&page), [2, 1]);
    assert_eq!(search(&server), "UID SEARCH ALL");
}

#[test]
fn punycode_input_also_skips_server_domain_search() {
    let server = start(international(), &[]);
    let domains = owned(&["xn--bcher-kva.example"]);
    let page = list(
        &server,
        ListMessagesOptions {
            sender_domains: &domains,
            ..Default::default()
        },
    );
    assert_eq!(uids(&page), [2, 1]);
    assert_eq!(search(&server), "UID SEARCH ALL");
}

#[test]
fn domain_fetch_failure_reports_error_and_logs_out() {
    let server = start(vec![(1, b"From: a@example.com\r\n\r\n".to_vec())], &[]);
    server.fail_next("UID FETCH", Failure::no());
    let domains = owned(&["example.com"]);
    let error = imap::list_messages(
        &account(&server),
        "INBOX",
        &ListMessagesOptions {
            sender_domains: &domains,
            ..Default::default()
        },
    )
    .unwrap_err();
    assert!(matches!(error, MailError::Operation(ref m)
        if m == "The server could not filter messages by sender domain"));
    assert_eq!(server.logout_count(), 1);
}

#[test]
fn summary_fetch_and_search_failures_report_errors() {
    let server = start(numbered(1..=3), &[]);
    server.fail_next("UID FETCH", Failure::no());
    let error = imap::list_messages(&account(&server), "INBOX", &ListMessagesOptions::default())
        .unwrap_err();
    assert_eq!(
        error.to_string(),
        "The server could not list messages in this folder"
    );
    server.fail_next("UID SEARCH", Failure::no());
    let error = imap::list_messages(&account(&server), "INBOX", &ListMessagesOptions::default())
        .unwrap_err();
    assert_eq!(error.to_string(), "The server could not search this folder");
    assert_eq!(server.logout_count(), 2);
}

#[test]
fn unicode_mapped_to_plain_ascii_keeps_original_header_candidates() {
    for query in ["", "offers"] {
        let server = start(
            vec![
                (
                    1,
                    "From: user@fa\u{df}.de\r\nSubject: offers\r\n\r\n"
                        .as_bytes()
                        .to_vec(),
                ),
                (2, b"From: user@fass.de\r\nSubject: offers\r\n\r\n".to_vec()),
                (3, b"From: user@other.de\r\nSubject: hello\r\n\r\n".to_vec()),
            ],
            &[],
        );
        let domains = owned(&["fa\u{df}.de"]);
        let page = list(
            &server,
            ListMessagesOptions {
                sender_domains: &domains,
                query,
                ..Default::default()
            },
        );
        assert_eq!(page["total"], 2, "query={query:?}");
        assert_eq!(uids(&page), [2, 1]);
        let expected = if query.is_empty() {
            "UID SEARCH ALL"
        } else {
            "UID SEARCH TEXT \"offers\""
        };
        assert_eq!(search(&server), expected);
    }
}

#[test]
fn has_unicode_input_flag_preserves_candidates_for_normalized_domains() {
    // The API passes normalized domains plus has_unicode_input=True.
    let server = start(
        vec![
            (1, "From: user@fa\u{df}.de\r\n\r\n".as_bytes().to_vec()),
            (2, b"From: user@fass.de\r\n\r\n".to_vec()),
        ],
        &[],
    );
    let domains = owned(&["fass.de"]);
    let page = list(
        &server,
        ListMessagesOptions {
            sender_domains: &domains,
            has_unicode_input: true,
            ..Default::default()
        },
    );
    assert_eq!(uids(&page), [2, 1]);
    assert_eq!(search(&server), "UID SEARCH ALL");
}

#[test]
fn query_quotes_and_backslashes_are_neutralized() {
    let server = start(numbered(1..=2), &[]);
    list(
        &server,
        ListMessagesOptions {
            query: "  a\"b\\c  ",
            ..Default::default()
        },
    );
    assert_eq!(search(&server), "UID SEARCH TEXT \"a b\\\\c\"");
}

#[test]
fn invalid_domains_are_rejected_before_connecting() {
    let server = start(numbered(1..=2), &[]);
    let many = vec!["a.example".to_string(); 201];
    let cases: Vec<Vec<String>> = vec![
        owned(&[""]),
        owned(&["user@example.com"]),
        owned(&["example.com\" ALL"]),
        owned(&["https://example.com"]),
        owned(&["a..com"]),
        many,
    ];
    for domains in &cases {
        let error = imap::list_messages(
            &account(&server),
            "INBOX",
            &ListMessagesOptions {
                sender_domains: domains,
                ..Default::default()
            },
        )
        .unwrap_err();
        assert_eq!(error.status(), 422, "{domains:?}");
    }
    assert_eq!(server.connection_count(), 0);
}

#[test]
fn invalid_read_status_or_category_is_rejected_before_connecting() {
    let server = start(numbered(1..=2), &[]);
    for read_status in ["", "READ", "unread ALL", "seen"] {
        let error = imap::list_messages(
            &account(&server),
            "INBOX",
            &ListMessagesOptions {
                read_status,
                ..Default::default()
            },
        )
        .unwrap_err();
        assert_eq!(error.status(), 422);
        assert_eq!(
            error.to_string(),
            "Read status must be all, unread, or read"
        );
    }
    let error = imap::list_messages(
        &account(&server),
        "INBOX",
        &ListMessagesOptions {
            category: Some("spam"),
            ..Default::default()
        },
    )
    .unwrap_err();
    assert_eq!(error.status(), 422);
    assert_eq!(error.to_string(), "Choose a valid email category");
    assert_eq!(server.connection_count(), 0);
}

#[test]
fn missing_folder_is_reported_with_python_repr() {
    let server = start(numbered(1..=2), &[]);
    let error = imap::list_messages(&account(&server), "Nope's", &ListMessagesOptions::default())
        .unwrap_err();
    assert_eq!(
        error.to_string(),
        "The server would not open folder \"Nope's\""
    );
    assert_eq!(error.status(), 502);
    assert_eq!(server.logout_count(), 1);
}
