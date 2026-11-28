//! Port of `SentCopyTests` (tests/test_imap_sent_copy.py) and the public
//! folder listing test against the fake IMAP server.

mod imap_support;

use imap_support::{account, account_at, commands_after_login, lines_named, pop3_account, server};
use mail_core::error::MailError;
use mail_core::imap;
use mail_proto::imap::Status;
use mail_proto::testkit::{Failure, FakeImapBuilder, FakeImapServer, FakeMessage, HookAction};
use serde_json::json;

const RAW: &[u8] =
    b"From: user@example.com\r\nTo: recipient@example.com\r\nMessage-ID: <sent@example.com>\r\n\r\nBody\r\n";
const MESSAGE_ID: &str = "<sent@example.com>";

fn utf8_raw() -> Vec<u8> {
    String::from_utf8(RAW.to_vec())
        .unwrap()
        .replace("recipient@example.com", "recipient@b\u{fc}cher.example")
        .into_bytes()
}

/// A server with only the given folders besides INBOX and the given
/// capabilities; capabilities only reach the client via CAPABILITY.
fn sent_server(capabilities: &[&str], folders: &[(&str, &[&str])]) -> FakeImapBuilder {
    let mut builder = server()
        .capabilities(capabilities)
        // Only the CAPABILITY command save_sent_copy sends is logged.
        .greeting_capabilities(true)
        .login_capability_code(true);
    for (name, attributes) in folders {
        builder = builder.folder(name, attributes);
    }
    builder
}

fn save(server: &FakeImapServer, raw: &[u8], message_id: &str) -> mail_core::Result<String> {
    let result = imap::save_sent_copy(&account(server), raw, message_id);
    assert_eq!(server.connection_count(), 1);
    result
}

fn sent_folder_of(error: MailError) -> Option<String> {
    match error {
        MailError::SentCopy { folder, message } => {
            assert_eq!(message, imap::SENT_COPY_MESSAGE);
            folder
        }
        other => panic!("expected SentCopyError, got {other:?}"),
    }
}

/// Command names after LOGIN (CAPABILITY included, LOGOUT excluded).
fn names(server: &FakeImapServer) -> Vec<String> {
    commands_after_login(server)
        .iter()
        .map(|line| {
            let mut words = line.split(' ');
            let first = words.next().unwrap_or_default();
            if first == "UID" {
                format!("UID {}", words.next().unwrap_or_default())
            } else {
                first.to_string()
            }
        })
        .collect()
}

fn appended(server: &FakeImapServer, folder: &str) -> Vec<FakeMessage> {
    server
        .folder(folder)
        .map(|f| f.messages)
        .unwrap_or_default()
}

#[test]
fn appends_full_message_seen_after_searching_message_id() {
    let server = sent_server(&["IMAP4rev1"], &[("Sent", &[])]).start();
    assert_eq!(save(&server, RAW, MESSAGE_ID).unwrap(), "Sent");
    assert_eq!(
        commands_after_login(&server),
        [
            "CAPABILITY".to_string(),
            "LIST \"\" *".into(),
            "EXAMINE \"Sent\"".into(),
            "UID SEARCH HEADER Message-ID \"<sent@example.com>\"".into(),
            format!("APPEND \"Sent\" (\\Seen) {{{}}}", RAW.len()),
        ]
    );
    let saved = appended(&server, "Sent");
    assert_eq!(saved.len(), 1);
    assert_eq!(saved[0].raw, RAW);
    assert_eq!(saved[0].flags, ["\\Seen"]);
    assert_eq!(server.logout_count(), 1);
}

#[test]
fn prefers_server_sent_attribute_over_folder_name() {
    let server = sent_server(
        &["IMAP4rev1", "SPECIAL-USE"],
        &[("Sent", &[]), ("[Gmail]/Sent Mail", &["\\Sent"])],
    )
    .special_use_in_plain_list(false)
    .start();
    assert_eq!(save(&server, RAW, MESSAGE_ID).unwrap(), "[Gmail]/Sent Mail");
    assert_eq!(
        commands_after_login(&server)[1],
        "LIST \"\" \"*\" RETURN (SPECIAL-USE)"
    );
    assert!(lines_named(&server, "APPEND")[0].starts_with("APPEND \"[Gmail]/Sent Mail\""));
    assert!(lines_named(&server, "CREATE").is_empty());
    assert_eq!(appended(&server, "[Gmail]/Sent Mail").len(), 1);
}

#[test]
fn rev2_requests_special_use_and_rejected_extension_falls_back_to_list() {
    for capabilities in [&["IMAP4rev1", "SPECIAL-USE"][..], &["IMAP4rev2"][..]] {
        for failure in [Failure::Bad("unsupported option".into()), Failure::no()] {
            let server = sent_server(capabilities, &[("Sent", &[])]).start();
            server.fail_next("LIST", failure);
            assert_eq!(save(&server, RAW, MESSAGE_ID).unwrap(), "Sent");
            assert_eq!(names(&server)[..3], ["CAPABILITY", "LIST", "LIST"]);
            assert_eq!(commands_after_login(&server)[2], "LIST \"\" *");
        }
    }
}

#[test]
fn rev2_accepts_utf8_headers_without_enable() {
    let server = sent_server(&["IMAP4rev2"], &[("Sent", &[])]).start();
    let raw = utf8_raw();
    assert_eq!(save(&server, &raw, MESSAGE_ID).unwrap(), "Sent");
    assert!(!names(&server).contains(&"ENABLE".to_string()));
    assert_eq!(names(&server).last().unwrap(), "APPEND");
    assert_eq!(appended(&server, "Sent")[0].raw, raw);
}

#[test]
fn rev1_enables_utf8_before_listing_and_saving_international_headers() {
    // Fake-server limitation: its APPEND UTF8 (~{n}) form requires
    // UTF8=ACCEPT to have been enabled, so the UTF8=ONLY case also
    // advertises UTF8=ACCEPT (RFC 6855 servers with UTF8=ONLY accept it).
    for capabilities in [
        &["IMAP4rev1", "ENABLE", "UTF8=ACCEPT"][..],
        &["IMAP4rev1", "ENABLE", "UTF8=ONLY", "UTF8=ACCEPT"][..],
    ] {
        let server = sent_server(capabilities, &[("Sent", &[])]).start();
        let raw = utf8_raw();
        assert_eq!(save(&server, &raw, MESSAGE_ID).unwrap(), "Sent");
        assert_eq!(
            commands_after_login(&server)[..3],
            ["CAPABILITY", "ENABLE UTF8=ACCEPT", "LIST \"\" *"]
        );
        let append = lines_named(&server, "APPEND").remove(0);
        assert!(append.contains("UTF8 ("), "{append}");
        assert_eq!(appended(&server, "Sent")[0].raw, raw);
    }
}

#[test]
fn utf8_only_server_is_enabled_even_for_ascii_messages() {
    let server = sent_server(
        &["IMAP4rev1", "ENABLE", "UTF8=ONLY", "UTF8=ACCEPT"],
        &[("Sent", &[])],
    )
    .start();
    assert_eq!(save(&server, RAW, MESSAGE_ID).unwrap(), "Sent");
    assert_eq!(commands_after_login(&server)[1], "ENABLE UTF8=ACCEPT");
}

#[test]
fn unsupported_or_rejected_utf8_never_appends_international_headers() {
    let cases: [(&[&str], Option<Failure>); 4] = [
        (&["IMAP4rev1"], None),
        (&["IMAP4rev1", "UTF8=ACCEPT"], None),
        (&["IMAP4rev1", "ENABLE", "UTF8=ACCEPT"], Some(Failure::no())),
        (
            &["IMAP4rev1", "ENABLE", "UTF8=ACCEPT"],
            Some(Failure::Bad("private server response".into())),
        ),
    ];
    for (capabilities, failure) in cases {
        let server = sent_server(capabilities, &[("Sent", &[])]).start();
        if let Some(failure) = failure {
            server.fail_next("ENABLE", failure);
        }
        let error = save(&server, &utf8_raw(), MESSAGE_ID).unwrap_err();
        assert!(!error.to_string().contains("private"));
        assert_eq!(sent_folder_of(error), None);
        assert!(!names(&server)
            .iter()
            .any(|name| name == "LIST" || name == "APPEND"));
        assert_eq!(server.logout_count(), 1);
    }
}

#[test]
fn eightbit_body_with_ascii_headers_does_not_require_utf8_header_support() {
    let server = sent_server(&["IMAP4rev1"], &[("Sent", &[])]).start();
    let raw = String::from_utf8(RAW.to_vec())
        .unwrap()
        .replace("Body", "Body caf\u{e9}")
        .into_bytes();
    assert_eq!(save(&server, &raw, MESSAGE_ID).unwrap(), "Sent");
    assert!(!names(&server).contains(&"ENABLE".to_string()));
    assert_eq!(appended(&server, "Sent")[0].raw, raw);
}

#[test]
fn rev2_international_folder_and_message_id_use_utf8_arguments() {
    let (folder, message_id) = ("Envoy\u{e9}s", "<sent@b\u{fc}cher.example>");
    let server = sent_server(&["IMAP4rev2"], &[(folder, &["\\Sent"])]).start();
    let raw = String::from_utf8(utf8_raw())
        .unwrap()
        .replace("<sent@example.com>", message_id)
        .into_bytes();
    assert_eq!(save(&server, &raw, message_id).unwrap(), folder);
    let commands = commands_after_login(&server);
    assert_eq!(
        commands[commands.len() - 2],
        format!("UID SEARCH HEADER Message-ID \"{message_id}\"")
    );
    assert!(commands[commands.len() - 1].starts_with(&format!("APPEND \"{folder}\" (\\Seen)")));
    assert_eq!(appended(&server, folder)[0].raw, raw);
}

#[test]
fn existing_common_names_and_inbox_hierarchies_are_reused() {
    for (name, delimiter) in [
        ("Sent", "/"),
        ("Sent Items", "/"),
        ("Sent Mail", "/"),
        ("Sent Messages", "/"),
        ("INBOX.Sent", "."),
        ("INBOX/Sent Items", "/"),
        ("[Gmail]/Sent Mail", "/"),
    ] {
        let server = sent_server(&["IMAP4rev1"], &[(name, &[])])
            .delimiter(Some(delimiter))
            .start();
        assert_eq!(save(&server, RAW, MESSAGE_ID).unwrap(), name);
        assert!(lines_named(&server, "CREATE").is_empty(), "{name}");
    }
}

#[test]
fn existing_root_folder_is_preferred_to_hierarchy_fallback() {
    let server = sent_server(&["IMAP4rev1"], &[("INBOX/Sent", &[]), ("Sent Items", &[])]).start();
    assert_eq!(save(&server, RAW, MESSAGE_ID).unwrap(), "Sent Items");
}

#[test]
fn creates_sent_when_no_existing_sent_folder_exists() {
    let server = sent_server(&["IMAP4rev1"], &[]).start();
    assert_eq!(save(&server, RAW, MESSAGE_ID).unwrap(), "Sent");
    assert_eq!(commands_after_login(&server)[2], "CREATE \"Sent\"");
    assert_eq!(names(&server).last().unwrap(), "APPEND");
    assert_eq!(appended(&server, "Sent").len(), 1);
}

#[test]
fn creates_sent_inside_an_existing_inbox_namespace() {
    let server = sent_server(&["IMAP4rev1"], &[("INBOX.Drafts", &[])])
        .delimiter(Some("."))
        .start();
    assert_eq!(save(&server, RAW, MESSAGE_ID).unwrap(), "INBOX.Sent");
    assert_eq!(commands_after_login(&server)[2], "CREATE \"INBOX.Sent\"");
    assert_eq!(appended(&server, "INBOX.Sent").len(), 1);
}

#[test]
fn noselect_sent_folder_is_never_used_for_append() {
    let server = sent_server(&["IMAP4rev1"], &[("Sent Items", &["\\Sent", "\\Noselect"])]).start();
    assert_eq!(save(&server, RAW, MESSAGE_ID).unwrap(), "Sent");
    assert_eq!(commands_after_login(&server)[2], "CREATE \"Sent\"");
}

#[test]
fn concurrently_created_sent_folder_is_found_after_create_fails() {
    let server = sent_server(&["IMAP4rev1"], &[]).start();
    server.fail_next("CREATE", Failure::no());
    // Another client creates Sent between our LIST and CREATE.
    server.add_folder("Sent Items", &[]);
    assert_eq!(save(&server, RAW, MESSAGE_ID).unwrap(), "Sent Items");
}

#[test]
fn provider_saved_message_is_not_appended_twice() {
    let server = sent_server(&["IMAP4rev1"], &[("Sent", &[])])
        .message("Sent", RAW.to_vec())
        .start();
    assert_eq!(save(&server, RAW, MESSAGE_ID).unwrap(), "Sent");
    assert_eq!(names(&server).last().unwrap(), "UID SEARCH");
    assert!(lines_named(&server, "APPEND").is_empty());
    assert_eq!(appended(&server, "Sent").len(), 1);
}

#[test]
fn folder_and_search_failures_prevent_append_and_preserve_discovered_folder() {
    for command in ["EXAMINE", "UID SEARCH"] {
        let server = sent_server(&["IMAP4rev1"], &[("Sent", &[])]).start();
        server.fail_next(command, Failure::no());
        let error = save(&server, RAW, MESSAGE_ID).unwrap_err();
        assert_eq!(sent_folder_of(error), Some("Sent".into()));
        assert!(lines_named(&server, "APPEND").is_empty());
        assert_eq!(server.logout_count(), 1);
    }
}

#[test]
fn append_rejections_and_disconnects_are_not_retried() {
    for failure in [
        Failure::no(),
        Failure::Disconnect,
        Failure::Bad("private credentials".into()),
    ] {
        let disconnect = failure == Failure::Disconnect;
        let server = sent_server(&["IMAP4rev1"], &[("Sent", &[])]).start();
        server.fail_next("APPEND", failure);
        let error = save(&server, RAW, MESSAGE_ID).unwrap_err();
        assert!(!error.to_string().contains("private"));
        assert_eq!(sent_folder_of(error), Some("Sent".into()));
        assert_eq!(lines_named(&server, "APPEND").len(), 1);
        assert!(appended(&server, "Sent").is_empty());
        if !disconnect {
            assert_eq!(server.logout_count(), 1);
        }
    }
}

#[test]
fn creation_or_discovery_failure_reports_unknown_folder() {
    for command in ["LIST", "CREATE"] {
        let server = sent_server(&["IMAP4rev1"], &[]).start();
        server.fail_next(command, Failure::no());
        let error = save(&server, RAW, MESSAGE_ID).unwrap_err();
        assert_eq!(sent_folder_of(error), None);
        assert!(lines_named(&server, "APPEND").is_empty());
        assert_eq!(server.logout_count(), 1);
    }
}

#[test]
fn connection_failure_reports_unknown_folder_without_private_details() {
    let server = sent_server(&["IMAP4rev1"], &[("Sent", &[])]).start();
    let mut wrong = account(&server);
    wrong.password = "private password".into();
    let error = imap::save_sent_copy(&wrong, RAW, MESSAGE_ID).unwrap_err();
    assert!(!error.to_string().contains("private"));
    assert_eq!(sent_folder_of(error), None);

    // Nothing listens on port 1.
    let error = imap::save_sent_copy(&account_at(1), RAW, MESSAGE_ID).unwrap_err();
    assert_eq!(sent_folder_of(error), None);
}

#[test]
fn pop3_accounts_never_connect_for_a_sent_copy() {
    let error = imap::save_sent_copy(&pop3_account(), RAW, MESSAGE_ID).unwrap_err();
    assert_eq!(error.status(), 502);
    assert_eq!(sent_folder_of(error), None);
}

#[test]
fn flat_and_escaped_and_literal_names_remain_valid_imap_arguments() {
    let flat = sent_server(&["IMAP4rev1"], &[("Sent Items", &["\\Sent"])])
        .delimiter(None)
        .start();
    let escaped = sent_server(&["IMAP4rev1"], &[("Sent \"Box\\", &["\\Sent"])]).start();
    let literal = sent_server(&["IMAP4rev1"], &[("Sent Mail", &["\\Sent"])])
        .literal_names(true)
        .start();
    for (server, name, argument) in [
        (&flat, "Sent Items", "\"Sent Items\""),
        (&escaped, "Sent \"Box\\", "\"Sent \\\"Box\\\\\""),
        (&literal, "Sent Mail", "\"Sent Mail\""),
    ] {
        assert_eq!(save(server, RAW, MESSAGE_ID).unwrap(), name);
        let append = lines_named(server, "APPEND").remove(0);
        assert!(
            append.starts_with(&format!("APPEND {argument} ")),
            "{append}"
        );
        assert_eq!(appended(server, name).len(), 1);
    }
}

#[test]
fn public_folder_listing_uses_same_parser_and_preserves_flags() {
    let server = server()
        .hook(|request| {
            if request.command != "LIST" {
                return HookAction::Continue;
            }
            HookAction::Respond {
                untagged: vec![
                    b"* LIST (\\Noselect) \"/\" \"Parent\"".to_vec(),
                    b"* LIST (\\Sent) NIL \"Sent Items\"".to_vec(),
                    b"* LIST () \"/\" \"INBOX\"".to_vec(),
                    b"* LIST (\\NonExistent) \"/\" \"Ghost\"".to_vec(),
                    b"* LIST malformed".to_vec(),
                ],
                status: Status::Ok,
                text: "LIST completed".into(),
            }
        })
        .start();
    let folders = imap::list_folders(&account(&server)).unwrap();
    let names: Vec<&str> = folders
        .iter()
        .map(|f| f["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["INBOX", "Ghost", "Parent", "Sent Items"]);
    assert_eq!(folders[0]["special"], "inbox");
    assert_eq!(folders[1]["selectable"], false);
    assert_eq!(folders[2]["selectable"], false);
    assert_eq!(
        folders[3],
        json!({
            "name": "Sent Items", "delimiter": "", "flags": ["\\Sent"],
            "special": "sent", "selectable": true,
        })
    );
    assert_eq!(lines_named(&server, "LIST"), ["LIST \"\" *"]);
    assert_eq!(server.logout_count(), 1);
}

#[test]
fn folder_listing_from_the_fake_mailbox_model() {
    let server = server()
        .folder("Trash", &["\\Trash"])
        .folder("archive", &["\\Archive", "\\HasNoChildren"])
        .start();
    let folders = imap::list_folders(&account(&server)).unwrap();
    assert_eq!(
        folders,
        vec![
            json!({"name": "INBOX", "delimiter": "/", "flags": [], "special": "inbox", "selectable": true}),
            json!({"name": "archive", "delimiter": "/", "flags": ["\\Archive", "\\HasNoChildren"], "special": "archive", "selectable": true}),
            json!({"name": "Trash", "delimiter": "/", "flags": ["\\Trash"], "special": "trash", "selectable": true}),
        ]
    );
}

#[test]
fn folder_listing_failure_is_an_operation_error() {
    let server = server().start();
    server.fail_next("LIST", Failure::no());
    let error = imap::list_folders(&account(&server)).unwrap_err();
    assert!(
        matches!(error, MailError::Operation(ref m) if m == "The server did not return a folder list")
    );
    assert_eq!(server.logout_count(), 1);
}
