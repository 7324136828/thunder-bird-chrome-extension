//! Resource caps on data a (possibly hostile) IMAP server sends back.

mod imap_support;

use imap_support::{account, message, server};
use mail_core::imap::{self, MAX_LITERAL_BYTES};
use mail_proto::imap::Status;
use mail_proto::testkit::HookAction;

#[test]
fn literal_cap_is_100_mib_and_covers_the_largest_handled_message() {
    assert_eq!(MAX_LITERAL_BYTES, 100 * 1024 * 1024);
    assert!(MAX_LITERAL_BYTES as u64 >= mail_core::trash::MAX_MESSAGE_BYTES);
    const { assert!(MAX_LITERAL_BYTES < mail_proto::imap::DEFAULT_MAX_LITERAL) };
}

#[test]
fn an_oversized_literal_is_refused_before_it_is_read() {
    // The server announces a literal one byte over the cap and then sends
    // nothing of it: the client must refuse at the announcement instead of
    // trying to buffer it (with mail_proto's 256 MiB default it would wait
    // for the bytes until the read timeout).
    let announced = MAX_LITERAL_BYTES + 1;
    let server = server()
        .uid_validity("INBOX", Some(7))
        .message_with("INBOX", message(5, "Subject: x\r\n\r\nbody\r\n"))
        .hook(move |request| {
            if request.command == "UID FETCH" {
                HookAction::Respond {
                    untagged: vec![format!("* 1 FETCH (UID 5 BODY[] {{{announced}}}").into_bytes()],
                    status: Status::Ok,
                    text: "FETCH completed".into(),
                }
            } else {
                HookAction::Continue
            }
        })
        .start();
    let started = std::time::Instant::now();
    let error = imap::fetch_raw(&account(&server), "INBOX", 5).unwrap_err();
    let text = error.to_string();
    assert!(
        text.contains(&format!(
            "{announced}-byte literal (limit {MAX_LITERAL_BYTES})"
        )),
        "{text}"
    );
    assert!(started.elapsed() < std::time::Duration::from_secs(10));
}
