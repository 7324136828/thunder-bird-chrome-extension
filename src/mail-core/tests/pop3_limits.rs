//! Resource caps on data a (possibly hostile) POP3 server sends back.

use mail_core::pop3::{self, MAX_RESPONSE_BYTES};
use mail_core::sessions::{MailAccount, PROTOCOL_POP3};
use mail_proto::testkit::FakePop3Server;

const EMAIL: &str = "user@example.com";
const PASSWORD: &str = "pop-secret-123";

fn account(server: &FakePop3Server) -> MailAccount {
    let mut account = MailAccount::new(
        EMAIL,
        PASSWORD,
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

#[test]
fn response_cap_is_100_mib_and_covers_the_largest_handled_message() {
    assert_eq!(MAX_RESPONSE_BYTES, 100 * 1024 * 1024);
    assert!(MAX_RESPONSE_BYTES as u64 >= mail_core::trash::MAX_MESSAGE_BYTES);
    const { assert!(MAX_RESPONSE_BYTES < mail_proto::pop3::DEFAULT_MAX_RESPONSE) };
}

#[test]
fn a_retr_reply_over_the_cap_is_refused() {
    // 1000-byte lines until the message is just over the cap.
    let line = format!(
        "{}
",
        "a".repeat(998)
    );
    let mut raw = b"Subject: huge

"
    .to_vec();
    while raw.len() <= MAX_RESPONSE_BYTES {
        raw.extend_from_slice(line.as_bytes());
    }
    let server = FakePop3Server::builder()
        .credentials(EMAIL, PASSWORD)
        .message(
            b"Subject: small

ok
"
            .to_vec(),
        )
        .message(raw)
        .start();
    let account = account(&server);

    // A normal message is unaffected.
    let small = pop3::fetch_raw(&account, "INBOX", 1).unwrap();
    assert!(small.starts_with(b"Subject: small"));
    let before = server.command_names().len();

    // The oversized reply aborts the connection mid-RETR: the session is
    // closed by the cap, so not even QUIT can be sent afterwards.
    let error = pop3::fetch_raw(&account, "INBOX", 2).unwrap_err();
    assert_eq!(
        error.to_string(),
        "The server could not fetch message UID 2"
    );
    assert_eq!(
        server.command_names()[before..],
        ["USER", "PASS", "LIST", "UIDL", "RETR"]
    );
}
