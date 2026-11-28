//! Fake IMAP + SMTP servers for the extension's real-backend e2e test
//! (`tests/e2e/extension-real-backend.mjs`).
//!
//! All servers listen on ephemeral loopback ports without TLS and accept
//! `user@example.com` / `e2e-Secret-Pass-7319` (IMAP, SMTP) and
//! `pop@example.com` / the same password (POP3, SMTP). The first stdout line
//! is `IMAP <port> SMTP <port> POP3 <port>`; afterwards one `SMTP-MAIL ...`
//! line is printed per message the SMTP server has received. Runs until killed.

use std::io::Write;
use std::time::Duration;

use mail_proto::testkit::{FakeImapServer, FakeMessage, FakePop3Server, FakeSmtpServer};

const USER: &str = "user@example.com";
const POP_USER: &str = "pop@example.com";
const PASSWORD: &str = "e2e-Secret-Pass-7319";

const HTML_MESSAGE: &str = "From: Sender <sender@example.org>\r\n\
To: user@example.com\r\n\
Subject: Smoke subject\r\n\
Date: Thu, 26 Nov 2026 10:00:00 +0000\r\n\
Message-ID: <m1@example.org>\r\n\
MIME-Version: 1.0\r\n\
Content-Type: multipart/mixed; boundary=\"b1\"\r\n\
\r\n\
--b1\r\n\
Content-Type: text/html; charset=utf-8\r\n\
\r\n\
<p>Body text</p><a href=\"https://example.com/landing\">Example landing link</a>\r\n\
--b1\r\n\
Content-Type: text/plain; name=\"notes.txt\"\r\n\
Content-Disposition: attachment; filename=\"notes.txt\"\r\n\
\r\n\
notes\r\n\
--b1--\r\n";

const PLAIN_MESSAGE: &str = "From: Other <other@example.net>\r\n\
To: user@example.com\r\n\
Subject: Second\r\n\
Date: Thu, 26 Nov 2026 09:00:00 +0000\r\n\
\r\n\
plain body\r\n";

const POP_MESSAGE: &str = "From: Pop Sender <pop-sender@example.org>\r\n\
To: pop@example.com\r\n\
Subject: POP3 smoke\r\n\
Date: Thu, 26 Nov 2026 08:00:00 +0000\r\n\
Message-ID: <p1@example.org>\r\n\
\r\n\
pop body\r\n";

fn main() {
    let imap = FakeImapServer::builder()
        .credentials(USER, PASSWORD)
        .folder("Sent", &[r"\Sent"])
        .folder("Trash", &[r"\Trash"])
        .message_with("INBOX", FakeMessage::new(HTML_MESSAGE.as_bytes().to_vec()))
        .message("INBOX", PLAIN_MESSAGE.as_bytes().to_vec())
        .start();
    let pop3 = FakePop3Server::builder()
        .credentials(POP_USER, PASSWORD)
        .message(POP_MESSAGE.as_bytes().to_vec())
        .start();
    let smtp = FakeSmtpServer::builder()
        .credentials(USER, PASSWORD)
        .credentials(POP_USER, PASSWORD)
        .start();
    let mut out = std::io::stdout();
    writeln!(
        out,
        "IMAP {} SMTP {} POP3 {}",
        imap.port(),
        smtp.port(),
        pop3.port()
    )
    .ok();
    out.flush().ok();
    let mut reported = 0;
    loop {
        std::thread::sleep(Duration::from_millis(300));
        let messages = smtp.messages();
        for mail in messages.iter().skip(reported) {
            writeln!(
                out,
                "SMTP-MAIL from={} rcpt={:?} bytes={}",
                mail.mail_from,
                mail.rcpt_to,
                mail.data.len()
            )
            .ok();
        }
        reported = messages.len();
        out.flush().ok();
    }
}
