//! `FakeSmtpServer` tests: a raw scripted client for protocol details and
//! `lettre` (the SMTP client the port uses) for compatibility.

use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;

use crate::testkit::{test_connector, Failure, FakeSmtpServer, TlsMode};

struct RawClient {
    reader: BufReader<TcpStream>,
    writer: TcpStream,
}

impl RawClient {
    fn connect(server: &FakeSmtpServer) -> Self {
        let stream = TcpStream::connect((server.host(), server.port())).unwrap();
        stream.set_read_timeout(Some(super::TIMEOUT)).unwrap();
        let mut client = RawClient {
            reader: BufReader::new(stream.try_clone().unwrap()),
            writer: stream,
        };
        assert!(client.reply().starts_with("220"));
        client
    }

    /// Read one (possibly multi-line) reply; returns all lines joined.
    fn reply(&mut self) -> String {
        let mut out = String::new();
        loop {
            let mut line = String::new();
            self.reader.read_line(&mut line).unwrap();
            out.push_str(&line);
            if line.len() < 4 || line.as_bytes()[3] != b'-' {
                return out;
            }
        }
    }

    fn send(&mut self, line: &str) -> String {
        self.writer
            .write_all(format!("{line}\r\n").as_bytes())
            .unwrap();
        self.reply()
    }
}

#[test]
fn raw_session_records_envelope_and_unstuffs_data() {
    let server = FakeSmtpServer::builder()
        .credentials("u@example.com", "pw")
        .start();
    let mut client = RawClient::connect(&server);
    let ehlo = client.send("EHLO client.example");
    assert!(ehlo.contains("250-AUTH PLAIN LOGIN") || ehlo.contains("250 AUTH PLAIN LOGIN"));
    assert!(ehlo.contains("SMTPUTF8"));
    assert!(!ehlo.contains("STARTTLS"));
    assert!(client.send("MAIL FROM:<u@example.com>").starts_with("530"));
    let plain = BASE64.encode("\0u@example.com\0pw");
    assert!(client
        .send(&format!("AUTH PLAIN {plain}"))
        .starts_with("235"));
    assert!(client.send("RCPT TO:<x@example.com>").starts_with("503"));
    assert!(client
        .send("MAIL FROM:<u@example.com> SMTPUTF8 BODY=8BITMIME")
        .starts_with("250"));
    assert!(client.send("RCPT TO:<a@example.com>").starts_with("250"));
    assert!(client.send("RCPT TO:<b@example.com>").starts_with("250"));
    assert!(client.send("DATA").starts_with("354"));
    client
        .writer
        .write_all(b"Subject: hi\r\n\r\n..dot line\r\nplain\r\n.\r\n")
        .unwrap();
    assert!(client.reply().starts_with("250"));
    assert!(client.send("QUIT").starts_with("221"));

    let messages = server.messages();
    assert_eq!(messages.len(), 1);
    let mail = &messages[0];
    assert_eq!(mail.mail_from, "u@example.com");
    assert_eq!(mail.mail_parameters, vec!["SMTPUTF8", "BODY=8BITMIME"]);
    assert_eq!(mail.rcpt_to, vec!["a@example.com", "b@example.com"]);
    assert_eq!(
        mail.data,
        b"Subject: hi\r\n\r\n.dot line\r\nplain\r\n".to_vec()
    );
    assert_eq!(mail.authenticated_user.as_deref(), Some("u@example.com"));
    assert!(server.commands().contains(&"AUTH PLAIN ****".to_string()));
    assert!(server.commands().iter().all(|c| !c.contains(&plain)));
}

#[test]
fn auth_login_failures_and_rejections() {
    let server = FakeSmtpServer::builder()
        .credentials("u", "pw")
        .reject_recipient("blocked@example.com")
        .start();
    let mut client = RawClient::connect(&server);
    client.send("EHLO c");
    assert!(client.send("AUTH LOGIN").starts_with("334 VXNlcm5hbWU6"));
    assert!(client
        .send(&BASE64.encode("u"))
        .starts_with("334 UGFzc3dvcmQ6"));
    assert!(client.send(&BASE64.encode("wrong")).starts_with("535"));
    assert!(client.send("AUTH LOGIN").starts_with("334"));
    client.send(&BASE64.encode("u"));
    assert!(client.send(&BASE64.encode("pw")).starts_with("235"));
    client.send("MAIL FROM:<u@example.com>");
    assert!(client
        .send("RCPT TO:<blocked@example.com>")
        .starts_with("550"));
    assert!(client.send("DATA").starts_with("554"));
    assert!(client.send("RSET").starts_with("250"));
    assert!(client.send("NOOP").starts_with("250"));
    assert!(client.send("VRFY x").starts_with("502"));

    let server = FakeSmtpServer::builder()
        .credentials("u", "pw")
        .fail_auth(true)
        .start();
    let mut client = RawClient::connect(&server);
    client.send("EHLO c");
    let plain = BASE64.encode("\0u\0pw");
    assert!(client
        .send(&format!("AUTH PLAIN {plain}"))
        .starts_with("535"));
}

#[test]
fn failure_injection_on_data() {
    let server = FakeSmtpServer::builder().start();
    server.fail_next("DATA", Failure::Code(451, "4.3.0 Try again later".into()));
    server.fail_next("MAIL", Failure::No("sender refused".into()));
    let mut client = RawClient::connect(&server);
    client.send("HELO c");
    assert!(client
        .send("MAIL FROM:<a@b>")
        .starts_with("550 sender refused"));
    client.send("MAIL FROM:<a@b>");
    client.send("RCPT TO:<c@d>");
    assert!(client.send("DATA").starts_with("354"));
    client.writer.write_all(b"x\r\n.\r\n").unwrap();
    assert!(client.reply().starts_with("451"));
    assert!(server.messages().is_empty());
}

fn lettre_message(to: &str) -> lettre::Message {
    lettre::Message::builder()
        .from("Sender <sender@example.com>".parse().unwrap())
        .to(to.parse().unwrap())
        .subject("Grüße")
        .body(String::from("Hello\r\n.line starting with a dot\r\n"))
        .unwrap()
}

#[test]
fn lettre_plain_with_auth() {
    use lettre::transport::smtp::authentication::Credentials;
    use lettre::Transport;

    let server = FakeSmtpServer::builder()
        .credentials("sender@example.com", "pw")
        .start();
    let mailer = lettre::SmtpTransport::builder_dangerous(server.host())
        .port(server.port())
        .credentials(Credentials::new("sender@example.com".into(), "pw".into()))
        .timeout(Some(super::TIMEOUT))
        .build();
    mailer
        .send(&lettre_message("Rcpt <rcpt@example.com>"))
        .unwrap();
    let messages = server.messages();
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0].mail_from, "sender@example.com");
    assert_eq!(messages[0].rcpt_to, vec!["rcpt@example.com"]);
    let data = String::from_utf8_lossy(&messages[0].data);
    assert!(data.contains("\r\n.line starting with a dot\r\n"), "{data}");
    assert_eq!(
        messages[0].authenticated_user.as_deref(),
        Some("sender@example.com")
    );

    let bad = lettre::SmtpTransport::builder_dangerous(server.host())
        .port(server.port())
        .credentials(Credentials::new("sender@example.com".into(), "nope".into()))
        .timeout(Some(super::TIMEOUT))
        .build();
    assert!(bad.send(&lettre_message("rcpt@example.com")).is_err());
}

#[test]
fn lettre_starttls_and_implicit_tls() {
    use lettre::transport::smtp::authentication::Credentials;
    use lettre::transport::smtp::client::{Certificate, Tls, TlsParameters};
    use lettre::Transport;

    let certificate =
        Certificate::from_pem(include_bytes!("../testkit/fixtures/test-cert.pem")).unwrap();
    let parameters = TlsParameters::builder("localhost".into())
        .add_root_certificate(certificate)
        .dangerous_accept_invalid_certs(true)
        .dangerous_accept_invalid_hostnames(true)
        .build()
        .unwrap();

    let server = FakeSmtpServer::builder()
        .credentials("u", "pw")
        .tls(TlsMode::StartTls)
        .start();
    let mailer = lettre::SmtpTransport::builder_dangerous(server.host())
        .port(server.port())
        .tls(Tls::Required(parameters.clone()))
        .credentials(Credentials::new("u".into(), "pw".into()))
        .timeout(Some(super::TIMEOUT))
        .build();
    mailer.send(&lettre_message("rcpt@example.com")).unwrap();
    assert!(server.messages()[0].tls);
    assert!(server.command_names().contains(&"STARTTLS".to_string()));

    let server = FakeSmtpServer::builder()
        .credentials("u", "pw")
        .tls(TlsMode::Implicit)
        .start();
    let mailer = lettre::SmtpTransport::builder_dangerous(server.host())
        .port(server.port())
        .tls(Tls::Wrapper(parameters))
        .credentials(Credentials::new("u".into(), "pw".into()))
        .timeout(Some(super::TIMEOUT))
        .build();
    mailer.send(&lettre_message("rcpt@example.com")).unwrap();
    assert!(server.messages()[0].tls);
    let _ = test_connector();
}
