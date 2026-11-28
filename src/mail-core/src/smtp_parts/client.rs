//! A blocking SMTP client with the semantics of Python's `smtplib.SMTP` /
//! `smtplib.SMTP_SSL` as used by `smtp_client.py`: greeting check, `ehlo`
//! with `esmtp_features` parsing, `ehlo_or_helo_if_needed`, `starttls`,
//! `login` (PLAIN, LOGIN), `sendmail` (`size=`, `SMTPUTF8`, per-recipient
//! refusal dictionary, `RSET` after failures), `data` dot-stuffing and
//! `quit`.
//!
//! Every failure is a [`ClientError`] (Python's `OSError` / `SMTPException`
//! family); the caller maps it to the phase-specific `MailSendError`
//! message, so server responses never reach the user. Credentials are
//! never logged or included in an error.

use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{IpAddr, Shutdown, TcpStream};
use std::time::Duration;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use native_tls::{TlsConnector, TlsStream};

/// `smtplib._MAXLINE`.
const MAX_LINE: usize = 8192;
/// `smtplib._MAXCHALLENGE`.
const MAX_CHALLENGE: usize = 5;
/// Error text of `SMTPAuthenticationError` (a rejected mechanism).
const AUTH_REJECTED: &str = "SMTPAuthenticationError";
/// `login`'s `preferred_auths` (CRAM-MD5 is not offered; see `smtp.rs`).
const PREFERRED_AUTHS: [&str; 2] = ["PLAIN", "LOGIN"];

/// Any `OSError` / `SMTPException`. The text is for debugging only and never
/// contains credentials; it is not shown to users.
#[derive(Debug)]
pub struct ClientError(pub String);

impl From<io::Error> for ClientError {
    fn from(error: io::Error) -> Self {
        ClientError(format!("socket error: {}", error.kind()))
    }
}

type R<T> = Result<T, ClientError>;

fn fail<T>(message: &str) -> R<T> {
    Err(ClientError(message.to_string()))
}

enum Stream {
    Plain(TcpStream),
    Tls(Box<TlsStream<TcpStream>>),
    Closed,
}

impl Read for Stream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Stream::Plain(stream) => stream.read(buf),
            Stream::Tls(stream) => stream.read(buf),
            Stream::Closed => Err(io::Error::new(io::ErrorKind::NotConnected, "closed")),
        }
    }
}

impl Write for Stream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Stream::Plain(stream) => stream.write(buf),
            Stream::Tls(stream) => stream.write(buf),
            Stream::Closed => Err(io::Error::new(io::ErrorKind::NotConnected, "closed")),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Stream::Plain(stream) => stream.flush(),
            Stream::Tls(stream) => stream.flush(),
            Stream::Closed => Err(io::Error::new(io::ErrorKind::NotConnected, "closed")),
        }
    }
}

/// One SMTP session.
pub struct SmtpClient {
    reader: BufReader<Stream>,
    host: String,
    local_hostname: String,
    helo_resp: Option<Vec<u8>>,
    ehlo_resp: Option<Vec<u8>>,
    does_esmtp: bool,
    /// `esmtp_features` (lowercased names, insertion order).
    features: Vec<(String, String)>,
    /// `command_encoding == 'utf-8'` (after `MAIL ... SMTPUTF8`).
    utf8_commands: bool,
}

fn tls_error(error: impl std::fmt::Display) -> ClientError {
    ClientError(format!("TLS error: {error}"))
}

/// `socket.create_connection((host, port), timeout)`.
fn create_connection(host: &str, port: u16, timeout: Duration) -> R<TcpStream> {
    let mut last = None;
    for address in mail_proto::resolve::resolve(host, port)? {
        match TcpStream::connect_timeout(&address, timeout) {
            Ok(stream) => {
                stream.set_read_timeout(Some(timeout))?;
                stream.set_write_timeout(Some(timeout))?;
                return Ok(stream);
            }
            Err(error) => last = Some(error),
        }
    }
    Err(last.map_or_else(
        || ClientError("getaddrinfo returned no addresses".into()),
        ClientError::from,
    ))
}

/// The EHLO name: an address literal of the local socket (smtplib's
/// fallback when the FQDN has no dot), so no host name is disclosed.
fn local_literal(stream: &TcpStream) -> String {
    match stream.local_addr().map(|address| address.ip()) {
        Ok(IpAddr::V4(ip)) => format!("[{ip}]"),
        Ok(IpAddr::V6(ip)) => format!("[IPv6:{ip}]"),
        Err(_) => "[127.0.0.1]".to_string(),
    }
}

impl SmtpClient {
    /// `SMTP(host, port, timeout)` (`implicit_tls: None`) or
    /// `SMTP_SSL(host, port, timeout, context)`: connect and require a 220
    /// greeting.
    pub fn connect(
        host: &str,
        port: u16,
        timeout: Duration,
        implicit_tls: Option<&TlsConnector>,
    ) -> R<Self> {
        let tcp = create_connection(host, port, timeout)?;
        let local_hostname = local_literal(&tcp);
        let stream = match implicit_tls {
            Some(connector) => {
                Stream::Tls(Box::new(connector.connect(host, tcp).map_err(tls_error)?))
            }
            None => Stream::Plain(tcp),
        };
        let mut client = SmtpClient {
            reader: BufReader::new(stream),
            host: host.to_string(),
            local_hostname,
            helo_resp: None,
            ehlo_resp: None,
            does_esmtp: false,
            features: Vec::new(),
            utf8_commands: false,
        };
        let (code, _) = client.getreply()?;
        if code != 220 {
            client.close();
            return fail("SMTPConnectError");
        }
        Ok(client)
    }

    /// `close()`.
    pub fn close(&mut self) {
        match std::mem::replace(self.reader.get_mut(), Stream::Closed) {
            Stream::Plain(stream) => {
                let _ = stream.shutdown(Shutdown::Both);
            }
            Stream::Tls(mut stream) => {
                let _ = stream.shutdown();
            }
            Stream::Closed => {}
        }
    }

    /// `putcmd(cmd, args)`.
    fn putcmd(&mut self, command: &str, args: &str) -> R<()> {
        let line = if args.is_empty() {
            format!("{command}\r\n")
        } else {
            format!("{command} {args}\r\n")
        };
        if line[..line.len() - 2].contains(['\r', '\n']) {
            return fail("command and arguments contain prohibited newline characters");
        }
        if !self.utf8_commands && !line.is_ascii() {
            return fail("UnicodeEncodeError in SMTP command");
        }
        let stream = self.reader.get_mut();
        if let Err(error) = stream
            .write_all(line.as_bytes())
            .and_then(|_| stream.flush())
        {
            self.close();
            return Err(error.into());
        }
        Ok(())
    }

    /// `getreply()`: `(code, message)`; `code` is -1 for a non-numeric reply.
    fn getreply(&mut self) -> R<(i32, Vec<u8>)> {
        let mut lines: Vec<Vec<u8>> = Vec::new();
        let code;
        loop {
            let mut line = Vec::new();
            let read = (&mut self.reader)
                .take(MAX_LINE as u64 + 1)
                .read_until(b'\n', &mut line);
            let read = match read {
                Ok(read) => read,
                Err(error) => {
                    self.close();
                    return Err(error.into());
                }
            };
            if read == 0 {
                self.close();
                return fail("Connection unexpectedly closed");
            }
            if line.len() > MAX_LINE {
                self.close();
                return fail("Line too long.");
            }
            let text = line.get(4..).unwrap_or_default();
            let start = text
                .iter()
                .position(|b| !b" \t\r\n".contains(b))
                .unwrap_or(text.len());
            let end = text
                .iter()
                .rposition(|b| !b" \t\r\n".contains(b))
                .map_or(start, |i| i + 1);
            lines.push(text[start..end.max(start)].to_vec());
            let digits = String::from_utf8_lossy(&line[..line.len().min(3)]).to_string();
            match digits.trim().parse::<i32>() {
                Ok(value) => {
                    if line.get(3) != Some(&b'-') {
                        code = value;
                        break;
                    }
                }
                Err(_) => {
                    code = -1;
                    break;
                }
            }
        }
        Ok((code, lines.join(&b'\n')))
    }

    /// `docmd(cmd, args)`.
    fn docmd(&mut self, command: &str, args: &str) -> R<(i32, Vec<u8>)> {
        self.putcmd(command, args)?;
        self.getreply()
    }

    /// `has_extn(name)`.
    fn has_extn(&self, name: &str) -> bool {
        let name = name.to_ascii_lowercase();
        self.features.iter().any(|(feature, _)| *feature == name)
    }

    fn feature(&self, name: &str) -> Option<&str> {
        self.features
            .iter()
            .find(|(feature, _)| feature == name)
            .map(|(_, params)| params.as_str())
    }

    fn set_feature(&mut self, name: &str, params: String) {
        match self
            .features
            .iter_mut()
            .find(|(feature, _)| feature == name)
        {
            Some(entry) => entry.1 = params,
            None => self.features.push((name.to_string(), params)),
        }
    }

    /// `ehlo()`: returns the reply code.
    pub fn ehlo(&mut self) -> R<i32> {
        self.features.clear();
        let name = self.local_hostname.clone();
        self.putcmd("ehlo", &name)?;
        let (code, message) = self.getreply()?;
        if code == -1 && message.is_empty() {
            self.close();
            return fail("Server not connected");
        }
        self.ehlo_resp = Some(message.clone());
        if code != 250 {
            return Ok(code);
        }
        self.does_esmtp = true;
        let text: String = message.iter().map(|&b| b as char).collect();
        for line in text.split('\n').skip(1) {
            if line.len() >= 5 && line[..5].eq_ignore_ascii_case("auth=") {
                let params = format!("{} {}", self.feature("auth").unwrap_or(""), &line[5..]);
                self.set_feature("auth", params);
                continue;
            }
            let bytes = line.as_bytes();
            if bytes.first().is_some_and(u8::is_ascii_alphanumeric) {
                let end = bytes
                    .iter()
                    .position(|b| !(b.is_ascii_alphanumeric() || *b == b'-'))
                    .unwrap_or(bytes.len());
                let feature = line[..end].to_ascii_lowercase();
                let params = line[end..].trim().to_string();
                if feature == "auth" {
                    let params = format!("{} {params}", self.feature("auth").unwrap_or(""));
                    self.set_feature("auth", params);
                } else {
                    self.set_feature(&feature, params);
                }
            }
        }
        Ok(code)
    }

    /// `helo()`.
    fn helo(&mut self) -> R<i32> {
        let name = self.local_hostname.clone();
        self.putcmd("helo", &name)?;
        let (code, message) = self.getreply()?;
        self.helo_resp = Some(message);
        Ok(code)
    }

    /// `ehlo_or_helo_if_needed()`.
    fn ehlo_or_helo_if_needed(&mut self) -> R<()> {
        if self.helo_resp.is_none() && self.ehlo_resp.is_none() {
            let code = self.ehlo()?;
            if !(200..=299).contains(&code) {
                let code = self.helo()?;
                if !(200..=299).contains(&code) {
                    return fail("SMTPHeloError");
                }
            }
        }
        Ok(())
    }

    /// `starttls(context)`.
    pub fn starttls(&mut self, connector: &TlsConnector) -> R<()> {
        self.ehlo_or_helo_if_needed()?;
        if !self.has_extn("starttls") {
            return fail("STARTTLS extension not supported by server.");
        }
        let (code, _) = self.docmd("STARTTLS", "")?;
        if code != 220 {
            return fail("SMTPResponseException after STARTTLS");
        }
        // Like smtplib (which drops its buffered file object), nothing that
        // arrived in plaintext after the 220 is ever interpreted.
        let tcp = match std::mem::replace(self.reader.get_mut(), Stream::Closed) {
            Stream::Plain(tcp) => tcp,
            other => {
                *self.reader.get_mut() = other;
                return fail("STARTTLS on an encrypted connection");
            }
        };
        let tls = connector.connect(&self.host, tcp).map_err(tls_error)?;
        self.reader = BufReader::new(Stream::Tls(Box::new(tls)));
        self.helo_resp = None;
        self.ehlo_resp = None;
        self.features.clear();
        self.does_esmtp = false;
        Ok(())
    }

    /// `auth(mechanism, authobject)` with `initial_response_ok=True`.
    fn auth(&mut self, mechanism: &str, user: &str, password: &str) -> R<()> {
        let response = |count: usize| -> String {
            match mechanism {
                "PLAIN" => format!("\0{user}\0{password}"),
                _ if count < 2 => user.to_string(),
                _ => password.to_string(),
            }
        };
        let initial = response(1);
        if !initial.is_ascii() || !password.is_ascii() {
            // Python: UnicodeEncodeError from `.encode('ascii')`.
            return fail("credentials are not ASCII");
        }
        let (mut code, _) =
            self.docmd("AUTH", &format!("{mechanism} {}", BASE64.encode(initial)))?;
        let mut count = 1;
        while code == 334 {
            count += 1;
            let answer = BASE64.encode(response(count));
            code = self.docmd(&answer, "")?.0;
            if count > MAX_CHALLENGE {
                return fail("Server AUTH mechanism infinite loop.");
            }
        }
        if code == 235 || code == 503 {
            Ok(())
        } else {
            fail(AUTH_REJECTED)
        }
    }

    /// `login(user, password)`.
    pub fn login(&mut self, user: &str, password: &str) -> R<()> {
        self.ehlo_or_helo_if_needed()?;
        if !self.has_extn("auth") {
            return fail("SMTP AUTH extension not supported by server.");
        }
        let advertised: Vec<String> = self
            .feature("auth")
            .unwrap_or("")
            .split_whitespace()
            .map(str::to_string)
            .collect();
        let authlist: Vec<&str> = PREFERRED_AUTHS
            .iter()
            .copied()
            .filter(|mechanism| advertised.iter().any(|item| item == mechanism))
            .collect();
        if authlist.is_empty() {
            return fail("No suitable authentication method found.");
        }
        // Only a rejected mechanism (SMTPAuthenticationError) moves on to the
        // next one; any other failure ends the attempt.
        for mechanism in authlist {
            match self.auth(mechanism, user, password) {
                Ok(()) => return Ok(()),
                Err(error) if error.0 == AUTH_REJECTED => continue,
                Err(error) => return Err(error),
            }
        }
        fail(AUTH_REJECTED)
    }

    /// `_rset()`: `RSET`, ignoring a disconnect.
    fn rset(&mut self) {
        let _ = self.docmd("rset", "");
    }

    /// `send_message`'s international check plus `sendmail(from, to, msg,
    /// mail_options)`: returns the refused recipients (an empty list when
    /// every recipient was accepted).
    pub fn send_message(&mut self, from: &str, to: &[String], message: &[u8]) -> R<Vec<String>> {
        self.ehlo_or_helo_if_needed()?;
        let international = !from.is_ascii() || to.iter().any(|address| !address.is_ascii());
        let mut mail_options: Vec<String> = Vec::new();
        if international {
            if !self.has_extn("smtputf8") {
                return fail("One or more source or delivery addresses require internationalized email support, but the server does not advertise the required SMTPUTF8 capability");
            }
            mail_options.push("SMTPUTF8".into());
            mail_options.push("BODY=8BITMIME".into());
        }
        let mut esmtp_options = Vec::new();
        if self.does_esmtp {
            if self.has_extn("size") {
                esmtp_options.push(format!("size={}", message.len()));
            }
            esmtp_options.extend(mail_options);
        }
        // mail()
        let mut option_list = String::new();
        if !esmtp_options.is_empty() && self.does_esmtp {
            if esmtp_options
                .iter()
                .any(|option| option.eq_ignore_ascii_case("smtputf8"))
            {
                if self.has_extn("smtputf8") {
                    self.utf8_commands = true;
                } else {
                    return fail("SMTPUTF8 not supported by server");
                }
            }
            option_list = format!(" {}", esmtp_options.join(" "));
        }
        let (code, _) = self.docmd("mail", &format!("from:<{from}>{option_list}"))?;
        if code != 250 {
            if code == 421 {
                self.close();
            } else {
                self.rset();
            }
            return fail("SMTPSenderRefused");
        }
        let mut refused = Vec::new();
        for recipient in to {
            let (code, _) = self.docmd("rcpt", &format!("to:<{recipient}>"))?;
            if code != 250 && code != 251 {
                refused.push(recipient.clone());
            }
            if code == 421 {
                self.close();
                return fail("SMTPRecipientsRefused");
            }
        }
        if refused.len() == to.len() {
            self.rset();
            return fail("SMTPRecipientsRefused");
        }
        // data()
        let (code, _) = self.docmd("data", "")?;
        if code != 354 {
            return fail("SMTPDataError");
        }
        let mut quoted = quote_periods(message);
        if !quoted.ends_with(b"\r\n") {
            quoted.extend_from_slice(b"\r\n");
        }
        quoted.extend_from_slice(b".\r\n");
        let stream = self.reader.get_mut();
        if let Err(error) = stream.write_all(&quoted).and_then(|_| stream.flush()) {
            self.close();
            return Err(error.into());
        }
        let (code, _) = self.getreply()?;
        if code != 250 {
            if code == 421 {
                self.close();
            } else {
                self.rset();
            }
            return fail("SMTPDataError");
        }
        Ok(refused)
    }

    /// `quit()`.
    pub fn quit(&mut self) -> R<()> {
        let result = self.docmd("quit", "");
        self.close();
        result.map(|_| ())
    }
}

/// `smtplib._quote_periods`: `re.sub(br'(?m)^\.', b'..', data)`.
fn quote_periods(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() + 16);
    let mut at_line_start = true;
    for &byte in data {
        if at_line_start && byte == b'.' {
            out.push(b'.');
        }
        out.push(byte);
        at_line_start = byte == b'\n';
    }
    out
}

#[cfg(test)]
mod tests {
    use super::quote_periods;

    #[test]
    fn periods_at_line_starts_are_doubled() {
        assert_eq!(quote_periods(b".a\r\nb.\r\n.\r\n"), b"..a\r\nb.\r\n..\r\n");
    }
}
