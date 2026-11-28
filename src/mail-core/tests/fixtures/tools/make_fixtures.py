"""Write .eml fixtures for the Rust parsing/audit parity tests."""
import sys
from pathlib import Path

out = Path(sys.argv[1])
out.mkdir(parents=True, exist_ok=True)

F = {}

F["sample_phish"] = b"""Return-Path: <bounce@bounces.example>
Received: from mail.evil.example (mail.evil.example [10.0.0.1])
        by mx.example.com with ESMTPS id abc123
        for <user@example.com>; Mon, 13 Oct 2026 10:00:05 +0000
Received: from phishing.host (phishing.host [10.0.0.2])
        by mail.evil.example with SMTP id def456;
        Mon, 13 Oct 2026 09:59:50 +0000
Authentication-Results: mx.example.com;
        spf=fail smtp.mailfrom=evil.example;
        dkim=none;
        dmarc=fail header.from=bank.example
From: "Bank Support <support@bank.example>" <forged@evil.example>
Reply-To: <helpdesk@other.example>
To: <user@example.com>
Subject: Urgent: verify your account
Date: Mon, 13 Oct 2026 09:59:40 +0000
Message-ID: <deadbeef@evil.example>
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="BOUND"

--BOUND
Content-Type: text/plain; charset="utf-8"

Click http://185.10.20.30/login to verify.
Also see https://bank.example/secure and https://xn--bnk-xua.example/.

--BOUND
Content-Type: text/html; charset="utf-8"

<a href="http://185.10.20.30/login">https://bank.example</a>

--BOUND
Content-Type: application/octet-stream; name="invoice.pdf.exe"
Content-Disposition: attachment; filename="invoice.pdf.exe"
Content-Transfer-Encoding: base64

TVo=

--BOUND--
"""

F["clean"] = (
    "Return-Path: <alice@example.com>\r\n"
    "Received: from smtp.example.com by mx.example.com; Mon, 13 Oct 2026 10:00:00 +0000\r\n"
    "Authentication-Results: mx.example.com; spf=pass; dkim=pass; dmarc=pass\r\n"
    "From: Alice <alice@example.com>\r\n"
    "To: <bob@example.com>\r\n"
    "Subject: Hello\r\n"
    "Date: Mon, 13 Oct 2026 10:00:00 +0000\r\n"
    "Message-ID: <abc@example.com>\r\n"
    "\r\n"
    "Plain body.\r\n"
).encode()

F["encoded_headers"] = (
    "From: =?utf-8?q?J=C3=B6rg_M=C3=BCller?= <Joerg.Mueller@Example.COM>\r\n"
    "To: \"Doe, Jane\" <JANE@example.org>, bob@example.net (Bob, B), Team: x@team.example, y@team.example;\r\n"
    "Cc: =?iso-8859-1?q?Andr=E9?= <andre@example.fr>,\r\n undisclosed-recipients:;\r\n"
    "Reply-To: Support <support@mail.example.com>\r\n"
    "Subject: =?utf-8?b?R3LDvMOfZQ==?= and =?utf-8?q?more?=\r\n =?utf-8?q?_text?= x=?utf-8?q?Y?=z\r\n"
    "Date: 13 Oct 2026 10:00:05 -0000\r\n"
    "Message-ID:  <id-1@mail.example.com> (comment)\r\n"
    "List-Unsubscribe: <mailto:unsub@example.com>, <https://example.com/unsub?id=1>\r\n"
    "List-Unsubscribe-Post: List-Unsubscribe=One-Click\r\n"
    "X-Mailer: =?utf-8?q?Mailer_=E2=9C=93?=\r\n"
    "X-Priority: 1 (Highest)\r\n"
    "Authentication-Results: mx1.example; spf=neutral smtp.mailfrom=example.com\r\n"
    "Authentication-Results: mx2.example; spf=pass smtp.mailfrom=Example.com;\r\n"
    "  dkim=PASS header.d=example.com header.i=@Example.com; dmarc=bestguesspass header.from=example.com\r\n"
    "Received: from a.example by b.example with LMTP for <x@y>; Tue, 14 Oct 2026 01:02:03 +0200\r\n"
    "Received: from c.example by a.example; 13 Oct 2026 22:00:00 -0100\r\n"
    "\r\n"
    "Body with https://example.com/path?x=1, and (https://paren.example) plus http://[::1]/x\r\n"
).encode("utf-8")

F["nested"] = (
    "From: Shop <orders@shop.example>\r\n"
    "To: me@example.com\r\n"
    "Subject: Your order\r\n"
    "Date: Wed, 1 Jan 2025 12:00:00 +0100\r\n"
    "Message-ID: <order@shop.example>\r\n"
    "X-Mailer: ShopMailer 1.0\r\n"
    "MIME-Version: 1.0\r\n"
    "Content-Type: multipart/mixed;\r\n boundary=\"outer\"\r\n"
    "\r\n"
    "This is a preamble.\r\n"
    "--outer\r\n"
    "Content-Type: multipart/alternative; boundary=inner\r\n"
    "\r\n"
    "--inner\r\n"
    "Content-Type: text/plain; charset=iso-8859-1\r\n"
    "Content-Transfer-Encoding: quoted-printable\r\n"
    "\r\n"
    "Caf=E9 cr=E8me =\r\n"
    "soft break. Visit https://shop.example/order/1.\r\n"
    "--inner\r\n"
    "Content-Type: text/html; charset=utf-8\r\n"
    "Content-Transfer-Encoding: base64\r\n"
    "\r\n"
).encode() + __import__("base64").encodebytes(
    (
        '<html><body><p>Hello&nbsp;<b>there</b></p>'
        '<a href="https://evil.example/track">https://shop.example/account</a> '
        "<A HREF='http://xn--shp-qla.example/'>Shop</a> "
        '<a class="x" href=https://shop.example/ok>  <span>https://www.shop.example/ok</span> </a>'
        '<a href="mailto:x@y">mail</a>'
        '<a href="http://user:pw@Host.Example:8080/p">cred</a>'
        "</body></html>"
    ).encode()
) + (
    "--inner--\r\n"
    "--outer\r\n"
    "Content-Type: application/pdf; name=\"=?utf-8?b?w6kucGRm?=\"\r\n"
    "Content-Disposition: attachment\r\n"
    "Content-Transfer-Encoding: base64\r\n"
    "\r\n"
    "JVBERi0xLjQK\r\n"
    "--outer\r\n"
    "Content-Type: application/javascript\r\n"
    "Content-Disposition: attachment; filename*0*=utf-8''r%C3%A9port; filename*1=\".pdf.js\"\r\n"
    "\r\n"
    "alert(1)\r\n"
    "--outer\r\n"
    "Content-Type: text/plain; charset=windows-1252\r\n"
    "Content-Disposition: attachment\r\n"
    "\r\n"
).encode() + b"price \x80 5\r\n" + (
    "--outer\r\n"
    "Content-Type: image/png; name=logo.png\r\n"
    "Content-Disposition: inline; filename=\"logo.png\"\r\n"
    "Content-Transfer-Encoding: base64\r\n"
    "\r\n"
    "iVBORw0KGgo=\r\n"
    "--outer\r\n"
    "Content-Type: application/zip\r\n"
    "Content-Disposition: attachment; filename=\"archive.tar.zip\"\r\n"
    "\r\n"
    "PK\r\n"
    "--outer\r\n"
    "Content-Type: message/rfc822\r\n"
    "Content-Disposition: attachment; filename=\"fwd.eml\"\r\n"
    "\r\n"
    "From: inner@example.com\r\n"
    "Subject: Inner\r\n"
    "Content-Type: multipart/mixed; boundary=deep\r\n"
    "\r\n"
    "--deep\r\n"
    "Content-Type: text/plain\r\n"
    "\r\n"
    "inner text\r\n"
    "--deep\r\n"
    "Content-Type: application/x-msdownload; name=setup.EXE\r\n"
    "\r\n"
    "MZ\r\n"
    "--deep--\r\n"
    "\r\n"
    "--outer--\r\n"
    "epilogue\r\n"
).encode()

F["broken"] = (
    "From person@example.com Mon Oct 13 10:00:00 2026\n"
    "Subject: Broken \xc3\xa9t\xe9\n"
    "From: Person <person@example.com\n"
    "Received: by host.example; Mon, 13 Oct 2026 25:00:00 +0000\n"
    "Received: by host2.example; garbage date\n"
    "Received: from x.example; Mon, 13 Oct 2026 10:00:00 +9999\n"
    "Authentication-Results: mx; spf=softfail; dkim=temperror; dmarc=weird\n"
    "Content-Type: multipart/mixed; boundary=\"b\"\n"
    "Bad header line without colon\n"
    "Content-Type: text/plain\n"
    "\n"
    "body before boundary? no, this is still body\n"
).encode("latin-1")

F["missing_close"] = (
    b"From: a@b.example\r\n"
    b"Subject: Missing close\r\n"
    b"Content-Type: multipart/mixed; boundary=\"b\"\r\n"
    b"\r\n"
    b"--b\r\n"
    b"--b\r\n"
    b"Content-Type: text/plain; charset=x-unknown-charset\r\n"
    b"\r\n"
    b"caf\xc3\xa9 text\r\n"
    b"--b \r\n"
    b"Content-Type: text/html\r\n"
    b"Content-Disposition: attachment; filename=\"page.html\"\r\n"
    b"\r\n"
    b"<p>attached html</p>\r\n"
    b"--bnot a boundary\r\n"
    b"still html\r\n"
)

F["no_headers"] = b"just some text without headers\nhttp://example.com/x\n"

F["no_boundary"] = (
    b"From: a@b.example\r\nContent-Type: multipart/mixed\r\n\r\n--x\r\nContent-Type: text/plain\r\n\r\nhi\r\n--x--\r\n"
)

F["start_boundary_missing"] = (
    b"From: a@b.example\r\nContent-Type: multipart/alternative; boundary=zz\r\n\r\nno parts here\r\n--zz--\r\n"
)

F["digest"] = (
    b"From: list@example.com\r\n"
    b"Subject: Digest\r\n"
    b"Content-Type: multipart/digest; boundary=d\r\n"
    b"\r\n"
    b"--d\r\n"
    b"\r\n"
    b"From: one@example.com\r\n"
    b"Subject: One\r\n"
    b"\r\n"
    b"first digest body https://one.example\r\n"
    b"--d\r\n"
    b"Content-Type: message/delivery-status\r\n"
    b"\r\n"
    b"Reporting-MTA: dns; mx.example\r\n"
    b"\r\n"
    b"Final-Recipient: rfc822; x@example.com\r\n"
    b"Action: failed\r\n"
    b"--d--\r\n"
)

F["html_only"] = (
    b"From: News <news@news.example>\r\n"
    b"Subject: Weekly newsletter - 20% off\r\n"
    b"Content-Type: text/html; charset=utf-8\r\n"
    b"List-Unsubscribe: https://news.example/u\r\n"
    b"Precedence: bulk\r\n"
    b"\r\n"
    b"<html><head><style>p{}</style></head><body><h1>Big   Sale</h1>\r\n<p>Get it <a href='https://news.example/sale'>here</a>.</p>"
    b"<a href=\"https://192.168.0.1:8443/x\">https://news.example</a></body></html>\r\n"
)

F["lone_cr"] = b"From: cr@example.com\rSubject: CR only\r\rline one\rline two http://cr.example/a)\r"

F["empty"] = b""

for name, data in F.items():
    (out / f"{name}.eml").write_bytes(data)
print(len(F))
