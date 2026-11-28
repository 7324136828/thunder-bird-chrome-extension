"""Third golden case: harder MIME / mbox edge cases. Usage: python -I make_edge.py <fixtures_root>"""
import sys
from pathlib import Path
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import make_goldens as g  # sets mailbox.linesep and imports the original pipeline

def lf(t): return t.encode("utf-8")

DSN = """From: Mail Delivery System <MAILER-DAEMON@mx.example.net>
To: user@test.local
Subject: Undelivered Mail Returned to Sender
Date: Sun, 11 Aug 2024 23:59:59 +0000
Content-Type: multipart/report; report-type=delivery-status; boundary="r1"

--r1
Content-Description: Notification
Content-Type: text/plain; charset=us-ascii

This is the mail system at host mx.example.net.

--r1
Content-Type: message/delivery-status

Reporting-MTA: dns; mx.example.net

Final-Recipient: rfc822; nobody@example.org
Action: failed
Status: 5.1.1

--r1
Content-Type: message/rfc822

From: user@test.local
Subject: original
Content-Type: text/plain

original body
--r1--
"""

SIGNED = """From: Signer <signer@secure.example.com>
Subject: =?ISO-8859-1?Q?Gr=FC=DFe?= signed
Date: Mon, 12 Aug 2024 06:00:00 +0100
Content-Type: multipart/signed; protocol="application/pgp-signature"; micalg=pgp-sha256; boundary="sig"

--sig
Content-Type: multipart/mixed; boundary="mix"

--mix
Content-Type: text/plain; charset=windows-1252
Content-Transfer-Encoding: quoted-printable

Smart =93quotes=94 and =80uro
--mix
Content-Type: application/octet-stream
Content-Disposition: inline; filename*=utf-8''r%C3%A9sum%C3%A9.bin

AAAA
--mix--

--sig
Content-Type: application/pgp-signature; name="signature.asc"

-----BEGIN PGP SIGNATURE-----
--sig--
"""

BROKEN = """From: Broken <broken@odd.example>
Subject: no boundary multipart
Content-Type: multipart/mixed

just text, no boundary at all
"""

NOCLOSE = """From: Noclose <nc@odd.example>
Subject: missing close boundary
Content-Type: multipart/alternative; boundary=zz

--zz
Content-Type: text/plain; charset=unknown-charset-xyz

cannot decode this
--zz
Content-Type: text/plain

second part never closes
"""

BADB64 = """From: B64 <b64@odd.example>
Subject: bad base64
Content-Type: text/plain; charset=utf-8
Content-Transfer-Encoding: base64

SGVsbG8gd29y
bGQh!!!=
"""

NOHEADERS = """this file has no headers at all
just text
"""

ATTACHED = """From: Fwd <fwd@odd.example>
Subject: Fwd: attached
Content-Type: multipart/mixed; boundary="a"

--a
Content-Type: message/rfc822

From: inner@odd.example
Subject: inner
Content-Type: text/plain

forwarded inner text
--a--
"""

MBOX_CRLF = ("From x@y Mon Aug  5 10:00:00 2024\r\n"
             "From: Crlf Sender <crlf@mbox.example>\r\n"
             "Subject: crlf mbox; with = semicolons; and, commas, in a long header line that keeps going on\r\n"
             "X-Folded: first\r\n second\r\n"
             "Content-Type: multipart/mixed; boundary=\"q\"\r\n"
             "\r\n"
             "pre\r\n--q\r\nContent-Type: text/plain\r\n\r\nCRLF body\r\n--q--\r\nepi\r\n"
             "\r\n"
             "From y@z Tue Aug  6 10:00:00 2024\r\n"
             "Subject: no blank line before next From\r\n"
             "From: Second <second@mbox.example>\r\n"
             "\r\n"
             "body two\r\n"
             "From z@z Wed Aug  7 10:00:00 2024\r\n"
             "From: Third <third@mbox.example>\r\n"
             "Subject: =?utf-8?q?third?=\r\n"
             "X-Embedded: value\r\n"
             "\r\n"
             "last")

def edge_inputs():
    return {
        "dsn.eml": lf(DSN), "signed.eml": lf(SIGNED), "broken.eml": lf(BROKEN), "noclose.eml": lf(NOCLOSE),
        "badb64.eml": lf(BADB64), "noheaders.eml": lf(NOHEADERS), "attached.eml": lf(ATTACHED),
        "crlf.mbox": MBOX_CRLF.encode(), "annotations.json": b'{"odd.example": 5, "example.org": null}',
        "aliases.json": b'["not", "a", "dict"]',
    }

if __name__ == "__main__":
    g.run_case("edge", edge_inputs())
    print("ok")
