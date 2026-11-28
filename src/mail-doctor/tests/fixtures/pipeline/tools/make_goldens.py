# Setup: copy original-project/.../backend/app/doctor/{services/pipeline.py,services/cancellation.py,services/stages/*.py,utils/temp_manager.py}
# into ./pydoctor/ (same layout, empty __init__.py files, config.py = "class DoctorSettings: pass").
# Then run: python -I make_goldens.py <mail-doctor>/tests/fixtures/pipeline && python -I make_edge.py <same dir>
"""Generate Inbox Doctor pipeline fixtures + golden outputs from the ORIGINAL
Python stage code (copied read-only into ./pydoctor).

Usage: python -I make_goldens.py <fixtures_root>

POSIX semantics are forced so goldens match the Rust port's choice:
  * mailbox.linesep = b"\n"
  * text files written by Python on Windows get CRLF->LF normalized (CSV files
    are written with newline="" and keep their \r\n record terminators).
"""
import base64
import io
import json
import mailbox
import os
import shutil
import sys
import tempfile
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
mailbox.linesep = b"\n"

from pydoctor.services import pipeline  # noqa: E402
from pydoctor.services.stages import eml_extract  # noqa: E402
from pydoctor.utils import temp_manager  # noqa: E402

ROOT = Path(sys.argv[1]).resolve()

SAMPLE_EML = """From: Newsletter Bot <news@mail.example.com>
To: user@test.local
Subject: Weekly digest {n}
Date: Mon, 05 Aug 2024 10:0{n}:00 +0000
Message-ID: <msg{n}@mail.example.com>
List-Unsubscribe: <https://mail.example.com/unsub?token={n}>
MIME-Version: 1.0
Content-Type: text/plain; charset="utf-8"

Hello, here is your weekly digest number {n}.
"""

HUMAN_EML = """From: Alice Smith <alice@friends.org>
To: user@test.local
Subject: Lunch on Friday?
Date: Tue, 06 Aug 2024 09:15:00 +0000
Message-ID: <lunch@friends.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="utf-8"

Are you still up for lunch on Friday?
"""


def crlf(text: str) -> bytes:
    return text.replace("\n", "\r\n").encode("utf-8")


def lf(text: str) -> bytes:
    return text.encode("utf-8")


def basic_inputs() -> dict[str, bytes]:
    files = {f"news_{i}.eml": lf(SAMPLE_EML.format(n=i)) for i in range(12)}
    files["human.eml"] = lf(HUMAN_EML)
    return files


LATIN_BODY = base64.encodebytes("Grüße aus München!\n   Tschüss  \n".encode("latin-1")).decode()

ENCODED_EML = f"""Return-Path: <bounce@mailer.shop.example.co.uk>
From: =?utf-8?q?Caf=C3=A9_Shop?= <Offers@Mailer.Shop.Example.co.uk>
To: "Doe, Jane" <jane@example.net>, bob@example.net
Subject: =?utf-8?b?U3VwZXIgU2FsZSDwn46J?= =?utf-8?q?_today?=
 only
Date: Wed, 7 Aug 2024 18:30:00 +0200
Message-ID:   <enc-1@shop.example.co.uk>
List-Unsubscribe: <mailto:unsub@shop.example.co.uk>,
 <https://shop.example.co.uk/u?id=1>
List-Unsubscribe-Post: List-Unsubscribe=One-Click
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="outer"

preamble text
--outer
Content-Type: multipart/alternative; boundary=inner

--inner
Content-Type: text/plain; charset=iso-8859-1
Content-Transfer-Encoding: base64

{LATIN_BODY}--inner
Content-Type: text/html; charset=utf-8

<p>HTML</p>
--inner--

--outer
Content-Type: application/pdf; name="invoice.pdf"
Content-Disposition: attachment; filename="invoice.pdf"
Content-Transfer-Encoding: base64

JVBERi0xLjQK
--outer--
epilogue
"""

QP_EML = """From: "J. Smith (Work)" <john.smith@corp.example.com>
To: Team <team@corp.example.com>
Subject: Status =?bad?x?zz?= update, =?utf-8?q?na=C3=AFve?=
Date: Thu, 08 Aug 2024 07:05:09 -0700 (PDT)
Message-ID: <qp-1@corp.example.com>
List-Unsubscribe: https://plain.example.com/unsub
Content-Type: text/plain; charset="utf-8"
Content-Transfer-Encoding: quoted-printable

   Caf=C3=A9 notes: this line is soft=
 broken and =3D sign, broken =ZZ escape=
=0A second   line\twith tabs
"""

NODATE_EML = """From: a@x.org, b@y.org
To: undisclosed-recipients:;
Content-Type: text/html; charset=utf-8

<html><body>Only HTML here</body></html>
"""

BADCHARS_EML = """From: Jürgen Größe <j@umlaut.de>
To: someone@example.net
Subject: Prüfung ✓ =HYPERLINK("x")
Date: Fri, 09 Aug 2024 25:00:00 +0000
Message-ID: <bad-1@umlaut.de>
Content-Transfer-Encoding: 8bit

=Formula,with "quotes" and ünïcödé
"""

INJECT_EML = """From: "+cmd|' /C calc'!A0" <attacker@evil.example>
To: user@test.local
Subject: =SUM(A1:A9)
Date: Sat, 10 Aug 24 12:00:00 EST
Message-ID: <inj@evil.example>
Content-Type: text/plain

@SUM(1+1)*cmd|' /C calc'!A0
"""

DIGEST_EML = """From: Digest Robot <digest-noreply@lists.example.org>
To: user@test.local
Subject: Digest, Vol 1
Date: 11 Aug 2024 08:00 +0530
Content-Type: multipart/digest; boundary="dg"

--dg

From: Inner <inner@lists.example.org>
Subject: inner message
Content-Type: text/plain

  Inner   digest body text.
--dg--
"""

MBOX = """Ignored preamble line before the first separator
From MAILER-DAEMON Mon Aug  5 10:00:00 2024
From: Newsletter Bot <news@Mail.Example.com>
Subject: Weekly digest
 folded continuation
Date: Mon, 05 Aug 2024 10:00:00 +0000
Message-ID: <mbox1@mail.example.com>
List-Unsubscribe: <https://mail.example.com/unsub?token=a>
X-Long-Header: aaaa bbbb cccc dddd eeee ffff gggg hhhh iiii jjjj kkkk llll mmmm nnnn oooo pppp
X-Long-Token: {token}
X-Params: alpha=1; beta=2; gamma=3; delta=4; epsilon=5; zeta=6; eta=7; theta=8; iota=9
Content-Type: text/plain

Hello
>From the archive
body

From someone@example.org Tue Aug  6 09:00:00 2024
From: =?iso-8859-1?q?J=FCrgen?= <jurgen@example.org>
Subject: =?utf-8?q?caf=C3=A9?= and more
Date: Tue, 06 Aug 2024 09:00:00 -0000
Content-Type: multipart/alternative; boundary="b1"

--b1
Content-Type: text/plain; charset=utf-8

Plain part
--b1
Content-Type: text/html

<b>x</b>
--b1--

From x@y Wed Aug  7 00:00:00 2024
From: Raw Ünïcode <raw@eight.example>
Subject: Raw Ünïcode subject
Date: Wed, 07 Aug 2024 00:00:00 +0000

Body ✓
""".replace("{token}", "<" + "t" * 100 + ">")

ALIASES = {
    "eight.example": "example.org",
    "Mail.Example.com": "example.com",
    "group.example": ["umlaut.de", "corp.example.com"],
}

ANNOTATIONS = {
    "example.org": {"action": "keep", "note": "Friends & family"},
    "example.co.uk": "review",
    "plain.example.com": {"note": 42},
    "group.example": {"action": "bogus", "note": ["a", 1, None, True, 1.5]},
}


def make_zip() -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as output:
        output.writestr("nested/", b"")
        output.writestr("nested/dir/zipped.eml", lf(SAMPLE_EML.format(n=7)).replace(b"msg7@", b"zipped7@"))
        output.writestr("Upper.EML", lf(HUMAN_EML).replace(b"lunch@", b"upper@"))
        output.writestr("nested/readme.txt", b"not an input")
        output.writestr("inner.zip", b"PK\x05\x06" + b"\0" * 18)
        output.writestr("nested/annotations.json", json.dumps({"friends.org": "archive"}))
    return buffer.getvalue()


def mixed_inputs() -> dict[str, bytes]:
    return {
        "encoded.eml": crlf(ENCODED_EML),
        "qp.eml": lf(QP_EML),
        "nodate.eml": lf(NODATE_EML),
        "badchars.eml": lf(BADCHARS_EML),
        "inject.eml": lf(INJECT_EML),
        "digest.eml": lf(DIGEST_EML),
        "list.mbox": lf(MBOX),
        "human.eml": lf(HUMAN_EML),
        "aliases.json": json.dumps(ALIASES).encode(),
        "annotations.json": json.dumps(ANNOTATIONS).encode(),
        "archive.zip": make_zip(),
    }


def normalize(path: Path) -> bytes:
    data = path.read_bytes()
    if path.suffix == ".csv":
        return data
    return data.replace(b"\r\n", b"\n")


def run_case(name: str, inputs: dict[str, bytes], days=None) -> None:
    case = ROOT / name
    (case / "inputs").mkdir(parents=True, exist_ok=True)
    for filename, data in inputs.items():
        (case / "inputs" / filename).write_bytes(data)
    with tempfile.TemporaryDirectory() as tmp:
        job = Path(tmp) / "job"
        shutil.copytree(case / "inputs", job / "inputs")
        events = []
        pipeline.run_pipeline(job, days=days, event=lambda kind, msg: events.append([kind, msg]))
        expected = case / "expected"
        if expected.exists():
            shutil.rmtree(expected)
        for path in sorted((job / "outputs").rglob("*")):
            if path.is_file():
                target = expected / path.relative_to(job / "outputs")
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(normalize(path))
        (case / "events.json").write_text(json.dumps(events, indent=2, ensure_ascii=False) + "\n", encoding="utf-8", newline="\n")
        extracted = sorted(p.relative_to(job / "inputs").as_posix() for p in (job / "inputs").rglob("*") if p.is_file())
        (case / "inputs_after.json").write_text(json.dumps(extracted, indent=2) + "\n", encoding="utf-8", newline="\n")


def unit_cases() -> dict:
    from email.utils import getaddresses, parseaddr
    from email import message_from_bytes, policy
    from email.parser import BytesParser

    dates = [
        "Mon, 05 Aug 2024 10:00:00 +0000", "Wed, 7 Aug 2024 18:30:00 +0200", "Thu, 08 Aug 2024 07:05:09 -0700 (PDT)",
        "Sat, 10 Aug 24 12:00:00 EST", "11 Aug 2024 08:00 +0530", "Tue, 06 Aug 2024 09:00:00 -0000",
        "Fri, 09 Aug 2024 25:00:00 +0000", "", "   ", "garbage", "Sun, 31 Dec 1999 23:59:59 +2359",
        "1 Jan 70 00:00:00 GMT", "Mon,5 Aug 2024 10:00:00 +0000", "5-Aug-2024 10:00:00 +0100", "August 5 2024 10.30 PDT",
        "Mon, 05 Aug 2024 10:00:60 +0000", "Mon, 05 Aug 2024 10:00:00 +2500", "Mon, 05 Aug 2024 10:00:00 Z",
        "Mon, 05 Aug 2024 10:00:00 XYZ", "05 Aug 2024 10:00:00", "Mon, 05 Aug 2024, 10:00:00 +0000", "1 Jan 0001 00:00:00 +0100",
    ]
    addresses = [
        "Newsletter Bot <news@mail.example.com>", "a@x.org, b@y.org", '"Doe, Jane" <jane@example.net>, bob@example.net',
        "undisclosed-recipients:;", "plain@example.com", "Name Only", "<>", "x@[1.2.3.4]", "a@b@c.com", "(comment) user@example.com",
        'user@example.com (Real Name)', "broken (paren <a@b.com>", '"J. Smith (Work)" <john.smith@corp.example.com>',
        "=?utf-8?q?Caf=C3=A9_Shop?= <Offers@Mailer.Shop.Example.co.uk>", "Group: a@b.com, c@d.com;", "  ", "a.b.@c.d",
        "<@route:user@example.com>", '"quoted\\"local"@example.com', "user@example.com,", "first last <fl@example.com> trailing",
    ]
    legacy = [
        "Hello", "=?utf-8?q?caf=C3=A9?= and more", "=?utf-8?b?U3VwZXIgU2FsZSDwn46J?= =?utf-8?q?_today?=",
        "Weekly digest\n folded continuation", "=?iso-8859-1?q?J=FCrgen?=", "a =?utf-8?q?x?= =?utf-8?q?y?= b",
        "=?unknown-cs?q?abc?=", "=?utf-8?b?!!!?=", "=?utf-8?q?bad=FF?=", "x=?utf-8?q?y?=z", "=?bad?x?zz?=",
        "Status =?bad?x?zz?= update, =?utf-8?q?na=C3=AFve?=", "=?us-ascii?q?plain?= (comment)", "=?utf-8*en?q?lang?=",
    ]
    modern = [
        b"=?utf-8?b?U3VwZXIgU2FsZSDwn46J?= =?utf-8?q?_today?=\r\n only", b"Status =?bad?x?zz?= update, =?utf-8?q?na=C3=AFve?=",
        b"  leading and trailing  ", b"tab\there", b"x=?utf-8?q?y?=z", b"=?utf-8?q?a?= =?utf-8?q?b?=", b"=?utf-8?q?a?=  b",
        b"Pr\xc3\xbcfung \xe2\x9c\x93", b"bad \xff byte", b"=?iso-8859-1?q?J=FCrgen?=", b"=?unknown?q?abc=FF?=",
        b"=?utf-8?q?a?b?=", b"=?utf-8?Q?under_score?=", b"=?utf-8?q?=3F=3D?=", b"a\n\tb", b"=?utf-8?b?YWJj?==?utf-8?b?ZGVm?=",
    ]
    cases = {"dates": [], "first_address": [], "parseaddr": [], "legacy_decode": [], "modern_subject": [], "mbox_sizes": []}
    for value in dates:
        cases["dates"].append([value, eml_extract._parse_date(value)])
    for value in addresses:
        cases["first_address"].append([value, eml_extract._first_address(value)])
        cases["parseaddr"].append([value, list(parseaddr(value))])
    for value in legacy:
        cases["legacy_decode"].append([value, eml_extract._decode(value)])
    for value in modern:
        msg = BytesParser(policy=policy.default).parsebytes(b"Subject: " + value + b"\r\n\r\nbody")
        cases["modern_subject"].append([value.decode("latin-1"), eml_extract._decode(msg.get("Subject"))])
    box_path = ROOT / "mixed" / "inputs" / "list.mbox"
    box = mailbox.mbox(box_path)
    try:
        for msg in box:
            cases["mbox_sizes"].append(len(msg.as_bytes()))
    finally:
        box.close()
    names = [
        "inbox.zip", "../../etc/passwd", "C:\\Users\\x\\Mail.EML", "con.txt", "COM1", "lpt9.mbox", " .hidden. ", "a<b>c:d\"e|f?g*h.Eml",
        "", None, "...", "x" * 200 + ".MBOX", "y" * 200, "report.tar.GZ", "trailing.", "noext", "dir/sub/aliases.JSON", "ä😀.EML",
        "nul", "Aux.Json", "\x01ctrl\x1f.eml",
    ]
    cases["safe_filename"] = [[n, temp_manager.safe_filename(n)] for n in names]
    cases["safe_filename_fallback"] = [[n, temp_manager.safe_filename(n, "pasted.eml")] for n in ["", None, "..", "ok.EML"]]
    return cases


if __name__ == "__main__":
    run_case("basic", basic_inputs())
    run_case("mixed", mixed_inputs())
    cases = unit_cases()
    (ROOT / "unit_cases.json").write_text(json.dumps(cases, indent=1, ensure_ascii=False) + "\n", encoding="utf-8", newline="\n")
    print("ok")
