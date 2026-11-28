"""Run copies of the original parsing.py/audit.py over every fixture and
write the expected JSON used by the Rust parity test."""
import base64
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from orig import audit, parsing  # noqa: E402

fixtures = Path(sys.argv[1])
results = {}
for path in sorted(fixtures.glob("*.eml")):
    raw = path.read_bytes()
    msg = parsing.parse_message(raw)
    view = parsing.header_view(msg)
    try:
        report = audit.audit_message(raw, account_email="me@example.com")
        report.pop("generated_at")
    except Exception as error:  # noqa: BLE001
        report = {"error": type(error).__name__}
    text, html = parsing.extract_bodies(msg)
    payloads = []
    for index in range(len(view["attachments"]) + 1):
        payload = parsing.attachment_payload(msg, index)
        if payload is None:
            payloads.append(None)
            continue
        is_message = payload["content"].startswith(b"[<email.message")
        payloads.append({
            "filename": payload["filename"],
            "content_type": payload["content_type"],
            "content_b64": None if is_message else base64.b64encode(payload["content"]).decode(),
        })
    results[path.stem] = {
        "header_view": view,
        "audit": report,
        "links": parsing.extract_links(text, html),
        "walk": [
            {"type": p.get_content_type(), "filename": p.get_filename(),
             "disposition": p.get_content_disposition(), "charset": p.get_content_charset()}
            for p in msg.walk()
        ],
        "payloads": payloads,
        "addresses_to": parsing.addresses(msg.get("To")),
        "addresses_cc": parsing.addresses(msg.get("Cc")),
        "subject_header": None if msg.get("Subject") is None else str(msg.get("Subject")),
    }

(Path(sys.argv[2])).write_text(json.dumps(results, indent=1, ensure_ascii=False), encoding="utf-8")
print(len(results))
