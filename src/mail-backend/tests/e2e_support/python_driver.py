"""Differential driver: replay requests against the ORIGINAL Python backend.

Used by tests/e2e_differential.rs. Reads a JSON array of requests on stdin
({"method", "path", "params": [[k, v], ...], "json"?: any, "raw"?: str,
"content_type"?: str}) and prints a JSON array of responses
({"status", "content_type", "content_disposition", "json"?, "text"?}).

argv[1] = original project root, argv[2] = isolated state directory. The
caller points APPDATA / XDG_CONFIG_HOME / TEMP at the state directory, so the
user's real settings are never read or written.
"""

import base64
import json
import os
import sys
from pathlib import Path


BOUNDARY = "----WebKitFormBoundaryE2eTest7MA4YWxk"


def _multipart(fields, files) -> bytes:
    """The exact body e2e_support::multipart_body builds (fields, then files)."""
    crlf = b"\r\n"
    body = b""
    for name, value in fields:
        body += f"--{BOUNDARY}".encode() + crlf
        body += f'Content-Disposition: form-data; name="{name}"'.encode() + crlf + crlf
        body += value.encode("utf-8") + crlf
    for name, filename, content_type, data in files:
        body += f"--{BOUNDARY}".encode() + crlf
        body += f'Content-Disposition: form-data; name="{name}"; filename="{filename}"'.encode() + crlf
        body += f"Content-Type: {content_type}".encode() + crlf + crlf
        body += base64.b64decode(data) + crlf
    body += f"--{BOUNDARY}--".encode() + crlf
    return body


def _tolerate_missing_tzdata() -> None:
    """Windows Pythons without the `tzdata` package cannot load the weekly
    scheduler's zone at import time; the replayed requests never depend on
    it, so substitute a fixed offset instead of failing to import."""
    import zoneinfo
    from datetime import timedelta, timezone

    try:
        zoneinfo.ZoneInfo("America/New_York")
    except zoneinfo.ZoneInfoNotFoundError:
        original = zoneinfo.ZoneInfo

        def fallback(key):
            try:
                return original(key)
            except zoneinfo.ZoneInfoNotFoundError:
                return timezone(timedelta(hours=-5), key)

        zoneinfo.ZoneInfo = fallback


def main() -> None:
    project = Path(sys.argv[1]).resolve()
    state = Path(sys.argv[2]).resolve()
    sys.path.insert(0, str(project))
    _tolerate_missing_tzdata()
    from fastapi.testclient import TestClient  # noqa: E402
    from backend.app.main import create_app  # noqa: E402

    requests = json.load(sys.stdin)
    profiles = state / "mail-servers.json"
    if not profiles.exists():
        profiles.write_text('{"servers": {}}\n', encoding="utf-8")
    ollama = os.environ.get("E2E_OLLAMA_URL")
    if ollama:
        from backend.app.mail import local_classifier  # noqa: E402

        local_classifier.OLLAMA_URL = ollama
    app = create_app(profiles, doctor_data_directory=state / "data")
    results = []
    operation = None
    with TestClient(app, base_url="http://127.0.0.1:48101", raise_server_exceptions=False) as client:
        for item in requests:
            kwargs = {"params": [tuple(pair) for pair in item.get("params", [])]}
            if "json" in item:
                kwargs["json"] = item["json"]
            if "form" in item or "files" in item:
                kwargs["content"] = _multipart(item.get("form", []), item.get("files", []))
                kwargs["headers"] = {"content-type": f"multipart/form-data; boundary={BOUNDARY}"}
            if "raw" in item:
                kwargs["content"] = item["raw"].encode("utf-8")
                kwargs["headers"] = {"content-type": item.get("content_type", "application/json")}
            path = item["path"]
            if operation is not None:
                path = path.replace("{operation_id}", operation)
            response = client.request(item["method"], path, **kwargs)
            result = {
                "status": response.status_code,
                "content_type": response.headers.get("content-type"),
                "content_disposition": response.headers.get("content-disposition"),
            }
            try:
                result["json"] = response.json()
                if isinstance(result["json"], dict) and isinstance(result["json"].get("operation_id"), str):
                    operation = result["json"]["operation_id"]
            except ValueError:
                result["text"] = response.content.decode("utf-8", "replace")
            results.append(result)
    json.dump(results, sys.stdout)


if __name__ == "__main__":
    main()
