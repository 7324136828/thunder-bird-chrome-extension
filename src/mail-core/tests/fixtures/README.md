# Parsing / audit / retention parity fixtures

These files back the golden parity tests in `mail-core/src/parsing.rs`
(`parity_with_python_fixtures`) and `mail-core/src/retention.rs`
(`parity_with_python_vectors`).

| File | Contents |
|------|----------|
| `*.eml` | Sample messages (phishing sample from `test_mail.py`, encoded headers, nested MIME, broken/missing boundaries, digest + delivery-status, header-less input, lone-CR line endings, ...). Written by `tools/make_fixtures.py`. |
| `expected.json` | Output of the original Python `parsing.py` / `audit.py` for every `.eml`: `header_view`, `audit_message` (minus `generated_at`), `extract_links`, the `walk()` part list, every `attachment_payload`, `addresses()` of To/Cc and the decoded Subject. |
| `retention_expected.json` | Output of the original `normalize_sender_address`, `sender_address`, `classify_headers` and `normalize_uid_validity` for edge-case inputs. |

## Regenerating

The scripts need only the Python 3.12 standard library plus copies of the
original modules. Never modify the original project.

```bash
cd mail-core/tests/fixtures/tools
mkdir -p orig && touch orig/__init__.py
cp <original-project>/backend/app/mail/parsing.py <original-project>/backend/app/mail/audit.py orig/
python -I make_fixtures.py ..
python -I make_expected.py .. ../expected.json
python -I make_retention_expected.py ../retention_expected.json <original-project>/backend
rm -r orig
```

`make_retention_expected.py` executes only the stdlib-only functions it
extracts from `schemas.py` and `retention.py`; it does not import the original
backend package (which would read settings and environment files).

## Known, intentional deviations

* `message/*` attachments: Python's `_part_bytes` returned `str()` of the
  sub-message list (e.g. `"[<email.message.EmailMessage object at 0x...>]"`),
  so their `size` and downloaded content were garbage. The Rust port returns
  the embedded message source instead; the parity test masks those sizes and
  `make_expected.py` stores `content_b64: null` for them.
* `extract_links` with an invalid bracketed host (`http://[zz::1]/`) raised
  `ValueError` in Python (an HTTP 500); the Rust port reports an empty domain.
* Audit delivery timing with a mix of naive (`-0000`) and aware Received dates
  raised `TypeError` in Python; the Rust port reports `delivery_seconds: null`.
