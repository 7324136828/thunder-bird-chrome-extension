# mail-backend API matrix

Every route of the original FastAPI backend
(`backend/app/main.py`, `backend/app/doctor/router.py`,
`backend/app/doctor/metrics_router.py`), with the Rust module that owns it.
Paths, parameters and JSON shapes stay identical so the copied React
frontend (`src/extension/app/src`) works unchanged. Each route module's doc
comment repeats its rows in more detail; `routes/mod.rs` merges the routers.

**Status:** all 54 Python routes are implemented (37 in main.py, 16 in
doctor/router.py, 1 in metrics_router.py). The only additions are routing
aliases that reproduce FastAPI behaviour: `GET /api/jobs/paste` (FastAPI
resolved it as `get_job("paste")`, so it answers 404 `Job not found`) and
the empty relative paths `GET /api/jobs/{job_id}/files/` and
`.../snapshot-files/` (Starlette's `path` converter matched them).
Known gaps are listed under [Intentional deviations](#intentional-deviations-from-the-python-backend).

The backend listens on `127.0.0.1:48101` by default (`--port`, `--addr`,
`MAIL_BACKEND_ADDR`); non-loopback listen addresses are refused at start-up.

## Conventions

- **acct**: the `require_account` dependency, query `account: str` (required).
  It is resolved *before* the route's other query parameters, so a locked
  account answers **401** even when other parameters are invalid; a missing
  `account` is reported as a 422 issue together with the others.
- **401**: always `{"detail": {"error": "password_required", "email": "<trimmed lowercase>"}}`
  (`MailError::CredentialRequired`). Body routes call `store.require(body.account)`
  and answer the same way. Exception: a failed login in `POST /api/accounts/unlock`
  is 401 `{"detail": str}`.
- **422**: FastAPI validation, `{"detail": [{"type", "loc", "msg", "input", "ctx"?}]}`
  (`crate::extract` + `mail_core::schemas`), or a string detail where Python raised
  `HTTPException(422, str(ValueError))` (`MailError::validation`).
  On `/api/settings` and `/api/accounts/unlock` the validation list is
  serialized with `ensure_ascii=True` and Python separators
  (`error::ASCII_VALIDATION_PATHS`). Password values in issues are
  replaced by `"[redacted]"` (see [Security model](#security-model)).
- **JSON bodies**: an empty or `null` body is a 422 `missing` issue at `["body"]`;
  malformed JSON is 422 `json_invalid` at `["body", <pos>]`; an undecodable body
  is 400 `There was an error parsing the body`. A body sent **without** a JSON
  `Content-Type` (absent, empty or another type) is not parsed: model validation
  gets the raw text and answers 422 `model_attributes_type`, as FastAPI does
  with its default `strict_content_type=True`.
- **502**: upstream failure: `MailOperationError` (IMAP/POP3), `MailSendError`,
  `LocalClassifierError`, `TrashOperationError` → `{"detail": str}`.
- **500**: `SettingsError` / `MailServersError` / `RetentionError` → `{"detail": str}`;
  panics → `{"detail": "Internal Server Error"}`.
- **409**: `RetentionConflictError`; **404**: `TrashOperationNotFound`.
- **413**: request body over the route's limit (see [Request size limits](#request-size-limits)).
- **403**: the Host / Origin / Sec-Fetch-Site guard, which runs before every route.
- Unknown path → 404 `{"detail":"Not Found"}`; wrong method → 405
  `{"detail":"Method Not Allowed"}` with `Allow`.
- `str(a..=b)` = `min_length`/`max_length`; `int(a..=b)` = `ge`/`le`;
  *strict* = pydantic `strict=True` (no string→int coercion).
- Frontend consumers: `api.*` = `api.ts`, `doctorApi.*` = `doctorApi.ts`,
  `emailMetricsApi.*` = `emailMetricsApi.ts`. The MCP server (`mail-mcp`) calls
  the same routes without an `Origin` header.
- **POP3** column notes: see [POP3 compatibility](#pop3-compatibility).

## Core (main.py)

| Method / path | Params / body | Success shape | Error statuses | Frontend consumer | Rust file |
|---|---|---|---|---|---|
| `GET /api/health` | — | 200 `{"status":"ok"}` | — | `api.health` | `routes/health.rs` (implemented) |
| `GET /api/settings` | — | 200 `{messages_per_page, signature, category_expiration_days{cat:int}, local_ai_model}` | 500 | `api.settings` | `routes/settings.rs` (implemented) |
| `PUT /api/settings` | JSON `MailPreferencesIn {messages_per_page: int strict 1..=200, signature?: str strict, category_expiration_days?: {EmailCategory: int strict <=MAX}\|null, local_ai_model?: str strict <=200\|null}` (exclude_unset) | 200 preferences (as GET) | 422 (ASCII-encoded list), 500 | `api.saveSettings` | `routes/settings.rs` (implemented) |
| `GET /api/accounts` | — | 200 `{"accounts":[public_dict]}` (display name via `accounts::sender_account`), session insertion order | 500 | `api.accounts` | `routes/accounts.rs` (implemented) |
| `POST /api/accounts/unlock` | JSON `UnlockIn {email: str 3..=320, password: str 1..=4096, profile_key?: str <=200, display_name?: str <=200, incoming_server?: <=253, incoming_port?: 1..=65535, incoming_protocol?: <=20, outgoing_server?, outgoing_port?, outgoing_protocol?, save_profile?: bool, incoming_mail_protocol?: "imap"\|"pop3"}` | 200 `{"account": public_dict}` | 400 `Enter a valid email address`, 404 `Profile not found`, 400 `No incoming (IMAP) server is configured for this account`, **401 `{detail: str}` on login failure**, 422 (ASCII, passwords redacted), 500 | `api.unlock` | `routes/accounts.rs` (implemented; POP3 extension) |
| `DELETE /api/accounts/{email}` | path `email` | 200 `{"locked": email lowercased}`; forgets image sources, remote-image cache and trash operations | 404 `Account is not unlocked` | `api.lock` | `routes/accounts.rs` (implemented) |
| `GET /api/mail/servers` | — | 200 `{"path", "servers": {key: profile}, "display_names": {...}}` (+ `display_names_error`) | 500 | `api.servers` | `routes/servers.rs` (implemented) |
| `PUT /api/mail/servers/{key}` | path `key` (sanitized, <=120); JSON `ServerProfileIn {email_address?, display_name?, incoming_server: 1..=253, incoming_port?=993, incoming_protocol?="SSL/TLS", outgoing_server: 1..=253, outgoing_port?=587, outgoing_protocol?="STARTTLS", incoming_mail_protocol?="imap"\|"pop3"}` | **201** `{"key", "profile"}` | 400 `Profile key is empty`, 422, 500 | `api.saveProfile` | `routes/servers.rs` (implemented) |
| `DELETE /api/mail/servers/{key}` | path `key` (exact) | 200 `{"deleted": key}` | 404 `Profile not found`, 500 | `api.deleteProfile` | `routes/servers.rs` (implemented) |
| `GET /api/mail/signature` | acct | 200 `{"account", "text", "multipart-path", "images"}` | 401, 422, 500 | `api.signature` | `routes/signature.rs` (implemented) |
| `PUT /api/mail/signature` | acct; multipart: one `signature` JSON field `{"text","uploads":[{"content_id"}]}` (<= `MAX_SIGNATURE_JSON_BYTES`) + <=20 `files` images (10 MiB each, 20 MiB total); `RequestSizeLimitLayer::signature()` | 200 signature dict | **size layer first**: 400 `Invalid request size`, 413 `Signature request exceeds maximum allowed size`; then 401, 400 malformed form / `Invalid multipart data.`, 413 file limits, 422, 500 | `api.saveSignature` | `routes/signature.rs` (implemented) |
| `GET /api/mail/signature/image` | acct; `content_id: str <=100` (req), `revision: str <=32 = ""` | 200 image bytes; `Cache-Control: no-store`, `X-Content-Type-Options: nosniff`, `Content-Security-Policy: default-src 'none'; sandbox` | 401, 400 `Invalid signature image identifier`, 404 `Signature image not found`, 422, 500 | `api.signatureImage` | `routes/signature.rs` (implemented) |
| `GET /api/mail/folders` | acct | 200 `{"folders":[...]}` | 401, 422, 502 | `api.folders` | `routes/mail.rs` (implemented; POP3: INBOX only) |
| `GET /api/mail/messages` | acct; `folder <=500 ="INBOX"`, `offset ge 0 =0`, `limit 1..=200 \| None`→prefs, `query <=200 =""`, `read_status: all\|unread\|read`, `sender_domain: list[str]` (repeated key), `category: Literal[5]\|None`, `expired_only: bool=false` | 200 `{"total","offset","limit","messages":[...]}` newest first | 401, 422 (list or string), 409, 500, 502 | `api.messages` | `routes/mail.rs` (implemented; POP3 works) |
| `GET /api/mail/message` | acct; `folder <=500 ="INBOX"`, `uid ge 1` (req), `mark_seen: bool=true` | 200 message view (registers image sources) | 401, 422, 502 | `api.message` | `routes/mail.rs` (implemented; POP3 works, `mark_seen` no-op) |
| `DELETE /api/mail/message` | acct; `folder <=500`, `uid ge 1`, `trash <=500 =""`, `uid_validity <=10 \| None` | 200 `{"deleted": uid}` | 401, 422 `UID validity must be a positive 32-bit decimal number`, 502; POP3 → 400 | `api.deleteMessage` | `routes/mail.rs` (implemented; IMAP only) |
| `GET /api/mail/message/eml` | acct; `folder`, `uid ge 1` | 200 `message/rfc822`, `Content-Disposition: attachment; filename="message-{uid}.eml"`, nosniff, no-store, CSP `default-src 'none'; sandbox` | 401, 422, 502 | `api.messageEmlUrl` (link) | `routes/mail.rs` (implemented; POP3 works) |
| `GET /api/mail/message/attachment` | acct; `folder`, `uid ge 1`, `index ge 0` | 200 bytes, `Content-Disposition: attachment; filename="..."` (`"\\\r\n`→`_`), nosniff, no-store, CSP `default-src 'none'; sandbox` | 401, 422, 502 | `api.attachmentUrl` (link) | `routes/mail.rs` (implemented; POP3 works) |
| `POST /api/mail/message/flags` | JSON `FlagsIn {account 3..=320, folder 1..=500, uid ge 1, seen?: bool, flagged?: bool}` | 200 `{"uid","flags","seen","flagged"}` (real server FLAGS) | 401, 422, 502; POP3 → 400 | `api.setFlags` | `routes/mail.rs` (implemented; IMAP only) |
| `POST /api/mail/messages/delete` | JSON `DeleteMessagesIn {account, folder, uids: [int strict 1..=2^32-1], trash <=500, uid_validity?: ^[1-9][0-9]{0,9}$}` | 200 `{"deleted":[uid]}` | 401, 422, 502; POP3 → 400 | `api.deleteMessages` | `routes/mail.rs` (implemented; IMAP only) |
| `PUT /api/mail/message/retention` | JSON `MessageRetentionIn {account, folder, uid strict, uid_validity strict pattern, category?: EmailCategory\|null, expiration_days?: int strict <=MAX\|null}` | 200 `{"uid","folder",...metadata}` | 401, 409, 422, 500, 502 | `api.updateRetention` | `routes/retention.rs` (implemented; POP3 works) |
| `POST /api/mail/message/sender-rule` | JSON `MessageSenderRuleIn {account, folder, uid, uid_validity, category, expected_category_revision?: int strict ge 0}` | 200 `{"uid","folder",...metadata,"rule"}` | 401, 409 `The email category changed. Refresh the message before saving a sender rule.`, 422, 500, 502 | `api.saveSenderRule` | `routes/retention.rs` (implemented; POP3 works) |
| `GET /api/mail/sender-rules` | acct; `folder: str 1..=500 \| None` | 200 `{"rules":[...]}` | 401, 422, 500 | `api.senderRules` | `routes/retention.rs` (implemented) |
| `DELETE /api/mail/sender-rules` | acct; `sender: str 3..=320` (req), `folder: str 1..=500` (req), `expected_revision: int ge 1 \| None` | 200 `{"deleted": bool}` (absent rule → `false`, no server contact) | 401, 409, 422, 500, 502 | `api.deleteSenderRule` | `routes/retention.rs` (implemented; POP3 works) |
| `GET /api/mail/classifier/status` | `model: str <=200 \| None` (no acct) | 200 `{"available","model","installed_models","error"}` | 422, 500 | `api.classifierStatus` | `routes/classifier.rs` (implemented) |
| `POST /api/mail/message/classify` | JSON `MessageClassifyIn {account, folder, uid strict, uid_validity strict}` | 200 `{"uid","folder",...metadata}` | 401, 409, 422, 500, 502 (incl. invalid classification) | `api.classifyMessage` | `routes/classifier.rs` (implemented; POP3 works) |
| `POST /api/mail/message/image` | JSON `RemoteImageIn {account, folder, uid 1..=2^32-1, url 1..=4096, retry?: bool}` | 200 image bytes; no-store, nosniff, `CSP: default-src 'none'; sandbox` | 400 unsupported URL, 401, 403 `This image was not found in the selected email`, 422, 502 `The remote image could not be downloaded safely` | `api.messageImage` | `routes/images.rs` (implemented; POP3 works) |
| `POST /api/mail/trash/prepare` | JSON `TrashPrepareIn {account, folder 1..=500, archive: bool strict}` | 200 `{"operation_id","count","archive","filename"}` | 401, 422, 502; POP3 → 400 | `api.prepareTrash` | `routes/trash.rs` (implemented; IMAP only) |
| `GET /api/mail/trash/{operation_id}/archive` | acct | 200 ZIP (`FileResponse`), no-store, nosniff | 401, 404, 502 | `api.trashArchiveUrl` (link) | `routes/trash.rs` (implemented) |
| `POST /api/mail/trash/{operation_id}/empty` | JSON `TrashEmptyIn {account}` | 200 `{"deleted","remaining"}` | 401, 404, 422, 502; POP3 → 400 | `api.emptyTrash` | `routes/trash.rs` (implemented; IMAP only) |
| `DELETE /api/mail/trash/{operation_id}` | acct | 200 `{"discarded": operation_id}` | 401, 404, 502 | `api.discardTrash` | `routes/trash.rs` (implemented) |
| `POST /api/mail/send` | JSON `SendIn {account, to/cc/bcc <=100, subject <=998, text, html, in_reply_to <=998, references <=2048, uploads <=20}`; `RequestSizeLimitLayer::send_json()` (8 MiB) | 200 `{"sent":true,"message_id","from","sent_saved","sent_folder","warning"?}` | 400 `Invalid request size`, 413, 422 `Use the attachment upload endpoint for messages with files`, 422, 401, 502 | `api.send` (no uploads) | `routes/send.rs` (implemented; POP3: `sent_saved:false`) |
| `POST /api/mail/send/files` | multipart: one `message` field (JSON `SendIn`, <=8 MiB, `uploads: [{content_id, disposition}]`) + `files` (<=20, 10 MiB each, 20 MiB total); `RequestSizeLimitLayer::send_files()` (30 MiB) | 200 as above | 400 invalid size / `Invalid multipart data.`, 413, 422, 401, 502 | `api.send` (with uploads) | `routes/send.rs` (implemented) |
| `GET /api/mail/audit` | acct; `folder <=500 ="INBOX"`, `uid ge 1` | 200 audit report | 401, 422, 502 | `api.audit` | `routes/audit.rs` (implemented; POP3 works) |
| `POST /api/audit/eml` | JSON `PasteAuditIn {content: str min 1}`; body limit 64 MiB | 200 audit report | 413, 422 | `api.auditEml` | `routes/audit.rs` (implemented) |
| `GET /api/email-metrics/schedule` | — | 200 `{"enabled":true,"timezone","weekday":5,"hour":18,"minute":0,"accounts":[{email,next_run_at,last_run_at,pending_runs,unlocked,last_error}]}` | — | `emailMetricsApi.schedule` | `routes/metrics.rs` (implemented) |

## Inbox Doctor (doctor/router.py)

`JobOut` = `{id, filename, file_size, status, progress, stage, log, error_message, created_at, completed_at, output_files[], source_kind, account_email, days, downloaded_messages, total_messages, snapshot_available, snapshot_at, run_kind, scheduled_for, window_start, window_end}`.
"capacity" = `runner.ensure_capacity()` → 429 `{"detail": str}`.

| Method / path | Params / body | Success shape | Error statuses | Frontend consumer | Rust file |
|---|---|---|---|---|---|
| `POST /api/jobs` | multipart `files` (1..=1000; .eml/.zip/.mbox/.json; >=1 data file); `RequestSizeLimitLayer::doctor_upload(max_upload_bytes)` (stream count, +1 MiB); parts spooled (1 MiB in memory, then an anonymous 0600 temp file) | **201** `JobOut` | 413 `Request exceeds maximum allowed size`, 429, 400 `Upload between 1 and 1000 files` / `Unsupported file type: {name}. Accepted: .eml, .zip, .mbox, .json` / `Upload must include at least one .eml, .zip, or .mbox file` / staging error / `There was an error parsing the body`, 422 | `doctorApi.upload` | `routes/doctor.rs` (implemented) |
| `POST /api/jobs/paste` | JSON `PasteJobIn {content: str 1..=200 MiB, filename?: str <=1000}`; same size layer | **201** `JobOut` | 413, 429, 400 `Pasted source exceeds maximum allowed size`, 422 | `doctorApi.paste` | `routes/doctor.rs` (implemented) |
| `GET /api/mail/providers` | `email: str <=320 = ""` | 200 `{"provider","imap_server","imap_port","use_ssl","oauth_configured","oauth_callback_url","known_domains"}` | 422 | `doctorApi.discover` | `routes/doctor.rs` (implemented) |
| `POST /api/mail/jobs/account` | JSON `AccountJobIn {account 3..=320, days 1..=3650 =7}` | **201** `JobOut` | 401, 400 `Inbox Doctor mailbox audits require an IMAP account.` (POP3), 429, 422 | `doctorApi.account` | `routes/doctor.rs` (implemented; IMAP only) |
| `POST /api/mail/jobs` | JSON `MailCredentialsIn {email, password 1..=4096, days, imap_server?, imap_port?, use_ssl?, use_app_password=false, incoming_protocol?: SSL/TLS\|STARTTLS\|NONE}` | **201** `JobOut` | 400 `Enter a valid email address` / Microsoft OAuth-only / Google app-password rules, 429, 422 (password redacted) | `doctorApi.connect` | `routes/doctor.rs` (implemented) |
| `POST /api/mail/oauth/start` | JSON `OAuthStartIn {provider, email, days}`; the request's extension `Origin` is stored with the flow | 200 `{"authorization_url","state","message_origin"}` | 400 (email / `Unsupported OAuth provider` / provider mismatch), 429, 503, 422 | `doctorApi.oauth` | `routes/doctor.rs` (implemented) |
| `GET /api/mail/oauth/{provider}/callback` | `state <=200`, `code <=8192`, `error <=500` (all default "") | 200 HTML posting `{"type":"email-doctor-oauth","jobId"\|"error"}` to the extension origin that started the flow (else `frontend_url`); no-store, `Referrer-Policy: no-referrer`; query never logged | 422 | OAuth popup (`DoctorConnect.tsx` message listener) | `routes/doctor.rs` (implemented; exempt from the Sec-Fetch-Site rule) |
| `GET /api/jobs` | — | 200 `[JobOut]` (log blank) | — | `doctorApi.jobs` | `routes/doctor.rs` (implemented) |
| `GET /api/jobs/{job_id}` | — | 200 `JobOut` (+ output_files when completed) | 404 `Job not found` | `doctorApi.job` | `routes/doctor.rs` (implemented; also serves `GET /api/jobs/paste`) |
| `GET /api/jobs/{job_id}/files` | — | 200 `{"files":[...]}` | 404, 400 `Job is not completed` | `doctorApi.files` | `routes/doctor.rs` (implemented) |
| `GET /api/jobs/{job_id}/snapshot-files` | — | 200 `{"files":[...]}` | 404 `Job not found` / `No audit snapshot is available yet` | `doctorApi.files(id, true)` | `routes/doctor.rs` (implemented) |
| `GET /api/jobs/{job_id}/files/{*rel_path}` | — (also the empty path `.../files/`) | 200 bytes (`.md`/`.jsonl` → text/plain), nosniff, no-store, CSP `sandbox; default-src 'none'; style-src 'unsafe-inline'; img-src data:` on **every** file | 404 `Job not found` / `File not found`, 400 `Job is not completed` | `doctorApi.fileUrl`, `doctorApi.text` | `routes/doctor.rs` (implemented) |
| `GET /api/jobs/{job_id}/snapshot-files/{*rel_path}` | — (also `.../snapshot-files/`) | as above | 404 incl. `No audit snapshot is available yet` | `doctorApi.fileUrl(.., true)`, `doctorApi.text` | `routes/doctor.rs` (implemented) |
| `POST /api/jobs/{job_id}/discard` | — | 200 `JobOut` | 404, 400 `Job was already discarded` | `doctorApi.discard` | `routes/doctor.rs` (implemented) |
| `GET /api/jobs/{job_id}/download-zip` | — | 200 ZIP, `Content-Disposition: attachment; filename*=utf-8''{stem}_audit.zip`, no-store, nosniff | 404 `Job not found` / `ZIP archive not found`, 400 | `doctorApi.zipUrl` (link) | `routes/doctor.rs` (implemented) |

## Metrics (doctor/metrics_router.py)

| Method / path | Params / body | Success shape | Error statuses | Frontend consumer | Rust file |
|---|---|---|---|---|---|
| `GET /api/email-metrics` | `account: str <=320 \| None` (strip+lower; non-empty needs one `@`, no whitespace/control) | 200 `{"runs":[...],"domains":[...],"accounts":[...]}` | 400 `Enter a valid account email address`, 422 | `emailMetricsApi.history` | `routes/metrics.rs` (implemented) |

## Request size limits

Ports of the ASGI middlewares (`limits.rs`), plus a global default that
Python did not have.

| Route | Layer | Limit | Declared `Content-Length` check | Message |
|---|---|---|---|---|
| `POST /api/mail/send` | `RequestSizeLimitLayer::send_json()` | 8 MiB | yes (400 `Invalid request size` if malformed/repeated) | `Request exceeds maximum allowed size` |
| `POST /api/mail/send/files` | `RequestSizeLimitLayer::send_files()` | 30 MiB | yes | `Request exceeds maximum allowed size` |
| `PUT /api/mail/signature` | `RequestSizeLimitLayer::signature()` | 20 MiB + 1 552 KiB + 64 KiB | yes | `Signature request exceeds maximum allowed size` |
| `POST /api/jobs`, `POST /api/jobs/paste` | `RequestSizeLimitLayer::doctor_upload(max_upload_bytes)` | `MAX_UPLOAD_BYTES` (200 MiB) + 1 MiB | no (stream count only) | `Request exceeds maximum allowed size` |
| `POST /api/audit/eml` | `limits::default_body_limit` | 64 MiB (`AUDIT_PASTE_BODY_LIMIT`) | yes | `Request exceeds maximum allowed size` |
| every other route | `limits::default_body_limit` | 4 MiB (`DEFAULT_BODY_LIMIT`) | yes | `Request exceeds maximum allowed size` |

The limit is checked on the declared length first, then on streamed (chunked)
bytes; whatever the handler answered, an over-limit body becomes the JSON 413.
axum's own `DefaultBodyLimit` is disabled so these layers are the only limits.

## Security model

The Python backend served a web frontend on `http://localhost:3741` behind
`CORSMiddleware(allow_origins=CORS_ORIGINS)`. This port is called by the
browser extension and by local tools (the MCP server), so `security.rs`
replaces that with an extension-only policy. The middleware order
(`lib.rs::apply_middleware`, outermost first) is: request log → guard → CORS
→ JSON error normalization → panic catcher → body limit → routes.

- **Loopback listen only.** `main.rs` refuses non-loopback `--addr` /
  `MAIL_BACKEND_ADDR` values: the API serves unlocked mailboxes, and a LAN
  client could forge `Host` and omit `Origin`.
- **Loopback `Host`.** The `Host` header (or the HTTP/2 authority) must be an
  IPv4 literal in `127.0.0.0/8` (dotted quad only, e.g. `127.0.0.1`,
  `127.0.0.2`; no shorthand, octal or integer forms), `localhost` or `[::1]`,
  with an optional numeric port. Anything else is 403 `Forbidden: requests must
  be addressed to 127.0.0.1 or localhost ...`. This defeats DNS rebinding: a page
  on `evil.example` that resolves to 127.0.0.1 still sends `Host: evil.example`.
- **Extension-id allow-list.** A request with an `Origin` is accepted only
  from `chrome-extension://<id>`, `extension://<id>` (Edge) or
  `moz-extension://<id>` whose id is allowed. By default only this
  extension's pinned id **`hhhanbkdjaecdfoclhpoicmfhejdbkjl`** is allowed
  (`security::DEFAULT_EXTENSION_ID`; Chrome and Edge derive it from the
  manifest `key`). `MAIL_BACKEND_EXTENSION_IDS` (comma-separated ids or full
  origins, read once at first use) **replaces** the list, for example for an
  unpacked copy without the key or for Firefox, whose `moz-extension://` ids
  are random per install and are therefore only allowed when listed. The value
  `*` trusts every extension id and is logged as INSECURE (development only).
  Invalid entries are ignored; if none remains the default is used. The
  allowed ids are printed at start-up. Any other `Origin` (web pages, `null`,
  `http://localhost:3741`, other extensions) is 403 `Forbidden: only the
  browser extension may use this service (Origin ... refused).`
- **Sec-Fetch-Site rule.** A request without `Origin` (MCP server, curl,
  tests, a URL typed into a tab) is accepted unless `Sec-Fetch-Site` is
  `cross-site` or `same-site`, which marks an `<img>`/`<script>`/form probe from
  a web page (403). A typed URL sends `Sec-Fetch-Site: none`.
- **OAuth callback exemption.** `GET /api/mail/oauth/{provider}/callback` is
  reached by the provider's top-level cross-site redirect without `Origin`.
  For that one path, document navigations (`Sec-Fetch-Mode: navigate`,
  `Sec-Fetch-Dest: document`, or the headers absent) pass the Sec-Fetch-Site
  rule. The page only completes a flow whose unguessable `state` the
  extension started and posts the result to that extension's origin, so a web
  page gains nothing readable from it.
- **CORS reflection.** CORS headers are reflected only for allowed extension
  origins (no wildcard, no credentials): methods GET/POST/PUT/DELETE/OPTIONS,
  request headers `Content-Type`, `Accept`, `Accept-Language`, `Cache-Control`,
  exposed `Content-Disposition`, `Access-Control-Allow-Private-Network`,
  max-age 600 s. Refused requests get no CORS headers.
- **Body limits.** 4 MiB by default and 64 MiB for `/api/audit/eml`, on top of
  the per-route upload limits (see [Request size limits](#request-size-limits)).
- **Password redaction in 422s.** The `input` of an issue whose `loc` ends in
  `password` (except `missing`, whose input is the enclosing object), every
  `"password"` member inside an issue's
  `input` or `ctx` (for example the whole body echoed by a `missing` issue) and
  a raw-text body echoed at `loc: ["body"]` that mentions `password` are
  replaced by `"[redacted]"` (`mail_core::schemas::redact_issue`, applied in
  `ValidationIssue::to_json` and `ApiError::new`). The rest of the issue is
  unchanged.
- **Download hardening.** Attachments, `.eml` downloads, signature images and
  proxied remote images carry `X-Content-Type-Options: nosniff`,
  `Cache-Control: no-store` and `Content-Security-Policy: default-src 'none';
  sandbox`; Inbox Doctor job files carry nosniff, no-store and the sandbox CSP
  on every file.
- **Secrets.** Passwords live only in the in-memory session store and are
  cleared on Ctrl+C shutdown. The request log records method, path, status and
  duration, never the query string (account emails, OAuth codes).

## POP3 compatibility

POP3 accounts (`incoming_mail_protocol: "pop3"` on unlock or in a server
profile) are a new feature; the Python app was IMAP-only. The scope is
**list and read the INBOX** (`mail_core::pop3`). The maildrop is never
modified (no `DELE`).

| Works for POP3 | Refused for POP3 |
|---|---|
| `POST /api/accounts/unlock` (`STAT` after login; default port 995 instead of 993) | `POST /api/mail/message/flags` → 400 |
| `GET /api/mail/folders` (only `INBOX`; any other folder → 502 `The server would not open folder '…'`) | `DELETE /api/mail/message` → 400 |
| `GET /api/mail/messages` (newest first; every message is unread, so `read_status=read` is always empty) | `POST /api/mail/messages/delete` → 400 |
| `GET /api/mail/message` (`mark_seen` is a no-op), `/eml`, `/attachment` | `POST /api/mail/trash/prepare` and `/{id}/empty` → 400 (`archive` / discard → 404, since no operation can exist) |
| `PUT /api/mail/message/retention`, `POST /api/mail/message/classify`, sender rules (`POST`/`GET`/`DELETE`) | `POST /api/mail/jobs/account` → 400 `Inbox Doctor mailbox audits require an IMAP account.` |
| `POST /api/mail/message/image`, `GET /api/mail/audit` | The weekly audit scheduler skips POP3 sessions (the window stays pending, like a locked account) |
| `POST /api/mail/send` and `/send/files` (no Sent copy: 200 with `sent_saved: false` and the warning) | |

The 400 detail is `This operation requires an IMAP account. POP3 accounts can
only list and read the INBOX.` (`pop3::IMAP_ONLY_MESSAGE`).

- **UIDs** are 1-based POP3 message numbers of the current maildrop.
- **Synthetic `uid_validity`.** A positive 32-bit decimal derived from a
  stable hash of the full `UIDL` list (from message sizes when the server
  refuses `UIDL`). It changes whenever the maildrop changes, so stale message
  numbers are rejected with the same 409/422 rules as IMAP. Consequence:
  per-message manual and AI retention choices saved under an older epoch stop
  applying after the maildrop changes; sender rules keep working because
  across epochs they compare arrival times.
- **Arrival time** (`internal_date`, `received_at`) is the date of the topmost
  parseable `Received:` header, falling back to `Date:`, else unknown.
- **Response cap.** One multi-line response (`RETR`, `TOP`, `LIST`, `UIDL`)
  is capped at 100 MiB (`pop3::MAX_RESPONSE_BYTES`); a larger reply is a
  connection error (502).
- **Extension UI.** IMAP-only actions (Flag, Mark read/unread, Delete,
  select + Move to Trash, Trash archive/empty, the read-status filter) are
  hidden for POP3 accounts, with a compatibility-mode note and a sidebar
  label; `App.tsx` also refuses those handlers.

## Intentional deviations from the Python backend

Collected from the doc comments of `mail-core`, `mail-doctor` and
`mail-backend` and from the fix-agent reports. The linked module holds the
details.

### HTTP layer and security (`mail-backend`)

- Only the pinned extension id (or the ids in `MAIL_BACKEND_EXTENSION_IDS`)
  may call the backend; Python's CORS allowed its web frontend origin
  (`security.rs`).
- `Host` must be loopback (127.0.0.0/8 literal, `localhost`, `[::1]`); Python
  did not check it (`security.rs`).
- Global request body limits: 4 MiB by default, 64 MiB for `/api/audit/eml`,
  JSON 413 when exceeded; Python had no cap (`limits.rs`).
- Passwords in 422 issue `input`/`ctx` are replaced by `"[redacted]"`;
  pydantic/FastAPI echo them (`error.rs`, `mail_core::schemas::redact_issue`).
- Valid JSON sent without a JSON `Content-Type` gets 422
  `model_attributes_type`. This matches FastAPI's `strict_content_type`
  default; an earlier version of this port parsed it as JSON (`extract.rs`).
- Attachment and `.eml` downloads add `X-Content-Type-Options: nosniff`,
  `Cache-Control: no-store` and `Content-Security-Policy: default-src 'none';
  sandbox`; Python sent only `Content-Disposition` (`routes/mail.rs`).
- Unhandled exceptions are JSON 500 `{"detail":"Internal Server Error"}`
  instead of Starlette's plain-text body (`error.rs`).
- Ordinary JSON responses keep serde_json float formatting (`1e16` vs Python's
  `1e+16`, `1e-5` vs `1e-05`); only the ASCII re-encoded 422 bodies reproduce
  Python's float repr. Documented, not changed (`error.rs`).
- Starlette's trailing-slash redirect (`/api/health/` → 307) is not
  reproduced; such paths answer 404.
- `/docs`, `/redoc` and `/openapi.json` (FastAPI's generated docs) are not
  served.
- Encoded slashes in path parameters (`DELETE /api/accounts/a%2Fb@x`,
  `PUT /api/mail/servers/a%2Fb`) reach the handler decoded; Starlette routed on
  the decoded path and answered 404 (`routes/accounts.rs`, `routes/servers.rs`).
- A JSON body with a lone UTF-16 surrogate escape (`"\ud800"`) is rejected
  by the JSON decoder (422 `json_invalid`) on `PUT /api/settings` and
  `POST /api/audit/eml`; Python accepted it and failed later or encoded it as
  `?` (`routes/settings.rs`, `routes/audit.rs`).
- Multipart (send, signature): the RFC 2046 preamble before the first
  boundary is accepted and a truncated final part is a 400 `Invalid multipart
  data.`; python-multipart rejected the preamble and silently dropped the
  truncated part (`routes/send.rs`, `routes/signature.rs`).
- Doctor uploads: a multipart body the parser cannot read is 400 `There was
  an error parsing the body` (`routes/doctor.rs`).
- Query/body UIDs above the 32-bit IMAP range never reach the server: reads
  answer 502 `The server returned no data for message UID {uid}`, flag
  updates 502 `The server could not update flag …`, deletes 502 `Select
  between 1 and 500 valid message UIDs`. Python sent them and the server's
  `BAD` escaped as a 500 (`routes/mail.rs`, `routes/audit.rs`).
- `POST /api/accounts/unlock`: a POP3 unlock without a port defaults to 995;
  a profile port outside 1..=65535 is a 500 (Python's `OverflowError` was a
  500 too); a failing `audit_scheduler.register` is the generic 500 after the
  account was unlocked (`routes/accounts.rs`).
- Trash archive download: Starlette `FileResponse` headers without `etag` and
  without range support; a file that vanished before the response is a JSON
  500 (`routes/trash.rs`).
- Inbox Doctor's `public_backend_url` defaults to `http://localhost:<actual
  listen port>` when `PUBLIC_BACKEND_URL` and `BACKEND_PORT` are unset,
  instead of the fixed `BACKEND_PORT` default 48101 (`state.rs`).

### Mail logic (`mail-core`)

- IMAP, POP3 and SMTP host lookups retry twice (under one second) and then
  fall back to the address that last worked for the same host and port within
  the past hour, so a short DNS outage does not fail the request; Python
  failed on the first resolver error (`mail-proto/src/resolve.rs`).
- IMAP literals and POP3 multi-line responses over 100 MiB fail with a
  connection error (502); `imaplib`/`poplib` had no cap (`imap.rs`,
  `pop3.rs`).
- `set_flags` returns the real `FLAGS` from the server; Python always
  returned `[]` because of an `imaplib` parsing bug (`imap.rs`).
- IMAP FETCH/LIST responses are parsed with a tokenizer (one malformed
  response is skipped); TLS certificates are verified against the system
  trust store; command arguments containing CR/LF are rejected; socket or
  protocol failures that escaped as 500 in Python are 502 `The mail server
  connection failed: …` (`imap.rs`).
- POP3 support is new (see [POP3 compatibility](#pop3-compatibility)).
- SMTP: a hand-written `smtplib` port; login offers PLAIN and LOGIN only (no
  CRAM-MD5); the EHLO name is the local address literal instead of
  `getfqdn()`; inputs that crashed Python with `UnicodeEncodeError` get the
  matching `MailSendError`; MIME output is byte-identical to CPython 3.14
  except for how RFC 2047 encoded words are chunked (`smtp.rs`).
- Recipient validation: inputs that crashed Python's address parser are
  rejected with `Enter a valid recipient email address` (`schemas.rs`).
- Settings: `initialize_mail_servers` takes an optional seed file instead of
  the project root; rewriting `settings.json` keeps key order; a file with a
  lone surrogate escape is reported as unreadable (`SettingsError`, 500)
  (`settings.rs`).
- Trash: preparations are serialized by their own lock instead of holding the
  registry lock for the whole preparation; operation ids are 43 URL-safe
  characters from two v4 UUIDs; non-`BadZipFile` `testzip()` failures are
  reported as "could not be verified" (`trash.rs`).
- Local classifier: httpx per-operation timeouts become one total
  per-request timeout; request JSON whitespace may differ (`classifier.rs`).
- Parsing: the size of `message/*` attachments is not Python's length of
  `str()` of the sub-message list (`parsing.rs` tests).

### Inbox Doctor (`mail-doctor`)

- The sandbox CSP is sent on every served job file (Python: `.html` only)
  (`runner.rs`, `routes/doctor.rs`).
- Upload spool files are anonymous OS temp files (0600, deleted when
  closed); Python's `SpooledTemporaryFile` rolls over to `TemporaryFile`,
  which has the same properties (`routes/doctor.rs`).
- ZIP uploads are read by a port of CPython's `zipfile` (`pyzip.rs`) instead
  of the `zip` crate: duplicate entry names are kept (`x.eml`, `x_1.eml`, ...,
  all counted toward `max_archive_members`); stored, deflate, bzip2, LZMA and
  Zstandard (Python 3.14 behaviour) are decoded; deflate64 and other methods
  are refused. Corrupt-stream exceptions that Python does not translate
  (`zlib.error`, `LZMAError`, `EOFError`, ...) all become `Cannot read the
  uploaded ZIP archive`.
- When Python's MIME parser raises from an internal assert (practically
  unreachable), `header_str` keeps the raw value; the eml stage still
  reproduces Python's outcome (file skipped / no attachments / empty snippet)
  (`stages/py_email.rs`, `stages/eml_extract.rs`).
- `json.loads` port: a lone UTF-16 surrogate escape becomes U+FFFD
  (`stages/pyjson.rs`).
- Mailbox audits and the weekly scheduler are IMAP only (POP3 → 400 / skipped).

### MCP server (`mail-mcp`)

- `mail_read_message` is annotated `readOnlyHint=false` because
  `mark_seen=true` changes `\Seen`; hosts may ask before reads.
- `mail_send` is annotated `destructiveHint=false` (it only adds data, per the
  MCP definition); `openWorldHint=true` marks it as reaching outside the
  mailbox. It is the only open-world tool.
- No `confirm` flag on `mail_send` or `mail_move_to_trash`, by design; only
  `mail_empty_trash` requires `confirm=true` (`mail-mcp/README.md`, Security
  model > Confirmation policy). Tools that return message content warn that it
  is untrusted data, and the server instructions forbid acting on
  instructions inside emails.

### Browser extension (`src/extension`)

- The extension id is pinned by the manifest `key`
  (`hhhanbkdjaecdfoclhpoicmfhejdbkjl`); `build-extension.mjs` checks it.
- Backend URL policy: only `http://127.0.0.1` or `http://localhost` (any
  port); remote hosts and https are refused, and `[::1]` is no longer accepted
  (Chrome CSP limitation; use `localhost`). `connect-src` and
  `host_permissions` match.
- The connect form's incoming port also follows the default when the
  Security select changes (993↔143, 995↔110), and only when the current port
  is a default; the original form changed nothing on Security change.
- POP3 accounts hide the read-status filter and every IMAP-only action (see
  [POP3 compatibility](#pop3-compatibility)).
