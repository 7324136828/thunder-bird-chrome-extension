# Claude Handoff — Thunderbird Chrome Extension / Rust Backend / MCP Port

Current state as of 2026-11-27: **the port is feature-complete and verified.** All 54 routes of the original backend (37 core, 16 Inbox Doctor, 1 metrics) are implemented in Rust, and every intentional difference is documented. `agent.md` holds the short design memory. `src/mail-backend/API_MATRIX.md` is the authoritative route, security and deviation reference.

## 1. Mission

Port `../original-project/20261011-thunderbird` (Python/FastAPI + React) with the **full feature set** into:

1. a Chrome/Edge Manifest V3 extension (`src/extension`);
2. a Rust loopback backend: IMAP, compatibility-level POP3, SMTP, categorization, retention, trash workflow, remote-image proxy, signatures, audit, metrics, Inbox Doctor (`src/mail-*`);
3. an MCP stdio server for read/send/trash/categorize and related operations (`src/mail-mcp`).

## 2. Hard constraints (still binding)

- `original-project/` is read-only reference material. Never modify it.
  - Anything that runs its Python code must use `python -B` / `PYTHONDONTWRITEBYTECODE=1`, or work on copies.
- Do not copy or commit secrets. In particular, do not copy `.env` files or OAuth credentials from the original tree.
- Passwords are memory-only in the backend. Restarting the backend locks every account. Server profiles and non-secret settings may be persisted.
- MCP never stores credentials. It only uses accounts already unlocked in the backend, through the loopback API.
- The backend binds loopback only and has no permissive CORS (see §5).
- POP3 is compatibility level only: unlock, list INBOX, read. Mutating operations answer 400.
- Commit or push only when the user asks. The repo has a single "Initial commit"; everything under `src/`, this file and `agent.md` is still untracked.

## 3. Layout

```text
thunder-bird-chrome-extension/
├── CLAUDE.md, agent.md, README.md, LICENSE, .gitignore
├── extension/ extension-src/ tools/   # EMPTY leftover scaffolds; safe to delete (deletion was not permitted to the agent)
└── src/
    ├── Cargo.toml / Cargo.lock        # workspace; serde_json "preserve_order" enabled (Python dict order)
    ├── run-backend.{ps1,bat,sh}       # cargo run --release -p mail-backend
    ├── mail-proto/    # blocking imaplib/poplib-style IMAP & POP3 clients, TLS/STARTTLS transport;
    │                  # feature "testkit": fake IMAP/POP3/SMTP servers used by all integration tests
    ├── mail-core/     # synchronous ports of backend/app/mail/*.py + settings/servers/sessions/schemas
    ├── mail-doctor/   # Inbox Doctor: jobs runner, pipeline stages, reports, SQLite db, metrics,
    │                  # weekly scheduler, OAuth, mailbox download, CPython zipfile port (pyzip.rs)
    ├── mail-backend/  # axum 0.8 HTTP server (127.0.0.1:48101), routes/*.rs, security.rs, limits.rs
    │                  # API_MATRIX.md = route/security/POP3/deviation reference
    ├── mail-mcp/      # rmcp stdio server → MAIL_BACKEND_URL (README: tools, registration)
    └── extension/     # MV3 extension: manifest.json (pinned "key"), app/ (React+Vite), tools/, tests/
                       # README: build, load unpacked, options, CSP, backend address policy
```

Key implementation patterns:
- **Blocking work:** handlers run blocking mail code through `run_blocking`/`spawn_blocking`.
- **Errors:** `MailError` maps to 502/500/409/404/401/422/400. The 401 body is `{"detail":{"error":"password_required","email":...}}`. FastAPI-compatible 422s come from `extract.rs` and `mail-core/src/schemas.rs`.
- **POP3 dispatch:** `mail_core::imap` read functions dispatch to `mail_core::pop3` when `account.is_pop3()`. Mutating operations return `pop3::imap_only()`.
- **State:** `AppState` (`mail-backend/src/state.rs`) owns sessions, image sources, retention, trash operations, the doctor `JobRunner` and the weekly audit scheduler. `shutdown()` closes them all.

## 4. Verified state (2026-11-27)

| Check | Result |
|---|---|
| `cargo build --workspace --all-targets --all-features` | clean, 0 warnings |
| `cargo clippy --workspace --all-targets --all-features` | clean |
| `cargo test --workspace --all-features` | 1144 passed, 0 failed. 2 ignored: Python differential (below); 2 doc examples marked `ignore` |
| `cargo test -p mail-backend --all-features --test e2e_differential -- --ignored` | 2/2 pass. Same request sequences replayed against the Python backend (needs Python 3 + fastapi); outputs identical apart from documented deviations |
| `npm run typecheck`, `npm test` (23), `npm run build:extension` | pass |
| `npm run test:e2e` (headless Chrome, extension loaded, mock backend) | 42/42 |
| `npm run test:e2e:real` (extension + real Rust backend + fake IMAP/POP3/SMTP) | 33/33 |

Test coverage includes:
- fake-server IMAP/POP3/SMTP integration tests;
- golden and parity tests against Python outputs, for MIME, ZIP, signatures sanitizer, SMTP framing and doctor reports;
- security audits: guard, paths, sessions, SSRF, injection;
- MCP over real stdio against the real backend.

**Not verified:**
- real mail providers (no credentials/network in tests);
- Google/Microsoft OAuth against real provider registrations (needs user-owned client ids/secrets);
- the Microsoft Edge runtime (the e2e tests run on Chrome);
- `mail-mcp` inside an actual Claude Desktop/Code session (protocol tested through rmcp client in tests).

## 5. Security model (summary; details in API_MATRIX.md "Security model")

- **Listen address:** loopback only, default `127.0.0.1:48101`. Change it with `--port`, `--addr` or `MAIL_BACKEND_ADDR`.
- **Host header:** must be `localhost`, a 127.0.0.0/8 literal, or `[::1]`, with an optional port.
- **Origin:**
  - Must be an allowed extension. Default: `chrome-extension://` or `extension://` with id `hhhanbkdjaecdfoclhpoicmfhejdbkjl`, pinned via the manifest `"key"`.
  - `MAIL_BACKEND_EXTENSION_IDS` (comma-separated) replaces the list. Firefox `moz-extension` ids must be listed. `*` means any id, which is insecure and is logged as such.
  - Requests with no Origin are refused when `Sec-Fetch-Site` is cross-site or same-site. The one exception is the top-level navigation `GET /api/mail/oauth/{provider}/callback`.
  - CORS is reflected only for allowed origins.
- **Body limits:** 4 MiB global default and 64 MiB for `/api/audit/eml`. Send, signature and jobs routes keep their own limits. Over-limit requests get a JSON 413.
- **422 responses:** passwords are redacted to `"[redacted]"`.
- **Downloads:** attachment and `.eml` downloads send `nosniff`, `no-store` and `CSP: default-src 'none'; sandbox`. Doctor job files always get the sandbox CSP.
- **Remote images:**
  - Only through `POST /api/mail/message/image`, for URLs registered when the message was rendered. The fetcher pins public IPs, revalidates redirects, and caps size and type.
  - The extension CSP blocks direct remote loads.
  - Like the original, the first 24 remote images load automatically through the proxy when a message is opened. This is a product decision left to the user.
- **Extension backend address:** loopback-only (`127.0.0.1` / `localhost`; `[::1]` is not usable because Chrome CSP rejects IPv6 literals).

## 6. Configuration

| Variable | Used by | Meaning |
|---|---|---|
| `MAIL_BACKEND_ADDR` | backend | listen address (`--addr`) |
| `MAIL_BACKEND_EXTENSION_IDS` | backend | allowed extension ids (replaces the default) |
| `MAIL_SERVERS_PATH` | backend | server-profile JSON path |
| `PUBLIC_BACKEND_URL` / `BACKEND_PORT` | doctor | OAuth redirect base. Default: `http://localhost:<actual listen port>` |
| `FRONTEND_URL` / `FRONTEND_PORT` | doctor | OAuth result fallback origin |
| `GOOGLE_OAUTH_CLIENT_ID/SECRET`, `MICROSOFT_OAUTH_CLIENT_ID/SECRET` | doctor | OAuth apps (memory only) |
| `MAX_UPLOAD_BYTES`, `MAX_EXPANDED_BYTES`, `MAX_ARCHIVE_MEMBERS`, `MAX_AUDIT_MESSAGES`, `JOB_LOG_CHAR_CAP`, `MAIL_SNAPSHOT_EVERY_MESSAGES` | doctor | limits (same names as Python) |
| `MAIL_BACKEND_URL`, `MAIL_BACKEND_TIMEOUT_SECS`, `MAIL_MCP_ALLOW_NON_LOOPBACK` | mcp | backend base URL (loopback enforced unless allowed), timeout |

## 7. Build / run / test

```powershell
cd src
cargo build --workspace --all-targets --all-features
cargo test --workspace --all-features
cargo clippy --workspace --all-targets --all-features
cargo test -p mail-backend --all-features --test e2e_differential -- --ignored   # optional, needs Python + fastapi
.\run-backend.ps1                      # or: cargo run --release -p mail-backend -- --port 48101
cargo build --release -p mail-mcp      # register per src/mail-mcp/README.md

cd extension
npm install
npm run typecheck; npm test; npm run build:extension   # loadable output: src/extension/dist
npm run test:e2e; npm run test:e2e:real                # headless Chrome
```

Load `src/extension/dist` via chrome://extensions or edge://extensions, with Developer mode on, using "Load unpacked". The id will be `hhhanbkdjaecdfoclhpoicmfhejdbkjl`.

## 8. Intentional deviations (full list: API_MATRIX.md "Intentional deviations")

- **Security and request handling:**
  - extension-id allow-list (replaces Python's web-frontend CORS);
  - global body limits;
  - password redaction in 422s;
  - download hardening headers;
  - doctor sandbox CSP on every job file;
  - a JSON body without a Content-Type gets a 422 (matches FastAPI's strict default).
- **Backend defaults:**
  - default port 48101 (Python used 8741);
  - doctor `public_backend_url` follows the actual listen port.
- **Mail behaviour:**
  - mail host lookups retry and fall back to the last address that worked within the hour (`mail-proto/src/resolve.rs`), so short DNS outages do not fail requests;
  - `set_flags` returns the real FLAGS (Python returned `[]`);
  - IMAP literals and POP3 responses are capped at 100 MiB.
- **POP3 (compatibility mode):**
  - message numbers act as UIDs;
  - `uid_validity` is a synthetic hash of the UIDL list (or of sizes); without UIDL, a same-size replacement keeps the epoch.
- **Inbox Doctor parity limits:**
  - ZIP and MIME parity with CPython is complete except for corrupt archives, non-ASCII digit RFC 2231 sections, and headers that crash Python's address parser (the port treats them as empty).
- **Minor:**
  - JSON floats print as `1e16` where Python prints `1e+16`.
- **MCP:**
  - only `mail_empty_trash` requires `confirm=true`;
  - every tool carries read-only/destructive annotations;
  - tools that return mail content describe it as untrusted data that may contain prompt-injection text.
- **Extension:**
  - IMAP/POP3 selector;
  - IMAP-only actions are hidden for POP3;
  - the default port follows the protocol/security choice;
  - loopback-only backend URL;
  - stricter CSP.

## 9. Known open items / suggestions

- Delete the empty root scaffolds `extension/`, `extension-src/`, `tools/` (user action).
- **mail-proto hardening ideas** (not bugs):
  - a cumulative per-command byte cap and an untagged-response count cap;
  - a literal cap applied before the greeting/CAPABILITY handshake.
- `mail-doctor/src/mailbox_download.rs` sets its own literal cap. It could reuse `mail_core::imap::MAX_LITERAL_BYTES`.
- A developer copy of the extension without the manifest `"key"` (a different id), or Firefox, needs `MAIL_BACKEND_EXTENSION_IDS`.
- OAuth redirect URI registered with providers must be `PUBLIC_BACKEND_URL` + `/api/mail/oauth/{provider}/callback` (default `http://localhost:48101/...`).
- `mail-proto/src/testkit/fixtures/test-key.pem` is a self-signed test-only key for the fake TLS servers (not a secret, used only by tests).

## 10. Working notes for future agents

- **JSON key order matters** for parity: `Map` keeps insertion order. Use `shift_remove`, not `remove`.
- **Tests:**
  - Tests that call the backend must use Origin `chrome-extension://hhhanbkdjaecdfoclhpoicmfhejdbkjl` or set `MAIL_BACKEND_EXTENSION_IDS` on the spawned binary.
  - Backend send tests take `mail_core::settings::scoped_settings_path` (a process-wide mutex). Never hold two guards at once.
- **Parity checks** against Python must run on copies of the original or with bytecode writing disabled.
