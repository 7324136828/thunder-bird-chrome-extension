# Thunderbird Chrome Extension Port — Project Memory

## Goal and scope

Port the original Python/FastAPI + React Thunderbird-style mail client into:

- a Chrome/Edge Manifest V3 extension frontend;
- a local Rust backend owning IMAP, POP3 (compatibility read support), SMTP, classification, retention, trash, audit, Inbox Doctor, metrics, signatures, and settings;
- an MCP stdio server that shares the backend's in-memory unlocked account sessions through the local backend API.

Behavioral parity target: `original-project/20261011-thunderbird`, which is read-only. Passwords must remain memory-only. Server profiles and settings may be persisted, but credentials never are.

See `CLAUDE.md` for the current handoff and verification state. See `src/mail-backend/API_MATRIX.md` for routes, the security model, POP3 behaviour and deviations.

## Reference inventory

| Source | Role |
|---|---|
| `original-project/20261011-thunderbird/backend/app/main.py` | REST endpoint contract |
| `backend/app/mail/*.py` | IMAP/SMTP/parsing/categories/retention/trash/signatures/audit/classifier |
| `backend/app/doctor/**/*.py` | Inbox Doctor jobs, mailbox downloads, reports, metrics, weekly scheduler, OAuth |
| `frontend/src/**/*.tsx` | React three-pane UI and workflows |
| `the_editor` | Packaging and local-backend security pattern for the extension architecture |

## Architecture

```text
thunder-bird-chrome-extension/
└── src/
    ├── Cargo.toml       Rust workspace
    ├── mail-proto/      IMAP/POP3 protocol clients + fake IMAP/POP3/SMTP servers (feature "testkit")
    ├── mail-core/       Mail logic: sessions, settings, servers, imap, pop3, smtp, parsing, retention,
    │                    classifier, signatures, remote images, audit, trash
    ├── mail-doctor/     Inbox Doctor jobs, pipeline, reports, metrics, scheduler, OAuth
    ├── mail-backend/    Loopback axum HTTP backend on 127.0.0.1:48101
    ├── mail-mcp/        rmcp stdio server forwarding to the backend API
    └── extension/       MV3 extension (manifest + React/Vite app, build to extension/dist)
```

The root-level `extension/`, `extension-src/` and `tools/` directories are empty leftovers and are not used.

Security design follows `the_editor`:
- The backend listens on loopback and validates loopback Host headers.
- It accepts only allowed extension origins: the pinned id `hhhanbkdjaecdfoclhpoicmfhejdbkjl`, or the ids in `MAIL_BACKEND_EXTENSION_IDS`.
- It refuses cross-site no-Origin requests, except the OAuth callback navigation.
- It reflects CORS only for allowed origins.
- MCP sends no Origin and is treated as a trusted local process. Users should run it only through trusted MCP clients.

## Feature inventory

| ID | Feature | Source of truth | Rust module | Status |
|---|---|---|---|---|
| F-001 | Settings and category expiration preferences | `backend/settings.py` | `mail-core::settings` | done |
| F-002 | Server profiles without secrets | `mail/servers.py` | `mail-core::servers` | done |
| F-003 | In-memory account sessions | `mail/sessions.py` | `mail-core::sessions` | done |
| F-004 | IMAP unlock/folders/list/read/flags/delete/trash/sent-copy | `mail/imap_client.py` | `mail-core::imap` + `mail-proto` | done |
| F-005 | POP3 compatibility unlock/list/read | user requirement | `mail-core::pop3` + `mail-proto` | done |
| F-006 | SMTP send, attachments, inline images, sent copy | `mail/smtp_client.py` | `mail-core::smtp`, `send_uploads` | done |
| F-007 | RFC822 parsing, bodies, attachments, links | `mail/parsing.py` | `mail-core::parsing` | done |
| F-008 | Rule/AI/manual/sender-rule categories and expiration | `mail/retention.py` | `mail-core::retention` | done |
| F-009 | Ollama local classifier | `mail/local_classifier.py` | `mail-core::classifier` | done |
| F-010 | Rich account signatures and images | `mail/signatures.py` | `mail-core::signatures` | done |
| F-011 | Remote image privacy proxy | `mail/remote_images.py`, `image_sources.py` | `mail-core::remote_images`, `image_sources` | done |
| F-012 | Single-message security audit | `mail/audit.py` | `mail-core::audit` | done |
| F-013 | Trash archive/empty snapshot workflow | `mail/trash.py` | `mail-core::trash` | done |
| F-014 | Inbox Doctor upload/paste/mailbox jobs and reports | `doctor/**/*` | `mail-doctor` | done |
| F-015 | Email metrics and weekly scheduler | `doctor/metrics.py`, `scheduler.py` | `mail-doctor::{metrics,scheduler}` | done |
| F-016 | Google/Microsoft OAuth for doctor | `doctor/services/oauth.py` | `mail-doctor::oauth` | done (not tested against real providers) |
| F-017 | React extension UI parity | `frontend/src` | `src/extension` | done (Chrome e2e; Edge not tested) |
| F-018 | MCP read/send/trash/categorize tools | user requirement | `mail-mcp` | done (17 tools) |

## API/compatibility decisions

1. Keep the original `/api/...` routes and JSON shapes, including key order, so the copied React UI needs minimal changes.
2. Add an optional `incoming_mail_protocol` (`imap` default, `pop3`) instead of overloading the encryption settings. IMAP remains required for folders, flags, server trash, stable UIDs and sender-rule identity.
3. POP3 compatibility scope (chosen by the user): unlock, list and read INBOX mail. Sending still uses SMTP. Mutating operations answer 400 with an explanatory message.
4. MCP is a separate process and does not store passwords. It calls the loopback backend, so unlocks made in the extension are shared.
5. The backend port defaults to `48101`, replacing the original `8741`. The extension's default backend URL is `http://127.0.0.1:48101`.

## Build / test commands

```powershell
cd src
cargo build --workspace --all-targets --all-features
cargo test --workspace --all-features
cargo clippy --workspace --all-targets --all-features

cd extension
npm install
npm run typecheck; npm test; npm run build:extension
npm run test:e2e; npm run test:e2e:real
```

## Open questions / expected deviations

- Byte-for-byte parity with Python's email/zipfile packages was pursued through ports and differential tests. A few edge cases remain on malformed input; they are listed in API_MATRIX.md.
- OAuth needs user-owned client ids and secrets. The flow is implemented, but provider app registrations cannot be created here.
- POP3 has no folders, flags or stable UIDs. Message numbers act as UIDs, and `uid_validity` is a synthetic hash.
- Remote images: as in the original, the first 24 load automatically through the proxy when a message is opened. Switching to click-to-load is a product decision.

## Change log

- 2026-11-26: Inventoried the original implementation and the reference `the_editor`. The user selected full-parity scope, shared backend sessions for MCP, and compatibility-level POP3.
- 2026-11-27: Rebuilt on the blocking `mail-proto` clients and finished the full port.
  - Added Inbox Doctor and MCP via rmcp.
  - Hardened security with the pinned extension id, body limits, password redaction and download headers.
  - Made mail host lookups tolerate short DNS outages (retry, then last-known-good address) after a transient "No such host is known" error against a real provider.
  - Verified with 1144 Rust tests, Python differential tests, and extension unit and e2e tests.
