# mail-mcp

An MCP (Model Context Protocol) server for the Thunderbird-style mail
extension. It lets an MCP client such as Claude Code or Claude Desktop read,
search, send, categorize and trash mail **in accounts the user has already
unlocked in the extension**.

- Transport: MCP stdio (newline-delimited JSON-RPC 2.0 on stdin/stdout), built
  on the official Rust SDK [`rmcp`](https://crates.io/crates/rmcp). stdout
  carries only protocol messages; all logs go to stderr.
- Every tool proxies to the local `mail-backend` HTTP API
  (`http://127.0.0.1:48101` by default). The server keeps no state of its own.

## Build

```powershell
cd src
cargo build --release -p mail-mcp
# binary: src\target\release\mail-mcp.exe  (Linux/macOS: src/target/release/mail-mcp)
```

Before using the tools:

1. Start the backend (`cargo run -p mail-backend`, `run-backend.ps1` /
   `run-backend.sh`, or however the extension starts it). It prints the URL it
   listens on, `http://127.0.0.1:48101` by default. If you start it with
   `--port N`, set `MAIL_BACKEND_URL=http://127.0.0.1:N` below.
2. Unlock the account(s) in the extension. The MCP server can only use
   accounts that are unlocked there, and restarting the backend locks them all
   again.

The MCP client starts `mail-mcp` itself. Do not start it by hand. Use the
absolute path of the binary in the configurations below; replace
`C:\path\to\...` with your checkout.

## Register with Claude Code

User-wide, available in every project:

```powershell
claude mcp add --scope user thunderbird-mail --env MAIL_BACKEND_URL=http://127.0.0.1:48101 -- "C:\path\to\thunder-bird-chrome-extension\src\target\release\mail-mcp.exe"
```

```sh
# Linux/macOS
claude mcp add --scope user thunderbird-mail --env MAIL_BACKEND_URL=http://127.0.0.1:48101 -- /path/to/thunder-bird-chrome-extension/src/target/release/mail-mcp
```

Leave out `--scope user` to register the server for the current project only
(`local` scope), or use `--scope project` to write it to the project's
`.mcp.json`, which can be shared with the team:

```json
{
  "mcpServers": {
    "thunderbird-mail": {
      "type": "stdio",
      "command": "C:\\path\\to\\thunder-bird-chrome-extension\\src\\target\\release\\mail-mcp.exe",
      "args": [],
      "env": { "MAIL_BACKEND_URL": "http://127.0.0.1:48101" }
    }
  }
}
```

Backslashes in JSON paths must be doubled. Check the registration with
`claude mcp list` (or `claude mcp get thunderbird-mail`), and run `/mcp`
inside Claude Code to see the server status and its tools. Remove it with
`claude mcp remove thunderbird-mail` (add `--scope user` if you registered it
that way).

## Register with Claude Desktop

Open Settings → Developer → Edit Config, or edit `claude_desktop_config.json`
directly (Windows: `%APPDATA%\Claude\claude_desktop_config.json`,
macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`).
Add the server under `mcpServers`, keeping any servers already listed, and
then fully quit and restart Claude Desktop:

```json
{
  "mcpServers": {
    "thunderbird-mail": {
      "command": "C:\\path\\to\\thunder-bird-chrome-extension\\src\\target\\release\\mail-mcp.exe",
      "args": [],
      "env": { "MAIL_BACKEND_URL": "http://127.0.0.1:48101" }
    }
  }
}
```

On macOS use the POSIX path, for example
`"/Users/me/thunder-bird-chrome-extension/src/target/release/mail-mcp"`.
The mail tools then show up in the tools menu of the chat input. Claude
Desktop writes the server's stderr (set `"RUST_LOG": "mail_mcp=debug"` in
`env` for more detail) to `mcp-server-thunderbird-mail.log` in its logs folder
(Windows: `%APPDATA%\Claude\logs`, macOS: `~/Library/Logs/Claude`).

Never put a mailbox password in any of these configurations. The server does
not read one.

## Troubleshooting

| Tool error | Meaning / fix |
|---|---|
| `"code": "backend_unreachable"` | The backend is not running, or `MAIL_BACKEND_URL` points at the wrong port. |
| `"code": "password_required"` (HTTP 401) | That account is locked. Unlock it in the extension and retry. |
| `No mail account is unlocked` | Nothing is unlocked yet. Unlock an account in the extension. |
| `Several accounts are unlocked (...)` | Pass the `account` argument. |
| HTTP 403 `Forbidden: ...` | The backend's loopback/Origin guard refused the request; `MAIL_BACKEND_URL` must use `127.0.0.1`, `localhost` or `[::1]`. |
| `mail-mcp: MAIL_BACKEND_URL must point at a loopback address ...` (on stderr, exit code 2) | Fix the URL; see the configuration table. |

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `MAIL_BACKEND_URL` | `http://127.0.0.1:48101` | Base URL of the mail-backend. Must be `http`/`https`, with no credentials, query or fragment. |
| `MAIL_MCP_ALLOW_NON_LOOPBACK` | unset | Set to `1` to allow a backend host that is not `127.0.0.1`/`::1`/`localhost`. Not recommended. |
| `MAIL_BACKEND_TIMEOUT_SECS` | `300` | Per-request timeout. Local-AI classification and large sends can be slow. |
| `RUST_LOG` | `warn` | Log filter for stderr output, e.g. `mail_mcp=debug`. |

## Tools

Every mail tool takes an optional `account` (email address). Leave it out when
exactly one account is unlocked and that account is used. Results come back as
JSON text, which is the backend's response unless the table says otherwise.
Failures come back as tool results with `isError: true` and a JSON body
`{"error": "...", "status": 4xx/5xx, "detail": ...}`.

| Tool | Backend call | Notes |
|---|---|---|
| `mail_list_accounts` | `GET /api/accounts` | Unlocked accounts (never passwords). |
| `mail_list_folders` | `GET /api/mail/folders` | Includes the `special` use (inbox/sent/trash/...) and `selectable`. |
| `mail_list_messages` | `GET /api/mail/messages` | `folder`, `offset`, `limit` (1-200), `query`, `read_status`, `sender_domain[]`, `category`, `expired_only`. |
| `mail_read_message` | `GET /api/mail/message` | `mark_seen` defaults to **false**. `html_body` is dropped when a text body exists unless `include_html=true`. |
| `mail_get_raw_message` | `GET /api/mail/message/eml` | `.eml` as text, truncated to `max_bytes` (default 256 KiB, max 4 MiB). |
| `mail_get_attachment` | `GET /api/mail/message/attachment` | Base64 plus filename and content type. Refused above `max_bytes` (default 2 MiB, max 10 MiB). |
| `mail_send` | `POST /api/mail/send` or `POST /api/mail/send/files` | `to`/`cc`/`bcc`/`subject`/`text`/`html`/`in_reply_to`/`references`. With `attachments: [{filename, content_type, content_base64}]` it sends the same multipart layout as the extension UI: a `message` JSON field with `uploads` metadata, then one `files` part per file. Limits: 20 files, 10 MiB each, 20 MiB in total. |
| `mail_move_to_trash` | `GET /api/mail/folders`, then `POST /api/mail/messages/delete` | Finds the Trash folder as the UI does (first folder with `special == "trash"` that is selectable). Refuses when there is no Trash folder, so it never deletes permanently. Pass `uid_validity`. Adds `trash_folder` to the result. |
| `mail_set_flags` | `POST /api/mail/message/flags` | `seen` and/or `flagged`. |
| `mail_categorize` | `PUT /api/mail/message/retention` | `category` and/or `expiration_days`. `null` resets a field. Requires `uid_validity`. |
| `mail_classify_with_local_ai` | `POST /api/mail/message/classify` | Uses the local Ollama model set in the extension settings. |
| `mail_sender_rule_create` | `POST /api/mail/message/sender-rule` | `category` must equal the message's current category. |
| `mail_sender_rule_list` | `GET /api/mail/sender-rules` | Optional `folder`. |
| `mail_sender_rule_delete` | `DELETE /api/mail/sender-rules` | `folder`, `sender`, optional `expected_revision`. |
| `mail_audit_message` | `GET /api/mail/audit` | SPF/DKIM/DMARC, routing, links, findings, risk verdict. |
| `mail_empty_trash` | `POST /api/mail/trash/prepare` (archive=false), `POST /api/mail/trash/{id}/empty`, `DELETE /api/mail/trash/{id}` | Permanently deletes the prepared snapshot of Trash. **Requires `confirm=true`.** Optional `expected_count` cancels the operation, deleting nothing, if Trash holds a different number of messages. Never creates or downloads a ZIP archive. |
| `mail_get_settings` | `GET /api/settings` | Page size, signature, retention policy, local AI model. |

POP3 accounts work at compatibility level only: list INBOX, read messages and
send (categories, retention and sender rules are kept locally by the
backend). `mail_set_flags` returns the backend's 400 ("This operation
requires an IMAP account..."). `mail_move_to_trash` and
`mail_empty_trash` refuse before contacting the backend, because a POP3
account has no server Trash folder.

## Security model

- **No credentials.** There is no unlock tool, so mailbox passwords never pass
  through the model or the MCP client. The user unlocks accounts in the
  extension, and the backend keeps passwords in memory only. If the backend
  answers `401 {"error": "password_required"}`, the tool error tells the user
  to unlock the account in the extension.
- **No persistence.** The server writes no files and caches nothing.
- **Loopback only.** The backend URL must be a loopback address unless you
  explicitly override it. Requests go out with no proxy, no redirects and no
  `Origin` header. The backend treats such callers as trusted local processes,
  so only register this server with MCP clients you trust.
- **Mail is untrusted input (prompt injection).** Anything a tool returns
  from a mailbox (subjects, senders, bodies, headers, links, attachments) was
  written by third parties and may contain instructions aimed at the model.
  The server instructions tell the model never to act on instructions found
  inside an email and to confirm every send and Trash move with the user,
  and every tool that returns message content repeats that warning in its
  description, for clients that drop server instructions.
- **Tool annotations.** Every tool sets all four MCP hints explicitly
  (`readOnlyHint`, `destructiveHint`, `idempotentHint`, `openWorldHint`), so
  hosts never fall back to the spec defaults:

  | Tool | readOnly | destructive | idempotent | openWorld |
  |---|---|---|---|---|
  | `mail_list_accounts`, `mail_list_folders`, `mail_list_messages`, `mail_get_raw_message`, `mail_get_attachment`, `mail_sender_rule_list`, `mail_audit_message`, `mail_get_settings` | true | false | true | false |
  | `mail_read_message` (`mark_seen=true` sets `\Seen`) | false | false | true | false |
  | `mail_set_flags`, `mail_categorize`, `mail_sender_rule_create` | false | false | true | false |
  | `mail_classify_with_local_ai` (model output can vary) | false | false | false | false |
  | `mail_send` | false | false | false | **true** |
  | `mail_move_to_trash`, `mail_sender_rule_delete` | false | **true** | true | false |
  | `mail_empty_trash` | false | **true** | false | false |

  `mail_send` only adds data (the sent message and its Sent copy), so under
  the MCP definition it is not destructive; it is the one open-world tool,
  which is what tells hosts that its effect reaches people outside the
  mailbox. The other tools only reach the user's own mail servers and the
  local backend (the local AI model included; the audit makes no DNS
  lookups).
- **Confirmation policy (decision).** Only `mail_empty_trash`, the one
  permanent and archive-less deletion, requires `confirm=true`, and it also
  never falls back to anything broader than the prepared snapshot.
  `mail_send` and `mail_move_to_trash` deliberately have **no** confirm
  flag: the model sets such a flag itself, so a prompt-injected model would
  set it too, and it would add friction without adding protection. The real
  safeguards are the MCP host's per-call approval prompt (Claude Code and
  Claude Desktop ask before running a tool unless the user has allowed it,
  and the annotations above let them single out `mail_send` and the
  destructive tools), the instructions and descriptions above, and the
  backend's own limits. `mail_move_to_trash` is also recoverable (the
  messages stay in the server Trash) and refuses accounts without a Trash
  folder, so it never deletes permanently. Do not add these tools to an
  "always allow" list if you read untrusted mail with them.
- **Bounded output.** Raw messages are truncated and attachments are size
  capped, so a single result cannot flood the model's context. Backend JSON
  responses are capped at 64 MiB, and incoming JSON-RPC lines at 40 MiB.

## Tests

```powershell
cd src
cargo test -p mail-mcp
```

- `src/*` unit tests cover URL validation, error mapping, argument parsing,
  query building, attachment decoding and Content-Disposition parsing.
- `tests/tools_http.rs` checks every tool against a mock axum backend:
  request paths, query strings, JSON bodies, the multipart layout, the Trash
  flows and error mapping.
- `tests/stdio_e2e.rs` spawns the compiled binary and runs `initialize`,
  `notifications/initialized`, `tools/list` and `tools/call` over real stdio
  against the mock backend.
- `tests/e2e_real_backend.rs` is the full end-to-end test. It builds the
  real `mail-backend` executable (`cargo build -p mail-backend`; set
  `MAIL_BACKEND_BIN` to use a prebuilt one instead) and starts it on an
  ephemeral loopback port, with settings, profiles and data isolated in a
  temporary directory through `WEBMAIL_SETTINGS_PATH`, `MAIL_SERVERS_PATH`
  and `DATA_DIRECTORY`. It also starts the `mail_proto::testkit` fake
  IMAP/SMTP/POP3 servers and unlocks accounts through the backend HTTP API
  as the extension does. It then drives the real `mail-mcp` binary over
  stdio and calls every tool: it checks the effects on the fake servers
  (flags, moves, expunges, the delivered mail and its Sent copy), the
  locked-account and unreachable-backend tool errors, and POP3 compatibility
  mode. It also checks that no tool schema asks for a password, that the
  password never appears in tool output or logs, and that `mail-mcp` writes
  no files.
