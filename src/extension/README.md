# Webmail extension (Chrome / Edge, Manifest V3)

The Thunderbird-style three-pane webmail from the original project
(`original-project/20261011-thunderbird/frontend`), packaged as a Manifest V3
extension. All mail work happens in the local Rust backend (`../mail-backend`,
default `http://127.0.0.1:48101`). The extension is only the UI.

## Extension id (pinned)

`manifest.json` carries a `"key"` (a public key), so every unpacked or packed
build of this folder gets the same id in Chrome and Edge, wherever it is
loaded from:

```text
hhhanbkdjaecdfoclhpoicmfhejdbkjl
```

- mail-backend accepts state-changing requests only from
  `Origin: chrome-extension://hhhanbkdjaecdfoclhpoicmfhejdbkjl` by default
  (and requests without `Origin`, which is what extension GETs send).
- `MAIL_BACKEND_EXTENSION_IDS` (comma-separated ids) replaces that allow-list,
  for example for a Chrome Web Store build (the store assigns its own id and
  strips `"key"`), a build signed with another key, or a Firefox port
  (`moz-extension://` uses a per-install UUID; list that UUID). Set it in the
  backend's environment before starting it.
- `tools/build-extension.mjs` copies the manifest (including `"key"`) into
  `dist/` unchanged, recomputes the id from the key and fails if it is not the
  pinned id; it prints the id after building. Change `PINNED_EXTENSION_ID`
  there, the backend default and this README together if the key is ever
  replaced.

## Layout

```text
src/extension/
├── package.json            npm project (run every command from this folder)
├── manifest.json           MV3 manifest source (version must match package.json)
├── icons/                  generated PNG icons (npm run icons)
├── app/                    Vite root
│   ├── index.html          the webmail app (opened in a tab)
│   ├── options.html        backend address settings
│   ├── public/frame-host.* sandboxed frame host (copied verbatim)
│   ├── vite.config.ts
│   └── src/
│       ├── App.tsx, components/, api.ts, …   original React app (minimal patches)
│       ├── platform/       backend URL, downloads, mailto hand-off, IMAP/POP3 helpers (extension glue)
│       ├── background/     service worker + message contracts
│       └── options/        options page script + styles
├── tools/
│   ├── build-extension.mjs assembles and checks dist/
│   ├── gen-icons.mjs       draws the icons with no image library
│   └── fake-mail/          fake IMAP/POP3/SMTP servers for test:e2e:real (own cargo project)
├── tests/                  node --test unit tests + e2e/ (fake-backend smoke, real-backend)
└── dist/                   load-unpacked output (generated)
```

`app/package.json` is only a marker that keeps `"type": "module"` for the Vite
root. Dependencies live in this folder's `package.json`.

## Build

Requires Node.js 22.18 or newer (developed with Node 26).

```powershell
cd src/extension
npm install
npm run typecheck          # tsc -b app (app, options, service worker, tests)
npm test                   # unit tests (node --test, native TypeScript)
npm run build:extension    # typecheck + vite build + package into dist/
```

| Script | What it does |
| --- | --- |
| `npm run dev` | Vite dev server on `http://127.0.0.1:3741`, proxying `/api` to the backend |
| `npm run typecheck` | TypeScript project build check |
| `npm run build` | `vite build` → `app/dist` (pages, assets, `background.js`, frame host) |
| `npm run build:extension` | The above, then `tools/build-extension.mjs` → `dist/` |
| `npm run icons` | Regenerate `icons/icon-{16,48,128}.png` |
| `npm test` | Unit tests |
| `npm run test:e2e` | Headless Chrome smoke test of `dist/` against a fake backend |
| `npm run test:e2e:real` | Headless Chrome test of `dist/` against the real `mail-backend` binary and fake IMAP/SMTP servers (see below) |

`build-extension.mjs` fails if a file named by the manifest is missing, the
service worker imports a missing chunk, the manifest and package versions
differ, or any page has an inline script, inline event handler or
`javascript:` URL (MV3 CSP).

## Load unpacked (Chrome / Edge)

1. Build: `cd src/extension`, `npm install` (once), `npm run build:extension`.
2. Start the backend: `cd src`, then `run-backend.bat` / `./run-backend.sh` /
   `cargo run --release -p mail-backend`.
3. Open `chrome://extensions` (Chrome) or `edge://extensions` (Edge) and turn
   on **Developer mode** (Edge: the toggle in the left pane).
4. Click **Load unpacked** and choose `src/extension/dist`. The card shows the
   id `hhhanbkdjaecdfoclhpoicmfhejdbkjl`; any other id means the `"key"` was
   lost and the backend will refuse the extension's POST/PUT/DELETE requests
   (403) unless `MAIL_BACKEND_EXTENSION_IDS` lists that id.
5. Click the toolbar button. The webmail opens in a tab. Clicking again focuses
   that tab instead of opening another one.

After rebuilding, click the reload icon on the extension card. Only one copy
with this id can be installed per browser profile.

## Changes to the original sources

Every file under `app/src` that also exists in the original `frontend/src` is
byte-identical except for these patches (`diff --strip-trailing-cr`):

| File | Change | Why |
| --- | --- | --- |
| `api.ts`, `doctorApi.ts`, `emailMetricsApi.ts` | `fetch(apiUrl(path))`; link builders wrapped in `apiUrl` | The backend is another origin (configured base URL) |
| `api.ts` | optional `incoming_mail_protocol` on `ServerProfile`, `Account` and the unlock body | Rust backend's POP3 compatibility mode |
| `main.tsx` | resolve the base URL before rendering; reload when Options changes it | Every request needs the base; accounts belong to one backend |
| `App.tsx` | compose a `mailto:` link handed over by the context menu (`platform/launch.ts`) | MV3 `mailto:` integration |
| `components/EmailHtml.tsx`, `components/DoctorResults.tsx` | `<SandboxFrame>` instead of `<iframe sandbox srcDoc>` | Extension page CSP blocks inline scripts in srcdoc frames |
| `components/MessageView.tsx`, `DoctorResults.tsx`, `TrashActionsModal.tsx` | `onClick={backendDownloadClick(...)}` on download links | `<a download>` is ignored for cross-origin URLs |
| `components/ConnectScreen.tsx` | "Incoming mail protocol" (IMAP / POP3) in the advanced settings, following the profile; the incoming port follows the protocol and security defaults (993 IMAP SSL/TLS, 143 IMAP STARTTLS/none, 995 POP3 SSL/TLS, 110 POP3 STARTTLS/none) unless the user typed another port | POP3 accounts were otherwise reachable only through a hand-edited profile |
| `App.tsx`, `components/MessageList.tsx`, `MessageView.tsx`, `Sidebar.tsx` | POP3 accounts (`incoming_mail_protocol: "pop3"`): Flag, Mark read/unread, Delete, selection + Move to Trash, Trash actions and the read-status filter are hidden; a "POP3 compatibility mode" note and a sidebar label are shown (`platform/mailProtocol.ts`) | The backend answers 400 "This operation requires an IMAP account…" for those, and POP3 has no server read state |
| `components/ConnectScreen.tsx` | the password-only re-unlock form no longer sends the form's untouched server defaults | The original sent port 993 / `SSL/TLS`, which override the saved profile and break STARTTLS, plain and POP3 profiles |
| `vite-env.d.ts` | `VITE_BACKEND_BASE_URL` typing | Dev-server option |
| `index.html` | meta description says Rust backend | Text only |

## Options

Right-click the toolbar button and choose **Options** (or use the extension's
details page).

- **Backend address**, stored in `chrome.storage.local` as
  `{ settings: { backend_url } }`. Input is normalized: blank means
  `http://127.0.0.1:48101`, `http://` is added when missing, and trailing
  slashes are removed. Credentials, queries and fragments are rejected.
- See **Backend address policy** below: only `http://127.0.0.1:<port>` and
  `http://localhost:<port>` (optional path prefix) are accepted. Anything
  else is refused with an error and never saved; a refused value found in
  storage (edited by hand, older build) is ignored and the default address
  is used.
- **Test connection** calls `GET {address}/api/health` and expects `{"status":"ok"}`.
- Saving a new address reloads open webmail tabs against it (accounts and
  sessions belong to a backend).

## Backend address policy

One rule, enforced in three places that must agree:

| Where | What it allows |
| --- | --- |
| `extension_pages` CSP `connect-src` | `'self' http://127.0.0.1:* http://localhost:*` |
| `host_permissions` | `http://127.0.0.1/*`, `http://localhost/*` |
| Options page / app (`platform/backendUrl.ts` `validateBackendUrl`) | `http://127.0.0.1:<port>[/prefix]`, `http://localhost:<port>[/prefix]` |

- **Remote backends are refused entirely**, whether `http://` or `https://`.
  There is no "I understand the risk" override: mail passwords are sent to
  this address, and the CSP would block the requests anyway. The backend
  itself only listens on loopback.
- **`https://` on loopback is refused** too: mail-backend serves plain HTTP on
  loopback, and the CSP and host permissions list only `http://` origins.
- **`[::1]` is refused** with a hint to use `localhost`: Chrome rejects IPv6
  literals in CSP source lists (`The source list for ... 'connect-src' contains
  an invalid source: 'http://[::1]:*'. It will be ignored.`), so it cannot be
  allowed. `localhost` also reaches a backend listening on `::1`.
- A remote or TLS backend therefore needs a rebuilt extension: widen
  `connect-src` and `host_permissions` in `manifest.json`, `REQUIRED_PAGE_CSP`
  in `tools/build-extension.mjs` and `validateBackendUrl` together.

## How the app talks to the backend

- `main.tsx` resolves the base URL (`platform/backend.ts` `initBackendBase()`)
  **before** React renders. Every request goes through `apiUrl(path)`: the
  `request` helpers in `api.ts`, `doctorApi.ts` and `emailMetricsApi.ts`,
  plus the link builders (`messageEmlUrl`, `attachmentUrl`, `trashArchiveUrl`,
  `doctorApi.fileUrl`, `doctorApi.zipUrl`). The original `/api/...` paths and
  JSON shapes are unchanged. `tests/packaging.test.ts` fails if a component
  builds a relative `/api` URL or calls `fetch` without the base.
- Host permissions for `127.0.0.1` and `localhost` let extension pages
  read backend responses (including `Content-Disposition`) without CORS headers.
- **Downloads** (.eml, attachments, trash archive ZIP, doctor ZIP and report
  files): browsers ignore `<a download>` for cross-origin URLs, so the links keep
  their markup but `platform/downloads.ts` fetches the bytes, wraps them in a
  same-origin `blob:` URL and saves them. The file name comes from
  `Content-Disposition` (RFC 5987 `filename*` first). Errors such as
  `401 password_required` are shown to the user (the trash dialog shows them
  in its own error banner). No `downloads` permission is needed.

## Sandboxed HTML (email bodies, doctor HTML report)

The original renders both with `<iframe sandbox="allow-scripts" srcDoc>`. On an
extension page a srcdoc frame inherits the page CSP (`script-src 'self'`), which
blocks the email link bridge (a nonce script) and the report's own inline
script. `components/SandboxFrame.tsx` therefore loads `frame-host.html`, a
manifest **sandbox** page with its own CSP. The host renders the HTML in a
nested srcdoc frame, so the document's own `<meta>` CSP still applies
unchanged (for email: nonce-only scripts, `img-src data:`, no network). It
relays the nested frame's messages to the app when asked, and `EmailHtml`'s
`event.source` and per-render token checks keep working. On the Vite dev
server `SandboxFrame` renders the original srcdoc iframe.

## mailto: links

- Context menu **Compose with Webmail** on `mailto:` links (any page).
- The service worker focuses an open webmail tab and sends it the raw link
  (`webmail:compose-mailto`, accepted only by the tab with that tab id), or
  opens `index.html?mailto=<encoded link>`. The app removes the parameter from
  the address and parses the link with the original `mailto.ts`, exactly as for
  links inside messages. If no account is unlocked yet, the draft waits until one is.
- Finding the open tab uses `chrome.runtime.getContexts` (Chrome/Edge 116+),
  so the `tabs` permission is not needed.

## Permissions and CSP

- `permissions`: `storage` (backend address) and `contextMenus` (mailto menu).
- `host_permissions`: `http://127.0.0.1/*`, `http://localhost/*`.
- `extension_pages` CSP (checked by `build-extension.mjs` and `tests/packaging.test.ts`):

  ```text
  script-src 'self'; object-src 'self'; base-uri 'self';
  img-src 'self' data: blob:; frame-src 'self'; form-action 'none';
  connect-src 'self' http://127.0.0.1:* http://localhost:*
  ```

  - `img-src`: the app never points an `<img>` at the backend or the web.
    Remote email images come from `POST /api/mail/message/image` as bytes
    (fetch), are decoded from a `blob:` URL and embedded as `data:` in the
    sandboxed email frame; compose/signature images are local `blob:`/`data:`
    previews; signature images saved on the backend are fetched, not linked.
  - `frame-src 'self'`: the only frame is `frame-host.html` (the email body
    and doctor report live in its nested srcdoc frame, governed by the
    sandbox CSP).
  - `form-action 'none'`: every form is handled in script (`preventDefault`).
  - `connect-src`: see **Backend address policy**. Downloads (`.eml`,
    attachments, ZIPs) are `fetch`ed from the backend and saved via `blob:`.
  - Inline `style` attributes stay allowed (no `style-src`/`default-src`):
    the rich-text editor and signatures rely on them.
- `sandbox` CSP (frame host only): scripts from the package or inline, no
  network (`connect-src 'none'`), `data:` images only, no forms, plugins, fonts or media.

## Dev mode (Vite dev server)

```powershell
npm run dev          # http://127.0.0.1:3741, /api proxied to http://127.0.0.1:48101
```

Outside the extension there is no `chrome.storage`, so the base URL is `''`
and the original relative `/api` paths go through the dev proxy. Overrides:

- `VITE_BACKEND_URL=http://127.0.0.1:9000 npm run dev` changes the proxy target.
- `VITE_BACKEND_BASE_URL=http://127.0.0.1:9000` makes the app call that
  backend directly (only useful with a backend that allows
  `http://127.0.0.1:3741` through CORS; mail-backend does not).
- `FRONTEND_HOST=0.0.0.0` exposes the dev server on the network (default is loopback only).

The context menu, options storage and frame host apply to the extension build only.

## What the backend must provide (integration notes)

- Same routes and JSON as `backend/app/main.py`, served on `127.0.0.1:48101`.
- **Origin policy**: extension GET requests carry **no** `Origin` header.
  POST/PUT/DELETE requests carry `Origin: chrome-extension://<id>`, and the
  id is pinned by the manifest `"key"` to `hhhanbkdjaecdfoclhpoicmfhejdbkjl`
  (see **Extension id**). The backend accepts that origin (or the ids in
  `MAIL_BACKEND_EXTENSION_IDS`) and requests without `Origin`, and refuses
  every web origin and other extensions. The Vite dev proxy therefore drops the `Origin` header
  when (and only when) it is the dev server's own origin
  (`http://127.0.0.1:3741`, `http://localhost:3741`); other pages' origins are
  forwarded and refused. CORS response headers are not needed for the
  extension (host permissions); calling the backend directly from the dev
  server (`VITE_BACKEND_BASE_URL`) does not work because the backend refuses
  the dev origin.
- **Inbox Doctor OAuth** (`DoctorConnect.tsx`, unchanged): the app opens a
  popup, calls `POST /api/mail/oauth/start`, navigates the popup to
  `authorization_url` and accepts a `postMessage` whose origin equals
  `message_origin` (the backend's public URL, `PUBLIC_BACKEND_URL`, default
  `http://localhost:48101`). The provider redirects to the backend callback
  (`/api/mail/oauth/{provider}/callback`); the backend remembers the
  validated extension `Origin` of the `/oauth/start` request with the flow
  state, and the callback page posts `{type: "email-doctor-oauth", jobId |
  error}` to `window.opener` with that origin as target. `test:e2e:real`
  verifies this hand-off (with a provider error, so no provider is
  contacted). It has not been tested against real providers; a provider's
  Cross-Origin-Opener-Policy may break `window.opener`, exactly as in the
  original web app. If the backend runs on another port, set
  `PUBLIC_BACKEND_URL` (or `BACKEND_PORT`) to match.

## Real-backend e2e test

`npm run test:e2e` (fake backend) additionally checks the pinned id, the
extension page CSP (loopback `connect-src` allowed, remote http/https blocked,
`data:`/`blob:` images allowed and remote images, foreign frames and form
posts blocked) and the POP3 compatibility UI.

`npm run test:e2e:real` drives `dist/` in headless Chrome against the real
`mail-backend` executable (default `../target/debug/mail-backend`, override
with `WEBMAIL_E2E_BACKEND`; build it first with `cargo build -p mail-backend`
in `src`). `tools/fake-mail` (a small cargo project outside the workspace,
built automatically into `tools/fake-mail/target`) runs fake IMAP, POP3 and
SMTP servers from `mail-proto`'s testkit. The backend runs on port 48197
(`WEBMAIL_E2E_BACKEND_PORT`) with all settings, profiles and data in a
temporary folder. Covered: Options Test connection, the Origin guard
accepting every extension request, unlock through the Connect screen, list,
HTML message through the frame host and the link confirmation, `.eml` and
attachment downloads, settings and signature (multipart) writes, compose and
send through SMTP, trash prepare/discard, an Inbox Doctor account audit with
its ZIP, the OAuth callback page posting to the extension origin, re-unlock
after a lost session, and a POP3 account (port defaults, unlock, read, the
400 for mutations, and the hidden IMAP-only actions).

## Troubleshooting

- *"Not reachable"* in Options: start the backend, check the port, then Test connection.
- Blank message bodies: make sure `dist/frame-host.html` and `frame-host.js`
  exist (rebuild) and that the manifest still lists the `sandbox` page.
- Branded Chrome 137+ ignores `--load-extension`. The e2e test installs the
  build through the DevTools command `Extensions.loadUnpacked` instead.
