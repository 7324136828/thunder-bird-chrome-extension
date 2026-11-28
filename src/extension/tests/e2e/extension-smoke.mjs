#!/usr/bin/env node
/**
 * End-to-end smoke test of the BUILT extension (dist/) in headless Chrome,
 * driven over the DevTools protocol, against an in-process fake mail backend
 * that deliberately sends no CORS headers.
 *
 *   npm run build:extension
 *   npm run test:e2e
 *   node tests/e2e/extension-smoke.mjs [browserPath] [extensionDir] [cdpPort] [fakeBackendPort]
 *
 * Branded Chrome 137+ ignores --load-extension, so the extension is installed
 * with the CDP command Extensions.loadUnpacked (needs
 * --enable-unsafe-extension-debugging). Override the browser with the
 * WEBMAIL_E2E_BROWSER environment variable.
 *
 * Covers: options page (normalization, loopback warning, save, Test
 * connection), configured base URL for all requests, ?mailto= launch, the
 * sandboxed frame host (email link bridge + relay, CSP behaviour), fetch-based
 * downloads incl. error reporting, service-worker mailto hand-off to an open
 * tab, context menu registration and "Open webmail", the pinned extension id
 * (manifest "key"), the hardened extension_pages CSP (loopback-only
 * connect-src, img/frame/form restrictions) and the POP3 compatibility UI
 * (IMAP-only actions hidden).
 */
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const DEFAULT_BROWSERS = [
  process.env.WEBMAIL_E2E_BROWSER,
  'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
  'C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe',
  '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
  '/usr/bin/google-chrome',
  '/usr/bin/chromium',
].filter(Boolean);
const args = process.argv.slice(2);
const browser = args[0] || DEFAULT_BROWSERS.find((candidate) => fs.existsSync(candidate));
const extDir = path.resolve(args[1] || path.join(ROOT, 'dist'));
const cdpPort = args[2] || '9340';
const backendPort = args[3] || '48199';
if (!browser) throw new Error('No Chrome found; pass its path or set WEBMAIL_E2E_BROWSER.');
if (!fs.existsSync(path.join(extDir, 'manifest.json'))) throw new Error(`${extDir} has no manifest.json; run npm run build:extension first.`);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const results = [];
const check = (name, ok, detail = '') => { results.push({ name, ok, detail }); console.log(`${ok ? 'PASS' : 'FAIL'} ${name}${detail ? ` -- ${detail}` : ''}`); };
const downloads = fs.mkdtempSync(path.join(os.tmpdir(), 'webmail-dl-'));

// ---------------------------------------------------------------- fake backend
const requests = [];
const account = { email: 'demo@example.test', display_name: 'Demo', incoming_server: 'imap.example.test', incoming_port: 993, incoming_protocol: 'ssl', outgoing_server: 'smtp.example.test', outgoing_port: 465, outgoing_protocol: 'ssl', unlocked_at: 1 };
const popAccount = { ...account, email: 'pop@example.test', display_name: 'Pop', incoming_server: 'pop.example.test', incoming_port: 995, incoming_mail_protocol: 'pop3', unlocked_at: 2 };
const summary = { uid: 1, flags: [], seen: false, flagged: false, answered: false, size: 1200, internal_date: null, subject: 'Smoke subject', from: 'Sender <s@example.test>', to: 'demo@example.test', date: '2026-11-26T10:00:00Z', category: 'updates', expiration_days: 30, expires_at: null, expired: false, uid_validity: '7' };
const full = { ...summary, folder: 'INBOX', from_name: 'Sender', from_addr: 's@example.test', cc: '', message_id: '<m1@example.test>', text_body: 'hello', snippet: 'hello', attachments: [{ index: 0, filename: 'notes.txt', content_type: 'text/plain', size: 5 }],
  html_body: '<a href="https://example.com/landing">Example landing link</a><p>Body text</p>' };
const server = http.createServer((req, res) => {
  const url = new URL(req.url, 'http://x');
  requests.push({ method: req.method, path: url.pathname, origin: req.headers.origin ?? null });
  const json = (status, body) => { res.writeHead(status, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(body)); };
  switch (url.pathname) {
    case '/api/health': return json(200, { status: 'ok' });
    case '/api/settings': return json(200, { messages_per_page: 5, signature: '' });
    case '/api/accounts': return json(200, { accounts: [account, popAccount] });
    case '/api/mail/folders': return json(200, { folders: [{ name: 'INBOX', delimiter: '/', flags: [], special: 'inbox', selectable: true }] });
    case '/api/mail/messages': return json(200, { total: 1, offset: 0, limit: 5, messages: [summary] });
    case '/api/mail/message': return json(200, full);
    case '/api/mail/sender-rules': return json(200, { rules: [] });
    case '/api/mail/signature': return json(200, { account: account.email, text: '', 'multipart-path': {}, images: [] });
    case '/api/mail/message/eml':
      res.writeHead(200, { 'Content-Type': 'message/rfc822', 'Content-Disposition': 'attachment; filename="message-1.eml"' });
      return res.end('Subject: Smoke\r\n\r\nhello\r\n');
    case '/api/mail/message/attachment':
      if (url.searchParams.get('index') === '9') return json(401, { detail: { error: 'password_required', email: account.email } });
      res.writeHead(200, { 'Content-Type': 'text/plain', 'Content-Disposition': 'attachment; filename="notes.txt"' });
      return res.end('notes');
    default: return json(404, { detail: 'Not Found' });
  }
});
await new Promise((r) => server.listen(Number(backendPort), '127.0.0.1', r));

// ---------------------------------------------------------------- browser + CDP
const profile = fs.mkdtempSync(path.join(os.tmpdir(), 'webmail-smoke-'));
const child = spawn(browser, [
  `--user-data-dir=${profile}`, `--remote-debugging-port=${cdpPort}`, '--headless=new', '--no-first-run',
  '--no-default-browser-check', '--enable-unsafe-extension-debugging', '--window-size=1400,900', 'about:blank',
], { stdio: 'ignore' });

let version = null;
for (let i = 0; i < 60 && !version; i += 1) {
  await sleep(250);
  version = await fetch(`http://127.0.0.1:${cdpPort}/json/version`).then((r) => r.json(), () => null);
}
if (!version) throw new Error('Chrome did not open its DevTools port');
const ws = new WebSocket(version.webSocketDebuggerUrl);
await new Promise((r) => ws.addEventListener('open', r, { once: true }));
let nextId = 0;
const pending = new Map();
const events = [];
ws.addEventListener('message', (message) => {
  const data = JSON.parse(message.data);
  if (data.id && pending.has(data.id)) { pending.get(data.id)(data); pending.delete(data.id); }
  else events.push(data);
});
const send = (method, params = {}, sessionId) => new Promise((resolve, reject) => {
  const id = ++nextId;
  pending.set(id, (data) => (data.error ? reject(new Error(`${method}: ${data.error.message}`)) : resolve(data.result)));
  ws.send(JSON.stringify({ id, method, params, ...(sessionId ? { sessionId } : {}) }));
});
const loaded = await send('Extensions.loadUnpacked', { path: extDir });
const extId = loaded.id;
let swReady = false;
for (let i = 0; i < 40 && !swReady; i += 1) {
  await sleep(250);
  swReady = (await send('Target.getTargets')).targetInfos.some((t) => t.type === 'service_worker' && t.url === `chrome-extension://${extId}/background.js`);
}
check('extension loads (Extensions.loadUnpacked) and service worker starts', swReady, extId);
check('manifest "key" pins the extension id', extId === 'hhhanbkdjaecdfoclhpoicmfhejdbkjl', extId);
const evaluate = async (sessionId, expression) => {
  const result = await send('Runtime.evaluate', { expression, awaitPromise: true, returnByValue: true }, sessionId);
  if (result.exceptionDetails) throw new Error(result.exceptionDetails.exception?.description ?? result.exceptionDetails.text);
  return result.result.value;
};
const waitFor = async (sessionId, expression, timeout = 8000) => {
  const end = Date.now() + timeout;
  while (Date.now() < end) {
    try { if (await evaluate(sessionId, expression)) return true; } catch { /* page navigating */ }
    await sleep(150);
  }
  return false;
};
async function openPage(url, reload = true) {
  const { targetId } = await send('Target.createTarget', { url });
  const { sessionId } = await send('Target.attachToTarget', { targetId, flatten: true });
  await send('Runtime.enable', {}, sessionId);
  await send('Log.enable', {}, sessionId);
  await send('Page.enable', {}, sessionId);
  if (reload) {
    await sleep(300);
    await send('Page.reload', {}, sessionId);
    await sleep(300);
  }
  return { targetId, sessionId };
}
const problems = (sessionId) => events.filter((e) => e.sessionId === sessionId && (
  e.method === 'Runtime.exceptionThrown'
  || (e.method === 'Log.entryAdded' && e.params.entry.level === 'error' && e.params.entry.source !== 'network')
  || (e.method === 'Runtime.consoleAPICalled' && e.params.type === 'error')))
  .map((e) => JSON.stringify(e.params).slice(0, 300));

const base = `chrome-extension://${extId}`;
await send('Browser.setDownloadBehavior', { behavior: 'allow', downloadPath: downloads, eventsEnabled: true });

// ---------------------------------------------------------------- options page
const options = await openPage(`${base}/options.html`);
await waitFor(options.sessionId, `document.getElementById('backend-url')?.value === 'http://127.0.0.1:48101'`);
check('options shows default backend', await evaluate(options.sessionId, `document.getElementById('backend-url').value`) === 'http://127.0.0.1:48101');
await evaluate(options.sessionId, `(() => { const i = document.getElementById('backend-url'); i.value = '192.168.1.5:1'; i.dispatchEvent(new Event('input')); })()`);
check('options rejects a non-loopback address', await evaluate(options.sessionId, `!document.getElementById('url-error').hidden && document.getElementById('url-error').textContent.includes('on this computer')`));
await evaluate(options.sessionId, `document.getElementById('backend-form').requestSubmit()`);
await sleep(300);
const notSaved = await evaluate(options.sessionId, `chrome.storage.local.get('settings').then((d) => JSON.stringify(d))`);
check('non-loopback address is not saved', !notSaved.includes('192.168'), notSaved);
await evaluate(options.sessionId, `chrome.storage.local.set({ settings: { backend_url: 'http://192.168.1.5:1' } })`);
const stale = await openPage(`${base}/index.html`, false);
await sleep(1500);
const staleTargets = await evaluate(stale.sessionId, `performance.getEntriesByType('resource').map((e) => e.name).filter((n) => n.includes('/api/'))`);
check('stored non-loopback address is ignored (default backend used)', staleTargets.length > 0 && staleTargets.every((n) => n.startsWith('http://127.0.0.1:48101/')), JSON.stringify(staleTargets.slice(0, 3)));
await send('Target.closeTarget', { targetId: stale.targetId });
await evaluate(options.sessionId, `chrome.storage.local.remove('settings')`);
await evaluate(options.sessionId, `(() => { const i = document.getElementById('backend-url'); i.value = 'http://u:p@127.0.0.1'; i.dispatchEvent(new Event('input')); })()`);
check('options rejects credentials in URL', await evaluate(options.sessionId, `!document.getElementById('url-error').hidden`));
await evaluate(options.sessionId, `(() => { const i = document.getElementById('backend-url'); i.value = '127.0.0.1:${backendPort}/'; document.getElementById('backend-form').requestSubmit(); })()`);
const connected = await waitFor(options.sessionId, `document.getElementById('test-result').textContent.includes('Connected')`);
check('options saves + Test connection hits /api/health', connected, await evaluate(options.sessionId, `document.getElementById('test-result').textContent + ' | value=' + document.getElementById('backend-url').value`));
const stored = await evaluate(options.sessionId, `chrome.storage.local.get('settings').then((d) => JSON.stringify(d))`);
check('backend URL stored normalized in chrome.storage.local', stored === `{"settings":{"backend_url":"http://127.0.0.1:${backendPort}"}}`, stored);
check('options page has no errors', problems(options.sessionId).length === 0, problems(options.sessionId).join(' || '));

// ---------------------------------------------------------------- app page
requests.length = 0;
const app = await openPage(`${base}/index.html?mailto=${encodeURIComponent('mailto:friend@example.test?subject=From%20menu')}`, false);
const composed = await waitFor(app.sessionId, `Boolean(document.querySelector('[aria-label="Compose message"]'))`, 10000);
check('launch ?mailto= opens composer', composed);
check('launch parameter stripped from address', await evaluate(app.sessionId, `location.search === ''`), await evaluate(app.sessionId, 'location.href'));
check('composer prefilled from mailto', await evaluate(app.sessionId, `[...document.querySelectorAll('[aria-label="Compose message"] input')].some((i) => i.value.includes('friend@example.test')) && [...document.querySelectorAll('[aria-label="Compose message"] input')].some((i) => i.value === 'From menu')`));
check(`app requests reach the configured backend (port ${backendPort})`, requests.some((r) => r.path === '/api/accounts') && requests.some((r) => r.path === '/api/mail/messages'), JSON.stringify(requests.slice(0, 4)));
// Close composer (Escape) then open the message.
await evaluate(app.sessionId, `[...document.querySelectorAll('[aria-label="Compose message"] button')].find((b) => /close|cancel|discard/i.test(b.getAttribute('aria-label') || b.textContent))?.click()`);
await sleep(300);
if (await evaluate(app.sessionId, `Boolean(document.querySelector('[aria-label="Compose message"]'))`)) {
  await evaluate(app.sessionId, `window.confirm = () => true; [...document.querySelectorAll('[aria-label="Compose message"] button')].find((b) => /close|cancel|discard/i.test(b.getAttribute('aria-label') || b.textContent))?.click()`);
  await sleep(300);
}
await evaluate(app.sessionId, `[...document.querySelectorAll('.message-rows button')].find((b) => b.textContent.includes('Smoke subject'))?.click()`);
const frameReady = await waitFor(app.sessionId, `Boolean(document.querySelector('iframe.html-frame'))`, 8000);
check('message HTML rendered in frame host iframe', frameReady && await evaluate(app.sessionId, `document.querySelector('iframe.html-frame').getAttribute('src') === 'frame-host.html'`));
await sleep(1200);
const rect = await evaluate(app.sessionId, `(() => { const f = document.querySelector('iframe.html-frame'); f.scrollIntoView(); const r = f.getBoundingClientRect(); return { x: r.left, y: r.top, w: r.width, h: r.height }; })()`);
for (const type of ['mousePressed', 'mouseReleased']) {
  await send('Input.dispatchMouseEvent', { type, x: rect.x + 40, y: rect.y + 29, button: 'left', clickCount: 1 }, app.sessionId);
}
const modal = await waitFor(app.sessionId, `document.body.textContent.includes('https://example.com/landing') && document.body.textContent.includes('Continue only if you trust')`, 5000);
check('trusted click on email link reaches app via nested-frame bridge + relay (ExternalLinkModal)', modal, JSON.stringify(rect));
await evaluate(app.sessionId, `[...document.querySelectorAll('button')].find((b) => b.textContent.trim() === 'Cancel')?.click()`);

// Direct srcdoc in an extension page: the nonce script must be blocked (why frame-host exists).
const direct = await evaluate(app.sessionId, `new Promise((resolve) => {
  let got = false; const f = document.createElement('iframe'); f.setAttribute('sandbox', 'allow-scripts');
  addEventListener('message', (e) => { if (e.source === f.contentWindow) got = true; });
  f.srcdoc = '<meta http-equiv="Content-Security-Policy" content="script-src \\'nonce-abc\\'"><script nonce="abc">parent.postMessage("direct", "*")<\\/script>';
  document.body.append(f); setTimeout(() => { f.remove(); resolve(got); }, 1000); })`);
check('control: plain srcdoc inline script is blocked on extension page', direct === false, String(direct));
// Frame host keeps the document's own meta CSP: a non-nonce inline script stays blocked.
const hostCsp = await evaluate(app.sessionId, `new Promise((resolve) => {
  const got = []; const f = document.createElement('iframe'); f.setAttribute('sandbox', 'allow-scripts'); f.src = 'frame-host.html';
  addEventListener('message', (e) => { if (e.source === f.contentWindow) got.push(e.data); });
  f.onload = () => f.contentWindow.postMessage({ type: 'webmail:frame-render', relay: true, title: 't', srcDoc: '<meta http-equiv="Content-Security-Policy" content="script-src \\'nonce-abc\\'"><script nonce="abc">parent.postMessage("nonce-ok", "*")<\\/script><script>parent.postMessage("inline-leak", "*")<\\/script>' }, '*');
  document.body.append(f); setTimeout(() => { f.remove(); resolve(got); }, 1200); })`);
check('frame host: nonce script runs, non-nonce inline script blocked', JSON.stringify(hostCsp) === '["nonce-ok"]', JSON.stringify(hostCsp));
const report = await evaluate(app.sessionId, `new Promise((resolve) => {
  const got = []; const f = document.createElement('iframe'); f.setAttribute('sandbox', 'allow-scripts'); f.src = 'frame-host.html';
  addEventListener('message', (e) => { if (e.source === f.contentWindow) got.push(e.data); });
  f.onload = () => f.contentWindow.postMessage({ type: 'webmail:frame-render', relay: true, title: 't', srcDoc: '<head><meta http-equiv="Content-Security-Policy" content="default-src \\'none\\'; script-src \\'unsafe-inline\\'; connect-src \\'none\\'"></head><script>fetch("http://127.0.0.1:${backendPort}/api/health").then(() => parent.postMessage("fetch-leak", "*"), () => parent.postMessage("fetch-blocked", "*")); parent.postMessage("report-script-ran", "*")<\\/script>' }, '*');
  document.body.append(f); setTimeout(() => { f.remove(); resolve(got); }, 1500); })`);
check('frame host: doctor-report style inline script runs, network blocked', JSON.stringify(report.sort()) === '["fetch-blocked","report-script-ran"]', JSON.stringify(report));

// Downloads: .eml via fetch -> blob -> anchor, file name from Content-Disposition.
requests.length = 0;
await evaluate(app.sessionId, `[...document.querySelectorAll('a')].find((a) => a.textContent.includes('.eml'))?.click()`);
let eml = null;
for (let i = 0; i < 40 && !eml; i += 1) { await sleep(200); const f = path.join(downloads, 'message-1.eml'); if (fs.existsSync(f)) eml = fs.readFileSync(f, 'utf8'); }
check('.eml download saved as message-1.eml from cross-origin backend', eml?.includes('Subject: Smoke') ?? false, `${eml === null ? 'missing' : 'ok'}; requests=${JSON.stringify(requests)}; files=${fs.readdirSync(downloads)}`);
check('app tab still on app page after download click', await evaluate(app.sessionId, `location.pathname === '/index.html'`));
await evaluate(app.sessionId, `[...document.querySelectorAll('a')].find((a) => a.textContent.includes('notes.txt'))?.click()`);
let notes = null;
for (let i = 0; i < 40 && !notes; i += 1) { await sleep(200); const f = path.join(downloads, 'notes.txt'); if (fs.existsSync(f)) notes = fs.readFileSync(f, 'utf8'); }
check('attachment download saved as notes.txt', notes === 'notes', String(notes));
const failedDownload = await evaluate(app.sessionId, `(() => { let message = ''; window.alert = (m) => { message = m; }; const a = [...document.querySelectorAll('a')].find((x) => x.textContent.includes('notes.txt')); a.href = a.href.replace('index=0', 'index=9'); a.click(); return new Promise((r) => setTimeout(() => r(message), 800)); })()`);
check('failed download (401 password_required) reported to user', failedDownload.includes('locked'), failedDownload);

// Existing tab receives a mailto from the service worker (context-menu path).
const swTarget = (await send('Target.getTargets')).targetInfos.find((t) => t.type === 'service_worker' && t.url.startsWith(base));
const sw = await send('Target.attachToTarget', { targetId: swTarget.targetId, flatten: true });
const tabId = await evaluate(sw.sessionId, `chrome.runtime.getContexts({ contextTypes: ['TAB'] }).then((c) => c.find((x) => x.documentUrl.includes('/index.html'))?.tabId)`);
const reply = await evaluate(sw.sessionId, `chrome.runtime.sendMessage({ type: 'webmail:compose-mailto', url: 'mailto:second@example.test?subject=Again', tabId: ${tabId} })`);
check('existing app tab accepts mailto from service worker', reply?.accepted === true, JSON.stringify(reply));
check('composer opened for second mailto', await waitFor(app.sessionId, `[...document.querySelectorAll('[aria-label="Compose message"] input')].some((i) => i.value.includes('second@example.test'))`, 5000));
const wrongTab = await evaluate(sw.sessionId, `chrome.runtime.sendMessage({ type: 'webmail:compose-mailto', url: 'mailto:x@example.test', tabId: 999999 }).then((r) => r ?? null, (e) => 'rejected: ' + e.message)`);
check('mailto for another tab id is ignored', !wrongTab || wrongTab.accepted !== true, JSON.stringify(wrongTab));
const menu = await evaluate(sw.sessionId, `new Promise((r) => chrome.contextMenus.create({ id: 'probe', title: 'p', contexts: ['link'], targetUrlPatterns: ['mailto:*'] }, () => r(chrome.runtime.lastError?.message ?? 'ok')))`);
check('contextMenus accepts targetUrlPatterns mailto:*', menu === 'ok', menu);
const menuExists = await evaluate(sw.sessionId, `chrome.contextMenus.update('webmail-compose-mailto', {}).then(() => 'ok', (e) => e.message)`);
check('"Compose with Webmail" context menu registered', menuExists === 'ok', menuExists);
const openTabs = await evaluate(sw.sessionId, `chrome.runtime.getContexts({ contextTypes: ['TAB'] }).then((c) => c.filter((x) => x.documentUrl.includes('/index.html')).length)`);
check('mailto reused the existing app tab (no new tab)', openTabs === 1, String(openTabs));
const openReply = await evaluate(options.sessionId, `chrome.runtime.sendMessage({ type: 'webmail:open-app' })`);
const tabsAfterOpen = await evaluate(sw.sessionId, `chrome.runtime.getContexts({ contextTypes: ['TAB'] }).then((c) => c.filter((x) => x.documentUrl.includes('/index.html')).length)`);
check('options "Open webmail" focuses the existing app tab via service worker', openReply?.ok === true && tabsAfterOpen === 1, JSON.stringify(openReply) + ' tabs=' + tabsAfterOpen);
// IMAP account (control): mutating actions are offered.
check('IMAP account: Delete / Flag / Mark read offered', await evaluate(app.sessionId, `(() => { const t = [...document.querySelectorAll('.message-actions button')].map((b) => b.textContent); return t.some((x) => x.includes('Delete')) && t.some((x) => x.includes('Flag')) && t.some((x) => /Mark (un)?read/.test(x)); })()`));

// POP3 compatibility account: IMAP-only actions are hidden, with a note.
await evaluate(app.sessionId, `[...document.querySelectorAll('.account-item')].find((b) => b.textContent.includes('pop@example.test'))?.click()`);
check('POP3 account is labelled in the sidebar', await waitFor(app.sessionId, `[...document.querySelectorAll('.account-item')].some((b) => b.textContent.includes('pop@example.test') && b.textContent.includes('POP3'))`, 5000));
check('POP3 account shows the compatibility-mode note', await waitFor(app.sessionId, `document.querySelector('.pop3-note')?.textContent.includes('POP3 compatibility mode')`, 5000));
await waitFor(app.sessionId, `[...document.querySelectorAll('.message-rows button')].some((b) => b.textContent.includes('Smoke subject'))`, 5000);
check('POP3 account: no selection checkboxes, Move to Trash or read-status filter', await evaluate(app.sessionId, `!document.querySelector('.message-checkbox') && ![...document.querySelectorAll('button')].some((b) => b.textContent.includes('Move to Trash')) && !document.body.textContent.includes('Message status')`));
await evaluate(app.sessionId, `[...document.querySelectorAll('.message-rows button')].find((b) => b.textContent.includes('Smoke subject'))?.click()`);
await waitFor(app.sessionId, `Boolean(document.querySelector('.message-actions'))`, 5000);
check('POP3 account: Delete / Flag / Mark read hidden, .eml download kept', await evaluate(app.sessionId, `(() => { const t = [...document.querySelectorAll('.message-actions button')].map((b) => b.textContent); return t.some((x) => x.includes('Reply')) && !t.some((x) => x.includes('Delete') || x.includes('Flag') || /Mark (un)?read/.test(x)) && [...document.querySelectorAll('.message-actions a')].some((a) => a.textContent.includes('.eml')); })()`));

requests.length = 0;
await evaluate(app.sessionId, `fetch('http://127.0.0.1:${backendPort}/api/health', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' }).then((r) => r.status)`);
console.log('INFO POST Origin header seen by backend:', JSON.stringify(requests.map((r) => r.origin)));
check('app page has no console errors / exceptions', problems(app.sessionId).length === 0, problems(app.sessionId).join(' || '));

// ---------------------------------------------------------------- extension_pages CSP (own tab: violations log errors)
const probe = await openPage(`${base}/options.html`, false);
await waitFor(probe.sessionId, `document.readyState === 'complete'`);
const csp = await evaluate(probe.sessionId, `(async () => {
  const violations = [];
  document.addEventListener('securitypolicyviolation', (e) => violations.push(e.effectiveDirective + ' ' + e.blockedURI));
  const tryFetch = (url) => fetch(url, { cache: 'no-store' }).then((r) => 'ok ' + r.status, (e) => 'error');
  const out = {
    loopback: await tryFetch('http://127.0.0.1:${backendPort}/api/health'),
    localhost: await tryFetch('http://localhost:1/'),
    remote: await tryFetch('http://192.0.2.10:48101/api/health'),
    remoteTls: await tryFetch('https://example.com/'),
  };
  const img = (src) => new Promise((r) => { const i = new Image(); i.onload = () => r('load'); i.onerror = () => r('error'); i.src = src; });
  out.dataImg = await img('data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7');
  const gif = Uint8Array.from(atob('R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7'), (c) => c.charCodeAt(0));
  out.blobImg = await img(URL.createObjectURL(new Blob([gif], { type: 'image/gif' })));
  out.remoteImg = await img('https://example.com/pixel.gif');
  const frame = document.createElement('iframe'); frame.src = 'https://example.com/'; document.body.append(frame);
  const form = document.createElement('form'); form.action = 'https://example.com/post'; form.method = 'post'; form.target = '_blank'; document.body.append(form);
  form.submit();
  await new Promise((r) => setTimeout(r, 1500));
  out.violations = violations;
  return out;
})()`);
const blocked = (directive, uri) => csp.violations.some((v) => v.startsWith(directive) && v.includes(uri));
check('CSP connect-src allows the loopback backend', csp.loopback === 'ok 200', JSON.stringify(csp));
check('CSP connect-src allows localhost (no violation)', !csp.violations.some((v) => v.includes('localhost')), JSON.stringify(csp.violations));
check('CSP connect-src blocks remote http and https backends', csp.remote === 'error' && csp.remoteTls === 'error' && blocked('connect-src', '192.0.2.10') && blocked('connect-src', 'example.com'), JSON.stringify(csp));
check('CSP img-src allows data: and blob:, blocks remote images', csp.dataImg === 'load' && csp.blobImg === 'load' && csp.remoteImg === 'error' && blocked('img-src', 'example.com'), JSON.stringify(csp));
check('CSP frame-src blocks foreign frames', blocked('frame-src', 'example.com'), JSON.stringify(csp.violations));
check('CSP form-action blocks form posts', blocked('form-action', 'example.com'), JSON.stringify(csp.violations));
await send('Target.closeTarget', { targetId: probe.targetId });


const failed = results.filter((r) => !r.ok).length;
console.log(`\n${results.length - failed}/${results.length} checks passed`);
ws.close();
child.kill();
server.close();
process.exit(failed ? 1 : 0);
