#!/usr/bin/env node
/**
 * End-to-end test of the BUILT extension (dist/) in headless Chrome against
 * the REAL Rust mail-backend executable, which talks to fake IMAP/SMTP
 * servers (mail-proto testkit) over loopback.
 *
 *   npm run build:extension
 *   (cd .. && cargo build -p mail-backend)
 *   npm run test:e2e:real
 *
 * Inputs (environment):
 *   WEBMAIL_E2E_BACKEND   mail-backend executable (default ../target/debug/mail-backend[.exe])
 *   WEBMAIL_E2E_FAKEMAIL  fake IMAP/SMTP executable (default: tools/fake-mail, built here with
 *                         cargo into tools/fake-mail/target on first use). It prints
 *                         "IMAP <port> SMTP <port> POP3 <port>" and serves user@example.com /
 *                         e2e-Secret-Pass-7319 (IMAP, "Smoke subject" in INBOX) and
 *                         pop@example.com (POP3, "POP3 smoke").
 *   WEBMAIL_E2E_BACKEND_PORT  fixed backend port (default 48197; OAuth needs a known public URL)
 *   WEBMAIL_E2E_BROWSER   Chrome/Edge executable (default: Chrome's usual install paths)
 *
 * Every backend path (settings, profiles, data) lives in a temporary folder.
 * Covers: options page Test connection against the real /api/health, the
 * Origin / Sec-Fetch-Site guard accepting extension GET and POST requests,
 * unlock through the Connect screen, message list and HTML message through
 * the frame host, .eml / attachment downloads with the backend's real
 * Content-Disposition, settings PUT, signature multipart PUT, composing and
 * sending through SMTP, trash prepare, an Inbox Doctor account audit, the
 * OAuth callback posting to the extension origin, lock, and a POP3
 * (compatibility mode) account unlocked through the Connect screen.
 */
import { spawn, spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import readline from 'node:readline';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const exe = process.platform === 'win32' ? '.exe' : '';
const backendExe = process.env.WEBMAIL_E2E_BACKEND || path.join(ROOT, '..', 'target', 'debug', `mail-backend${exe}`);
const browser = [
  process.env.WEBMAIL_E2E_BROWSER,
  'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
  'C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe',
  '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
  '/usr/bin/google-chrome',
  '/usr/bin/chromium',
].filter(Boolean).find((candidate) => fs.existsSync(candidate));
const extDir = path.join(ROOT, 'dist');
const cdpPort = process.env.WEBMAIL_E2E_CDP_PORT || '9341';
const USER = 'user@example.com';
const PASSWORD = 'e2e-Secret-Pass-7319';
if (!browser) throw new Error('No Chrome found; set WEBMAIL_E2E_BROWSER.');
if (!fs.existsSync(backendExe)) throw new Error(`${backendExe} not found; run cargo build -p mail-backend.`);
if (!fs.existsSync(path.join(extDir, 'manifest.json'))) throw new Error('dist/ has no manifest.json; run npm run build:extension first.');

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const results = [];
const check = (name, ok, detail = '') => { results.push({ name, ok }); console.log(`${ok ? 'PASS' : 'FAIL'} ${name}${detail ? ` -- ${detail}` : ''}`); };
const children = [];
const cleanup = () => { for (const child of children) { try { child.kill(); } catch { /* gone */ } } };
process.on('exit', cleanup);

/** Spawn and resolve with the first stdout line matching `pattern`. */
function startProcess(file, args, env, pattern) {
  const child = spawn(file, args, { env: { ...process.env, ...env }, stdio: ['ignore', 'pipe', 'pipe'] });
  children.push(child);
  const output = [];
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`${file} did not start:\n${output.join('\n')}`)), 60000);
    for (const stream of [child.stdout, child.stderr]) {
      readline.createInterface({ input: stream }).on('line', (line) => {
        output.push(line);
        const match = pattern.exec(line);
        if (match) { clearTimeout(timer); resolve({ child, match, output }); }
      });
    }
    child.on('exit', (code) => { clearTimeout(timer); reject(new Error(`${file} exited (${code}):\n${output.join('\n')}`)); });
  });
}

// ---------------------------------------------------------------- fake mail + backend
let fakeMail = process.env.WEBMAIL_E2E_FAKEMAIL;
if (!fakeMail) {
  const manifest = path.join(ROOT, 'tools', 'fake-mail', 'Cargo.toml');
  console.log('INFO building tools/fake-mail (first run takes a while)...');
  const build = spawnSync('cargo', ['build', '--quiet', '--manifest-path', manifest], { stdio: 'inherit' });
  if (build.status !== 0) throw new Error('cargo build of tools/fake-mail failed');
  fakeMail = path.join(ROOT, 'tools', 'fake-mail', 'target', 'debug', `webmail-e2e-fake-mail${exe}`);
}
const fake = await startProcess(fakeMail, [], {}, /^IMAP (\d+) SMTP (\d+) POP3 (\d+)/);
const [, imapPort, smtpPort, pop3Port] = fake.match;
const fakeOutput = fake.output;
if (!imapPort || !smtpPort) throw new Error('fake-mail did not report its ports.');

const root = fs.mkdtempSync(path.join(os.tmpdir(), 'webmail-real-'));
const appdata = path.join(root, 'appdata');
fs.mkdirSync(appdata, { recursive: true });
const backendPort = process.env.WEBMAIL_E2E_BACKEND_PORT || '48197';
const backendProcess = await startProcess(backendExe, ['--port', backendPort], {
  // OAuth start needs a configured client; the test never contacts the provider.
  PUBLIC_BACKEND_URL: `http://localhost:${backendPort}`,
  GOOGLE_OAUTH_CLIENT_ID: 'e2e-client.apps.example.com', GOOGLE_OAUTH_CLIENT_SECRET: 'e2e-client-secret',
  WEBMAIL_SETTINGS_PATH: path.join(root, 'settings.json'),
  MAIL_SERVERS_PATH: path.join(root, 'mail-servers.json'),
  DATA_DIRECTORY: path.join(root, 'data'),
  APPDATA: appdata, LOCALAPPDATA: appdata, XDG_CONFIG_HOME: appdata, XDG_DATA_HOME: appdata, HOME: appdata,
  RUST_LOG: 'info', MAIL_BACKEND_ADDR: '', HTTP_PROXY: '', HTTPS_PROXY: '',
}, /Backend:\s*(\S+)/);
const backendUrl = backendProcess.match[1].replace(/\/+$/, '');
const backendLog = backendProcess.output;
console.log(`INFO backend ${backendUrl}, IMAP ${imapPort}, SMTP ${smtpPort}, POP3 ${pop3Port}`);

// ---------------------------------------------------------------- browser + CDP
const downloads = fs.mkdtempSync(path.join(os.tmpdir(), 'webmail-real-dl-'));
const profile = fs.mkdtempSync(path.join(os.tmpdir(), 'webmail-real-profile-'));
const chrome = spawn(browser, [
  `--user-data-dir=${profile}`, `--remote-debugging-port=${cdpPort}`, '--headless=new', '--no-first-run',
  '--no-default-browser-check', '--enable-unsafe-extension-debugging', '--window-size=1400,900', 'about:blank',
], { stdio: 'ignore' });
children.push(chrome);
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
  if (data.id && pending.has(data.id)) { pending.get(data.id)(data); pending.delete(data.id); } else events.push(data);
});
const send = (method, params = {}, sessionId) => new Promise((resolve, reject) => {
  const id = ++nextId;
  pending.set(id, (data) => (data.error ? reject(new Error(`${method}: ${data.error.message}`)) : resolve(data.result)));
  ws.send(JSON.stringify({ id, method, params, ...(sessionId ? { sessionId } : {}) }));
});
const evaluate = async (sessionId, expression) => {
  const result = await send('Runtime.evaluate', { expression, awaitPromise: true, returnByValue: true }, sessionId);
  if (result.exceptionDetails) throw new Error(result.exceptionDetails.exception?.description ?? result.exceptionDetails.text);
  return result.result.value;
};
const waitFor = async (sessionId, expression, timeout = 10000) => {
  const end = Date.now() + timeout;
  while (Date.now() < end) {
    try { if (await evaluate(sessionId, expression)) return true; } catch { /* navigating */ }
    await sleep(150);
  }
  return false;
};
async function openPage(url) {
  const { targetId } = await send('Target.createTarget', { url });
  const { sessionId } = await send('Target.attachToTarget', { targetId, flatten: true });
  await send('Runtime.enable', {}, sessionId);
  await send('Log.enable', {}, sessionId);
  await send('Network.enable', {}, sessionId);
  return { targetId, sessionId };
}
const problems = (sessionId) => events.filter((e) => e.sessionId === sessionId && (
  e.method === 'Runtime.exceptionThrown'
  || (e.method === 'Log.entryAdded' && e.params.entry.level === 'error' && e.params.entry.source !== 'network')
  || (e.method === 'Runtime.consoleAPICalled' && e.params.type === 'error')))
  .map((e) => JSON.stringify(e.params).slice(0, 300));
/** Backend responses seen by a page: [{ status, url, method }]. */
const responses = (sessionId) => {
  const methods = new Map(events.filter((e) => e.sessionId === sessionId && e.method === 'Network.requestWillBeSent')
    .map((e) => [e.params.requestId, e.params.request.method]));
  return events.filter((e) => e.sessionId === sessionId && e.method === 'Network.responseReceived' && e.params.response.url.startsWith(backendUrl))
    .map((e) => ({ status: e.params.response.status, method: methods.get(e.params.requestId), url: e.params.response.url.slice(backendUrl.length).split('?')[0] }));
};
/** Focus a field and type into it like a user (works with React inputs). */
const typeInto = async (sessionId, selector, text) => {
  await evaluate(sessionId, `(() => { const el = ${selector}; el.focus(); el.select?.(); return true; })()`);
  await send('Input.insertText', { text }, sessionId);
};

const loaded = await send('Extensions.loadUnpacked', { path: extDir });
const base = `chrome-extension://${loaded.id}`;
await send('Browser.setDownloadBehavior', { behavior: 'allow', downloadPath: downloads, eventsEnabled: true });
await sleep(800);

// ---------------------------------------------------------------- options page -> real backend
const options = await openPage(`${base}/options.html`);
await waitFor(options.sessionId, `document.getElementById('backend-url')?.value === 'http://127.0.0.1:48101'`);
await evaluate(options.sessionId, `(() => { const i = document.getElementById('backend-url'); i.value = ${JSON.stringify(backendUrl)}; document.getElementById('backend-form').requestSubmit(); })()`);
const connected = await waitFor(options.sessionId, `document.getElementById('test-result').textContent.includes('Connected')`);
check('options Test connection against the real backend', connected, await evaluate(options.sessionId, `document.getElementById('test-result').textContent`));

// ---------------------------------------------------------------- connect screen
const app = await openPage(`${base}/index.html`);
await waitFor(app.sessionId, `document.body.textContent.includes('Connect')`);
// Save a server profile through the backend (PUT, extension Origin) like the settings UI.
const profileStatus = await evaluate(app.sessionId, `fetch(${JSON.stringify(`${backendUrl}/api/mail/servers/fake`)}, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ incoming_server: '127.0.0.1', incoming_port: ${imapPort}, incoming_protocol: 'NONE', outgoing_server: '127.0.0.1', outgoing_port: ${smtpPort}, outgoing_protocol: 'NONE', email_address: '${USER}', display_name: 'Example User' }) }).then((r) => r.status)`);
check('PUT /api/mail/servers/{key} from the extension origin is accepted', profileStatus === 201, String(profileStatus));
await send('Page.reload', {}, app.sessionId);
await waitFor(app.sessionId, `[...document.querySelectorAll('select option')].some((o) => o.value === 'fake')`);
await evaluate(app.sessionId, `(() => { const s = [...document.querySelectorAll('select')].find((x) => [...x.options].some((o) => o.value === 'fake')); const set = Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype, 'value').set; set.call(s, 'fake'); s.dispatchEvent(new Event('change', { bubbles: true })); return true; })()`);
await typeInto(app.sessionId, `document.querySelector('input[type=email]')`, USER);
await typeInto(app.sessionId, `document.querySelector('input[type=password]')`, PASSWORD);
await evaluate(app.sessionId, `[...document.querySelectorAll('button')].find((b) => b.textContent.trim() === 'Connect').click()`);
const listed = await waitFor(app.sessionId, `document.body.textContent.includes('Smoke subject')`, 20000);
check('unlock via Connect screen, then message list from fake IMAP', listed, await evaluate(app.sessionId, `document.querySelector('.banner.error')?.textContent ?? ''`));
check('backend log never contains the password', !backendLog.join('\n').includes(PASSWORD));

// ---------------------------------------------------------------- message view
await evaluate(app.sessionId, `[...document.querySelectorAll('.message-rows button')].find((b) => b.textContent.includes('Smoke subject'))?.click()`);
const frameReady = await waitFor(app.sessionId, `document.querySelector('iframe.html-frame')?.getAttribute('src') === 'frame-host.html'`);
check('HTML body rendered through the sandboxed frame host', frameReady);
await sleep(1200);
const rect = await evaluate(app.sessionId, `(() => { const f = document.querySelector('iframe.html-frame'); f.scrollIntoView(); const r = f.getBoundingClientRect(); return { x: r.left, y: r.top, w: r.width, h: r.height }; })()`);
// Click the link: it is the second line of the body (after "Body text").
let modal = false;
for (let dy = 6; dy <= 130 && !modal; dy += 8) {
  for (const type of ['mousePressed', 'mouseReleased']) {
    await send('Input.dispatchMouseEvent', { type, x: rect.x + 30, y: rect.y + dy, button: 'left', clickCount: 1 }, app.sessionId);
  }
  if (await waitFor(app.sessionId, `document.body.textContent.includes('https://example.com/landing') && document.body.textContent.includes('Continue only if you trust')`, 400)) modal = true;
}
check('email link click reaches the link confirmation dialog', modal);
await evaluate(app.sessionId, `[...document.querySelectorAll('button')].find((b) => b.textContent.trim() === 'Cancel')?.click()`);

// ---------------------------------------------------------------- downloads with the real Content-Disposition
await evaluate(app.sessionId, `[...document.querySelectorAll('a')].find((a) => a.textContent.includes('.eml'))?.click()`);
const waitFile = async (pattern) => {
  for (let i = 0; i < 50; i += 1) {
    const hit = fs.readdirSync(downloads).find((name) => pattern.test(name) && !name.endsWith('.crdownload'));
    if (hit) return hit;
    await sleep(200);
  }
  return null;
};
const emlName = await waitFile(/\.eml$/);
check('.eml downloaded under the backend file name', Boolean(emlName) && fs.readFileSync(path.join(downloads, emlName), 'utf8').includes('Smoke subject'), `${emlName}; files=${fs.readdirSync(downloads)}`);
await evaluate(app.sessionId, `[...document.querySelectorAll('a')].find((a) => a.textContent.includes('notes.txt'))?.click()`);
const notesName = await waitFile(/^notes/);
check('attachment downloaded as notes.txt', notesName === 'notes.txt' && fs.readFileSync(path.join(downloads, notesName), 'utf8').trim() === 'notes', String(notesName));

// ---------------------------------------------------------------- settings / signature / send
const settings = await evaluate(app.sessionId, `fetch(${JSON.stringify(`${backendUrl}/api/settings`)}, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ messages_per_page: 7 }) }).then(async (r) => [r.status, await r.json()])`);
check('PUT /api/settings', settings[0] === 200 && settings[1].messages_per_page === 7, JSON.stringify(settings));
const signature = await evaluate(app.sessionId, `(() => { const f = new FormData(); f.append('signature', JSON.stringify({ text: '<p>Regards</p>', uploads: [] })); return fetch(${JSON.stringify(`${backendUrl}/api/mail/signature?account=${encodeURIComponent(USER)}`)}, { method: 'PUT', body: f }).then(async (r) => [r.status, await r.json()]); })()`);
check('PUT /api/mail/signature multipart (field "signature")', signature[0] === 200 && JSON.stringify(signature[1]).includes('Regards'), JSON.stringify(signature).slice(0, 300));

await evaluate(app.sessionId, `[...document.querySelectorAll('button')].find((b) => b.textContent.trim().endsWith('Compose'))?.click()`);
const composer = await waitFor(app.sessionId, `Boolean(document.querySelector('[aria-label="Compose message"]'))`);
check('composer opens', composer);
if (composer) {
  await typeInto(app.sessionId, `document.querySelector('[aria-label="Compose message"] input[placeholder^="a@example.com"]')`, 'friend@example.org');
  await typeInto(app.sessionId, `[...document.querySelectorAll('[aria-label="Compose message"] label')].find((l) => l.querySelector('span')?.textContent.trim() === 'Subject').querySelector('input')`, 'Real backend e2e');
  await evaluate(app.sessionId, `[...document.querySelectorAll('[aria-label="Compose message"] button')].find((b) => b.type === 'submit' && b.textContent.trim() === 'Send').click()`);
  const sent = await waitFor(app.sessionId, `!document.querySelector('[aria-label="Compose message"]')`, 15000);
  await sleep(800);
  check('send through fake SMTP closes the composer', sent, await evaluate(app.sessionId, `document.querySelector('[aria-label="Compose message"] .banner.error')?.textContent ?? ''`));
  check('fake SMTP received the message', fakeOutput.some((line) => line.startsWith('SMTP-MAIL') && line.includes('friend@example.org')), fakeOutput.slice(-3).join(' | '));
}

// ---------------------------------------------------------------- trash prepare
const trash = await evaluate(app.sessionId, `fetch(${JSON.stringify(`${backendUrl}/api/mail/trash/prepare`)}, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ account: ${JSON.stringify(USER)}, folder: 'Trash', archive: true }) }).then(async (r) => [r.status, await r.json()])`);
check('POST /api/mail/trash/prepare answers with an operation (or a clear refusal)', trash[0] === 200 ? typeof trash[1].operation_id === 'string' : typeof trash[1].detail === 'string', JSON.stringify(trash).slice(0, 300));
if (trash[0] === 200) {
  const discard = await evaluate(app.sessionId, `fetch(${JSON.stringify(`${backendUrl}/api/mail/trash/`)} + encodeURIComponent(${JSON.stringify(trash[1].operation_id)}) + '?account=' + encodeURIComponent(${JSON.stringify(USER)}), { method: 'DELETE' }).then(async (r) => [r.status, await r.json()])`);
  check('DELETE /api/mail/trash/{id} discards (returns the id like main.py)', discard[0] === 200 && discard[1].discarded === trash[1].operation_id, JSON.stringify(discard));
}

// ---------------------------------------------------------------- Inbox Doctor: account audit + report + ZIP
const job = await evaluate(app.sessionId, `fetch(${JSON.stringify(`${backendUrl}/api/mail/jobs/account`)}, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ account: ${JSON.stringify(USER)}, days: 7 }) }).then(async (r) => [r.status, await r.json()])`);
check('POST /api/mail/jobs/account creates a job (201)', job[0] === 201 && typeof job[1].id === 'string', JSON.stringify(job).slice(0, 300));
if (job[0] === 201) {
  const jobUrl = `${backendUrl}/api/jobs/${encodeURIComponent(job[1].id)}`;
  let status = job[1].status;
  for (let i = 0; i < 100 && (status === 'queued' || status === 'in_progress'); i += 1) {
    await sleep(300);
    status = (await evaluate(app.sessionId, `fetch(${JSON.stringify(jobUrl)}).then((r) => r.json())`)).status;
  }
  check('doctor account job completes against fake IMAP', status === 'completed', status);
  const files = await evaluate(app.sessionId, `fetch(${JSON.stringify(`${jobUrl}/files`)}).then((r) => r.json())`);
  check('job files list the HTML report', Array.isArray(files.files) && files.files.includes('inbox_audit.html'), JSON.stringify(files).slice(0, 300));
  const zip = await evaluate(app.sessionId, `fetch(${JSON.stringify(`${jobUrl}/download-zip`)}).then(async (r) => ({ status: r.status, disposition: r.headers.get('Content-Disposition'), magic: String.fromCharCode(...new Uint8Array(await r.arrayBuffer()).slice(0, 2)) }))`);
  check('download-zip readable from the extension with Content-Disposition', zip.status === 200 && zip.magic === 'PK' && /filename/i.test(zip.disposition ?? ''), JSON.stringify(zip));
}

// ---------------------------------------------------------------- OAuth callback posts to the extension origin
const oauth = await send('Runtime.evaluate', { userGesture: true, awaitPromise: true, returnByValue: true, expression: `(async () => {
  const popup = window.open('about:blank', 'inbox-doctor-sign-in', 'width=600,height=720');
  if (!popup) return { error: 'popup blocked' };
  const response = await fetch(${JSON.stringify(`${backendUrl}/api/mail/oauth/start`)}, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ provider: 'google', email: 'someone@gmail.com', days: 7 }) });
  const started = await response.json();
  if (!response.ok) { popup.close(); return { error: response.status + ' ' + JSON.stringify(started) }; }
  const expected = new URL(started.message_origin).origin;
  const received = new Promise((resolve) => {
    addEventListener('message', (event) => { if (event.source === popup) resolve({ origin: event.origin, data: event.data }); });
    setTimeout(() => resolve(null), 8000);
  });
  // The provider would redirect here; error=access_denied needs no token exchange.
  popup.location.href = started.message_origin + '/api/mail/oauth/google/callback?state=' + encodeURIComponent(started.state) + '&error=access_denied';
  const message = await received;
  return { expected, authorization: started.authorization_url.slice(0, 40), message };
})()` }, app.sessionId);
const oauthValue = oauth.result?.value ?? { error: oauth.exceptionDetails?.text };
check('OAuth callback page posts its result to the extension page with origin == message_origin',
  oauthValue.message?.origin === oauthValue.expected && oauthValue.message?.data?.type === 'email-doctor-oauth' && typeof oauthValue.message?.data?.error === 'string',
  JSON.stringify(oauthValue));

// ---------------------------------------------------------------- guard + lock
const refused = responses(app.sessionId).filter((r) => r.status === 403);
check('no request from the extension was refused by the Origin / Sec-Fetch-Site guard', refused.length === 0, JSON.stringify(refused));
// Session lost (backend restart / lock elsewhere): the app asks for the password only.
// The relock form must not override the saved profile's port / security.
await evaluate(app.sessionId, `fetch(${JSON.stringify(`${backendUrl}/api/accounts/${encodeURIComponent(USER)}`)}, { method: 'DELETE' }).then((r) => r.status)`);
await evaluate(app.sessionId, `[...document.querySelectorAll('.message-rows button')].find((b) => b.textContent.includes('Second'))?.click()`);
const relockShown = await waitFor(app.sessionId, `[...document.querySelectorAll('button')].some((b) => b.textContent.trim() === 'Unlock')`);
check('locked session shows the re-unlock (password only) form', relockShown);
if (relockShown) {
  await typeInto(app.sessionId, `document.querySelector('input[type=password]')`, PASSWORD);
  await evaluate(app.sessionId, `[...document.querySelectorAll('button')].find((b) => b.textContent.trim() === 'Unlock').click()`);
  const relocked = await waitFor(app.sessionId, `![...document.querySelectorAll('button')].some((b) => b.textContent.trim() === 'Unlock') && document.body.textContent.includes('plain body')`, 15000);
  check('re-unlock uses the saved profile (non-default port, no TLS) and resumes', relocked, await evaluate(app.sessionId, `document.querySelector('.banner.error')?.textContent ?? ''`));
}
const lock = await evaluate(app.sessionId, `fetch(${JSON.stringify(`${backendUrl}/api/accounts/${encodeURIComponent(USER)}`)}, { method: 'DELETE' }).then(async (r) => [r.status, await r.json()])`);
check('DELETE /api/accounts/{email} locks', lock[0] === 200 && lock[1].locked === USER, JSON.stringify(lock));

// ---------------------------------------------------------------- POP3 compatibility account via the Connect screen
const setField = (sessionId, selector, value) => evaluate(sessionId, `(() => {
  const el = ${selector};
  const proto = el instanceof HTMLSelectElement ? HTMLSelectElement.prototype : HTMLInputElement.prototype;
  Object.getOwnPropertyDescriptor(proto, 'value').set.call(el, ${JSON.stringify(String(value))});
  el.dispatchEvent(new Event(el instanceof HTMLSelectElement ? 'change' : 'input', { bubbles: true }));
  return true; })()`);
const fieldIn = (label, tag = 'input') => `[...document.querySelectorAll('label.field')].find((l) => l.querySelector('span')?.textContent.trim() === ${JSON.stringify(label)}).querySelector('${tag}')`;
const nthField = (label, index, tag = 'input') => `[...document.querySelectorAll('label.field')].filter((l) => l.querySelector('span')?.textContent.trim() === ${JSON.stringify(label)})[${index}].querySelector('${tag}')`;
await send('Page.reload', {}, app.sessionId);
await waitFor(app.sessionId, `[...document.querySelectorAll('button')].some((b) => b.textContent.trim() === 'Connect')`);
await setField(app.sessionId, fieldIn('Server profile', 'select'), '');
await evaluate(app.sessionId, `(() => { const d = document.querySelector('details'); d.open = true; d.dispatchEvent(new Event('toggle')); return true; })()`);
await setField(app.sessionId, `document.querySelector('input[type=email]')`, 'pop@example.com');
await setField(app.sessionId, `document.querySelector('input[type=password]')`, PASSWORD);
await setField(app.sessionId, nthField('Port', 0), '993');
await setField(app.sessionId, fieldIn('Incoming mail protocol', 'select'), 'pop3');
const popPortDefault = await evaluate(app.sessionId, `${nthField('Port', 0)}.value`);
check('choosing POP3 switches the default incoming port to 995', popPortDefault === '995', popPortDefault);
await setField(app.sessionId, nthField('Security', 0, 'select'), 'STARTTLS');
const popPlainDefault = await evaluate(app.sessionId, `${nthField('Port', 0)}.value`);
check('POP3 with STARTTLS switches the default incoming port to 110', popPlainDefault === '110', popPlainDefault);
await setField(app.sessionId, fieldIn('POP3 server'), '127.0.0.1');
await setField(app.sessionId, nthField('Port', 0), pop3Port);
await setField(app.sessionId, nthField('Security', 0, 'select'), 'NONE');
await setField(app.sessionId, fieldIn('SMTP server'), '127.0.0.1');
await setField(app.sessionId, nthField('Port', 1), smtpPort);
await setField(app.sessionId, nthField('Security', 1, 'select'), 'NONE');
await evaluate(app.sessionId, `[...document.querySelectorAll('button')].find((b) => b.textContent.trim() === 'Connect').click()`);
const popListed = await waitFor(app.sessionId, `document.body.textContent.includes('POP3 smoke')`, 20000);
check('POP3 account unlocked through the Connect screen lists its Inbox', popListed, await evaluate(app.sessionId, `document.querySelector('.banner.error')?.textContent ?? ''`));
const popAccount = await evaluate(app.sessionId, `fetch(${JSON.stringify(`${backendUrl}/api/accounts`)}).then((r) => r.json()).then((d) => d.accounts.find((a) => a.email === 'pop@example.com'))`);
check('backend unlocked it in POP3 mode', popAccount?.incoming_mail_protocol === 'pop3' && popAccount?.incoming_port === Number(pop3Port), JSON.stringify(popAccount));
await evaluate(app.sessionId, `[...document.querySelectorAll('.message-rows button')].find((b) => b.textContent.includes('POP3 smoke'))?.click()`);
check('POP3 message opens', await waitFor(app.sessionId, `document.body.textContent.includes('pop body')`, 10000));
const popDelete = await evaluate(app.sessionId, `fetch(${JSON.stringify(`${backendUrl}/api/mail/messages/delete`)}, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ account: 'pop@example.com', folder: 'INBOX', uids: [1], trash: '' }) }).then(async (r) => [r.status, await r.json()])`);
check('mutating operation on a POP3 account answers 400 with a message', popDelete[0] === 400 && typeof popDelete[1].detail === 'string', JSON.stringify(popDelete));
check('the 400 detail is the IMAP-only message the UI knows', popDelete[1]?.detail === 'This operation requires an IMAP account. POP3 accounts can only list and read the INBOX.', JSON.stringify(popDelete));
check('POP3 account: compatibility note shown, Delete / Flag / Mark read / Move to Trash hidden', await evaluate(app.sessionId, `(() => {
  const labels = [...document.querySelectorAll('button')].map((b) => b.textContent);
  return Boolean(document.querySelector('.pop3-note')) && !document.querySelector('.message-checkbox')
    && !labels.some((x) => x.includes('Delete') || x.includes('Flag') || /Mark (un)?read/.test(x) || x.includes('Move to Trash'));
})()`));
check('app page has no console errors / exceptions', problems(app.sessionId).length === 0, problems(app.sessionId).join(' || '));
console.log('INFO backend responses:', JSON.stringify([...new Set(responses(app.sessionId).map((r) => `${r.method} ${r.url} ${r.status}`))]));

const failed = results.filter((r) => !r.ok).length;
console.log(`\n${results.length - failed}/${results.length} checks passed`);
ws.close();
cleanup();
process.exit(failed ? 1 : 0);
