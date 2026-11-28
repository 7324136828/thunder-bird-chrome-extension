/**
 * Options page: backend address stored in chrome.storage.local
 * (`settings.backend_url`). Open app tabs watch storage.onChanged and reload
 * against the new backend (main.tsx). Pattern from the_editor options page.
 */
import './options.css';
import { DEFAULT_BACKEND_URL, validateBackendUrl } from '../platform/backendUrl';
import { extensionStorage, readStoredBackendUrl, saveBackendUrl } from '../platform/backend';
import { OPEN_APP_MESSAGE } from '../background/messages';

const HEALTH_TIMEOUT_MS = 4000;

function element<T extends HTMLElement>(id: string): T {
  const found = document.getElementById(id);
  if (!found) throw new Error(`Missing #${id} in options.html`);
  return found as T;
}

const els = {
  form: element<HTMLFormElement>('backend-form'),
  url: element<HTMLInputElement>('backend-url'),
  error: element<HTMLParagraphElement>('url-error'),
  test: element<HTMLButtonElement>('btn-test'),
  reset: element<HTMLButtonElement>('btn-reset'),
  result: element<HTMLDivElement>('test-result'),
  howto: element<HTMLDetailsElement>('howto'),
  status: element<HTMLSpanElement>('save-status'),
  open: element<HTMLButtonElement>('btn-open'),
};

let statusTimer = 0;

function flash(message: string, isError = false) {
  els.status.textContent = message;
  els.status.className = `save-status${isError ? ' error' : ''}`;
  window.clearTimeout(statusTimer);
  statusTimer = window.setTimeout(() => { els.status.textContent = ''; }, isError ? 6000 : 2500);
}

/** Validate the input, show problems, and return the normalized URL or null. */
function validated(): string | null {
  // http://127.0.0.1 or http://localhost only (see platform/backendUrl.ts):
  // passwords travel to this address, and the extension CSP connect-src
  // allows nothing else.
  const result = validateBackendUrl(els.url.value);
  els.error.hidden = result.ok;
  els.error.textContent = result.ok ? '' : result.error;
  els.url.setAttribute('aria-invalid', result.ok ? 'false' : 'true');
  return result.ok ? result.url : null;
}

async function save(url: string) {
  try {
    await saveBackendUrl(url);
    els.url.value = url;
    flash('Saved');
  } catch (failure) {
    flash(`Could not save: ${failure instanceof Error ? failure.message : String(failure)}`, true);
  }
}

function showResult(ok: boolean, lines: string[]) {
  els.result.hidden = false;
  els.result.className = `test-result ${ok ? 'ok' : 'fail'}`;
  els.result.replaceChildren(...lines.map((line, index) => {
    const node = document.createElement(index === 0 ? 'strong' : 'div');
    node.textContent = line;
    return node;
  }));
}

/** GET {url}/api/health and expect {"status": "ok"}. */
async function testConnection() {
  const url = validated();
  if (!url) return;
  els.test.disabled = true;
  els.result.hidden = false;
  els.result.className = 'test-result';
  els.result.textContent = 'Testing…';
  const controller = new AbortController();
  const timer = window.setTimeout(() => controller.abort(), HEALTH_TIMEOUT_MS);
  try {
    const response = await fetch(`${url}/api/health`, { cache: 'no-store', signal: controller.signal });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const body = (await response.json().catch(() => null)) as { status?: unknown } | null;
    if (body?.status !== 'ok') throw new Error('unexpected /api/health response');
    showResult(true, [`Connected to the mail backend at ${url}.`]);
  } catch (failure) {
    const reason = controller.signal.aborted
      ? 'no answer in time'
      : failure instanceof Error ? failure.message : String(failure);
    showResult(false, [
      `Not reachable at ${url}: ${reason.replace(/[.?!]+$/, '')}.`,
      'Start mail-backend (see “How to start the backend” below), then click Test connection.',
    ]);
    els.howto.open = true;
  } finally {
    window.clearTimeout(timer);
    els.test.disabled = false;
  }
}

async function openApp() {
  try {
    await chrome.runtime.sendMessage({ type: OPEN_APP_MESSAGE });
  } catch {
    window.open(chrome.runtime.getURL('index.html'), '_blank', 'noopener');
  }
}

async function init() {
  if (!extensionStorage()) {
    els.url.value = DEFAULT_BACKEND_URL;
    els.error.hidden = false;
    els.error.textContent = 'Settings can only be saved when this page is opened from the extension.';
  } else {
    els.url.value = await readStoredBackendUrl();
  }
  validated();

  els.url.addEventListener('input', () => validated());
  els.form.addEventListener('submit', (event) => {
    event.preventDefault();
    const url = validated();
    if (url) void save(url).then(testConnection);
  });
  els.test.addEventListener('click', () => void testConnection());
  els.reset.addEventListener('click', () => {
    els.url.value = DEFAULT_BACKEND_URL;
    validated();
    void save(DEFAULT_BACKEND_URL).then(testConnection);
  });
  els.open.addEventListener('click', () => void openApp());
}

void init();
