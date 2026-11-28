/**
 * Backend address helpers shared by the app, the options page and tests.
 * Pure functions only (no chrome.* or Vite globals) so Node can test them.
 *
 * Mirrors the_editor's lib/backend.js normalizeBackendUrl/isLoopbackBackendUrl,
 * with stricter validation because mail passwords travel to this address.
 *
 * Policy (one rule, enforced in three places): the backend address is
 * `http://` on `127.0.0.1` or `localhost` (any port, optional path prefix)
 * and nothing else. The same set is
 *   - the manifest `connect-src` of the extension pages
 *     (`'self' http://127.0.0.1:* http://localhost:*`),
 *   - the extension's `host_permissions`, and
 *   - what {@link validateBackendUrl} accepts for saving and for use.
 * `[::1]` is loopback too, but Chrome rejects IPv6 literals in CSP source
 * lists ("contains an invalid source: 'http://[::1]:*'. It will be ignored"),
 * so it cannot be allowed in connect-src; `localhost` reaches a backend
 * listening on ::1 instead.
 * Remote addresses, plain or https, are refused outright (no "are you sure"
 * override): the CSP would block them anyway, and mail passwords travel to
 * this address. `https://` on a loopback name is refused too, because
 * mail-backend serves plain HTTP on loopback and the CSP/host permissions
 * only cover `http://`. A remote backend needs a rebuilt extension with a
 * widened CSP and host permissions (see README "Backend address policy").
 */

export const DEFAULT_BACKEND_URL = 'http://127.0.0.1:48101';

export type BackendUrlResult = { ok: true; url: string } | { ok: false; error: string };

/**
 * Normalize user input into `scheme://host[:port][/prefix]` without a trailing
 * slash. Blank input means the default address. A missing scheme means http.
 */
export function normalizeBackendUrl(input: string | null | undefined): BackendUrlResult {
  let value = String(input ?? '').trim();
  if (!value) return { ok: true, url: DEFAULT_BACKEND_URL };
  if (/[\u0000-\u001f\u007f\s]/.test(value)) {
    return { ok: false, error: 'The backend address must not contain spaces or control characters.' };
  }
  if (!/^[a-z][a-z\d+.-]*:\/\//i.test(value)) value = `http://${value}`;
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return { ok: false, error: 'Enter a valid address such as http://127.0.0.1:48101.' };
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    return { ok: false, error: 'The backend address must start with http:// or https://.' };
  }
  if (!url.hostname) return { ok: false, error: 'The backend address needs a host name.' };
  if (url.username || url.password) {
    return { ok: false, error: 'The backend address must not contain a user name or password.' };
  }
  if (url.search || url.hash || value.includes('?') || value.includes('#')) {
    return { ok: false, error: 'The backend address must not contain a query (?) or fragment (#).' };
  }
  const prefix = url.pathname.replace(/\/+$/, '');
  return { ok: true, url: `${url.origin}${prefix}` };
}

/**
 * True when the address names this computer the way the backend accepts it:
 * `127.0.0.1`, `localhost` or `[::1]` (the mail-backend's `Host` guard; other
 * 127.x addresses get 403 from the backend). {@link validateBackendUrl}
 * further narrows this to what the extension CSP can reach.
 */
export function isLoopbackBackendUrl(input: string): boolean {
  const normalized = normalizeBackendUrl(input);
  if (!normalized.ok) return false;
  const host = new URL(normalized.url).hostname.toLowerCase();
  return host === 'localhost' || host === '[::1]' || host === '127.0.0.1';
}

export const LOOPBACK_REQUIRED_ERROR =
  'The backend address must be on this computer: 127.0.0.1 or localhost. Mail passwords are sent to this address.';

export const IPV6_LOOPBACK_ERROR =
  'Chrome does not let extensions allow [::1] in their connection policy. Use http://localhost or http://127.0.0.1 with the same port.';

export const LOOPBACK_HTTP_REQUIRED_ERROR =
  'The local mail backend speaks plain http:// on this computer. Use an address such as http://127.0.0.1:48101.';

/**
 * normalizeBackendUrl plus the loopback (and plain http) requirement. Use for every address
 * the extension saves or sends requests to: passwords travel to it, and the
 * backend only listens on (and only answers for) loopback names.
 */
export function validateBackendUrl(input: string | null | undefined): BackendUrlResult {
  const normalized = normalizeBackendUrl(input);
  if (!normalized.ok) return normalized;
  if (!isLoopbackBackendUrl(normalized.url)) return { ok: false, error: LOOPBACK_REQUIRED_ERROR };
  // connect-src and host_permissions only cover http://127.0.0.1 and http://localhost.
  if (!normalized.url.startsWith('http://')) return { ok: false, error: LOOPBACK_HTTP_REQUIRED_ERROR };
  if (new URL(normalized.url).hostname === '[::1]') return { ok: false, error: IPV6_LOOPBACK_ERROR };
  return normalized;
}
