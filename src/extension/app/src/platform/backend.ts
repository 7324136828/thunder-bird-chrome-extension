import { DEFAULT_BACKEND_URL, normalizeBackendUrl, validateBackendUrl } from './backendUrl';

/**
 * Where the app sends every backend request.
 *
 * - Extension pages read `settings.backend_url` from chrome.storage.local
 *   (written by the options page) before React renders; default
 *   http://127.0.0.1:48101.
 * - The Vite dev server has no chrome.storage. There the base is
 *   VITE_BACKEND_BASE_URL when set, otherwise '' so the original relative
 *   /api paths go through the dev-server proxy (vite.config.ts).
 */

export const SETTINGS_KEY = 'settings';

export interface ExtensionSettings {
  backend_url?: string;
}

let apiBase = '';

/** chrome.storage.local, or null outside an extension page. */
export function extensionStorage(): chrome.storage.StorageArea | null {
  try {
    return typeof chrome !== 'undefined' && chrome.storage?.local ? chrome.storage.local : null;
  } catch {
    return null;
  }
}

/** True on chrome-extension:// pages (not on the Vite dev server). */
export function isExtensionPage(): boolean {
  try {
    return typeof chrome !== 'undefined' && Boolean(chrome.runtime?.id) && window.location.protocol === 'chrome-extension:';
  } catch {
    return false;
  }
}

function devBase(): string {
  const configured = import.meta.env.VITE_BACKEND_BASE_URL;
  if (!configured) return '';
  const normalized = normalizeBackendUrl(configured);
  return normalized.ok ? normalized.url : '';
}

/** The stored backend address (normalized), or the default. Never throws. */
export async function readStoredBackendUrl(storage = extensionStorage()): Promise<string> {
  if (!storage) return DEFAULT_BACKEND_URL;
  try {
    const data = await storage.get(SETTINGS_KEY);
    const settings = (data?.[SETTINGS_KEY] ?? {}) as ExtensionSettings;
    // A stored non-loopback address (older build, edited storage) is ignored.
    const normalized = validateBackendUrl(settings.backend_url);
    return normalized.ok ? normalized.url : DEFAULT_BACKEND_URL;
  } catch {
    return DEFAULT_BACKEND_URL;
  }
}

/** Persist a backend address (must be loopback), keeping other settings keys. */
export async function saveBackendUrl(url: string, storage = extensionStorage()): Promise<void> {
  if (!storage) throw new Error('Extension storage is not available on this page.');
  const checked = validateBackendUrl(url);
  if (!checked.ok) throw new Error(checked.error);
  url = checked.url;
  const data = await storage.get(SETTINGS_KEY);
  const current = (data?.[SETTINGS_KEY] ?? {}) as ExtensionSettings;
  await storage.set({ [SETTINGS_KEY]: { ...current, backend_url: url } });
}

/** Resolve the base URL once, before the app renders. */
export async function initBackendBase(): Promise<string> {
  apiBase = extensionStorage() ? await readStoredBackendUrl() : devBase();
  return apiBase;
}

/** Current base ('' means same-origin, i.e. the dev proxy). */
export function backendBase(): string {
  return apiBase;
}

/** Absolute URL for an original `/api/...` path. */
export function apiUrl(path: string): string {
  return `${apiBase}${path}`;
}

/**
 * Call `onChange` when the options page stores a different backend address.
 * Returns an unsubscribe function (a no-op outside the extension).
 */
export function watchBackendBase(onChange: (url: string) => void): () => void {
  if (!extensionStorage() || !chrome.storage?.onChanged) return () => undefined;
  const listener = (changes: Record<string, chrome.storage.StorageChange>, area: string) => {
    if (area !== 'local' || !changes[SETTINGS_KEY]) return;
    const next = validateBackendUrl((changes[SETTINGS_KEY].newValue as ExtensionSettings | undefined)?.backend_url);
    const url = next.ok ? next.url : DEFAULT_BACKEND_URL;
    if (url !== apiBase) onChange(url);
  };
  chrome.storage.onChanged.addListener(listener);
  return () => chrome.storage.onChanged.removeListener(listener);
}
