/**
 * Message contracts between the service worker and extension pages.
 * Dependency-free so the service worker bundle stays tiny.
 */

/** App page path inside the built extension. */
export const APP_PAGE = 'index.html';

/** Query parameter carrying a mailto: link into a new app tab. */
export const MAILTO_PARAM = 'mailto';

/** Longest mailto: link accepted (matches mailto.ts parseMailto). */
export const MAX_MAILTO_LENGTH = 8192;

/** Service worker -> app tab: `{ type, url, tabId }`; reply `{ accepted: true }`. */
export const MAILTO_MESSAGE = 'webmail:compose-mailto';

/** Extension page -> service worker: focus or open the app tab. */
export const OPEN_APP_MESSAGE = 'webmail:open-app';

export interface MailtoMessage {
  type: typeof MAILTO_MESSAGE;
  url: string;
  tabId: number;
}

/** A link the app may receive; parseMailto does the real validation. */
export function isMailtoCandidate(value: unknown): value is string {
  return typeof value === 'string' && value.length <= MAX_MAILTO_LENGTH && /^mailto:/i.test(value);
}
