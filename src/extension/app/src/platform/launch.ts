/**
 * Hand-off of `mailto:` links from the background service worker
 * ("Compose with Webmail" context menu) to the app tab.
 *
 * - New tab: the service worker opens `index.html?mailto=<encoded link>`.
 *   The app takes the parameter once and removes it from the address so a
 *   reload does not open the composer again.
 * - Existing tab: the service worker focuses it and sends
 *   `{ type: MAILTO_MESSAGE, url, tabId }`; only the tab with that id accepts.
 *
 * The raw link is parsed by the app's own mailto.ts (parseMailto), exactly
 * like `mailto:` links clicked inside a message.
 */

import { isMailtoCandidate, MAILTO_MESSAGE, MAILTO_PARAM, type MailtoMessage } from '../background/messages';

/** Read and strip the launch `?mailto=` parameter, if any. */
export function takeLaunchMailto(): string | null {
  try {
    const url = new URL(window.location.href);
    const value = url.searchParams.get(MAILTO_PARAM);
    if (value === null) return null;
    url.searchParams.delete(MAILTO_PARAM);
    window.history.replaceState(window.history.state, '', `${url.pathname}${url.search}${url.hash}`);
    return isMailtoCandidate(value) ? value : null;
  } catch {
    return null;
  }
}

/**
 * Listen for compose requests from this extension's service worker that
 * target this tab. Returns an unsubscribe function.
 */
export function onMailtoRequest(handler: (url: string) => void): () => void {
  if (typeof chrome === 'undefined' || !chrome.runtime?.onMessage || !chrome.tabs?.getCurrent) return () => undefined;
  let tabId: number | undefined;
  let active = true;
  void chrome.tabs.getCurrent().then((tab) => { tabId = tab?.id; }).catch(() => undefined);
  const listener = (
    message: unknown,
    sender: chrome.runtime.MessageSender,
    sendResponse: (response: { accepted: boolean }) => void,
  ) => {
    const data = message as Partial<MailtoMessage> | null;
    if (!active || !data || data.type !== MAILTO_MESSAGE) return false;
    // Only the service worker (no sender tab) of this extension may ask.
    if (sender.id !== chrome.runtime.id || sender.tab || tabId === undefined || data.tabId !== tabId) return false;
    if (!isMailtoCandidate(data.url)) return false;
    handler(data.url);
    sendResponse({ accepted: true });
    return false;
  };
  chrome.runtime.onMessage.addListener(listener);
  return () => {
    active = false;
    chrome.runtime.onMessage.removeListener(listener);
  };
}
