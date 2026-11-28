/**
 * Webmail extension service worker (MV3, built to dist/background.js).
 *
 * - Toolbar button: open the three-pane app in a tab, reusing an open one.
 * - "Compose with Webmail" context menu on mailto: links: open/focus the app
 *   and hand it the raw link; the app parses it with mailto.ts and opens the
 *   composer (see platform/launch.ts).
 * - Extension pages may ask it to open the app (options page button).
 *
 * Uses chrome.runtime.getContexts (Chrome/Edge 116+) to find app tabs, so
 * the extension needs no "tabs" permission.
 */
import {
  APP_PAGE,
  isMailtoCandidate,
  MAILTO_MESSAGE,
  MAILTO_PARAM,
  OPEN_APP_MESSAGE,
  type MailtoMessage,
} from './messages';

const MENU_COMPOSE = 'webmail-compose-mailto';
const MENU_TITLE = 'Compose with Webmail';

function appUrl(mailto?: string): string {
  const base = chrome.runtime.getURL(APP_PAGE);
  return mailto ? `${base}?${MAILTO_PARAM}=${encodeURIComponent(mailto)}` : base;
}

interface AppTab {
  tabId: number;
  windowId: number;
}

/** The first top-level tab showing the app page, if any. */
async function findAppTab(): Promise<AppTab | null> {
  const base = chrome.runtime.getURL(APP_PAGE);
  try {
    const contexts = await chrome.runtime.getContexts({ contextTypes: [chrome.runtime.ContextType.TAB] });
    const match = contexts.find((context) => {
      const url = context.documentUrl ?? '';
      return context.tabId >= 0 && context.frameId === 0
        && (url === base || url.startsWith(`${base}?`) || url.startsWith(`${base}#`));
    });
    return match ? { tabId: match.tabId, windowId: match.windowId } : null;
  } catch {
    return null;
  }
}

/** Focus an open app tab (handing it `mailto` when given) or open a new one. */
async function openApp(mailto?: string): Promise<void> {
  const existing = await findAppTab();
  if (existing) {
    try {
      await chrome.tabs.update(existing.tabId, { active: true });
      await chrome.windows.update(existing.windowId, { focused: true }).catch(() => undefined);
      if (!mailto) return;
      const message: MailtoMessage = { type: MAILTO_MESSAGE, url: mailto, tabId: existing.tabId };
      const reply = (await chrome.runtime.sendMessage(message)) as { accepted?: boolean } | undefined;
      if (reply?.accepted) return;
    } catch {
      // The tab closed or is still loading: fall through to a new tab.
    }
  }
  await chrome.tabs.create({ url: appUrl(mailto) });
}

function createContextMenu(): void {
  chrome.contextMenus.removeAll(() => {
    try {
      chrome.contextMenus.create(
        { id: MENU_COMPOSE, title: MENU_TITLE, contexts: ['link'], targetUrlPatterns: ['mailto:*'] },
        () => {
          if (!chrome.runtime.lastError) return;
          // Pattern rejected: show on every link; onClicked ignores the rest.
          chrome.contextMenus.create({ id: MENU_COMPOSE, title: MENU_TITLE, contexts: ['link'] });
        },
      );
    } catch {
      chrome.contextMenus.create({ id: MENU_COMPOSE, title: MENU_TITLE, contexts: ['link'] });
    }
  });
}

chrome.runtime.onInstalled.addListener(() => createContextMenu());

chrome.contextMenus.onClicked.addListener((info) => {
  if (info.menuItemId !== MENU_COMPOSE || !isMailtoCandidate(info.linkUrl)) return;
  void openApp(info.linkUrl);
});

chrome.action.onClicked.addListener(() => {
  void openApp();
});

chrome.runtime.onMessage.addListener((message: unknown, sender, sendResponse) => {
  const data = message as { type?: unknown } | null;
  if (!data || data.type !== OPEN_APP_MESSAGE || sender.id !== chrome.runtime.id) return false;
  void openApp().then(
    () => sendResponse({ ok: true }),
    (failure: unknown) => sendResponse({ ok: false, error: String(failure) }),
  );
  return true;
});
