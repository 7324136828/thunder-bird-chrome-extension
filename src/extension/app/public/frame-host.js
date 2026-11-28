// @ts-check
/**
 * Sandboxed frame host (manifest "sandbox" page, opaque origin, no chrome.*).
 *
 * The app (SandboxFrame.tsx) posts { type, srcDoc, relay, title }. The host
 * renders srcDoc in a nested `sandbox="allow-scripts"` srcdoc frame. That
 * frame inherits this page's sandbox CSP (manifest.json, which permits inline
 * scripts) and also enforces the document's own <meta> CSP, so the email's
 * nonce-only script policy and the doctor report's policy apply unchanged.
 *
 * With relay=true, messages from the nested frame (the email link bridge) are
 * forwarded to the app; the app still validates the per-render token.
 *
 * Classic script on purpose: module scripts would need CORS from an opaque origin.
 */
(() => {
  'use strict';
  const MESSAGE = 'webmail:frame-render';
  // location.origin is "null" in a sandboxed document; the URL still names us.
  const extensionOrigin = `${location.protocol}//${location.host}`;
  /** @type {HTMLIFrameElement | null} */
  let inner = null;
  let relay = false;

  window.addEventListener('message', (event) => {
    if (inner && event.source === inner.contentWindow) {
      if (relay) window.parent.postMessage(event.data, extensionOrigin);
      return;
    }
    if (event.source !== window.parent || event.origin !== extensionOrigin) return;
    const data = event.data;
    if (!data || typeof data !== 'object' || data.type !== MESSAGE || typeof data.srcDoc !== 'string') return;
    relay = data.relay === true;
    const next = document.createElement('iframe');
    next.setAttribute('sandbox', 'allow-scripts');
    next.setAttribute('referrerpolicy', 'no-referrer');
    next.title = typeof data.title === 'string' ? data.title : '';
    next.srcdoc = data.srcDoc;
    if (inner) inner.replaceWith(next);
    else document.body.append(next);
    inner = next;
  });
})();
