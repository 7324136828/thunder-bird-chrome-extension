import { forwardRef, IframeHTMLAttributes, useCallback, useEffect, useRef, useState } from 'react';
import { isExtensionPage } from '../platform/backend';

/**
 * A `sandbox="allow-scripts"` iframe showing an HTML string.
 *
 * On the Vite dev server this is the original `<iframe srcDoc>`.
 *
 * On extension pages a srcdoc frame would inherit the extension page CSP
 * (`script-src 'self'`), which blocks the inline scripts these documents
 * need (the email link bridge, the doctor report's own script). So the frame
 * loads frame-host.html instead: a manifest "sandbox" page with its own CSP.
 * The host renders the HTML in a nested srcdoc frame, which still applies the
 * document's own <meta> CSP (e.g. the email's nonce-only script policy), and
 * optionally relays the nested frame's messages to this page, so
 * `event.source === frame.contentWindow` checks keep working.
 */

export const FRAME_HOST_PAGE = 'frame-host.html';
export const FRAME_HOST_MESSAGE = 'webmail:frame-render';

type Props = Omit<IframeHTMLAttributes<HTMLIFrameElement>, 'src' | 'srcDoc' | 'sandbox' | 'onLoad'> & {
  srcDoc: string;
  /** Forward messages posted by the document to this page (email link bridge). */
  relayMessages?: boolean;
};

const SandboxFrame = forwardRef<HTMLIFrameElement, Props>(function SandboxFrame(
  { srcDoc, relayMessages = false, title, ...rest },
  forwardedRef,
) {
  const hosted = isExtensionPage();
  const frame = useRef<HTMLIFrameElement | null>(null);
  const [loaded, setLoaded] = useState(false);

  const setRef = useCallback((node: HTMLIFrameElement | null) => {
    frame.current = node;
    if (typeof forwardedRef === 'function') forwardedRef(node);
    else if (forwardedRef) forwardedRef.current = node;
  }, [forwardedRef]);

  useEffect(() => {
    if (!hosted || !loaded) return;
    // The host has an opaque origin, so '*' is the only usable target. The
    // frame never navigates elsewhere: it is sandboxed and only runs our host.
    frame.current?.contentWindow?.postMessage(
      { type: FRAME_HOST_MESSAGE, srcDoc, relay: relayMessages, title: title ?? '' },
      '*',
    );
  }, [hosted, loaded, srcDoc, relayMessages, title]);

  if (!hosted) {
    return <iframe ref={setRef} title={title} sandbox="allow-scripts" srcDoc={srcDoc} {...rest} />;
  }
  return (
    <iframe
      ref={setRef}
      title={title}
      sandbox="allow-scripts"
      src={FRAME_HOST_PAGE}
      onLoad={() => setLoaded(true)}
      {...rest}
    />
  );
});

export default SandboxFrame;
