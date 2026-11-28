import { useEffect, useMemo, useRef, useState } from 'react';
import { api } from '../api';
import { EmailImageState, prepareEmailHtml, renderEmailHtml } from '../emailHtml';
import ExternalLinkModal from './ExternalLinkModal';
import SandboxFrame from './SandboxFrame';

interface Props {
  account: string;
  folder: string;
  uid: number;
  html: string;
  onMailto: (url: string) => void;
}

interface ImageSession {
  active: boolean;
  controller: AbortController;
  images: Map<string, EmailImageState>;
  attempted: Set<string>;
  objectUrls: Set<string>;
  localBytes: number;
}

const MAX_IMAGES_PER_BATCH = 24;
const DOWNLOAD_CONCURRENCY = 4;
const MAX_LOCAL_IMAGE_BYTES = 32 * 1024 * 1024;

function decodeImage(objectUrl: string, signal: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    const image = new Image();
    const dispose = () => {
      window.clearTimeout(timeout);
      signal.removeEventListener('abort', abort);
      image.onload = null;
      image.onerror = null;
      image.removeAttribute('src');
    };
    const fail = (error: Error) => {
      dispose();
      reject(error);
    };
    const abort = () => fail(new DOMException('Image download cancelled', 'AbortError'));
    const timeout = window.setTimeout(() => fail(new Error('Image could not be decoded')), 10000);
    image.onload = () => {
      const valid = image.naturalWidth > 0 && image.naturalHeight > 0;
      dispose();
      if (valid) resolve();
      else reject(new Error('Image could not be decoded'));
    };
    image.onerror = () => fail(new Error('Image could not be decoded'));
    signal.addEventListener('abort', abort, { once: true });
    if (signal.aborted) abort();
    else image.src = objectUrl;
  });
}

function localImageDataUrl(blob: Blob, signal: AbortSignal): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    const dispose = () => signal.removeEventListener('abort', abort);
    const abort = () => {
      reader.abort();
      dispose();
      reject(new DOMException('Image download cancelled', 'AbortError'));
    };
    reader.onload = () => {
      dispose();
      resolve(String(reader.result));
    };
    reader.onerror = () => {
      dispose();
      reject(new Error('Image could not be read'));
    };
    signal.addEventListener('abort', abort, { once: true });
    if (signal.aborted) abort();
    else reader.readAsDataURL(blob);
  });
}

async function downloadImages(
  session: ImageSession,
  urls: string[],
  retry: boolean,
  account: string,
  folder: string,
  uid: number,
  publish: () => void,
) {
  for (const url of urls) {
    session.images.set(url, { state: 'loading' });
    session.attempted.add(url);
  }
  publish();
  let nextIndex = 0;
  const worker = async () => {
    while (session.active && nextIndex < urls.length) {
      const url = urls[nextIndex++];
      let objectUrl: string | undefined;
      let reservedBytes = 0;
      try {
        const blob = await api.messageImage(account, folder, uid, url, retry, session.controller.signal);
        if (!session.active) return;
        if (session.localBytes + blob.size > MAX_LOCAL_IMAGE_BYTES) {
          throw new Error('The message image size limit has been reached');
        }
        reservedBytes = blob.size;
        session.localBytes += reservedBytes;
        objectUrl = URL.createObjectURL(blob);
        session.objectUrls.add(objectUrl);
        await decodeImage(objectUrl, session.controller.signal);
        const dataUrl = await localImageDataUrl(blob, session.controller.signal);
        URL.revokeObjectURL(objectUrl);
        session.objectUrls.delete(objectUrl);
        if (!session.active) return;
        // An opaque sandboxed frame cannot read the parent's blob URLs. Embed
        // only validated backend bytes, preserving the frame's origin isolation.
        session.images.set(url, { state: 'ready', dataUrl });
      } catch {
        session.localBytes -= reservedBytes;
        if (objectUrl) {
          URL.revokeObjectURL(objectUrl);
          session.objectUrls.delete(objectUrl);
        }
        if (!session.active) return;
        session.images.set(url, { state: 'blocked' });
      }
    }
  };
  await Promise.all(Array.from({ length: Math.min(DOWNLOAD_CONCURRENCY, urls.length) }, worker));
  // Update one batch at a time so iframe reloads do not continually reset the
  // reader's scroll position as individual images finish downloading.
  publish();
}

export default function EmailHtml({ account, folder, uid, html, onMailto }: Props) {
  const prepared = useMemo(() => prepareEmailHtml(html), [html]);
  const [images, setImages] = useState<Map<string, EmailImageState>>(() => new Map());
  const [frameRevision, setFrameRevision] = useState(0);
  const sessionRef = useRef<ImageSession | null>(null);
  const frameRef = useRef<HTMLIFrameElement>(null);
  const [pendingLink, setPendingLink] = useState<string | null>(null);
  const pendingLinkRef = useRef<string | null>(null);
  const mailtoHandlerRef = useRef(onMailto);
  mailtoHandlerRef.current = onMailto;

  useEffect(() => {
    const session: ImageSession = {
      active: true,
      controller: new AbortController(),
      images: new Map(prepared.imageUrls.map((url) => [url, { state: 'blocked' }])),
      attempted: new Set(),
      objectUrls: new Set(),
      localBytes: 0,
    };
    sessionRef.current = session;
    const publish = () => {
      if (session.active) {
        setImages(new Map(session.images));
        setFrameRevision((revision) => revision + 1);
      }
    };
    // StrictMode simulates mount/unmount in development. Wait until the first
    // cleanup has had a chance to cancel before making network requests.
    queueMicrotask(() => {
      if (session.active) {
        void downloadImages(session, prepared.imageUrls.slice(0, MAX_IMAGES_PER_BATCH), false, account, folder, uid, publish);
      }
    });
    return () => {
      session.active = false;
      session.controller.abort();
      for (const objectUrl of session.objectUrls) URL.revokeObjectURL(objectUrl);
      session.objectUrls.clear();
    };
  }, [account, folder, uid, prepared]);

  const hasPending = prepared.imageUrls.some((url) => images.get(url)?.state === 'loading');
  const { srcDoc, hasRenderBlocked, linkToken } = useMemo(() => renderEmailHtml(prepared, images), [prepared, images]);
  const hasBlocked = hasRenderBlocked || prepared.imageUrls.some((url) => images.get(url)?.state === 'blocked');

  useEffect(() => {
    pendingLinkRef.current = null;
    setPendingLink(null);
  }, [account, folder, uid, prepared]);

  useEffect(() => {
    const receiveLink = (event: MessageEvent) => {
      if (!linkToken || event.source !== frameRef.current?.contentWindow || pendingLinkRef.current) return;
      const data = event.data;
      if (!data || typeof data !== 'object' || data.type !== 'email-external-link' || data.token !== linkToken) return;
      if (!Number.isSafeInteger(data.index) || data.index < 0 || data.index >= prepared.linkUrls.length) return;
      const destination = prepared.linkUrls[data.index];
      if (new URL(destination).protocol === 'mailto:') {
        mailtoHandlerRef.current(destination);
        return;
      }
      pendingLinkRef.current = destination;
      setPendingLink(destination);
    };
    window.addEventListener('message', receiveLink);
    return () => window.removeEventListener('message', receiveLink);
  }, [prepared, linkToken]);

  const dismissLink = () => {
    pendingLinkRef.current = null;
    setPendingLink(null);
  };

  const continueLink = () => {
    const destination = pendingLinkRef.current;
    if (!destination) return;
    // The user's click here supplies browser activation for the new tab/app.
    window.open(destination, '_blank', 'noopener,noreferrer');
    dismissLink();
  };

  const retry = () => {
    const session = sessionRef.current;
    if (!session?.active || Array.from(session.images.values()).some((image) => image.state === 'loading')) return;
    const blocked = prepared.imageUrls.filter((url) => session.images.get(url)?.state === 'blocked');
    // Unattempted images beyond the automatic limit get the next batch first.
    const urls = [
      ...blocked.filter((url) => !session.attempted.has(url)),
      ...blocked.filter((url) => session.attempted.has(url)),
    ].slice(0, MAX_IMAGES_PER_BATCH);
    void downloadImages(session, urls, true, account, folder, uid, () => {
      if (session.active) {
        setImages(new Map(session.images));
        setFrameRevision((revision) => revision + 1);
      }
    });
  };

  return (
    <div className="email-html-content">
      {hasBlocked && (
        <div className="remote-resources-banner" role="status">
          <span>To protect your privacy remote resources have been blocked.</span>
          <button className="btn subtle" type="button" disabled={hasPending} onClick={retry}>
            Allow Download
          </button>
        </div>
      )}
      {hasPending && (
        <p className="remote-resources-loading muted" role="status">Downloading remote images…</p>
      )}
      <SandboxFrame
        key={frameRevision}
        ref={frameRef}
        title="Message content"
        className="html-frame"
        referrerPolicy="no-referrer"
        srcDoc={srcDoc}
        relayMessages
      />
      {pendingLink && <ExternalLinkModal
        destination={pendingLink}
        onCancel={dismissLink}
        onContinue={continueLink}
        onRestoreFocus={() => frameRef.current?.focus()}
      />}
    </div>
  );
}
