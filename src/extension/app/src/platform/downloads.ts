import type { MouseEvent } from 'react';
import { ApiError } from '../api';
import { filenameFromContentDisposition, filenameFromUrl } from './contentDisposition';

/**
 * Downloads from an extension page.
 *
 * The backend lives on another origin (http://127.0.0.1:48101), and browsers
 * ignore `<a download>` for cross-origin URLs: a click would navigate the app
 * tab away or lose the error body. Instead the bytes are fetched (host
 * permissions make the response readable), wrapped in a same-origin blob: URL
 * and saved with a temporary anchor. No `downloads` permission is needed.
 */

async function errorFrom(response: Response): Promise<ApiError> {
  const text = await response.text().catch(() => '');
  let detail: unknown = text || response.statusText;
  try {
    const body = JSON.parse(text) as { detail?: unknown };
    detail = body.detail ?? body;
  } catch {
    // Keep the readable non-JSON response.
  }
  return new ApiError(response.status, detail);
}

/** Save a blob under `filename` through a same-origin object URL. */
export function saveBlob(blob: Blob, filename: string): void {
  const href = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = href;
  anchor.download = filename;
  anchor.rel = 'noopener';
  anchor.style.display = 'none';
  document.body.append(anchor);
  anchor.click();
  anchor.remove();
  // The download has its own reference once started; free the URL later.
  window.setTimeout(() => URL.revokeObjectURL(href), 60_000);
}

/**
 * Fetch `url` and save it. The file name comes from Content-Disposition, then
 * `fallbackName`, then the URL path. Resolves with the name used; rejects with
 * ApiError on an HTTP error (e.g. 401 password_required).
 */
export async function downloadFromBackend(url: string, fallbackName = ''): Promise<string> {
  const response = await fetch(url, { cache: 'no-store' });
  if (!response.ok) throw await errorFrom(response);
  const blob = await response.blob();
  const filename = filenameFromContentDisposition(response.headers.get('Content-Disposition'))
    || fallbackName || filenameFromUrl(url) || 'download';
  saveBlob(blob, filename);
  return filename;
}

/** User-facing text for a failed download. */
export function downloadErrorMessage(failure: unknown): string {
  if (failure instanceof ApiError) {
    if (failure.passwordRequired) return 'Your account is locked. Unlock it, then download again.';
    return `Download failed: ${failure.message}`;
  }
  return `Download failed: ${failure instanceof Error ? failure.message : String(failure)}`;
}

interface DownloadClickOptions {
  /** Used when the response has no Content-Disposition file name. */
  fallbackName?: string;
  onError?: (message: string) => void;
  onDone?: (filename: string) => void;
}

/**
 * onClick handler for an `<a href={backendUrl} download>` link: keeps the
 * link markup (and keyboard behaviour) but performs the download via fetch.
 */
export function backendDownloadClick(options: DownloadClickOptions = {}) {
  return (event: MouseEvent<HTMLAnchorElement>) => {
    if (event.defaultPrevented) return;
    event.preventDefault();
    const link = event.currentTarget;
    const fallbackName = options.fallbackName || link.getAttribute('download') || '';
    void downloadFromBackend(link.href, fallbackName).then(
      (filename) => options.onDone?.(filename),
      (failure: unknown) => {
        const message = downloadErrorMessage(failure);
        if (options.onError) options.onError(message);
        else window.alert(message);
      },
    );
  };
}
