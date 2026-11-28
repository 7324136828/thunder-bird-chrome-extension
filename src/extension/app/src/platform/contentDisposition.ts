/**
 * File name from a Content-Disposition header: RFC 5987 `filename*=` wins
 * (percent-decoded; a malformed encoding is kept literally), then the plain
 * `filename=` value (never percent-decoded). Returns '' when absent.
 *
 * Port of the_editor lib/backend.js filenameFromContentDisposition. The mail
 * backend sends `attachment; filename="message-1.eml"` for .eml/attachments
 * and `filename*=utf-8''…` for Inbox Doctor ZIPs.
 */
export function filenameFromContentDisposition(header: string | null | undefined): string {
  const value = String(header ?? '');
  const star = /filename\*\s*=\s*([^;]+)/i.exec(value);
  if (star) {
    let encoded = star[1].trim().replace(/^"(.*)"$/, '$1');
    const parts = /^([\w!#$%&+^`{}~-]*)'[^']*'(.*)$/.exec(encoded);
    const charset = parts ? parts[1].toLowerCase() : 'utf-8';
    if (parts) encoded = parts[2];
    try {
      if (charset === 'utf-8' || charset === '') return decodeURIComponent(encoded);
      // ISO-8859-1: each percent byte is one code point.
      return encoded.replace(/%([0-9a-f]{2})/gi, (_, hex: string) => String.fromCharCode(parseInt(hex, 16)));
    } catch {
      return encoded;
    }
  }
  const plain = /filename\s*=\s*("((?:\\.|[^"\\])*)"|[^;]+)/i.exec(value);
  if (plain) {
    const name = plain[2] !== undefined ? plain[2].replace(/\\(.)/g, '$1') : plain[1].trim();
    return name.trim();
  }
  return '';
}

/** Last non-empty path segment of a URL, decoded, or ''. */
export function filenameFromUrl(url: string): string {
  try {
    const segments = new URL(url, 'http://localhost/').pathname.split('/').filter(Boolean);
    const last = segments[segments.length - 1] ?? '';
    return decodeURIComponent(last);
  } catch {
    return '';
  }
}
