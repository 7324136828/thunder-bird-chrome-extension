export interface MailtoDraft {
  to: string;
  cc: string;
  bcc: string;
  subject: string;
  body: string;
}

/** RFC 6068 uses percent encoding, so literal '+' must stay a plus. */
export function parseMailto(value: string): MailtoDraft | null {
  if (value.length > 8192 || /[\u0000-\u001f\u007f]/.test(value)) return null;
  try {
    const url = new URL(value);
    if (url.protocol !== 'mailto:' || url.host || url.username || url.password) return null;
    const draft: MailtoDraft = { to: decodeURIComponent(url.pathname), cc: '', bcc: '', subject: '', body: '' };
    const found = new Set<string>();
    for (const item of url.search.slice(1).split('&')) {
      if (!item) continue;
      const equals = item.indexOf('=');
      const name = decodeURIComponent(equals < 0 ? item : item.slice(0, equals)).toLowerCase();
      if (!['to', 'cc', 'bcc', 'subject', 'body'].includes(name)) continue;
      const content = decodeURIComponent(equals < 0 ? '' : item.slice(equals + 1));
      if (name === 'to' || name === 'cc' || name === 'bcc') {
        draft[name] = [draft[name], content].filter(Boolean).join(', ');
      } else if (!found.has(name)) {
        draft[name as 'subject' | 'body'] = content;
      }
      found.add(name);
    }
    // Link-supplied content stays editable. It can never introduce new headers.
    for (const value of [draft.to, draft.cc, draft.bcc, draft.subject]) {
      if (/[\u0000-\u001f\u007f]/.test(value)) return null;
    }
    if (/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/.test(draft.body)) return null;
    draft.body = draft.body.replace(/\r\n?/g, '\n');
    return draft;
  } catch {
    return null;
  }
}
