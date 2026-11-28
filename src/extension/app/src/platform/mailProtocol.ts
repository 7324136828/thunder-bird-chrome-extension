/**
 * Incoming mail protocol helpers (extension addition; the original app was
 * IMAP-only). Pure functions so Node can test them.
 *
 * The Rust backend's POP3 compatibility mode (mail-core `pop3.rs`) can unlock,
 * list and read the INBOX, download `.eml`/attachments, and keep local
 * category/expiration choices and sender rules. Everything that changes the
 * server mailbox answers HTTP 400 with {@link POP3_IMAP_ONLY_DETAIL}: flags
 * (read/unread, flagged), deleting or moving messages to Trash, and the
 * prepared Trash empty/archive workflow. POP3 has no folders besides INBOX and
 * no server read state (every message is reported unread, so the read-status
 * filter is meaningless). The UI hides those actions for POP3 accounts instead
 * of letting the user hit the 400.
 */

export type IncomingMailProtocol = 'imap' | 'pop3';

/** Exact detail of the backend's 400 for IMAP-only operations on POP3 accounts. */
export const POP3_IMAP_ONLY_DETAIL =
  'This operation requires an IMAP account. POP3 accounts can only list and read the INBOX.';

/** Short user-facing explanation shown wherever IMAP-only actions are hidden. */
export const POP3_COMPAT_NOTE =
  'POP3 compatibility mode: only the Inbox can be listed and read. Flags, read state, deleting and Trash need an IMAP account.';

/** Default incoming ports: implicit TLS vs. plain / STARTTLS. */
export const DEFAULT_INCOMING_PORTS: Record<IncomingMailProtocol, { tls: number; plain: number }> = {
  imap: { tls: 993, plain: 143 },
  pop3: { tls: 995, plain: 110 },
};

/** 'pop3' only for an explicit POP3 value; anything else (missing, '', 'IMAP') is IMAP. */
export function normalizeMailProtocol(value: string | null | undefined): IncomingMailProtocol {
  return String(value ?? '').trim().toLowerCase() === 'pop3' ? 'pop3' : 'imap';
}

export function isPop3Account(account: { incoming_mail_protocol?: string } | null | undefined): boolean {
  return normalizeMailProtocol(account?.incoming_mail_protocol) === 'pop3';
}

/**
 * Default incoming port for a protocol and security setting:
 * 993 IMAP SSL/TLS, 143 IMAP STARTTLS/none, 995 POP3 SSL/TLS, 110 POP3 STARTTLS/none.
 */
export function defaultIncomingPort(protocol: string, security: string): number {
  const ports = DEFAULT_INCOMING_PORTS[normalizeMailProtocol(protocol)];
  return /^(ssl|ssl\/tls|tls)$/i.test(security.trim()) ? ports.tls : ports.plain;
}

/**
 * Port to show after switching the incoming protocol: follows the new
 * protocol's default only when the current port is one of the old protocol's
 * defaults (a port the user typed is kept). TLS defaults map to TLS defaults
 * and plain ones to plain ones.
 */
export function portAfterProtocolChange(port: number, from: string, to: string): number {
  const previous = DEFAULT_INCOMING_PORTS[normalizeMailProtocol(from)];
  const target = DEFAULT_INCOMING_PORTS[normalizeMailProtocol(to)];
  if (port === previous.tls) return target.tls;
  if (port === previous.plain) return target.plain;
  return port;
}
