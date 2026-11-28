import { apiUrl } from './platform/backend';

export interface ServerProfile {
  incoming_server: string;
  incoming_port: number;
  incoming_protocol: string;
  outgoing_server: string;
  outgoing_port: number;
  outgoing_protocol: string;
  email_address: string;
  display_name: string;
  /** Rust backend extension: 'imap' (default) or 'pop3' (compatibility mode). */
  incoming_mail_protocol?: string;
}

export interface Account {
  email: string;
  display_name: string;
  incoming_server: string;
  incoming_port: number;
  incoming_protocol: string;
  outgoing_server: string;
  outgoing_port: number;
  outgoing_protocol: string;
  /** Rust backend extension: 'imap' (default) or 'pop3' (compatibility mode). */
  incoming_mail_protocol?: string;
  unlocked_at: number;
}

export interface Folder {
  name: string;
  delimiter: string;
  flags: string[];
  special: string;
  selectable: boolean;
}

export interface MailSettings {
  messages_per_page: number;
  signature: string;
  category_expiration_days?: CategoryExpirationDays;
  local_ai_model?: string;
}

export const DEFAULT_LOCAL_AI_MODEL = 'llama3.2:latest';

export interface LocalClassifierStatus {
  available: boolean;
  model: string;
  installed_models: string[];
  error?: string | null;
}

export const EMAIL_CATEGORIES = ['marketing', 'transactional', 'updates', 'verification', 'uncategorized'] as const;
export type EmailCategory = typeof EMAIL_CATEGORIES[number];
export type CategoryExpirationDays = Record<EmailCategory, number>;
export type CategoryFilter = EmailCategory | 'all';

export interface SenderCategoryRule {
  sender: string;
  category: EmailCategory;
  created_at: string;
  first_uid: number;
  uid_validity: string;
  revision?: number;
}

export interface MessageRetention {
  category?: EmailCategory;
  category_source?: 'automatic' | 'manual' | 'ai' | 'sender_rule';
  category_reason?: string;
  category_model?: string | null;
  expiration_days?: number;
  expiration_source?: 'category' | 'manual';
  expires_at?: string | -1 | null;
  expired?: boolean;
  received_at?: string | null;
  uid_validity?: string | null;
  sender_rule?: SenderCategoryRule | null;
}

export interface RetentionUpdate {
  category?: EmailCategory | null;
  expiration_days?: number | null;
}

export interface TrashPreparation {
  operation_id: string;
  count: number;
  archive: boolean;
  filename: string | null;
}

export interface TrashEmptyResult {
  deleted: number;
  remaining: number;
}

export interface MessageSummary extends MessageRetention {
  uid: number;
  flags: string[];
  seen: boolean;
  flagged: boolean;
  answered: boolean;
  size: number;
  internal_date: string | null;
  subject: string;
  from: string;
  to: string;
  date: string | null;
}

export type MessageReadStatus = 'all' | 'unread' | 'read';

export interface Attachment {
  index: number;
  filename: string;
  content_type: string;
  size: number;
}

export interface FullMessage extends MessageRetention {
  uid: number;
  folder: string;
  flags: string[];
  seen: boolean;
  flagged: boolean;
  subject: string;
  from_name: string;
  from_addr: string;
  to: string;
  cc: string;
  date: string | null;
  message_id: string;
  text_body: string;
  html_body: string;
  snippet: string;
  attachments: Attachment[];
}

export interface SendMessage {
  account: string;
  to: string[];
  cc: string[];
  bcc: string[];
  subject: string;
  text: string;
  html?: string;
  in_reply_to?: string;
  references?: string;
}

export interface SendUpload {
  file: File;
  contentId?: string;
  inline: boolean;
}

export interface RichSignature {
  html: string;
  uploads: SendUpload[];
}

export interface StoredAccountSignature {
  account: string;
  text: string;
  'multipart-path': Record<string, string>;
  images: { content_id: string; filename: string; content_type: string; url: string }[];
}

export interface SendResult {
  sent: boolean;
  message_id: string;
  from: string;
  sent_saved?: boolean;
  sent_folder?: string | null;
  warning?: string;
}

export interface Finding {
  severity: 'pass' | 'info' | 'warn' | 'alert';
  title: string;
  detail: string;
}

export interface AuditReport {
  generated_at: string;
  account: string;
  subject: string;
  from_name: string;
  from_addr: string;
  to: string;
  date: string | null;
  message_id: string;
  authentication: {
    spf: string;
    dkim: string;
    dmarc: string;
    raw: string[];
  };
  sender: {
    from_domain: string;
    reply_to: string;
    return_path: string;
    message_id_domain: string;
    x_mailer: string;
    importance: string;
  };
  routing: {
    hop_count: number;
    delivery_seconds: number | null;
    hops: {
      index: number;
      from: string;
      by: string;
      with: string;
      for: string;
      timestamp: string | null;
    }[];
  };
  links: { url: string; domain: string; label: string }[];
  link_count: number;
  attachments: Attachment[];
  unsubscribe: { present: boolean; link: string; one_click: boolean };
  findings: Finding[];
  risk_score: number;
  verdict: 'low' | 'medium' | 'high';
  snippet: string;
}

export class ApiError extends Error {
  status: number;
  detail: unknown;

  constructor(status: number, detail: unknown) {
    super(typeof detail === 'string' ? detail : `Request failed (${status})`);
    this.status = status;
    this.detail = detail;
  }

  get passwordRequired(): { error: string; email: string } | null {
    if (
      this.status === 401 &&
      typeof this.detail === 'object' &&
      this.detail !== null &&
      (this.detail as { error?: string }).error === 'password_required'
    ) {
      return this.detail as { error: string; email: string };
    }
    return null;
  }
}

async function request<T>(path: string, options?: RequestInit): Promise<T> {
  const response = await fetch(apiUrl(path), options);
  if (!response.ok) {
    let detail: unknown = response.statusText;
    try {
      const body = (await response.json()) as { detail?: unknown };
      detail = body.detail ?? body;
    } catch {
      detail = await response.text().catch(() => response.statusText);
    }
    throw new ApiError(response.status, detail);
  }
  return (await response.json()) as T;
}

async function requestImage(path: string, options: RequestInit): Promise<Blob> {
  const response = await fetch(apiUrl(path), options);
  if (!response.ok) {
    const text = await response.text();
    let detail: unknown = text || response.statusText;
    try {
      const body = JSON.parse(text) as { detail?: unknown };
      detail = body.detail ?? body;
    } catch {
      // Non-JSON failures still retain the server's status and message.
    }
    throw new ApiError(response.status, detail);
  }
  const blob = await response.blob();
  if (!['image/png', 'image/jpeg', 'image/gif', 'image/webp', 'image/bmp'].includes(blob.type)) {
    throw new ApiError(502, 'The remote resource is not a supported image.');
  }
  return blob;
}

function mailQuery(account: string, extra: Record<string, string | number | boolean> = {}) {
  const params = new URLSearchParams({ account });
  for (const [key, value] of Object.entries(extra)) {
    params.set(key, String(value));
  }
  return params.toString();
}

function messageQuery(account: string, folder: string, offset: number, limit: number, query: string, domains: string[], readStatus: MessageReadStatus, category: CategoryFilter, expiredOnly: boolean) {
  const params = new URLSearchParams(mailQuery(account, { folder, offset, limit, query }));
  domains.forEach((domain) => params.append('sender_domain', domain));
  if (readStatus !== 'all') params.set('read_status', readStatus);
  if (category !== 'all') params.set('category', category);
  if (expiredOnly) params.set('expired_only', 'true');
  return params.toString();
}

export const api = {
  health: () => request<{ status: string }>('/api/health'),

  settings: () => request<MailSettings>('/api/settings'),

  saveSettings: (messagesPerPage: number, signature?: string, categoryExpirationDays?: CategoryExpirationDays, localAiModel?: string) => request<MailSettings>('/api/settings', {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ messages_per_page: messagesPerPage, ...(signature !== undefined ? { signature } : {}), ...(categoryExpirationDays ? { category_expiration_days: categoryExpirationDays } : {}), ...(localAiModel !== undefined ? { local_ai_model: localAiModel } : {}) }),
  }),

  signature: (account: string) => request<StoredAccountSignature>(
    `/api/mail/signature?${mailQuery(account)}`,
  ),

  signatureImage: (account: string, contentId: string, revision?: string) => requestImage(
    `/api/mail/signature/image?${mailQuery(account, { content_id: contentId, ...(revision ? { revision } : {}) })}`,
    { method: 'GET' },
  ),

  saveSignature: (account: string, html: string, uploads: SendUpload[]) => {
    const form = new FormData();
    form.append('signature', JSON.stringify({
      text: html,
      uploads: uploads.map((upload) => ({ content_id: upload.contentId })),
    }));
    uploads.forEach((upload) => form.append('files', upload.file, upload.file.name));
    return request<StoredAccountSignature>(`/api/mail/signature?${mailQuery(account)}`, { method: 'PUT', body: form });
  },

  servers: () =>
    request<{ path: string; servers: Record<string, ServerProfile>; display_names?: Record<string, string>; display_names_error?: string }>(
      '/api/mail/servers',
    ),

  saveProfile: (key: string, profile: ServerProfile) =>
    request<{ key: string; profile: ServerProfile }>(
      `/api/mail/servers/${encodeURIComponent(key)}`,
      {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(profile),
      },
    ),

  deleteProfile: (key: string) =>
    request<{ deleted: string }>(
      `/api/mail/servers/${encodeURIComponent(key)}`,
      { method: 'DELETE' },
    ),

  accounts: () => request<{ accounts: Account[] }>('/api/accounts'),

  unlock: (body: {
    email: string;
    password: string;
    profile_key?: string;
    display_name?: string;
    incoming_server?: string;
    incoming_port?: number;
    incoming_protocol?: string;
    outgoing_server?: string;
    outgoing_port?: number;
    outgoing_protocol?: string;
    incoming_mail_protocol?: string;
    save_profile?: boolean;
  }) =>
    request<{ account: Account }>('/api/accounts/unlock', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    }),

  lock: (email: string) =>
    request<{ locked: string }>(`/api/accounts/${encodeURIComponent(email)}`, {
      method: 'DELETE',
    }),

  folders: (account: string) =>
    request<{ folders: Folder[] }>(`/api/mail/folders?${mailQuery(account)}`),

  messages: (
    account: string,
    folder: string,
    offset: number,
    limit: number,
    query: string,
    domains: string[] = [],
    readStatus: MessageReadStatus = 'all',
    category: CategoryFilter = 'all',
    expiredOnly = false,
  ) =>
    request<{
      total: number;
      offset: number;
      limit: number;
      messages: MessageSummary[];
    }>(`/api/mail/messages?${messageQuery(account, folder, offset, limit, query, domains, readStatus, category, expiredOnly)}`),

  updateRetention: (account: string, folder: string, uid: number, uidValidity: string | null | undefined, update: RetentionUpdate) =>
    request<MessageRetention>('/api/mail/message/retention', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ account, folder, uid, uid_validity: uidValidity, ...update }),
    }),

  classifyMessage: (account: string, folder: string, uid: number, uidValidity: string) =>
    request<MessageRetention>('/api/mail/message/classify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ account, folder, uid, uid_validity: uidValidity }),
    }),

  saveSenderRule: (account: string, folder: string, uid: number, uidValidity: string, category: EmailCategory) =>
    request<MessageRetention & { rule: SenderCategoryRule }>('/api/mail/message/sender-rule', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ account, folder, uid, uid_validity: uidValidity, category }),
    }),

  senderRules: (account: string, folder: string) => request<{ rules: SenderCategoryRule[] }>(
    `/api/mail/sender-rules?${mailQuery(account, { folder })}`,
  ),

  deleteSenderRule: (account: string, folder: string, sender: string, expectedRevision?: number) => request<{ deleted: boolean }>(
    `/api/mail/sender-rules?${mailQuery(account, { folder, sender, ...(expectedRevision !== undefined ? { expected_revision: expectedRevision } : {}) })}`, { method: 'DELETE' },
  ),

  classifierStatus: (model?: string) => request<LocalClassifierStatus>(
    `/api/mail/classifier/status${model ? `?${new URLSearchParams({ model })}` : ''}`,
  ),

  message: (account: string, folder: string, uid: number, markSeen = true) =>
    request<FullMessage>(
      `/api/mail/message?${mailQuery(account, { folder, uid, mark_seen: markSeen })}`,
    ),

  messageImage: (
    account: string,
    folder: string,
    uid: number,
    url: string,
    retry = false,
    signal?: AbortSignal,
  ) =>
    requestImage('/api/mail/message/image', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ account, folder, uid, url, retry }),
      signal,
    }),

  messageEmlUrl: (account: string, folder: string, uid: number) =>
    apiUrl(`/api/mail/message/eml?${mailQuery(account, { folder, uid })}`),

  attachmentUrl: (account: string, folder: string, uid: number, index: number) =>
    apiUrl(`/api/mail/message/attachment?${mailQuery(account, { folder, uid, index })}`),

  setFlags: (
    account: string,
    folder: string,
    uid: number,
    flags: { seen?: boolean; flagged?: boolean },
  ) =>
    request<{ uid: number; flags: string[]; seen: boolean; flagged: boolean }>(
      '/api/mail/message/flags',
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ account, folder, uid, ...flags }),
      },
    ),

  deleteMessage: (account: string, folder: string, uid: number, trash: string, uidValidity?: string) =>
    request<{ deleted: number }>(
      `/api/mail/message?${mailQuery(account, { folder, uid, trash, ...(uidValidity ? { uid_validity: uidValidity } : {}) })}`,
      { method: 'DELETE' },
    ),

  deleteMessages: (account: string, folder: string, uids: number[], trash: string, uidValidity?: string) =>
    request<{ deleted: number[] }>('/api/mail/messages/delete', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ account, folder, uids, trash, ...(uidValidity ? { uid_validity: uidValidity } : {}) }),
    }),

  prepareTrash: (account: string, folder: string, archive: boolean) =>
    request<TrashPreparation>('/api/mail/trash/prepare', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ account, folder, archive }),
    }),

  trashArchiveUrl: (account: string, operationId: string) =>
    apiUrl(`/api/mail/trash/${encodeURIComponent(operationId)}/archive?${mailQuery(account)}`),

  emptyTrash: (account: string, operationId: string) =>
    request<TrashEmptyResult>(`/api/mail/trash/${encodeURIComponent(operationId)}/empty`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ account }),
    }),

  discardTrash: (account: string, operationId: string) =>
    request<{ discarded: boolean }>(
      `/api/mail/trash/${encodeURIComponent(operationId)}?${mailQuery(account)}`,
      { method: 'DELETE' },
    ),

  send: (body: SendMessage, uploads: SendUpload[] = []) => {
    if (uploads.length) {
      const form = new FormData();
      form.append('message', JSON.stringify({
        ...body,
        uploads: uploads.map((upload) => ({
          content_id: upload.contentId ?? '',
          disposition: upload.inline ? 'inline' : 'attachment',
        })),
      }));
      uploads.forEach((upload) => form.append('files', upload.file, upload.file.name));
      return request<SendResult>('/api/mail/send/files', { method: 'POST', body: form });
    }
    return request<SendResult>('/api/mail/send', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
  },

  audit: (account: string, folder: string, uid: number) =>
    request<AuditReport>(
      `/api/mail/audit?${mailQuery(account, { folder, uid })}`,
    ),

  auditEml: (content: string) =>
    request<AuditReport>('/api/audit/eml', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ content }),
    }),
};
