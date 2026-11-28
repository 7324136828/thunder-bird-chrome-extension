import { ApiError } from './api';
import { apiUrl } from './platform/backend';

export interface DoctorJob {
  id: string;
  filename: string;
  file_size: number;
  status: 'queued' | 'in_progress' | 'completed' | 'healthy' | 'failed' | 'discarded';
  progress: number;
  stage: string | null;
  log: string;
  error_message: string | null;
  created_at: string;
  completed_at: string | null;
  output_files: string[];
  source_kind: string;
  account_email: string | null;
  days: number | null;
  downloaded_messages: number;
  total_messages: number | null;
  snapshot_available: boolean;
  snapshot_at: string | null;
  run_kind?: 'scheduled' | 'adhoc';
  scheduled_for?: string | null;
  window_start?: string | null;
  window_end?: string | null;
}

export interface MailDiscovery {
  provider: 'google' | 'microsoft' | 'credentials';
  imap_server: string;
  imap_port: number;
  use_ssl: boolean;
  oauth_configured: boolean | null;
  oauth_callback_url: string | null;
}

export const doctorError = (error: unknown) => error instanceof Error ? error.message : String(error);
export const isRunning = (job: DoctorJob) => job.status === 'queued' || job.status === 'in_progress';

async function request<T>(path: string, options?: RequestInit): Promise<T> {
  const response = await fetch(apiUrl(path), options);
  if (!response.ok) {
    const body = await response.text();
    let detail: unknown = body || response.statusText;
    try {
      const parsed = JSON.parse(body) as { detail?: unknown };
      detail = parsed.detail ?? parsed;
    } catch { /* Keep a readable non-JSON response. */ }
    if (Array.isArray(detail)) {
      detail = detail.map((item: { msg?: string }) => item.msg ?? String(item)).join('; ');
    }
    throw new ApiError(response.status, detail);
  }
  return response.json() as Promise<T>;
}

function post<T>(path: string, body: unknown): Promise<T> {
  return request<T>(path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
}

export const doctorApi = {
  jobs: () => request<DoctorJob[]>('/api/jobs'),
  job: (id: string) => request<DoctorJob>(`/api/jobs/${encodeURIComponent(id)}`),
  upload: (files: File[]) => {
    const body = new FormData();
    files.forEach((file) => body.append('files', file, file.name));
    return request<DoctorJob>('/api/jobs', { method: 'POST', body });
  },
  paste: (content: string, filename: string) => post<DoctorJob>('/api/jobs/paste', { content, filename }),
  account: (account: string, days: number) => post<DoctorJob>('/api/mail/jobs/account', { account, days }),
  discover: (email: string) => request<MailDiscovery>(`/api/mail/providers?email=${encodeURIComponent(email)}`),
  connect: (body: {
    email: string; password: string; days: number; imap_server: string;
    imap_port: number; use_ssl: boolean; use_app_password: boolean;
  }) => post<DoctorJob>('/api/mail/jobs', body),
  oauth: (provider: string, email: string, days: number) => post<{
    authorization_url: string; message_origin: string; state: string;
  }>('/api/mail/oauth/start', { provider, email, days }),
  discard: (id: string) => request<DoctorJob>(`/api/jobs/${encodeURIComponent(id)}/discard`, { method: 'POST' }),
  files: (id: string, snapshot = false) => request<{ files: string[] }>(
    `/api/jobs/${encodeURIComponent(id)}/${snapshot ? 'snapshot-files' : 'files'}`,
  ),
  fileUrl: (id: string, path: string, snapshot = false) =>
    apiUrl(`/api/jobs/${encodeURIComponent(id)}/${snapshot ? 'snapshot-files' : 'files'}/${path.split('/').map(encodeURIComponent).join('/')}`),
  zipUrl: (id: string) => apiUrl(`/api/jobs/${encodeURIComponent(id)}/download-zip`),
  text: async (id: string, path: string, snapshot = false) => {
    const response = await fetch(doctorApi.fileUrl(id, path, snapshot));
    if (!response.ok) throw new Error(`Could not load ${path} (${response.status}).`);
    return response.text();
  },
};
