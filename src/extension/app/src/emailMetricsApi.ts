import { ApiError } from './api';
import { apiUrl } from './platform/backend';

export interface EmailMetricsDomain {
  domain: string;
  message_count: number;
  size_bytes: number;
}

export interface EmailMetricsRun {
  id: string;
  created_at: string;
  completed_at: string | null;
  account_email: string | null;
  source_kind: string;
  run_kind: 'scheduled' | 'adhoc';
  scheduled_for: string | null;
  window_start: string | null;
  window_end: string | null;
  days: number | null;
  total_messages: number;
  total_size_bytes: number;
  domains: EmailMetricsDomain[];
}

export interface EmailMetricsHistory {
  runs: EmailMetricsRun[];
  domains: string[];
  accounts: string[];
}

export interface EmailMetricsScheduleAccount {
  email: string;
  next_run_at: string | null;
  last_run_at: string | null;
  pending_runs: number;
  unlocked: boolean;
  last_error: string | null;
}

export interface EmailMetricsSchedule {
  enabled: boolean;
  timezone: string;
  weekday: number;
  hour: number;
  minute: number;
  accounts: EmailMetricsScheduleAccount[];
}

async function get<T>(path: string, signal?: AbortSignal): Promise<T> {
  const response = await fetch(apiUrl(path), { signal });
  if (!response.ok) {
    const body = await response.text();
    let detail: unknown = body || response.statusText;
    try {
      const parsed = JSON.parse(body) as { detail?: unknown };
      detail = parsed.detail ?? parsed;
    } catch { /* Keep the readable response when it is not JSON. */ }
    throw new ApiError(response.status, detail);
  }
  return response.json() as Promise<T>;
}

export const emailMetricsApi = {
  history: (account = '', signal?: AbortSignal) => get<EmailMetricsHistory>(
    `/api/email-metrics${account ? `?account=${encodeURIComponent(account)}` : ''}`, signal,
  ),
  schedule: (signal?: AbortSignal) => get<EmailMetricsSchedule>('/api/email-metrics/schedule', signal),
};
