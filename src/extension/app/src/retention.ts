import { CategoryExpirationDays, EmailCategory, MessageRetention } from './api';

export const DEFAULT_CATEGORY_EXPIRATION_DAYS: CategoryExpirationDays = {
  marketing: 30,
  transactional: 30,
  updates: 30,
  verification: 30,
  uncategorized: -1,
};

export const MAX_EXPIRATION_DAYS = 365000;

export function categoryLabel(category: EmailCategory): string {
  return category[0].toUpperCase() + category.slice(1);
}

export function expirationLabel(message: MessageRetention, compact = false): string {
  if (message.expires_at === -1 || (message.expiration_days !== undefined && message.expiration_days < 0)) return compact ? 'Never expires' : 'Never (-1)';
  if (!message.expires_at) return 'Expiration unavailable';
  const date = new Date(message.expires_at);
  if (Number.isNaN(date.getTime())) return 'Expiration unavailable';
  if (compact && message.expired) return 'Expired';
  return `${message.expired ? 'Expired' : 'Expires'} ${compact ? date.toLocaleDateString() : date.toLocaleString()}`;
}

export function parseExpirationDays(value: string): number | null {
  if (!value.trim()) return null;
  const days = Number(value);
  if (!Number.isFinite(days) || !Number.isInteger(days)) return null;
  if (days < 0) return -1;
  return days > MAX_EXPIRATION_DAYS ? null : days;
}
