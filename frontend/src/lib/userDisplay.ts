import type { UserSummary } from '../types/api';

const trimText = (value: unknown): string => String(value || '').trim();

export const userDisplayName = (
  user?: UserSummary | null,
  userId?: string | null,
  fallback: string = 'Unknown user'
): string => {
  const display = trimText(user?.display_name);
  if (display) return display;

  const fullName = trimText(user?.full_name);
  if (fullName) return fullName;

  const id = trimText(user?.id || userId);
  if (!id) return fallback;
  return `user-${id.slice(0, 8)}`;
};

export const userDisplayMeta = (user?: UserSummary | null, userId?: string | null): string => {
  const role = trimText(user?.role);
  const id = trimText(user?.id || userId);
  if (role && id) return `${role} • ${id}`;
  if (role) return role;
  if (id) return id;
  return '';
};
