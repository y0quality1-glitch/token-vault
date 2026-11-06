/**
 * Credential rotation reminders. An integration may have a rotation interval; its credential
 * is then due that many days after it was last rotated (or connected, if never rotated).
 * Reminders only: an overdue credential keeps working, the dashboard warns about it.
 */
export const ROTATION_INTERVAL_OPTIONS = [30, 60, 90, 180, 365] as const;
export const ROTATION_INTERVAL_MIN_DAYS = 7;
export const ROTATION_INTERVAL_MAX_DAYS = 730;
/** How far ahead of the due date the dashboard starts reminding. */
export const ROTATION_REMINDER_DAYS = 7;

const DAY = 86_400_000;

export function rotationDueAt(i: { rotationIntervalDays: number | null; rotatedAt: string | null; createdAt: string }): string | null {
  if (!i.rotationIntervalDays) return null;
  return new Date(Date.parse(i.rotatedAt ?? i.createdAt) + i.rotationIntervalDays * DAY).toISOString();
}

export type RotationState = { state: 'none' } | { state: 'ok' | 'due_soon' | 'overdue'; dueAt: string; days: number };

/** Where a credential stands against its rotation interval; `days` is until (or since, when overdue) the due date, rounded up. */
export function rotationState(i: { rotationIntervalDays: number | null; rotatedAt: string | null; createdAt: string }, now = Date.now()): RotationState {
  const dueAt = rotationDueAt(i);
  if (!dueAt) return { state: 'none' };
  const left = Date.parse(dueAt) - now;
  if (left <= 0) return { state: 'overdue', dueAt, days: Math.max(1, Math.ceil(-left / DAY)) };
  return { state: left <= ROTATION_REMINDER_DAYS * DAY ? 'due_soon' : 'ok', dueAt, days: Math.ceil(left / DAY) };
}
