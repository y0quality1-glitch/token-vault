import { describe, expect, it } from 'vitest';
import { ROTATION_REMINDER_DAYS, rotationDueAt, rotationState } from '@token-vault/shared';

const DAY = 86_400_000;
const now = Date.parse('2026-11-06T12:00:00.000Z');
const at = (days: number) => new Date(now + days * DAY).toISOString();

describe('credential rotation reminders', () => {
  it('has no due date without an interval', () => {
    expect(rotationDueAt({ rotationIntervalDays: null, rotatedAt: null, createdAt: at(-400) })).toBeNull();
    expect(rotationState({ rotationIntervalDays: null, rotatedAt: null, createdAt: at(-400) }, now)).toEqual({ state: 'none' });
  });

  it('counts from the last rotation, or from the connection if never rotated', () => {
    expect(rotationDueAt({ rotationIntervalDays: 90, rotatedAt: null, createdAt: at(-10) })).toBe(at(80));
    expect(rotationDueAt({ rotationIntervalDays: 90, rotatedAt: at(-5), createdAt: at(-200) })).toBe(at(85));
  });

  it(`reminds ${ROTATION_REMINDER_DAYS} days ahead, then reports how overdue it is`, () => {
    expect(rotationState({ rotationIntervalDays: 30, rotatedAt: null, createdAt: at(-10) }, now)).toMatchObject({ state: 'ok', days: 20 });
    expect(rotationState({ rotationIntervalDays: 30, rotatedAt: null, createdAt: at(-25) }, now)).toMatchObject({ state: 'due_soon', days: 5 });
    expect(rotationState({ rotationIntervalDays: 30, rotatedAt: null, createdAt: at(-23) }, now)).toMatchObject({ state: 'due_soon', days: 7 });
    expect(rotationState({ rotationIntervalDays: 30, rotatedAt: null, createdAt: at(-30) }, now)).toMatchObject({ state: 'overdue', days: 1 });
    expect(rotationState({ rotationIntervalDays: 30, rotatedAt: null, createdAt: at(-42.5) }, now)).toMatchObject({ state: 'overdue', days: 13, dueAt: at(-12.5) });
  });
});
