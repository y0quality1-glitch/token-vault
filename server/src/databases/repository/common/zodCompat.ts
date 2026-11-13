/**
 * Problem functions (for `Check`) that reproduce the zod messages the old routes sent, so
 * converted DTOs keep their exact error texts ("Required", "String must contain at most 80
 * character(s)", "Invalid enum value. Expected 'a' | 'b', received 'c'").
 */

/** zod's name for the type of a value. */
export function zodType(v: unknown): string {
  if (v === null) return 'null';
  if (Array.isArray(v)) return 'array';
  if (typeof v === 'number' && Number.isNaN(v)) return 'nan';
  return typeof v;
}

const expected = (type: string, v: unknown) => (v === undefined ? 'Required' : `Expected ${type}, received ${zodType(v)}`);

/** z.string().min(min, minMessage).max(max): run after `@Transform(trim)` for `.trim()`. */
export function zString(opts: { min?: number; minMessage?: string; max?: number } = {}) {
  return (v: unknown): string | null => {
    if (typeof v !== 'string') return expected('string', v);
    if (opts.min !== undefined && v.length < opts.min) return opts.minMessage ?? `String must contain at least ${opts.min} character(s)`;
    if (opts.max !== undefined && v.length > opts.max) return `String must contain at most ${opts.max} character(s)`;
    return null;
  };
}

/** z.enum(values). */
export function zEnum(values: readonly string[]) {
  const list = values.map((x) => `'${x}'`).join(' | ');
  return (v: unknown): string | null => {
    if (typeof v !== 'string') return expected(list, v);
    return values.includes(v) ? null : `Invalid enum value. Expected ${list}, received '${v}'`;
  };
}

/** z.boolean(). */
export const zBoolean = (v: unknown): string | null => (typeof v === 'boolean' ? null : expected('boolean', v));
