import type { ArgumentCondition, ArgumentOperator } from './types';

/**
 * Argument rules: conditions on what a request contains (its input and resource fields).
 * A policy with argument rules applies only when every rule holds, so the same rules work
 * for DENY ("deny when input.title matches password"), REQUIRE_APPROVAL ("approve when
 * input.amount is greater than 500") and ALLOW (traceability).
 */

export const ARGUMENT_OPERATORS: { op: ArgumentOperator; label: string; value: 'text' | 'number' | 'list' }[] = [
  { op: 'equals', label: 'equals', value: 'text' },
  { op: 'not_equals', label: 'does not equal', value: 'text' },
  { op: 'contains', label: 'contains', value: 'text' },
  { op: 'not_contains', label: 'does not contain', value: 'text' },
  { op: 'matches', label: 'matches pattern', value: 'text' },
  { op: 'not_matches', label: 'does not match pattern', value: 'text' },
  { op: 'in', label: 'is one of', value: 'list' },
  { op: 'not_in', label: 'is not one of', value: 'list' },
  { op: 'longer_than', label: 'is longer than (characters)', value: 'number' },
  { op: 'greater_than', label: 'is greater than', value: 'number' },
  { op: 'less_than', label: 'is less than', value: 'number' },
];

/**
 * `input.<name>` or `resource.<name>` (names as in provider definitions), or a field of the
 * user the agent acts for: `user.sub`, `user.email`, `user.name`, `user.groups`, `user.issuer`
 * (empty when the agent acts for itself).
 */
export const ARGUMENT_FIELD = /^((input|resource)\.[a-zA-Z][a-zA-Z0-9_]{0,39}|user\.(sub|email|name|groups|issuer))$/;
export const USER_ARGUMENT_FIELDS = ['user.sub', 'user.email', 'user.name', 'user.groups', 'user.issuer'] as const;
export const MAX_PATTERN_LENGTH = 200;

export interface RequestContent {
  resource: Record<string, string>;
  input: Record<string, unknown>;
  /** The user the agent acts for (absent or null: the agent acts for itself). */
  user?: { sub: string; email?: string | null; name?: string | null; groups: string[]; issuer: string } | null;
}

function fieldValue(field: string, req: RequestContent): unknown {
  const [scope, name] = field.split('.', 2) as ['input' | 'resource' | 'user', string];
  if (scope === 'user') {
    const u = req.user;
    if (name === 'groups') return u?.groups ?? [];
    return u ? (u as unknown as Record<string, unknown>)[name] : undefined;
  }
  const source = scope === 'input' ? req.input : req.resource;
  return Object.prototype.hasOwnProperty.call(source, name) ? source[name] : undefined;
}

const NEGATED: ArgumentOperator[] = ['not_equals', 'not_contains', 'not_matches', 'not_in'];

const asText = (v: unknown): string => (v === undefined || v === null ? '' : typeof v === 'string' ? v : typeof v === 'object' ? JSON.stringify(v) : String(v));

function asNumber(v: unknown): number | null {
  if (typeof v === 'number') return Number.isFinite(v) ? v : null;
  if (typeof v === 'string' && v.trim() !== '' && Number.isFinite(Number(v))) return Number(v);
  return null;
}

/** Whether one argument rule holds for the request. Text comparisons ignore case. */
export function argumentHolds(c: ArgumentCondition, req: RequestContent): boolean {
  const value = fieldValue(c.field, req);
  // A list (user.groups): a rule holds when any item satisfies it; a negated rule when every item does (none matches).
  if (Array.isArray(value)) {
    const each = (v: unknown) => valueHolds(c, v);
    return NEGATED.includes(c.op) ? value.every(each) : value.some(each);
  }
  return valueHolds(c, value);
}

function valueHolds(c: ArgumentCondition, raw: unknown): boolean {
  const text = asText(raw).toLowerCase();
  const target = typeof c.value === 'string' ? c.value.toLowerCase() : '';
  const list = Array.isArray(c.value) ? c.value.map((x) => x.toLowerCase()) : [];
  switch (c.op) {
    case 'equals':
      return text === target;
    case 'not_equals':
      return text !== target;
    case 'contains':
      return text.includes(target);
    case 'not_contains':
      return !text.includes(target);
    case 'matches':
    case 'not_matches': {
      let hit: boolean;
      try {
        // Bounded input keeps a badly written pattern from stalling the engine.
        hit = new RegExp(String(c.value), 'i').test(asText(raw).slice(0, 10_000));
      } catch {
        hit = c.op === 'matches'; // an invalid pattern (rejected on save) fails closed
      }
      return c.op === 'matches' ? hit : !hit;
    }
    case 'in':
      return list.includes(text);
    case 'not_in':
      return !list.includes(text);
    case 'longer_than':
      return asText(raw).length > Number(c.value);
    case 'greater_than':
    case 'less_than': {
      const n = asNumber(raw);
      if (n === null) return true; // not a number: fail closed
      return c.op === 'greater_than' ? n > Number(c.value) : n < Number(c.value);
    }
  }
}

/** Problem with a rule as an administrator wrote it, or null. */
export function argumentProblem(c: ArgumentCondition): string | null {
  if (!ARGUMENT_FIELD.test(c.field)) return `"${c.field}" must be input.<name>, resource.<name> or one of ${USER_ARGUMENT_FIELDS.join(', ')}`;
  const kind = ARGUMENT_OPERATORS.find((o) => o.op === c.op)?.value;
  if (!kind) return `Unknown operator "${c.op}"`;
  if (kind === 'number' && (typeof c.value !== 'number' || !Number.isFinite(c.value))) return `${c.field}: enter a number`;
  if (kind === 'list' && (!Array.isArray(c.value) || c.value.length === 0 || c.value.length > 50)) return `${c.field}: enter 1–50 values`;
  if (kind === 'text' && typeof c.value !== 'string') return `${c.field}: enter a value`;
  if (c.op === 'matches' || c.op === 'not_matches') {
    const p = String(c.value);
    if (!p || p.length > MAX_PATTERN_LENGTH) return `${c.field}: the pattern must be 1–${MAX_PATTERN_LENGTH} characters`;
    try {
      new RegExp(p, 'i');
    } catch {
      return `${c.field}: "${p}" is not a valid regular expression`;
    }
  }
  return null;
}

export function describeArgument(c: ArgumentCondition): string {
  const label = ARGUMENT_OPERATORS.find((o) => o.op === c.op)?.label ?? c.op;
  const value = Array.isArray(c.value) ? c.value.join(', ') : String(c.value);
  return `${c.field} ${label} ${c.op === 'matches' || c.op === 'not_matches' ? `/${value}/` : `"${value}"`}`;
}
