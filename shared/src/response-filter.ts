/**
 * Response filtering: what an agent (and the model behind it) gets back from an application.
 *
 * Applied by the customer webhook, so raw values never leave the customer's side, and again
 * by the control plane when a webhook did not apply exactly the filter it was asked to (an
 * older webhook), so an agent never receives an unfiltered result. Pure functions, no I/O:
 * the same code runs in both places and in the browser (for previews).
 *
 *  - mask: replaces detected values (emails, phone numbers, card numbers, IP addresses,
 *    secrets such as API keys, tokens and private keys, and custom patterns) with
 *    "[REDACTED:<kind>]";
 *  - removeFields: deletes fields by name ("email") or by the end of their path ("author.email");
 *  - promptInjection: looks for text that tries to instruct the model ("ignore previous
 *    instructions", chat markup, "send this to https://…"): "flag" passes the result with
 *    warnings, "block" withholds it.
 * The report counts what was done; it never contains the values.
 */

export type DataDetector = 'email' | 'phone' | 'credit_card' | 'ip_address' | 'secret';
export type InjectionMode = 'off' | 'flag' | 'block';

export interface ResponseFilter {
  mask: DataDetector[];
  /** Extra values to mask: a name (used in the replacement) and a regular expression. */
  customPatterns: { name: string; pattern: string }[];
  /** Field names, or dotted path endings, to remove wherever they appear. */
  removeFields: string[];
  promptInjection: InjectionMode;
}

export interface InjectionSignal {
  /** Where in the result (e.g. "items[3].body"). */
  path: string;
  signal: string;
}

export interface FilterReport {
  /** Values masked, per detector or custom pattern name. */
  masked: Record<string, number>;
  removedFields: number;
  injection: { detected: boolean; signals: InjectionSignal[] };
  /** The result was withheld (prompt injection with "block", or too large to inspect). */
  withheld: boolean;
  withheldReason: string | null;
}

export const DATA_DETECTORS: { id: DataDetector; label: string; example: string }[] = [
  { id: 'email', label: 'Email addresses', example: 'ada@example.com' },
  { id: 'phone', label: 'Phone numbers', example: '+44 20 7946 0958' },
  { id: 'credit_card', label: 'Payment card numbers', example: '4111 1111 1111 1111' },
  { id: 'ip_address', label: 'IP addresses', example: '203.0.113.7' },
  { id: 'secret', label: 'Secrets (API keys, tokens, private keys, passwords)', example: 'ghp_…, AKIA…, -----BEGIN PRIVATE KEY-----' },
];

export const INJECTION_MODES: { id: InjectionMode; label: string; hint: string }[] = [
  { id: 'off', label: 'Off', hint: 'No check.' },
  { id: 'flag', label: 'Flag', hint: 'Pass the result, with a warning the agent and the audit log see.' },
  { id: 'block', label: 'Withhold the result', hint: 'The operation still ran, but the agent receives no result.' },
];

export const FILTER_LIMITS = { MAX_PATTERNS: 10, MAX_PATTERN_LENGTH: 200, MAX_FIELDS: 50, MAX_NODES: 50_000, MAX_DEPTH: 20, MAX_STRING: 100_000, MAX_SIGNALS: 10 };

export const EMPTY_FILTER: ResponseFilter = { mask: [], customPatterns: [], removeFields: [], promptInjection: 'off' };

// ---------------------------------------------------------------- detectors

function luhn(digits: string): boolean {
  let sum = 0;
  for (let i = 0; i < digits.length; i++) {
    let d = Number(digits[digits.length - 1 - i]);
    if (i % 2 === 1) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
  }
  return sum % 10 === 0;
}

/** Each detector: patterns, and an optional check on a match (false: leave it). Order matters: secrets first. */
const DETECTORS: Record<DataDetector, { patterns: RegExp[]; check?: (m: string) => boolean }> = {
  secret: {
    patterns: [
      /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g,
      /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g,
      /\bgh[pousr]_[A-Za-z0-9]{36,255}\b/g,
      /\bgithub_pat_[A-Za-z0-9_]{22,255}\b/g,
      /\bxox[abprs]-[A-Za-z0-9-]{10,}/g,
      /\b[rs]k_(?:live|test)_[A-Za-z0-9]{16,}\b/g,
      /\bAIza[0-9A-Za-z_-]{35}\b/g,
      /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g,
      /\btv(?:ak|dt)_[0-9a-f]{12}_[A-Za-z0-9_-]{20,64}/g,
      /\b(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token)\b\s*[:=]\s*["']?[^\s"',;]{6,}/gi,
      /\bBearer\s+[A-Za-z0-9._~+/-]{20,}=*/g,
    ],
  },
  credit_card: { patterns: [/\b\d(?:[ -]?\d){12,18}\b/g], check: (m) => luhn(m.replace(/\D/g, '')) },
  email: { patterns: [/[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}/g] },
  phone: { patterns: [/(?<![\w+])\+\d{1,3}[\s.-]?(?:\(\d{1,4}\)[\s.-]?)?\d{2,4}(?:[\s.-]?\d{2,4}){1,3}(?!\w)/g, /(?<![\w+])\(?\d{3}\)?[\s.-]\d{3}[\s.-]\d{4}(?!\w)/g] },
  ip_address: { patterns: [/\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b/g] },
};
const DETECTOR_ORDER: DataDetector[] = ['secret', 'credit_card', 'email', 'phone', 'ip_address'];

const INJECTION_PATTERNS: { signal: string; pattern: RegExp }[] = [
  { signal: 'asks to ignore instructions', pattern: /\b(?:ignore|disregard|forget|override)\b[^.\n]{0,40}\b(?:previous|prior|above|earlier|all|any|your|the|these)\b[^.\n]{0,20}\b(?:instructions?|prompts?|rules|directions|guidelines)\b/i },
  { signal: 'tries to change the assistant role', pattern: /\byou are now\b|\bfrom now on,? you\b|\bact as (?:an?|the)\b[^.\n]{0,30}\b(?:assistant|ai|model|system|admin)\b/i },
  { signal: 'mentions the system prompt', pattern: /\b(?:system prompt|developer message|hidden instructions?)\b/i },
  { signal: 'contains chat markup', pattern: /<\|im_(?:start|end)\|>|\[\/?INST\]|<<\/?SYS>>|^\s*(?:###\s*)?(?:system|assistant)\s*:/im },
  { signal: 'tells the agent to call a tool', pattern: /\b(?:you (?:must|should|need to|have to)|assistant,?|AI,?|agent,?)\s+(?:now\s+|immediately\s+)?(?:call|use|invoke|run|execute)\s+(?:the\s+)?(?:\w+\s+)?(?:tool|function)\b/i },
  { signal: 'asks to send data somewhere', pattern: /\b(?:send|post|upload|forward|exfiltrate|email)\b[^.\n]{0,60}\b(?:to|at)\s+(?:https?:\/\/|[\w.-]+@[\w-]+\.)/i },
  { signal: 'asks to hide something from the user', pattern: /\b(?:do not|don't|never)\s+(?:tell|inform|mention|reveal|show)\b[^.\n]{0,30}\b(?:the user|anyone|them|the human)\b/i },
];

// ---------------------------------------------------------------- validation and merging

/** Problem with a filter as an administrator wrote it, or null. */
export function responseFilterProblem(f: ResponseFilter): string | null {
  for (const d of f.mask) if (!DATA_DETECTORS.some((x) => x.id === d)) return `Unknown detector "${d}"`;
  if (f.customPatterns.length > FILTER_LIMITS.MAX_PATTERNS) return `At most ${FILTER_LIMITS.MAX_PATTERNS} custom patterns`;
  for (const p of f.customPatterns) {
    if (!/^[a-z][a-z0-9_-]{0,39}$/.test(p.name)) return `Pattern name "${p.name}": lowercase letters, digits, - and _ (for example employee_id)`;
    if (!p.pattern || p.pattern.length > FILTER_LIMITS.MAX_PATTERN_LENGTH) return `Pattern "${p.name}": 1–${FILTER_LIMITS.MAX_PATTERN_LENGTH} characters`;
    try {
      if (new RegExp(p.pattern, 'g').test('')) return `Pattern "${p.name}" matches empty text`;
    } catch {
      return `Pattern "${p.name}" is not a valid regular expression`;
    }
  }
  if (f.removeFields.length > FILTER_LIMITS.MAX_FIELDS) return `At most ${FILTER_LIMITS.MAX_FIELDS} fields to remove`;
  for (const field of f.removeFields) if (!/^[A-Za-z_][\w-]{0,63}(?:\.[A-Za-z_][\w-]{0,63}){0,5}$/.test(field)) return `"${field}" is not a field name or dotted path`;
  if (!['off', 'flag', 'block'].includes(f.promptInjection)) return 'Unknown prompt injection setting';
  if (!f.mask.length && !f.customPatterns.length && !f.removeFields.length && f.promptInjection === 'off') return 'The filter does nothing: choose something to mask, remove or check';
  return null;
}

/** Several matching filter policies combine: everything any of them masks or removes, and the strictest injection setting. */
export function mergeFilters(filters: ResponseFilter[]): ResponseFilter | null {
  if (!filters.length) return null;
  const rank: Record<InjectionMode, number> = { off: 0, flag: 1, block: 2 };
  const patterns = new Map<string, { name: string; pattern: string }>();
  for (const f of filters) for (const p of f.customPatterns) patterns.set(`${p.name}\u0000${p.pattern}`, p);
  return {
    mask: DETECTOR_ORDER.filter((d) => filters.some((f) => f.mask.includes(d))),
    customPatterns: [...patterns.values()].sort((a, b) => (a.name + a.pattern).localeCompare(b.name + b.pattern)),
    removeFields: [...new Set(filters.flatMap((f) => f.removeFields.map((x) => x.toLowerCase())))].sort(),
    promptInjection: filters.reduce<InjectionMode>((m, f) => (rank[f.promptInjection] > rank[m] ? f.promptInjection : m), 'off'),
  };
}

/** A short, stable fingerprint of a filter (not a security hash: the webhook's response is signed). */
export function filterFingerprint(f: ResponseFilter): string {
  const text = JSON.stringify([f.mask, f.customPatterns.map((p) => [p.name, p.pattern]), f.removeFields, f.promptInjection]);
  let h1 = 0xdeadbeef;
  let h2 = 0x41c6ce57;
  for (let i = 0; i < text.length; i++) {
    const c = text.charCodeAt(i);
    h1 = Math.imul(h1 ^ c, 2654435761);
    h2 = Math.imul(h2 ^ c, 1597334677);
  }
  h1 = Math.imul(h1 ^ (h1 >>> 16), 2246822507) ^ Math.imul(h2 ^ (h2 >>> 13), 3266489909);
  h2 = Math.imul(h2 ^ (h2 >>> 16), 2246822507) ^ Math.imul(h1 ^ (h1 >>> 13), 3266489909);
  return `rf1-${(h2 >>> 0).toString(16).padStart(8, '0')}${(h1 >>> 0).toString(16).padStart(8, '0')}`;
}

// ---------------------------------------------------------------- applying

class TooLarge extends Error {}

/**
 * Applies a filter to a result. Returns the filtered result (null when withheld) and a
 * report without any of the values.
 */
export function applyResponseFilter(value: unknown, filter: ResponseFilter): { value: unknown; report: FilterReport } {
  const report: FilterReport = { masked: {}, removedFields: 0, injection: { detected: false, signals: [] }, withheld: false, withheldReason: null };
  const custom = filter.customPatterns.flatMap((p) => {
    try {
      return [{ name: p.name, re: new RegExp(p.pattern, 'g') }];
    } catch {
      return [];
    }
  });
  const remove = filter.removeFields.map((f) => f.toLowerCase().split('.'));
  const detectors = DETECTOR_ORDER.filter((d) => filter.mask.includes(d));
  let nodes = 0;

  const count = (kind: string, n: number) => {
    if (n) report.masked[kind] = (report.masked[kind] ?? 0) + n;
  };

  const maskText = (text: string): string => {
    let out = text;
    for (const d of detectors) {
      const det = DETECTORS[d];
      for (const re of det.patterns) {
        re.lastIndex = 0;
        out = out.replace(re, (m) => {
          if (det.check && !det.check(m)) return m;
          count(d, 1);
          return `[REDACTED:${d}]`;
        });
      }
    }
    for (const c of custom) {
      c.re.lastIndex = 0;
      out = out.replace(c.re, (m) => {
        if (!m) return m;
        count(c.name, 1);
        return `[REDACTED:${c.name}]`;
      });
    }
    return out;
  };

  const inspect = (text: string, path: string) => {
    if (filter.promptInjection === 'off') return;
    for (const p of INJECTION_PATTERNS) {
      if (p.pattern.test(text)) {
        report.injection.detected = true;
        if (report.injection.signals.length < FILTER_LIMITS.MAX_SIGNALS) report.injection.signals.push({ path: path || '(result)', signal: p.signal });
      }
    }
  };

  const removed = (keys: string[]) => remove.some((spec) => spec.length <= keys.length && spec.every((s, i) => s === keys[keys.length - spec.length + i]));

  const walk = (v: unknown, keys: string[], path: string, depth: number): unknown => {
    if (++nodes > FILTER_LIMITS.MAX_NODES || depth > FILTER_LIMITS.MAX_DEPTH) throw new TooLarge();
    if (typeof v === 'string') {
      if (v.length > FILTER_LIMITS.MAX_STRING) throw new TooLarge();
      inspect(v, path);
      return detectors.length || custom.length ? maskText(v) : v;
    }
    if (Array.isArray(v)) return v.map((x, i) => walk(x, keys, `${path}[${i}]`, depth + 1));
    if (v && typeof v === 'object') {
      const out: Record<string, unknown> = {};
      for (const [k, x] of Object.entries(v as Record<string, unknown>)) {
        const next = [...keys, k.toLowerCase()];
        if (remove.length && removed(next)) {
          report.removedFields++;
          continue;
        }
        out[k] = walk(x, next, path ? `${path}.${k}` : k, depth + 1);
      }
      return out;
    }
    return v;
  };

  let filtered: unknown;
  try {
    filtered = walk(value, [], '', 0);
  } catch (e) {
    if (!(e instanceof TooLarge)) throw e;
    // Fail closed: a result too large or too deep to inspect is not passed on.
    return { value: null, report: { ...report, withheld: true, withheldReason: 'The result was too large or too deeply nested to filter, so it was withheld.' } };
  }
  if (report.injection.detected && filter.promptInjection === 'block') {
    return { value: null, report: { ...report, withheld: true, withheldReason: `The result looks like it contains instructions for the model (${[...new Set(report.injection.signals.map((s) => s.signal))].join('; ')}), so it was withheld.` } };
  }
  return { value: filtered, report };
}

/** "3 emails, 1 secret masked; 2 fields removed; possible prompt injection", for logs and summaries. */
export function describeFilterReport(r: FilterReport): string {
  const parts: string[] = [];
  const masked = Object.entries(r.masked).map(([k, n]) => `${n} ${k.replace('_', ' ')}`);
  if (masked.length) parts.push(`masked ${masked.join(', ')}`);
  if (r.removedFields) parts.push(`removed ${r.removedFields} field${r.removedFields > 1 ? 's' : ''}`);
  if (r.injection.detected) parts.push(`possible prompt injection (${[...new Set(r.injection.signals.map((s) => s.signal))].join('; ')})`);
  if (r.withheld) parts.push('result withheld');
  return parts.length ? parts.join('; ') : 'nothing to filter';
}
