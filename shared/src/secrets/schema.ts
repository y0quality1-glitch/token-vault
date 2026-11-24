import { z } from 'zod';

/**
 * Secret types (spec 4.9.3): the classification model as data. A type decides a secret's
 * structure (its fields, which are sensitive, how each is validated), the metadata kept with
 * it in the control plane, and the lifecycle operations it supports. Types are published by
 * the provider CMS, signed, and verified by the control plane and the customer webhook.
 *
 * Every field of a payload is encrypted by the webhook, whatever its sensitivity. `sensitive`
 * decides whether a field may ever be shown in a summary: sensitive fields are masked
 * everywhere and only returned by an authorized retrieval. Metadata is descriptive and never
 * sensitive (it is stored in the control plane in clear).
 */

export const SECRET_CATEGORIES = ['api', 'database', 'auth', 'cloud', 'crypto', 'certificate', 'infrastructure', 'application', 'webhook', 'dynamic', 'custom'] as const;
export type SecretCategory = (typeof SECRET_CATEGORIES)[number];

export const SECRET_CATEGORY_LABELS: Record<SecretCategory, string> = {
  api: 'API secrets',
  database: 'Database secrets',
  auth: 'Authentication and OAuth secrets',
  cloud: 'Cloud provider secrets',
  crypto: 'Cryptographic secrets',
  certificate: 'Certificates and PKI',
  infrastructure: 'Infrastructure and SSH secrets',
  application: 'Application secrets',
  webhook: 'Webhook secrets',
  dynamic: 'Dynamic secrets',
  custom: 'Custom secrets',
};

export const SECRET_FIELD_KINDS = ['text', 'multiline', 'number', 'integer', 'boolean', 'url', 'email', 'hostname', 'port', 'pem', 'json', 'enum', 'datetime', 'keyvalue'] as const;
export type SecretFieldKind = (typeof SECRET_FIELD_KINDS)[number];

/** Lifecycle operations a type supports (spec 4.9.8, 4.9.11, 4.9.12, 4.9.3 J). */
export const SECRET_LIFECYCLE_OPERATIONS = ['versioning', 'rotation', 'expiration', 'dynamic'] as const;

/** Type keys share the CMS key space with application keys. */
export const SECRET_TYPE_KEY = /^[a-z][a-z0-9-]{1,30}$/;
const FIELD_NAME = /^[a-z][a-zA-Z0-9_]{0,39}$/;

/** Upper bound for any single value (a kubeconfig or a certificate chain fits comfortably). */
export const MAX_SECRET_FIELD_LENGTH = 65_536;
/** Upper bound for a whole payload, serialized. */
export const MAX_SECRET_PAYLOAD_BYTES = 262_144;

const baseField = {
  label: z.string().min(1).max(80),
  description: z.string().max(300).default(''),
  kind: z.enum(SECRET_FIELD_KINDS).default('text'),
  required: z.boolean().default(false),
  /** Anchored regular expression (text-like kinds). */
  pattern: z.string().min(2).max(500).optional(),
  minLength: z.number().int().min(0).max(MAX_SECRET_FIELD_LENGTH).optional(),
  maxLength: z.number().int().positive().max(MAX_SECRET_FIELD_LENGTH).optional(),
  min: z.number().optional(),
  max: z.number().optional(),
  /** Allowed values (kind enum). */
  values: z.array(z.string().min(1).max(100)).min(1).max(50).optional(),
  placeholder: z.string().max(200).optional(),
  /**
   * Display position (ascending; ties by name). Explicit because definitions are stored as
   * JSON objects whose key order is not preserved (PostgreSQL jsonb, canonical JSON).
   */
  order: z.number().int().min(0).max(1000).default(0),
};

/** Encodings a generated value can have (see generateSecretFieldValue). */
export const SECRET_GENERATE_ENCODINGS = ['hex', 'base64', 'base64url', 'alphanumeric'] as const;
export type SecretGenerateEncoding = (typeof SECRET_GENERATE_ENCODINGS)[number];

/**
 * A value the customer webhook can create itself (random bytes in an encoding), so a secret of
 * this type can rotate without anyone typing the new value ("generated" rotation, spec 4.9.11).
 * Only for values the organization issues itself: a provider-issued key cannot be invented.
 */
const generateSpec = z.object({ encoding: z.enum(SECRET_GENERATE_ENCODINGS), bytes: z.number().int().min(16).max(256) }).strict();
export type SecretGenerateSpec = z.infer<typeof generateSpec>;

const payloadField = z.object({ ...baseField, sensitive: z.boolean().default(true), generate: generateSpec.optional() }).strict();
const metadataField = z.object(baseField).strict();

export const secretTypeDefinitionSchema = z
  .object({
    key: z.string().regex(SECRET_TYPE_KEY, 'lower-case letters, digits and dashes; starts with a letter (2-31 characters)'),
    version: z.number().int().positive(),
    name: z.string().min(1).max(60),
    description: z.string().max(500).default(''),
    category: z.enum(SECRET_CATEGORIES),
    /** Payload fields (shown in `order`; see orderedFields). */
    fields: z.record(z.string().regex(FIELD_NAME), payloadField).refine((f) => Object.keys(f).length > 0 && Object.keys(f).length <= 40, 'between 1 and 40 fields'),
    /** Descriptive attributes kept with the secret's metadata (never sensitive). */
    metadata: z.record(z.string().regex(FIELD_NAME), metadataField).default({}),
    /**
     * Payload fields that, together, identify the credential (e.g. username + host): shown
     * in summaries when not sensitive, and used for duplicate detection.
     */
    identifiedBy: z.array(z.string().regex(FIELD_NAME)).max(5).default([]),
    lifecycle: z
      .object({
        versioning: z.boolean().default(true),
        rotation: z.boolean().default(true),
        expiration: z.boolean().default(true),
        dynamic: z.boolean().default(false),
      })
      .strict()
      .default({}),
    defaults: z
      .object({
        rotationIntervalDays: z.number().int().min(1).max(3650).optional(),
        expiresInDays: z.number().int().min(1).max(3650).optional(),
        /** Days before expiry when a secret becomes EXPIRING. */
        expiryWarningDays: z.number().int().min(1).max(365).default(14),
      })
      .strict()
      .default({}),
    /** Free-form tags shown in the type picker (e.g. "postgres", "aws"). */
    tags: z.array(z.string().min(1).max(30)).max(10).default([]),
  })
  .strict();

export type SecretTypeDefinition = z.infer<typeof secretTypeDefinitionSchema>;
export type SecretTypeDefinitionInput = z.input<typeof secretTypeDefinitionSchema>;
export type SecretFieldDefinition = SecretTypeDefinition['fields'][string];
export type SecretMetadataField = SecretTypeDefinition['metadata'][string];

export class SecretTypeError extends Error {
  constructor(public issues: string[]) {
    super(`Invalid secret type: ${issues.join('; ')}`);
  }
}

const TEXT_KINDS = new Set<SecretFieldKind>(['text', 'multiline', 'url', 'email', 'hostname', 'pem', 'json', 'datetime']);

function checkFieldSpec(where: string, f: z.infer<typeof metadataField>, issues: string[]) {
  if (f.pattern !== undefined) {
    if (!TEXT_KINDS.has(f.kind)) issues.push(`${where}.pattern: only text-like fields can have a pattern`);
    if (!f.pattern.startsWith('^') || !f.pattern.endsWith('$')) issues.push(`${where}.pattern: must be anchored with ^ and $`);
    try {
      new RegExp(f.pattern);
    } catch {
      issues.push(`${where}.pattern: not a valid regular expression`);
    }
  }
  if (f.kind === 'enum' && !f.values) issues.push(`${where}.values: an enum field needs its values`);
  if (f.kind !== 'enum' && f.values) issues.push(`${where}.values: only enum fields have values`);
  if (f.minLength !== undefined && f.maxLength !== undefined && f.minLength > f.maxLength) issues.push(`${where}: minLength is greater than maxLength`);
  if (f.min !== undefined && f.max !== undefined && f.min > f.max) issues.push(`${where}: min is greater than max`);
  if ((f.min !== undefined || f.max !== undefined) && !['number', 'integer', 'port'].includes(f.kind)) issues.push(`${where}: only numeric fields have min and max`);
}

/** A generated value must be a sensitive text field and satisfy the field's own rules. */
function checkGenerateSpec(where: string, f: SecretFieldDefinition, issues: string[]) {
  if (f.kind !== 'text') return void issues.push(`${where}: only text fields can be generated`);
  if (!f.sensitive) return void issues.push(`${where}: only sensitive fields can be generated`);
  const issue = checkValue(f, generateSecretFieldValue(f.generate!)).issue;
  if (issue) issues.push(`${where}: a generated value would not be valid (${issue})`);
}

/** Parses and semantically checks a secret type. Throws SecretTypeError with every problem found. */
export function validateSecretTypeDefinition(raw: unknown): SecretTypeDefinition {
  const parsed = secretTypeDefinitionSchema.safeParse(raw);
  if (!parsed.success) throw new SecretTypeError(parsed.error.issues.map((i) => `${i.path.join('.') || 'definition'}: ${i.message}`));
  const def = parsed.data;
  const issues: string[] = [];
  for (const [name, f] of Object.entries(def.fields)) {
    checkFieldSpec(`fields.${name}`, f, issues);
    if (f.generate) checkGenerateSpec(`fields.${name}.generate`, f, issues);
  }
  for (const [name, f] of Object.entries(def.metadata)) {
    checkFieldSpec(`metadata.${name}`, f, issues);
    if (def.fields[name]) issues.push(`metadata.${name}: also a payload field (use one or the other)`);
  }
  // A secret type that holds nothing secret would put credentials in clear text wherever summaries go.
  if (!Object.values(def.fields).some((f) => f.sensitive)) issues.push('fields: at least one field must be sensitive');
  for (const name of def.identifiedBy) if (!def.fields[name]) issues.push(`identifiedBy: ${name} is not a payload field`);
  if (def.lifecycle.dynamic && def.category !== 'dynamic') issues.push('lifecycle.dynamic: only types in the dynamic category generate credentials');
  if (def.category === 'dynamic' && !def.lifecycle.dynamic) issues.push('category dynamic: set lifecycle.dynamic');
  if (def.defaults.rotationIntervalDays && !def.lifecycle.rotation) issues.push('defaults.rotationIntervalDays: the type does not support rotation');
  if (def.defaults.expiresInDays && !def.lifecycle.expiration) issues.push('defaults.expiresInDays: the type does not support expiration');
  if (issues.length) throw new SecretTypeError(issues);
  return def;
}

// ── payloads ──────────────────────────────────────────────────────

export type SecretPayload = Record<string, string | number | boolean | Record<string, string>>;

const HOSTNAME = /^(?=.{1,253}$)([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$/;
const EMAIL = /^[^\s@]{1,64}@[^\s@]{1,255}$/;
const PEM = /^-----BEGIN [A-Z0-9 ]{1,60}-----\r?\n[\s\S]+?\r?\n-----END [A-Z0-9 ]{1,60}-----\s*$/;
const ENV_NAME = /^[A-Za-z_][A-Za-z0-9_.-]{0,127}$/;

/** Checks one value against its field. Returns the normalized value or a problem. */
function checkValue(f: z.infer<typeof metadataField>, v: unknown): { value?: SecretPayload[string]; issue?: string } {
  switch (f.kind) {
    case 'boolean':
      return typeof v === 'boolean' ? { value: v } : { issue: 'must be true or false' };
    case 'number':
    case 'integer':
    case 'port': {
      const n = typeof v === 'string' && v.trim() !== '' ? Number(v) : v;
      if (typeof n !== 'number' || !Number.isFinite(n)) return { issue: 'must be a number' };
      if (f.kind !== 'number' && !Number.isInteger(n)) return { issue: 'must be a whole number' };
      if (f.kind === 'port' && (n < 1 || n > 65535)) return { issue: 'must be a port between 1 and 65535' };
      if (f.min !== undefined && n < f.min) return { issue: `must be at least ${f.min}` };
      if (f.max !== undefined && n > f.max) return { issue: `must be at most ${f.max}` };
      return { value: n };
    }
    case 'keyvalue': {
      if (!v || typeof v !== 'object' || Array.isArray(v)) return { issue: 'must be an object of names to values' };
      const entries = Object.entries(v as Record<string, unknown>);
      if (entries.length > 500) return { issue: 'at most 500 entries' };
      const out: Record<string, string> = {};
      for (const [k, x] of entries) {
        if (!ENV_NAME.test(k)) return { issue: `${k} is not a valid name (letters, digits, _ . -; starts with a letter or _)` };
        if (typeof x !== 'string') return { issue: `${k} must be a string` };
        if (x.length > MAX_SECRET_FIELD_LENGTH) return { issue: `${k} is too long` };
        out[k] = x;
      }
      if (f.required && entries.length === 0) return { issue: 'needs at least one entry' };
      return { value: out };
    }
    default: {
      if (typeof v !== 'string') return { issue: 'must be a string' };
      const s = f.kind === 'multiline' || f.kind === 'pem' ? v : v.trim();
      if (f.required && s === '') return { issue: 'is required' };
      const max = f.maxLength ?? MAX_SECRET_FIELD_LENGTH;
      if (s.length > max) return { issue: `must be at most ${max} characters` };
      if (f.minLength !== undefined && s.length < f.minLength) return { issue: `must be at least ${f.minLength} characters` };
      if (s === '') return { value: s };
      if (f.kind === 'url') {
        try {
          const u = new URL(s);
          if (!['http:', 'https:', 'postgres:', 'postgresql:', 'mysql:', 'mongodb:', 'mongodb+srv:', 'redis:', 'rediss:', 'sqlserver:', 'jdbc:', 'amqp:', 'amqps:'].includes(u.protocol)) return { issue: 'uses an unsupported scheme' };
        } catch {
          return { issue: 'must be a valid URL' };
        }
      }
      if (f.kind === 'email' && !EMAIL.test(s)) return { issue: 'must be an email address' };
      if (f.kind === 'hostname' && !HOSTNAME.test(s) && !/^[0-9a-fA-F:.]+$/.test(s)) return { issue: 'must be a host name or IP address' };
      if (f.kind === 'pem' && !PEM.test(s)) return { issue: 'must be PEM (-----BEGIN …----- … -----END …-----)' };
      if (f.kind === 'json') {
        try {
          JSON.parse(s);
        } catch {
          return { issue: 'must be valid JSON' };
        }
      }
      if (f.kind === 'datetime' && Number.isNaN(Date.parse(s))) return { issue: 'must be a date and time (ISO 8601)' };
      if (f.kind === 'enum' && !f.values!.includes(s)) return { issue: `must be one of ${f.values!.join(', ')}` };
      if (f.pattern && !new RegExp(f.pattern).test(s)) return { issue: 'does not have the expected format' };
      return { value: s };
    }
  }
}

function checkRecord(spec: Record<string, z.infer<typeof metadataField>>, raw: unknown, where: string): { value: SecretPayload; issues: Record<string, string> } {
  const issues: Record<string, string> = {};
  const value: SecretPayload = {};
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return { value, issues: { [where]: 'must be an object' } };
  const input = raw as Record<string, unknown>;
  for (const k of Object.keys(input)) if (!spec[k]) issues[k] = 'is not a field of this secret type';
  for (const [name, f] of Object.entries(spec)) {
    const v = input[name];
    if (v === undefined || v === null || v === '') {
      if (f.required) issues[name] = `${f.label} is required`;
      continue;
    }
    const r = checkValue(f, v);
    if (r.issue) issues[name] = `${f.label} ${r.issue}`;
    else value[name] = r.value!;
  }
  return { value, issues };
}

/**
 * Validates a payload against its type: unknown fields are refused, required fields checked,
 * values normalized (trimmed, numbers parsed). Problems are keyed by field and never contain
 * the value.
 */
export function validateSecretPayload(type: SecretTypeDefinition, raw: unknown): { value: SecretPayload; issues: Record<string, string> } {
  const r = checkRecord(type.fields, raw, 'payload');
  if (!Object.keys(r.issues).length && new TextEncoder().encode(JSON.stringify(r.value)).length > MAX_SECRET_PAYLOAD_BYTES) r.issues.payload = `The secret is larger than ${MAX_SECRET_PAYLOAD_BYTES / 1024} KiB`;
  return r;
}

/** Validates a secret's metadata against its type (descriptive, never sensitive). */
export function validateSecretMetadata(type: SecretTypeDefinition, raw: unknown): { value: SecretPayload; issues: Record<string, string> } {
  return checkRecord(type.metadata, raw ?? {}, 'metadata');
}

/** How a sensitive value is shown: never any of its characters (versions are told apart by fingerprint). */
export const MASKED_SECRET_VALUE = '••••••••';

/**
 * What may be shown about a payload without retrieving it: non-sensitive fields as they are,
 * sensitive fields fully masked, key-value fields by their names only (names are not secret;
 * the values are).
 */
export function summarizeSecretPayload(type: SecretTypeDefinition, payload: SecretPayload): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [name, f] of orderedFields(type.fields)) {
    const v = payload[name];
    if (v === undefined) continue;
    if (f.kind === 'keyvalue' && typeof v === 'object') out[name] = `${Object.keys(v).length} entries: ${Object.keys(v).slice(0, 20).join(', ')}`;
    else if (f.sensitive) out[name] = MASKED_SECRET_VALUE;
    else out[name] = String(v).slice(0, 200);
  }
  return out;
}

/** Fields or metadata entries in display order: by `order`, then by name. */
export function orderedFields<F extends { order: number }>(fields: Record<string, F>): [string, F][] {
  return Object.entries(fields).sort(([a, x], [b, y]) => x.order - y.order || a.localeCompare(b));
}

/** Fields a retrieval may ask for: unknown names are refused rather than silently ignored. */
export function unknownSecretFields(type: SecretTypeDefinition, requested: readonly string[]): string[] {
  return requested.filter((f) => !type.fields[f]);
}

// ── generated values (rotation strategy "generated") ───────────────

const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
const ALNUM = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';

function randomBytes(n: number): Uint8Array {
  const out = new Uint8Array(n);
  globalThis.crypto.getRandomValues(out);
  return out;
}

function base64(bytes: Uint8Array, url: boolean): string {
  let s = '';
  for (let i = 0; i < bytes.length; i += 3) {
    const n = (bytes[i]! << 16) | ((bytes[i + 1] ?? 0) << 8) | (bytes[i + 2] ?? 0);
    s += B64[(n >> 18) & 63]! + B64[(n >> 12) & 63]! + (i + 1 < bytes.length ? B64[(n >> 6) & 63]! : '=') + (i + 2 < bytes.length ? B64[n & 63]! : '=');
  }
  return url ? s.replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_') : s;
}

/**
 * A fresh random value for a field with `generate` (cryptographically secure: Web Crypto, in
 * Node and browsers). `bytes` is the entropy; alphanumeric values are long enough to carry it.
 */
export function generateSecretFieldValue(spec: SecretGenerateSpec): string {
  switch (spec.encoding) {
    case 'hex':
      return Array.from(randomBytes(spec.bytes), (b) => b.toString(16).padStart(2, '0')).join('');
    case 'base64':
      return base64(randomBytes(spec.bytes), false);
    case 'base64url':
      return base64(randomBytes(spec.bytes), true);
    case 'alphanumeric': {
      const length = Math.ceil((spec.bytes * 8) / Math.log2(ALNUM.length));
      let out = '';
      // Rejection sampling: 248 = 4 * 62, so every character is equally likely.
      while (out.length < length) for (const b of randomBytes(length)) if (b < 248 && out.length < length) out += ALNUM[b % 62];
      return out;
    }
  }
}

/** The fields of a type the webhook can generate (empty: the type cannot rotate by itself). */
export function generatableSecretFields(type: SecretTypeDefinition): string[] {
  return orderedFields(type.fields)
    .filter(([, f]) => !!f.generate)
    .map(([name]) => name);
}
