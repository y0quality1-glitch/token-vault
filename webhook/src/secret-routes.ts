import type { Request, Response, NextFunction, Router } from 'express';
import { CUSTOM_SECRET_TYPE_PREFIX, SecretTypeError, generatableSecretFields, generateSecretFieldValue, summarizeSecretPayload, unknownSecretFields, validateCustomSecretType, validateSecretPayload, type SecretPayload, type SecretTypeDefinition } from '@token-vault/shared';
import { keyIdOfRef, KeyServiceUnavailableError } from './store/credential-store';
import { SecretValueUnreadableError, destroyValues, getValue, readValue, storeValue } from './store/secret-store';
import { secretTypeSync, secretTypes } from './providers/secret-types';
import { ProviderError, engines, type Connection } from './providers/secret-engines';

/**
 * Secret values (Secret Management, spec 4.9.4–4.9.8). Every route requires the control
 * plane's signature. Values are validated against a secret type this webhook verified itself
 * (never one the control plane sends), encrypted before they are stored, and decrypted only
 * to answer one read. Nothing here logs a value, a field of a payload or a validation input.
 *
 *   POST /internal/v1/secrets/store     {org_id, secret_id, version, type_key, payload} → 201 stored version
 *   POST /internal/v1/secrets/read      {org_id, secret_id, value_ref, fields?} → the payload (only `fields`, if given)
 *   POST /internal/v1/secrets/copy      {org_id, secret_id, from_ref, version} → 201 a new version with the same value (rollback)
 *   POST /internal/v1/secrets/generate  {org_id, secret_id, from_ref, version} → 201 a new version whose generatable
 *                                       fields are fresh random values (rotation; the value never leaves this webhook)
 *   POST /internal/v1/secrets/destroy   {org_id, secret_id, value_refs} → the refs destroyed
 *   POST /internal/v1/secrets/provider-rotate  {org_id, secret_id, from_ref, version, connection?} → 201 the credential
 *                                       changed at its provider, checked, and stored as a new version
 *   POST /internal/v1/secrets/provider-check   {org_id, secret_id, value_ref, connection?} → {ok, detail} the login works
 *   POST /internal/v1/secrets/lease     {org_id, secret_id, value_ref, lease_id, expires_at} → 201 short-lived credentials
 *   POST /internal/v1/secrets/lease/renew   {..., lease_id, username, expires_at} → {expires_at}
 *   POST /internal/v1/secrets/lease/revoke  {..., lease_id, username} → {revoked}
 *
 * Organization-defined types (keys starting "custom-") are not in the signed catalog: the control
 * plane sends their definition as `type_definition`, checked against the same schema (every field
 * is still encrypted; custom types cannot be dynamic). Provider routes connect only to hosts in
 * PROVIDER_ALLOWED_HOSTS.
 */
type SignedRequest = Request & { json?: Record<string, any> };
type Helpers = {
  requireSignature: (req: Request, res: Response, next: NextFunction) => unknown;
  signedJson: (req: Request, res: Response, status: number, body: unknown) => void;
};

const ID = /^[A-Za-z0-9_-]{1,64}$/;
const id = (v: unknown) => (typeof v === 'string' && ID.test(v) ? v : '');
/** PostgreSQL error code (drizzle wraps the driver error in `cause`). */
const pgCode = (e: unknown) => (e as { code?: string })?.code ?? (e as { cause?: { code?: string } })?.cause?.code;
const posInt = (v: unknown) => (Number.isInteger(v) && (v as number) > 0 && (v as number) < 1_000_000 ? (v as number) : 0);

async function typeOf(key: unknown, definition?: unknown): Promise<SecretTypeDefinition | undefined> {
  if (typeof key !== 'string') return undefined;
  if (key.startsWith(CUSTOM_SECRET_TYPE_PREFIX)) {
    try {
      const def = validateCustomSecretType(definition);
      return def.key === key ? def : undefined;
    } catch (e) {
      if (e instanceof SecretTypeError) return undefined;
      throw e;
    }
  }
  if (!secretTypes.get(key) && secretTypeSync) await secretTypeSync.refresh();
  return secretTypes.get(key);
}

export function secretRoutes(r: Router, { requireSignature, signedJson }: Helpers) {
  const fail = (req: Request, res: Response, status: number, code: string, message: string, details?: unknown) => signedJson(req, res, status, { error: { code, message, ...(details ? { details } : {}) } });

  /** Key-service and decryption failures, without revealing anything about the value. */
  function valueFailure(req: Request, res: Response, e: unknown, context: string) {
    if (e instanceof KeyServiceUnavailableError) {
      console.warn(`[vault] ${context}: key service unavailable (${e.message})`);
      return fail(req, res, 503, 'KEY_SERVICE_UNAVAILABLE', 'The key management service is unavailable; retry shortly');
    }
    if (e instanceof SecretValueUnreadableError) {
      console.warn(`[vault] ${context}: value ${e.valueRef} cannot be decrypted with the configured key`);
      return fail(req, res, 500, 'SECRET_UNREADABLE', 'The stored value cannot be decrypted by this webhook; restore the key that encrypted it or store a new version');
    }
    console.warn(`[vault] ${context} failed: ${(e as Error).name}`);
    return fail(req, res, 500, 'SECRET_STORE_FAILED', 'The value could not be processed');
  }

  const storedView = (type: SecretTypeDefinition, payload: SecretPayload, v: Awaited<ReturnType<typeof storeValue>>) => ({
    value_ref: v.valueRef,
    version: v.version,
    fingerprint: v.fingerprint,
    summary: summarizeSecretPayload(type, payload),
    type_version: type.version,
    encryption_key_id: keyIdOfRef(v.encryptionKeyRef),
    created_at: v.createdAt,
  });

  r.post('/internal/v1/secrets/store', requireSignature, async (req: SignedRequest, res) => {
    const b = req.json ?? {};
    const orgId = id(b.org_id);
    const secretId = id(b.secret_id);
    const version = posInt(b.version);
    if (!orgId || !secretId || !version) return fail(req, res, 400, 'INVALID_SECRET_REQUEST', 'org_id, secret_id and version are required');
    const type = await typeOf(b.type_key, b.type_definition);
    if (!type) return fail(req, res, 400, 'SECRET_TYPE_UNKNOWN', 'This webhook does not know that secret type (it is not in the verified catalog, or the custom definition is invalid)');
    const { value, issues } = validateSecretPayload(type, b.payload);
    if (Object.keys(issues).length) return fail(req, res, 400, 'SECRET_INVALID', 'The value does not match its secret type', { fields: issues });
    try {
      const v = await storeValue(orgId, secretId, version, type.key, value);
      console.log(`[vault] stored secret value ${v.valueRef} secret=${secretId} v${version} type=${type.key} (encrypted, AES-256-GCM)`);
      signedJson(req, res, 201, storedView(type, value, v));
    } catch (e) {
      if (pgCode(e) === '23505') return fail(req, res, 409, 'SECRET_VERSION_EXISTS', `Version ${version} of this secret is already stored`);
      valueFailure(req, res, e, `store secret=${secretId}`);
    }
  });

  r.post('/internal/v1/secrets/read', requireSignature, async (req: SignedRequest, res) => {
    const b = req.json ?? {};
    const row = await getValue(id(b.org_id), id(b.secret_id), id(b.value_ref));
    if (!row) return fail(req, res, 404, 'SECRET_VALUE_NOT_FOUND', 'No such value for this secret');
    const fields: string[] | null = Array.isArray(b.fields) ? b.fields.filter((f: unknown): f is string => typeof f === 'string').slice(0, 40) : null;
    const type = secretTypes.get(row.typeKey);
    if (fields && type) {
      const unknown = unknownSecretFields(type, fields);
      if (unknown.length) return fail(req, res, 400, 'SECRET_FIELD_UNKNOWN', `Not a field of ${type.name}: ${unknown.join(', ')}`);
    }
    try {
      const payload = await readValue(row);
      const out = fields ? Object.fromEntries(Object.entries(payload).filter(([k]) => fields.includes(k))) : payload;
      console.log(`[vault] read secret value ${row.valueRef} secret=${row.secretId} v${row.version}${fields ? ` fields=${fields.length}` : ''}`);
      signedJson(req, res, 200, { value_ref: row.valueRef, version: row.version, type_key: row.typeKey, payload: out });
    } catch (e) {
      valueFailure(req, res, e, `read ${row.valueRef}`);
    }
  });

  r.post('/internal/v1/secrets/copy', requireSignature, async (req: SignedRequest, res) => {
    const b = req.json ?? {};
    const version = posInt(b.version);
    const row = await getValue(id(b.org_id), id(b.secret_id), id(b.from_ref));
    if (!row || !version) return fail(req, res, 404, 'SECRET_VALUE_NOT_FOUND', 'No such value for this secret');
    const type = await typeOf(row.typeKey, b.type_definition);
    if (!type) return fail(req, res, 400, 'SECRET_TYPE_UNKNOWN', 'The secret type of this value is no longer in the verified catalog');
    try {
      // A rollback creates a new version from the old value; it must still satisfy the current type.
      const { value, issues } = validateSecretPayload(type, await readValue(row));
      if (Object.keys(issues).length) return fail(req, res, 409, 'SECRET_INVALID', `That version no longer matches the current ${type.name} type`, { fields: issues });
      const v = await storeValue(row.orgId, row.secretId, version, type.key, value);
      console.log(`[vault] copied secret value ${row.valueRef} -> ${v.valueRef} secret=${row.secretId} v${version}`);
      signedJson(req, res, 201, { ...storedView(type, value, v), copied_from: row.version });
    } catch (e) {
      if (pgCode(e) === '23505') return fail(req, res, 409, 'SECRET_VERSION_EXISTS', `Version ${version} of this secret is already stored`);
      valueFailure(req, res, e, `copy ${row.valueRef}`);
    }
  });

  r.post('/internal/v1/secrets/generate', requireSignature, async (req: SignedRequest, res) => {
    const b = req.json ?? {};
    const version = posInt(b.version);
    const row = await getValue(id(b.org_id), id(b.secret_id), id(b.from_ref));
    if (!row || !version) return fail(req, res, 404, 'SECRET_VALUE_NOT_FOUND', 'No such value for this secret');
    const type = await typeOf(row.typeKey, b.type_definition);
    if (!type) return fail(req, res, 400, 'SECRET_TYPE_UNKNOWN', 'The secret type of this value is no longer in the verified catalog');
    const generated = generatableSecretFields(type);
    if (!generated.length) return fail(req, res, 409, 'SECRET_NOT_GENERATABLE', `${type.name} values cannot be generated; store the new value instead`);
    try {
      // Fields that are not generated (an application ID, a key ID) carry over from the current version.
      const next: Record<string, unknown> = { ...(await readValue(row)) };
      for (const f of generated) next[f] = generateSecretFieldValue(type.fields[f]!.generate!);
      const { value, issues } = validateSecretPayload(type, next);
      if (Object.keys(issues).length) return fail(req, res, 409, 'SECRET_INVALID', `The current value no longer matches the ${type.name} type; store a new value instead`, { fields: issues });
      const v = await storeValue(row.orgId, row.secretId, version, type.key, value);
      console.log(`[vault] generated secret value ${v.valueRef} secret=${row.secretId} v${version} fields=${generated.length} (from ${row.valueRef})`);
      signedJson(req, res, 201, { ...storedView(type, value, v), generated_fields: generated });
    } catch (e) {
      if (pgCode(e) === '23505') return fail(req, res, 409, 'SECRET_VERSION_EXISTS', `Version ${version} of this secret is already stored`);
      valueFailure(req, res, e, `generate from ${row.valueRef}`);
    }
  });

  // ── providers (spec 4.9.3 J, 4.9.11, 4.9.16) ──────────────────────

  function providerFailure(req: Request, res: Response, e: unknown, context: string) {
    if (e instanceof ProviderError) {
      console.warn(`[vault] ${context}: ${e.code}`);
      return fail(req, res, e.retryable ? 503 : 409, e.code, e.message);
    }
    return valueFailure(req, res, e, context);
  }

  /** Non-secret connection details the control plane keeps as metadata (static types); the allow-list still applies. */
  const connectionOf = (c: unknown): Partial<Connection> | undefined => {
    if (!c || typeof c !== 'object') return undefined;
    const x = c as Record<string, unknown>;
    return { ...(typeof x.host === 'string' ? { host: x.host } : {}), ...(Number.isInteger(x.port) ? { port: x.port as number } : {}), ...(typeof x.database === 'string' ? { database: x.database } : {}), ...(x.ssl === true ? { ssl: true } : {}) };
  };

  async function valueFor(req: Request, res: Response, ref: unknown) {
    const b = (req as SignedRequest).json ?? {};
    const row = await getValue(id(b.org_id), id(b.secret_id), id(ref));
    if (!row) {
      fail(req, res, 404, 'SECRET_VALUE_NOT_FOUND', 'No such value for this secret');
      return null;
    }
    return row;
  }

  r.post('/internal/v1/secrets/provider-rotate', requireSignature, async (req: SignedRequest, res) => {
    const b = req.json ?? {};
    const version = posInt(b.version);
    const row = await valueFor(req, res, b.from_ref);
    if (!row) return;
    if (!version) return fail(req, res, 400, 'INVALID_SECRET_REQUEST', 'version is required');
    const type = await typeOf(row.typeKey);
    if (!type) return fail(req, res, 400, 'SECRET_TYPE_UNKNOWN', 'The secret type of this value is no longer in the verified catalog');
    let undo: (() => Promise<void>) | null = null;
    try {
      const rotated = await engines.rotate(type.key, await readValue(row), connectionOf(b.connection));
      undo = rotated.undo;
      const { value, issues } = validateSecretPayload(type, rotated.next);
      if (Object.keys(issues).length) throw new ProviderError('SECRET_INVALID', 'The rotated value does not match its type');
      const v = await storeValue(row.orgId, row.secretId, version, type.key, value);
      console.log(`[vault] rotated secret ${row.secretId} at its provider: v${version} stored as ${v.valueRef} (new login checked)`);
      signedJson(req, res, 201, { ...storedView(type, value, v), rotated_at_provider: true });
    } catch (e) {
      // Changed at the provider but not stored: change it back, or the stored version stops working.
      if (undo) await undo().catch(() => console.warn(`[vault] provider rotation of ${row.secretId}: could not restore the previous password`));
      if (pgCode(e) === '23505') return fail(req, res, 409, 'SECRET_VERSION_EXISTS', `Version ${version} of this secret is already stored`);
      providerFailure(req, res, e, `provider rotation of ${row.secretId}`);
    }
  });

  r.post('/internal/v1/secrets/provider-check', requireSignature, async (req: SignedRequest, res) => {
    const b = req.json ?? {};
    const row = await valueFor(req, res, b.value_ref);
    if (!row) return;
    const started = Date.now();
    try {
      const detail = await engines.check(row.typeKey, await readValue(row), connectionOf(b.connection));
      signedJson(req, res, 200, { ok: true, detail, latency_ms: Date.now() - started });
    } catch (e) {
      if (e instanceof ProviderError) return signedJson(req, res, 200, { ok: false, code: e.code, detail: e.message, retryable: e.retryable, latency_ms: Date.now() - started });
      valueFailure(req, res, e, `provider check of ${row.secretId}`);
    }
  });

  const leaseId = (v: unknown) => (typeof v === 'string' && /^lse_[A-Za-z0-9]{8,40}$/.test(v) ? v : '');
  const futureDate = (v: unknown) => {
    const t = typeof v === 'string' ? Date.parse(v) : NaN;
    return Number.isFinite(t) && t > Date.now() && t < Date.now() + 31 * 86_400_000 ? new Date(t) : null;
  };

  r.post('/internal/v1/secrets/lease', requireSignature, async (req: SignedRequest, res) => {
    const b = req.json ?? {};
    const row = await valueFor(req, res, b.value_ref);
    if (!row) return;
    const lease = leaseId(b.lease_id);
    const until = futureDate(b.expires_at);
    if (!lease || !until) return fail(req, res, 400, 'INVALID_LEASE_REQUEST', 'lease_id and a future expires_at are required');
    try {
      const out = await engines.lease(row.typeKey, await readValue(row), lease, until);
      console.log(`[vault] issued lease ${lease} (${out.username}) from secret ${row.secretId}, expires ${out.expiresAt}`);
      signedJson(req, res, 201, { username: out.username, credentials: out.credentials, expires_at: out.expiresAt, renewable: out.renewable });
    } catch (e) {
      providerFailure(req, res, e, `lease ${lease} from ${row.secretId}`);
    }
  });

  r.post('/internal/v1/secrets/lease/renew', requireSignature, async (req: SignedRequest, res) => {
    const b = req.json ?? {};
    const row = await valueFor(req, res, b.value_ref);
    if (!row) return;
    const until = futureDate(b.expires_at);
    if (!leaseId(b.lease_id) || typeof b.username !== 'string' || !until) return fail(req, res, 400, 'INVALID_LEASE_REQUEST', 'lease_id, username and a future expires_at are required');
    try {
      await engines.renew(row.typeKey, await readValue(row), b.username, until);
      console.log(`[vault] renewed lease ${b.lease_id} until ${until.toISOString()}`);
      signedJson(req, res, 200, { expires_at: until.toISOString() });
    } catch (e) {
      providerFailure(req, res, e, `renew lease ${b.lease_id}`);
    }
  });

  r.post('/internal/v1/secrets/lease/revoke', requireSignature, async (req: SignedRequest, res) => {
    const b = req.json ?? {};
    const row = await valueFor(req, res, b.value_ref);
    if (!row) return;
    if (!leaseId(b.lease_id) || typeof b.username !== 'string') return fail(req, res, 400, 'INVALID_LEASE_REQUEST', 'lease_id and username are required');
    try {
      const revoked = await engines.revoke(row.typeKey, await readValue(row), b.username);
      console.log(`[vault] ${revoked ? 'revoked' : 'released (expires on its own)'} lease ${b.lease_id}`);
      signedJson(req, res, 200, { revoked });
    } catch (e) {
      providerFailure(req, res, e, `revoke lease ${b.lease_id}`);
    }
  });

  r.post('/internal/v1/secrets/destroy', requireSignature, async (req: SignedRequest, res) => {
    const b = req.json ?? {};
    const orgId = id(b.org_id);
    const secretId = id(b.secret_id);
    const refs: string[] = Array.isArray(b.value_refs) ? b.value_refs.map(id).filter(Boolean).slice(0, 1000) : [];
    if (!orgId || !secretId) return fail(req, res, 400, 'INVALID_SECRET_REQUEST', 'org_id and secret_id are required');
    const destroyed = await destroyValues(orgId, secretId, refs);
    console.log(`[vault] destroyed ${destroyed.length} secret value(s) secret=${secretId}`);
    signedJson(req, res, 200, { destroyed });
  });
}
