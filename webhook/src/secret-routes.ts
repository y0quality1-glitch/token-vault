import type { Request, Response, NextFunction, Router } from 'express';
import { summarizeSecretPayload, unknownSecretFields, validateSecretPayload, type SecretPayload, type SecretTypeDefinition } from '@token-vault/shared';
import { keyIdOfRef, KeyServiceUnavailableError } from './store/credential-store';
import { SecretValueUnreadableError, destroyValues, getValue, readValue, storeValue } from './store/secret-store';
import { secretTypeSync, secretTypes } from './providers/secret-types';

/**
 * Secret values (Secret Management, spec 4.9.4–4.9.8). Every route requires the control
 * plane's signature. Values are validated against a secret type this webhook verified itself
 * (never one the control plane sends), encrypted before they are stored, and decrypted only
 * to answer one read. Nothing here logs a value, a field of a payload or a validation input.
 *
 *   POST /internal/v1/secrets/store     {org_id, secret_id, version, type_key, payload} → 201 stored version
 *   POST /internal/v1/secrets/read      {org_id, secret_id, value_ref, fields?} → the payload (only `fields`, if given)
 *   POST /internal/v1/secrets/copy      {org_id, secret_id, from_ref, version} → 201 a new version with the same value (rollback)
 *   POST /internal/v1/secrets/destroy   {org_id, secret_id, value_refs} → the refs destroyed
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

async function typeOf(key: unknown): Promise<SecretTypeDefinition | undefined> {
  if (typeof key !== 'string') return undefined;
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
    const type = await typeOf(b.type_key);
    if (!type) return fail(req, res, 400, 'SECRET_TYPE_UNKNOWN', 'This webhook does not know that secret type (it is not in the verified catalog)');
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
    const type = await typeOf(row.typeKey);
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
