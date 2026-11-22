import { createHmac, randomUUID } from 'node:crypto';
import { and, count, eq, inArray, ne } from 'drizzle-orm';
import { canonicalJson, type SecretPayload } from '@token-vault/shared';
import { config } from '../config';
import { db } from '../db/client';
import { secretValues } from '../db/schema';
import { KeyServiceUnavailableError, fingerprintKey, openRecord, sealSecret } from './credential-store';

/**
 * Secret values (Secret Management, spec 4.9.5), in the customer trust zone. Each version of
 * a secret is one encrypted row; the payload is decrypted in memory only to answer one
 * authorized request and is never logged. Rows are sealed with the same key as credentials
 * (env key or KMS envelope) and re-encrypted with them after a key rotation.
 */
type Row = typeof secretValues.$inferSelect;

export class SecretValueUnreadableError extends Error {
  constructor(public valueRef: string) {
    super(`Secret value ${valueRef} cannot be decrypted with the configured key`);
  }
}

/**
 * Additional authenticated data: binds the ciphertext to its organization, secret and version.
 * A row whose org_id, secret_id or version is changed in the database no longer opens.
 */
const aadOf = (r: Pick<Row, 'valueRef' | 'orgId' | 'secretId' | 'version'>) => `secret:${r.orgId}:${r.secretId}:${r.version}:${r.valueRef}`;

const sealedOf = (r: Row) => ({ credentialRef: aadOf(r), sealed: { iv: r.iv, ciphertext: r.ciphertext, authTag: r.authTag }, encryptionKeyRef: r.encryptionKeyRef, wrappedKey: r.wrappedKey ?? null });

/** Keyed fingerprint of a payload (canonical JSON), domain-separated from credential fingerprints. */
async function payloadFingerprint(payload: SecretPayload): Promise<string> {
  return 'fp_' + createHmac('sha256', await fingerprintKey()).update('secret-value:' + canonicalJson(payload)).digest('hex').slice(0, 16);
}

export interface StoredValue {
  valueRef: string;
  version: number;
  fingerprint: string;
  encryptionKeyRef: string;
  createdAt: string;
}

const stored = (r: Row): StoredValue => ({ valueRef: r.valueRef, version: r.version, fingerprint: r.fingerprint, encryptionKeyRef: r.encryptionKeyRef, createdAt: r.createdAt });

/** Encrypts and stores one version. Throws KeyServiceUnavailableError when the KMS is down (nothing is stored). */
export async function storeValue(orgId: string, secretId: string, version: number, typeKey: string, payload: SecretPayload): Promise<StoredValue> {
  const valueRef = 'sval_' + randomUUID().replace(/-/g, '').slice(0, 20);
  const sealed = await sealSecret(aadOf({ valueRef, orgId, secretId, version }), JSON.stringify(payload));
  const [row] = await db
    .insert(secretValues)
    .values({ valueRef, orgId, secretId, version, typeKey, ...sealed, fingerprint: await payloadFingerprint(payload), createdAt: new Date().toISOString() })
    .returning();
  return stored(row!);
}

/** Org- and secret-scoped lookup: a value is never resolvable from another organization or secret. */
export async function getValue(orgId: string, secretId: string, valueRef: string): Promise<Row | null> {
  if (!orgId || !secretId || !valueRef) return null;
  const [row] = await db.select().from(secretValues).where(and(eq(secretValues.valueRef, valueRef), eq(secretValues.orgId, orgId), eq(secretValues.secretId, secretId)));
  return row ?? null;
}

/** Decrypts a version in memory. KeyServiceUnavailableError propagates (the row may be fine). */
export async function readValue(row: Row): Promise<SecretPayload> {
  const plaintext = await openRecord(sealedOf(row));
  if (plaintext === null) throw new SecretValueUnreadableError(row.valueRef);
  return JSON.parse(plaintext) as SecretPayload;
}

/** Destroys versions (crypto-shredding: the only copy of the ciphertext is deleted). Returns the refs destroyed. */
export async function destroyValues(orgId: string, secretId: string, valueRefs: string[]): Promise<string[]> {
  if (!valueRefs.length) return [];
  const rows = await db
    .delete(secretValues)
    .where(and(eq(secretValues.orgId, orgId), eq(secretValues.secretId, secretId), inArray(secretValues.valueRef, valueRefs)))
    .returning({ ref: secretValues.valueRef });
  return rows.map((r) => r.ref);
}

export async function countValues(): Promise<number> {
  const [row] = await db.select({ n: count() }).from(secretValues);
  return row?.n ?? 0;
}

/**
 * Re-encrypts every value not under the current key (after a key rotation), like credentials:
 * each update is conditional on the ciphertext being unchanged; unreadable rows are counted
 * and left alone; a KMS outage leaves rows pending (still readable with their old key).
 */
export async function reencryptValues(): Promise<{ reencrypted: number; unreadable: number; pending: number }> {
  const rows = await db.select().from(secretValues).where(ne(secretValues.encryptionKeyRef, config.encryptionKeyRef));
  let reencrypted = 0;
  let unreadable = 0;
  let pending = 0;
  for (const r of rows) {
    try {
      const plaintext = await openRecord(sealedOf(r));
      if (plaintext === null) {
        unreadable++;
        continue;
      }
      const next = await sealSecret(aadOf(r), plaintext);
      const done = await db
        .update(secretValues)
        .set(next)
        .where(and(eq(secretValues.valueRef, r.valueRef), eq(secretValues.ciphertext, r.ciphertext)))
        .returning({ ref: secretValues.valueRef });
      reencrypted += done.length;
    } catch (e) {
      if (!(e instanceof KeyServiceUnavailableError)) throw e;
      pending++;
    }
  }
  return { reencrypted, unreadable, pending };
}
