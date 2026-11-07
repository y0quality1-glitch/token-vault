import { randomBytes, randomUUID } from 'node:crypto';
import { existsSync, readFileSync, renameSync } from 'node:fs';
import { and, count, eq, ne, sql } from 'drizzle-orm';
import { SEED_CREDENTIAL_REFS } from '@token-vault/shared';
import { config } from '../config';
import { db } from '../db/client';
import { credentials, vaultSettings } from '../db/schema';
import { fingerprint, mask, type Sealed } from '../security/encryption';
import { openWith, sealWith } from '../security/keyring';
import { DataKeyCache, KeyServiceUnavailableError, openEnvelope, sealEnvelope } from '../security/key-provider';

export { KeyServiceUnavailableError };

/**
 * Customer-controlled credential store (PostgreSQL, customer trust zone). Only
 * ciphertext is persisted; the AES-256-GCM key is injected via environment and is
 * never stored alongside it. Every lookup is scoped to the owning organization.
 */
export interface CredentialRecord {
  credentialRef: string;
  orgId: string;
  provider: string;
  sealed: Sealed;
  encryptionKeyRef: string;
  /** KMS mode: the row's data key, wrapped by the KMS. Null for rows sealed with an environment key. */
  wrappedKey: string | null;
  maskedIdentifier: string;
  fingerprint: string;
  metadata: Record<string, string>;
  status: 'ACTIVE' | 'DISABLED';
  createdAt: string;
  rotatedAt: string | null;
}

/** Raised when a stored credential cannot be decrypted (wrong key, or tampered ciphertext). */
export class CredentialUnreadableError extends Error {
  constructor(public credentialRef: string) {
    super(`Credential ${credentialRef} cannot be decrypted with the configured key`);
  }
}

type Row = typeof credentials.$inferSelect;

function toRecord(r: Row): CredentialRecord {
  return {
    credentialRef: r.credentialRef,
    orgId: r.orgId,
    provider: r.provider,
    sealed: { iv: r.iv, ciphertext: r.ciphertext, authTag: r.authTag },
    encryptionKeyRef: r.encryptionKeyRef,
    wrappedKey: r.wrappedKey ?? null,
    maskedIdentifier: r.maskedIdentifier,
    fingerprint: r.fingerprint,
    metadata: r.metadata,
    status: r.status,
    createdAt: r.createdAt,
    rotatedAt: r.rotatedAt,
  };
}

// ---------------------------------------------------------------- sealing

const dataKeys = new DataKeyCache(config.dataKeyCacheSeconds * 1000);

/** Whether the KMS answered the last call (reported by /internal/v1/health). */
export let keyServiceStatus: { ok: boolean; at: string; detail: string } | null = null;
function noteKeyService<T>(p: Promise<T>): Promise<T> {
  return p.then(
    (v) => ((keyServiceStatus = { ok: true, at: new Date().toISOString(), detail: 'ok' }), v),
    (e) => {
      if (e instanceof KeyServiceUnavailableError) keyServiceStatus = { ok: false, at: new Date().toISOString(), detail: e.message };
      throw e;
    },
  );
}

/**
 * Seals a secret for one row: with a fresh data key wrapped by the KMS, or (env mode) with
 * the current environment key. Throws KeyServiceUnavailableError when the KMS is down.
 */
async function sealSecret(ref: string, secret: string) {
  if (config.keyProvider) {
    const e = await noteKeyService(sealEnvelope(config.keyProvider, secret, ref));
    return { iv: e.sealed.iv, ciphertext: e.sealed.ciphertext, authTag: e.sealed.authTag, encryptionKeyRef: e.ref, wrappedKey: e.wrappedKey };
  }
  const { sealed, ref: keyRef } = sealWith(config.keyring!, secret, ref);
  return { iv: sealed.iv, ciphertext: sealed.ciphertext, authTag: sealed.authTag, encryptionKeyRef: keyRef, wrappedKey: null };
}

/**
 * Opens a row: KMS-wrapped data key, or an environment key (current, previous, or legacy).
 * Returns null if no configured key opens it (wrong key, removed key, tampered row). Throws
 * KeyServiceUnavailableError when the KMS cannot be reached: that says nothing about the row.
 */
async function openRecord(r: Pick<CredentialRecord, 'credentialRef' | 'sealed' | 'encryptionKeyRef' | 'wrappedKey'>): Promise<string | null> {
  if (r.wrappedKey) {
    const provider = config.keyProvider;
    if (!provider || !provider.handles(r.encryptionKeyRef)) return null;
    try {
      return await noteKeyService(openEnvelope(provider, dataKeys, r.sealed, r.wrappedKey, r.credentialRef, r.encryptionKeyRef));
    } catch (e) {
      if (e instanceof KeyServiceUnavailableError) throw e;
      return null; // the KMS refused, or the data key does not open this ciphertext
    }
  }
  return config.keyring ? (openWith(config.keyring, r.sealed, r.credentialRef, r.encryptionKeyRef ?? '')?.plaintext ?? null) : null;
}

/**
 * HMAC key for fingerprints. Env mode: the environment key (as before). KMS mode: a key kept
 * wrapped in vault_settings. It is created on first use, from the environment key when one is
 * still configured (so fingerprints stay comparable across the switch), else at random.
 */
let fingerprintKeyPromise: Promise<Buffer> | null = null;
const FINGERPRINT_SETTING = 'fingerprint_key';
const settingContext = { token_vault_setting: FINGERPRINT_SETTING };
function fingerprintKey(): Promise<Buffer> {
  if (!config.keyProvider) return Promise.resolve(config.encryptionKey!);
  fingerprintKeyPromise ??= (async () => {
    const provider = config.keyProvider!;
    const [row] = await db.select().from(vaultSettings).where(eq(vaultSettings.name, FINGERPRINT_SETTING));
    if (row && provider.handles(row.keyRef)) return noteKeyService(provider.unwrap(row.wrappedValue, settingContext, row.keyRef));
    const value = config.encryptionKey ? Buffer.from(config.encryptionKey) : randomBytes(32);
    const wrappedValue = await noteKeyService(provider.wrap(value, settingContext));
    await db
      .insert(vaultSettings)
      .values({ name: FINGERPRINT_SETTING, wrappedValue, keyRef: provider.ref, createdAt: new Date().toISOString() })
      .onConflictDoUpdate({ target: vaultSettings.name, set: { wrappedValue, keyRef: provider.ref } });
    if (row) console.warn('[vault] the fingerprint key was wrapped by a key service that is no longer configured; a new one was created (new fingerprints will differ)');
    return value;
  })().catch((e) => {
    fingerprintKeyPromise = null; // retry on the next call
    throw e;
  });
  return fingerprintKeyPromise;
}

/** Forgets cached keys (data keys, fingerprint key). Tests use it after changing the key configuration. */
export function resetKeyCaches() {
  fingerprintKeyPromise = null;
  dataKeys.clear();
}

/** Encrypts a secret into the column set for one row. The plaintext goes no further. */
async function encrypted(ref: string, secret: string, masked?: string) {
  return { ...(await sealSecret(ref, secret)), maskedIdentifier: masked ?? mask(secret), fingerprint: fingerprint(await fingerprintKey(), secret) };
}

async function readable(r: Pick<CredentialRecord, 'credentialRef' | 'sealed' | 'encryptionKeyRef' | 'wrappedKey'>): Promise<boolean> {
  return (await openRecord(r)) !== null;
}

/** Key id shown for a key ref: kid_… for environment keys, the ref itself for a KMS key, "legacy" for pre-key-id rows. */
export function keyIdOfRef(ref: string): string {
  if (ref.startsWith('env:')) return /#(kid_[0-9a-f]{16})$/.exec(ref)?.[1] ?? 'legacy';
  return ref;
}

const mockSecret = () => `mock_ghp_${randomBytes(18).toString('base64url')}`;

// ---------------------------------------------------------------- startup

/**
 * Prepares the store: optional reset (tests), one-time import of the pre-PostgreSQL
 * JSON file, then demo seeding. Seeding (re)creates MOCK credentials for the seeded refs
 * only where absent or unreadable. Other unreadable credentials are reported, never
 * deleted: a misconfigured key must not silently destroy customer credentials.
 */
export async function initStore() {
  if (config.seedMode === 'reset') {
    console.warn('[vault] SEED_MODE=reset: wiping the credential store');
    await db.execute(sql`TRUNCATE credentials, used_nonces, provider_catalog_state`);
  }
  await importLegacyFile();

  for (const seed of Object.values(SEED_CREDENTIAL_REFS)) {
    const [row] = await db.select().from(credentials).where(eq(credentials.credentialRef, seed.ref));
    try {
      if (row && (await readable(toRecord(row)))) continue;
      const now = new Date().toISOString();
      const values = await encrypted(seed.ref, mockSecret());
      await db
        .insert(credentials)
        .values({ credentialRef: seed.ref, orgId: seed.orgId, provider: 'github', ...values, metadata: { label: seed.label, seeded: 'true' }, status: 'ACTIVE', createdAt: now, rotatedAt: null })
        .onConflictDoUpdate({ target: credentials.credentialRef, set: { ...values, rotatedAt: now, status: 'ACTIVE' } });
    } catch (e) {
      if (!(e instanceof KeyServiceUnavailableError)) throw e;
      console.warn(`[vault] demo credential ${seed.ref} not checked: ${e.message}`);
    }
  }

  if (config.keyProvider) {
    // One wrap/unwrap of a throwaway key: a misconfigured or unreachable KMS shows up at once.
    const probe = randomBytes(32);
    try {
      const back = await noteKeyService(config.keyProvider.unwrap(await noteKeyService(config.keyProvider.wrap(probe, { token_vault_probe: 'start' })), { token_vault_probe: 'start' }, config.keyProvider.ref));
      console.log(`[vault] key service ${config.keyProvider.ref}: ${back.equals(probe) ? 'ok' : 'returned a different key'}`);
    } catch (e) {
      console.warn(`[vault] key service ${config.keyProvider.ref} is not usable yet: ${(e as Error).message}`);
    }
  }
  const result = await reencryptStore();
  if (result.reencrypted) console.log(`[vault] re-encrypted ${result.reencrypted} credential(s) under the current key ${keyIdOfRef(config.encryptionKeyRef)}`);
  if (result.pending) console.warn(`[vault] ${result.pending} credential(s) not re-encrypted yet: the key service is unavailable (${keyServiceStatus?.detail}); they stay readable and are retried at the next start`);
  if (result.unreadable) {
    console.warn(
      `[vault] ${result.unreadable} credential(s) cannot be decrypted with VAULT_ENCRYPTION_KEY or VAULT_PREVIOUS_ENCRYPTION_KEYS; requests using them fail until the key that encrypted them is added back (as a previous key) or they are rotated. They are kept, never deleted.`,
    );
  }
}

/** Outcome of the last re-encryption pass (reported by /internal/v1/health). */
export let lastReencryption: { at: string; reencrypted: number; unreadable: number; pending: number } | null = null;

/**
 * Re-encrypts every record that is not under the current key: records written before a
 * key rotation (named previous key) or by older versions (legacy ref). Each update is
 * conditional on the ciphertext being unchanged, so a concurrent write (an OAuth refresh,
 * a rotation) is never overwritten with an older secret; such a row is picked up next time.
 * Records no configured key can open are counted and left untouched.
 */
export async function reencryptStore(): Promise<{ reencrypted: number; unreadable: number; pending: number }> {
  const current = config.encryptionKeyRef;
  const rows = await db.select().from(credentials).where(ne(credentials.encryptionKeyRef, current));
  let reencrypted = 0;
  let unreadable = 0;
  let pending = 0; // the KMS was unavailable: left as they are, still readable with their old key
  for (const r of rows) {
    try {
      const plaintext = await openRecord(toRecord(r));
      if (plaintext === null) {
        unreadable++;
        continue;
      }
      const next = await sealSecret(r.credentialRef, plaintext);
      // The fingerprint and masked identifier stay: the secret itself did not change.
      const done = await db
        .update(credentials)
        .set(next)
        .where(and(eq(credentials.credentialRef, r.credentialRef), eq(credentials.ciphertext, r.ciphertext)))
        .returning({ ref: credentials.credentialRef });
      reencrypted += done.length;
    } catch (e) {
      if (!(e instanceof KeyServiceUnavailableError)) throw e;
      pending++;
    }
  }
  lastReencryption = { at: new Date().toISOString(), reencrypted, unreadable, pending };
  return { reencrypted, unreadable, pending };
}

/** How many records each key holds (by key id; "legacy" for records from before key ids). */
export async function recordsByKey(): Promise<Record<string, number>> {
  const rows = await db.select({ ref: credentials.encryptionKeyRef, n: count() }).from(credentials).groupBy(credentials.encryptionKeyRef);
  const out: Record<string, number> = {};
  for (const r of rows) {
    const id = keyIdOfRef(r.ref);
    out[id] = (out[id] ?? 0) + r.n;
  }
  return out;
}

/** Imports ciphertext records from webhook/data/vault-store.json (pre-PostgreSQL store), once. */
async function importLegacyFile() {
  const file = config.legacyDataFile;
  if (!existsSync(file)) return;
  let list: (Omit<CredentialRecord, 'status'> & { status: string })[];
  try {
    list = JSON.parse(readFileSync(file, 'utf8'));
  } catch {
    console.warn('[vault] legacy store file is not valid JSON; skipping import');
    return;
  }
  let imported = 0;
  for (const r of list) {
    if (r.status === 'DELETED' || !(await readable({ ...r, wrappedKey: null }))) continue; // only records a configured key can open
    const res = await db
      .insert(credentials)
      .values({
        credentialRef: r.credentialRef,
        orgId: r.orgId,
        provider: r.provider,
        iv: r.sealed.iv,
        ciphertext: r.sealed.ciphertext,
        authTag: r.sealed.authTag,
        encryptionKeyRef: r.encryptionKeyRef,
        maskedIdentifier: r.maskedIdentifier,
        fingerprint: r.fingerprint,
        metadata: r.metadata ?? {},
        status: r.status === 'DISABLED' ? 'DISABLED' : 'ACTIVE',
        createdAt: r.createdAt,
        rotatedAt: r.rotatedAt,
      })
      .onConflictDoNothing()
      .returning({ ref: credentials.credentialRef });
    imported += res.length;
  }
  renameSync(file, `${file}.imported`);
  console.log(`[vault] imported ${imported} credential(s) from the legacy JSON store; file renamed to ${file}.imported`);
}

// ---------------------------------------------------------------- operations

/** `masked` overrides the default token-style mask (e.g. for GitHub App credentials). */
export async function createCredential(orgId: string, provider: string, secret: string, metadata: Record<string, string>, masked?: string): Promise<CredentialRecord> {
  const ref = 'cref_' + randomUUID().replace(/-/g, '').slice(0, 16);
  const values = await encrypted(ref, secret, masked);
  const [row] = await db
    .insert(credentials)
    .values({ credentialRef: ref, orgId, provider, ...values, metadata, status: 'ACTIVE', createdAt: new Date().toISOString(), rotatedAt: null })
    .returning();
  return toRecord(row!);
}

export async function rotateCredential(ref: string, orgId: string, secret: string, masked?: string): Promise<CredentialRecord | null> {
  const values = await encrypted(ref, secret, masked);
  const [row] = await db
    .update(credentials)
    .set({ ...values, rotatedAt: new Date().toISOString(), status: 'ACTIVE' })
    .where(and(eq(credentials.credentialRef, ref), eq(credentials.orgId, orgId)))
    .returning();
  return row ? toRecord(row) : null;
}

/**
 * Re-encrypts a credential's secret in place without changing its masked identifier,
 * fingerprint or rotation date (OAuth token refreshes and connection completion).
 */
export async function replaceSecret(ref: string, orgId: string, secret: string, masked?: string): Promise<CredentialRecord | null> {
  const next = await sealSecret(ref, secret);
  const [row] = await db
    .update(credentials)
    .set({ ...next, ...(masked ? { maskedIdentifier: masked } : {}) })
    .where(and(eq(credentials.credentialRef, ref), eq(credentials.orgId, orgId)))
    .returning();
  return row ? toRecord(row) : null;
}

/** Crypto-shred: the row (and with it the only copy of the ciphertext) is removed. */
export async function deleteCredential(ref: string, orgId: string): Promise<boolean> {
  const rows = await db
    .delete(credentials)
    .where(and(eq(credentials.credentialRef, ref), eq(credentials.orgId, orgId)))
    .returning({ ref: credentials.credentialRef });
  return rows.length === 1;
}

/** Org-scoped lookup: a credential is never resolvable from another organization. */
export async function get(ref: string, orgId: string): Promise<CredentialRecord | null> {
  if (!ref || !orgId) return null;
  const [row] = await db.select().from(credentials).where(and(eq(credentials.credentialRef, ref), eq(credentials.orgId, orgId)));
  return row ? toRecord(row) : null;
}

/** Decrypts in memory only for the duration of one upstream call. */
export async function withSecret<T>(rec: CredentialRecord, fn: (secret: string) => Promise<T>): Promise<T> {
  const plaintext = await openRecord(rec); // KeyServiceUnavailableError propagates: the record may be fine
  if (plaintext === null) throw new CredentialUnreadableError(rec.credentialRef);
  return fn(plaintext);
}

export function publicView(rec: CredentialRecord) {
  return {
    credential_ref: rec.credentialRef,
    provider: rec.provider,
    masked_identifier: rec.maskedIdentifier,
    fingerprint: rec.fingerprint,
    encryption_key_ref: rec.encryptionKeyRef,
    status: rec.status,
    created_at: rec.createdAt,
    rotated_at: rec.rotatedAt,
  };
}

export async function countCredentials(): Promise<number> {
  const [row] = await db.select({ n: count() }).from(credentials);
  return row?.n ?? 0;
}
