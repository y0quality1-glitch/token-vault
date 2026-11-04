import { randomBytes, randomUUID } from 'node:crypto';
import { existsSync, readFileSync, renameSync } from 'node:fs';
import { and, count, eq, sql } from 'drizzle-orm';
import { SEED_CREDENTIAL_REFS } from '@token-vault/shared';
import { config } from '../config';
import { db } from '../db/client';
import { credentials } from '../db/schema';
import { fingerprint, mask, open, seal, type Sealed } from '../security/encryption';

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
    maskedIdentifier: r.maskedIdentifier,
    fingerprint: r.fingerprint,
    metadata: r.metadata,
    status: r.status,
    createdAt: r.createdAt,
    rotatedAt: r.rotatedAt,
  };
}

/** Encrypts a secret into the column set for one row. The plaintext goes no further. */
function encrypted(ref: string, secret: string, masked?: string) {
  const sealed = seal(config.encryptionKey, secret, ref);
  return {
    iv: sealed.iv,
    ciphertext: sealed.ciphertext,
    authTag: sealed.authTag,
    encryptionKeyRef: config.encryptionKeyRef,
    maskedIdentifier: masked ?? mask(secret),
    fingerprint: fingerprint(config.encryptionKey, secret),
  };
}

function readable(r: Pick<CredentialRecord, 'credentialRef' | 'sealed'>): boolean {
  try {
    open(config.encryptionKey, r.sealed, r.credentialRef);
    return true;
  } catch {
    return false;
  }
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
    await db.execute(sql`TRUNCATE credentials, used_nonces`);
  }
  await importLegacyFile();

  for (const seed of Object.values(SEED_CREDENTIAL_REFS)) {
    const [row] = await db.select().from(credentials).where(eq(credentials.credentialRef, seed.ref));
    if (row && readable(toRecord(row))) continue;
    const now = new Date().toISOString();
    await db
      .insert(credentials)
      .values({ credentialRef: seed.ref, orgId: seed.orgId, provider: 'github', ...encrypted(seed.ref, mockSecret()), metadata: { label: seed.label, seeded: 'true' }, status: 'ACTIVE', createdAt: now, rotatedAt: null })
      .onConflictDoUpdate({ target: credentials.credentialRef, set: { ...encrypted(seed.ref, mockSecret()), rotatedAt: now, status: 'ACTIVE' } });
  }

  const unreadable = (await db.select().from(credentials)).map(toRecord).filter((r) => !readable(r));
  if (unreadable.length) {
    console.warn(`[vault] ${unreadable.length} credential(s) cannot be decrypted with the configured VAULT_ENCRYPTION_KEY; requests using them will fail until the original key is restored or they are rotated`);
  }
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
    if (r.status === 'DELETED' || !readable(r)) continue; // only records the current key can open
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
  const [row] = await db
    .insert(credentials)
    .values({ credentialRef: ref, orgId, provider, ...encrypted(ref, secret, masked), metadata, status: 'ACTIVE', createdAt: new Date().toISOString(), rotatedAt: null })
    .returning();
  return toRecord(row!);
}

export async function rotateCredential(ref: string, orgId: string, secret: string, masked?: string): Promise<CredentialRecord | null> {
  const [row] = await db
    .update(credentials)
    .set({ ...encrypted(ref, secret, masked), rotatedAt: new Date().toISOString(), status: 'ACTIVE' })
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
  let secret: string;
  try {
    secret = open(config.encryptionKey, rec.sealed, rec.credentialRef);
  } catch {
    throw new CredentialUnreadableError(rec.credentialRef);
  }
  return fn(secret);
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
