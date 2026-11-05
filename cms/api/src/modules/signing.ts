import { and, eq, inArray, notInArray, sql } from 'drizzle-orm';
import { signaturePayload } from '@token-vault/shared';
import { sign } from 'node:crypto';
import { config } from '../config';
import { db, type Executor } from '../db/client';
import { signingKeys, versionSignatures, versions } from '../db/schema';
import { SYSTEM_ACTOR, audit } from './audit';

/**
 * Key rotation without a flag day: published versions are immutable, so instead of
 * re-signing them in place the CMS adds a signature per key. When it starts with a new
 * key it signs every published version with it; the catalog then serves both signatures,
 * and consumers pinning the old key, the new key or both keep accepting the catalog.
 * The old private key is not needed for this.
 */
export function signDigest(digest: string): string {
  return sign(null, Buffer.from(signaturePayload(digest)), config.signingKey).toString('base64');
}

/** Records the active key (idempotent). Returns true the first time this key is seen. */
export async function registerActiveKey(ex: Executor): Promise<boolean> {
  const inserted = await ex
    .insert(signingKeys)
    .values({ keyId: config.keyId, algorithm: 'Ed25519', publicKeyPem: config.publicKeyPem, firstUsedAt: new Date().toISOString() })
    .onConflictDoNothing()
    .returning({ keyId: signingKeys.keyId });
  // A key carried over from before this table existed has no public key yet: fill it in.
  await ex.update(signingKeys).set({ publicKeyPem: config.publicKeyPem }).where(and(eq(signingKeys.keyId, config.keyId), sql`${signingKeys.publicKeyPem} is null`));
  return inserted.length > 0;
}

export async function addSignature(ex: Executor, versionId: string, digest: string, signature = signDigest(digest)) {
  await ex.insert(versionSignatures).values({ versionId, keyId: config.keyId, signature, signedAt: new Date().toISOString() }).onConflictDoNothing();
}

/** Signs every published version that has no signature by the active key yet. Returns how many. */
export async function signPublishedWithActiveKey(ex: Executor): Promise<number> {
  const signed = ex.select({ id: versionSignatures.versionId }).from(versionSignatures).where(eq(versionSignatures.keyId, config.keyId));
  const pending = await ex
    .select({ id: versions.id, digest: versions.digest })
    .from(versions)
    .where(and(inArray(versions.status, ['PUBLISHED', 'SUPERSEDED']), sql`${versions.digest} is not null`, notInArray(versions.id, signed)));
  for (const v of pending) await addSignature(ex, v.id, v.digest!);
  return pending.length;
}

/** Start-up: register the active key and make sure every published version carries its signature. */
export async function initSigning() {
  await db.transaction(async (tx) => {
    const isNew = await registerActiveKey(tx);
    const count = await signPublishedWithActiveKey(tx);
    if (isNew) await audit(tx, SYSTEM_ACTOR, 'signing.key_activated', {}, { keyId: config.keyId });
    if (count) await audit(tx, SYSTEM_ACTOR, 'signing.versions_signed', {}, { keyId: config.keyId, count });
    if (isNew || count) console.log(`[cms] signing key ${config.keyId}: ${isNew ? 'activated, ' : ''}signed ${count} published version(s)`);
  });
}
