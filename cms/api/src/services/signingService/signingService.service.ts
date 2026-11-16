import { sign } from 'node:crypto';
import type { EntityManager } from 'typeorm';
import { signaturePayload } from '@token-vault/shared';
import { SIGNING } from '../../config';
import AppDatabase from '../../databases/database';
import { SigningKeyEntity } from '../../entities/signingKeyEntity';
import { VersionSignatureEntity } from '../../entities/versionSignatureEntity';
import { SYSTEM_ACTOR, audit } from '../auditService/auditService.service';

/**
 * Key rotation without a flag day: published versions are immutable, so instead of re-signing
 * them in place the CMS adds a signature per key. When it starts with a new key it signs every
 * published version with it; the catalog then serves both signatures, and consumers pinning the
 * old key, the new key or both keep accepting the catalog. The old private key is not needed.
 */
export function signDigest(digest: string): string {
  return sign(null, Buffer.from(signaturePayload(digest)), SIGNING.key).toString('base64');
}

/** Records the active key (idempotent). Returns true the first time this key is seen. */
export async function registerActiveKey(m: EntityManager): Promise<boolean> {
  const inserted = await m
    .createQueryBuilder()
    .insert()
    .into(SigningKeyEntity)
    .values({ key_id: SIGNING.keyId, algorithm: 'Ed25519', public_key_pem: SIGNING.publicKeyPem, first_used_at: new Date().toISOString() })
    .orIgnore()
    .returning(['key_id'])
    .execute();
  // A key carried over from before the key table existed has no public key yet: fill it in.
  await m.createQueryBuilder().update(SigningKeyEntity).set({ public_key_pem: SIGNING.publicKeyPem }).where('key_id = :id AND public_key_pem IS NULL', { id: SIGNING.keyId }).execute();
  return (inserted.raw as unknown[]).length > 0;
}

export async function addSignature(m: EntityManager, versionId: string, digest: string, signature = signDigest(digest)) {
  await m.createQueryBuilder().insert().into(VersionSignatureEntity).values({ version_id: versionId, key_id: SIGNING.keyId, signature, signed_at: new Date().toISOString() }).orIgnore().execute();
}

/** Signs every published (or superseded) version that has no signature by the active key yet. Returns how many. */
export async function signPublishedWithActiveKey(m: EntityManager): Promise<number> {
  const pending: { id: string; digest: string }[] = await m.query(
    `SELECT id, digest FROM application_versions
      WHERE status IN ('PUBLISHED', 'SUPERSEDED') AND digest IS NOT NULL
        AND id NOT IN (SELECT version_id FROM cms_version_signatures WHERE key_id = $1)`,
    [SIGNING.keyId],
  );
  for (const v of pending) await addSignature(m, v.id, v.digest);
  return pending.length;
}

/** Start-up: register the active key and make sure every published version carries its signature. */
export async function initSigning() {
  await AppDatabase.getInstance().executeInTransaction(async (m) => {
    const isNew = await registerActiveKey(m);
    const count = await signPublishedWithActiveKey(m);
    if (isNew) await audit(m, SYSTEM_ACTOR, 'signing.key_activated', {}, { keyId: SIGNING.keyId });
    if (count) await audit(m, SYSTEM_ACTOR, 'signing.versions_signed', {}, { keyId: SIGNING.keyId, count });
    if (isNew || count) console.log(`[cms] signing key ${SIGNING.keyId}: ${isNew ? 'activated, ' : ''}signed ${count} published version(s)`);
  });
}
