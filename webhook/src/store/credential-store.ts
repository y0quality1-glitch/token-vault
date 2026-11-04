import { randomBytes, randomUUID } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';
import { SEED_CREDENTIAL_REFS } from '@token-vault/shared';
import { config } from '../config';
import { fingerprint, mask, open, seal, type Sealed } from '../security/encryption';

/**
 * Customer-controlled credential store. Only ciphertext is persisted; the
 * encryption key is injected via environment and never stored alongside it.
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
  status: 'ACTIVE' | 'DISABLED' | 'DELETED';
  createdAt: string;
  rotatedAt: string | null;
}

const records = new Map<string, CredentialRecord>();

function persist() {
  mkdirSync(dirname(config.dataFile), { recursive: true });
  writeFileSync(config.dataFile, JSON.stringify([...records.values()], null, 2), { mode: 0o600 });
}

export function loadStore() {
  if (existsSync(config.dataFile)) {
    try {
      const list = JSON.parse(readFileSync(config.dataFile, 'utf8')) as CredentialRecord[];
      for (const r of list) records.set(r.credentialRef, r);
    } catch {
      console.warn('[vault] could not read store file; starting empty');
    }
  }
  // Drop records that cannot be decrypted with the current key (e.g. key was regenerated).
  for (const r of [...records.values()]) {
    try {
      open(config.encryptionKey, r.sealed, r.credentialRef);
    } catch {
      records.delete(r.credentialRef);
    }
  }
  // Seed MOCK credentials for the demo organization. Values are random per install.
  for (const seed of Object.values(SEED_CREDENTIAL_REFS)) {
    if (!records.has(seed.ref)) {
      const mockSecret = `mock_ghp_${randomBytes(18).toString('base64url')}`;
      put(seed.ref, seed.orgId, 'github', mockSecret, { label: seed.label, seeded: 'true' });
    }
  }
  persist();
}

function put(ref: string, orgId: string, provider: string, secret: string, metadata: Record<string, string>): CredentialRecord {
  const now = new Date().toISOString();
  const rec: CredentialRecord = {
    credentialRef: ref,
    orgId,
    provider,
    sealed: seal(config.encryptionKey, secret, ref),
    encryptionKeyRef: config.encryptionKeyRef,
    maskedIdentifier: mask(secret),
    fingerprint: fingerprint(config.encryptionKey, secret),
    metadata,
    status: 'ACTIVE',
    createdAt: now,
    rotatedAt: null,
  };
  records.set(ref, rec);
  return rec;
}

export function createCredential(orgId: string, provider: string, secret: string, metadata: Record<string, string>) {
  const ref = 'cref_' + randomUUID().replace(/-/g, '').slice(0, 16);
  const rec = put(ref, orgId, provider, secret, metadata);
  persist();
  return rec;
}

export function rotateCredential(ref: string, orgId: string, secret: string) {
  const rec = get(ref, orgId);
  if (!rec) return null;
  rec.sealed = seal(config.encryptionKey, secret, ref);
  rec.maskedIdentifier = mask(secret);
  rec.fingerprint = fingerprint(config.encryptionKey, secret);
  rec.rotatedAt = new Date().toISOString();
  rec.status = 'ACTIVE';
  persist();
  return rec;
}

export function deleteCredential(ref: string, orgId: string) {
  const rec = get(ref, orgId);
  if (!rec) return false;
  records.delete(ref); // crypto-shred: the ciphertext is removed from the store
  persist();
  return true;
}

/** Org-scoped lookup: a credential is never resolvable from another organization. */
export function get(ref: string, orgId: string): CredentialRecord | null {
  const rec = records.get(ref);
  if (!rec || rec.orgId !== orgId || rec.status === 'DELETED') return null;
  return rec;
}

/** Decrypts in memory only for the duration of one upstream call. */
export function withSecret<T>(rec: CredentialRecord, fn: (secret: string) => Promise<T>): Promise<T> {
  const secret = open(config.encryptionKey, rec.sealed, rec.credentialRef);
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

export function count() {
  return records.size;
}
