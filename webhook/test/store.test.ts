import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { randomBytes } from 'node:crypto';
import { existsSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

/**
 * Integration tests for the customer-side PostgreSQL store. Skipped unless
 * WEBHOOK_TEST_DATABASE_URL is set (CI provides one). The database is wiped.
 */
const url = process.env.WEBHOOK_TEST_DATABASE_URL;
const suite = url ? describe : describe.skip;

suite('customer credential store (PostgreSQL)', () => {
  const key = randomBytes(32);
  const legacyFile = join(mkdtempSync(join(tmpdir(), 'tv-webhook-')), 'vault-store.json');
  let m: {
    client: typeof import('../src/db/client');
    store: typeof import('../src/store/credential-store');
    nonces: typeof import('../src/security/nonce-store');
    enc: typeof import('../src/security/encryption');
    schema: typeof import('../src/db/schema');
    orm: typeof import('drizzle-orm');
  };

  beforeAll(async () => {
    process.env.WEBHOOK_DATABASE_URL = url;
    process.env.VAULT_ENCRYPTION_KEY = key.toString('base64');
    process.env.WEBHOOK_SIGNING_SECRET ??= randomBytes(32).toString('base64url');
    process.env.WEBHOOK_DATA_FILE = legacyFile;
    process.env.SEED_MODE = 'reset';
    m = {
      client: await import('../src/db/client'),
      store: await import('../src/store/credential-store'),
      nonces: await import('../src/security/nonce-store'),
      enc: await import('../src/security/encryption'),
      schema: await import('../src/db/schema'),
      orm: await import('drizzle-orm'),
    };

    // A pre-PostgreSQL JSON store: one record sealed with the current key, one with another key.
    const legacy = (ref: string, k: Buffer) => ({
      credentialRef: ref,
      orgId: 'org_legacy',
      provider: 'github',
      sealed: m.enc.seal(k, 'mock_ghp_legacyValue1234567890', ref),
      encryptionKeyRef: 'env:VAULT_ENCRYPTION_KEY#v1',
      maskedIdentifier: 'mock_ghp_••••••••7890',
      fingerprint: 'fp_0000000000000000',
      metadata: {},
      status: 'ACTIVE',
      createdAt: new Date().toISOString(),
      rotatedAt: null,
    });
    writeFileSync(legacyFile, JSON.stringify([legacy('cref_legacy_ok', key), legacy('cref_legacy_other_key', randomBytes(32))]));

    await m.client.runMigrations();
    await m.store.initStore();
  }, 60_000);

  afterAll(async () => {
    await m?.client.closeDatabase();
  });

  it('seeds the demo mock credentials and imports readable legacy records once', async () => {
    const { SEED_CREDENTIAL_REFS } = await import('@token-vault/shared');
    for (const s of Object.values(SEED_CREDENTIAL_REFS)) expect(await m.store.get(s.ref, s.orgId)).not.toBeNull();
    expect(await m.store.get('cref_legacy_ok', 'org_legacy')).not.toBeNull();
    expect(await m.store.get('cref_legacy_other_key', 'org_legacy')).toBeNull(); // unreadable: not imported
    expect(existsSync(legacyFile)).toBe(false);
    expect(existsSync(`${legacyFile}.imported`)).toBe(true);
  });

  it('stores only ciphertext and resolves credentials only within their organization', async () => {
    const secret = 'mock_ghp_' + randomBytes(16).toString('hex');
    const rec = await m.store.createCredential('org_a', 'github', secret, { label: 'test' });
    const { rows } = await m.client.db.execute(m.orm.sql`select * from credentials where credential_ref = ${rec.credentialRef}`);
    expect(JSON.stringify(rows)).not.toContain(secret);
    expect(await m.store.get(rec.credentialRef, 'org_b')).toBeNull();
    const fetched = (await m.store.get(rec.credentialRef, 'org_a'))!;
    expect(await m.store.withSecret(fetched, async (s) => s)).toBe(secret);
  });

  it('rotates in place (same reference, new ciphertext) and deletes by crypto-shredding the row', async () => {
    const rec = await m.store.createCredential('org_a', 'github', 'mock_ghp_firstValue_abcdefghij', {});
    expect(await m.store.rotateCredential(rec.credentialRef, 'org_b', 'mock_ghp_secondValue_abcdefghi')).toBeNull();
    const rotated = (await m.store.rotateCredential(rec.credentialRef, 'org_a', 'mock_ghp_secondValue_abcdefghi'))!;
    expect(rotated.credentialRef).toBe(rec.credentialRef);
    expect(rotated.sealed.ciphertext).not.toBe(rec.sealed.ciphertext);
    expect(rotated.rotatedAt).not.toBeNull();
    expect(await m.store.withSecret(rotated, async (s) => s)).toBe('mock_ghp_secondValue_abcdefghi');
    expect(await m.store.deleteCredential(rec.credentialRef, 'org_b')).toBe(false);
    expect(await m.store.deleteCredential(rec.credentialRef, 'org_a')).toBe(true);
    expect(await m.store.get(rec.credentialRef, 'org_a')).toBeNull();
  });

  it('rejects a replayed nonce across webhook instances, and lets an expired nonce be reused', async () => {
    const instanceA = new m.nonces.PgNonceStore(120_000);
    const instanceB = new m.nonces.PgNonceStore(120_000);
    const nonce = 'nonce_' + randomBytes(12).toString('hex');
    expect(await instanceA.use(nonce)).toBe(true);
    expect(await instanceB.use(nonce)).toBe(false);
    const later = Date.now() + 121_000; // past the validity window
    expect(await instanceB.use(nonce, later)).toBe(true);
  });

  it('reports but never deletes credentials the current key cannot decrypt', async () => {
    const rec = await m.store.createCredential('org_a', 'github', 'mock_ghp_tamperTarget_123456789', {});
    const { credentials } = m.schema;
    await m.client.db.update(credentials).set({ authTag: randomBytes(16).toString('base64') }).where(m.orm.eq(credentials.credentialRef, rec.credentialRef));
    const tampered = (await m.store.get(rec.credentialRef, 'org_a'))!;
    await expect(m.store.withSecret(tampered, async (s) => s)).rejects.toBeInstanceOf(m.store.CredentialUnreadableError);

    const { config } = await import('../src/config');
    config.seedMode = 'if-missing'; // config is read once at import; switch the loaded value
    const before = await m.store.countCredentials();
    await m.store.initStore();
    expect(await m.store.countCredentials()).toBe(before);
    expect(await m.store.get(rec.credentialRef, 'org_a')).not.toBeNull();
  });
});
