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

  it('persists the verified provider catalog in the customer database, and a reset clears it', async () => {
    const { pgCatalogCache } = await import('../src/providers/catalog-cache');
    expect(await pgCatalogCache.load()).toBeNull();
    const state = { envelopes: [{ definition: { key: 'notes' }, digest: 'd1', signature: 's', key_id: 'k', published_at: 'p', published_by: 'a', approved_by: 'b' }], highWater: { notes: 2 }, savedAt: new Date().toISOString() };
    await pgCatalogCache.save(state);
    await pgCatalogCache.save({ ...state, highWater: { notes: 3 } }); // upsert, single row
    expect(await pgCatalogCache.load()).toMatchObject({ envelopes: state.envelopes, highWater: { notes: 3 } });
    const { config } = await import('../src/config');
    config.seedMode = 'reset'; // an earlier test switched the loaded value to if-missing
    await m.store.initStore();
    expect(await pgCatalogCache.load()).toBeNull();
  });

  it('rotates the encryption key: re-encrypts every record under the new key, keeps fingerprints, then works without the old key', async () => {
    const { config } = await import('../src/config');
    const { buildKeyring, sealWith, LEGACY_KEY_REF } = await import('../src/security/keyring');
    const { credentials } = m.schema;
    const original = config.keyring;
    const oldKey = config.keyring!.current.key;
    try {
      const rec = await m.store.createCredential('org_rot', 'stripe', 'sk_test_rotationValue1234567890', {});
      expect(rec.encryptionKeyRef).toBe(config.keyring!.current.ref);
      // A record written by a version without key ids.
      const legacySealed = sealWith(buildKeyring(oldKey), 'sk_test_legacyRecord12345678901', 'cref_rot_legacy').sealed;
      await m.client.db.insert(credentials).values({ credentialRef: 'cref_rot_legacy', orgId: 'org_rot', provider: 'stripe', iv: legacySealed.iv, ciphertext: legacySealed.ciphertext, authTag: legacySealed.authTag, encryptionKeyRef: LEGACY_KEY_REF, maskedIdentifier: 'sk_test_••••8901', fingerprint: 'fp_legacy00000000', metadata: {}, status: 'ACTIVE', createdAt: new Date().toISOString(), rotatedAt: null });

      // A record no configured key can open: counted, never touched.
      const broken = await m.store.createCredential('org_rot', 'stripe', 'sk_test_brokenRecord12345678901', {});
      await m.client.db.update(credentials).set({ authTag: randomBytes(16).toString('base64') }).where(m.orm.eq(credentials.credentialRef, broken.credentialRef));

      // Rotate: new current key, the old one kept as a previous key.
      const newKey = randomBytes(32);
      config.keyring = buildKeyring(newKey, [oldKey]);
      const before = (await m.store.get(rec.credentialRef, 'org_rot'))!;
      expect(await m.store.withSecret(before, async (s) => s)).toBe('sk_test_rotationValue1234567890'); // still readable before re-encryption

      const result = await m.store.reencryptStore();
      expect(result).toMatchObject({ unreadable: 1 });
      expect(result.reencrypted).toBeGreaterThanOrEqual(2);
      const brokenAfter = (await m.store.get(broken.credentialRef, 'org_rot'))!;
      expect(brokenAfter.sealed.ciphertext).toBe(broken.sealed.ciphertext); // left as it was
      const after = (await m.store.get(rec.credentialRef, 'org_rot'))!;
      expect(after.encryptionKeyRef).toBe(config.keyring!.current.ref);
      expect(after.sealed.ciphertext).not.toBe(before.sealed.ciphertext);
      expect(after.fingerprint).toBe(before.fingerprint);
      expect(after.maskedIdentifier).toBe(before.maskedIdentifier);
      expect((await m.store.get('cref_rot_legacy', 'org_rot'))!.encryptionKeyRef).toBe(config.keyring!.current.ref);
      const byKey = await m.store.recordsByKey();
      // Only the unreadable record is left on the old key.
      expect(Object.entries(byKey).filter(([id]) => id !== config.keyring!.current.id)).toEqual([[buildKeyring(oldKey).current.id, 1]]);

      // Retire the old key: everything that was readable still is.
      config.keyring = buildKeyring(newKey);
      expect(await m.store.withSecret((await m.store.get(rec.credentialRef, 'org_rot'))!, async (s) => s)).toBe('sk_test_rotationValue1234567890');
      expect(await m.store.withSecret((await m.store.get('cref_rot_legacy', 'org_rot'))!, async (s) => s)).toBe('sk_test_legacyRecord12345678901');
      expect(await m.store.reencryptStore()).toMatchObject({ reencrypted: 0, unreadable: 1 });
    } finally {
      config.keyring = original;
    }
  });

  /** Env key -> KMS: existing records move over, new ones use wrapped data keys, the env key can then go. */
  async function kmsFlow(provider: import('../src/security/key-provider').KeyProvider, outage?: { state: { down: boolean } }) {
    const { config } = await import('../src/config');
    const { credentials, vaultSettings } = m.schema;
    const original = { keyring: config.keyring, keyProvider: config.keyProvider, kind: config.keyProviderKind };
    try {
      // Before the switch: sealed with the environment key.
      const a = await m.store.createCredential('org_kms', 'stripe', 'demo-secret-kmsMigrationValue12345678', {});
      expect(a.wrappedKey).toBeNull();

      config.keyProvider = provider;
      config.keyProviderKind = provider.kind;
      m.store.resetKeyCaches();
      const result = await m.store.reencryptStore();
      expect(result.reencrypted).toBeGreaterThanOrEqual(1);
      expect(result.pending).toBe(0);
      const moved = (await m.store.get(a.credentialRef, 'org_kms'))!;
      expect(moved.encryptionKeyRef).toBe(provider.ref);
      expect(moved.wrappedKey).toBeTruthy();
      expect(moved.sealed.ciphertext).not.toBe(a.sealed.ciphertext);
      expect(moved.fingerprint).toBe(a.fingerprint); // the secret did not change
      expect(await m.store.withSecret(moved, async (s) => s)).toBe('demo-secret-kmsMigrationValue12345678');

      // New records: a wrapped data key per row; fingerprints stay comparable across the switch.
      const b = await m.store.createCredential('org_kms', 'stripe', 'demo-secret-kmsMigrationValue12345678', {});
      expect(b.encryptionKeyRef).toBe(provider.ref);
      expect(b.wrappedKey).not.toBe(moved.wrappedKey);
      expect(b.fingerprint).toBe(a.fingerprint);
      const [setting] = await m.client.db.select().from(vaultSettings);
      expect(setting).toMatchObject({ name: 'fingerprint_key', keyRef: provider.ref });
      expect(setting!.wrappedValue).not.toContain(original.keyring!.current.key.toString('base64'));

      // Retire the environment key: everything still opens, new records still work.
      config.keyring = null;
      m.store.resetKeyCaches();
      expect(await m.store.withSecret((await m.store.get(a.credentialRef, 'org_kms'))!, async (s) => s)).toBe('demo-secret-kmsMigrationValue12345678');
      const c = await m.store.createCredential('org_kms', 'stripe', 'demo-secret-afterRetirement123456789', {});
      expect(c.fingerprint).not.toBe(a.fingerprint);
      expect(await m.store.withSecret(c, async (s) => s)).toBe('demo-secret-afterRetirement123456789');
      const [raw] = await m.client.db.select().from(credentials).where(m.orm.eq(credentials.credentialRef, c.credentialRef));
      expect(JSON.stringify(raw)).not.toContain('afterRetirement');

      if (outage) {
        // KMS down: reads and writes say "key service unavailable", never "unreadable".
        outage.state.down = true;
        m.store.resetKeyCaches();
        await expect(m.store.withSecret(c, async (s) => s)).rejects.toBeInstanceOf(m.store.KeyServiceUnavailableError);
        await expect(m.store.createCredential('org_kms', 'stripe', 'demo-secret-duringOutage1234567890', {})).rejects.toBeInstanceOf(m.store.KeyServiceUnavailableError);
        // A record still on the env key stays put (pending), not counted as unreadable.
        config.keyring = original.keyring;
        const envRow = await (async () => {
          config.keyProvider = original.keyProvider;
          const r = await m.store.createCredential('org_kms', 'stripe', 'demo-secret-stillOnEnvKey1234567890', {});
          config.keyProvider = provider;
          return r;
        })();
        const during = await m.store.reencryptStore();
        expect(during.pending).toBeGreaterThanOrEqual(1);
        expect((await m.store.get(envRow.credentialRef, 'org_kms'))!.encryptionKeyRef).toBe(original.keyring!.current.ref);
        outage.state.down = false;
        expect((await m.store.reencryptStore()).pending).toBe(0);
        expect((await m.store.get(envRow.credentialRef, 'org_kms'))!.encryptionKeyRef).toBe(provider.ref);
      }
    } finally {
      config.keyring = original.keyring;
      config.keyProvider = original.keyProvider;
      config.keyProviderKind = original.kind;
      m.store.resetKeyCaches();
      await m.client.db.delete(credentials).where(m.orm.eq(credentials.orgId, 'org_kms'));
      await m.client.db.delete(vaultSettings);
    }
  }

  it('moves to a KMS: envelope encryption with per-record data keys, outages kept apart from unreadable records', async () => {
    const { fakeKms } = await import('./helpers/fake-kms');
    const kms = fakeKms();
    await kmsFlow(kms.provider, kms);
  });

  (process.env.VAULT_TEST_ADDR ? it : it.skip)('moves to real Vault Transit the same way', async () => {
    const key = `token-vault-store-${Date.now()}`;
    const headers = { 'x-vault-token': process.env.VAULT_TEST_TOKEN ?? '', 'content-type': 'application/json' };
    await fetch(`${process.env.VAULT_TEST_ADDR}/v1/sys/mounts/transit`, { method: 'POST', headers, body: JSON.stringify({ type: 'transit' }) });
    await fetch(`${process.env.VAULT_TEST_ADDR}/v1/transit/keys/${key}`, { method: 'POST', headers, body: '{}' });
    const { vaultTransitProvider } = await import('../src/security/providers/vault-transit');
    await kmsFlow(vaultTransitProvider({ addr: process.env.VAULT_TEST_ADDR!, mount: 'transit', key, token: process.env.VAULT_TEST_TOKEN }));
  });
});
