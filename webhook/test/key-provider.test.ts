import { describe, expect, it } from 'vitest';
import { randomBytes } from 'node:crypto';
import { fakeKms } from './helpers/fake-kms';
import { DataKeyCache, KeyAccessDeniedError, KeyServiceUnavailableError, openEnvelope, sealEnvelope } from '../src/security/key-provider';
import { parseKeyProviderConfig } from '../src/security/provider-config';

describe('envelope encryption', () => {
  it('seals each secret with its own data key, wrapped by the KMS and bound to the credential', async () => {
    const { provider, state } = fakeKms();
    const cache = new DataKeyCache(60_000);
    const a = await sealEnvelope(provider, 'sk_live_secretA', 'cref_a');
    const b = await sealEnvelope(provider, 'sk_live_secretA', 'cref_b');
    expect(a.ref).toBe(provider.ref);
    expect(a.wrappedKey).not.toBe(b.wrappedKey); // a fresh data key per record
    expect(a.sealed.ciphertext).not.toContain('secretA');
    expect(await openEnvelope(provider, cache, a.sealed, a.wrappedKey, 'cref_a', a.ref)).toBe('sk_live_secretA');
    // The wrapped key is bound to its credential: it does not unwrap for another one.
    await expect(openEnvelope(provider, new DataKeyCache(0), a.sealed, a.wrappedKey, 'cref_b', a.ref)).rejects.toBeInstanceOf(KeyAccessDeniedError);
    // Cached: a second read needs no KMS call; with caching off, every read does.
    const before = state.unwraps;
    await openEnvelope(provider, cache, a.sealed, a.wrappedKey, 'cref_a', a.ref);
    expect(state.unwraps).toBe(before);
  });

  it('reports an outage as unavailable, never as a bad record', async () => {
    const { provider, state } = fakeKms();
    const e = await sealEnvelope(provider, 'token', 'cref_x');
    state.down = true;
    await expect(openEnvelope(provider, new DataKeyCache(0), e.sealed, e.wrappedKey, 'cref_x', e.ref)).rejects.toBeInstanceOf(KeyServiceUnavailableError);
    await expect(sealEnvelope(provider, 'token', 'cref_y')).rejects.toBeInstanceOf(KeyServiceUnavailableError);
  });

  it('expires and bounds cached data keys', () => {
    const cache = new DataKeyCache(1000, 2);
    const k = randomBytes(32);
    cache.set('w1', k, 0);
    expect(cache.get('w1', 500)?.equals(k)).toBe(true);
    expect(cache.get('w1', 1500)).toBeNull();
    cache.set('a', k, 0);
    cache.set('b', k, 0);
    cache.set('c', k, 0);
    expect(cache.size).toBe(2);
    expect(cache.get('a', 1)).toBeNull(); // oldest evicted
    const off = new DataKeyCache(0);
    off.set('x', k);
    expect(off.get('x')).toBeNull();
  });
});

describe('key provider configuration', () => {
  it('defaults to the environment key', () => {
    expect(parseKeyProviderConfig({})).toEqual({ provider: { kind: 'env' }, cacheSeconds: 300 });
  });
  it('reads AWS KMS and Vault Transit settings', () => {
    expect(parseKeyProviderConfig({ VAULT_KEY_PROVIDER: 'aws-kms', KMS_KEY_ID: 'alias/token-vault', AWS_REGION: 'eu-west-1', KMS_DATA_KEY_CACHE_SECONDS: '0' })).toEqual({
      provider: { kind: 'aws-kms', keyId: 'alias/token-vault', region: 'eu-west-1', endpoint: undefined, timeoutMs: 2000 },
      cacheSeconds: 0,
    });
    expect(parseKeyProviderConfig({ VAULT_KEY_PROVIDER: 'aws-kms', KMS_KEY_ID: 'arn:aws:kms:us-east-2:111122223333:key/1234' }).provider).toMatchObject({ region: 'us-east-2' });
    expect(parseKeyProviderConfig({ VAULT_KEY_PROVIDER: 'vault-transit', VAULT_ADDR: 'https://vault.internal:8200', VAULT_TRANSIT_KEY: 'token-vault', VAULT_K8S_ROLE: 'webhook' }).provider).toMatchObject({
      kind: 'vault-transit',
      mount: 'transit',
      key: 'token-vault',
      k8sRole: 'webhook',
    });
  });
  it('refuses anything incomplete or unknown rather than falling back to another key', () => {
    expect(() => parseKeyProviderConfig({ VAULT_KEY_PROVIDER: 'kms' })).toThrow(/must be env, aws-kms or vault-transit/);
    expect(() => parseKeyProviderConfig({ VAULT_KEY_PROVIDER: 'aws-kms' })).toThrow(/needs KMS_KEY_ID/);
    expect(() => parseKeyProviderConfig({ VAULT_KEY_PROVIDER: 'aws-kms', KMS_KEY_ID: 'alias/x' })).toThrow(/needs AWS_REGION/);
    expect(() => parseKeyProviderConfig({ VAULT_KEY_PROVIDER: 'vault-transit', VAULT_ADDR: 'https://v', VAULT_TRANSIT_KEY: 'k' })).toThrow(/needs VAULT_TOKEN or VAULT_K8S_ROLE/);
    expect(() => parseKeyProviderConfig({ VAULT_KEY_PROVIDER: 'vault-transit', VAULT_ADDR: 'vault:8200', VAULT_TRANSIT_KEY: 'k', VAULT_TOKEN: 't' })).toThrow(/VAULT_ADDR/);
    expect(() => parseKeyProviderConfig({ VAULT_KEY_PROVIDER: 'vault-transit', VAULT_ADDR: 'https://v', VAULT_TRANSIT_KEY: 'k', VAULT_TOKEN: 't', VAULT_TRANSIT_MOUNT: '../sys' })).toThrow(/mount path/);
    expect(() => parseKeyProviderConfig({ KMS_DATA_KEY_CACHE_SECONDS: '-1' })).toThrow(/whole number/);
    expect(() => parseKeyProviderConfig({ KMS_TIMEOUT_MS: '50' })).toThrow(/KMS_TIMEOUT_MS/);
  });
});
