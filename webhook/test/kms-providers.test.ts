import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { randomBytes } from 'node:crypto';
import { CreateKeyCommand, KMSClient } from '@aws-sdk/client-kms';
import { KeyAccessDeniedError, KeyServiceUnavailableError } from '../src/security/key-provider';
import { awsKmsProvider } from '../src/security/providers/aws-kms';
import { vaultTransitProvider } from '../src/security/providers/vault-transit';

/**
 * The two providers against real services. Skipped unless they are configured:
 *   VAULT_TEST_ADDR + VAULT_TEST_TOKEN   a Vault (or OpenBao) dev server; Transit is enabled here
 *   KMS_TEST_ENDPOINT                     an AWS KMS-compatible endpoint (LocalStack), with
 *                                         AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY / AWS_REGION
 * CI runs both against service containers.
 */
const vaultAddr = process.env.VAULT_TEST_ADDR;
const vaultToken = process.env.VAULT_TEST_TOKEN ?? '';
const kmsEndpoint = process.env.KMS_TEST_ENDPOINT;
const ctx = { token_vault_credential_ref: 'cref_test0000000001' };

(vaultAddr ? describe : describe.skip)('Vault Transit (real Vault)', () => {
  const key = `token-vault-test-${Date.now()}`;
  const vault = async (path: string, body: unknown = {}) => fetch(`${vaultAddr}/v1/${path}`, { method: 'POST', headers: { 'x-vault-token': vaultToken, 'content-type': 'application/json' }, body: JSON.stringify(body) });

  beforeAll(async () => {
    await vault('sys/mounts/transit', { type: 'transit' }); // already mounted is fine
    expect((await vault(`transit/keys/${key}`)).status).toBeLessThan(300);
  });

  it('wraps and unwraps a data key; the master key never leaves Vault', async () => {
    const p = vaultTransitProvider({ addr: vaultAddr!, mount: 'transit', key, token: vaultToken });
    expect(p.ref).toBe(`vault-transit:transit/${key}`);
    const dataKey = randomBytes(32);
    const wrapped = await p.wrap(dataKey, ctx);
    expect(wrapped).toMatch(/^vault:v1:/);
    expect(wrapped).not.toContain(dataKey.toString('base64'));
    expect((await p.unwrap(wrapped, ctx, p.ref)).equals(dataKey)).toBe(true);
  });

  it('opens records wrapped by an earlier Transit key named in the record', async () => {
    const other = `${key}-old`;
    expect((await vault(`transit/keys/${other}`)).status).toBeLessThan(300);
    const old = vaultTransitProvider({ addr: vaultAddr!, mount: 'transit', key: other, token: vaultToken });
    const current = vaultTransitProvider({ addr: vaultAddr!, mount: 'transit', key, token: vaultToken });
    const dataKey = randomBytes(32);
    const wrapped = await old.wrap(dataKey, ctx);
    expect(current.handles(old.ref)).toBe(true);
    expect((await current.unwrap(wrapped, ctx, old.ref)).equals(dataKey)).toBe(true);
  });

  it('refuses tampered ciphertext and bad tokens; an unreachable Vault is an outage', async () => {
    const p = vaultTransitProvider({ addr: vaultAddr!, mount: 'transit', key, token: vaultToken });
    const wrapped = await p.wrap(randomBytes(32), ctx);
    const tampered = wrapped.slice(0, -6) + (wrapped.endsWith('AAAAAA') ? 'BBBBBB' : 'AAAAAA');
    await expect(p.unwrap(tampered, ctx, p.ref)).rejects.toBeInstanceOf(KeyAccessDeniedError);
    await expect(vaultTransitProvider({ addr: vaultAddr!, mount: 'transit', key, token: 'not-a-token' }).wrap(randomBytes(32), ctx)).rejects.toBeInstanceOf(KeyAccessDeniedError);
    await expect(vaultTransitProvider({ addr: 'http://127.0.0.1:1', mount: 'transit', key, token: vaultToken, timeoutMs: 500 }).wrap(randomBytes(32), ctx)).rejects.toBeInstanceOf(KeyServiceUnavailableError);
  });
});

(kmsEndpoint ? describe : describe.skip)('AWS KMS (KMS-compatible endpoint)', () => {
  let keyId = '';
  let otherKeyId = '';
  const region = process.env.AWS_REGION ?? 'us-east-1';
  const admin = new KMSClient({ region, endpoint: kmsEndpoint });

  beforeAll(async () => {
    keyId = (await admin.send(new CreateKeyCommand({ Description: 'token-vault test' }))).KeyMetadata!.KeyId!;
    otherKeyId = (await admin.send(new CreateKeyCommand({ Description: 'token-vault test (other)' }))).KeyMetadata!.KeyId!;
  });
  afterAll(() => admin.destroy());

  it('wraps and unwraps a data key with the credential reference as encryption context', async () => {
    const p = awsKmsProvider({ keyId, region, endpoint: kmsEndpoint });
    expect(p.ref).toBe(`aws-kms:${keyId}`);
    const dataKey = randomBytes(32);
    const wrapped = await p.wrap(dataKey, ctx);
    expect((await p.unwrap(wrapped, ctx, p.ref)).equals(dataKey)).toBe(true);
    // A different encryption context (another credential) does not unwrap it.
    await expect(p.unwrap(wrapped, { token_vault_credential_ref: 'cref_other' }, p.ref)).rejects.toBeInstanceOf(KeyAccessDeniedError);
  });

  it('opens records of an earlier KMS key, and refuses a ciphertext claimed for the wrong key', async () => {
    const old = awsKmsProvider({ keyId: otherKeyId, region, endpoint: kmsEndpoint });
    const current = awsKmsProvider({ keyId, region, endpoint: kmsEndpoint });
    const dataKey = randomBytes(32);
    const wrapped = await old.wrap(dataKey, ctx);
    expect((await current.unwrap(wrapped, ctx, old.ref)).equals(dataKey)).toBe(true);
    await expect(current.unwrap(wrapped, ctx, current.ref)).rejects.toBeInstanceOf(KeyAccessDeniedError);
  });

  it('an unreachable KMS is an outage, not a bad record', async () => {
    const p = awsKmsProvider({ keyId, region, endpoint: 'http://127.0.0.1:1' });
    await expect(p.wrap(randomBytes(32), ctx)).rejects.toBeInstanceOf(KeyServiceUnavailableError);
  });
});
