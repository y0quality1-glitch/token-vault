import { describe, expect, it } from 'vitest';
import { randomBytes } from 'node:crypto';
import { fingerprint, mask, open, seal } from '../src/security/encryption';
import { NonceCache, canonicalString, hmacHex, verifySignedRequest } from '../src/security/signature';

describe('AES-256-GCM credential sealing', () => {
  const key = randomBytes(32);
  it('round-trips and binds the credential ref as AAD', () => {
    const sealed = seal(key, 'mock_ghp_abcdefghijklmnopqrstuvwxyz', 'cref_1');
    expect(sealed.ciphertext).not.toContain('mock_ghp');
    expect(open(key, sealed, 'cref_1')).toBe('mock_ghp_abcdefghijklmnopqrstuvwxyz');
    expect(() => open(key, sealed, 'cref_2')).toThrow();
    expect(() => open(randomBytes(32), sealed, 'cref_1')).toThrow();
  });
  it('masks and fingerprints without revealing the secret', () => {
    expect(mask('ghp_1234567890abcdefWXYZ')).toBe('ghp_••••••••WXYZ');
    expect(fingerprint(key, 'x'.repeat(30))).toMatch(/^fp_[0-9a-f]{16}$/);
  });
});

describe('signed request verification', () => {
  const secret = 's'.repeat(40);
  const sign = (body: string, nonce: string, ts = String(Date.now())) => ({
    'x-tv-timestamp': ts,
    'x-tv-nonce': nonce,
    'x-tv-signature': hmacHex(secret, canonicalString('POST', '/internal/v1/execute', ts, nonce, body)),
  });
  it('accepts a valid signature once and rejects replay', async () => {
    const nonces = new NonceCache(120_000);
    const headers = sign('{}', 'nonce_aaaaaaaaaaaaaaaa');
    const base = { secret, method: 'POST', path: '/internal/v1/execute', body: '{}', nonces, maxSkewMs: 60_000 };
    expect((await verifySignedRequest({ ...base, headers })).ok).toBe(true);
    expect(await verifySignedRequest({ ...base, headers })).toEqual({ ok: false, reason: 'replayed_nonce' });
  });
  it('rejects tampered bodies and stale timestamps', async () => {
    const nonces = new NonceCache(120_000);
    const base = { secret, method: 'POST', path: '/internal/v1/execute', nonces, maxSkewMs: 60_000 };
    expect((await verifySignedRequest({ ...base, body: '{"x":1}', headers: sign('{}', 'nonce_bbbbbbbbbbbbbbbb') })).ok).toBe(false);
    const stale = sign('{}', 'nonce_cccccccccccccccc', String(Date.now() - 120_000));
    expect(await verifySignedRequest({ ...base, body: '{}', headers: stale })).toEqual({ ok: false, reason: 'timestamp_outside_window' });
  });
  it('accepts the previous secret during a rotation and says which one matched', async () => {
    const next = 'n'.repeat(40);
    const nonces = new NonceCache(120_000);
    const base = { method: 'POST', path: '/internal/v1/execute', body: '{}', nonces, maxSkewMs: 60_000 };
    // The webhook holds the new secret first; the control plane still signs with the old one.
    const old = await verifySignedRequest({ ...base, secret: [next, secret], headers: sign('{}', 'nonce_dddddddddddddddd') });
    expect(old).toMatchObject({ ok: true, secret, secretIndex: 1 });
    const ts = String(Date.now());
    const headers = { 'x-tv-timestamp': ts, 'x-tv-nonce': 'nonce_eeeeeeeeeeeeeeee', 'x-tv-signature': hmacHex(next, canonicalString('POST', '/internal/v1/execute', ts, 'nonce_eeeeeeeeeeeeeeee', '{}')) };
    expect(await verifySignedRequest({ ...base, secret: [next, secret], headers })).toMatchObject({ ok: true, secret: next, secretIndex: 0 });
    // Once retired, the old secret is refused, and a wrong one never burns a nonce.
    expect(await verifySignedRequest({ ...base, secret: [next], headers: sign('{}', 'nonce_ffffffffffffffff') })).toEqual({ ok: false, reason: 'bad_signature' });
    expect((await verifySignedRequest({ ...base, secret: [next, secret], headers: sign('{}', 'nonce_ffffffffffffffff') })).ok).toBe(true);
  });
});
