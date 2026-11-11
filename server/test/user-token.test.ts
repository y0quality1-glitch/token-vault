import { createHmac, generateKeyPairSync, sign, type KeyObject } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { parsePublicKey, verifyUserToken, type TrustedIssuer } from '../src/lib/user-token';

const now = Date.parse('2026-11-11T12:00:00Z');
const nowS = now / 1000;
const b64 = (v: unknown) => Buffer.from(JSON.stringify(v)).toString('base64url');

function jwt(alg: string, key: KeyObject, claims: Record<string, unknown>, header: Record<string, unknown> = {}) {
  const h = b64({ alg, typ: 'JWT', ...header });
  const p = b64(claims);
  const data = Buffer.from(`${h}.${p}`);
  const sig = alg === 'EdDSA' ? sign(null, data, key) : alg.startsWith('ES') ? sign('sha256', data, { key, dsaEncoding: 'ieee-p1363' }) : sign('sha256', data, key);
  return `${h}.${p}.${sig.toString('base64url')}`;
}

const rsa = generateKeyPairSync('rsa', { modulusLength: 2048 });
const ec = generateKeyPairSync('ec', { namedCurve: 'P-256' });
const ed = generateKeyPairSync('ed25519');
const pem = (k: KeyObject) => k.export({ type: 'spki', format: 'pem' }).toString();

const issuer = (overrides: Partial<TrustedIssuer> = {}): TrustedIssuer => ({
  id: 'uis_1',
  issuer: 'https://login.example.com',
  audience: 'token-vault',
  publicKey: pem(rsa.publicKey),
  groupsClaim: 'groups',
  maxTokenLifetimeSeconds: 3600,
  enabled: true,
  ...overrides,
});
const claims = (overrides: Record<string, unknown> = {}) => ({ iss: 'https://login.example.com', aud: 'token-vault', sub: 'u_ada', email: 'ada@example.com', name: 'Ada', groups: ['engineering'], iat: nowS - 60, exp: nowS + 600, ...overrides });

describe('user tokens', () => {
  it('accepts RS256, ES256 and EdDSA tokens from a registered issuer and returns the user', () => {
    const r = verifyUserToken(jwt('RS256', rsa.privateKey, claims({ token_vault: { operations: ['github:write'], resources: ['demo-org/*'] } })), [issuer()], now);
    expect(r).toEqual({ ok: true, user: { sub: 'u_ada', email: 'ada@example.com', name: 'Ada', groups: ['engineering'], permissions: { operations: ['github:write'], resources: ['demo-org/*'] }, issuerId: 'uis_1', issuer: 'https://login.example.com' }, expiresAt: new Date((nowS + 600) * 1000).toISOString() });
    expect(verifyUserToken(jwt('ES256', ec.privateKey, claims()), [issuer({ publicKey: pem(ec.publicKey) })], now).ok).toBe(true);
    expect(verifyUserToken(jwt('EdDSA', ed.privateKey, claims()), [issuer({ publicKey: pem(ed.publicKey) })], now).ok).toBe(true);
    // A JWK works as well as PEM.
    const jwk = JSON.stringify(ec.publicKey.export({ format: 'jwk' }));
    expect(verifyUserToken(jwt('ES256', ec.privateKey, claims()), [issuer({ publicKey: jwk })], now).ok).toBe(true);
  });

  it('rejects forged, foreign, expired and over-long tokens', () => {
    const reason = (token: string, issuers = [issuer()]) => {
      const r = verifyUserToken(token, issuers, now);
      return r.ok ? 'ok' : r.reason;
    };
    const other = generateKeyPairSync('rsa', { modulusLength: 2048 });
    expect(reason(jwt('RS256', other.privateKey, claims()))).toContain('signature is invalid');
    expect(reason(jwt('RS256', rsa.privateKey, claims({ iss: 'https://evil.example.com' })))).toContain('not registered');
    expect(reason(jwt('RS256', rsa.privateKey, claims()), [issuer({ enabled: false })])).toContain('disabled');
    expect(reason(jwt('RS256', rsa.privateKey, claims({ aud: 'someone-else' })))).toContain('aud must include');
    expect(reason(jwt('RS256', rsa.privateKey, claims({ aud: ['x', 'token-vault'] })))).toBe('ok');
    expect(reason(jwt('RS256', rsa.privateKey, claims({ exp: nowS - 120 })))).toContain('expired');
    expect(reason(jwt('RS256', rsa.privateKey, claims({ exp: undefined })))).toContain('no expiry');
    expect(reason(jwt('RS256', rsa.privateKey, claims({ nbf: nowS + 600 })))).toContain('not valid yet');
    expect(reason(jwt('RS256', rsa.privateKey, claims({ iat: nowS, exp: nowS + 7200 })))).toContain('at most 3600');
    expect(reason(jwt('RS256', rsa.privateKey, claims({ sub: '' })))).toContain('no subject');
    expect(reason(jwt('RS256', rsa.privateKey, claims({ groups: [1, 2] })))).toContain('list of strings');
    expect(reason(jwt('RS256', rsa.privateKey, claims({ token_vault: { operations: 'x'.repeat(300) } })))).toContain('token_vault.operations');
    expect(reason('not-a-jwt')).toContain('not a JWT');
    expect(reason('a'.repeat(9000))).toContain('too long');
  });

  it('refuses unsigned and symmetric tokens, and keys that do not match the algorithm', () => {
    const reason = (token: string, issuers = [issuer()]) => {
      const r = verifyUserToken(token, issuers, now);
      return r.ok ? 'ok' : r.reason;
    };
    const unsigned = `${b64({ alg: 'none' })}.${b64(claims())}.`;
    expect(reason(unsigned)).toContain('must be signed with');
    // HS256 with the public key as the HMAC secret (classic algorithm confusion) is refused.
    const h = b64({ alg: 'HS256' });
    const p = b64(claims());
    const hs = createHmac('sha256', pem(rsa.publicKey)).update(`${h}.${p}`).digest('base64url');
    expect(reason(`${h}.${p}.${hs}`)).toContain('must be signed with');
    expect(reason(jwt('ES256', ec.privateKey, claims()))).toContain('does not match');
  });

  it('accepts only public keys', () => {
    expect(parsePublicKey(rsa.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString())).toMatchObject({ ok: false, reason: expect.stringContaining('private key') });
    expect(parsePublicKey(JSON.stringify(ec.privateKey.export({ format: 'jwk' })))).toMatchObject({ ok: false, reason: expect.stringContaining('private') });
    expect(parsePublicKey('hello')).toMatchObject({ ok: false });
    const small = generateKeyPairSync('rsa', { modulusLength: 1024 });
    expect(parsePublicKey(pem(small.publicKey))).toMatchObject({ ok: false, reason: expect.stringContaining('2048') });
    const ok = parsePublicKey(pem(rsa.publicKey));
    expect(ok).toMatchObject({ ok: true, type: 'rsa', fingerprint: expect.stringMatching(/^SHA256:([0-9a-f]{2}:){15}[0-9a-f]{2}$/) });
  });
});
