import { describe, expect, it } from 'vitest';
import { createHash, generateKeyPairSync, sign, type JsonWebKey } from 'node:crypto';
import { canonicalJson, type DecisionTokenClaims } from '@token-vault/shared';
import { DecisionTokenError, verifyDecisionToken } from '../src';

const { privateKey, publicKey } = generateKeyPairSync('ed25519');
const jwk = { ...(publicKey.export({ format: 'jwk' }) as JsonWebKey), kid: 'tvd_test', alg: 'EdDSA' };
const keys = { keys: [jwk] };
const input = { title: 'Ship it' };
const now = Math.floor(Date.now() / 1000);

function token(over: Partial<DecisionTokenClaims> = {}, header: Record<string, string> = {}): string {
  const claims: DecisionTokenClaims = {
    iss: 'https://vault.example', sub: 'agt_1', jti: 'req_1', iat: now, exp: now + 120, org_id: 'org_1', integration_id: 'int_1', provider: 'github',
    operation: 'github.issues.create', resource: { repository: 'demo-org/demo-repo' }, input_sha256: createHash('sha256').update(canonicalJson(input)).digest('hex'), mode: 'DECISION_ONLY', ...over,
  };
  const enc = (v: unknown) => Buffer.from(JSON.stringify(v)).toString('base64url');
  const si = `${enc({ alg: 'EdDSA', typ: 'tv-decision+jwt', kid: 'tvd_test', ...header })}.${enc(claims)}`;
  return `${si}.${sign(null, Buffer.from(si), privateKey).toString('base64url')}`;
}

describe('verifyDecisionToken', () => {
  it('accepts a valid token for exactly this call and returns its claims', async () => {
    const claims = await verifyDecisionToken(token(), { keys, expect: { operation: 'github.issues.create', resource: { repository: 'demo-org/demo-repo' }, input } });
    expect(claims).toMatchObject({ sub: 'agt_1', jti: 'req_1', mode: 'DECISION_ONLY' });
  });

  it.each([
    ['an edited token', () => token().replace(/\.[^.]+\./, `.${Buffer.from(JSON.stringify({ operation: 'github.repos.delete' })).toString('base64url')}.`), {}, 'BAD_SIGNATURE'],
    ['an unknown key', () => token({}, { kid: 'tvd_other' }), {}, 'UNKNOWN_KEY'],
    ['an expired decision', () => token({ iat: now - 600, exp: now - 300 }), {}, 'EXPIRED'],
    ['another operation', () => token(), { operation: 'github.issues.list' }, 'MISMATCH'],
    ['another resource', () => token(), { resource: { repository: 'demo-org/other' } }, 'MISMATCH'],
    ['a different input', () => token(), { input: { title: 'Something else' } }, 'MISMATCH'],
    ['not a token', () => 'abc', {}, 'MALFORMED'],
  ])('rejects %s', async (_name, make, expectOpt, code) => {
    await expect(verifyDecisionToken(make(), { keys, expect: expectOpt })).rejects.toSatisfy((e) => e instanceof DecisionTokenError && e.code === code);
  });
});
