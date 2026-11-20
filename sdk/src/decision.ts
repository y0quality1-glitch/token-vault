import { createHash, createPublicKey, verify, type JsonWebKey } from 'node:crypto';
import { canonicalJson, type DecisionTokenClaims } from '@token-vault/shared';
import { TokenVaultError } from './errors';

/** A decision token that is forged, expired, or does not match the call it is presented for. */
export class DecisionTokenError extends TokenVaultError {}

export interface VerifyDecisionOptions {
  /** Token Vault's public keys: a JWKS object, or the URL of /.well-known/jwks.json (fetched and cached for 5 minutes). */
  keys: { keys: JsonWebKey[] } | string;
  /** When given, the token must be for exactly this call. */
  expect?: { operation?: string; resource?: Record<string, string>; input?: unknown; integrationId?: string; orgId?: string };
  /** Allowed clock difference in seconds (default 30). */
  clockSkewS?: number;
  now?: () => number;
}

const cache = new Map<string, { at: number; jwks: { keys: JsonWebKey[] } }>();

async function keySet(keys: VerifyDecisionOptions['keys'], refresh = false): Promise<{ keys: JsonWebKey[] }> {
  if (typeof keys !== 'string') return keys;
  const hit = cache.get(keys);
  if (hit && !refresh && Date.now() - hit.at < 300_000) return hit.jwks;
  const res = await fetch(keys);
  if (!res.ok) throw new DecisionTokenError(`Could not load Token Vault's keys from ${keys} (HTTP ${res.status})`, { code: 'JWKS_UNAVAILABLE', httpStatus: res.status });
  const jwks = (await res.json()) as { keys: JsonWebKey[] };
  cache.set(keys, { at: Date.now(), jwks });
  return jwks;
}

const fail = (message: string, code: string): never => {
  throw new DecisionTokenError(message, { code, httpStatus: 401 });
};

/**
 * Verifies a decision token Token Vault issued for an integration in decision-only or
 * short-lived credential mode, the way an application or API gateway would before acting on it:
 * signature (Ed25519, key looked up by kid), expiry, and optionally that it covers exactly the
 * operation, resource and input of the call at hand. Returns the claims; throws DecisionTokenError.
 *
 * A token can be presented more than once until it expires; reject a repeated `jti` if your
 * application must act on each decision only once.
 */
export async function verifyDecisionToken(token: string, options: VerifyDecisionOptions): Promise<DecisionTokenClaims> {
  const parts = token.split('.');
  if (parts.length !== 3) fail('Not a decision token', 'MALFORMED');
  const [h, p, s] = parts as [string, string, string];
  let header: { alg?: string; typ?: string; kid?: string };
  let claims: DecisionTokenClaims;
  try {
    header = JSON.parse(Buffer.from(h, 'base64url').toString('utf8'));
    claims = JSON.parse(Buffer.from(p, 'base64url').toString('utf8'));
  } catch {
    return fail('Not a decision token', 'MALFORMED');
  }
  if (header.alg !== 'EdDSA' || header.typ !== 'tv-decision+jwt' || !header.kid) fail('Not a Token Vault decision token', 'MALFORMED');

  let jwk = (await keySet(options.keys)).keys.find((k) => (k as { kid?: string }).kid === header.kid);
  // A key Token Vault started using after the key set was cached: fetch it once more.
  if (!jwk && typeof options.keys === 'string') jwk = (await keySet(options.keys, true)).keys.find((k) => (k as { kid?: string }).kid === header.kid);
  if (!jwk) fail(`Unknown signing key ${header.kid}`, 'UNKNOWN_KEY');
  if (!verify(null, Buffer.from(`${h}.${p}`), createPublicKey({ key: jwk!, format: 'jwk' }), Buffer.from(s, 'base64url'))) fail('Signature does not verify', 'BAD_SIGNATURE');

  const now = Math.floor((options.now?.() ?? Date.now()) / 1000);
  const skew = options.clockSkewS ?? 30;
  if (typeof claims.exp !== 'number' || claims.exp + skew < now) fail('The decision has expired', 'EXPIRED');
  if (typeof claims.iat === 'number' && claims.iat - skew > now) fail('The decision is not valid yet', 'NOT_YET_VALID');

  const e = options.expect;
  if (e?.operation !== undefined && claims.operation !== e.operation) fail(`The decision is for ${claims.operation}, not ${e.operation}`, 'MISMATCH');
  if (e?.integrationId !== undefined && claims.integration_id !== e.integrationId) fail('The decision is for another integration', 'MISMATCH');
  if (e?.orgId !== undefined && claims.org_id !== e.orgId) fail('The decision is for another organization', 'MISMATCH');
  if (e?.resource !== undefined && canonicalJson(claims.resource) !== canonicalJson(e.resource)) fail('The decision is for another resource', 'MISMATCH');
  if (e && 'input' in e && createHash('sha256').update(canonicalJson(e.input ?? {})).digest('hex') !== claims.input_sha256) fail('The decision was made for a different input', 'MISMATCH');
  return claims;
}
