import { createHash, createPrivateKey, createPublicKey, hkdfSync, sign, type KeyObject } from 'node:crypto';
import { canonicalJson, type DecisionTokenClaims } from '@token-vault/shared';
import { config } from '../config';

/**
 * Decision tokens: what Token Vault hands the caller when an integration is not brokered
 * (DECISION_ONLY, SHORT_LIVED_CREDENTIAL). A compact JWS signed with Ed25519 ("EdDSA"), so the
 * application side can check a decision with the public key alone (GET /.well-known/jwks.json).
 *
 * The key is derived (HKDF, its own label) from DECISION_SIGNING_KEY, or from AUDIT_SIGNING_KEY
 * when that is unset. The key id is a fingerprint of the public key, so a new key shows up in the
 * key set under a new kid and verifiers that fetch the key set follow without configuration.
 */
const PKCS8_ED25519_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');

let cached: { material: string; privateKey: KeyObject; jwk: Record<string, string> } | null = null;

function signingKey() {
  const material = config.decisionSigningKey || config.auditSigningKey;
  if (cached?.material === material) return cached;
  const seed = Buffer.from(hkdfSync('sha256', material, 'token-vault', 'token-vault/decision-token/v1', 32));
  const privateKey = createPrivateKey({ key: Buffer.concat([PKCS8_ED25519_PREFIX, seed]), format: 'der', type: 'pkcs8' });
  const pub = createPublicKey(privateKey).export({ format: 'jwk' }) as { kty: string; crv: string; x: string };
  const kid = `tvd_${createHash('sha256').update(pub.x).digest('hex').slice(0, 16)}`;
  cached = { material, privateKey, jwk: { kty: pub.kty, crv: pub.crv, x: pub.x, kid, alg: 'EdDSA', use: 'sig' } };
  return cached;
}

/** The public key set verifiers use (JWKS). */
export function decisionJwks(): { keys: Record<string, string>[] } {
  return { keys: [signingKey().jwk] };
}

/** SHA-256 (hex) of the canonical JSON of a request input, as carried in `input_sha256`. */
export function inputDigest(input: unknown): string {
  return createHash('sha256').update(canonicalJson(input ?? {})).digest('hex');
}

export function signDecisionToken(claims: DecisionTokenClaims): string {
  const k = signingKey();
  const header = { alg: 'EdDSA', typ: 'tv-decision+jwt', kid: k.jwk.kid };
  const enc = (v: unknown) => Buffer.from(JSON.stringify(v)).toString('base64url');
  const signingInput = `${enc(header)}.${enc(claims)}`;
  return `${signingInput}.${sign(null, Buffer.from(signingInput), k.privateKey).toString('base64url')}`;
}
