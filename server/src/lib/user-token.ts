import { createHash, createPublicKey, verify as verifySignature, type KeyObject } from 'node:crypto';
import type { ActingUser } from '@token-vault/shared';

/**
 * User tokens: how an agent proves which user it acts for.
 *
 * The customer's application (or its identity provider) signs a short-lived JWT for the
 * signed-in user, and the agent passes it as `on_behalf_of`. Token Vault verifies it against
 * an issuer the organization registered, with that issuer's PUBLIC key: only asymmetric
 * algorithms are accepted, so nothing stored in Token Vault can mint a user token.
 *
 * Claims: iss, aud, sub, exp (required); iat, nbf, email, name, the groups claim (default
 * "groups"), and "token_vault": { operations?: string[], resources?: string[] } (what this
 * user may let an agent do, see shared/acting-user.ts).
 */

const ALGORITHMS: Record<string, { hash: string | null; keyType: string; curve?: string; ieee?: boolean }> = {
  RS256: { hash: 'sha256', keyType: 'rsa' },
  RS384: { hash: 'sha384', keyType: 'rsa' },
  RS512: { hash: 'sha512', keyType: 'rsa' },
  ES256: { hash: 'sha256', keyType: 'ec', curve: 'prime256v1', ieee: true },
  ES384: { hash: 'sha384', keyType: 'ec', curve: 'secp384r1', ieee: true },
  EdDSA: { hash: null, keyType: 'ed25519' },
};
export const USER_TOKEN_ALGORITHMS = Object.keys(ALGORITHMS);

export const USER_TOKEN_LIMITS = {
  MAX_TOKEN_LENGTH: 8192,
  CLOCK_SKEW_S: 60,
  MAX_GROUPS: 100,
  MAX_PERMISSION_ENTRIES: 100,
  MIN_LIFETIME_S: 60,
  MAX_LIFETIME_S: 24 * 3600,
} as const;

// ---------------------------------------------------------------- public keys
/** Parses a public key given as PEM or JWK (JSON). Private keys are refused: Token Vault must never hold one. */
export function parsePublicKey(text: string): { ok: true; key: KeyObject; fingerprint: string; type: string } | { ok: false; reason: string } {
  const t = text.trim();
  if (!t) return { ok: false, reason: 'Paste the public key (PEM or JWK).' };
  if (/PRIVATE KEY/.test(t)) return { ok: false, reason: 'This is a private key. Paste only the public key: the private key stays with your identity provider.' };
  let key: KeyObject;
  try {
    if (t.startsWith('{')) {
      const jwk = JSON.parse(t) as Record<string, unknown>;
      if (['d', 'p', 'q', 'dp', 'dq', 'qi', 'k'].some((f) => f in jwk)) return { ok: false, reason: 'This JWK contains private or secret key material. Paste only the public key.' };
      key = createPublicKey({ key: jwk as never, format: 'jwk' });
    } else {
      key = createPublicKey(t);
    }
  } catch {
    return { ok: false, reason: 'Not a valid public key. Use a PEM block (-----BEGIN PUBLIC KEY-----) or a JWK.' };
  }
  const type = key.asymmetricKeyType ?? 'unknown';
  if (!['rsa', 'ec', 'ed25519'].includes(type)) return { ok: false, reason: `Unsupported key type ${type}: use RSA, EC (P-256 or P-384) or Ed25519.` };
  if (type === 'rsa' && (key.asymmetricKeyDetails?.modulusLength ?? 0) < 2048) return { ok: false, reason: 'RSA keys must be at least 2048 bits.' };
  if (type === 'ec' && !['prime256v1', 'secp384r1'].includes(key.asymmetricKeyDetails?.namedCurve ?? '')) return { ok: false, reason: 'EC keys must use P-256 or P-384.' };
  const der = key.export({ type: 'spki', format: 'der' });
  const hex = createHash('sha256').update(der).digest('hex').slice(0, 32);
  return { ok: true, key, type, fingerprint: `SHA256:${hex.match(/../g)!.join(':')}` };
}

// ---------------------------------------------------------------- verification
export interface TrustedIssuer {
  id: string;
  issuer: string;
  audience: string;
  publicKey: string;
  groupsClaim: string;
  maxTokenLifetimeSeconds: number;
  enabled: boolean;
}

export type UserTokenResult = { ok: true; user: ActingUser; /** When the token expires (ISO). */ expiresAt: string } | { ok: false; reason: string; issuerId?: string };

const b64urlJson = (part: string): Record<string, unknown> | null => {
  if (!/^[A-Za-z0-9_-]+$/.test(part)) return null;
  try {
    const v = JSON.parse(Buffer.from(part, 'base64url').toString('utf8'));
    return v && typeof v === 'object' && !Array.isArray(v) ? v : null;
  } catch {
    return null;
  }
};

const shortString = (v: unknown, max: number): string | null => (typeof v === 'string' && v.length > 0 && v.length <= max ? v : null);

function stringList(v: unknown, max: number, label: string): { ok: true; list: string[] } | { ok: false; reason: string } {
  if (v === undefined || v === null) return { ok: true, list: [] };
  const arr = typeof v === 'string' ? [v] : v;
  if (!Array.isArray(arr) || !arr.every((x) => typeof x === 'string' && x.length > 0 && x.length <= 200)) return { ok: false, reason: `The ${label} claim must be a list of strings.` };
  if (arr.length > max) return { ok: false, reason: `The ${label} claim has more than ${max} entries.` };
  return { ok: true, list: arr as string[] };
}

/**
 * Verifies a user token against the organization's issuers. Every failure is a reason the
 * request is denied (USER_TOKEN_INVALID); the reason never echoes the token.
 */
export function verifyUserToken(token: string, issuers: TrustedIssuer[], now = Date.now()): UserTokenResult {
  if (token.length > USER_TOKEN_LIMITS.MAX_TOKEN_LENGTH) return { ok: false, reason: 'The user token is too long.' };
  const parts = token.split('.');
  if (parts.length !== 3) return { ok: false, reason: 'The user token is not a JWT (header.payload.signature).' };
  const [h, p, sig] = parts as [string, string, string];
  const header = b64urlJson(h);
  const claims = b64urlJson(p);
  if (!header || !claims) return { ok: false, reason: 'The user token is not a valid JWT.' };
  const alg = typeof header.alg === 'string' ? header.alg : '';
  const spec = ALGORITHMS[alg];
  if (!spec) return { ok: false, reason: `User tokens must be signed with ${USER_TOKEN_ALGORITHMS.join(', ')} (got "${alg || 'none'}").` };

  const iss = typeof claims.iss === 'string' ? claims.iss : '';
  const issuer = issuers.find((i) => i.issuer === iss);
  if (!issuer) return { ok: false, reason: `The user token's issuer "${iss.slice(0, 200)}" is not registered in this organization.` };
  if (!issuer.enabled) return { ok: false, reason: `The issuer "${iss}" is disabled in this organization.`, issuerId: issuer.id };

  const parsed = parsePublicKey(issuer.publicKey);
  if (!parsed.ok) return { ok: false, reason: `The issuer "${iss}" has an unusable public key.`, issuerId: issuer.id };
  if (parsed.type !== spec.keyType || (spec.curve && parsed.key.asymmetricKeyDetails?.namedCurve !== spec.curve)) {
    return { ok: false, reason: `The user token uses ${alg}, which does not match the issuer's ${parsed.type} key.`, issuerId: issuer.id };
  }
  if (!/^[A-Za-z0-9_-]+$/.test(sig)) return { ok: false, reason: 'The user token signature is invalid.', issuerId: issuer.id };
  const valid = verifySignature(spec.hash, Buffer.from(`${h}.${p}`), spec.ieee ? { key: parsed.key, dsaEncoding: 'ieee-p1363' } : parsed.key, Buffer.from(sig, 'base64url'));
  if (!valid) return { ok: false, reason: 'The user token signature is invalid.', issuerId: issuer.id };

  // Signature is valid: the claims come from the issuer. Now check they apply here and now.
  const aud = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
  if (!aud.includes(issuer.audience)) return { ok: false, reason: `The user token is not addressed to this organization (aud must include "${issuer.audience}").`, issuerId: issuer.id };
  const nowS = Math.floor(now / 1000);
  const skew = USER_TOKEN_LIMITS.CLOCK_SKEW_S;
  if (typeof claims.exp !== 'number') return { ok: false, reason: 'The user token has no expiry (exp).', issuerId: issuer.id };
  if (claims.exp + skew <= nowS) return { ok: false, reason: `The user token expired at ${new Date(claims.exp * 1000).toISOString()}.`, issuerId: issuer.id };
  if (typeof claims.nbf === 'number' && claims.nbf - skew > nowS) return { ok: false, reason: 'The user token is not valid yet (nbf).', issuerId: issuer.id };
  if (claims.iat !== undefined && (typeof claims.iat !== 'number' || claims.iat - skew > nowS)) return { ok: false, reason: 'The user token was issued in the future (iat).', issuerId: issuer.id };
  const lifetime = claims.exp - (typeof claims.iat === 'number' ? claims.iat : nowS);
  if (lifetime > issuer.maxTokenLifetimeSeconds) return { ok: false, reason: `The user token is valid for ${lifetime} seconds; this issuer allows at most ${issuer.maxTokenLifetimeSeconds}.`, issuerId: issuer.id };

  const sub = shortString(claims.sub, 256);
  if (!sub) return { ok: false, reason: 'The user token has no subject (sub).', issuerId: issuer.id };
  const groups = stringList(claims[issuer.groupsClaim], USER_TOKEN_LIMITS.MAX_GROUPS, issuer.groupsClaim);
  if (!groups.ok) return { ok: false, reason: groups.reason, issuerId: issuer.id };

  let permissions: ActingUser['permissions'] = null;
  const tv = claims.token_vault;
  if (tv !== undefined && tv !== null) {
    if (typeof tv !== 'object' || Array.isArray(tv)) return { ok: false, reason: 'The token_vault claim must be an object.', issuerId: issuer.id };
    const t = tv as Record<string, unknown>;
    permissions = {};
    for (const field of ['operations', 'resources'] as const) {
      if (t[field] === undefined) continue;
      const list = stringList(t[field], USER_TOKEN_LIMITS.MAX_PERMISSION_ENTRIES, `token_vault.${field}`);
      if (!list.ok) return { ok: false, reason: list.reason, issuerId: issuer.id };
      permissions[field] = list.list;
    }
  }

  return {
    ok: true,
    user: {
      sub,
      email: shortString(claims.email, 320),
      name: shortString(claims.name, 200),
      groups: groups.list,
      ...(permissions ? { permissions } : {}),
      issuerId: issuer.id,
      issuer: issuer.issuer,
    },
    expiresAt: new Date(claims.exp * 1000).toISOString(),
  };
}
