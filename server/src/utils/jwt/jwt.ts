import jwt from 'jsonwebtoken';
import { randomUUID } from 'node:crypto';
import { config } from '../../config';

const ISSUER = 'token-vault-console';

/** Claims of an admin session token. `type` keeps it from being accepted as any other token. */
export interface SessionClaims {
  sub: string;
  type: 'tv_session';
  jti: string;
  iat: number;
  exp: number;
}

/** Signs a session token for a user (template: utils/jwt createjwt). */
export const createjwt = (userId: string): string =>
  jwt.sign({ type: 'tv_session' }, config.sessionJwtSecret, { algorithm: 'HS256', subject: userId, issuer: ISSUER, expiresIn: Math.floor(config.sessionTtlMs / 1000), jwtid: randomUUID() });

/**
 * Verifies signature, algorithm, issuer and expiry, or returns null. Expiry is checked before
 * any database lookup (template fix B-08: no ignoreExpiration).
 */
export function verifyjwt(token: string): SessionClaims | null {
  try {
    const claims = jwt.verify(token, config.sessionJwtSecret, { algorithms: ['HS256'], issuer: ISSUER }) as SessionClaims;
    return claims.type === 'tv_session' && typeof claims.sub === 'string' ? claims : null;
  } catch {
    return null;
  }
}
