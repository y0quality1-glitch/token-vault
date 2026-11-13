import jwt from 'jsonwebtoken';
import { randomUUID } from 'node:crypto';
import { JWT_ISSUER, JWT_SECRET_KEY, SESSION_TTL_S } from '../../config';

/** Claims of a CMS session token. `type` keeps it from being accepted as any other kind of token. */
export interface SessionClaims {
  sub: string;
  role: string;
  type: 'cms_session';
  jti: string;
  iat: number;
  exp: number;
}

/** Signs a session token for a user (HS256, SESSION_TTL_S). */
export const createjwt = (user: { id: string; role: string }): string =>
  jwt.sign({ role: user.role, type: 'cms_session' }, JWT_SECRET_KEY, { algorithm: 'HS256', subject: user.id, issuer: JWT_ISSUER, expiresIn: SESSION_TTL_S, jwtid: randomUUID() });

/**
 * Verifies signature, algorithm, issuer and expiry, or returns null. Expiry is checked here,
 * before any database lookup (template fix B-08: no `ignoreExpiration`).
 */
export function verifyjwt(token: string): SessionClaims | null {
  try {
    const claims = jwt.verify(token, JWT_SECRET_KEY, { algorithms: ['HS256'], issuer: JWT_ISSUER }) as SessionClaims;
    return claims.type === 'cms_session' && typeof claims.sub === 'string' ? claims : null;
  } catch {
    return null;
  }
}
