import type { NextFunction, Request, Response } from 'express';
import type { CmsRole, CmsUser } from '@token-vault/shared';
import { SESSION_COOKIE } from '../config';
import { ServiceError, handleError } from '../core/ApiError';
import { sha256Hex } from '../core/Crypto';
import AppDatabase from '../databases/database';
import { UserEntity } from '../entities/userEntity';
import { UserLoginsEntity } from '../entities/userLoginsEntity';
import { verifyjwt } from '../utils/jwt/jwt';

declare module 'express-serve-static-core' {
  interface Request {
    user?: CmsUser;
    /** The verified session token (for logout). */
    sessionToken?: string;
  }
}

export function readCookie(req: Request, name: string): string | undefined {
  for (const part of (req.headers.cookie ?? '').split(';')) {
    const [k, ...v] = part.trim().split('=');
    if (k === name) return decodeURIComponent(v.join('='));
  }
  return undefined;
}

/** The session token: `Authorization: Bearer <jwt>` (API clients) or the httpOnly cookie (the CMS UI). */
export function sessionToken(req: Request): string | undefined {
  const bearer = /^Bearer\s+(\S+)$/i.exec(req.headers.authorization ?? '')?.[1];
  return bearer ?? readCookie(req, SESSION_COOKIE);
}

export const toUser = (u: UserEntity): CmsUser => ({ id: u.id, email: u.email, fullName: u.full_name, role: u.role });

/**
 * Authentication (template: middlewares/auth.middleware.ts). The JWT's signature and expiry are
 * checked first, then the session row (logout and expiry end a session server-side) and the
 * user. One indexed lookup by token hash; the user is attached as `req.user`, never merged into
 * the request body.
 */
const authMiddleware = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
  try {
    const token = sessionToken(req);
    if (!token) throw new ServiceError('E10002');
    const claims = verifyjwt(token);
    if (!claims) throw new ServiceError('E30003');
    const db = AppDatabase.getInstance().manager;
    const session = await db.findOneBy(UserLoginsEntity, { token_hash: sha256Hex(token) });
    if (!session || session.user_id !== claims.sub || new Date(session.expires_at).getTime() < Date.now()) throw new ServiceError('E30003');
    const user = await db.findOneBy(UserEntity, { id: claims.sub });
    if (!user) throw new ServiceError('E30003');
    req.user = toUser(user);
    req.sessionToken = token;
    next();
  } catch (e) {
    handleError(e, res);
  }
};

export default authMiddleware;

/** Only these roles may use the route (after authMiddleware). */
export function requireRole(...roles: CmsRole[]) {
  return (req: Request, res: Response, next: NextFunction): void => {
    if (!req.user || !roles.includes(req.user.role)) return void handleError(new ServiceError('E30004', `Requires role ${roles.join(' or ')}`), res);
    next();
  };
}

export const editors = requireRole('EDITOR', 'ADMIN');
export const reviewers = requireRole('PUBLISHER', 'ADMIN');
export const admins = requireRole('ADMIN');
