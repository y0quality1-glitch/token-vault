import { eq, lt } from 'drizzle-orm';
import { Router, type NextFunction, type Request, type Response } from 'express';
import { z } from 'zod';
import type { CmsRole, CmsSession, CmsUser } from '@token-vault/shared';
import { config } from '../config';
import { db } from '../db/client';
import { sessions, users } from '../db/schema';
import { randomToken, sha256Hex, verifyPassword } from '../lib/crypto';
import { HttpError, forbidden, parse, unauthorized } from '../lib/http';
import { audit } from './audit';

declare module 'express-serve-static-core' {
  interface Request {
    user?: CmsUser;
  }
}

function readCookie(req: Request, name: string): string | undefined {
  for (const part of (req.headers.cookie ?? '').split(';')) {
    const [k, ...v] = part.trim().split('=');
    if (k === name) return decodeURIComponent(v.join('='));
  }
  return undefined;
}

const toUser = (u: typeof users.$inferSelect): CmsUser => ({ id: u.id, email: u.email, fullName: u.fullName, role: u.role });

/** Session cookie (httpOnly, SameSite=Strict); only its SHA-256 is stored. */
export async function requireSession(req: Request, _res: Response, next: NextFunction) {
  const token = readCookie(req, config.sessionCookie);
  if (!token) throw unauthorized();
  const [row] = await db.select().from(sessions).innerJoin(users, eq(users.id, sessions.userId)).where(eq(sessions.tokenHash, sha256Hex(token)));
  if (!row || new Date(row.cms_sessions.expiresAt).getTime() < Date.now()) throw unauthorized('Your session has expired. Please sign in again.');
  req.user = toUser(row.cms_users);
  next();
}

export function requireRole(...roles: CmsRole[]) {
  return (req: Request, _res: Response, next: NextFunction) => {
    if (!req.user || !roles.includes(req.user.role)) throw forbidden(`Requires role ${roles.join(' or ')}`);
    next();
  };
}

export const authRouter = Router();
const failures = new Map<string, { count: number; until: number }>();

authRouter.post('/login', async (req, res) => {
  const body = parse(z.object({ email: z.string().email('Enter a valid email address'), password: z.string().min(1, 'Password is required') }), req.body);
  const email = body.email.toLowerCase();
  const f = failures.get(email);
  if (f && f.until > Date.now()) throw new HttpError(429, 'TOO_MANY_ATTEMPTS', 'Too many failed attempts. Try again in a minute.');
  const [user] = await db.select().from(users).where(eq(users.email, email));
  if (!user || !verifyPassword(body.password, user.passwordHash)) {
    const count = (f?.count ?? 0) + 1;
    failures.set(email, { count, until: count >= 5 ? Date.now() + 60_000 : 0 });
    throw new HttpError(401, 'INVALID_CREDENTIALS', 'Invalid email or password');
  }
  failures.delete(email);
  const token = randomToken();
  const now = Date.now();
  await db.delete(sessions).where(lt(sessions.expiresAt, new Date(now).toISOString()));
  await db.insert(sessions).values({ tokenHash: sha256Hex(token), userId: user.id, expiresAt: new Date(now + config.sessionTtlMs).toISOString(), createdAt: new Date(now).toISOString() });
  await audit(db, user, 'auth.login');
  res.cookie(config.sessionCookie, token, { httpOnly: true, sameSite: 'strict', secure: config.cookieSecure, maxAge: config.sessionTtlMs, path: '/' });
  const session: CmsSession = { user: toUser(user) };
  res.json(session);
});

authRouter.post('/logout', async (req, res) => {
  const token = readCookie(req, config.sessionCookie);
  if (token) await db.delete(sessions).where(eq(sessions.tokenHash, sha256Hex(token)));
  res.clearCookie(config.sessionCookie, { path: '/' });
  res.json({ ok: true });
});

authRouter.get('/me', requireSession, (req, res) => {
  const session: CmsSession = { user: req.user! };
  res.json(session);
});
