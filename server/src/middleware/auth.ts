import type { NextFunction, Request, Response } from 'express';
import { roleHas, type Organization, type Permission, type Role } from '@token-vault/shared';
import { config } from '../config';
import { forbidden, unauthorized } from '../lib/errors';
import { db, type UserRecord } from '../store/db';
import type { AdminContext } from '../types/express';

export function readCookie(req: Request, name: string): string | undefined {
  const header = req.headers.cookie;
  if (!header) return undefined;
  for (const part of header.split(';')) {
    const [k, ...v] = part.trim().split('=');
    if (k === name) return decodeURIComponent(v.join('='));
  }
  return undefined;
}

export function setSessionCookie(res: Response, sessionId: string) {
  res.cookie(config.sessionCookie, sessionId, {
    httpOnly: true, // not readable by browser JavaScript
    sameSite: 'strict',
    secure: config.cookieSecure,
    maxAge: config.sessionTtlMs,
    path: '/',
  });
}

export function clearSessionCookie(res: Response) {
  res.clearCookie(config.sessionCookie, { path: '/' });
}

/** Admin console session (httpOnly cookie). Agents never use this path. */
export function requireSession(req: Request, _res: Response, next: NextFunction) {
  const sid = readCookie(req, config.sessionCookie);
  const session = sid ? db.sessions.get(sid) : undefined;
  if (!session || session.expiresAt < Date.now()) {
    if (sid) db.sessions.delete(sid);
    throw unauthorized('Your session has expired. Please sign in again.');
  }
  const user = db.users.find((u) => u.id === session.userId && u.status === 'ACTIVE');
  if (!user) throw unauthorized();
  let org: Organization | null = null;
  let role: Role | null = null;
  if (session.organizationId) {
    const member = db.members.find((m) => m.userId === user.id && m.organizationId === session.organizationId);
    org = member ? db.organizations.find((o) => o.id === member.organizationId) ?? null : null;
    role = member?.role ?? null;
  }
  req.ctx = { session, user, org, role };
  next();
}

/** Requires an organization to be selected; enforces organization isolation downstream. */
export function requireOrg(req: Request, _res: Response, next: NextFunction) {
  if (!req.ctx?.org || !req.ctx.role) throw forbiddenNoOrg();
  next();
}

function forbiddenNoOrg() {
  const e = forbidden('Select an organization first');
  e.code = 'ORGANIZATION_REQUIRED';
  return e;
}

export function requirePermission(...permissions: Permission[]) {
  return (req: Request, _res: Response, next: NextFunction) => {
    const role = req.ctx?.role;
    if (!permissions.every((p) => roleHas(role, p))) {
      throw forbidden(`Your role (${role ?? 'none'}) does not allow this action. Required: ${permissions.join(', ')}`);
    }
    next();
  };
}

/** Narrowed accessor for handlers mounted after requireSession + requireOrg. */
export function orgCtx(req: Request): AdminContext & { org: Organization; role: Role; user: UserRecord } {
  const ctx = req.ctx;
  if (!ctx?.org || !ctx.role) throw forbiddenNoOrg();
  return ctx as AdminContext & { org: Organization; role: Role };
}
