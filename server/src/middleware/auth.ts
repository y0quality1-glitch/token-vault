import type { NextFunction, Request, Response } from 'express';
import { roleHas, type Organization, type Permission, type Role } from '@token-vault/shared';
import { config } from '../config';
import { forbidden, unauthorized } from '../lib/errors';
import { orgRepo, sessionRepo } from '../store/repos';
import type { UserRecord } from '../store/types';
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

export function setSessionCookie(res: Response, token: string) {
  res.cookie(config.sessionCookie, token, {
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

/** Admin console session (httpOnly cookie, hashed in the database). Agents never use this path. */
export async function requireSession(req: Request, _res: Response, next: NextFunction) {
  const token = readCookie(req, config.sessionCookie);
  const session = token ? await sessionRepo.getSession(token) : null;
  if (!session || new Date(session.expiresAt).getTime() < Date.now()) {
    if (token && session) await sessionRepo.deleteSession(token);
    throw unauthorized('Your session has expired. Please sign in again.');
  }
  const user = await orgRepo.getUser(session.userId);
  if (!user || user.status !== 'ACTIVE') throw unauthorized();
  let org: Organization | null = null;
  let role: Role | null = null;
  if (session.organizationId) {
    const member = await orgRepo.getMembership(user.id, session.organizationId);
    if (member) {
      org = await orgRepo.getOrganization(member.organizationId);
      role = member.role;
    }
  }
  req.ctx = { session, user, org, role };
  next();
}

function forbiddenNoOrg() {
  const e = forbidden('Select an organization first');
  e.code = 'ORGANIZATION_REQUIRED';
  return e;
}

/** Requires an organization to be selected; enforces organization isolation downstream. */
export function requireOrg(req: Request, _res: Response, next: NextFunction) {
  if (!req.ctx?.org || !req.ctx.role) throw forbiddenNoOrg();
  next();
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
