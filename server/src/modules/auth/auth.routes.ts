import { Router } from 'express';
import { z } from 'zod';
import { ROLE_PERMISSIONS, type SessionInfo } from '@token-vault/shared';
import { config } from '../../config';
import { randomToken, verifySecret } from '../../lib/crypto';
import { HttpError, forbidden } from '../../lib/errors';
import { parse } from '../../lib/validate';
import { clearSessionCookie, readCookie, requireSession, setSessionCookie } from '../../middleware/auth';
import { orgRepo, sessionRepo } from '../../store/repos';
import type { UserRecord } from '../../store/types';
import { recordEvent } from '../audit/audit.service';

export const authRouter = Router();

export async function sessionInfo(user: UserRecord, organizationId: string | null): Promise<SessionInfo> {
  const memberships = await orgRepo.membershipsForUser(user.id);
  const current = organizationId ? memberships.find((m) => m.organizationId === organizationId) : undefined;
  const { passwordHash: _ph, ...publicUser } = user;
  return {
    user: publicUser,
    memberships,
    currentOrganization: current ? await orgRepo.getOrganization(current.organizationId) : null,
    role: current?.role ?? null,
    permissions: current ? ROLE_PERMISSIONS[current.role] : [],
  };
}

// Simple in-process throttle for failed sign-ins (per email).
const failures = new Map<string, { count: number; until: number }>();

authRouter.post('/login', async (req, res) => {
  const body = parse(z.object({ email: z.string().email('Enter a valid email address'), password: z.string().min(1, 'Password is required') }), req.body);
  const email = body.email.toLowerCase();
  const f = failures.get(email);
  if (f && f.until > Date.now()) throw new HttpError(429, 'TOO_MANY_ATTEMPTS', 'Too many failed attempts. Try again in a minute.');

  const user = await orgRepo.findUserByEmail(email);
  if (!user || user.status !== 'ACTIVE' || !verifySecret(body.password, user.passwordHash)) {
    const count = (f?.count ?? 0) + 1;
    failures.set(email, { count, until: count >= 5 ? Date.now() + 60_000 : 0 });
    throw new HttpError(401, 'INVALID_CREDENTIALS', 'Invalid email or password');
  }
  failures.delete(email);

  const memberships = await orgRepo.membershipsForUser(user.id);
  const organizationId = memberships.length === 1 ? memberships[0]!.organizationId : null;
  const token = randomToken(32);
  await sessionRepo.createSession(token, user.id, organizationId, config.sessionTtlMs);
  setSessionCookie(res, token);
  for (const m of memberships) {
    await recordEvent({ orgId: m.organizationId, actor: { type: 'USER', id: user.id, name: user.fullName }, eventType: 'auth.login', target: { type: 'user', id: user.id, name: user.fullName }, metadata: { method: 'password' } });
  }
  res.json(await sessionInfo(user, organizationId));
});

authRouter.post('/logout', async (req, res) => {
  const token = readCookie(req, config.sessionCookie);
  if (token) await sessionRepo.deleteSession(token);
  clearSessionCookie(res);
  res.json({ ok: true });
});

authRouter.post('/forgot-password', (req, res) => {
  parse(z.object({ email: z.string().email('Enter a valid email address') }), req.body);
  // POC placeholder: always respond identically to avoid account enumeration.
  res.json({ ok: true, message: 'If an account exists, a reset link will be sent. (Placeholder in the POC: no email is sent.)' });
});

authRouter.get('/me', requireSession, async (req, res) => {
  res.json(await sessionInfo(req.ctx!.user, req.ctx!.org?.id ?? null));
});

authRouter.post('/select-organization', requireSession, async (req, res) => {
  const { organizationId } = parse(z.object({ organizationId: z.string().min(1) }), req.body);
  const ctx = req.ctx!;
  if (!(await orgRepo.getMembership(ctx.user.id, organizationId))) throw forbidden('You are not a member of that organization');
  await sessionRepo.setSessionOrganization(ctx.session.tokenHash, organizationId);
  res.json(await sessionInfo(ctx.user, organizationId));
});
