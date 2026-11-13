import { ROLE_PERMISSIONS, type SessionInfo } from '@token-vault/shared';
import { config } from '../../config';
import type { LoginDto } from '../../databases/repository/auth/auth.dto';
import { verifySecret } from '../../lib/crypto';
import { HttpError, forbidden } from '../../lib/errors';
import { orgRepo, sessionRepo } from '../../store/repos';
import type { UserRecord } from '../../store/types';
import type { AdminContext } from '../../types/express';
import { createjwt } from '../../utils/jwt/jwt';
import { recordEvent } from '../auditService/auditService.service';

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

/** Console sign-in: a JWT session token, recorded (hashed) so logout and expiry end it server-side. */
export default class AuthService {
  /** Simple in-process throttle for failed sign-ins (per email). */
  private failures = new Map<string, { count: number; until: number }>();

  async login(body: LoginDto): Promise<{ token: string; info: SessionInfo }> {
    const email = body.email.toLowerCase();
    const f = this.failures.get(email);
    if (f && f.until > Date.now()) throw new HttpError(429, 'TOO_MANY_ATTEMPTS', 'Too many failed attempts. Try again in a minute.');
    const user = await orgRepo.findUserByEmail(email);
    if (!user || user.status !== 'ACTIVE' || !verifySecret(body.password, user.passwordHash)) {
      const count = (f?.count ?? 0) + 1;
      this.failures.set(email, { count, until: count >= 5 ? Date.now() + 60_000 : 0 });
      throw new HttpError(401, 'INVALID_CREDENTIALS', 'Invalid email or password');
    }
    this.failures.delete(email);
    const memberships = await orgRepo.membershipsForUser(user.id);
    const organizationId = memberships.length === 1 ? memberships[0]!.organizationId : null;
    const token = createjwt(user.id);
    await sessionRepo.createSession(token, user.id, organizationId, config.sessionTtlMs);
    for (const m of memberships) {
      await recordEvent({ orgId: m.organizationId, actor: { type: 'USER', id: user.id, name: user.fullName }, eventType: 'auth.login', target: { type: 'user', id: user.id, name: user.fullName }, metadata: { method: 'password' } });
    }
    return { token, info: await sessionInfo(user, organizationId) };
  }

  async logout(token: string | undefined) {
    if (token) await sessionRepo.deleteSession(token);
    return { ok: true };
  }

  /** POC placeholder: always the same answer, so it can't be used to find accounts. */
  forgotPassword() {
    return { ok: true, message: 'If an account exists, a reset link will be sent. (Placeholder in the POC: no email is sent.)' };
  }

  async selectOrganization(ctx: AdminContext, organizationId: string): Promise<SessionInfo> {
    if (!(await orgRepo.getMembership(ctx.user.id, organizationId))) throw forbidden('You are not a member of that organization');
    await sessionRepo.setSessionOrganization(ctx.session.tokenHash, organizationId);
    return sessionInfo(ctx.user, organizationId);
  }
}
