import { LessThan } from 'typeorm';
import type { CmsSession } from '@token-vault/shared';
import { SESSION_TTL_S } from '../../config';
import { ServiceError } from '../../core/ApiError';
import { sha256Hex, verifyPassword } from '../../core/Crypto';
import AppDatabase from '../../databases/database';
import type { LoginDto } from '../../databases/repository/auth/auth.dto';
import { UserEntity } from '../../entities/userEntity';
import { UserLoginsEntity } from '../../entities/userLoginsEntity';
import { toUser } from '../../middlewares/auth.middleware';
import { createjwt } from '../../utils/jwt/jwt';
import { audit } from '../auditService/auditService.service';

const LOCKOUT_AFTER = 5;
const LOCKOUT_MS = 60_000;

/** Sign-in: a JWT session token, recorded (as a hash) so logout and expiry end it server-side. */
export default class AuthService {
  private failures = new Map<string, { count: number; until: number }>();

  async login(body: LoginDto): Promise<{ token: string; session: CmsSession }> {
    const f = this.failures.get(body.email);
    if (f && f.until > Date.now()) throw new ServiceError('E30002');
    const m = AppDatabase.getInstance().manager;
    const user = await m.findOneBy(UserEntity, { email: body.email });
    if (!user || !verifyPassword(body.password, user.password_hash)) {
      const count = (f?.count ?? 0) + 1;
      this.failures.set(body.email, { count, until: count >= LOCKOUT_AFTER ? Date.now() + LOCKOUT_MS : 0 });
      throw new ServiceError('E30001');
    }
    this.failures.delete(body.email);
    const token = createjwt(user);
    const t = Date.now();
    await m.delete(UserLoginsEntity, { expires_at: LessThan(new Date(t).toISOString()) });
    await m.insert(UserLoginsEntity, { token_hash: sha256Hex(token), user_id: user.id, expires_at: new Date(t + SESSION_TTL_S * 1000).toISOString(), created_at: new Date(t).toISOString() });
    await audit(m, { id: user.id, fullName: user.full_name }, 'auth.login');
    return { token, session: { user: toUser(user) } };
  }

  async logout(token: string | undefined): Promise<void> {
    if (token) await AppDatabase.getInstance().manager.delete(UserLoginsEntity, { token_hash: sha256Hex(token) });
  }
}
