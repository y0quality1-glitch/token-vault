import type { Organization, Role } from '@token-vault/shared';
import type { SessionRecord, UserRecord } from '../store/db';

export interface AdminContext {
  session: SessionRecord;
  user: UserRecord;
  org: Organization | null;
  role: Role | null;
}

declare global {
  namespace Express {
    interface Request {
      ctx?: AdminContext;
    }
  }
}
