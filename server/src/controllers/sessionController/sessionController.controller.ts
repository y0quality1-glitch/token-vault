import { PERMISSIONS } from '@token-vault/shared';
import { APP_ROUTES } from '../../core/AppRoutes';
import { orgCtx, requirePermission } from '../../middlewares/auth.middleware';
import SessionService from '../../services/auditService/sessionService.service';
import { BaseController } from '../baseController';
import { adminGuards } from '../guards';

/**
 * /api/v1/session
 *   POST /getall        session summaries { agentId?, search?, limit? }                      audit:read
 *   POST /getdatabyid   one session's timeline and approvals { id: sessionId, agentId? }     audit:read
 */
export class SessionController extends BaseController {
  constructor(private readonly service = new SessionService()) {
    super(APP_ROUTES.SESSION, 'Session', adminGuards);
  }

  protected _initialiseRoutes(): void {
    const read = requirePermission(PERMISSIONS.AUDIT_READ);
    this.route('post', '/getall', [read], (req) => this.service.list(orgCtx(req).org.id, req.body ?? {}));
    this.route('post', '/getdatabyid', [read], (req) => {
      const body = (req.body ?? {}) as { id?: unknown; agentId?: unknown };
      // A missing or malformed id fails the session id check (400 "Not a session id"), as before.
      return this.service.get(orgCtx(req).org.id, typeof body.id === 'string' ? body.id : '', body.agentId);
    });
  }
}
