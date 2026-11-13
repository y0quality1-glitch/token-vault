import { PERMISSIONS } from '@token-vault/shared';
import { APP_ROUTES } from '../../core/AppRoutes';
import { orgCtx, requirePermission } from '../../middlewares/auth.middleware';
import AuditLogService from '../../services/auditService/auditLogService.service';
import AuditEventService from '../../services/auditEventService/auditEventService.service';
import { BaseController } from '../baseController';
import { adminGuards } from '../guards';

/**
 * /api/v1/auditEvent
 *   POST /getall            audit events, filtered by { category?, actorType?, eventType?, outcome?,
 *                           targetId?, from?, to?, search?, limit? }                        audit:read
 *   GET  /getbyid/:id       one audit event                                                 audit:read
 *   POST /verifyIntegrity   verifies both audit hash chains of the organization             audit:read
 */
export class AuditEventController extends BaseController {
  constructor(
    private readonly service = new AuditEventService(),
    private readonly integrity = new AuditLogService(),
  ) {
    super(APP_ROUTES.AUDIT_EVENT, 'Audit event', adminGuards);
  }

  protected _initialiseRoutes(): void {
    const read = requirePermission(PERMISSIONS.AUDIT_READ);
    this.route('post', '/getall', [read], (req) => this.service.list(orgCtx(req).org.id, req.body ?? {}));
    this.route('get', '/getbyid/:id', [read], (req) => this.service.getById(orgCtx(req).org.id, String(req.params.id)));
    this.route('post', '/verifyIntegrity', [read], (req) => this.integrity.verifyIntegrity(orgCtx(req).org.id));
  }
}
