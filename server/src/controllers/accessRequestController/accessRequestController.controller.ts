import { PERMISSIONS } from '@token-vault/shared';
import { APP_ROUTES } from '../../core/AppRoutes';
import { orgCtx, requirePermission } from '../../middlewares/auth.middleware';
import AccessRequestService from '../../services/accessRequestService/accessRequestService.service';
import { BaseController } from '../baseController';
import { adminGuards } from '../guards';

/**
 * /api/v1/accessRequest
 *   POST /getall        access requests, filtered by { agentId?, integrationId?, grantId?, decision?,
 *                       operation?, from?, to?, search?, user?, sessionId?, limit? }        audit:read
 *   GET  /getbyid/:id   one access request with its correlated audit events                  audit:read
 */
export class AccessRequestController extends BaseController {
  constructor(private readonly service = new AccessRequestService()) {
    super(APP_ROUTES.ACCESS_REQUEST, 'Access request', adminGuards);
  }

  protected _initialiseRoutes(): void {
    const read = requirePermission(PERMISSIONS.AUDIT_READ);
    this.route('post', '/getall', [read], (req) => this.service.list(orgCtx(req).org.id, req.body ?? {}));
    this.route('get', '/getbyid/:id', [read], (req) => this.service.getById(orgCtx(req).org.id, String(req.params.id)));
  }
}
