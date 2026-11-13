import { PERMISSIONS } from '@token-vault/shared';
import { APP_ROUTES } from '../../core/AppRoutes';
import { orgCtx, requirePermission } from '../../middlewares/auth.middleware';
import GrantRequestService from '../../services/grantRequestService/grantRequestService.service';
import { BaseController, bodyId } from '../baseController';
import { adminGuards } from '../guards';

/**
 * /api/v1/grantRequest (just-in-time access requests from agents)
 *   POST /getall        { status? } with the number pending                                     any role
 *   GET  /getbyid/:id                                                                            any role
 *   POST /approve       { id, durationMinutes, operations?, repositories?, rateLimitPerMinute?, note? }  grant:approve
 *   POST /reject        { id, note? }                                                            grant:approve
 * The decision bodies are validated by the grant request service (shared with the agent API).
 */
export class GrantRequestController extends BaseController {
  constructor(private readonly service = new GrantRequestService()) {
    super(APP_ROUTES.GRANT_REQUEST, 'Access request', adminGuards);
  }

  protected _initialiseRoutes(): void {
    const decide = requirePermission(PERMISSIONS.GRANT_APPROVE);
    this.route('post', '/getall', [], (req) => this.service.list(orgCtx(req).org.id, (req.body ?? {}) as Record<string, unknown>));
    this.route('get', '/getbyid/:id', [], (req) => this.service.detail(orgCtx(req).org.id, String(req.params.id)));
    this.route('post', '/approve', [decide], (req) => this.service.approve(orgCtx(req), bodyId(req), req.body));
    this.route('post', '/reject', [decide], (req) => this.service.reject(orgCtx(req), bodyId(req), req.body));
  }
}
