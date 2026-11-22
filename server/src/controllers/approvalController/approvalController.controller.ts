import { PERMISSIONS } from '@token-vault/shared';
import { APP_ROUTES } from '../../core/AppRoutes';
import { orgCtx, requirePermission } from '../../middlewares/auth.middleware';
import ApprovalService from '../../services/approvalService/approvalService.service';
import { BaseController, bodyId } from '../baseController';
import { adminGuards } from '../guards';

/**
 * /api/v1/approval (operations held back by Require approval policies)
 *   POST /getall        { status? } with the number pending   any role
 *   GET  /getbyid/:id                                          any role
 *   POST /approve       { id, note? }                          grant:approve
 *   POST /reject        { id, note? }                          grant:approve
 * The decision body is validated by the approval service (shared with Slack approvals).
 */
export class ApprovalController extends BaseController {
  constructor(private readonly service = new ApprovalService()) {
    super(APP_ROUTES.APPROVAL, 'Approval', adminGuards);
  }

  protected _initialiseRoutes(): void {
    const decide = requirePermission(PERMISSIONS.GRANT_APPROVE);
    this.route('post', '/getall', [], (req) => this.service.list(orgCtx(req).org.id, (req.body ?? {}) as Record<string, unknown>));
    this.route('get', '/getbyid/:id', [], (req) => this.service.detail(orgCtx(req).org.id, String(req.params.id)));
    this.route('post', '/approve', [decide], (req) => this.service.approve(orgCtx(req), bodyId(req), req.body));
    this.route('post', '/reject', [decide], (req) => this.service.reject(orgCtx(req), bodyId(req), req.body));
  }
}
