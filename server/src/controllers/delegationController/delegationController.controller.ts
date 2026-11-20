import { PERMISSIONS } from '@token-vault/shared';
import { APP_ROUTES } from '../../core/AppRoutes';
import { orgCtx, requirePermission } from '../../middlewares/auth.middleware';
import DelegationService from '../../services/delegationService/delegationService.service';
import { BaseController, bodyId } from '../baseController';
import { adminGuards } from '../guards';

/**
 * /api/v1/delegation (sub-agent delegations; the agent side is /agent/v1/delegation)
 *   POST /getall   { agentId?, grantId? }                                          any role
 *   POST /revoke   { id, reason } stops the delegation and everything below it      grant:revoke
 * The revoke body is validated by the delegation service.
 */
export class DelegationController extends BaseController {
  constructor(private readonly service = new DelegationService()) {
    super(APP_ROUTES.DELEGATION, 'Delegation', adminGuards);
  }

  protected _initialiseRoutes(): void {
    this.route('post', '/getall', [], (req) => this.service.list(orgCtx(req).org.id, (req.body ?? {}) as Record<string, unknown>));
    this.route('post', '/revoke', [requirePermission(PERMISSIONS.GRANT_REVOKE)], (req) => this.service.revoke(orgCtx(req), bodyId(req), req.body));
  }
}
