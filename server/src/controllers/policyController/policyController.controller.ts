import { PERMISSIONS } from '@token-vault/shared';
import { APP_ROUTES } from '../../core/AppRoutes';
import { PolicyDto } from '../../databases/repository/policy/policy.dto';
import { orgCtx, requirePermission } from '../../middlewares/auth.middleware';
import { validationMiddleware } from '../../middlewares/validation.middleware';
import PolicyService from '../../services/policyService/policyService.service';
import { BaseController, Reply } from '../baseController';
import { adminGuards } from '../guards';

/**
 * /api/v1/policy
 *   POST /getall   every policy of the organization        any role
 *   POST /save     create (no id, 201) or update (id)       policy:manage
 */
export class PolicyController extends BaseController {
  constructor(private readonly service = new PolicyService()) {
    super(APP_ROUTES.POLICY, 'Policy', adminGuards);
  }

  protected _initialiseRoutes(): void {
    this.route('post', '/getall', [], (req) => this.service.list(orgCtx(req).org.id));
    this.route('post', '/save', [requirePermission(PERMISSIONS.POLICY_MANAGE), validationMiddleware(PolicyDto)], async (req) => {
      const { policy, created } = await this.service.save(orgCtx(req), req.body as PolicyDto);
      return new Reply(policy, created ? 201 : 200);
    });
  }
}
