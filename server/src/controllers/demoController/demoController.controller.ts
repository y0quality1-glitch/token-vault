import { PERMISSIONS } from '@token-vault/shared';
import { APP_ROUTES } from '../../core/AppRoutes';
import { orgCtx, requirePermission } from '../../middlewares/auth.middleware';
import DemoService from '../../services/demoService/demoService.service';
import { BaseController } from '../baseController';
import { adminGuards } from '../guards';

/**
 * /api/v1/demo (demonstration controls)
 *   POST /reset         restore the seeded demo state                       demo:reset
 *   POST /tamperAudit   edit the newest chained audit event in the database  demo:reset
 */
export class DemoController extends BaseController {
  constructor(private readonly service = new DemoService()) {
    super(APP_ROUTES.DEMO, 'Demo', adminGuards);
  }

  protected _initialiseRoutes(): void {
    this.route('post', '/reset', [requirePermission(PERMISSIONS.DEMO_RESET)], (req) => this.service.reset(orgCtx(req)));
    this.route('post', '/tamperAudit', [requirePermission(PERMISSIONS.DEMO_RESET)], (req) => this.service.tamperAudit(orgCtx(req)));
  }
}
