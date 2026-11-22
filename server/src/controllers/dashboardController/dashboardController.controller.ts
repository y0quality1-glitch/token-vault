import { APP_ROUTES } from '../../core/AppRoutes';
import { orgCtx } from '../../middlewares/auth.middleware';
import DashboardService from '../../services/dashboardService/dashboardService.service';
import { BaseController } from '../baseController';
import { adminGuards } from '../guards';

/**
 * /api/v1/dashboard
 *   POST /getdata   the dashboard summary   any role
 */
export class DashboardController extends BaseController {
  constructor(private readonly service = new DashboardService()) {
    super(APP_ROUTES.DASHBOARD, 'Dashboard', adminGuards);
  }

  protected _initialiseRoutes(): void {
    this.route('post', '/getdata', [], (req) => this.service.summary(orgCtx(req).org.id));
  }
}
