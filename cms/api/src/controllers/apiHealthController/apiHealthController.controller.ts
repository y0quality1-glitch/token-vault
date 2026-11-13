import { APP_ROUTES } from '../../core/AppRoutes';
import APIHealthCheckService from '../../services/apiHealthService/apiHealthService.service';
import { BaseController } from '../baseController';

/** GET /api/v1/apiHealthCheck/apihealth: no session needed; checks the database too. */
export class APIHealthCheckController extends BaseController {
  constructor(
    path: APP_ROUTES = APP_ROUTES.APIHEALTHCHECK,
    private readonly health = new APIHealthCheckService(),
  ) {
    super(path, null);
  }

  protected _initialiseRoutes(): void {
    this.route('get', '/apihealth', [], async (_req, res) => this.sendResponse(res, 'API Server is up and running successfully!', await this.health.apiHealthCheck()));
  }
}
