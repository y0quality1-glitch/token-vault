import { APP_ROUTES } from '../../core/AppRoutes';
import { db } from '../../databases/client';
import { BaseController } from '../baseController';

/** GET /api/v1/apiHealthCheck/apihealth: no session needed; checks the database too. */
export class APIHealthCheckController extends BaseController {
  constructor() {
    super(APP_ROUTES.APIHEALTHCHECK, 'Health');
  }
  protected _initialiseRoutes(): void {
    this.route('get', '/apihealth', [], async () => {
      await db.query('SELECT 1');
      return { service: 'token-vault-control-plane', database: 'ok' };
    });
  }
}
