import { APP_ROUTES } from '../../core/AppRoutes';
import authMiddleware from '../../middlewares/auth.middleware';
import AuditService from '../../services/auditService/auditService.service';
import { BaseController } from '../baseController';

/** POST /api/v1/audit/getall: newest first; `application` limits it to one key, `search` matches action, actor and key. */
export class AuditController extends BaseController {
  constructor(path: APP_ROUTES = APP_ROUTES.AUDIT, service = new AuditService()) {
    super(path, service);
  }

  protected _initialiseRoutes(): void {
    this.route('post', '/getall', [authMiddleware], (req, res) => this.getAll(req, res));
  }
}
