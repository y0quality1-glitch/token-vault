import { APP_ROUTES } from '../../core/AppRoutes';
import { orgCtx } from '../../middlewares/auth.middleware';
import AgentService from '../../services/agentService/agentService.service';
import { BaseController } from '../baseController';
import { adminGuards } from '../guards';

/**
 * /api/v1/apiClient
 *   POST /getall   issued agent credentials (metadata and masked key, never the secret)   any role
 */
export class ApiClientController extends BaseController {
  constructor(private readonly service = new AgentService()) {
    super(APP_ROUTES.API_CLIENT, 'API client', adminGuards);
  }

  protected _initialiseRoutes(): void {
    this.route('post', '/getall', [], (req) => this.service.listApiClients(orgCtx(req).org.id));
  }
}
