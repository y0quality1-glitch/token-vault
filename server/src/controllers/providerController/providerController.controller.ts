import { APP_ROUTES } from '../../core/AppRoutes';
import ProviderService from '../../services/providerService/providerService.service';
import { BaseController } from '../baseController';
import { adminGuards } from '../guards';

/**
 * /api/v1/provider (providers the control plane trusts: bundled or verified from the CMS catalog)
 *   POST /getall          every provider and the catalog sync status   any role
 *   GET  /getbyid/:key    one provider                                 any role
 */
export class ProviderController extends BaseController {
  constructor(private readonly service = new ProviderService()) {
    super(APP_ROUTES.PROVIDER, 'Provider', adminGuards);
  }

  protected _initialiseRoutes(): void {
    this.route('post', '/getall', [], () => this.service.list());
    this.route('get', '/getbyid/:key', [], (req) => this.service.get(String(req.params.key)));
  }
}
