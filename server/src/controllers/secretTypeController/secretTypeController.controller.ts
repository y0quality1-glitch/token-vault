import { APP_ROUTES } from '../../core/AppRoutes';
import SecretTypeService from '../../services/secretTypeService/secretTypeService.service';
import { BaseController } from '../baseController';
import { adminGuards } from '../guards';

/**
 * /api/v1/secretType (secret types the control plane trusts: verified from the CMS catalog, or predefined)
 *   POST /getall          every type (search, filters.category), categories and sync status   any role
 *   GET  /getbyid/:key    one type                                                            any role
 */
export class SecretTypeController extends BaseController {
  constructor(private readonly service = new SecretTypeService()) {
    super(APP_ROUTES.SECRET_TYPE, 'Secret type', adminGuards);
  }

  protected _initialiseRoutes(): void {
    this.route('post', '/getall', [], (req) => this.service.list(req.body ?? {}));
    this.route('get', '/getbyid/:key', [], (req) => this.service.get(String(req.params.key)));
  }
}
