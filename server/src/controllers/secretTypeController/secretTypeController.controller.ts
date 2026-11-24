import { PERMISSIONS } from '@token-vault/shared';
import { APP_ROUTES } from '../../core/AppRoutes';
import { orgCtx, requirePermission } from '../../middlewares/auth.middleware';
import SecretTypeService from '../../services/secretTypeService/secretTypeService.service';
import { BaseController } from '../baseController';
import { adminGuards } from '../guards';

/**
 * /api/v1/secretType: secret types the control plane trusts (verified from the CMS catalog, or
 * predefined) and the organization's own types (spec 4.9.3 K).
 *   POST   /getall               every type (search, filters.category, includeArchived), categories, sync status   any role
 *   GET    /getbyid/:key         one type                                                                          any role
 *   POST   /saveCustom           a custom type (key "custom-…"), or its next version                              secret:manage_types
 *   DELETE /archiveCustom/:key   no new secrets of it (refused while secrets use it)                              secret:manage_types
 */
export class SecretTypeController extends BaseController {
  constructor(private readonly service = new SecretTypeService()) {
    super(APP_ROUTES.SECRET_TYPE, 'Secret type', adminGuards);
  }

  protected _initialiseRoutes(): void {
    this.route('post', '/getall', [], (req) => this.service.list(orgCtx(req).org.id, req.body ?? {}));
    this.route('get', '/getbyid/:key', [], (req) => this.service.get(orgCtx(req).org.id, String(req.params.key)));
    this.route('post', '/saveCustom', [requirePermission(PERMISSIONS.SECRET_MANAGE_TYPES)], (req) => this.service.saveCustom(orgCtx(req), req.body));
    this.route('delete', '/archiveCustom/:key', [requirePermission(PERMISSIONS.SECRET_MANAGE_TYPES)], (req) => this.service.archiveCustom(orgCtx(req), String(req.params.key)));
  }
}
