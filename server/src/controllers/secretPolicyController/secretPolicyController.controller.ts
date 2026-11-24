import { PERMISSIONS } from '@token-vault/shared';
import { APP_ROUTES } from '../../core/AppRoutes';
import { SaveSecretPolicyDto } from '../../databases/repository/secret/secretLifecycle.dto';
import { orgCtx, requirePermission } from '../../middlewares/auth.middleware';
import { validationMiddleware } from '../../middlewares/validation.middleware';
import SecretPolicyService from '../../services/secretPolicyService/secretPolicyService.service';
import { BaseController } from '../baseController';
import { adminGuards } from '../guards';

/**
 * /api/v1/secretPolicy: expiry and version retention by organization, project or workspace
 * (spec 4.9.12, 4.9.8). The most specific level that sets a value wins.
 *   POST   /getall        every policy of the organization                                   secret:read_metadata
 *   POST   /save          `{scope, project?, workspace?, expiryWarningDays?, defaultExpiresInDays?,
 *                          keepVersions?, keepDays?}` (replaces that level's policy; all empty removes it)   secret:manage_versions
 *   DELETE /delete/:id                                                                        secret:manage_versions
 */
export class SecretPolicyController extends BaseController {
  constructor(private readonly service = new SecretPolicyService()) {
    super(APP_ROUTES.SECRET_POLICY, 'Secret policy', adminGuards);
  }

  protected _initialiseRoutes(): void {
    const P = PERMISSIONS;
    this.route('post', '/getall', [requirePermission(P.SECRET_READ_METADATA)], (req) => this.service.list(orgCtx(req).org.id));
    this.route('post', '/save', [requirePermission(P.SECRET_MANAGE_VERSIONS), validationMiddleware(SaveSecretPolicyDto)], (req) => this.service.save(orgCtx(req), req.body as SaveSecretPolicyDto));
    this.route('delete', '/delete/:id', [requirePermission(P.SECRET_MANAGE_VERSIONS)], (req) => this.service.remove(orgCtx(req), String(req.params.id)));
  }
}
