import { PERMISSIONS } from '@token-vault/shared';
import { APP_ROUTES } from '../../core/AppRoutes';
import { IntegrationAccessModeDto, IntegrationRotationPolicyDto, OAuthCancelDto, OAuthCompleteDto } from '../../databases/repository/integration/integration.dto';
import { orgCtx, requirePermission } from '../../middlewares/auth.middleware';
import { validationMiddleware } from '../../middlewares/validation.middleware';
import IntegrationService from '../../services/integrationService/integrationService.service';
import { BaseController, bodyId, created } from '../baseController';
import { adminGuards } from '../guards';

const manage = requirePermission(PERMISSIONS.INTEGRATION_MANAGE);

/**
 * /api/v1/integration
 *   POST   /getCatalog          the provider catalog with connected counts           any role
 *   POST   /getall              every integration of the organization                any role
 *   GET    /getbyid/:id         one integration with its granted agents              any role
 *   POST   /save                create (no id, 201; secret or GitHub App) or update  integration:manage
 *                               the metadata (id)
 *   POST   /oauthStart          OAuth connection step 1 (201, authorizeUrl)          integration:manage
 *   POST   /oauthComplete       OAuth connection step 2 (201, the integration)       integration:manage
 *   POST   /oauthCancel         drop a pending OAuth connection                      integration:manage
 *   POST   /setAccessMode       { id, accessMode }                                   integration:manage
 *   POST   /checkCredentials    re-test every stored credential now                  integration:manage
 *   POST   /setRotationPolicy   { id, intervalDays }                                 integration:manage
 *   POST   /test                { id }                                               integration:manage
 *   POST   /rotate              { id, secret | privateKey }                          integration:manage
 *   POST   /disable             { id }                                               integration:manage
 *   POST   /enable              { id }                                               integration:manage
 *   DELETE /delete/:id          soft delete, shred the credential, revoke grants     integration:manage
 */
export class IntegrationController extends BaseController {
  constructor(private readonly service = new IntegrationService()) {
    super(APP_ROUTES.INTEGRATION, 'Integration', adminGuards);
  }

  protected _initialiseRoutes(): void {
    this.route('post', '/getCatalog', [], (req) => this.service.catalog(orgCtx(req).org.id));
    this.route('post', '/getall', [], (req) => this.service.list(orgCtx(req).org.id));
    this.route('get', '/getbyid/:id', [], (req) => this.service.getById(orgCtx(req).org.id, String(req.params.id)));
    // The create body depends on the provider's auth method, so the service validates it.
    this.route('post', '/save', [manage], async (req) => {
      const ctx = orgCtx(req);
      if ((req.body as { id?: unknown } | undefined)?.id !== undefined) return this.service.updateMetadata(ctx, bodyId(req), req.body);
      return created(await this.service.create(ctx, req.body));
    });
    this.route('post', '/oauthStart', [manage], async (req) => created(await this.service.oauthStart(orgCtx(req), req.body)));
    this.route('post', '/oauthComplete', [manage, validationMiddleware(OAuthCompleteDto)], async (req) => {
      const { code, state } = req.body as OAuthCompleteDto;
      return created(await this.service.oauthComplete(orgCtx(req), code, state));
    });
    this.route('post', '/oauthCancel', [manage, validationMiddleware(OAuthCancelDto)], (req) => this.service.oauthCancel(orgCtx(req), (req.body as OAuthCancelDto).state));
    this.route('post', '/setAccessMode', [manage, validationMiddleware(IntegrationAccessModeDto)], (req) => {
      const { id, accessMode } = req.body as IntegrationAccessModeDto;
      return this.service.setAccessMode(orgCtx(req), id, accessMode);
    });
    this.route('post', '/checkCredentials', [manage], (req) => this.service.checkCredentials(orgCtx(req)));
    this.route('post', '/setRotationPolicy', [manage, validationMiddleware(IntegrationRotationPolicyDto)], (req) => {
      const { id, intervalDays } = req.body as IntegrationRotationPolicyDto;
      return this.service.setRotationPolicy(orgCtx(req), id, intervalDays);
    });
    this.route('post', '/test', [manage], (req) => this.service.test(orgCtx(req), bodyId(req)));
    this.route('post', '/rotate', [manage], (req) => this.service.rotate(orgCtx(req), bodyId(req), req.body));
    this.route('post', '/disable', [manage], (req) => this.service.setStatus(orgCtx(req), bodyId(req), 'DISABLED'));
    this.route('post', '/enable', [manage], (req) => this.service.setStatus(orgCtx(req), bodyId(req), 'CONNECTED'));
    this.route('delete', '/delete/:id', [manage], (req) => this.service.remove(orgCtx(req), String(req.params.id)));
  }
}

