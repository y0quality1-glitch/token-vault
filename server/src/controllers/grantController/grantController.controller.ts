import { PERMISSIONS } from '@token-vault/shared';
import { APP_ROUTES } from '../../core/AppRoutes';
import { ExtendGrantDto, GrantBatchDto, GrantDto, GrantVersionDto, RevokeGrantDto } from '../../databases/repository/grant/grant.dto';
import { orgCtx, requirePermission } from '../../middlewares/auth.middleware';
import { validationMiddleware } from '../../middlewares/validation.middleware';
import GrantService from '../../services/grantService/grantService.service';
import { BaseController, Reply, bodyId } from '../baseController';
import { adminGuards } from '../guards';

/**
 * /api/v1/grant
 *   POST /getall        { status?, agentId?, integrationId? }                          any role
 *   GET  /getbyid/:id   grant with usage, versions and matching policies              any role
 *   POST /save          create a grant (201)                                          grant:manage
 *   POST /savemulti     one agent, several integrations; all or none (201, { items })  grant:manage
 *   POST /revoke        { id, reason? }                                               grant:revoke
 *   POST /approve       { id } approve a grant pending approval                       grant:approve
 *   POST /extend        { id, expiresAt }                                             grant:manage
 *   POST /newVersion    { id, ...restrictions } supersedes the grant (201)            grant:manage
 *   POST /expireNow     { id } demo: expire the grant now                             grant:manage
 */
export class GrantController extends BaseController {
  constructor(private readonly service = new GrantService()) {
    super(APP_ROUTES.GRANT, 'Grant', adminGuards);
  }

  protected _initialiseRoutes(): void {
    const manage = requirePermission(PERMISSIONS.GRANT_MANAGE);
    this.route('post', '/getall', [], (req) => this.service.list(orgCtx(req).org.id, (req.body ?? {}) as Record<string, unknown>));
    this.route('get', '/getbyid/:id', [], (req) => this.service.detail(orgCtx(req).org.id, String(req.params.id)));
    this.route('post', '/save', [manage, validationMiddleware(GrantDto)], async (req) => new Reply(await this.service.create(orgCtx(req), req.body as GrantDto), 201));
    this.route('post', '/savemulti', [manage, validationMiddleware(GrantBatchDto)], async (req) => new Reply(await this.service.createMany(orgCtx(req), req.body as GrantBatchDto), 201));
    this.route('post', '/revoke', [requirePermission(PERMISSIONS.GRANT_REVOKE), validationMiddleware(RevokeGrantDto)], (req) => this.service.revoke(orgCtx(req), req.body as RevokeGrantDto));
    this.route('post', '/approve', [requirePermission(PERMISSIONS.GRANT_APPROVE)], (req) => this.service.approve(orgCtx(req), bodyId(req)));
    this.route('post', '/extend', [manage, validationMiddleware(ExtendGrantDto)], (req) => this.service.extend(orgCtx(req), req.body as ExtendGrantDto));
    this.route('post', '/newVersion', [manage, validationMiddleware(GrantVersionDto)], async (req) => new Reply(await this.service.newVersion(orgCtx(req), req.body as GrantVersionDto), 201));
    this.route('post', '/expireNow', [manage], (req) => this.service.expireNow(orgCtx(req), bodyId(req)));
  }
}
