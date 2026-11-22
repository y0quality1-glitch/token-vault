import { PERMISSIONS } from '@token-vault/shared';
import { APP_ROUTES } from '../../core/AppRoutes';
import { UserIssuerDto, VerifyUserTokenDto } from '../../databases/repository/userIssuer/userIssuer.dto';
import { orgCtx, requirePermission } from '../../middlewares/auth.middleware';
import { validationMiddleware } from '../../middlewares/validation.middleware';
import UserIssuerService from '../../services/userIssuerService/userIssuerService.service';
import { BaseController, Reply } from '../baseController';
import { adminGuards } from '../guards';

/**
 * /api/v1/userIssuer
 *   POST   /getall        every user identity issuer of the organization   any role
 *   POST   /save          create (no id, 201) or update (id)               policy:manage
 *   DELETE /delete/:id    remove an issuer (details: null)                 policy:manage
 *   POST   /verifyToken   check a user token against the issuers           policy:manage
 */
export class UserIssuerController extends BaseController {
  constructor(private readonly service = new UserIssuerService()) {
    super(APP_ROUTES.USER_ISSUER, 'User issuer', adminGuards);
  }

  protected _initialiseRoutes(): void {
    this.route('post', '/getall', [], (req) => this.service.list(orgCtx(req).org.id, req.body ?? {}));
    this.route('post', '/save', [requirePermission(PERMISSIONS.POLICY_MANAGE), validationMiddleware(UserIssuerDto)], async (req) => {
      const { issuer, created } = await this.service.save(orgCtx(req), req.body as UserIssuerDto);
      return new Reply(issuer, created ? 201 : 200);
    });
    // Previously 204 with no body; the envelope needs a body, so 200 with details: null.
    this.route('delete', '/delete/:id', [requirePermission(PERMISSIONS.POLICY_MANAGE)], async (req) => {
      await this.service.remove(orgCtx(req), String(req.params.id));
      return null;
    });
    this.route('post', '/verifyToken', [requirePermission(PERMISSIONS.POLICY_MANAGE), validationMiddleware(VerifyUserTokenDto)], (req) => this.service.verifyToken(orgCtx(req).org.id, (req.body as VerifyUserTokenDto).token));
  }
}
