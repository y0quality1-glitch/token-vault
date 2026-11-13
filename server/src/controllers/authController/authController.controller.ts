import { APP_ROUTES } from '../../core/AppRoutes';
import { ForgotPasswordDto, LoginDto, SelectOrganizationDto } from '../../databases/repository/auth/auth.dto';
import { clearSessionCookie, requireSession, sessionToken, setSessionCookie } from '../../middlewares/auth.middleware';
import { validationMiddleware } from '../../middlewares/validation.middleware';
import AuthService, { sessionInfo } from '../../services/authService/authService.service';
import { BaseController } from '../baseController';

/**
 * /api/v1/auth
 *   POST /login               email + password: session (httpOnly cookie; never in the body)
 *   POST /logout              ends the session
 *   POST /forgotPassword      placeholder
 *   GET  /me                  the signed-in user, memberships, current organization and permissions
 *   POST /selectOrganization  switch the session's organization
 */
export class AuthController extends BaseController {
  constructor(private readonly service = new AuthService()) {
    super(APP_ROUTES.AUTH, 'Session');
  }

  protected _initialiseRoutes(): void {
    this.route('post', '/login', [validationMiddleware(LoginDto)], async (req, res) => {
      const { token, info } = await this.service.login(req.body as LoginDto);
      setSessionCookie(res, token);
      return info;
    });
    this.route('post', '/logout', [], async (req, res) => {
      const out = await this.service.logout(sessionToken(req));
      clearSessionCookie(res);
      return out;
    });
    this.route('post', '/forgotPassword', [validationMiddleware(ForgotPasswordDto)], () => this.service.forgotPassword());
    this.route('get', '/me', [requireSession], (req) => sessionInfo(req.ctx!.user, req.ctx!.org?.id ?? null));
    this.route('post', '/selectOrganization', [requireSession, validationMiddleware(SelectOrganizationDto)], (req) => this.service.selectOrganization(req.ctx!, (req.body as SelectOrganizationDto).organizationId));
  }
}
