import type { CmsSession } from '@token-vault/shared';
import { COOKIE_SECURE, SESSION_COOKIE, SESSION_TTL_S } from '../../config';
import { APP_ROUTES } from '../../core/AppRoutes';
import { LoginDto } from '../../databases/repository/auth/auth.dto';
import authMiddleware, { sessionToken } from '../../middlewares/auth.middleware';
import { validationMiddleware } from '../../middlewares/validation.middleware';
import AuthService from '../../services/authService/authService.service';
import { BaseController } from '../baseController';

/**
 * Sign-in. The session token (JWT) is set only as an httpOnly, SameSite=Strict cookie, so page
 * scripts never see it (it is not in the response body). API clients take it from Set-Cookie
 * and may send it back as the cookie or as `Authorization: Bearer <token>`.
 */
export class AuthController extends BaseController {
  constructor(
    path: APP_ROUTES = APP_ROUTES.AUTH,
    private readonly auth = new AuthService(),
  ) {
    super(path, null);
  }

  protected _initialiseRoutes(): void {
    this.route('post', '/login', [validationMiddleware(LoginDto)], async (req, res) => {
      const { token, session } = await this.auth.login(req.body as LoginDto);
      res.cookie(SESSION_COOKIE, token, { httpOnly: true, sameSite: 'strict', secure: COOKIE_SECURE, maxAge: SESSION_TTL_S * 1000, path: '/' });
      this.sendResponse<CmsSession>(res, 'Signed in', session);
    });
    this.route('post', '/logout', [], async (req, res) => {
      await this.auth.logout(sessionToken(req));
      res.clearCookie(SESSION_COOKIE, { path: '/' });
      this.sendResponse(res, 'Signed out', { ok: true });
    });
    this.route('get', '/me', [authMiddleware], (req, res) => this.sendResponse<CmsSession>(res, 'Session', { user: req.user! }));
  }
}
