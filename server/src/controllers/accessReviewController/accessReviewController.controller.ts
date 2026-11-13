import { PERMISSIONS } from '@token-vault/shared';
import { APP_ROUTES } from '../../core/AppRoutes';
import { CertifyDto } from '../../databases/repository/accessReview/accessReview.dto';
import { orgCtx, requirePermission } from '../../middlewares/auth.middleware';
import { validationMiddleware } from '../../middlewares/validation.middleware';
import AccessReviewService from '../../services/accessReviewService/accessReviewService.service';
import { BaseController } from '../baseController';
import { adminGuards } from '../guards';

/**
 * /api/v1/accessReview (recertification of active grants)
 *   POST /getdata   the review `{ summary?: "1" }` (counts only)   any role
 *   POST /certify   keep grants `{ grantIds, note? }`              grant:revoke
 */
export class AccessReviewController extends BaseController {
  constructor(private readonly service = new AccessReviewService()) {
    super(APP_ROUTES.ACCESS_REVIEW, 'Access review', adminGuards);
  }

  protected _initialiseRoutes(): void {
    this.route('post', '/getdata', [], (req) => {
      const summary = (req.body as { summary?: unknown } | undefined)?.summary;
      return this.service.getData(orgCtx(req).org.id, summary === '1');
    });
    this.route('post', '/certify', [requirePermission(PERMISSIONS.GRANT_REVOKE), validationMiddleware(CertifyDto)], (req) => this.service.certify(orgCtx(req), req.body as CertifyDto));
  }
}
