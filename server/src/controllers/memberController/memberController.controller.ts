import { PERMISSIONS } from '@token-vault/shared';
import { APP_ROUTES } from '../../core/AppRoutes';
import { MemberDto } from '../../databases/repository/member/member.dto';
import { orgCtx, requirePermission } from '../../middlewares/auth.middleware';
import { validationMiddleware } from '../../middlewares/validation.middleware';
import MemberService from '../../services/memberService/memberService.service';
import { BaseController } from '../baseController';
import { adminGuards } from '../guards';

/**
 * /api/v1/member (members of the current organization)
 *   POST /getall   every member                           any role
 *   POST /save     change a role `{ id: memberId, role }`  members:manage
 */
export class MemberController extends BaseController {
  constructor(private readonly service = new MemberService()) {
    super(APP_ROUTES.MEMBER, 'Member', adminGuards);
  }

  protected _initialiseRoutes(): void {
    this.route('post', '/getall', [], (req) => this.service.list(orgCtx(req).org.id, req.body ?? {}));
    this.route('post', '/save', [requirePermission(PERMISSIONS.MEMBERS_MANAGE), validationMiddleware(MemberDto)], (req) => this.service.setRole(orgCtx(req), req.body as MemberDto));
  }
}
