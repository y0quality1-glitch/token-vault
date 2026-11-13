import { PERMISSIONS } from '@token-vault/shared';
import { APP_ROUTES } from '../../core/AppRoutes';
import { EmergencyStopDto, LiftEmergencyStopDto, OrganizationDto } from '../../databases/repository/organization/organization.dto';
import { orgCtx, requirePermission } from '../../middlewares/auth.middleware';
import { validationMiddleware } from '../../middlewares/validation.middleware';
import OrganizationService from '../../services/organizationService/organizationService.service';
import { BaseController, Reply } from '../baseController';
import { adminGuards } from '../guards';

/**
 * /api/v1/organization (the organization selected in the session)
 *   POST /getdata             the organization                                   any role
 *   POST /save                name and environment                               org:manage
 *   POST /getEmergencyStop    emergency stop state                               any role
 *   POST /emergencyStop       deny every agent request `{ reason }`              grant:revoke
 *   POST /liftEmergencyStop   restore access exactly as it was `{ note? }`       grant:approve
 */
export class OrganizationController extends BaseController {
  constructor(private readonly service = new OrganizationService()) {
    super(APP_ROUTES.ORGANIZATION, 'Organization', adminGuards);
  }

  protected _initialiseRoutes(): void {
    this.route('post', '/getdata', [], (req) => orgCtx(req).org);
    this.route('post', '/save', [requirePermission(PERMISSIONS.ORG_MANAGE), validationMiddleware(OrganizationDto)], async (req) => {
      // Always an update of the current organization (there is no id to tell it apart from a create).
      return new Reply(await this.service.update(orgCtx(req), req.body as OrganizationDto), 200, 'Organization Updated Successfully');
    });
    this.route('post', '/getEmergencyStop', [], (req) => this.service.stopView(orgCtx(req).org.id));
    this.route('post', '/emergencyStop', [requirePermission(PERMISSIONS.GRANT_REVOKE), validationMiddleware(EmergencyStopDto)], (req) => this.service.emergencyStop(orgCtx(req), req.body as EmergencyStopDto));
    this.route('post', '/liftEmergencyStop', [requirePermission(PERMISSIONS.GRANT_APPROVE), validationMiddleware(LiftEmergencyStopDto)], (req) =>
      this.service.liftEmergencyStop(orgCtx(req), req.body as LiftEmergencyStopDto),
    );
  }
}
