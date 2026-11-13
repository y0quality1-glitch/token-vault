import { PERMISSIONS } from '@token-vault/shared';
import { APP_ROUTES } from '../../core/AppRoutes';
import { AgentDto, RotateCredentialDto } from '../../databases/repository/agent/agent.dto';
import { orgCtx, requirePermission } from '../../middlewares/auth.middleware';
import { validationMiddleware } from '../../middlewares/validation.middleware';
import AgentService from '../../services/agentService/agentService.service';
import { BaseController, Reply, bodyId } from '../baseController';
import { adminGuards } from '../guards';

/**
 * /api/v1/agent (admin API; the agent API itself is /agent/v1)
 *   POST /getall                    every agent of the organization                        any role
 *   GET  /getbyid/:id               agent with grants, recent activity and masked key      any role
 *   POST /save                      register (no id, 201, returns the key once) or update   agent:manage
 *   POST /rotateCredential          { id, graceMinutes? } new key                           agent:manage
 *   POST /revokePreviousCredential  { id } ends the rotation grace period now               agent:manage
 *   POST /disable                   { id }                                                  agent:manage
 *   POST /enable                    { id }                                                  agent:manage
 *   POST /revokeGrants              { id } revokes every live grant of the agent            grant:revoke
 * Developers may change only agents they own (agent:manage_any for others).
 */
export class AgentController extends BaseController {
  constructor(private readonly service = new AgentService()) {
    super(APP_ROUTES.AGENT, 'Agent', adminGuards);
  }

  protected _initialiseRoutes(): void {
    const manage = requirePermission(PERMISSIONS.AGENT_MANAGE);
    this.route('post', '/getall', [], (req) => this.service.list(orgCtx(req).org.id));
    this.route('get', '/getbyid/:id', [], (req) => this.service.detail(orgCtx(req).org.id, String(req.params.id)));
    this.route('post', '/save', [manage, validationMiddleware(AgentDto)], async (req) => {
      const { result, created } = await this.service.save(orgCtx(req), req.body as AgentDto);
      return new Reply(result, created ? 201 : 200);
    });
    this.route('post', '/rotateCredential', [manage, validationMiddleware(RotateCredentialDto)], (req) => {
      const body = req.body as RotateCredentialDto;
      return this.service.rotateCredential(orgCtx(req), body.id, body.graceMinutes);
    });
    this.route('post', '/revokePreviousCredential', [manage], (req) => this.service.revokePreviousCredential(orgCtx(req), bodyId(req)));
    this.route('post', '/disable', [manage], (req) => this.service.setStatus(orgCtx(req), bodyId(req), 'DISABLED'));
    this.route('post', '/enable', [manage], (req) => this.service.setStatus(orgCtx(req), bodyId(req), 'ACTIVE'));
    this.route('post', '/revokeGrants', [requirePermission(PERMISSIONS.GRANT_REVOKE)], (req) => this.service.revokeGrants(orgCtx(req), bodyId(req)));
  }
}
