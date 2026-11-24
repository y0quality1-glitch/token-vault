import type { Request, Response } from 'express';
import { PERMISSIONS } from '@token-vault/shared';
import { AGENT_ROUTES, APP_ROUTES } from '../../core/AppRoutes';
import { CreateSecretGrantDto, SecretApprovalDecisionDto, SecretGrantRevokeDto } from '../../databases/repository/secret/secretAccess.dto';
import { normalizeIp } from '../../lib/net';
import { orgCtx, requirePermission } from '../../middlewares/auth.middleware';
import { validationMiddleware } from '../../middlewares/validation.middleware';
import SecretAccessService from '../../services/secretAccessService/secretAccessService.service';
import { BaseController, Reply } from '../baseController';
import { adminGuards } from '../guards';

/**
 * /api/v1/secretAccess: which agents may retrieve which secrets (spec 4.9.9, 4.9.15)
 *   POST /getall          `{secretId?, agentId?, status?}` grants (a secret's list includes covering selectors)   secret:read_metadata
 *   POST /save            grant an agent one secret or a selector (201)                                          secret:manage_access
 *   POST /revoke          `{id, reason?}`                                                                        secret:manage_access
 *   POST /getApprovals    `{status?}` retrievals held for approval                                               secret:read_metadata
 *   POST /approve         `{id, note?}` (not by the agent's owner)                                               secret:manage_access
 *   POST /reject          `{id, note?}`                                                                          secret:manage_access
 */
export class SecretAccessController extends BaseController {
  constructor(private readonly service = new SecretAccessService()) {
    super(APP_ROUTES.SECRET_ACCESS, 'Secret access', adminGuards);
  }

  protected _initialiseRoutes(): void {
    const P = PERMISSIONS;
    this.route('post', '/getall', [requirePermission(P.SECRET_READ_METADATA)], (req) => this.service.list(orgCtx(req).org.id, req.body ?? {}));
    this.route('post', '/save', [requirePermission(P.SECRET_MANAGE_ACCESS), validationMiddleware(CreateSecretGrantDto)], async (req) => new Reply(await this.service.create(orgCtx(req), req.body as CreateSecretGrantDto), 201));
    this.route('post', '/revoke', [requirePermission(P.SECRET_MANAGE_ACCESS), validationMiddleware(SecretGrantRevokeDto)], (req) => this.service.revoke(orgCtx(req), req.body as SecretGrantRevokeDto));
    this.route('post', '/getApprovals', [requirePermission(P.SECRET_READ_METADATA)], (req) => this.service.listApprovals(orgCtx(req).org.id, req.body ?? {}));
    this.route('post', '/approve', [requirePermission(P.SECRET_MANAGE_ACCESS), validationMiddleware(SecretApprovalDecisionDto)], (req) => this.service.decide(orgCtx(req), req.body as SecretApprovalDecisionDto, 'APPROVED'));
    this.route('post', '/reject', [requirePermission(P.SECRET_MANAGE_ACCESS), validationMiddleware(SecretApprovalDecisionDto)], (req) => this.service.decide(orgCtx(req), req.body as SecretApprovalDecisionDto, 'REJECTED'));
  }
}

/** Tells a caller that used a rotated key (grace period) when that key stops working. */
const keyNotice = (res: Response) => (expiresAt: string) => res.setHeader('Token-Vault-Key-Expires', expiresAt);

/**
 * /agent/v1/secret, authenticated only by the agent's own key (Authorization: Bearer tvak_…):
 *   POST /getall     the secrets this agent may read (metadata, allowed fields, whether approval is needed)
 *   POST /retrieve   `{secret_id | name + project? + workspace? + environment?, version?, fields?, reason?, approval_id?}`
 *                    → 200 the value; 202 APPROVAL_REQUIRED `{approval_id}` when the grant holds retrievals for approval
 */
export class AgentSecretController extends BaseController {
  constructor(private readonly service = new SecretAccessService()) {
    super(AGENT_ROUTES.SECRET, 'Secret');
  }

  protected _initialiseRoutes(): void {
    this.route('post', '/getall', [], (req: Request, res: Response) => this.service.agentList(req.headers.authorization, keyNotice(res)));
    this.route('post', '/retrieve', [], async (req: Request, res: Response) => {
      const r = await this.service.agentRetrieve({ authorization: req.headers.authorization, sourceIp: normalizeIp(req.ip), body: req.body, onPreviousKey: keyNotice(res) });
      return new Reply(r.body, r.status, r.status === 202 ? 'Approval Required' : 'Secret Retrieved Successfully');
    });
  }
}
