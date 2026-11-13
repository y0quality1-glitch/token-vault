import type { Request, Response } from 'express';
import { AGENT_ROUTES } from '../../core/AppRoutes';
import { HttpError } from '../../lib/errors';
import { normalizeIp } from '../../lib/net';
import { getForAgent as getApprovalForAgent } from '../../services/approvalService/approvalService.service';
import { authenticate, authenticateCaller, executeAgentRequest, getAgentOperations, getCapabilities, getOwnRequest } from '../../services/brokerService/brokerService.service';
import { createDelegation, listForAgent, revokeByAgent } from '../../services/delegationService/delegationService.service';
import { createFromAgent, getForAgent } from '../../services/grantRequestService/grantRequestService.service';
import { BaseController, agentReply, bodyId } from '../baseController';

/**
 * Agent-facing API at /agent/v1, authenticated ONLY by the agent credential
 * (Authorization: Bearer tvak_… or a delegation token tvdt_…). Admin session cookies are ignored.
 * Request bodies are validated by the services, so a malformed request is still audited.
 */

/** Tells a caller that used a rotated key (grace period) when that key stops working. */
const keyNotice = (res: Response) => (expiresAt: string) => res.setHeader('Token-Vault-Key-Expires', expiresAt);
const unauthenticated = () => new HttpError(401, 'AGENT_UNAUTHENTICATED', 'Invalid agent credential');
const isDelegationToken = (authorization: string | undefined) => /^Bearer\s+tvdt_/i.test(authorization ?? '');
const caller = async (req: Request, res: Response) => {
  const c = await authenticateCaller(req.headers.authorization, keyNotice(res));
  if (!c) throw unauthenticated();
  return c;
};

/** /request: run an operation, and read back one of this agent's requests. */
export class AgentRequestController extends BaseController {
  constructor() {
    super(AGENT_ROUTES.REQUEST, 'Request');
  }
  protected _initialiseRoutes(): void {
    this.route('post', '/execute', [], async (req, res) =>
      agentReply(
        await executeAgentRequest({
          authorization: req.headers.authorization,
          // Non-authoritative hint used only to attribute unauthenticated attempts in the audit log.
          orgHint: typeof req.headers['x-token-vault-org'] === 'string' ? req.headers['x-token-vault-org'] : undefined,
          sourceIp: normalizeIp(req.ip),
          source: req.headers['x-token-vault-client'] === 'playground' ? 'playground' : 'agent-api',
          body: req.body,
          traceparent: typeof req.headers.traceparent === 'string' ? req.headers.traceparent : undefined,
          onPreviousKey: keyNotice(res),
        }),
        'Request Completed Successfully',
      ),
    );
    this.route('get', '/getbyid/:id', [], async (req, res) => {
      const r = await getOwnRequest(req.headers.authorization, String(req.params.id), keyNotice(res));
      if (r.status === 401) throw unauthenticated();
      if (r.status === 404) throw new HttpError(404, 'NOT_FOUND', 'Request not found');
      return r.body;
    });
  }
}

/** /capability/getdata: what this agent may do (grants, operations, budgets). */
export class AgentCapabilityController extends BaseController {
  constructor() {
    super(AGENT_ROUTES.CAPABILITY, 'Capabilities');
  }
  protected _initialiseRoutes(): void {
    this.route('post', '/getdata', [], async (req, res) => {
      const r = await getCapabilities(req.headers.authorization, keyNotice(res));
      if (r.status === 401) throw unauthenticated();
      return r.body;
    });
  }
}

/** /operation/getall: definitions of the operations of the applications this agent has grants on. */
export class AgentOperationController extends BaseController {
  constructor() {
    super(AGENT_ROUTES.OPERATION, 'Operations');
  }
  protected _initialiseRoutes(): void {
    this.route('post', '/getall', [], async (req, res) => {
      const r = await getAgentOperations(req.headers.authorization, keyNotice(res));
      if (r.status === 401) throw unauthenticated();
      return r.body;
    });
  }
}

/** /accessRequest: just-in-time access. Sub-agents cannot request: they only ever narrow. */
export class AgentAccessRequestController extends BaseController {
  constructor() {
    super(AGENT_ROUTES.ACCESS_REQUEST, 'Access request');
  }
  protected _initialiseRoutes(): void {
    this.route('post', '/save', [], async (req, res) => {
      if (isDelegationToken(req.headers.authorization)) throw new HttpError(403, 'DELEGATION_DENIED', 'A sub-agent cannot request access; ask the agent that delegated to you.');
      const agent = await authenticate(req.headers.authorization, keyNotice(res));
      if (!agent) throw unauthenticated();
      return agentReply(await createFromAgent(agent, req.body), 'Access request Added Successfully');
    });
    this.route('get', '/getbyid/:id', [], async (req, res) => {
      const agent = await authenticate(req.headers.authorization, keyNotice(res));
      if (!agent) throw unauthenticated();
      const r = await getForAgent(agent, String(req.params.id));
      if (!r) throw new HttpError(404, 'NOT_FOUND', 'Access request not found');
      return r;
    });
  }
}

/** /approval/getbyid/:id: an approval one of this agent's requests waits for. */
export class AgentApprovalController extends BaseController {
  constructor() {
    super(AGENT_ROUTES.APPROVAL, 'Approval');
  }
  protected _initialiseRoutes(): void {
    this.route('get', '/getbyid/:id', [], async (req, res) => {
      const c = await caller(req, res);
      const r = await getApprovalForAgent(c.agent, String(req.params.id), c.delegation?.delegation.id ?? null);
      if (!r) throw new HttpError(404, 'NOT_FOUND', 'Approval not found');
      return r;
    });
  }
}

/**
 * /delegation: hand a sub-agent a narrower, short-lived slice of one grant (token returned once),
 * list what this caller delegated, and revoke (everything delegated from it stops too).
 */
export class AgentDelegationController extends BaseController {
  constructor() {
    super(AGENT_ROUTES.DELEGATION, 'Delegation');
  }
  protected _initialiseRoutes(): void {
    this.route('post', '/save', [], async (req, res) => {
      const c = await caller(req, res);
      return agentReply(await createDelegation(c.agent, c.delegation, req.body), 'Delegation Added Successfully');
    });
    this.route('post', '/getall', [], async (req, res) => {
      const c = await caller(req, res);
      return { items: await listForAgent(c.agent, c.delegation) };
    });
    this.route('post', '/revoke', [], async (req, res) => {
      const c = await caller(req, res);
      const { id: _id, ...body } = req.body ?? {};
      return revokeByAgent(c.agent, c.delegation, bodyId(req), body);
    });
  }
}

export const agentControllers = () => [new AgentRequestController(), new AgentCapabilityController(), new AgentOperationController(), new AgentAccessRequestController(), new AgentApprovalController(), new AgentDelegationController()];
