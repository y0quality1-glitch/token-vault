import { z } from 'zod';
import { GRANTABLE_OPERATIONS, getOperation, type AgentAccessRequestBody, type GrantRequest, type GrantRequestStatus } from '@token-vault/shared';
import { transaction } from '../../db/client';
import { HttpError, badRequest, conflict, forbidden, notFound } from '../../lib/errors';
import { newId } from '../../lib/ids';
import { parse } from '../../lib/validate';
import { agentRepo, auditRepo, grantRepo, grantRequestRepo, integrationRepo, orgRepo } from '../../store/repos';
import type { GrantRequestRecord } from '../../store/repos/grant-requests';
import type { AgentRecord } from '../../store/types';
import type { AdminContext } from '../../types/express';
import { recordEvent, userActor } from '../audit/audit.service';

/**
 * Just-in-time access: an agent asks for a time-limited grant, a human decides.
 *
 * - Requests can only ask for grantable (non-destructive) operations.
 * - At most MAX_PENDING per agent; an identical pending request is returned, not duplicated.
 * - Pending requests lapse after REQUEST_TTL_MS.
 * - Approval needs grant:approve, and the agent's owner may not approve their own agent.
 * - Approvers may narrow (operations, repositories, duration) but never widen a request.
 * - Approval creates an ordinary, expiring grant; every step is audited.
 */
export const LIMITS = {
  MAX_PENDING: 3,
  REQUEST_TTL_MS: 24 * 3600e3,
  REQUEST_MINUTES: { min: 15, max: 480, default: 60 },
  APPROVE_MAX_MINUTES: 1440,
};

const grantable = GRANTABLE_OPERATIONS.map((o) => o.id);
const repoPattern = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/;

export function effectiveStatus(r: Pick<GrantRequestRecord, 'status' | 'expiresAt'>, now = Date.now()): GrantRequestStatus {
  if (r.status === 'PENDING' && new Date(r.expiresAt).getTime() <= now) return 'EXPIRED';
  return r.status;
}

const sameSet = (a: string[], b: string[]) => a.length === b.length && [...a].sort().join('\n') === [...b].sort().join('\n');
const lower = (xs: string[]) => xs.map((x) => x.toLowerCase());

// ---------------------------------------------------------------- views

export async function toViews(organizationId: string, records: GrantRequestRecord[]): Promise<GrantRequest[]> {
  const [agents, integrations] = await Promise.all([agentRepo.listAgents(organizationId), integrationRepo.integrationNames(organizationId)]);
  const agentById = new Map(agents.map((a) => [a.id, a]));
  const users = await orgRepo.userNames(records.map((r) => r.decidedBy ?? '').filter(Boolean));
  return records.map((r) => ({
    id: r.id,
    organizationId: r.organizationId,
    agentId: r.agentId,
    agentName: agentById.get(r.agentId)?.name ?? 'Deleted agent',
    agentOwnerUserId: agentById.get(r.agentId)?.ownerUserId ?? '',
    integrationId: r.integrationId,
    integrationName: integrations.get(r.integrationId) ?? 'Deleted integration',
    operations: r.operations,
    repositories: r.repositories,
    justification: r.justification,
    requestedDurationMinutes: r.requestedDurationMinutes,
    deniedRequestId: r.deniedRequestId,
    status: effectiveStatus(r),
    createdAt: r.createdAt,
    expiresAt: r.expiresAt,
    decidedBy: r.decidedBy,
    decidedByName: r.decidedBy ? users.get(r.decidedBy) ?? 'Unknown user' : null,
    decidedAt: r.decidedAt,
    decisionNote: r.decisionNote,
    approvedDurationMinutes: r.approvedDurationMinutes,
    grantId: r.grantId,
  }));
}

async function agentBody(r: GrantRequestRecord): Promise<AgentAccessRequestBody> {
  const grant = r.grantId ? await grantRepo.getGrant(r.organizationId, r.grantId) : null;
  return {
    access_request_id: r.id,
    status: effectiveStatus(r),
    integration_id: r.integrationId,
    operations: r.operations,
    repositories: r.repositories,
    requested_duration_minutes: r.requestedDurationMinutes,
    created_at: r.createdAt,
    expires_at: r.expiresAt,
    decided_at: r.decidedAt,
    decision_note: r.decisionNote,
    grant_id: r.grantId,
    grant_expires_at: grant?.expiresAt ?? null,
  };
}

// ---------------------------------------------------------------- agent side

const agentRequestSchema = z.object({
  integration_id: z.string().min(1).max(64),
  operations: z.array(z.string()).min(1, 'Request at least one operation').max(4),
  repositories: z.array(z.string().trim().regex(repoPattern, 'Use owner/repository format')).max(5).default([]),
  justification: z.string().trim().min(10, 'Explain why access is needed (at least 10 characters)').max(500),
  duration_minutes: z.number().int().min(LIMITS.REQUEST_MINUTES.min).max(LIMITS.REQUEST_MINUTES.max).default(LIMITS.REQUEST_MINUTES.default),
  denied_request_id: z.string().max(64).optional(),
});

export async function createFromAgent(agent: AgentRecord, raw: unknown): Promise<{ status: number; body: AgentAccessRequestBody & { duplicate?: boolean; message: string } }> {
  if (agent.status !== 'ACTIVE') throw new HttpError(403, 'AGENT_DISABLED', 'Agent is disabled and cannot request access.');
  const req = parse(agentRequestSchema, raw);
  const operations = [...new Set(req.operations)];
  const notGrantable = operations.filter((o) => !grantable.includes(o));
  if (notGrantable.length) {
    const destructive = notGrantable.filter((o) => getOperation(o)?.destructive);
    throw badRequest(destructive.length ? `Destructive operations cannot be requested: ${destructive.join(', ')}` : `Unknown or non-grantable operations: ${notGrantable.join(', ')}`);
  }
  const integration = await integrationRepo.getIntegration(agent.organizationId, req.integration_id);
  if (!integration) throw new HttpError(404, 'INTEGRATION_NOT_FOUND', `Integration "${req.integration_id}" does not exist in this organization.`);
  if (integration.allowedResources.length && req.repositories.some((r) => !lower(integration.allowedResources).includes(r.toLowerCase()))) {
    throw badRequest(`Repositories must be among the integration's allowed resources: ${integration.allowedResources.join(', ')}`);
  }
  if (req.denied_request_id && !(await auditRepo.getAccessRequestForAgent(agent.id, req.denied_request_id))) {
    throw badRequest('denied_request_id must be one of this agent’s own request IDs');
  }

  const result = await transaction(async (tx) => {
    const pending = (await grantRequestRepo.pendingForAgent(agent.id, tx)).filter((r) => effectiveStatus(r) === 'PENDING');
    const same = pending.find((r) => r.integrationId === integration.id && sameSet(r.operations, operations) && sameSet(lower(r.repositories), lower(req.repositories)));
    if (same) return { record: same, duplicate: true };
    if (pending.length >= LIMITS.MAX_PENDING) {
      throw new HttpError(429, 'TOO_MANY_PENDING_REQUESTS', `This agent already has ${pending.length} pending access requests; wait for a decision.`);
    }
    const now = Date.now();
    const record = await grantRequestRepo.insertGrantRequest(
      {
        id: newId('arq'),
        organizationId: agent.organizationId,
        agentId: agent.id,
        integrationId: integration.id,
        operations,
        repositories: req.repositories,
        justification: req.justification,
        requestedDurationMinutes: req.duration_minutes,
        deniedRequestId: req.denied_request_id ?? null,
        status: 'PENDING',
        createdAt: new Date(now).toISOString(),
        expiresAt: new Date(now + LIMITS.REQUEST_TTL_MS).toISOString(),
        decidedBy: null,
        decidedAt: null,
        decisionNote: null,
        approvedDurationMinutes: null,
        grantId: null,
      },
      tx,
    );
    await recordEvent(
      {
        orgId: agent.organizationId,
        actor: { type: 'AGENT', id: agent.id, name: agent.name },
        eventType: 'grant_request.created',
        target: { type: 'integration', id: integration.id, name: integration.displayName },
        metadata: { accessRequestId: record.id, operations, repositories: req.repositories, durationMinutes: req.duration_minutes, justification: req.justification, deniedRequestId: req.denied_request_id ?? null },
      },
      tx,
    );
    return { record, duplicate: false };
  });

  return {
    status: result.duplicate ? 200 : 201,
    body: {
      ...(await agentBody(result.record)),
      ...(result.duplicate ? { duplicate: true } : {}),
      message: result.duplicate
        ? 'An identical request is already pending. A human must approve it; check its status later.'
        : 'Access request submitted. A human administrator must approve it; until then requests stay denied. Check its status later.',
    },
  };
}

export async function getForAgent(agent: AgentRecord, id: string): Promise<AgentAccessRequestBody | null> {
  const r = await grantRequestRepo.getGrantRequestForAgent(agent.id, id);
  return r ? agentBody(r) : null;
}

// ---------------------------------------------------------------- admin side

const approveSchema = z.object({
  durationMinutes: z.number().int().min(LIMITS.REQUEST_MINUTES.min, 'At least 15 minutes').max(LIMITS.APPROVE_MAX_MINUTES, 'At most 24 hours'),
  operations: z.array(z.string()).min(1, 'Approve at least one operation').optional(),
  repositories: z.array(z.string().trim().regex(repoPattern, 'Use owner/repository format')).max(20).optional(),
  rateLimitPerMinute: z.number().int().min(1).max(600).default(10),
  note: z.string().trim().max(240).default(''),
});

export async function approve(ctx: AdminContext & { org: { id: string } }, id: string, raw: unknown): Promise<GrantRequestRecord> {
  const body = parse(approveSchema, raw);
  return transaction(async (tx) => {
    const r = await grantRequestRepo.getGrantRequest(ctx.org.id, id, tx);
    if (!r) throw notFound('Access request');
    const status = effectiveStatus(r);
    if (status !== 'PENDING') throw conflict(`This request is ${status.toLowerCase()} and can no longer be approved`);
    const agent = await agentRepo.getAgent(ctx.org.id, r.agentId, tx);
    if (!agent) throw notFound('Agent');
    if (agent.ownerUserId === ctx.user.id) throw forbidden('Separation of duties: you own this agent, so another administrator must approve its access.');
    if (agent.status !== 'ACTIVE') throw conflict('The agent is disabled; enable it or reject the request');
    const integration = await integrationRepo.getIntegration(ctx.org.id, r.integrationId, tx);
    if (!integration || integration.credentialStatus !== 'CONNECTED') throw conflict('The integration is not connected; reject the request or reconnect the integration');

    // Narrow, never widen.
    const operations = body.operations ?? r.operations;
    const extraOps = operations.filter((o) => !r.operations.includes(o));
    if (extraOps.length) throw badRequest('Request validation failed', { fields: { operations: `Not requested by the agent: ${extraOps.join(', ')}` } });
    let repositories = body.repositories ?? r.repositories;
    if (r.repositories.length) {
      const extra = repositories.filter((x) => !lower(r.repositories).includes(x.toLowerCase()));
      if (extra.length || repositories.length === 0) throw badRequest('Request validation failed', { fields: { repositories: `Must be a non-empty subset of the requested repositories (${r.repositories.join(', ')})` } });
    } else if (integration.allowedResources.length) {
      const extra = repositories.filter((x) => !lower(integration.allowedResources).includes(x.toLowerCase()));
      if (extra.length) throw badRequest('Request validation failed', { fields: { repositories: `Not allowed by the integration: ${extra.join(', ')}` } });
    }
    repositories = [...new Set(repositories)];

    const now = Date.now();
    const grant = await grantRepo.insertGrant(
      {
        id: newId('grt'),
        organizationId: ctx.org.id,
        agentId: agent.id,
        integrationId: integration.id,
        name: `JIT: ${agent.name} → ${integration.displayName} (${r.id.slice(-6)})`,
        environment: integration.environment,
        scopes: operations,
        resourceConstraints: { repositories },
        rateLimitPerMinute: body.rateLimitPerMinute,
        allowedCidrs: [],
        validFrom: new Date(now).toISOString(),
        expiresAt: new Date(now + body.durationMinutes * 60_000).toISOString(),
        approvalRequired: true,
        storedStatus: 'ACTIVE',
        version: 1,
        previousVersionId: null,
        createdBy: ctx.user.id,
        createdAt: new Date(now).toISOString(),
        approvedBy: ctx.user.id,
        approvedAt: new Date(now).toISOString(),
        revokedAt: null,
        revokedBy: null,
        revocationReason: null,
        lastUsedAt: null,
        usageCount: 0,
      },
      tx,
    );
    const decided = await grantRequestRepo.decideGrantRequest(
      r.id,
      { status: 'APPROVED', decidedBy: ctx.user.id, decidedAt: new Date(now).toISOString(), decisionNote: body.note || null, approvedDurationMinutes: body.durationMinutes, grantId: grant.id },
      tx,
    );
    if (!decided) throw conflict('This request was decided by someone else in the meantime'); // rolls back the grant
    const meta = { accessRequestId: r.id, grantId: grant.id, operations, repositories, durationMinutes: body.durationMinutes, narrowed: !sameSet(operations, r.operations) || !sameSet(lower(repositories), lower(r.repositories)) || body.durationMinutes !== r.requestedDurationMinutes };
    await recordEvent({ orgId: ctx.org.id, actor: userActor(ctx), eventType: 'grant_request.approved', target: { type: 'agent', id: agent.id, name: agent.name }, metadata: { ...meta, note: body.note } }, tx);
    await recordEvent({ orgId: ctx.org.id, actor: userActor(ctx), eventType: 'grant.created', target: { type: 'grant', id: grant.id, name: grant.name }, metadata: { ...meta, justInTime: true, expiresAt: grant.expiresAt } }, tx);
    return decided;
  });
}

export async function reject(ctx: AdminContext & { org: { id: string } }, id: string, raw: unknown): Promise<GrantRequestRecord> {
  const { note } = parse(z.object({ note: z.string().trim().max(240).default('') }), raw ?? {});
  return transaction(async (tx) => {
    const r = await grantRequestRepo.getGrantRequest(ctx.org.id, id, tx);
    if (!r) throw notFound('Access request');
    const status = effectiveStatus(r);
    if (status !== 'PENDING') throw conflict(`This request is ${status.toLowerCase()} and can no longer be rejected`);
    const decided = await grantRequestRepo.decideGrantRequest(r.id, { status: 'REJECTED', decidedBy: ctx.user.id, decidedAt: new Date().toISOString(), decisionNote: note || null }, tx);
    if (!decided) throw conflict('This request was decided by someone else in the meantime');
    const agent = await agentRepo.getAgent(ctx.org.id, r.agentId, tx);
    await recordEvent({ orgId: ctx.org.id, actor: userActor(ctx), eventType: 'grant_request.rejected', target: { type: 'agent', id: r.agentId, name: agent?.name ?? r.agentId }, severity: 'warning', metadata: { accessRequestId: r.id, note } }, tx);
    return decided;
  });
}
