import { OperationApprovalEntity } from '../../entities';
import { BaseServices } from '../baseService';
import type { Pagination } from '../../core/Y0Params';
import { createHash } from 'node:crypto';
import { z } from 'zod';
import { canonicalJson, type ActingUser, type AgentApprovalBody, type DelegationRef, type OperationApproval, type OperationApprovalStatus } from '@token-vault/shared';
import { transaction } from '../../databases/client';
import { conflict, forbidden, notFound } from '../../lib/errors';
import { newId } from '../../lib/ids';
import { parse } from '../../lib/validate';
import { agentRepo, approvalRepo, auditRepo, integrationRepo, orgRepo } from '../../store/repos';
import type { OperationApprovalRecord } from '../../store/repos/operation-approvals';
import type { AgentRecord, IntegrationRecord } from '../../store/types';
import type { AdminContext } from '../../types/express';
import { recordEvent, userActor } from '../auditService/auditService.service';

/**
 * Human approval of one exact request (REQUIRE_APPROVAL policies).
 *
 * - The approval is bound to a digest of the request (integration, operation, resource,
 *   input, and the user the agent acts for): an approval for one issue title cannot run a
 *   different one, and an approval for one user cannot run for another.
 * - It is single use, and must be used within EXECUTE_WINDOW_MS of being approved.
 * - Every other check still runs when it is used: revoking the grant still wins.
 * - The agent's owner may not approve their own agent's request (separation of duties).
 * - A pending approval lapses after PENDING_TTL_MS; an agent has at most MAX_PENDING.
 */
export const APPROVAL_LIMITS = {
  PENDING_TTL_MS: 60 * 60_000,
  EXECUTE_WINDOW_MS: 15 * 60_000,
  MAX_PENDING: 10,
  /** A rejected request is answered with APPROVAL_REJECTED (not re-queued) for this long. */
  REJECTION_MEMORY_MS: 24 * 3600e3,
};

/**
 * Notification hooks (Slack approvals register here; approvals do not depend on Slack). Called
 * after the change is committed; failures never affect the request or the decision.
 */
export type DecisionChannel = 'console' | 'slack';
export const approvalHooks: {
  requested: ((r: OperationApprovalRecord) => Promise<void>)[];
  decided: ((r: OperationApprovalRecord, deciderName: string, via: DecisionChannel) => Promise<void>)[];
} = { requested: [], decided: [] };

function fire<A extends unknown[]>(hooks: ((...a: A) => Promise<void>)[], ...args: A) {
  for (const h of hooks) void h(...args).catch((e) => console.error('[api] approval notification failed:', (e as Error).message));
}

export interface RequestShape {
  integrationId: string;
  operation: string;
  resource: Record<string, string>;
  input: Record<string, unknown>;
  /** The user the agent acts for (null or absent: for itself). */
  onBehalfOf?: ActingUser | null;
  /** The sub-agent delegation sending it (null or absent: the agent itself). */
  delegation?: DelegationRef | null;
}

/** sha256 over the canonical request, domain-separated. The user is included only when there is one, so digests without a user are unchanged. */
export function requestDigest(r: RequestShape): string {
  const user = r.onBehalfOf ? { on_behalf_of: { issuer: r.onBehalfOf.issuer, sub: r.onBehalfOf.sub } } : {};
  // An approval given to one sub-agent is not usable by another, nor by the agent itself.
  const via = r.delegation ? { delegation_id: r.delegation.id } : {};
  const payload = canonicalJson({ integration_id: r.integrationId, operation: r.operation, resource: r.resource, input: r.input, ...user, ...via });
  return createHash('sha256').update(`token-vault/operation-approval/v1:${payload}`).digest('hex');
}

export function effectiveStatus(r: Pick<OperationApprovalRecord, 'status' | 'expiresAt'>, now = Date.now()): OperationApprovalStatus {
  if ((r.status === 'PENDING' || r.status === 'APPROVED') && new Date(r.expiresAt).getTime() <= now) return 'EXPIRED';
  return r.status;
}

// ---------------------------------------------------------------- broker side

export type ApprovalLookup =
  | { kind: 'none' }
  | { kind: 'approved'; record: OperationApprovalRecord; approvedBy: string }
  | { kind: 'pending'; record: OperationApprovalRecord }
  | { kind: 'rejected'; record: OperationApprovalRecord }
  | { kind: 'invalid'; reason: string; record: OperationApprovalRecord | null };

async function approvedBy(r: OperationApprovalRecord): Promise<string> {
  if (!r.decidedBy) return 'an administrator';
  return (await orgRepo.userNames([r.decidedBy])).get(r.decidedBy) ?? 'an administrator';
}

/**
 * Finds the approval that applies to this request.
 * With approval_id: that approval must be the agent's own, for exactly this request, and usable.
 * Without: the agent's latest approval for the same request is used, so simply re-sending
 * an approved request works.
 */
export async function lookupApproval(agent: AgentRecord, digest: string, approvalId: string | undefined, now = Date.now()): Promise<ApprovalLookup> {
  if (approvalId) {
    const r = await approvalRepo.getApprovalForAgent(agent.id, approvalId);
    if (!r) return { kind: 'invalid', reason: `Approval "${approvalId}" does not exist for this agent.`, record: null };
    if (r.requestDigest !== digest) return { kind: 'invalid', reason: `Approval ${r.id} was given for a different request (integration, operation, resource, input, user or sub-agent differ). Send exactly the approved request.`, record: r };
    return classify(r, now);
  }
  const [latest] = await approvalRepo.forAgentDigest(agent.id, digest);
  if (!latest) return { kind: 'none' };
  const c = await classify(latest, now);
  if (c.kind === 'rejected' && new Date(latest.decidedAt ?? latest.createdAt).getTime() + APPROVAL_LIMITS.REJECTION_MEMORY_MS <= now) return { kind: 'none' };
  // Expired or already executed: this request needs a new approval.
  return c.kind === 'invalid' ? { kind: 'none' } : c;
}

async function classify(r: OperationApprovalRecord, now: number): Promise<ApprovalLookup> {
  const status = effectiveStatus(r, now);
  if (status === 'APPROVED') return { kind: 'approved', record: r, approvedBy: await approvedBy(r) };
  if (status === 'PENDING') return { kind: 'pending', record: r };
  if (status === 'REJECTED') return { kind: 'rejected', record: r };
  if (status === 'EXECUTED') return { kind: 'invalid', reason: `Approval ${r.id} was already used (request ${r.executedRequestId}). Each approval runs one request.`, record: r };
  return { kind: 'invalid', reason: r.status === 'APPROVED' ? `Approval ${r.id} was not used in time (it expired at ${r.expiresAt}).` : `Approval ${r.id} expired at ${r.expiresAt} before anyone decided.`, record: r };
}

/** Creates a PENDING approval for a request a REQUIRE_APPROVAL policy held back. Null when the agent has too many pending. */
export async function createPending(args: {
  agent: AgentRecord;
  integration: IntegrationRecord;
  policy: { id: string; name: string };
  request: RequestShape;
  digest: string;
  requestId: string;
  correlationId: string;
}): Promise<{ record: OperationApprovalRecord; created: boolean } | null> {
  const result = await transaction(async (tx) => {
    const pending = (await approvalRepo.pendingForAgent(args.agent.id, tx)).filter((r) => effectiveStatus(r) === 'PENDING');
    const same = pending.find((r) => r.requestDigest === args.digest);
    if (same) return { record: same, created: false };
    if (pending.length >= APPROVAL_LIMITS.MAX_PENDING) return null;
    const now = Date.now();
    const record = await approvalRepo.insertApproval(
      {
        id: newId('apv'),
        organizationId: args.agent.organizationId,
        agentId: args.agent.id,
        integrationId: args.integration.id,
        policyId: args.policy.id,
        policyName: args.policy.name,
        operation: args.request.operation,
        resource: args.request.resource,
        input: args.request.input,
        requestDigest: args.digest,
        status: 'PENDING',
        requestedByRequestId: args.requestId,
        createdAt: new Date(now).toISOString(),
        expiresAt: new Date(now + APPROVAL_LIMITS.PENDING_TTL_MS).toISOString(),
        decidedBy: null,
        decidedAt: null,
        decisionNote: null,
        executedAt: null,
        executedRequestId: null,
        onBehalfOf: args.request.onBehalfOf ?? null,
        delegation: args.request.delegation ?? null,
        notifications: null,
      },
      tx,
    );
    await recordEvent(
      {
        orgId: args.agent.organizationId,
        actor: { type: 'AGENT', id: args.agent.id, name: args.agent.name },
        eventType: 'approval.requested',
        target: { type: 'integration', id: args.integration.id, name: args.integration.displayName },
        metadata: { approvalId: record.id, requestId: args.requestId, policyId: args.policy.id, policyName: args.policy.name, operation: args.request.operation, ...args.request.resource, ...(args.request.onBehalfOf ? { onBehalfOf: args.request.onBehalfOf.sub } : {}), ...(args.request.delegation ? { delegationId: args.request.delegation.id } : {}) },
        correlationId: args.correlationId,
      },
      tx,
    );
    return { record, created: true };
  });
  return result;
}

/**
 * Announces a new approval to the notification hooks (Slack). The broker calls it once the held
 * request's access record is written, so the notification can show the session that led to it.
 */
export function announceRequested(r: OperationApprovalRecord) {
  fire(approvalHooks.requested, r);
}

export function approvalSummary(r: OperationApprovalRecord) {
  return { approval_id: r.id, status: effectiveStatus(r), expires_at: r.expiresAt };
}

// ---------------------------------------------------------------- views

export async function toViews(organizationId: string, records: OperationApprovalRecord[]): Promise<OperationApproval[]> {
  const [agents, integrations] = await Promise.all([agentRepo.listAgents(organizationId), integrationRepo.integrationNames(organizationId)]);
  const agentById = new Map(agents.map((a) => [a.id, a]));
  const users = await orgRepo.userNames(records.map((r) => r.decidedBy ?? '').filter(Boolean));
  // The session the held request was part of, so the approver can see what led to it.
  const sessions = new Map(
    await Promise.all(
      records.map(async (r) => {
        const held = await auditRepo.getAccessRequest(organizationId, r.requestedByRequestId);
        const t = held?.trace;
        if (!t) return [r.id, null] as const;
        // The label may have been sent with any request of the session.
        const [summary] = await auditRepo.listSessions(organizationId, { sessionId: t.sessionId, agentId: r.agentId, limit: 1 });
        const session = { sessionId: t.sessionId, sessionLabel: t.sessionLabel ?? summary?.sessionLabel ?? null, earlierRequests: await auditRepo.sessionRequestsBefore(organizationId, t.sessionId, r.agentId, held!.createdAt) };
        return [r.id, session] as const;
      }),
    ),
  );
  return records.map((r) => ({
    id: r.id,
    organizationId: r.organizationId,
    agentId: r.agentId,
    agentName: agentById.get(r.agentId)?.name ?? 'Deleted agent',
    agentOwnerUserId: agentById.get(r.agentId)?.ownerUserId ?? '',
    integrationId: r.integrationId,
    integrationName: integrations.get(r.integrationId) ?? 'Deleted integration',
    policyId: r.policyId,
    policyName: r.policyName,
    operation: r.operation,
    resource: r.resource,
    input: r.input,
    status: effectiveStatus(r),
    requestedByRequestId: r.requestedByRequestId,
    createdAt: r.createdAt,
    expiresAt: r.expiresAt,
    decidedBy: r.decidedBy,
    decidedByName: r.decidedBy ? users.get(r.decidedBy) ?? 'Unknown user' : null,
    decidedAt: r.decidedAt,
    decisionNote: r.decisionNote,
    executedAt: r.executedAt,
    executedRequestId: r.executedRequestId,
    onBehalfOf: r.onBehalfOf ?? null,
    delegation: r.delegation ?? null,
    session: sessions.get(r.id) ?? null,
  }));
}

export function agentBody(r: OperationApprovalRecord): AgentApprovalBody {
  return {
    approval_id: r.id,
    status: effectiveStatus(r),
    integration_id: r.integrationId,
    operation: r.operation,
    resource: r.resource,
    input: r.input,
    created_at: r.createdAt,
    expires_at: r.expiresAt,
    decided_at: r.decidedAt,
    decision_note: r.decisionNote,
    executed_request_id: r.executedRequestId,
    on_behalf_of: r.onBehalfOf ? { sub: r.onBehalfOf.sub, issuer: r.onBehalfOf.issuer } : null,
  };
}

/** One of the agent's approvals; a sub-agent sees only those it asked for. */
export async function getForAgent(agent: AgentRecord, id: string, delegationId: string | null = null): Promise<AgentApprovalBody | null> {
  const r = await approvalRepo.getApprovalForAgent(agent.id, id);
  if (!r || (delegationId && r.delegation?.id !== delegationId)) return null;
  return agentBody(r);
}

// ---------------------------------------------------------------- admin side

const decisionSchema = z.object({ note: z.string().trim().max(240).default('') });

async function decide(ctx: DeciderContext, id: string, raw: unknown, outcome: 'APPROVED' | 'REJECTED', via: DecisionChannel = 'console'): Promise<OperationApprovalRecord> {
  const { note } = parse(decisionSchema, raw ?? {});
  const decided = await transaction(async (tx) => {
    const r = await approvalRepo.getApproval(ctx.org.id, id, tx);
    if (!r) throw notFound('Approval');
    const status = effectiveStatus(r);
    if (status !== 'PENDING') throw conflict(`This approval is ${status.toLowerCase()} and can no longer be ${outcome === 'APPROVED' ? 'approved' : 'rejected'}`);
    const agent = await agentRepo.getAgent(ctx.org.id, r.agentId, tx);
    if (outcome === 'APPROVED') {
      if (!agent) throw notFound('Agent');
      if (agent.ownerUserId === ctx.user.id) throw forbidden('Separation of duties: you own this agent, so another administrator must approve its request.');
      if (agent.status !== 'ACTIVE') throw conflict('The agent is disabled; enable it or reject the request');
    }
    const now = Date.now();
    const decided = await approvalRepo.decideApproval(
      r.id,
      {
        status: outcome,
        decidedBy: ctx.user.id,
        decidedAt: new Date(now).toISOString(),
        decisionNote: note || null,
        // Approved: the agent must run it within the execution window.
        expiresAt: outcome === 'APPROVED' ? new Date(now + APPROVAL_LIMITS.EXECUTE_WINDOW_MS).toISOString() : r.expiresAt,
      },
      tx,
    );
    if (!decided) throw conflict('This approval was decided by someone else in the meantime');
    await recordEvent(
      {
        orgId: ctx.org.id,
        actor: userActor(ctx),
        eventType: outcome === 'APPROVED' ? 'approval.approved' : 'approval.rejected',
        target: { type: 'agent', id: r.agentId, name: agent?.name ?? r.agentId },
        severity: outcome === 'APPROVED' ? 'info' : 'warning',
        metadata: { approvalId: r.id, requestId: r.requestedByRequestId, policyName: r.policyName, operation: r.operation, ...r.resource, note, via, ...(outcome === 'APPROVED' ? { usableUntil: decided.expiresAt } : {}) },
      },
      tx,
    );
    return decided;
  });
  fire(approvalHooks.decided, decided, ctx.user.fullName, via);
  return decided;
}

/** Who decides: a console user, or a Slack user mapped to one (with their organization). */
export type DeciderContext = Pick<AdminContext, 'user'> & { org: { id: string } };

export const approve = (ctx: DeciderContext, id: string, raw: unknown, via: DecisionChannel = 'console') => decide(ctx, id, raw, 'APPROVED', via);
export const reject = (ctx: DeciderContext, id: string, raw: unknown, via: DecisionChannel = 'console') => decide(ctx, id, raw, 'REJECTED', via);

// ---------------------------------------------------------------- admin API

/** Admin API for operation approvals (requests held back by REQUIRE_APPROVAL policies). */
export default class ApprovalService extends BaseServices<OperationApprovalEntity, OperationApproval> {
  constructor() {
    super(OperationApprovalEntity);
  }
  getModuleName() {
    return 'Approval';
  }
  getGlobalSearchColumns() {
    return ['main.id', 'main.operation', 'main.policy_name'];
  }
  protected async postProcessAfterGetData(rows: OperationApprovalEntity[], orgId: string, _param: Pagination) {
    return toViews(orgId, rows);
  }
  protected async postProcessAfterGetById(r: OperationApprovalEntity, orgId: string) {
    return (await toViews(orgId, [r]))[0]!;
  }

  /**
   * `status` filters the list. It is the effective status (a lapsed request shows as EXPIRED),
   * so it is applied to the loaded page; `pending` counts the pending ones on it.
   */
  async list(orgId: string, f: Record<string, unknown> = {}) {
    const { status, ...body } = f;
    const { records, totalRecords } = await this.getAll(orgId, body);
    const pending = records.filter((r) => r.status === 'PENDING').length;
    const items = typeof status === 'string' && status ? records.filter((r) => r.status === status) : records;
    return { items, pending, total: typeof status === 'string' && status ? items.length : totalRecords };
  }

  async detail(orgId: string, id: string) {
    return this.getById(orgId, id);
  }

  async approve(ctx: DeciderContext, id: string, raw: unknown) {
    return (await toViews(ctx.org.id, [await approve(ctx, id, raw)]))[0];
  }

  async reject(ctx: DeciderContext, id: string, raw: unknown) {
    return (await toViews(ctx.org.id, [await reject(ctx, id, raw)]))[0];
  }
}
