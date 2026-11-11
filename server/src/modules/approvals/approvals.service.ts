import { createHash } from 'node:crypto';
import { z } from 'zod';
import { canonicalJson, type ActingUser, type AgentApprovalBody, type DelegationRef, type OperationApproval, type OperationApprovalStatus } from '@token-vault/shared';
import { transaction } from '../../db/client';
import { conflict, forbidden, notFound } from '../../lib/errors';
import { newId } from '../../lib/ids';
import { parse } from '../../lib/validate';
import { agentRepo, approvalRepo, integrationRepo, orgRepo } from '../../store/repos';
import type { OperationApprovalRecord } from '../../store/repos/operation-approvals';
import type { AgentRecord, IntegrationRecord } from '../../store/types';
import type { AdminContext } from '../../types/express';
import { recordEvent, userActor } from '../audit/audit.service';

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
}): Promise<OperationApprovalRecord | null> {
  return transaction(async (tx) => {
    const pending = (await approvalRepo.pendingForAgent(args.agent.id, tx)).filter((r) => effectiveStatus(r) === 'PENDING');
    const same = pending.find((r) => r.requestDigest === args.digest);
    if (same) return same;
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
    return record;
  });
}

export function approvalSummary(r: OperationApprovalRecord) {
  return { approval_id: r.id, status: effectiveStatus(r), expires_at: r.expiresAt };
}

// ---------------------------------------------------------------- views

export async function toViews(organizationId: string, records: OperationApprovalRecord[]): Promise<OperationApproval[]> {
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

async function decide(ctx: AdminContext & { org: { id: string } }, id: string, raw: unknown, outcome: 'APPROVED' | 'REJECTED'): Promise<OperationApprovalRecord> {
  const { note } = parse(decisionSchema, raw ?? {});
  return transaction(async (tx) => {
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
        metadata: { approvalId: r.id, requestId: r.requestedByRequestId, policyName: r.policyName, operation: r.operation, ...r.resource, note, ...(outcome === 'APPROVED' ? { usableUntil: decided.expiresAt } : {}) },
      },
      tx,
    );
    return decided;
  });
}

export const approve = (ctx: AdminContext & { org: { id: string } }, id: string, raw: unknown) => decide(ctx, id, raw, 'APPROVED');
export const reject = (ctx: AdminContext & { org: { id: string } }, id: string, raw: unknown) => decide(ctx, id, raw, 'REJECTED');
