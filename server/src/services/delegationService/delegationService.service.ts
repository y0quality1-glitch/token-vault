import { z } from 'zod';
import { DECISION_CODES, type ActingUser, type AgentDelegationBody, type DelegationRef, type DelegationStatus, type DelegationView } from '@token-vault/shared';
import { transaction } from '../../databases/client';
import { badRequest, conflict, forbidden, notFound } from '../../lib/errors';
import { generateDelegationToken, parseDelegationToken, verifySecret } from '../../lib/crypto';
import { newId } from '../../lib/ids';
import { parse } from '../../lib/validate';
import { USER_TOKEN_LIMITS, verifyUserToken } from '../../lib/user-token';
import { agentRepo, delegationRepo, grantRepo, integrationRepo, orgRepo, userIssuerRepo } from '../../store/repos';
import type { DelegationRecord } from '../../store/repos/delegations';
import type { AgentRecord } from '../../store/types';
import { effectiveGrantStatus } from '../../store/views';
import type { AdminContext } from '../../types/express';
import { recordEvent, userActor } from '../auditService/auditService.service';
import { getOperation } from '../providerService/registry';

/**
 * Delegation to sub-agents.
 *
 * An agent (or a sub-agent, up to DELEGATION_LIMITS.MAX_DEPTH levels) hands a narrower,
 * short-lived slice of one grant to a sub-agent, which authenticates with its own token.
 * Requests are evaluated as the parent agent's, restricted to that grant and to the
 * delegation's operations, resources and request cap. Nothing a delegation allows can
 * exceed what created it, and the whole chain is checked on every request, so revoking
 * a delegation stops everything delegated from it.
 */
export const DELEGATION_LIMITS = {
  MAX_DEPTH: 3,
  MIN_TTL_S: 60,
  MAX_TTL_S: 24 * 3600,
  DEFAULT_TTL_S: 3600,
  MAX_ACTIVE_PER_AGENT: 50,
};

/** The delegation a caller authenticated with, with its ancestors (parent first). */
export interface DelegationContext {
  delegation: DelegationRecord;
  chain: DelegationRecord[];
}

export function refOf(d: DelegationRecord): DelegationRef {
  return { id: d.id, label: d.label, depth: d.depth, parentId: d.parentDelegationId };
}

/** Ancestors of a delegation, nearest first. */
export async function ancestorsOf(d: DelegationRecord): Promise<DelegationRecord[]> {
  const chain: DelegationRecord[] = [];
  let parentId = d.parentDelegationId;
  for (let i = 0; parentId && i < DELEGATION_LIMITS.MAX_DEPTH; i++) {
    const [p] = await delegationRepo.byIds([parentId]);
    if (!p) break;
    chain.push(p);
    parentId = p.parentDelegationId;
  }
  return chain;
}

/** Effective status, counting the whole chain: a revoked or expired ancestor ends it too. */
export function statusOf(d: DelegationRecord, chain: DelegationRecord[], now = Date.now()): { status: DelegationStatus; reason: string | null; code: string | null } {
  for (const x of [d, ...chain]) {
    if (x.revokedAt) {
      const own = x.id === d.id;
      return { status: 'REVOKED', code: DECISION_CODES.DELEGATION_REVOKED, reason: own ? `Delegation ${d.id} was revoked at ${x.revokedAt}${x.revocationReason ? ` ("${x.revocationReason}")` : ''}.` : `Delegation ${x.id}, which delegation ${d.id} came from, was revoked at ${x.revokedAt}.` };
    }
  }
  for (const x of [d, ...chain]) {
    if (Date.parse(x.expiresAt) <= now) return { status: 'EXPIRED', code: DECISION_CODES.DELEGATION_EXPIRED, reason: x.id === d.id ? `Delegation ${d.id} expired at ${x.expiresAt}.` : `Delegation ${x.id}, which delegation ${d.id} came from, expired at ${x.expiresAt}.` };
  }
  return { status: 'ACTIVE', reason: null, code: null };
}

/**
 * Resolves a delegation token. `agent` is set whenever the token's key id is known, so a
 * failed attempt is attributed to the right organization.
 */
export async function resolveDelegationToken(token: string, now = Date.now()): Promise<{ ok: true; agent: AgentRecord; ctx: DelegationContext } | { ok: false; agent: AgentRecord | null; delegation: DelegationRecord | null; code: string; reason: string }> {
  const parsed = parseDelegationToken(token);
  const d = parsed ? await delegationRepo.findByKeyId(parsed.keyId) : null;
  if (!parsed || !d) return { ok: false, agent: null, delegation: null, code: DECISION_CODES.AGENT_UNAUTHENTICATED, reason: 'Delegation token is invalid or unknown.' };
  const agent = await agentRepo.getAgent(d.organizationId, d.agentId);
  if (!verifySecret(token, d.credentialHash)) return { ok: false, agent, delegation: null, code: DECISION_CODES.AGENT_UNAUTHENTICATED, reason: 'Delegation token is invalid or unknown.' };
  if (!agent) return { ok: false, agent: null, delegation: d, code: DECISION_CODES.AGENT_UNAUTHENTICATED, reason: 'The agent this delegation belongs to no longer exists.' };
  const chain = await ancestorsOf(d);
  const s = statusOf(d, chain, now);
  if (s.status !== 'ACTIVE') return { ok: false, agent, delegation: d, code: s.code!, reason: s.reason! };
  return { ok: true, agent, ctx: { delegation: d, chain } };
}

// ---------------------------------------------------------------- creation (agent API)

const createSchema = z.object({
  grant_id: z.string().min(1).max(64).optional(),
  label: z.string().trim().min(3, 'Describe the sub-agent in at least 3 characters').max(80),
  operations: z.array(z.string().min(1).max(80)).min(1, 'Delegate at least one operation').max(50),
  resources: z.array(z.string().trim().min(1).max(300)).max(20).default([]),
  expires_in_seconds: z.number().int().min(DELEGATION_LIMITS.MIN_TTL_S).max(DELEGATION_LIMITS.MAX_TTL_S).default(DELEGATION_LIMITS.DEFAULT_TTL_S),
  max_requests: z.number().int().min(1).max(100_000).optional(),
  on_behalf_of: z.string().min(1).max(USER_TOKEN_LIMITS.MAX_TOKEN_LENGTH).optional(),
});

const lower = (s: string) => s.toLowerCase();

/** Creates a delegation for a sub-agent. The token is returned once and only its hash is kept. */
export async function createDelegation(agent: AgentRecord, caller: DelegationContext | null, raw: unknown): Promise<{ status: number; body: unknown }> {
  const body = parse(createSchema, raw);
  const now = Date.now();
  const org = await orgRepo.getOrganization(agent.organizationId);
  if (org?.emergencyStoppedAt) throw forbidden('All agent access in this organization is stopped; nothing can be delegated.');
  if (agent.status !== 'ACTIVE') throw forbidden('This agent is disabled.');

  const parent = caller?.delegation ?? null;
  const grantId = parent ? parent.grantId : body.grant_id;
  if (!grantId) throw badRequest('Request validation failed', { fields: { grant_id: 'Choose the grant to delegate from' } });
  if (parent && body.grant_id && body.grant_id !== parent.grantId) throw forbidden('A sub-agent can only delegate from the grant it was given.');
  const grant = await grantRepo.getGrant(agent.organizationId, grantId);
  if (!grant || grant.agentId !== agent.id) throw notFound('Grant');
  if (effectiveGrantStatus(grant, now) !== 'ACTIVE') throw forbidden(`Grant "${grant.name}" is not active (${effectiveGrantStatus(grant, now).toLowerCase()}); it cannot be delegated.`);
  const depth = (parent?.depth ?? 0) + 1;
  if (depth > DELEGATION_LIMITS.MAX_DEPTH) throw forbidden(`Delegations can be at most ${DELEGATION_LIMITS.MAX_DEPTH} levels deep.`);

  // Operations: within what the caller holds, never destructive.
  const allowedOps = parent ? parent.operations : grant.scopes;
  const ops = [...new Set(body.operations)];
  for (const op of ops) {
    if (!allowedOps.includes(op)) throw badRequest('Request validation failed', { fields: { operations: `${op} is not ${parent ? 'in this delegation' : `granted by "${grant.name}"`}; a delegation can only narrow.` } });
    if (getOperation(op)?.destructive) throw badRequest('Request validation failed', { fields: { operations: `${op} is destructive and cannot be delegated.` } });
  }

  // Resources: within the caller's (empty there means anything the grant allows).
  const baseResources = parent ? (parent.resources.length ? parent.resources : grant.resourceConstraints.repositories) : grant.resourceConstraints.repositories;
  const resources = [...new Set(body.resources)];
  if (baseResources.length) {
    const outside = resources.filter((r) => !baseResources.map(lower).includes(lower(r)));
    if (outside.length) throw badRequest('Request validation failed', { fields: { resources: `${outside.join(', ')} ${outside.length > 1 ? 'are' : 'is'} outside what ${parent ? 'this delegation' : `"${grant.name}"`} allows (${baseResources.join(', ')}).` } });
  }
  const effectiveResources = resources.length ? resources : baseResources;

  // Request cap: never above the caller's.
  if (parent?.maxRequests && body.max_requests && body.max_requests > parent.maxRequests) throw badRequest('Request validation failed', { fields: { max_requests: `At most ${parent.maxRequests}, this delegation's own cap.` } });
  const maxRequests = body.max_requests ?? parent?.maxRequests ?? null;

  // The user: inherited from the parent delegation, or verified from on_behalf_of.
  let user: ActingUser | null = parent?.onBehalfOf ?? null;
  const caps = [now + body.expires_in_seconds * 1000, Date.parse(grant.expiresAt)];
  if (parent) caps.push(Date.parse(parent.expiresAt));
  if (body.on_behalf_of) {
    if (parent) throw forbidden(parent.onBehalfOf ? 'This delegation already acts for a user; its sub-agents act for the same user.' : 'This delegation acts for the agent itself; it cannot be turned into one for a user.');
    const v = verifyUserToken(body.on_behalf_of, await userIssuerRepo.listIssuers(agent.organizationId), now);
    if (!v.ok) throw forbidden(`The user token was not accepted: ${v.reason}`);
    if ((grant.onBehalfOf ?? 'ALLOWED') === 'NOT_ALLOWED') throw forbidden(`Grant "${grant.name}" lets the agent act only for itself, not on behalf of users.`);
    user = v.user;
    caps.push(Date.parse(v.expiresAt)); // a delegation for a user never outlives that user's token
  }
  if (!user && (grant.onBehalfOf ?? 'ALLOWED') === 'REQUIRED') throw forbidden(`Grant "${grant.name}" works only on behalf of a signed-in user: pass the user's token as on_behalf_of.`);
  const expiresAt = Math.min(...caps);
  if (expiresAt - now < DELEGATION_LIMITS.MIN_TTL_S * 1000) throw conflict('The delegation would last less than a minute (the grant, the parent delegation or the user token expires sooner).');

  if ((await delegationRepo.activeCount(agent.id, new Date(now).toISOString())) >= DELEGATION_LIMITS.MAX_ACTIVE_PER_AGENT) {
    return { status: 429, body: { error: { code: 'TOO_MANY_DELEGATIONS', message: `This agent already has ${DELEGATION_LIMITS.MAX_ACTIVE_PER_AGENT} active delegations; revoke unused ones first.` } } };
  }

  const cred = generateDelegationToken();
  const created = await transaction(async (tx) => {
    const d = await delegationRepo.insertDelegation(
      {
        id: newId('dlg'),
        organizationId: agent.organizationId,
        agentId: agent.id,
        grantId: grant.id,
        parentDelegationId: parent?.id ?? null,
        depth,
        label: body.label,
        operations: ops,
        resources: effectiveResources,
        maxRequests,
        onBehalfOf: user,
        keyId: cred.keyId,
        credentialHash: cred.hash,
        createdAt: new Date(now).toISOString(),
        expiresAt: new Date(expiresAt).toISOString(),
        revokedAt: null,
        revokedBy: null,
        revocationReason: null,
        lastUsedAt: null,
      },
      tx,
    );
    await recordEvent(
      {
        orgId: agent.organizationId,
        actor: { type: 'AGENT', id: agent.id, name: parent ? `${agent.name} via ${parent.label}` : agent.name },
        eventType: 'delegation.created',
        target: { type: 'grant', id: grant.id, name: grant.name },
        metadata: { delegationId: d.id, label: d.label, depth, parentDelegationId: d.parentDelegationId, operations: ops, resources: effectiveResources, maxRequests, expiresAt: d.expiresAt, ...(user ? { onBehalfOf: user.sub } : {}) },
      },
      tx,
    );
    return d;
  });
  return { status: 201, body: { ...(await agentBody(created)), token: cred.token } };
}

// ---------------------------------------------------------------- views

export async function agentBody(d: DelegationRecord, used?: number): Promise<AgentDelegationBody> {
  const s = statusOf(d, await ancestorsOf(d));
  return {
    delegation_id: d.id,
    label: d.label,
    grant_id: d.grantId,
    parent_delegation_id: d.parentDelegationId,
    depth: d.depth,
    operations: d.operations,
    resources: d.resources,
    max_requests: d.maxRequests,
    used: used ?? (await delegationRepo.usage([d.id])).get(d.id) ?? 0,
    on_behalf_of: d.onBehalfOf ? { sub: d.onBehalfOf.sub, email: d.onBehalfOf.email ?? null, issuer: d.onBehalfOf.issuer } : null,
    status: s.status,
    status_reason: s.reason,
    created_at: d.createdAt,
    expires_at: d.expiresAt,
    revoked_at: d.revokedAt,
  };
}

/** Delegations visible to a caller: an agent sees all of its own; a sub-agent sees those delegated from it (directly or further down). */
export async function visibleTo(agent: AgentRecord, caller: DelegationContext | null): Promise<DelegationRecord[]> {
  const all = await delegationRepo.listDelegations(agent.organizationId, { agentId: agent.id });
  if (!caller) return all;
  const byId = new Map(all.map((d) => [d.id, d]));
  const descends = (d: DelegationRecord) => {
    for (let p = d.parentDelegationId, i = 0; p && i <= DELEGATION_LIMITS.MAX_DEPTH; p = byId.get(p)?.parentDelegationId ?? null, i++) if (p === caller.delegation.id) return true;
    return false;
  };
  return all.filter(descends);
}

export async function listForAgent(agent: AgentRecord, caller: DelegationContext | null): Promise<AgentDelegationBody[]> {
  const list = await visibleTo(agent, caller);
  const used = await delegationRepo.usage(list.map((d) => d.id));
  return Promise.all(list.map((d) => agentBody(d, used.get(d.id) ?? 0)));
}

/** The agent (or a sub-agent, for what it delegated) revokes a delegation; everything delegated from it stops too. */
export async function revokeByAgent(agent: AgentRecord, caller: DelegationContext | null, id: string, raw: unknown): Promise<AgentDelegationBody> {
  const { reason } = parse(z.object({ reason: z.string().trim().max(240).default('') }), raw ?? {});
  const target = (await visibleTo(agent, caller)).find((d) => d.id === id);
  if (!target) throw notFound('Delegation');
  const by = caller ? `delegation:${caller.delegation.id}` : `agent:${agent.id}`;
  const revoked = await transaction(async (tx) => {
    const r = await delegationRepo.revoke(target.id, { revokedAt: new Date().toISOString(), revokedBy: by, revocationReason: reason || null }, tx);
    if (!r) return target; // already revoked: idempotent
    await recordEvent({ orgId: agent.organizationId, actor: { type: 'AGENT', id: agent.id, name: caller ? `${agent.name} via ${caller.delegation.label}` : agent.name }, eventType: 'delegation.revoked', target: { type: 'grant', id: r.grantId, name: r.label }, metadata: { delegationId: r.id, reason: reason || null } }, tx);
    return r;
  });
  return agentBody(revoked);
}

const adminRevokeSchema = z.object({ reason: z.string().trim().min(3, 'Give a reason (at least 3 characters)').max(240) });

export async function revokeByAdmin(ctx: AdminContext & { org: { id: string } }, id: string, raw: unknown): Promise<DelegationView> {
  const { reason } = parse(adminRevokeSchema, raw);
  const target = await delegationRepo.getDelegation(ctx.org.id, id);
  if (!target) throw notFound('Delegation');
  const revoked = await transaction(async (tx) => {
    const r = await delegationRepo.revoke(target.id, { revokedAt: new Date().toISOString(), revokedBy: ctx.user.id, revocationReason: reason }, tx);
    if (!r) return target;
    await recordEvent({ orgId: ctx.org.id, actor: userActor(ctx), eventType: 'delegation.revoked', target: { type: 'grant', id: r.grantId, name: r.label }, severity: 'warning', metadata: { delegationId: r.id, agentId: r.agentId, reason } }, tx);
    return r;
  });
  return (await toViews(ctx.org.id, [revoked]))[0]!;
}

export async function toViews(organizationId: string, list: DelegationRecord[]): Promise<DelegationView[]> {
  const [agents, integrations, used] = await Promise.all([agentRepo.listAgents(organizationId), integrationRepo.integrationNames(organizationId), delegationRepo.usage(list.map((d) => d.id))]);
  const agentName = new Map(agents.map((a) => [a.id, a.name]));
  const grants = new Map((await Promise.all([...new Set(list.map((d) => d.grantId))].map((g) => grantRepo.getGrant(organizationId, g)))).filter(Boolean).map((g) => [g!.id, g!]));
  return Promise.all(
    list.map(async (d) => {
      const s = statusOf(d, await ancestorsOf(d));
      const g = grants.get(d.grantId);
      const { credentialHash: _h, ...rest } = d;
      return {
        ...rest,
        status: s.status,
        statusReason: s.reason,
        agentName: agentName.get(d.agentId) ?? 'Deleted agent',
        grantName: g?.name ?? 'Deleted grant',
        integrationId: g?.integrationId ?? '',
        integrationName: g ? integrations.get(g.integrationId) ?? 'Deleted integration' : '—',
        used: used.get(d.id) ?? 0,
      };
    }),
  );
}

// ---------------------------------------------------------------- admin API

const filter = (v: unknown) => (typeof v === 'string' && v ? v : undefined);

/** Console view of sub-agent delegations; revoking one stops everything delegated from it. */
export default class DelegationService {
  async list(orgId: string, f: Record<string, unknown> = {}) {
    const list = await delegationRepo.listDelegations(orgId, { agentId: filter(f.agentId), grantId: filter(f.grantId) });
    return { items: await toViews(orgId, list) };
  }

  revoke(ctx: AdminContext & { org: { id: string } }, id: string, raw: unknown) {
    return revokeByAdmin(ctx, id, raw);
  }
}
