import type { SelectQueryBuilder } from 'typeorm';
import { type Grant, type GrantDetail } from '@token-vault/shared';
import type { Pagination } from '../../core/Y0Params';
import { GrantEntity } from '../../entities';
import { BaseServices } from '../baseService';
import { transaction, type Executor } from '../../databases/client';
import type { ExtendGrantDto, GrantBatchDto, GrantDto, GrantVersionDto, RevokeGrantDto } from '../../databases/repository/grant/grant.dto';
import { HttpError, badRequest, conflict, notFound } from '../../lib/errors';
import { newId } from '../../lib/ids';
import { agentRepo, auditRepo, delegationRepo, grantRepo, integrationRepo, policyRepo } from '../../store/repos';
import type { AgentRecord, GrantRecord, IntegrationRecord } from '../../store/types';
import { effectiveGrantStatus, loadLookups, toGrant } from '../../store/views';
import type { AdminContext } from '../../types/express';
import { recordEvent, userActor } from '../auditService/auditService.service';
import { budgetUsageFor } from '../brokerService/brokerService.service';
import { approvalPolicyCovering, policyMatches } from '../policyEngine/engine';
import { foreignOperations, getOperation, resourceProblem } from '../providerService/registry';

export type OrgContext = AdminContext & { org: { id: string } };

/** The validated fields of one new grant (POST /grant/save, or one item of /grant/savemulti). */
export type CreateGrantInput = Pick<
  GrantDto,
  | 'name'
  | 'agentId'
  | 'integrationId'
  | 'environment'
  | 'approvalRequired'
  | 'scopes'
  | 'repositories'
  | 'validFrom'
  | 'expiresAt'
  | 'rateLimitPerMinute'
  | 'maxRequestsPerDay'
  | 'maxWritesPerHour'
  | 'allowedCidrs'
  | 'onBehalfOf'
  | 'allowedUserGroups'
>;

const q = (v: unknown) => (typeof v === 'string' && v ? v : undefined);

async function getGrant(orgId: string, id: string, ex?: Executor): Promise<GrantRecord> {
  const g = await grantRepo.getGrant(orgId, id, ex);
  if (!g) throw notFound('Grant');
  return g;
}

export function validateWindow(validFrom: string, expiresAt: string) {
  const from = new Date(validFrom).getTime();
  const to = new Date(expiresAt).getTime();
  if (to <= from) throw badRequest('Request validation failed', { fields: { expiresAt: 'Expiry must be after the start time' } });
  if (to <= Date.now()) throw badRequest('Request validation failed', { fields: { expiresAt: 'Expiry must be in the future' } });
  if (to - from > 366 * 86400e3) throw badRequest('Request validation failed', { fields: { expiresAt: 'Grants may be valid for at most one year' } });
}

export function validateRepos(integration: IntegrationRecord, repos: string[], scopes?: string[]) {
  const problem = resourceProblem(integration.provider, repos);
  if (problem) throw badRequest('Request validation failed', { fields: { repositories: problem } });
  const foreign = scopes ? foreignOperations(integration.provider, scopes) : [];
  if (foreign.length) throw badRequest('Request validation failed', { fields: { scopes: `Not operations of this integration's provider: ${foreign.join(', ')}` } });
  if (integration.allowedResources.length > 0) {
    const bad = repos.filter((r) => !integration.allowedResources.some((a) => a.toLowerCase() === r.toLowerCase()));
    if (bad.length) throw badRequest('Request validation failed', { fields: { repositories: `Not allowed by the integration: ${bad.join(', ')}` } });
  }
}

const facts = (id: string) => {
  const o = getOperation(id);
  return o ? { id: o.id, provider: o.provider, risk: o.risk } : undefined;
};

/**
 * A destructive operation may be granted only where an enabled, unconditional Require approval
 * policy covers it for this agent and integration, so it can never run without a human's approval.
 * (The engine also refuses it at request time if that policy is later disabled.)
 */
export async function validateDestructive(agent: AgentRecord, integration: IntegrationRecord, scopes: string[], ex?: Executor) {
  const destructive = scopes.map((id) => getOperation(id)).filter((o) => o?.destructive);
  if (!destructive.length) return;
  const policies = await policyRepo.listPolicies(agent.organizationId, ex);
  const uncovered = destructive.filter((o) => !approvalPolicyCovering(policies, { agent, integration, operationId: o!.id, operation: facts(o!.id) }));
  if (uncovered.length) {
    const names = uncovered.map((o) => `"${o!.label}"`).join(', ');
    throw badRequest('Request validation failed', {
      fields: { scopes: `${names} ${uncovered.length > 1 ? 'are' : 'is'} destructive and can be granted only with human approval: first create an enabled Require approval policy that covers ${uncovered.length > 1 ? 'them' : 'it'} for this agent (without a time window, source IP or argument rules).` },
    });
  }
}

/** The grant with usage, recent requests, versions, matching policies and budget usage. */
export async function toDetail(g: GrantRecord): Promise<GrantDetail> {
  const [requests, chain, lookups, agent, integration, policies, budgets] = await Promise.all([
    auditRepo.accessRequestsForGrant(g.id),
    grantRepo.versionChain(g.organizationId, g),
    loadLookups(g.organizationId, [g.createdBy]),
    agentRepo.getAgent(g.organizationId, g.agentId),
    integrationRepo.getIntegration(g.organizationId, g.integrationId),
    policyRepo.listPolicies(g.organizationId),
    budgetUsageFor([g]),
  ]);
  const since = Date.now() - 86400e3;
  const matchingPolicies =
    agent && integration
      ? policies
          .filter((p) => p.enabled)
          .filter((p) => g.scopes.some((op) => policyMatches(p, { agent, integration, operationId: op, operation: facts(op) })))
          .map((p) => ({ id: p.id, name: p.name, effect: p.effect }))
      : [];
  return {
    ...toGrant(g, lookups),
    usage: {
      allowed: requests.filter((r) => r.decision === 'ALLOW').length,
      denied: requests.filter((r) => r.decision === 'DENY').length,
      last24h: requests.filter((r) => new Date(r.createdAt).getTime() > since).length,
    },
    recentRequests: requests.slice(0, 20),
    versions: chain.map((v) => ({ id: v.id, version: v.version, status: effectiveGrantStatus(v), createdAt: v.createdAt })),
    matchingPolicies,
    budgetUsage: budgets.get(g.id) ?? null,
  };
}

/**
 * Validates and inserts one grant, with its audit event, inside the caller's transaction.
 * Shared by single creation and multi-application creation, so both apply the same checks.
 */
export async function createGrant(ctx: OrgContext, body: CreateGrantInput, tx: Executor, extra: Record<string, unknown> = {}): Promise<GrantRecord> {
  const agent = await agentRepo.getAgent(ctx.org.id, body.agentId, tx);
  if (!agent) throw badRequest('Request validation failed', { fields: { agentId: 'Unknown agent' } });
  if (agent.status !== 'ACTIVE') throw badRequest('Request validation failed', { fields: { agentId: 'Agent is disabled; enable it before granting access' } });
  const integration = await integrationRepo.getIntegration(ctx.org.id, body.integrationId, tx);
  if (!integration) throw badRequest('Request validation failed', { fields: { integrationId: 'Unknown integration' } });
  if (integration.credentialStatus !== 'CONNECTED') throw badRequest('Request validation failed', { fields: { integrationId: 'Integration is not connected' } });
  if (body.environment !== integration.environment) throw badRequest('Request validation failed', { fields: { environment: `Must match the integration environment (${integration.environment})` } });
  validateWindow(body.validFrom, body.expiresAt);
  validateRepos(integration, body.repositories, body.scopes);
  await validateDestructive(agent, integration, body.scopes, tx);
  if (await grantRepo.grantNameExists(ctx.org.id, body.name, tx)) throw conflict(`A grant named "${body.name}" already exists`);

  const created = await grantRepo.insertGrant(
    {
      id: newId('grt'),
      organizationId: ctx.org.id,
      agentId: agent.id,
      integrationId: integration.id,
      name: body.name,
      environment: body.environment,
      scopes: [...body.scopes],
      resourceConstraints: { repositories: [...body.repositories] },
      rateLimitPerMinute: body.rateLimitPerMinute,
      maxRequestsPerDay: body.maxRequestsPerDay,
      maxWritesPerHour: body.maxWritesPerHour,
      onBehalfOf: body.onBehalfOf,
      allowedUserGroups: [...body.allowedUserGroups],
      allowedCidrs: [...body.allowedCidrs],
      validFrom: new Date(body.validFrom).toISOString(),
      expiresAt: new Date(body.expiresAt).toISOString(),
      approvalRequired: body.approvalRequired,
      storedStatus: body.approvalRequired ? 'PENDING_APPROVAL' : 'ACTIVE',
      version: 1,
      previousVersionId: null,
      createdBy: ctx.user.id,
      createdAt: new Date().toISOString(),
      approvedBy: null,
      approvedAt: null,
      revokedAt: null,
      revokedBy: null,
      revocationReason: null,
      lastUsedAt: null,
      usageCount: 0,
    },
    tx,
  );
  await recordEvent(
    {
      orgId: ctx.org.id,
      actor: userActor(ctx),
      eventType: 'grant.created',
      target: { type: 'grant', id: created.id, name: created.name },
      metadata: { agentId: agent.id, integrationId: integration.id, scopes: created.scopes, repositories: [...body.repositories], expiresAt: created.expiresAt, status: created.storedStatus, maxRequestsPerDay: body.maxRequestsPerDay, maxWritesPerHour: body.maxWritesPerHour, onBehalfOf: body.onBehalfOf, allowedUserGroups: [...body.allowedUserGroups], ...extra },
    },
    tx,
  );
  return created;
}

/** Prefixes field errors of one item (items.<n>.<field>); errors about shared fields keep their name. */
const ITEM_FIELDS = new Set(['integrationId', 'environment', 'scopes', 'repositories', 'name']);
function forItem(e: unknown, n: number): unknown {
  if (!(e instanceof HttpError)) return e;
  const details = e.details as { fields?: Record<string, string> } | undefined;
  if (details?.fields) {
    const fields = Object.fromEntries(Object.entries(details.fields).map(([k, v]) => [ITEM_FIELDS.has(k.split('.')[0]!) ? `items.${n}.${k}` : k, v]));
    return new HttpError(e.status, e.code, e.message, { ...details, fields });
  }
  if (e.status === 409) return new HttpError(e.status, e.code, e.message, { fields: { [`items.${n}.name`]: e.message } });
  return e;
}

function assertMutable(g: GrantRecord) {
  const s = effectiveGrantStatus(g);
  if (s === 'REVOKED' || s === 'SUPERSEDED') throw new HttpError(409, 'GRANT_NOT_MUTABLE', `Grant is ${s.toLowerCase()} and cannot be changed`);
}

/** Grants: an agent's time-limited access to operations of one integration. */
export default class GrantService extends BaseServices<GrantEntity, Grant> {
  constructor() {
    super(GrantEntity);
  }
  getModuleName() {
    return 'Grant';
  }
  getGlobalSearchColumns() {
    return ['main.name', 'main.id'];
  }
  /** Filters: agentId, integrationId (status is the effective one: see list). */
  protected applyFilters(qb: SelectQueryBuilder<GrantEntity>, { filters: f }: Pagination) {
    if (f.agentId) qb.andWhere('main.agent_id = :agentId', { agentId: f.agentId });
    if (f.integrationId) qb.andWhere('main.integration_id = :integrationId', { integrationId: f.integrationId });
    return qb;
  }
  protected async postProcessAfterGetData(rows: GrantEntity[], orgId: string): Promise<Grant[]> {
    const lookups = await loadLookups(orgId);
    return rows.map((g) => toGrant(g, lookups));
  }

  /**
   * `status` is the effective status (EXPIRED and SCHEDULED are computed from the dates), so it
   * is applied to the loaded page.
   */
  async list(orgId: string, f: Record<string, unknown> = {}) {
    const { status, ...body } = f;
    const { records, totalRecords } = await this.getAll(orgId, body);
    const wanted = q(status);
    const items = wanted ? records.filter((g) => g.status === wanted) : records;
    return { items, total: wanted ? items.length : totalRecords };
  }

  async detail(orgId: string, id: string) {
    return toDetail(await getGrant(orgId, id));
  }

  async create(ctx: OrgContext, body: GrantDto) {
    const grant = await transaction((tx) => createGrant(ctx, body, tx));
    return toDetail(grant);
  }

  /**
   * One agent, several applications: one grant per integration (each with its own operations,
   * resources and name), sharing validity, rate limit, budgets, user and IP settings. All are
   * created or none: a problem with any item rejects the whole request, with field errors
   * named items.<n>.<field>.
   */
  async createMany(ctx: OrgContext, body: GrantBatchDto) {
    const { items, ...shared } = body;
    const grants = await transaction(async (tx) => {
      const agent = await agentRepo.getAgent(ctx.org.id, shared.agentId, tx);
      if (!agent) throw badRequest('Request validation failed', { fields: { agentId: 'Unknown agent' } });
      const batchId = newId('gbt');
      const created: GrantRecord[] = [];
      for (const [n, item] of items.entries()) {
        const integration = await integrationRepo.getIntegration(ctx.org.id, item.integrationId, tx);
        if (!integration) throw badRequest('Request validation failed', { fields: { [`items.${n}.integrationId`]: 'Unknown integration' } });
        const name = item.name ?? `${agent.name} → ${integration.displayName}`;
        const one: CreateGrantInput = { ...shared, integrationId: integration.id, environment: integration.environment, name, scopes: item.scopes, repositories: item.repositories };
        try {
          created.push(await createGrant(ctx, one, tx, { batchId, batchSize: items.length }));
        } catch (e) {
          throw forItem(e, n);
        }
      }
      await recordEvent({ orgId: ctx.org.id, actor: userActor(ctx), eventType: 'grant.batch_created', target: { type: 'agent', id: agent.id, name: agent.name }, metadata: { batchId, grantIds: created.map((g) => g.id), integrationIds: created.map((g) => g.integrationId) } }, tx);
      return created;
    });
    return { items: await Promise.all(grants.map((g) => toDetail(g))) };
  }

  /** Revocation takes effect on the very next authorization check (state is read from the database per request). */
  async revoke(ctx: OrgContext, body: RevokeGrantDto) {
    const updated = await transaction(async (tx) => {
      const g = await getGrant(ctx.org.id, body.id, tx);
      assertMutable(g);
      const u = await grantRepo.updateGrant(g.id, { storedStatus: 'REVOKED', revokedAt: new Date().toISOString(), revokedBy: ctx.user.id, revocationReason: body.reason || 'Revoked by administrator' }, tx);
      await recordEvent({ orgId: ctx.org.id, actor: userActor(ctx), eventType: 'grant.revoked', target: { type: 'grant', id: g.id, name: g.name }, severity: 'warning', metadata: { reason: u.revocationReason, agentId: g.agentId, integrationId: g.integrationId } }, tx);
      return u;
    });
    return toDetail(updated);
  }

  async approve(ctx: OrgContext, id: string) {
    const updated = await transaction(async (tx) => {
      const g = await getGrant(ctx.org.id, id, tx);
      if (g.storedStatus !== 'PENDING_APPROVAL') throw conflict('Only grants pending approval can be approved');
      const u = await grantRepo.updateGrant(g.id, { storedStatus: 'ACTIVE', approvedBy: ctx.user.id, approvedAt: new Date().toISOString() }, tx);
      await recordEvent({ orgId: ctx.org.id, actor: userActor(ctx), eventType: 'grant.approved', target: { type: 'grant', id: g.id, name: g.name }, metadata: { simulatedApproval: true } }, tx);
      return u;
    });
    return toDetail(updated);
  }

  async extend(ctx: OrgContext, body: ExtendGrantDto) {
    const updated = await transaction(async (tx) => {
      const g = await getGrant(ctx.org.id, body.id, tx);
      assertMutable(g);
      validateWindow(g.validFrom, body.expiresAt);
      const u = await grantRepo.updateGrant(g.id, { expiresAt: new Date(body.expiresAt).toISOString() }, tx);
      await recordEvent({ orgId: ctx.org.id, actor: userActor(ctx), eventType: 'grant.expiry_extended', target: { type: 'grant', id: g.id, name: g.name }, metadata: { from: g.expiresAt, to: u.expiresAt } }, tx);
      return u;
    });
    return toDetail(updated);
  }

  /** Editing restrictions creates a new grant version for auditability; the old version is superseded atomically. */
  async newVersion(ctx: OrgContext, body: GrantVersionDto) {
    const next = await transaction(async (tx) => {
      const g = await getGrant(ctx.org.id, body.id, tx);
      assertMutable(g);
      validateWindow(body.validFrom, body.expiresAt);
      const integration = await integrationRepo.getIntegration(ctx.org.id, g.integrationId, tx);
      if (!integration) throw badRequest('The integration for this grant no longer exists');
      validateRepos(integration, body.repositories, body.scopes);
      const agent = await agentRepo.getAgent(ctx.org.id, g.agentId, tx);
      if (!agent) throw badRequest('The agent for this grant no longer exists');
      await validateDestructive(agent, integration, body.scopes, tx);
      await grantRepo.updateGrant(g.id, { storedStatus: 'SUPERSEDED' }, tx);
      const created = await grantRepo.insertGrant(
        {
          ...g,
          id: newId('grt'),
          scopes: [...body.scopes],
          resourceConstraints: { repositories: [...body.repositories] },
          rateLimitPerMinute: body.rateLimitPerMinute,
          maxRequestsPerDay: body.maxRequestsPerDay,
          maxWritesPerHour: body.maxWritesPerHour,
          onBehalfOf: body.onBehalfOf,
          allowedUserGroups: [...body.allowedUserGroups],
          allowedCidrs: [...body.allowedCidrs],
          validFrom: new Date(body.validFrom).toISOString(),
          expiresAt: new Date(body.expiresAt).toISOString(),
          version: g.version + 1,
          previousVersionId: g.id,
          createdBy: ctx.user.id,
          createdAt: new Date().toISOString(),
          lastUsedAt: null,
          usageCount: 0,
        },
        tx,
      );
      // Delegations to sub-agents follow the grant to its new version (and are narrowed by it at every request).
      await delegationRepo.moveToGrant(g.id, created.id, tx);
      await recordEvent({ orgId: ctx.org.id, actor: userActor(ctx), eventType: 'grant.version_created', target: { type: 'grant', id: created.id, name: created.name }, metadata: { previousVersionId: g.id, version: created.version, scopes: created.scopes, repositories: [...body.repositories], onBehalfOf: body.onBehalfOf, allowedUserGroups: [...body.allowedUserGroups] } }, tx);
      return created;
    });
    return toDetail(next);
  }

  /** Demo control for Scenario E: immediately expire a grant. */
  async expireNow(ctx: OrgContext, id: string) {
    const updated = await transaction(async (tx) => {
      const g = await getGrant(ctx.org.id, id, tx);
      assertMutable(g);
      const now = Date.now();
      const patch: Partial<GrantRecord> = { expiresAt: new Date(now - 1000).toISOString() };
      if (new Date(g.validFrom).getTime() > now) patch.validFrom = new Date(now - 60_000).toISOString();
      const u = await grantRepo.updateGrant(g.id, patch, tx);
      await recordEvent({ orgId: ctx.org.id, actor: userActor(ctx), eventType: 'grant.expired_manually', target: { type: 'grant', id: g.id, name: g.name }, severity: 'warning', metadata: { simulated: true } }, tx);
      return u;
    });
    return toDetail(updated);
  }
}
