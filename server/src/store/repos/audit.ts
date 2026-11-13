import { type SelectQueryBuilder } from 'typeorm';
import type { AccessRequest, AuditEvent } from '@token-vault/shared';
import { config } from '../../config';
import { db, transaction, type Executor } from '../../databases/client';
import { AccessRequestEntity, AuditEventEntity } from '../../entities';
import { link, type ChainTable } from '../../services/auditService/chain';
import { escapeLike, oneBy } from './orm';

/**
 * Append-only, tamper-evident audit storage. There are intentionally no update or delete
 * functions; the database also rejects UPDATE/DELETE on these tables (trigger in the baseline).
 *
 * Every insert extends the organization's hash chain (see services/auditService/chain.ts). A
 * transaction-scoped advisory lock per (table, organization) serializes appends, so concurrent
 * writers cannot fork the chain; a unique (organization, seq) index backs it up.
 */
async function appendChained<T extends { organizationId: string; id: string }>(table: ChainTable, record: T, ex: Executor): Promise<T> {
  const entity = table === 'audit_events' ? AuditEventEntity : AccessRequestEntity;
  const run = async (tx: Executor) => {
    await tx.query('SELECT pg_advisory_xact_lock(hashtext($1), hashtext($2))', [table, record.organizationId]);
    const [prev]: { seq: string | null; hash: string | null }[] = await tx.query(`SELECT seq, hash FROM ${table} WHERE organization_id = $1 AND seq IS NOT NULL ORDER BY seq DESC LIMIT 1`, [record.organizationId]);
    const fields = link(config.auditSigningKey, table, record.organizationId, prev?.seq && prev.hash ? { seq: Number(prev.seq), hash: prev.hash } : null, record as unknown as Record<string, unknown>);
    await tx.insert(entity, { ...(record as Record<string, unknown>), ...fields } as never);
    return (await tx.findOneBy(entity, { id: record.id })) as unknown as T;
  };
  return ex === db ? transaction(run) : run(ex);
}

export function insertAccessRequest(record: AccessRequest, ex: Executor = db): Promise<AccessRequest> {
  return appendChained('access_requests', record, ex);
}

export function insertAuditEvent(record: AuditEvent, ex: Executor = db): Promise<AuditEvent> {
  return appendChained('audit_events', record, ex);
}

/** Chained rows of one organization in sequence order, plus the count of pre-chain rows. */
export async function chainRows(table: ChainTable, organizationId: string, ex: Executor = db) {
  const entity = table === 'audit_events' ? AuditEventEntity : AccessRequestEntity;
  const [rows, legacy] = await Promise.all([
    ex.createQueryBuilder(entity, 't').where('t.organization_id = :organizationId AND t.seq IS NOT NULL', { organizationId }).orderBy('t.seq', 'ASC').getMany(),
    ex.createQueryBuilder(entity, 't').where('t.organization_id = :organizationId AND t.seq IS NULL', { organizationId }).getCount(),
  ]);
  return { rows: rows as unknown as (Record<string, unknown> & { id: string; seq: number; prevHash: string | null; hash: string | null; mac: string | null })[], legacy };
}

export interface AccessRequestFilter {
  agentId?: string;
  integrationId?: string;
  grantId?: string;
  decision?: string;
  operation?: string;
  from?: string;
  to?: string;
  search?: string;
  /** The user the agent acted for: matches the subject or email (case-insensitive, partial). */
  user?: string;
  /** Exact session id (Audit → Sessions). */
  sessionId?: string;
}

export async function listAccessRequests(organizationId: string, f: AccessRequestFilter, limit: number, ex: Executor = db): Promise<{ items: AccessRequest[]; total: number }> {
  const qb = ex.createQueryBuilder(AccessRequestEntity, 'r').where('r.organization_id = :organizationId', { organizationId });
  if (f.agentId) qb.andWhere('r.agent_id = :agentId', { agentId: f.agentId });
  if (f.integrationId) qb.andWhere('r.integration_id = :integrationId', { integrationId: f.integrationId });
  if (f.grantId) qb.andWhere('r.grant_id = :grantId', { grantId: f.grantId });
  if (f.decision === 'ALLOW' || f.decision === 'DENY') qb.andWhere('r.decision = :decision', { decision: f.decision });
  if (f.operation) qb.andWhere('r.operation = :operation', { operation: f.operation });
  if (f.from) qb.andWhere('r.created_at >= :from', { from: f.from });
  if (f.to) qb.andWhere('r.created_at <= :to', { to: f.to });
  if (f.search) {
    qb.andWhere(
      `(r.id ILIKE :search OR r.correlation_id ILIKE :search OR r.agent_name ILIKE :search OR r.integration_name ILIKE :search OR r.decision_code ILIKE :search
        OR r.on_behalf_of->>'sub' ILIKE :search OR r.on_behalf_of->>'email' ILIKE :search)`,
      { search: `%${escapeLike(f.search)}%` },
    );
  }
  if (f.sessionId) qb.andWhere(`r.trace->>'sessionId' = :sessionId`, { sessionId: f.sessionId });
  if (f.user) qb.andWhere(`(r.on_behalf_of->>'sub' ILIKE :user OR r.on_behalf_of->>'email' ILIKE :user)`, { user: `%${escapeLike(f.user)}%` });
  const [items, total] = await Promise.all([qb.clone().orderBy('r.created_at', 'DESC').take(limit).getMany(), qb.clone().getCount()]);
  return { items, total };
}

export async function getAccessRequest(organizationId: string, id: string, ex: Executor = db): Promise<AccessRequest | null> {
  return oneBy(ex, AccessRequestEntity, { organizationId, id });
}

/** An agent may read back only its own requests. */
export async function getAccessRequestForAgent(agentId: string, id: string, ex: Executor = db): Promise<AccessRequest | null> {
  return oneBy(ex, AccessRequestEntity, { agentId, id });
}

export async function accessRequestsForGrant(grantId: string, ex: Executor = db): Promise<AccessRequest[]> {
  if (!grantId) return [];
  return ex.find(AccessRequestEntity, { where: { grantId }, order: { createdAt: 'DESC' } });
}

/**
 * Authorized requests of a grant per operation since `since` (budgets). Counted from the
 * append-only access log, so budgets hold across restarts and control-plane instances.
 */
export async function authorizedByOperationSince(grantId: string, since: string, ex: Executor = db): Promise<{ operation: string; n: number }[]> {
  const rows: { operation: string; n: number }[] = await ex.query(
    `SELECT operation, count(*)::int AS n FROM access_requests WHERE grant_id = $1 AND decision = 'ALLOW' AND created_at >= $2 GROUP BY operation`,
    [grantId, since],
  );
  return rows.map((r) => ({ operation: r.operation, n: Number(r.n) }));
}

export async function accessRequestsForAgent(agentId: string, limit: number, ex: Executor = db): Promise<AccessRequest[]> {
  if (!agentId) return [];
  return ex.find(AccessRequestEntity, { where: { agentId }, order: { createdAt: 'DESC' }, take: limit });
}

export async function accessRequestsSince(organizationId: string, sinceIso: string, ex: Executor = db): Promise<AccessRequest[]> {
  return ex.createQueryBuilder(AccessRequestEntity, 'r').where('r.organization_id = :organizationId AND r.created_at >= :since', { organizationId, since: sinceIso }).orderBy('r.created_at', 'DESC').getMany();
}

export async function latestAccessRequests(organizationId: string, limit: number, ex: Executor = db): Promise<AccessRequest[]> {
  return ex.find(AccessRequestEntity, { where: { organizationId }, order: { createdAt: 'DESC' }, take: limit });
}

export async function hasAccessRequests(organizationId: string, ex: Executor = db): Promise<boolean> {
  return ex.existsBy(AccessRequestEntity, { organizationId });
}

export interface AuditEventFilter {
  actorType?: string;
  eventType?: string;
  outcome?: string;
  targetId?: string;
  from?: string;
  to?: string;
  search?: string;
  securityOnly?: boolean;
}

export async function listAuditEvents(organizationId: string, f: AuditEventFilter, limit: number, ex: Executor = db): Promise<{ items: AuditEvent[]; total: number }> {
  const qb: SelectQueryBuilder<AuditEventEntity> = ex.createQueryBuilder(AuditEventEntity, 'e').where('e.organization_id = :organizationId', { organizationId });
  if (f.securityOnly) qb.andWhere(`e.event_type <> 'access.allowed'`);
  if (f.actorType) qb.andWhere('e.actor_type = :actorType', { actorType: f.actorType });
  if (f.eventType) qb.andWhere('e.event_type LIKE :eventType', { eventType: `${escapeLike(f.eventType)}%` });
  if (f.outcome) qb.andWhere('e.outcome = :outcome', { outcome: f.outcome });
  if (f.targetId) qb.andWhere('e.target_id = :targetId', { targetId: f.targetId });
  if (f.from) qb.andWhere('e.created_at >= :from', { from: f.from });
  if (f.to) qb.andWhere('e.created_at <= :to', { to: f.to });
  if (f.search) {
    qb.andWhere('(e.id ILIKE :search OR e.correlation_id ILIKE :search OR e.actor_name ILIKE :search OR e.target_name ILIKE :search OR e.event_type ILIKE :search)', { search: `%${escapeLike(f.search)}%` });
  }
  const [items, total] = await Promise.all([qb.clone().orderBy('e.created_at', 'DESC').take(limit).getMany(), qb.clone().getCount()]);
  return { items, total };
}

export async function getAuditEvent(organizationId: string, id: string, ex: Executor = db): Promise<AuditEvent | null> {
  return oneBy(ex, AuditEventEntity, { organizationId, id });
}

export async function auditEventsByCorrelation(organizationId: string, correlationId: string, ex: Executor = db): Promise<AuditEvent[]> {
  if (!correlationId) return [];
  return ex.find(AuditEventEntity, { where: { organizationId, correlationId }, order: { createdAt: 'ASC' } });
}

/** Allowed/denied request counts per grant since a point in time (access reviews). */
export async function usageByGrant(organizationId: string, sinceIso: string, ex: Executor = db): Promise<Map<string, { allowed: number; denied: number }>> {
  const rows: { grant_id: string; decision: string; n: number }[] = await ex.query(
    `SELECT grant_id, decision, count(*)::int AS n FROM access_requests
      WHERE organization_id = $1 AND created_at >= $2 AND grant_id IS NOT NULL GROUP BY grant_id, decision`,
    [organizationId, sinceIso],
  );
  const out = new Map<string, { allowed: number; denied: number }>();
  for (const r of rows) {
    const cur = out.get(r.grant_id) ?? { allowed: 0, denied: 0 };
    if (r.decision === 'ALLOW') cur.allowed += Number(r.n);
    else cur.denied += Number(r.n);
    out.set(r.grant_id, cur);
  }
  return out;
}

// ---------------------------------------------------------------- sessions (Audit → Sessions)

export interface SessionRow {
  sessionId: string;
  sessionLabel: string | null;
  agentId: string | null;
  agentName: string;
  requests: number;
  allowed: number;
  denied: number;
  held: number;
  firstAt: string;
  lastAt: string;
  integrations: string[];
  users: string[];
  subAgents: string[];
}

const toIso = (v: unknown) => (v instanceof Date ? v : new Date(String(v))).toISOString();

/**
 * Sessions of an organization: requests grouped by session id (and agent), most recent first.
 * Uses the (organization, trace->>'sessionId') index.
 */
export async function listSessions(organizationId: string, f: { agentId?: string; sessionId?: string; search?: string; limit?: number } = {}, ex: Executor = db): Promise<SessionRow[]> {
  const params: unknown[] = [organizationId];
  const conds = ['organization_id = $1', 'trace IS NOT NULL'];
  const p = (v: unknown) => `$${params.push(v)}`;
  if (f.agentId) conds.push(`agent_id = ${p(f.agentId)}`);
  if (f.sessionId) conds.push(`trace->>'sessionId' = ${p(f.sessionId)}`);
  if (f.search) {
    const s = p(`%${escapeLike(f.search)}%`);
    conds.push(`(trace->>'sessionId' ILIKE ${s} OR trace->>'sessionLabel' ILIKE ${s} OR trace->>'traceId' ILIKE ${s} OR agent_name ILIKE ${s})`);
  }
  const limit = p(Math.min(f.limit ?? 100, 500));
  const rows: Record<string, unknown>[] = await ex.query(
    `SELECT trace->>'sessionId' AS session_id,
            (array_agg(trace->>'sessionLabel' ORDER BY created_at DESC) FILTER (WHERE trace->>'sessionLabel' IS NOT NULL))[1] AS session_label,
            agent_id,
            max(agent_name) AS agent_name,
            count(*)::int AS requests,
            (count(*) FILTER (WHERE decision = 'ALLOW'))::int AS allowed,
            (count(*) FILTER (WHERE decision = 'DENY' AND decision_code <> 'APPROVAL_REQUIRED'))::int AS denied,
            (count(*) FILTER (WHERE decision_code = 'APPROVAL_REQUIRED'))::int AS held,
            min(created_at) AS first_at,
            max(created_at) AS last_at,
            array_remove(array_agg(DISTINCT integration_name), '—') AS integrations,
            coalesce(array_agg(DISTINCT on_behalf_of->>'sub') FILTER (WHERE on_behalf_of IS NOT NULL), '{}') AS users,
            coalesce(array_agg(DISTINCT delegation->>'label') FILTER (WHERE delegation IS NOT NULL), '{}') AS sub_agents
       FROM access_requests
      WHERE ${conds.join(' AND ')}
      GROUP BY trace->>'sessionId', agent_id
      ORDER BY max(created_at) DESC
      LIMIT ${limit}`,
    params,
  );
  return rows.map((r) => ({
    sessionId: String(r.session_id),
    sessionLabel: (r.session_label as string | null) ?? null,
    agentId: (r.agent_id as string | null) ?? null,
    agentName: String(r.agent_name),
    requests: Number(r.requests),
    allowed: Number(r.allowed),
    denied: Number(r.denied),
    held: Number(r.held),
    firstAt: toIso(r.first_at),
    lastAt: toIso(r.last_at),
    integrations: (r.integrations as string[]) ?? [],
    users: (r.users as string[]) ?? [],
    subAgents: (r.sub_agents as string[]) ?? [],
  }));
}

/** Every request of one session (of one agent, when given), oldest first. */
export async function sessionTimeline(organizationId: string, sessionId: string, agentId: string | null, ex: Executor = db): Promise<AccessRequest[]> {
  const qb = ex.createQueryBuilder(AccessRequestEntity, 'r').where(`r.organization_id = :organizationId AND r.trace->>'sessionId' = :sessionId`, { organizationId, sessionId });
  if (agentId) qb.andWhere('r.agent_id = :agentId', { agentId });
  return qb.orderBy('r.created_at', 'ASC').take(1000).getMany();
}

/** Requests of a session made before a given time (approvals: "what led to this"). */
export async function sessionRequestsBefore(organizationId: string, sessionId: string, agentId: string | null, before: string, ex: Executor = db): Promise<number> {
  const qb = ex.createQueryBuilder(AccessRequestEntity, 'r').where(`r.organization_id = :organizationId AND r.trace->>'sessionId' = :sessionId AND r.created_at < :before`, { organizationId, sessionId, before });
  if (agentId) qb.andWhere('r.agent_id = :agentId', { agentId });
  return qb.getCount();
}
