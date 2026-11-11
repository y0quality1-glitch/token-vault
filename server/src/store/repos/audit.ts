import { and, asc, count, desc, eq, gte, ilike, isNotNull, isNull, like, lte, ne, or, sql, type SQL } from 'drizzle-orm';
import type { AccessRequest, AuditEvent } from '@token-vault/shared';
import { config } from '../../config';
import { db, transaction, type Executor } from '../../db/client';
import { link, type ChainTable } from '../../modules/audit/chain';
import { accessRequests, auditEvents } from '../../db/schema';

/**
 * Append-only, tamper-evident audit storage. There are intentionally no update or delete
 * functions; the database also rejects UPDATE/DELETE on these tables (migration 0001).
 *
 * Every insert extends the organization's hash chain (see modules/audit/chain.ts). A
 * transaction-scoped advisory lock per (table, organization) serializes appends, so
 * concurrent writers cannot fork the chain; a unique (organization, seq) index backs it up.
 */
async function appendChained<T extends { organizationId: string }>(table: ChainTable, record: T, ex: Executor): Promise<T> {
  const t = table === 'audit_events' ? auditEvents : accessRequests;
  const run = async (tx: Executor) => {
    await tx.execute(sql`select pg_advisory_xact_lock(hashtext(${table}), hashtext(${record.organizationId}))`);
    const [prev] = await tx
      .select({ seq: t.seq, hash: t.hash })
      .from(t)
      .where(and(eq(t.organizationId, record.organizationId), isNotNull(t.seq)))
      .orderBy(desc(t.seq))
      .limit(1);
    const fields = link(config.auditSigningKey, table, record.organizationId, prev?.seq && prev.hash ? { seq: prev.seq, hash: prev.hash } : null, record as unknown as Record<string, unknown>);
    const [row] = await tx.insert(t).values({ ...(record as Record<string, unknown>), ...fields } as never).returning();
    return row as unknown as T;
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
  const t = table === 'audit_events' ? auditEvents : accessRequests;
  const [rows, [legacy]] = await Promise.all([
    ex.select().from(t).where(and(eq(t.organizationId, organizationId), isNotNull(t.seq))).orderBy(asc(t.seq)),
    ex.select({ n: count() }).from(t).where(and(eq(t.organizationId, organizationId), isNull(t.seq))),
  ]);
  return { rows: rows as (Record<string, unknown> & { id: string; seq: number; prevHash: string | null; hash: string | null; mac: string | null })[], legacy: legacy?.n ?? 0 };
}

const escapeLike = (s: string) => s.replace(/[\\%_]/g, (c) => `\\${c}`);

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
  const where: SQL[] = [eq(accessRequests.organizationId, organizationId)];
  if (f.agentId) where.push(eq(accessRequests.agentId, f.agentId));
  if (f.integrationId) where.push(eq(accessRequests.integrationId, f.integrationId));
  if (f.grantId) where.push(eq(accessRequests.grantId, f.grantId));
  if (f.decision === 'ALLOW' || f.decision === 'DENY') where.push(eq(accessRequests.decision, f.decision));
  if (f.operation) where.push(eq(accessRequests.operation, f.operation));
  if (f.from) where.push(gte(accessRequests.createdAt, f.from));
  if (f.to) where.push(lte(accessRequests.createdAt, f.to));
  if (f.search) {
    const p = `%${escapeLike(f.search)}%`;
    where.push(or(ilike(accessRequests.id, p), ilike(accessRequests.correlationId, p), ilike(accessRequests.agentName, p), ilike(accessRequests.integrationName, p), ilike(accessRequests.decisionCode, p), sql`${accessRequests.onBehalfOf}->>'sub' ilike ${p}`, sql`${accessRequests.onBehalfOf}->>'email' ilike ${p}`)!);
  }
  if (f.sessionId) where.push(sql`${accessRequests.trace}->>'sessionId' = ${f.sessionId}`);
  if (f.user) {
    const p = `%${escapeLike(f.user)}%`;
    where.push(or(sql`${accessRequests.onBehalfOf}->>'sub' ilike ${p}`, sql`${accessRequests.onBehalfOf}->>'email' ilike ${p}`)!);
  }
  const cond = and(...where);
  const [items, [totalRow]] = await Promise.all([
    ex.select().from(accessRequests).where(cond).orderBy(desc(accessRequests.createdAt)).limit(limit),
    ex.select({ n: count() }).from(accessRequests).where(cond),
  ]);
  return { items, total: totalRow?.n ?? 0 };
}

export async function getAccessRequest(organizationId: string, id: string, ex: Executor = db): Promise<AccessRequest | null> {
  const [row] = await ex.select().from(accessRequests).where(and(eq(accessRequests.organizationId, organizationId), eq(accessRequests.id, id)));
  return row ?? null;
}

/** An agent may read back only its own requests. */
export async function getAccessRequestForAgent(agentId: string, id: string, ex: Executor = db): Promise<AccessRequest | null> {
  const [row] = await ex.select().from(accessRequests).where(and(eq(accessRequests.agentId, agentId), eq(accessRequests.id, id)));
  return row ?? null;
}

export async function accessRequestsForGrant(grantId: string, ex: Executor = db): Promise<AccessRequest[]> {
  return ex.select().from(accessRequests).where(eq(accessRequests.grantId, grantId)).orderBy(desc(accessRequests.createdAt));
}

/**
 * Authorized requests of a grant per operation since `since` (budgets). Counted from the
 * append-only access log, so budgets hold across restarts and control-plane instances.
 */
export async function authorizedByOperationSince(grantId: string, since: string, ex: Executor = db): Promise<{ operation: string; n: number }[]> {
  return ex
    .select({ operation: accessRequests.operation, n: count() })
    .from(accessRequests)
    .where(and(eq(accessRequests.grantId, grantId), eq(accessRequests.decision, 'ALLOW'), gte(accessRequests.createdAt, since)))
    .groupBy(accessRequests.operation);
}

export async function accessRequestsForAgent(agentId: string, limit: number, ex: Executor = db): Promise<AccessRequest[]> {
  return ex.select().from(accessRequests).where(eq(accessRequests.agentId, agentId)).orderBy(desc(accessRequests.createdAt)).limit(limit);
}

export async function accessRequestsSince(organizationId: string, sinceIso: string, ex: Executor = db): Promise<AccessRequest[]> {
  return ex
    .select()
    .from(accessRequests)
    .where(and(eq(accessRequests.organizationId, organizationId), gte(accessRequests.createdAt, sinceIso)))
    .orderBy(desc(accessRequests.createdAt));
}

export async function latestAccessRequests(organizationId: string, limit: number, ex: Executor = db): Promise<AccessRequest[]> {
  return ex.select().from(accessRequests).where(eq(accessRequests.organizationId, organizationId)).orderBy(desc(accessRequests.createdAt)).limit(limit);
}

export async function hasAccessRequests(organizationId: string, ex: Executor = db): Promise<boolean> {
  const rows = await ex.select({ id: accessRequests.id }).from(accessRequests).where(eq(accessRequests.organizationId, organizationId)).limit(1);
  return rows.length > 0;
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
  const where: SQL[] = [eq(auditEvents.organizationId, organizationId)];
  if (f.securityOnly) where.push(ne(auditEvents.eventType, 'access.allowed'));
  if (f.actorType) where.push(eq(auditEvents.actorType, f.actorType as AuditEvent['actorType']));
  if (f.eventType) where.push(like(auditEvents.eventType, `${escapeLike(f.eventType)}%`));
  if (f.outcome) where.push(eq(auditEvents.outcome, f.outcome as AuditEvent['outcome']));
  if (f.targetId) where.push(eq(auditEvents.targetId, f.targetId));
  if (f.from) where.push(gte(auditEvents.createdAt, f.from));
  if (f.to) where.push(lte(auditEvents.createdAt, f.to));
  if (f.search) {
    const p = `%${escapeLike(f.search)}%`;
    where.push(or(ilike(auditEvents.id, p), ilike(auditEvents.correlationId, p), ilike(auditEvents.actorName, p), ilike(auditEvents.targetName, p), ilike(auditEvents.eventType, p))!);
  }
  const cond = and(...where);
  const [items, [totalRow]] = await Promise.all([
    ex.select().from(auditEvents).where(cond).orderBy(desc(auditEvents.createdAt)).limit(limit),
    ex.select({ n: count() }).from(auditEvents).where(cond),
  ]);
  return { items, total: totalRow?.n ?? 0 };
}

export async function getAuditEvent(organizationId: string, id: string, ex: Executor = db): Promise<AuditEvent | null> {
  const [row] = await ex.select().from(auditEvents).where(and(eq(auditEvents.organizationId, organizationId), eq(auditEvents.id, id)));
  return row ?? null;
}

export async function auditEventsByCorrelation(organizationId: string, correlationId: string, ex: Executor = db): Promise<AuditEvent[]> {
  return ex.select().from(auditEvents).where(and(eq(auditEvents.organizationId, organizationId), eq(auditEvents.correlationId, correlationId))).orderBy(auditEvents.createdAt);
}

/** Allowed/denied request counts per grant since a point in time (access reviews). */
export async function usageByGrant(organizationId: string, sinceIso: string, ex: Executor = db): Promise<Map<string, { allowed: number; denied: number }>> {
  const rows = await ex
    .select({ grantId: accessRequests.grantId, decision: accessRequests.decision, n: count() })
    .from(accessRequests)
    .where(and(eq(accessRequests.organizationId, organizationId), gte(accessRequests.createdAt, sinceIso), isNotNull(accessRequests.grantId)))
    .groupBy(accessRequests.grantId, accessRequests.decision);
  const out = new Map<string, { allowed: number; denied: number }>();
  for (const r of rows) {
    const cur = out.get(r.grantId!) ?? { allowed: 0, denied: 0 };
    if (r.decision === 'ALLOW') cur.allowed += r.n;
    else cur.denied += r.n;
    out.set(r.grantId!, cur);
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
  const conds = [sql`organization_id = ${organizationId}`, sql`trace is not null`];
  if (f.agentId) conds.push(sql`agent_id = ${f.agentId}`);
  if (f.sessionId) conds.push(sql`trace->>'sessionId' = ${f.sessionId}`);
  if (f.search) {
    const p = `%${escapeLike(f.search)}%`;
    conds.push(sql`(trace->>'sessionId' ilike ${p} or trace->>'sessionLabel' ilike ${p} or trace->>'traceId' ilike ${p} or agent_name ilike ${p})`);
  }
  const result = await ex.execute(sql`
    select trace->>'sessionId' as session_id,
           (array_agg(trace->>'sessionLabel' order by created_at desc) filter (where trace->>'sessionLabel' is not null))[1] as session_label,
           agent_id,
           max(agent_name) as agent_name,
           count(*)::int as requests,
           (count(*) filter (where decision = 'ALLOW'))::int as allowed,
           (count(*) filter (where decision = 'DENY' and decision_code <> 'APPROVAL_REQUIRED'))::int as denied,
           (count(*) filter (where decision_code = 'APPROVAL_REQUIRED'))::int as held,
           min(created_at) as first_at,
           max(created_at) as last_at,
           array_remove(array_agg(distinct integration_name), '—') as integrations,
           coalesce(array_agg(distinct on_behalf_of->>'sub') filter (where on_behalf_of is not null), '{}') as users,
           coalesce(array_agg(distinct delegation->>'label') filter (where delegation is not null), '{}') as sub_agents
      from access_requests
     where ${sql.join(conds, sql` and `)}
     group by trace->>'sessionId', agent_id
     order by max(created_at) desc
     limit ${Math.min(f.limit ?? 100, 500)}`);
  return (result.rows as Record<string, unknown>[]).map((r) => ({
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
  const where: SQL[] = [eq(accessRequests.organizationId, organizationId), sql`${accessRequests.trace}->>'sessionId' = ${sessionId}`];
  if (agentId) where.push(eq(accessRequests.agentId, agentId));
  return ex.select().from(accessRequests).where(and(...where)).orderBy(asc(accessRequests.createdAt)).limit(1000);
}

/** Requests of a session made before a given time (approvals: "what led to this"). */
export async function sessionRequestsBefore(organizationId: string, sessionId: string, agentId: string | null, before: string, ex: Executor = db): Promise<number> {
  const where: SQL[] = [eq(accessRequests.organizationId, organizationId), sql`${accessRequests.trace}->>'sessionId' = ${sessionId}`, sql`${accessRequests.createdAt} < ${before}`];
  if (agentId) where.push(eq(accessRequests.agentId, agentId));
  const [r] = await ex.select({ n: count() }).from(accessRequests).where(and(...where));
  return Number(r?.n ?? 0);
}
