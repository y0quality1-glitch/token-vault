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
    where.push(or(ilike(accessRequests.id, p), ilike(accessRequests.correlationId, p), ilike(accessRequests.agentName, p), ilike(accessRequests.integrationName, p), ilike(accessRequests.decisionCode, p))!);
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
