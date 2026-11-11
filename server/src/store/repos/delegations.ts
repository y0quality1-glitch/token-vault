import { and, count, desc, eq, inArray, isNull, sql } from 'drizzle-orm';
import type { Delegation } from '@token-vault/shared';
import { db, type Executor } from '../../db/client';
import { accessRequests, delegations } from '../../db/schema';

export type DelegationRecord = Delegation & { credentialHash: string };

export async function insertDelegation(record: DelegationRecord, ex: Executor = db): Promise<DelegationRecord> {
  const [row] = await ex.insert(delegations).values(record).returning();
  return row!;
}

export async function findByKeyId(keyId: string, ex: Executor = db): Promise<DelegationRecord | null> {
  const [row] = await ex.select().from(delegations).where(eq(delegations.keyId, keyId));
  return row ?? null;
}

export async function getDelegation(organizationId: string, id: string, ex: Executor = db): Promise<DelegationRecord | null> {
  const [row] = await ex.select().from(delegations).where(and(eq(delegations.organizationId, organizationId), eq(delegations.id, id)));
  return row ?? null;
}

export async function listDelegations(organizationId: string, f: { agentId?: string; grantId?: string } = {}, ex: Executor = db): Promise<DelegationRecord[]> {
  const where = [eq(delegations.organizationId, organizationId)];
  if (f.agentId) where.push(eq(delegations.agentId, f.agentId));
  if (f.grantId) where.push(eq(delegations.grantId, f.grantId));
  return ex.select().from(delegations).where(and(...where)).orderBy(desc(delegations.createdAt)).limit(500);
}

export async function byIds(ids: string[], ex: Executor = db): Promise<DelegationRecord[]> {
  if (!ids.length) return [];
  return ex.select().from(delegations).where(inArray(delegations.id, ids));
}

/** Not-yet-expired, unrevoked delegations of an agent (for the per-agent limit). */
export async function activeCount(agentId: string, now: string, ex: Executor = db): Promise<number> {
  const [r] = await ex.select({ n: count() }).from(delegations).where(and(eq(delegations.agentId, agentId), isNull(delegations.revokedAt), sql`${delegations.expiresAt} > ${now}`));
  return Number(r?.n ?? 0);
}

/** Revokes one delegation (its descendants stop working because their chain is checked on every request). */
export async function revoke(id: string, patch: { revokedAt: string; revokedBy: string; revocationReason: string | null }, ex: Executor = db): Promise<DelegationRecord | null> {
  const [row] = await ex.update(delegations).set(patch).where(and(eq(delegations.id, id), isNull(delegations.revokedAt))).returning();
  return row ?? null;
}

export async function touch(id: string, at: string, ex: Executor = db) {
  await ex.update(delegations).set({ lastUsedAt: at }).where(eq(delegations.id, id));
}

/** A new grant version replaces the old one: its delegations follow it. */
export async function moveToGrant(fromGrantId: string, toGrantId: string, ex: Executor = db) {
  await ex.update(delegations).set({ grantId: toGrantId }).where(eq(delegations.grantId, fromGrantId));
}

/** Authorized requests made through each delegation (from the append-only access log). */
export async function usage(ids: string[], ex: Executor = db): Promise<Map<string, number>> {
  if (!ids.length) return new Map();
  const id = sql<string>`${accessRequests.delegation}->>'id'`;
  const rows = await ex
    .select({ id, n: count() })
    .from(accessRequests)
    .where(and(eq(accessRequests.decision, 'ALLOW'), inArray(id, ids)))
    .groupBy(id);
  return new Map(rows.map((r) => [r.id, Number(r.n)]));
}
