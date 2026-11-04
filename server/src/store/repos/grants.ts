import { and, desc, eq, inArray, ne, sql } from 'drizzle-orm';
import { db, type Executor } from '../../db/client';
import { grants } from '../../db/schema';
import type { GrantRecord } from '../types';

export async function listGrants(organizationId: string, filter: { agentId?: string; integrationId?: string } = {}, ex: Executor = db): Promise<GrantRecord[]> {
  const where = [eq(grants.organizationId, organizationId)];
  if (filter.agentId) where.push(eq(grants.agentId, filter.agentId));
  if (filter.integrationId) where.push(eq(grants.integrationId, filter.integrationId));
  return ex.select().from(grants).where(and(...where)).orderBy(desc(grants.createdAt));
}

export async function getGrant(organizationId: string, id: string, ex: Executor = db): Promise<GrantRecord | null> {
  const [row] = await ex.select().from(grants).where(and(eq(grants.organizationId, organizationId), eq(grants.id, id)));
  return row ?? null;
}

/** All non-superseded grants for an agent + integration pair (input to the policy engine). */
export async function grantsForPair(organizationId: string, agentId: string, integrationId: string, ex: Executor = db): Promise<GrantRecord[]> {
  return ex
    .select()
    .from(grants)
    .where(and(eq(grants.organizationId, organizationId), eq(grants.agentId, agentId), eq(grants.integrationId, integrationId), ne(grants.storedStatus, 'SUPERSEDED')));
}

export async function grantNameExists(organizationId: string, name: string, ex: Executor = db): Promise<boolean> {
  const rows = await ex
    .select({ id: grants.id })
    .from(grants)
    .where(and(eq(grants.organizationId, organizationId), sql`lower(${grants.name}) = lower(${name})`, ne(grants.storedStatus, 'SUPERSEDED')));
  return rows.length > 0;
}

/** Full version chain (v1 … vN) that contains the given grant. */
export async function versionChain(organizationId: string, grant: GrantRecord, ex: Executor = db): Promise<GrantRecord[]> {
  const all = await ex.select().from(grants).where(and(eq(grants.organizationId, organizationId), eq(grants.agentId, grant.agentId), eq(grants.integrationId, grant.integrationId)));
  const byId = new Map(all.map((g) => [g.id, g]));
  let root: GrantRecord = grant;
  while (root.previousVersionId && byId.has(root.previousVersionId)) root = byId.get(root.previousVersionId)!;
  const chain: GrantRecord[] = [];
  let cursor: GrantRecord | undefined = root;
  while (cursor) {
    chain.push(cursor);
    const current: GrantRecord = cursor;
    cursor = all.find((g) => g.previousVersionId === current.id);
  }
  return chain;
}

export async function insertGrant(record: GrantRecord, ex: Executor = db): Promise<GrantRecord> {
  const [row] = await ex.insert(grants).values(record).returning();
  return row!;
}

export async function updateGrant(id: string, patch: Partial<Omit<GrantRecord, 'id' | 'organizationId'>>, ex: Executor = db): Promise<GrantRecord> {
  const [row] = await ex.update(grants).set(patch).where(eq(grants.id, id)).returning();
  return row!;
}

/** Revokes every given grant in one statement. */
export async function revokeGrants(ids: string[], revokedBy: string, reason: string, ex: Executor = db) {
  if (ids.length === 0) return;
  await ex.update(grants).set({ storedStatus: 'REVOKED', revokedAt: new Date().toISOString(), revokedBy, revocationReason: reason }).where(inArray(grants.id, ids));
}

/** Atomic usage counter update after an authorized request. */
export async function recordGrantUse(id: string, ex: Executor = db) {
  await ex
    .update(grants)
    .set({ usageCount: sql`${grants.usageCount} + 1`, lastUsedAt: new Date().toISOString() })
    .where(eq(grants.id, id));
}
