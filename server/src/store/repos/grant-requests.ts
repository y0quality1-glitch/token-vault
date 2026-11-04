import { and, desc, eq } from 'drizzle-orm';
import { db, type Executor } from '../../db/client';
import { grantRequests } from '../../db/schema';

export type GrantRequestRecord = typeof grantRequests.$inferSelect;

export async function listGrantRequests(organizationId: string, ex: Executor = db): Promise<GrantRequestRecord[]> {
  return ex.select().from(grantRequests).where(eq(grantRequests.organizationId, organizationId)).orderBy(desc(grantRequests.createdAt));
}

export async function getGrantRequest(organizationId: string, id: string, ex: Executor = db): Promise<GrantRequestRecord | null> {
  const [row] = await ex.select().from(grantRequests).where(and(eq(grantRequests.organizationId, organizationId), eq(grantRequests.id, id)));
  return row ?? null;
}

/** An agent may read only its own requests. */
export async function getGrantRequestForAgent(agentId: string, id: string, ex: Executor = db): Promise<GrantRequestRecord | null> {
  const [row] = await ex.select().from(grantRequests).where(and(eq(grantRequests.agentId, agentId), eq(grantRequests.id, id)));
  return row ?? null;
}

export async function pendingForAgent(agentId: string, ex: Executor = db): Promise<GrantRequestRecord[]> {
  return ex.select().from(grantRequests).where(and(eq(grantRequests.agentId, agentId), eq(grantRequests.status, 'PENDING')));
}

export async function insertGrantRequest(record: GrantRequestRecord, ex: Executor = db): Promise<GrantRequestRecord> {
  const [row] = await ex.insert(grantRequests).values(record).returning();
  return row!;
}

/** Decides a request only if it is still PENDING (guards against double approval). */
export async function decideGrantRequest(id: string, patch: Partial<Omit<GrantRequestRecord, 'id' | 'organizationId'>>, ex: Executor = db): Promise<GrantRequestRecord | null> {
  const [row] = await ex
    .update(grantRequests)
    .set(patch)
    .where(and(eq(grantRequests.id, id), eq(grantRequests.status, 'PENDING')))
    .returning();
  return row ?? null;
}
