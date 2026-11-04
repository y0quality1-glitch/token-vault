import { and, asc, eq } from 'drizzle-orm';
import type { Policy } from '@token-vault/shared';
import { db, type Executor } from '../../db/client';
import { policies } from '../../db/schema';

export async function listPolicies(organizationId: string, ex: Executor = db): Promise<Policy[]> {
  return ex.select().from(policies).where(eq(policies.organizationId, organizationId)).orderBy(asc(policies.priority), asc(policies.createdAt));
}

export async function getPolicy(organizationId: string, id: string, ex: Executor = db): Promise<Policy | null> {
  const [row] = await ex.select().from(policies).where(and(eq(policies.organizationId, organizationId), eq(policies.id, id)));
  return row ?? null;
}

export async function insertPolicy(record: Policy, ex: Executor = db): Promise<Policy> {
  const [row] = await ex.insert(policies).values(record).returning();
  return row!;
}

export async function updatePolicy(id: string, patch: Partial<Omit<Policy, 'id' | 'organizationId'>>, ex: Executor = db): Promise<Policy> {
  const [row] = await ex.update(policies).set(patch).where(eq(policies.id, id)).returning();
  return row!;
}
