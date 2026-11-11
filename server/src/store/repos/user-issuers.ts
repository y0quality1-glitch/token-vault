import { and, asc, eq } from 'drizzle-orm';
import type { UserIssuer } from '@token-vault/shared';
import { db, type Executor } from '../../db/client';
import { userIssuers } from '../../db/schema';

export async function listIssuers(organizationId: string, ex: Executor = db): Promise<UserIssuer[]> {
  return ex.select().from(userIssuers).where(eq(userIssuers.organizationId, organizationId)).orderBy(asc(userIssuers.createdAt));
}

export async function getIssuer(organizationId: string, id: string, ex: Executor = db): Promise<UserIssuer | null> {
  const [row] = await ex.select().from(userIssuers).where(and(eq(userIssuers.organizationId, organizationId), eq(userIssuers.id, id)));
  return row ?? null;
}

export async function insertIssuer(record: UserIssuer, ex: Executor = db): Promise<UserIssuer> {
  const [row] = await ex.insert(userIssuers).values(record).returning();
  return row!;
}

export async function updateIssuer(organizationId: string, id: string, patch: Partial<Omit<UserIssuer, 'id' | 'organizationId' | 'createdAt'>>, ex: Executor = db): Promise<UserIssuer | null> {
  const [row] = await ex.update(userIssuers).set(patch).where(and(eq(userIssuers.organizationId, organizationId), eq(userIssuers.id, id))).returning();
  return row ?? null;
}

export async function deleteIssuer(organizationId: string, id: string, ex: Executor = db): Promise<boolean> {
  const rows = await ex.delete(userIssuers).where(and(eq(userIssuers.organizationId, organizationId), eq(userIssuers.id, id))).returning({ id: userIssuers.id });
  return rows.length > 0;
}
