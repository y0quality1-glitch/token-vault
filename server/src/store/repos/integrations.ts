import { and, eq, isNull } from 'drizzle-orm';
import { db, type Executor } from '../../db/client';
import { integrations } from '../../db/schema';
import type { IntegrationRecord } from '../types';

const live = isNull(integrations.deletedAt);

export async function listIntegrations(organizationId: string, ex: Executor = db): Promise<IntegrationRecord[]> {
  return ex.select().from(integrations).where(and(eq(integrations.organizationId, organizationId), live)).orderBy(integrations.createdAt);
}

export async function getIntegration(organizationId: string, id: string, ex: Executor = db): Promise<IntegrationRecord | null> {
  const [row] = await ex.select().from(integrations).where(and(eq(integrations.organizationId, organizationId), eq(integrations.id, id), live));
  return row ?? null;
}

/** Display names including soft-deleted integrations (for grants and audit views). */
export async function integrationNames(organizationId: string, ex: Executor = db): Promise<Map<string, string>> {
  const rows = await ex.select({ id: integrations.id, name: integrations.displayName, deletedAt: integrations.deletedAt }).from(integrations).where(eq(integrations.organizationId, organizationId));
  return new Map(rows.map((r) => [r.id, r.deletedAt ? `${r.name} (deleted)` : r.name]));
}

/** Seeded integrations whose masked identifier has not yet been fetched from the webhook. */
export async function listUnsyncedIntegrations(ex: Executor = db): Promise<IntegrationRecord[]> {
  return ex.select().from(integrations).where(and(eq(integrations.maskedIdentifier, ''), live));
}

export async function insertIntegration(record: IntegrationRecord, ex: Executor = db): Promise<IntegrationRecord> {
  const [row] = await ex.insert(integrations).values(record).returning();
  return row!;
}

export async function updateIntegration(id: string, patch: Partial<Omit<IntegrationRecord, 'id' | 'organizationId'>>, ex: Executor = db): Promise<IntegrationRecord> {
  const [row] = await ex.update(integrations).set(patch).where(eq(integrations.id, id)).returning();
  return row!;
}
