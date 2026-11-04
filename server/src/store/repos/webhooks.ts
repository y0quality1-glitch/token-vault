import { and, eq, isNotNull } from 'drizzle-orm';
import { db, type Executor } from '../../db/client';
import { webhooks } from '../../db/schema';
import type { WebhookRecord } from '../types';

export async function listWebhooks(organizationId: string, ex: Executor = db): Promise<WebhookRecord[]> {
  return ex.select().from(webhooks).where(eq(webhooks.organizationId, organizationId)).orderBy(webhooks.createdAt);
}

export async function getWebhook(organizationId: string, id: string, ex: Executor = db): Promise<WebhookRecord | null> {
  const [row] = await ex.select().from(webhooks).where(and(eq(webhooks.organizationId, organizationId), eq(webhooks.id, id)));
  return row ?? null;
}

/** Webhooks that completed verification, across organizations (for the heartbeat). */
export async function listVerifiedWebhooks(ex: Executor = db): Promise<WebhookRecord[]> {
  return ex.select().from(webhooks).where(isNotNull(webhooks.verifiedAt));
}

export async function insertWebhook(record: WebhookRecord, ex: Executor = db): Promise<WebhookRecord> {
  const [row] = await ex.insert(webhooks).values(record).returning();
  return row!;
}

export async function updateWebhook(id: string, patch: Partial<Omit<WebhookRecord, 'id' | 'organizationId'>>, ex: Executor = db): Promise<WebhookRecord> {
  const [row] = await ex.update(webhooks).set(patch).where(eq(webhooks.id, id)).returning();
  return row!;
}
