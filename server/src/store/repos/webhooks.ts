import { Not, IsNull } from 'typeorm';
import { db, type Executor } from '../../databases/client';
import { WebhookEntity } from '../../entities';
import type { WebhookRecord } from '../types';
import { insertRow, oneBy, updateRow } from './orm';

export async function listWebhooks(organizationId: string, ex: Executor = db): Promise<WebhookRecord[]> {
  return ex.find(WebhookEntity, { where: { organizationId }, order: { createdAt: 'ASC' } });
}

export async function getWebhook(organizationId: string, id: string, ex: Executor = db): Promise<WebhookRecord | null> {
  return oneBy(ex, WebhookEntity, { organizationId, id });
}

/** Webhooks that completed verification, across organizations (for the heartbeat). */
export async function listVerifiedWebhooks(ex: Executor = db): Promise<WebhookRecord[]> {
  return ex.findBy(WebhookEntity, { verifiedAt: Not(IsNull()) });
}

export async function insertWebhook(record: WebhookRecord, ex: Executor = db): Promise<WebhookRecord> {
  return insertRow(ex, WebhookEntity, record, { id: record.id });
}

export async function updateWebhook(id: string, patch: Partial<Omit<WebhookRecord, 'id' | 'organizationId'>>, ex: Executor = db): Promise<WebhookRecord> {
  return updateRow(ex, WebhookEntity, { id }, patch);
}
