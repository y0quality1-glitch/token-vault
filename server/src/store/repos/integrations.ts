import { IsNull, Not } from 'typeorm';
import { db, type Executor } from '../../databases/client';
import { IntegrationEntity } from '../../entities';
import type { IntegrationRecord } from '../types';
import { insertRow, updateRow, updateWhere } from './orm';

/** Soft-deleted integrations are hidden from everything except name lookups. */
const live = { deletedAt: IsNull() };

export async function listIntegrations(organizationId: string, ex: Executor = db): Promise<IntegrationRecord[]> {
  return ex.find(IntegrationEntity, { where: { organizationId, ...live }, order: { createdAt: 'ASC' } });
}

export async function getIntegration(organizationId: string, id: string, ex: Executor = db): Promise<IntegrationRecord | null> {
  if (!id || !organizationId) return null;
  return ex.findOneBy(IntegrationEntity, { organizationId, id, ...live });
}

/** Display names including soft-deleted integrations (for grants and audit views). */
export async function integrationNames(organizationId: string, ex: Executor = db): Promise<Map<string, string>> {
  const rows = await ex.find(IntegrationEntity, { where: { organizationId }, select: { id: true, displayName: true, deletedAt: true } });
  return new Map(rows.map((r) => [r.id, r.deletedAt ? `${r.displayName} (deleted)` : r.displayName]));
}

/** Seeded integrations whose masked identifier has not yet been fetched from the webhook. */
export async function listUnsyncedIntegrations(ex: Executor = db): Promise<IntegrationRecord[]> {
  return ex.findBy(IntegrationEntity, { maskedIdentifier: '', ...live });
}

export async function insertIntegration(record: IntegrationRecord, ex: Executor = db): Promise<IntegrationRecord> {
  return insertRow(ex, IntegrationEntity, record, { id: record.id });
}

export async function updateIntegration(id: string, patch: Partial<Omit<IntegrationRecord, 'id' | 'organizationId'>>, ex: Executor = db): Promise<IntegrationRecord> {
  return updateRow(ex, IntegrationEntity, { id }, patch);
}

/** Every live integration that is not disabled, across organizations (scheduled credential checks). */
export async function listCheckableIntegrations(organizationId?: string, ex: Executor = db): Promise<IntegrationRecord[]> {
  return ex.find(IntegrationEntity, {
    where: { ...live, credentialStatus: Not('DISABLED'), ...(organizationId ? { organizationId } : {}) },
    order: { organizationId: 'ASC', createdAt: 'ASC' },
  });
}

/**
 * Changes the credential status only if it is still one of `from` (so concurrent reports of
 * the same rejection change it, and audit it, once). Returns the updated row, or null.
 */
export async function transitionCredentialStatus(id: string, from: IntegrationRecord['credentialStatus'][], patch: Partial<Omit<IntegrationRecord, 'id' | 'organizationId'>>, ex: Executor = db): Promise<IntegrationRecord | null> {
  if (!from.length) return null;
  return updateWhere(ex, IntegrationEntity, 'id = :id AND credential_status IN (:...from) AND deleted_at IS NULL', { id, from }, patch);
}
