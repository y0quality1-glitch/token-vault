import type { Policy } from '@token-vault/shared';
import { db, type Executor } from '../../databases/client';
import { PolicyEntity } from '../../entities';
import { insertRow, oneBy, updateRow } from './orm';

export async function listPolicies(organizationId: string, ex: Executor = db): Promise<Policy[]> {
  return ex.find(PolicyEntity, { where: { organizationId }, order: { priority: 'ASC', createdAt: 'ASC' } });
}

export async function getPolicy(organizationId: string, id: string, ex: Executor = db): Promise<Policy | null> {
  return oneBy(ex, PolicyEntity, { organizationId, id });
}

export async function insertPolicy(record: Policy, ex: Executor = db): Promise<Policy> {
  return insertRow(ex, PolicyEntity, record, { id: record.id });
}

export async function updatePolicy(id: string, patch: Partial<Omit<Policy, 'id' | 'organizationId'>>, ex: Executor = db): Promise<Policy> {
  return updateRow(ex, PolicyEntity, { id }, patch);
}
