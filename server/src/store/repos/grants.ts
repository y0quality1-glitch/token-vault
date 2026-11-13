import { In, Not } from 'typeorm';
import { db, type Executor } from '../../databases/client';
import { GrantEntity } from '../../entities';
import type { GrantRecord } from '../types';
import { insertRow, oneBy, updateRow } from './orm';

export async function listGrants(organizationId: string, filter: { agentId?: string; integrationId?: string } = {}, ex: Executor = db): Promise<GrantRecord[]> {
  return ex.find(GrantEntity, {
    where: { organizationId, ...(filter.agentId ? { agentId: filter.agentId } : {}), ...(filter.integrationId ? { integrationId: filter.integrationId } : {}) },
    order: { createdAt: 'DESC' },
  });
}

export async function getGrant(organizationId: string, id: string, ex: Executor = db): Promise<GrantRecord | null> {
  return oneBy(ex, GrantEntity, { organizationId, id });
}

/** All non-superseded grants for an agent + integration pair (input to the policy engine). */
export async function grantsForPair(organizationId: string, agentId: string, integrationId: string, ex: Executor = db): Promise<GrantRecord[]> {
  if (!organizationId || !agentId || !integrationId) return [];
  return ex.findBy(GrantEntity, { organizationId, agentId, integrationId, storedStatus: Not('SUPERSEDED') });
}

export async function grantNameExists(organizationId: string, name: string, ex: Executor = db): Promise<boolean> {
  return ex
    .createQueryBuilder(GrantEntity, 'g')
    .where('g.organization_id = :organizationId AND lower(g.name) = lower(:name) AND g.status <> :superseded', { organizationId, name, superseded: 'SUPERSEDED' })
    .getExists();
}

/** Full version chain (v1 … vN) that contains the given grant. */
export async function versionChain(organizationId: string, grant: GrantRecord, ex: Executor = db): Promise<GrantRecord[]> {
  const all: GrantRecord[] = await ex.findBy(GrantEntity, { organizationId, agentId: grant.agentId, integrationId: grant.integrationId });
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
  return insertRow(ex, GrantEntity, record, { id: record.id });
}

export async function updateGrant(id: string, patch: Partial<Omit<GrantRecord, 'id' | 'organizationId'>>, ex: Executor = db): Promise<GrantRecord> {
  return updateRow(ex, GrantEntity, { id }, patch);
}

/** Revokes every given grant in one statement. */
export async function revokeGrants(ids: string[], revokedBy: string, reason: string, ex: Executor = db) {
  if (ids.length === 0) return;
  await ex.update(GrantEntity, { id: In(ids) }, { storedStatus: 'REVOKED', revokedAt: new Date().toISOString(), revokedBy, revocationReason: reason });
}

/** Atomic usage counter update after an authorized request. */
export async function recordGrantUse(id: string, ex: Executor = db) {
  await ex
    .createQueryBuilder()
    .update(GrantEntity)
    .set({ usageCount: () => 'usage_count + 1', lastUsedAt: new Date().toISOString() })
    .where('id = :id', { id })
    .execute();
}
