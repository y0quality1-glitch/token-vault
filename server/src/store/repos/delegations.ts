import { In } from 'typeorm';
import type { Delegation } from '@token-vault/shared';
import { db, type Executor } from '../../databases/client';
import { DelegationEntity } from '../../entities';
import { insertRow, oneBy, updateBy, updateWhere } from './orm';

export type DelegationRecord = Delegation & { credentialHash: string };

export async function insertDelegation(record: DelegationRecord, ex: Executor = db): Promise<DelegationRecord> {
  return insertRow(ex, DelegationEntity, record, { id: record.id }) as Promise<DelegationRecord>;
}

export async function findByKeyId(keyId: string, ex: Executor = db): Promise<DelegationRecord | null> {
  return oneBy(ex, DelegationEntity, { keyId }) as Promise<DelegationRecord | null>;
}

export async function getDelegation(organizationId: string, id: string, ex: Executor = db): Promise<DelegationRecord | null> {
  return oneBy(ex, DelegationEntity, { organizationId, id }) as Promise<DelegationRecord | null>;
}

export async function listDelegations(organizationId: string, f: { agentId?: string; grantId?: string } = {}, ex: Executor = db): Promise<DelegationRecord[]> {
  return ex.find(DelegationEntity, {
    where: { organizationId, ...(f.agentId ? { agentId: f.agentId } : {}), ...(f.grantId ? { grantId: f.grantId } : {}) },
    order: { createdAt: 'DESC' },
    take: 500,
  }) as Promise<DelegationRecord[]>;
}

export async function byIds(ids: string[], ex: Executor = db): Promise<DelegationRecord[]> {
  if (!ids.length) return [];
  return ex.findBy(DelegationEntity, { id: In(ids) }) as Promise<DelegationRecord[]>;
}

/** Not-yet-expired, unrevoked delegations of an agent (for the per-agent limit). */
export async function activeCount(agentId: string, now: string, ex: Executor = db): Promise<number> {
  return ex.createQueryBuilder(DelegationEntity, 'd').where('d.agent_id = :agentId AND d.revoked_at IS NULL AND d.expires_at > :now', { agentId, now }).getCount();
}

/** Revokes one delegation (its descendants stop working because their chain is checked on every request). */
export async function revoke(id: string, patch: { revokedAt: string; revokedBy: string; revocationReason: string | null }, ex: Executor = db): Promise<DelegationRecord | null> {
  return updateWhere(ex, DelegationEntity, 'id = :id AND revoked_at IS NULL', { id }, patch) as Promise<DelegationRecord | null>;
}

export async function touch(id: string, at: string, ex: Executor = db) {
  await updateBy(ex, DelegationEntity, { id }, { lastUsedAt: at });
}

/** A new grant version replaces the old one: its delegations follow it. */
export async function moveToGrant(fromGrantId: string, toGrantId: string, ex: Executor = db) {
  await updateBy(ex, DelegationEntity, { grantId: fromGrantId }, { grantId: toGrantId });
}

/** Authorized requests made through each delegation (from the append-only access log). */
export async function usage(ids: string[], ex: Executor = db): Promise<Map<string, number>> {
  if (!ids.length) return new Map();
  const rows: { id: string; n: number }[] = await ex.query(
    `SELECT delegation->>'id' AS id, count(*)::int AS n FROM access_requests
      WHERE decision = 'ALLOW' AND delegation->>'id' = ANY($1) GROUP BY delegation->>'id'`,
    [ids],
  );
  return new Map(rows.map((r) => [r.id, Number(r.n)]));
}

