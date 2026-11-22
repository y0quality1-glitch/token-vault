import { db, type Executor } from '../../databases/client';
import { GrantRequestEntity } from '../../entities';
import { insertRow, oneBy, updateWhere } from './orm';

export type GrantRequestRecord = Omit<GrantRequestEntity, keyof import('typeorm').BaseEntity>;

export async function listGrantRequests(organizationId: string, ex: Executor = db): Promise<GrantRequestRecord[]> {
  return ex.find(GrantRequestEntity, { where: { organizationId }, order: { createdAt: 'DESC' } });
}

export async function getGrantRequest(organizationId: string, id: string, ex: Executor = db): Promise<GrantRequestRecord | null> {
  return oneBy(ex, GrantRequestEntity, { organizationId, id });
}

/** An agent may read only its own requests. */
export async function getGrantRequestForAgent(agentId: string, id: string, ex: Executor = db): Promise<GrantRequestRecord | null> {
  return oneBy(ex, GrantRequestEntity, { agentId, id });
}

export async function pendingForAgent(agentId: string, ex: Executor = db): Promise<GrantRequestRecord[]> {
  if (!agentId) return [];
  return ex.findBy(GrantRequestEntity, { agentId, status: 'PENDING' });
}

export async function insertGrantRequest(record: GrantRequestRecord, ex: Executor = db): Promise<GrantRequestRecord> {
  return insertRow(ex, GrantRequestEntity, record, { id: record.id });
}

/** Decides a request only if it is still PENDING (guards against double approval). */
export async function decideGrantRequest(id: string, patch: Partial<Omit<GrantRequestRecord, 'id' | 'organizationId'>>, ex: Executor = db): Promise<GrantRequestRecord | null> {
  return updateWhere(ex, GrantRequestEntity, "id = :id AND status = 'PENDING'", { id }, patch);
}
