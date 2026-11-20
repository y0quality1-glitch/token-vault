import { db, type Executor } from '../../databases/client';
import { AgentEntity } from '../../entities';
import type { AgentRecord } from '../types';
import { insertRow, oneBy, updateRow } from './orm';

export async function listAgents(organizationId: string, ex: Executor = db): Promise<AgentRecord[]> {
  return ex.find(AgentEntity, { where: { organizationId }, order: { createdAt: 'ASC' } });
}

export async function getAgent(organizationId: string, id: string, ex: Executor = db): Promise<AgentRecord | null> {
  return oneBy(ex, AgentEntity, { organizationId, id });
}

/** Credential lookup by the public key ID embedded in tvak_<keyId>_<secret>. */
export async function findAgentByKeyId(keyId: string, ex: Executor = db): Promise<AgentRecord | null> {
  // The current key, or the previous one during a rotation's grace period (the caller checks expiry and hash).
  return ex.findOne(AgentEntity, { where: [{ credentialKeyId: keyId }, { previousCredentialKeyId: keyId }] });
}

export async function insertAgent(record: AgentRecord, ex: Executor = db): Promise<AgentRecord> {
  return insertRow(ex, AgentEntity, record, { id: record.id });
}

export async function updateAgent(id: string, patch: Partial<Omit<AgentRecord, 'id' | 'organizationId'>>, ex: Executor = db): Promise<AgentRecord> {
  return updateRow(ex, AgentEntity, { id }, patch);
}
