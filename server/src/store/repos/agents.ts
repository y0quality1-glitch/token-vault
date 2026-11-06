import { and, eq, or } from 'drizzle-orm';
import { db, type Executor } from '../../db/client';
import { agents } from '../../db/schema';
import type { AgentRecord } from '../types';

export async function listAgents(organizationId: string, ex: Executor = db): Promise<AgentRecord[]> {
  return ex.select().from(agents).where(eq(agents.organizationId, organizationId)).orderBy(agents.createdAt);
}

export async function getAgent(organizationId: string, id: string, ex: Executor = db): Promise<AgentRecord | null> {
  const [row] = await ex.select().from(agents).where(and(eq(agents.organizationId, organizationId), eq(agents.id, id)));
  return row ?? null;
}

/** Credential lookup by the public key ID embedded in tvak_<keyId>_<secret>. */
export async function findAgentByKeyId(keyId: string, ex: Executor = db): Promise<AgentRecord | null> {
  // The current key, or the previous one during a rotation's grace period (the caller checks expiry and hash).
  const [row] = await ex.select().from(agents).where(or(eq(agents.credentialKeyId, keyId), eq(agents.previousCredentialKeyId, keyId)));
  return row ?? null;
}

export async function insertAgent(record: AgentRecord, ex: Executor = db): Promise<AgentRecord> {
  const [row] = await ex.insert(agents).values(record).returning();
  return row!;
}

export async function updateAgent(id: string, patch: Partial<Omit<AgentRecord, 'id' | 'organizationId'>>, ex: Executor = db): Promise<AgentRecord> {
  const [row] = await ex.update(agents).set(patch).where(eq(agents.id, id)).returning();
  return row!;
}
