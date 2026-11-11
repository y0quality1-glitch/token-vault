import { and, desc, eq, isNull } from 'drizzle-orm';
import { db, type Executor } from '../../db/client';
import { operationApprovals } from '../../db/schema';

export type OperationApprovalRecord = typeof operationApprovals.$inferSelect;

export async function listApprovals(organizationId: string, ex: Executor = db): Promise<OperationApprovalRecord[]> {
  return ex.select().from(operationApprovals).where(eq(operationApprovals.organizationId, organizationId)).orderBy(desc(operationApprovals.createdAt));
}

export async function getApproval(organizationId: string, id: string, ex: Executor = db): Promise<OperationApprovalRecord | null> {
  const [row] = await ex.select().from(operationApprovals).where(and(eq(operationApprovals.organizationId, organizationId), eq(operationApprovals.id, id)));
  return row ?? null;
}

/** An agent may read only its own approvals. */
export async function getApprovalForAgent(agentId: string, id: string, ex: Executor = db): Promise<OperationApprovalRecord | null> {
  const [row] = await ex.select().from(operationApprovals).where(and(eq(operationApprovals.agentId, agentId), eq(operationApprovals.id, id)));
  return row ?? null;
}

export async function pendingForAgent(agentId: string, ex: Executor = db): Promise<OperationApprovalRecord[]> {
  return ex.select().from(operationApprovals).where(and(eq(operationApprovals.agentId, agentId), eq(operationApprovals.status, 'PENDING')));
}

/** The agent's approvals for one exact request, newest first. */
export async function forAgentDigest(agentId: string, digest: string, ex: Executor = db): Promise<OperationApprovalRecord[]> {
  return ex
    .select()
    .from(operationApprovals)
    .where(and(eq(operationApprovals.agentId, agentId), eq(operationApprovals.requestDigest, digest)))
    .orderBy(desc(operationApprovals.createdAt));
}

export async function insertApproval(record: OperationApprovalRecord, ex: Executor = db): Promise<OperationApprovalRecord> {
  const [row] = await ex.insert(operationApprovals).values(record).returning();
  return row!;
}

/** Decides an approval only if it is still PENDING (guards against double decisions). */
export async function decideApproval(id: string, patch: Pick<OperationApprovalRecord, 'status' | 'decidedBy' | 'decidedAt' | 'decisionNote' | 'expiresAt'>, ex: Executor = db): Promise<OperationApprovalRecord | null> {
  const [row] = await ex
    .update(operationApprovals)
    .set(patch)
    .where(and(eq(operationApprovals.id, id), eq(operationApprovals.status, 'PENDING')))
    .returning();
  return row ?? null;
}

/** Uses an APPROVED approval exactly once: returns null if it was already used (or is not approved). */
export async function consumeApproval(id: string, requestId: string, at: string, ex: Executor = db): Promise<OperationApprovalRecord | null> {
  const [row] = await ex
    .update(operationApprovals)
    .set({ status: 'EXECUTED', executedAt: at, executedRequestId: requestId })
    .where(and(eq(operationApprovals.id, id), eq(operationApprovals.status, 'APPROVED'), isNull(operationApprovals.executedAt)))
    .returning();
  return row ?? null;
}
