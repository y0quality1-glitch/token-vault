import { db, type Executor } from '../../databases/client';
import { OperationApprovalEntity } from '../../entities';
import { insertRow, oneBy, updateWhere } from './orm';

export type OperationApprovalRecord = Omit<OperationApprovalEntity, keyof import('typeorm').BaseEntity>;

export async function listApprovals(organizationId: string, ex: Executor = db): Promise<OperationApprovalRecord[]> {
  return ex.find(OperationApprovalEntity, { where: { organizationId }, order: { createdAt: 'DESC' } });
}

export async function getApproval(organizationId: string, id: string, ex: Executor = db): Promise<OperationApprovalRecord | null> {
  return oneBy(ex, OperationApprovalEntity, { organizationId, id });
}

/** An agent may read only its own approvals. */
export async function getApprovalForAgent(agentId: string, id: string, ex: Executor = db): Promise<OperationApprovalRecord | null> {
  return oneBy(ex, OperationApprovalEntity, { agentId, id });
}

export async function pendingForAgent(agentId: string, ex: Executor = db): Promise<OperationApprovalRecord[]> {
  if (!agentId) return [];
  return ex.findBy(OperationApprovalEntity, { agentId, status: 'PENDING' });
}

/** The agent's approvals for one exact request, newest first. */
export async function forAgentDigest(agentId: string, digest: string, ex: Executor = db): Promise<OperationApprovalRecord[]> {
  if (!agentId || !digest) return [];
  return ex.find(OperationApprovalEntity, { where: { agentId, requestDigest: digest }, order: { createdAt: 'DESC' } });
}

export async function insertApproval(record: OperationApprovalRecord, ex: Executor = db): Promise<OperationApprovalRecord> {
  return insertRow(ex, OperationApprovalEntity, record, { id: record.id });
}

/** Decides an approval only if it is still PENDING (guards against double decisions). */
export async function decideApproval(id: string, patch: Pick<OperationApprovalRecord, 'status' | 'decidedBy' | 'decidedAt' | 'decisionNote' | 'expiresAt'>, ex: Executor = db): Promise<OperationApprovalRecord | null> {
  return updateWhere(ex, OperationApprovalEntity, "id = :id AND status = 'PENDING'", { id }, patch);
}

/** Uses an APPROVED approval exactly once: returns null if it was already used (or is not approved). */
export async function consumeApproval(id: string, requestId: string, at: string, ex: Executor = db): Promise<OperationApprovalRecord | null> {
  return updateWhere(ex, OperationApprovalEntity, "id = :id AND status = 'APPROVED' AND executed_at IS NULL", { id }, { status: 'EXECUTED', executedAt: at, executedRequestId: requestId });
}
