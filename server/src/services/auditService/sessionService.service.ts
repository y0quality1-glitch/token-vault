import { SESSION_ID, type SessionDetail, type SessionSummary } from '@token-vault/shared';
import { badRequest, notFound } from '../../lib/errors';
import { approvalRepo, auditRepo } from '../../store/repos';
import { effectiveStatus } from '../approvalService/approvalService.service';

const q = (v: unknown) => (typeof v === 'string' && v ? v : undefined);

/**
 * Audit → Sessions: an agent's requests grouped by the session (conversation, task, job) it
 * said they belong to, or by W3C trace id. Shows why something happened, not just that it did.
 */
export default class SessionService {
  async list(orgId: string, f: Record<string, unknown> = {}): Promise<{ items: SessionSummary[] }> {
    const items: SessionSummary[] = await auditRepo.listSessions(orgId, { agentId: q(f.agentId), search: q(f.search), limit: Number(f.limit) || 100 });
    return { items };
  }

  async get(orgId: string, sessionId: string, agentFilter?: unknown): Promise<SessionDetail> {
    if (!SESSION_ID.test(sessionId)) throw badRequest('Not a session id');
    const agentId = q(agentFilter) ?? null;
    const [summary] = await auditRepo.listSessions(orgId, { sessionId, agentId: agentId ?? undefined, limit: 1 });
    if (!summary) throw notFound('Session');
    // A session id is the agent's own: without an agent filter, show the most recent agent's session.
    const timeline = await auditRepo.sessionTimeline(orgId, sessionId, summary.agentId);
    const ids = new Set(timeline.map((r) => r.id));
    const approvals = (await approvalRepo.listApprovals(orgId))
      .filter((a) => ids.has(a.requestedByRequestId))
      .map((a) => ({ id: a.id, status: effectiveStatus(a), operation: a.operation, createdAt: a.createdAt, requestId: a.requestedByRequestId }));
    return { ...summary, timeline, approvals };
  }
}
