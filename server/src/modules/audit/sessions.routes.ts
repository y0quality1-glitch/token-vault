import { Router } from 'express';
import { PERMISSIONS, SESSION_ID, type SessionDetail, type SessionSummary } from '@token-vault/shared';
import { badRequest, notFound } from '../../lib/errors';
import { orgCtx, requirePermission } from '../../middleware/auth';
import { approvalRepo, auditRepo } from '../../store/repos';
import { effectiveStatus } from '../approvals/approvals.service';

/**
 * Audit → Sessions: an agent's requests grouped by the session (conversation, task, job) it
 * said they belong to, or by W3C trace id. Shows why something happened, not just that it did.
 */
export const sessionsRouter = Router();

const q = (v: unknown) => (typeof v === 'string' && v ? v : undefined);

sessionsRouter.get('/sessions', requirePermission(PERMISSIONS.AUDIT_READ), async (req, res) => {
  const { org } = orgCtx(req);
  const items: SessionSummary[] = await auditRepo.listSessions(org.id, { agentId: q(req.query.agentId), search: q(req.query.search), limit: Number(req.query.limit) || 100 });
  res.json({ items });
});

sessionsRouter.get('/sessions/:sessionId', requirePermission(PERMISSIONS.AUDIT_READ), async (req, res) => {
  const { org } = orgCtx(req);
  const sessionId = String(req.params.sessionId);
  if (!SESSION_ID.test(sessionId)) throw badRequest('Not a session id');
  const agentId = q(req.query.agentId) ?? null;
  const [summary] = await auditRepo.listSessions(org.id, { sessionId, agentId: agentId ?? undefined, limit: 1 });
  if (!summary) throw notFound('Session');
  // A session id is the agent's own: without an agent filter, show the most recent agent's session.
  const timeline = await auditRepo.sessionTimeline(org.id, sessionId, summary.agentId);
  const ids = new Set(timeline.map((r) => r.id));
  const approvals = (await approvalRepo.listApprovals(org.id))
    .filter((a) => ids.has(a.requestedByRequestId))
    .map((a) => ({ id: a.id, status: effectiveStatus(a), operation: a.operation, createdAt: a.createdAt, requestId: a.requestedByRequestId }));
  const body: SessionDetail = { ...summary, timeline, approvals };
  res.json(body);
});
