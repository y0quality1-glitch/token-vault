import { Router } from 'express';
import { PERMISSIONS } from '@token-vault/shared';
import { notFound } from '../../lib/errors';
import { orgCtx, requirePermission } from '../../middleware/auth';
import { auditRepo } from '../../store/repos';

export const auditRouter = Router();

const q = (v: unknown) => (typeof v === 'string' && v.length > 0 ? v : undefined);
const isoOrUndefined = (v: unknown) => {
  const s = q(v);
  if (!s) return undefined;
  const d = new Date(s);
  return Number.isNaN(d.getTime()) ? undefined : d.toISOString();
};
const limitOf = (v: unknown) => Math.min(Number(v ?? 200) || 200, 500);

auditRouter.get('/access-requests', requirePermission(PERMISSIONS.AUDIT_READ), async (req, res) => {
  const { org } = orgCtx(req);
  const f = req.query;
  res.json(
    await auditRepo.listAccessRequests(
      org.id,
      { agentId: q(f.agentId), integrationId: q(f.integrationId), grantId: q(f.grantId), decision: q(f.decision), operation: q(f.operation), from: isoOrUndefined(f.from), to: isoOrUndefined(f.to), search: q(f.search) },
      limitOf(f.limit),
    ),
  );
});

auditRouter.get('/access-requests/:id', requirePermission(PERMISSIONS.AUDIT_READ), async (req, res) => {
  const { org } = orgCtx(req);
  const item = await auditRepo.getAccessRequest(org.id, String(req.params.id));
  if (!item) throw notFound('Access request');
  const auditEvents = await auditRepo.auditEventsByCorrelation(org.id, item.correlationId);
  res.json({ ...item, auditEvents });
});

auditRouter.get('/audit-events', requirePermission(PERMISSIONS.AUDIT_READ), async (req, res) => {
  const { org } = orgCtx(req);
  const f = req.query;
  res.json(
    await auditRepo.listAuditEvents(
      org.id,
      { securityOnly: f.category === 'security', actorType: q(f.actorType), eventType: q(f.eventType), outcome: q(f.outcome), targetId: q(f.targetId), from: isoOrUndefined(f.from), to: isoOrUndefined(f.to), search: q(f.search) },
      limitOf(f.limit),
    ),
  );
});

auditRouter.get('/audit-events/:id', requirePermission(PERMISSIONS.AUDIT_READ), async (req, res) => {
  const { org } = orgCtx(req);
  const item = await auditRepo.getAuditEvent(org.id, String(req.params.id));
  if (!item) throw notFound('Audit event');
  res.json(item);
});
