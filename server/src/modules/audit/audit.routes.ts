import { Router } from 'express';
import { PERMISSIONS } from '@token-vault/shared';
import { notFound } from '../../lib/errors';
import { orgCtx, requirePermission } from '../../middleware/auth';
import { db, inOrg } from '../../store/db';

export const auditRouter = Router();

function inRange(createdAt: string, from?: unknown, to?: unknown) {
  if (typeof from === 'string' && from && createdAt < new Date(from).toISOString()) return false;
  if (typeof to === 'string' && to && createdAt > new Date(to).toISOString()) return false;
  return true;
}

const q = (v: unknown) => (typeof v === 'string' && v.length > 0 ? v : undefined);

auditRouter.get('/access-requests', requirePermission(PERMISSIONS.AUDIT_READ), (req, res) => {
  const { org } = orgCtx(req);
  const { agentId, integrationId, decision, operation, from, to, search, grantId } = req.query;
  let items = inOrg(db.accessRequests, org.id).filter((r) => inRange(r.createdAt, from, to));
  if (q(agentId)) items = items.filter((r) => r.agentId === agentId);
  if (q(integrationId)) items = items.filter((r) => r.integrationId === integrationId);
  if (q(grantId)) items = items.filter((r) => r.grantId === grantId);
  if (q(decision)) items = items.filter((r) => r.decision === decision);
  if (q(operation)) items = items.filter((r) => r.operation === operation);
  if (q(search)) {
    const s = String(search).toLowerCase();
    items = items.filter((r) => [r.id, r.correlationId, r.agentName, r.integrationName, r.decisionCode].some((v) => v.toLowerCase().includes(s)));
  }
  const limit = Math.min(Number(req.query.limit ?? 200) || 200, 500);
  res.json({ items: items.slice(0, limit), total: items.length });
});

auditRouter.get('/access-requests/:id', requirePermission(PERMISSIONS.AUDIT_READ), (req, res) => {
  const { org } = orgCtx(req);
  const item = db.accessRequests.find((r) => r.id === String(req.params.id) && r.organizationId === org.id);
  if (!item) throw notFound('Access request');
  const auditEvents = db.auditEvents.filter((e) => e.organizationId === org.id && e.correlationId === item.correlationId);
  res.json({ ...item, auditEvents });
});

auditRouter.get('/audit-events', requirePermission(PERMISSIONS.AUDIT_READ), (req, res) => {
  const { org } = orgCtx(req);
  const { actorType, eventType, outcome, targetId, from, to, search, category } = req.query;
  let items = inOrg(db.auditEvents, org.id).filter((e) => inRange(e.createdAt, from, to));
  if (category === 'security') items = items.filter((e) => !e.eventType.startsWith('access.allowed'));
  if (q(actorType)) items = items.filter((e) => e.actorType === actorType);
  if (q(eventType)) items = items.filter((e) => e.eventType.startsWith(String(eventType)));
  if (q(outcome)) items = items.filter((e) => e.outcome === outcome);
  if (q(targetId)) items = items.filter((e) => e.targetId === targetId);
  if (q(search)) {
    const s = String(search).toLowerCase();
    items = items.filter((e) => [e.id, e.correlationId, e.actorName, e.targetName, e.eventType].some((v) => v.toLowerCase().includes(s)));
  }
  const limit = Math.min(Number(req.query.limit ?? 200) || 200, 500);
  res.json({ items: items.slice(0, limit), total: items.length });
});

auditRouter.get('/audit-events/:id', requirePermission(PERMISSIONS.AUDIT_READ), (req, res) => {
  const { org } = orgCtx(req);
  const item = db.auditEvents.find((e) => e.id === String(req.params.id) && e.organizationId === org.id);
  if (!item) throw notFound('Audit event');
  res.json(item);
});
