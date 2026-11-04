import { Router } from 'express';
import { PERMISSIONS } from '@token-vault/shared';
import { notFound } from '../../lib/errors';
import { orgCtx, requirePermission } from '../../middleware/auth';
import { grantRequestRepo } from '../../store/repos';
import { approve, reject, toViews } from './grant-requests.service';

/** Admin API for just-in-time access requests (named grant-requests to avoid clashing with the access-request audit log). */
export const grantRequestsRouter = Router();

grantRequestsRouter.get('/grant-requests', async (req, res) => {
  const { org } = orgCtx(req);
  let items = await toViews(org.id, await grantRequestRepo.listGrantRequests(org.id));
  const status = typeof req.query.status === 'string' ? req.query.status : '';
  if (status) items = items.filter((r) => r.status === status);
  res.json({ items, pending: items.filter((r) => r.status === 'PENDING').length });
});

grantRequestsRouter.get('/grant-requests/:id', async (req, res) => {
  const { org } = orgCtx(req);
  const r = await grantRequestRepo.getGrantRequest(org.id, String(req.params.id));
  if (!r) throw notFound('Access request');
  res.json((await toViews(org.id, [r]))[0]);
});

grantRequestsRouter.post('/grant-requests/:id/approve', requirePermission(PERMISSIONS.GRANT_APPROVE), async (req, res) => {
  const ctx = orgCtx(req);
  const decided = await approve(ctx, String(req.params.id), req.body);
  res.json((await toViews(ctx.org.id, [decided]))[0]);
});

grantRequestsRouter.post('/grant-requests/:id/reject', requirePermission(PERMISSIONS.GRANT_APPROVE), async (req, res) => {
  const ctx = orgCtx(req);
  const decided = await reject(ctx, String(req.params.id), req.body);
  res.json((await toViews(ctx.org.id, [decided]))[0]);
});
