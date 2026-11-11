import { Router } from 'express';
import { PERMISSIONS } from '@token-vault/shared';
import { notFound } from '../../lib/errors';
import { orgCtx, requirePermission } from '../../middleware/auth';
import { approvalRepo } from '../../store/repos';
import { approve, reject, toViews } from './approvals.service';

/** Admin API for operation approvals (requests held back by REQUIRE_APPROVAL policies). */
export const approvalsRouter = Router();

approvalsRouter.get('/approvals', async (req, res) => {
  const { org } = orgCtx(req);
  let items = await toViews(org.id, await approvalRepo.listApprovals(org.id));
  const pending = items.filter((r) => r.status === 'PENDING').length;
  const status = typeof req.query.status === 'string' ? req.query.status : '';
  if (status) items = items.filter((r) => r.status === status);
  res.json({ items, pending });
});

approvalsRouter.get('/approvals/:id', async (req, res) => {
  const { org } = orgCtx(req);
  const r = await approvalRepo.getApproval(org.id, String(req.params.id));
  if (!r) throw notFound('Approval');
  res.json((await toViews(org.id, [r]))[0]);
});

approvalsRouter.post('/approvals/:id/approve', requirePermission(PERMISSIONS.GRANT_APPROVE), async (req, res) => {
  const ctx = orgCtx(req);
  const decided = await approve(ctx, String(req.params.id), req.body);
  res.json((await toViews(ctx.org.id, [decided]))[0]);
});

approvalsRouter.post('/approvals/:id/reject', requirePermission(PERMISSIONS.GRANT_APPROVE), async (req, res) => {
  const ctx = orgCtx(req);
  const decided = await reject(ctx, String(req.params.id), req.body);
  res.json((await toViews(ctx.org.id, [decided]))[0]);
});
