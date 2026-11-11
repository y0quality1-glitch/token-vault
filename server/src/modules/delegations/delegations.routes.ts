import { Router } from 'express';
import { PERMISSIONS } from '@token-vault/shared';
import { orgCtx, requirePermission } from '../../middleware/auth';
import { delegationRepo } from '../../store/repos';
import { revokeByAdmin, toViews } from './delegations.service';

/** Console view of sub-agent delegations; revoking one stops everything delegated from it. */
export const delegationsRouter = Router();

const q = (v: unknown) => (typeof v === 'string' && v ? v : undefined);

delegationsRouter.get('/delegations', async (req, res) => {
  const { org } = orgCtx(req);
  const list = await delegationRepo.listDelegations(org.id, { agentId: q(req.query.agentId), grantId: q(req.query.grantId) });
  res.json({ items: await toViews(org.id, list) });
});

delegationsRouter.post('/delegations/:id/revoke', requirePermission(PERMISSIONS.GRANT_REVOKE), async (req, res) => {
  res.json(await revokeByAdmin(orgCtx(req), String(req.params.id), req.body));
});
