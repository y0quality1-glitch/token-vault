import { Router } from 'express';
import { z } from 'zod';
import { PERMISSIONS } from '@token-vault/shared';
import { transaction } from '../../db/client';
import { conflict, notFound } from '../../lib/errors';
import { parse } from '../../lib/validate';
import { orgCtx, requirePermission } from '../../middleware/auth';
import { orgRepo } from '../../store/repos';
import { recordEvent, userActor } from '../audit/audit.service';

export const organizationsRouter = Router();

organizationsRouter.get('/organizations/current', (req, res) => {
  res.json(orgCtx(req).org);
});

organizationsRouter.patch('/organizations/current', requirePermission(PERMISSIONS.ORG_MANAGE), async (req, res) => {
  const ctx = orgCtx(req);
  const body = parse(
    z.object({
      name: z.string().trim().min(2, 'Name must be at least 2 characters').max(80),
      environment: z.enum(['development', 'staging', 'production']),
    }),
    req.body,
  );
  const org = await transaction(async (tx) => {
    const updated = await orgRepo.updateOrganization(ctx.org.id, { ...body, updatedAt: new Date().toISOString() }, tx);
    await recordEvent({ orgId: updated.id, actor: userActor(ctx), eventType: 'organization.updated', target: { type: 'organization', id: updated.id, name: updated.name }, metadata: body }, tx);
    return updated;
  });
  res.json(org);
});

organizationsRouter.get('/organizations/current/members', async (req, res) => {
  const { org } = orgCtx(req);
  res.json({ items: await orgRepo.listMembers(org.id) });
});

organizationsRouter.patch('/organizations/current/members/:memberId', requirePermission(PERMISSIONS.MEMBERS_MANAGE), async (req, res) => {
  const ctx = orgCtx(req);
  const { role } = parse(z.object({ role: z.enum(['OWNER', 'VAULT_ADMIN', 'SECURITY_ADMIN', 'DEVELOPER', 'AUDITOR']) }), req.body);
  const updated = await transaction(async (tx) => {
    const member = await orgRepo.getMember(ctx.org.id, String(req.params.memberId), tx);
    if (!member) throw notFound('Member');
    if (member.role === 'OWNER' && role !== 'OWNER' && (await orgRepo.countOwners(ctx.org.id, tx)) === 1) throw conflict('An organization must keep at least one owner');
    await orgRepo.updateMemberRole(member.id, role, tx);
    await recordEvent({ orgId: ctx.org.id, actor: userActor(ctx), eventType: 'member.role_changed', target: { type: 'user', id: member.userId, name: member.fullName }, severity: 'warning', metadata: { from: member.role, to: role } }, tx);
    return { ...member, role };
  });
  res.json(updated);
});
