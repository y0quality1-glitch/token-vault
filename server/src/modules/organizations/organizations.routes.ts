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

// ---------------------------------------------------------------- emergency stop
/**
 * One switch that denies every agent request in the organization (EMERGENCY_STOP) until it
 * is lifted. Grants, keys and credentials are left untouched, so lifting it restores access
 * exactly as it was. Stopping needs grant:revoke; lifting (re-opening access) needs grant:approve.
 */
async function stopView(orgId: string) {
  const org = (await orgRepo.getOrganization(orgId))!;
  const byName = org.emergencyStoppedBy ? ((await orgRepo.userNames([org.emergencyStoppedBy])).get(org.emergencyStoppedBy) ?? 'Unknown user') : null;
  return { stopped: !!org.emergencyStoppedAt, stoppedAt: org.emergencyStoppedAt ?? null, stoppedBy: org.emergencyStoppedBy ?? null, stoppedByName: byName, reason: org.emergencyStopReason ?? null };
}

organizationsRouter.get('/organizations/current/emergency-stop', async (req, res) => {
  res.json(await stopView(orgCtx(req).org.id));
});

organizationsRouter.post('/organizations/current/emergency-stop', requirePermission(PERMISSIONS.GRANT_REVOKE), async (req, res) => {
  const ctx = orgCtx(req);
  const { reason } = parse(z.object({ reason: z.string().trim().min(3, 'Say why (at least 3 characters)').max(240) }), req.body ?? {});
  await transaction(async (tx) => {
    const org = (await orgRepo.getOrganization(ctx.org.id, tx))!;
    if (org.emergencyStoppedAt) throw conflict('Agent access is already stopped');
    const now = new Date().toISOString();
    await orgRepo.updateOrganization(org.id, { emergencyStoppedAt: now, emergencyStoppedBy: ctx.user.id, emergencyStopReason: reason, updatedAt: now }, tx);
    await recordEvent({ orgId: org.id, actor: userActor(ctx), eventType: 'organization.emergency_stop', target: { type: 'organization', id: org.id, name: org.name }, severity: 'critical', metadata: { reason } }, tx);
  });
  res.json(await stopView(ctx.org.id));
});

organizationsRouter.post('/organizations/current/emergency-stop/lift', requirePermission(PERMISSIONS.GRANT_APPROVE), async (req, res) => {
  const ctx = orgCtx(req);
  const { note } = parse(z.object({ note: z.string().trim().max(240).default('') }), req.body ?? {});
  await transaction(async (tx) => {
    const org = (await orgRepo.getOrganization(ctx.org.id, tx))!;
    if (!org.emergencyStoppedAt) throw conflict('Agent access is not stopped');
    await orgRepo.updateOrganization(org.id, { emergencyStoppedAt: null, emergencyStoppedBy: null, emergencyStopReason: null, updatedAt: new Date().toISOString() }, tx);
    await recordEvent({ orgId: org.id, actor: userActor(ctx), eventType: 'organization.emergency_stop_lifted', target: { type: 'organization', id: org.id, name: org.name }, severity: 'warning', metadata: { stoppedAt: org.emergencyStoppedAt, reason: org.emergencyStopReason, note } }, tx);
  });
  res.json(await stopView(ctx.org.id));
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
