import { Router } from 'express';
import { z } from 'zod';
import { PERMISSIONS, type Member } from '@token-vault/shared';
import { conflict, notFound } from '../../lib/errors';
import { parse } from '../../lib/validate';
import { orgCtx, requirePermission } from '../../middleware/auth';
import { db } from '../../store/db';
import { recordEvent, userActor } from '../audit/audit.service';

export const organizationsRouter = Router();

organizationsRouter.get('/organizations/current', (req, res) => {
  res.json(orgCtx(req).org);
});

organizationsRouter.patch('/organizations/current', requirePermission(PERMISSIONS.ORG_MANAGE), (req, res) => {
  const ctx = orgCtx(req);
  const body = parse(
    z.object({
      name: z.string().trim().min(2, 'Name must be at least 2 characters').max(80),
      environment: z.enum(['development', 'staging', 'production']),
    }),
    req.body,
  );
  const org = db.organizations.find((o) => o.id === ctx.org.id)!;
  Object.assign(org, body, { updatedAt: new Date().toISOString() });
  recordEvent({ orgId: org.id, actor: userActor(ctx), eventType: 'organization.updated', target: { type: 'organization', id: org.id, name: org.name }, metadata: body });
  res.json(org);
});

function toMember(m: (typeof db.members)[number]): Member {
  const u = db.users.find((x) => x.id === m.userId)!;
  return { id: m.id, organizationId: m.organizationId, userId: u.id, email: u.email, fullName: u.fullName, role: m.role, createdAt: m.createdAt };
}

organizationsRouter.get('/organizations/current/members', (req, res) => {
  const { org } = orgCtx(req);
  res.json({ items: db.members.filter((m) => m.organizationId === org.id).map(toMember) });
});

organizationsRouter.patch('/organizations/current/members/:memberId', requirePermission(PERMISSIONS.MEMBERS_MANAGE), (req, res) => {
  const ctx = orgCtx(req);
  const { role } = parse(z.object({ role: z.enum(['OWNER', 'VAULT_ADMIN', 'SECURITY_ADMIN', 'DEVELOPER', 'AUDITOR']) }), req.body);
  const member = db.members.find((m) => m.id === String(req.params.memberId) && m.organizationId === ctx.org.id);
  if (!member) throw notFound('Member');
  const owners = db.members.filter((m) => m.organizationId === ctx.org.id && m.role === 'OWNER');
  if (member.role === 'OWNER' && role !== 'OWNER' && owners.length === 1) throw conflict('An organization must keep at least one owner');
  const previous = member.role;
  member.role = role;
  const target = toMember(member);
  recordEvent({ orgId: ctx.org.id, actor: userActor(ctx), eventType: 'member.role_changed', target: { type: 'user', id: target.userId, name: target.fullName }, severity: 'warning', metadata: { from: previous, to: role } });
  res.json(target);
});
