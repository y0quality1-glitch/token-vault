import { Router } from 'express';
import { z } from 'zod';
import { OPERATIONS, PERMISSIONS, type Policy } from '@token-vault/shared';
import { notFound } from '../../lib/errors';
import { newId } from '../../lib/ids';
import { isValidCidr } from '../../lib/net';
import { parse } from '../../lib/validate';
import { orgCtx, requirePermission } from '../../middleware/auth';
import { db, findInOrg, inOrg } from '../../store/db';
import { recordEvent, userActor } from '../audit/audit.service';

export const policiesRouter = Router();

const opIds = OPERATIONS.map((o) => o.id);

const policySchema = z.object({
  name: z.string().trim().min(3, 'Name must be at least 3 characters').max(80),
  description: z.string().trim().max(300).default(''),
  effect: z.enum(['ALLOW', 'DENY']),
  priority: z.number().int().min(1, 'Priority must be between 1 and 1000').max(1000, 'Priority must be between 1 and 1000'),
  enabled: z.boolean(),
  conditions: z.object({
    agentSelector: z.object({ type: z.enum(['any', 'agent', 'agentType']), value: z.string().optional() }),
    integrationSelector: z.object({ type: z.enum(['any', 'integration', 'provider']), value: z.string().optional() }),
    operations: z
      .array(z.string())
      .min(1, 'Select at least one operation (or Any)')
      .refine((ops) => ops.every((o) => o === '*' || opIds.includes(o)), 'Unknown operation'),
    environment: z.enum(['any', 'development', 'staging', 'production']),
    timeWindow: z
      .object({ startHour: z.number().int().min(0).max(23), endHour: z.number().int().min(0).max(24) })
      .nullable()
      .optional(),
    sourceCidrs: z.array(z.string().trim().refine(isValidCidr, 'Use IPv4 CIDR notation')).max(20).optional(),
  }),
});

policiesRouter.get('/policies', (req, res) => {
  const { org } = orgCtx(req);
  res.json({ items: inOrg(db.policies, org.id).sort((a, b) => a.priority - b.priority) });
});

policiesRouter.post('/policies', requirePermission(PERMISSIONS.POLICY_MANAGE), (req, res) => {
  const ctx = orgCtx(req);
  const body = parse(policySchema, req.body);
  const now = new Date().toISOString();
  const policy: Policy = { id: newId('pol'), organizationId: ctx.org.id, ...body, conditions: { ...body.conditions, timeWindow: body.conditions.timeWindow ?? null, sourceCidrs: body.conditions.sourceCidrs ?? [] }, createdAt: now, updatedAt: now };
  db.policies.push(policy);
  recordEvent({ orgId: ctx.org.id, actor: userActor(ctx), eventType: 'policy.created', target: { type: 'policy', id: policy.id, name: policy.name }, metadata: { effect: policy.effect, priority: policy.priority, enabled: policy.enabled } });
  res.status(201).json(policy);
});

policiesRouter.put('/policies/:id', requirePermission(PERMISSIONS.POLICY_MANAGE), (req, res) => {
  const ctx = orgCtx(req);
  const policy = findInOrg(db.policies, ctx.org.id, String(req.params.id));
  if (!policy) throw notFound('Policy');
  const body = parse(policySchema, req.body);
  const wasEnabled = policy.enabled;
  Object.assign(policy, body, { conditions: { ...body.conditions, timeWindow: body.conditions.timeWindow ?? null, sourceCidrs: body.conditions.sourceCidrs ?? [] }, updatedAt: new Date().toISOString() });
  recordEvent({
    orgId: ctx.org.id,
    actor: userActor(ctx),
    eventType: wasEnabled !== policy.enabled ? (policy.enabled ? 'policy.enabled' : 'policy.disabled') : 'policy.updated',
    target: { type: 'policy', id: policy.id, name: policy.name },
    severity: policy.effect === 'DENY' && wasEnabled && !policy.enabled ? 'warning' : 'info',
    metadata: { effect: policy.effect, priority: policy.priority, enabled: policy.enabled },
  });
  res.json(policy);
});
