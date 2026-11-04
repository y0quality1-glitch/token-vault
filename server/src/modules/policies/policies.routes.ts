import { Router } from 'express';
import { z } from 'zod';
import { PERMISSIONS, type Policy } from '@token-vault/shared';
import { notFound } from '../../lib/errors';
import { newId } from '../../lib/ids';
import { isValidCidr } from '../../lib/net';
import { parse } from '../../lib/validate';
import { orgCtx, requirePermission } from '../../middleware/auth';
import { transaction } from '../../db/client';
import { policyRepo } from '../../store/repos';
import { recordEvent, userActor } from '../audit/audit.service';
import { getOperation } from '../providers/registry';

export const policiesRouter = Router();


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
      .refine((ops) => ops.every((o) => o === '*' || !!getOperation(o)), 'Unknown operation'),
    environment: z.enum(['any', 'development', 'staging', 'production']),
    timeWindow: z
      .object({ startHour: z.number().int().min(0).max(23), endHour: z.number().int().min(0).max(24) })
      .nullable()
      .optional(),
    sourceCidrs: z.array(z.string().trim().refine(isValidCidr, 'Use IPv4 CIDR notation')).max(20).optional(),
  }),
});

policiesRouter.get('/policies', async (req, res) => {
  const { org } = orgCtx(req);
  res.json({ items: await policyRepo.listPolicies(org.id) });
});

const normalize = (c: z.infer<typeof policySchema>['conditions']) => ({ ...c, timeWindow: c.timeWindow ?? null, sourceCidrs: c.sourceCidrs ?? [] });

policiesRouter.post('/policies', requirePermission(PERMISSIONS.POLICY_MANAGE), async (req, res) => {
  const ctx = orgCtx(req);
  const body = parse(policySchema, req.body);
  const now = new Date().toISOString();
  const policy = await transaction(async (tx) => {
    const created = await policyRepo.insertPolicy({ id: newId('pol'), organizationId: ctx.org.id, ...body, conditions: normalize(body.conditions), createdAt: now, updatedAt: now } satisfies Policy, tx);
    await recordEvent({ orgId: ctx.org.id, actor: userActor(ctx), eventType: 'policy.created', target: { type: 'policy', id: created.id, name: created.name }, metadata: { effect: created.effect, priority: created.priority, enabled: created.enabled } }, tx);
    return created;
  });
  res.status(201).json(policy);
});

policiesRouter.put('/policies/:id', requirePermission(PERMISSIONS.POLICY_MANAGE), async (req, res) => {
  const ctx = orgCtx(req);
  const body = parse(policySchema, req.body);
  const updated = await transaction(async (tx) => {
    const existing = await policyRepo.getPolicy(ctx.org.id, String(req.params.id), tx);
    if (!existing) throw notFound('Policy');
    const policy = await policyRepo.updatePolicy(existing.id, { ...body, conditions: normalize(body.conditions), updatedAt: new Date().toISOString() }, tx);
    await recordEvent(
      {
        orgId: ctx.org.id,
        actor: userActor(ctx),
        eventType: existing.enabled !== policy.enabled ? (policy.enabled ? 'policy.enabled' : 'policy.disabled') : 'policy.updated',
        target: { type: 'policy', id: policy.id, name: policy.name },
        severity: policy.effect === 'DENY' && existing.enabled && !policy.enabled ? 'warning' : 'info',
        metadata: { effect: policy.effect, priority: policy.priority, enabled: policy.enabled },
      },
      tx,
    );
    return policy;
  });
  res.json(updated);
});
