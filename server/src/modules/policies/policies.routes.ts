import { Router } from 'express';
import { z } from 'zod';
import { ARGUMENT_OPERATORS, DATA_DETECTORS, FILTER_LIMITS, PERMISSIONS, argumentProblem, responseFilterProblem, type DataDetector, describeOperationSelector, operationSelectorProblem, selectorApplication, type ArgumentOperator, type Policy } from '@token-vault/shared';
import { badRequest, notFound } from '../../lib/errors';
import { newId } from '../../lib/ids';
import { isValidCidr } from '../../lib/net';
import { parse } from '../../lib/validate';
import { orgCtx, requirePermission } from '../../middleware/auth';
import { transaction } from '../../db/client';
import { agentRepo, integrationRepo, policyRepo } from '../../store/repos';
import { recordEvent, userActor } from '../audit/audit.service';
import { getOperation, operations, registry } from '../providers/registry';

export const policiesRouter = Router();


const policySchema = z.object({
  name: z.string().trim().min(3, 'Name must be at least 3 characters').max(80),
  description: z.string().trim().max(300).default(''),
  effect: z.enum(['ALLOW', 'DENY', 'REQUIRE_APPROVAL', 'FILTER']),
  priority: z.number().int().min(1, 'Priority must be between 1 and 1000').max(1000, 'Priority must be between 1 and 1000'),
  enabled: z.boolean(),
  conditions: z.object({
    agentSelector: z.object({ type: z.enum(['any', 'agent', 'agentType']), value: z.string().optional() }),
    integrationSelector: z.object({ type: z.enum(['any', 'integration', 'provider']), value: z.string().optional() }),
    operations: z
      .array(z.string())
      .min(1, 'Select at least one operation (or Any)')
      .max(100)
      // Exact ids, or selectors matched against the live catalog: "*", "github.*", "risk:write", "github:destructive".
      .superRefine((ops, ctx) => {
        const known = { operationIds: operations().map((o) => o.id), providers: [...new Set(operations().map((o) => o.provider))] };
        for (const o of ops) {
          const problem = operationSelectorProblem(o, known);
          if (problem) return void ctx.addIssue({ code: z.ZodIssueCode.custom, message: problem });
        }
      }),
    environment: z.enum(['any', 'development', 'staging', 'production']),
    timeWindow: z
      .object({ startHour: z.number().int().min(0).max(23), endHour: z.number().int().min(0).max(24) })
      .nullable()
      .optional(),
    sourceCidrs: z.array(z.string().trim().refine(isValidCidr, 'Use IPv4 CIDR notation')).max(20).optional(),
    arguments: z
      .array(
        z.object({
          field: z.string().trim().max(60),
          op: z.enum(ARGUMENT_OPERATORS.map((o) => o.op) as [ArgumentOperator, ...ArgumentOperator[]]),
          value: z.union([z.string().max(500), z.number(), z.array(z.string().trim().min(1).max(200))]),
        }),
      )
      .max(10, 'At most 10 argument rules')
      .optional()
      .superRefine((rules, ctx) => {
        for (const r of rules ?? []) {
          const problem = argumentProblem(r);
          if (problem) return void ctx.addIssue({ code: z.ZodIssueCode.custom, message: problem });
        }
      }),
  }),
  // FILTER policies: what to mask, remove or check in results before the agent gets them.
  responseFilter: z
    .object({
      mask: z.array(z.enum(DATA_DETECTORS.map((d) => d.id) as [DataDetector, ...DataDetector[]])).max(DATA_DETECTORS.length).default([]),
      customPatterns: z.array(z.object({ name: z.string().trim().max(40), pattern: z.string().max(FILTER_LIMITS.MAX_PATTERN_LENGTH) })).max(FILTER_LIMITS.MAX_PATTERNS).default([]),
      removeFields: z.array(z.string().trim().min(1).max(200)).max(FILTER_LIMITS.MAX_FIELDS).default([]),
      promptInjection: z.enum(['off', 'flag', 'block']).default('off'),
    })
    .nullable()
    .optional()
    .superRefine((f, ctx) => {
      const problem = f ? responseFilterProblem(f) : null;
      if (problem) ctx.addIssue({ code: z.ZodIssueCode.custom, message: problem });
    }),
});

policiesRouter.get('/policies', async (req, res) => {
  const { org } = orgCtx(req);
  res.json({ items: await policyRepo.listPolicies(org.id) });
});

/**
 * Who, where and what must fit together: a named agent or integration must exist, and every
 * operation must belong to the application the policy is limited to (otherwise it could never match).
 */
async function validateTargets(orgId: string, c: z.infer<typeof policySchema>['conditions']) {
  const fail = (field: string, message: string) => badRequest('Request validation failed', { fields: { [field]: message } });
  const a = c.agentSelector;
  if (a.type !== 'any' && !a.value) throw fail('conditions.agentSelector', a.type === 'agent' ? 'Choose an agent' : 'Choose an agent type');
  if (a.type === 'agent' && !(await agentRepo.getAgent(orgId, a.value!))) throw fail('conditions.agentSelector', 'That agent does not exist in this organization');
  if (a.type === 'agentType' && !['AI_AGENT', 'APPLICATION', 'SERVICE'].includes(a.value!)) throw fail('conditions.agentSelector', 'Unknown agent type');

  const i = c.integrationSelector;
  let application: string | null = null;
  if (i.type !== 'any' && !i.value) throw fail('conditions.integrationSelector', i.type === 'provider' ? 'Choose an application' : 'Choose an integration');
  if (i.type === 'provider') {
    if (!operations().some((o) => o.provider === i.value)) throw fail('conditions.integrationSelector', `Unknown application "${i.value}"`);
    application = i.value!;
  }
  if (i.type === 'integration') {
    const integration = await integrationRepo.getIntegration(orgId, i.value!);
    if (!integration) throw fail('conditions.integrationSelector', 'That integration does not exist in this organization');
    application = integration.provider;
  }
  if (!application) return;
  const appName = registry.get(application)?.name ?? application;
  const label = (s: string) => describeOperationSelector(s, { operation: (id) => getOperation(id)?.label ?? id, provider: (k) => registry.get(k)?.name ?? k });
  const foreign = c.operations.filter((s) => {
    const app = selectorApplication(s, (id) => getOperation(id)?.provider);
    return app !== null && app !== application;
  });
  if (foreign.length) {
    throw fail('conditions.operations', `${foreign.map((s) => `"${label(s)}"`).join(', ')} can never match: this policy only applies to ${appName}. Remove ${foreign.length > 1 ? 'them' : 'it'}, or apply the policy to any application.`);
  }
}

const normalize = (c: z.infer<typeof policySchema>['conditions']) => ({ ...c, timeWindow: c.timeWindow ?? null, sourceCidrs: c.sourceCidrs ?? [], arguments: c.arguments ?? [] });

/** A Filter responses policy needs a filter; other decisions never carry one. */
function filterOf(body: z.infer<typeof policySchema>) {
  if (body.effect !== 'FILTER') return null;
  if (!body.responseFilter) throw badRequest('Request validation failed', { fields: { responseFilter: 'Choose what to mask, remove or check' } });
  return body.responseFilter;
}

policiesRouter.post('/policies', requirePermission(PERMISSIONS.POLICY_MANAGE), async (req, res) => {
  const ctx = orgCtx(req);
  const body = parse(policySchema, req.body);
  await validateTargets(orgCtx(req).org.id, body.conditions);
  const now = new Date().toISOString();
  const policy = await transaction(async (tx) => {
    const created = await policyRepo.insertPolicy({ id: newId('pol'), organizationId: ctx.org.id, ...body, conditions: normalize(body.conditions), responseFilter: filterOf(body), createdAt: now, updatedAt: now } satisfies Policy, tx);
    await recordEvent({ orgId: ctx.org.id, actor: userActor(ctx), eventType: 'policy.created', target: { type: 'policy', id: created.id, name: created.name }, metadata: { effect: created.effect, priority: created.priority, enabled: created.enabled } }, tx);
    return created;
  });
  res.status(201).json(policy);
});

policiesRouter.put('/policies/:id', requirePermission(PERMISSIONS.POLICY_MANAGE), async (req, res) => {
  const ctx = orgCtx(req);
  const body = parse(policySchema, req.body);
  await validateTargets(orgCtx(req).org.id, body.conditions);
  const updated = await transaction(async (tx) => {
    const existing = await policyRepo.getPolicy(ctx.org.id, String(req.params.id), tx);
    if (!existing) throw notFound('Policy');
    const policy = await policyRepo.updatePolicy(existing.id, { ...body, conditions: normalize(body.conditions), responseFilter: filterOf(body), updatedAt: new Date().toISOString() }, tx);
    await recordEvent(
      {
        orgId: ctx.org.id,
        actor: userActor(ctx),
        eventType: existing.enabled !== policy.enabled ? (policy.enabled ? 'policy.enabled' : 'policy.disabled') : 'policy.updated',
        target: { type: 'policy', id: policy.id, name: policy.name },
        // Turning off a restriction (deny, or required approval) weakens protection.
        severity: (existing.effect !== 'ALLOW' && existing.enabled && (!policy.enabled || policy.effect === 'ALLOW')) ? 'warning' : 'info',
        metadata: { effect: policy.effect, priority: policy.priority, enabled: policy.enabled },
      },
      tx,
    );
    return policy;
  });
  res.json(updated);
});
