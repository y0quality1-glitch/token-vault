import { describeOperationSelector, selectorApplication, type Policy } from '@token-vault/shared';
import { transaction } from '../../databases/client';
import type { PolicyDto } from '../../databases/repository/policy/policy.dto';
import { badRequest, notFound } from '../../lib/errors';
import { newId } from '../../lib/ids';
import { agentRepo, integrationRepo, policyRepo } from '../../store/repos';
import type { AdminContext } from '../../types/express';
import { recordEvent, userActor } from '../auditService/auditService.service';
import { getOperation, operations, registry } from '../providerService/registry';

type OrgContext = AdminContext & { org: { id: string } };
type Conditions = PolicyDto['conditions'];

/** Policies: the Who / Where / What rules evaluated on every agent request. */
export default class PolicyService {
  list(orgId: string) {
    return policyRepo.listPolicies(orgId).then((items) => ({ items }));
  }

  /**
   * Who, where and what must fit together: a named agent or integration must exist, and every
   * operation must belong to the application the policy is limited to (otherwise it could never match).
   */
  private async validateTargets(orgId: string, c: Conditions) {
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

  /** Plain data for storage (the DTO is a class instance). */
  private fields(body: PolicyDto) {
    const c = body.conditions;
    const conditions = JSON.parse(JSON.stringify({ ...c, timeWindow: c.timeWindow ?? null, sourceCidrs: c.sourceCidrs ?? [], arguments: c.arguments ?? [] })) as Policy['conditions'];
    // A Filter responses policy needs a filter; other decisions never carry one.
    let responseFilter: Policy['responseFilter'] = null;
    if (body.effect === 'FILTER') {
      if (!body.responseFilter) throw badRequest('Request validation failed', { fields: { responseFilter: 'Choose what to mask, remove or check' } });
      responseFilter = JSON.parse(JSON.stringify(body.responseFilter));
    }
    return { name: body.name, description: body.description, effect: body.effect, priority: body.priority, enabled: body.enabled, conditions, responseFilter };
  }

  /** Creates a policy (no `id`) or updates one (with `id`). Returns the policy and whether it is new. */
  async save(ctx: OrgContext, body: PolicyDto): Promise<{ policy: Policy; created: boolean }> {
    await this.validateTargets(ctx.org.id, body.conditions);
    const fields = this.fields(body);
    const now = new Date().toISOString();
    if (!body.id) {
      const policy = await transaction(async (tx) => {
        const created = await policyRepo.insertPolicy({ id: newId('pol'), organizationId: ctx.org.id, ...fields, createdAt: now, updatedAt: now } satisfies Policy, tx);
        await recordEvent({ orgId: ctx.org.id, actor: userActor(ctx), eventType: 'policy.created', target: { type: 'policy', id: created.id, name: created.name }, metadata: { effect: created.effect, priority: created.priority, enabled: created.enabled } }, tx);
        return created;
      });
      return { policy, created: true };
    }
    const policy = await transaction(async (tx) => {
      const existing = await policyRepo.getPolicy(ctx.org.id, body.id!, tx);
      if (!existing) throw notFound('Policy');
      const updated = await policyRepo.updatePolicy(existing.id, { ...fields, updatedAt: now }, tx);
      await recordEvent(
        {
          orgId: ctx.org.id,
          actor: userActor(ctx),
          eventType: existing.enabled !== updated.enabled ? (updated.enabled ? 'policy.enabled' : 'policy.disabled') : 'policy.updated',
          target: { type: 'policy', id: updated.id, name: updated.name },
          // Turning off a restriction (deny, or required approval) weakens protection.
          severity: existing.effect !== 'ALLOW' && existing.enabled && (!updated.enabled || updated.effect === 'ALLOW') ? 'warning' : 'info',
          metadata: { effect: updated.effect, priority: updated.priority, enabled: updated.enabled },
        },
        tx,
      );
      return updated;
    });
    return { policy, created: false };
  }
}
