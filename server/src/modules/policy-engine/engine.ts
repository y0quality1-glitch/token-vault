import { DECISION_CODES, type DecisionCheck, type MatchedRule, type OperationDef, type Policy } from '@token-vault/shared';
import { ipAllowed, ipInCidr } from '../../lib/net';
import type { AgentRecord, GrantRecord, IntegrationRecord } from '../../store/types';

/**
 * Deterministic authorization (spec section "Screen 10 - Policies").
 *
 *  1. Authenticate caller                 (performed by the broker before calling evaluate)
 *  2. Agent is active
 *  3. Explicit DENY policies              (explicit deny always wins over allow)
 *  4. Grant exists and is active          (not revoked / pending approval)
 *  5. Grant validity period               (valid_from <= now < expires_at)
 *  6. Integration is active
 *  7. Operation within grant scopes
 *  8. Resource restrictions               (grant + integration allow-lists)
 *  9. Rate limit
 * 10. Source IP restriction               (grant + agent CIDRs)
 * Deny by default if any mandatory check fails. Matching ALLOW policies are recorded
 * for traceability but never substitute for a grant.
 */
export const CHECK_NAMES = [
  'Authenticate caller',
  'Agent is active',
  'Explicit deny policies',
  'Grant exists and is active',
  'Grant validity period',
  'Integration is active',
  'Operation within grant scopes',
  'Resource restrictions',
  'Rate limit',
  'Source IP restriction',
] as const;

export interface EvaluationInput {
  agent: Pick<AgentRecord, 'id' | 'name' | 'status' | 'agentType' | 'allowedCidrs'>;
  integration: Pick<IntegrationRecord, 'id' | 'displayName' | 'provider' | 'environment' | 'credentialStatus' | 'allowedResources'>;
  /** Grants for this agent + integration (any status except superseded). */
  grants: GrantRecord[];
  policies: Policy[];
  operation: OperationDef;
  /** The primary resource grants are scoped to (named "repository" for historical reasons; e.g. a GitHub repository or a project). */
  resource: { repository?: string; path?: string };
  sourceIp: string;
  now: number;
  /** Number of authorized requests for a grant within the last 60 seconds. */
  recentRequests: (grantId: string) => number;
}

export interface EvaluationResult {
  decision: 'ALLOW' | 'DENY';
  code: string;
  reason: string;
  grant: GrantRecord | null;
  matchedRule: MatchedRule;
  checks: DecisionCheck[];
  allowPolicies: { id: string; name: string }[];
}

export interface PolicyContext {
  agent: Pick<AgentRecord, 'id' | 'agentType'>;
  integration: Pick<IntegrationRecord, 'id' | 'provider' | 'environment'>;
  operationId: string;
  sourceIp?: string;
  now?: number;
}

/** True when every condition of the policy applies to the request context. */
export function policyMatches(p: Policy, ctx: PolicyContext): boolean {
  const c = p.conditions;
  const a = c.agentSelector;
  if (a.type === 'agent' && a.value !== ctx.agent.id) return false;
  if (a.type === 'agentType' && a.value !== ctx.agent.agentType) return false;
  const i = c.integrationSelector;
  if (i.type === 'integration' && i.value !== ctx.integration.id) return false;
  if (i.type === 'provider' && i.value !== ctx.integration.provider) return false;
  if (!c.operations.includes('*') && !c.operations.includes(ctx.operationId)) return false;
  if (c.environment !== 'any' && c.environment !== ctx.integration.environment) return false;
  if (c.timeWindow && ctx.now !== undefined) {
    const h = new Date(ctx.now).getUTCHours();
    const { startHour, endHour } = c.timeWindow;
    const inside = startHour <= endHour ? h >= startHour && h < endHour : h >= startHour || h < endHour;
    if (!inside) return false;
  }
  if (c.sourceCidrs && c.sourceCidrs.length > 0 && ctx.sourceIp !== undefined) {
    if (!c.sourceCidrs.some((cidr) => ipInCidr(ctx.sourceIp!, cidr))) return false;
  }
  return true;
}

export function skippedChecks(fromStep: number): DecisionCheck[] {
  return CHECK_NAMES.slice(fromStep - 1).map((name, i) => ({ step: fromStep + i, name, passed: null, detail: 'Not evaluated (an earlier check failed)' }));
}

export function evaluate(input: EvaluationInput): EvaluationResult {
  const checks: DecisionCheck[] = [{ step: 1, name: CHECK_NAMES[0], passed: true, detail: `Authenticated as ${input.agent.name} (${input.agent.id}) from credential` }];
  let grant: GrantRecord | null = null;

  const deny = (step: number, code: string, reason: string, matchedRule: MatchedRule = { type: 'default', name: 'Deny by default' }): EvaluationResult => {
    checks.push({ step, name: CHECK_NAMES[step - 1]!, passed: false, detail: reason });
    checks.push(...skippedChecks(step + 1));
    return { decision: 'DENY', code, reason, grant, matchedRule, checks, allowPolicies: [] };
  };
  const pass = (step: number, detail: string) => checks.push({ step, name: CHECK_NAMES[step - 1]!, passed: true, detail });

  // 2. Agent active
  if (input.agent.status !== 'ACTIVE') return deny(2, DECISION_CODES.AGENT_DISABLED, 'Agent is disabled.');
  pass(2, 'Agent status is ACTIVE');

  // 3. Explicit deny policies (priority ascending: lower number evaluated first)
  const pctx: PolicyContext = { agent: input.agent, integration: input.integration, operationId: input.operation.id, sourceIp: input.sourceIp, now: input.now };
  const enabled = input.policies.filter((p) => p.enabled).sort((a, b) => a.priority - b.priority);
  const denyPolicy = enabled.find((p) => p.effect === 'DENY' && policyMatches(p, pctx));
  if (denyPolicy) {
    return deny(3, DECISION_CODES.POLICY_DENIED, `Explicit deny policy "${denyPolicy.name}" matched.`, { type: 'policy', id: denyPolicy.id, name: denyPolicy.name });
  }
  pass(3, `No enabled deny policy matched (${enabled.filter((p) => p.effect === 'DENY').length} evaluated)`);

  // 4. Grant exists and is active
  const candidates = input.grants.filter((g) => g.storedStatus !== 'SUPERSEDED');
  if (candidates.length === 0) {
    return deny(4, DECISION_CODES.GRANT_MISSING, `No grant authorizes ${input.agent.name} to use ${input.integration.displayName}.`);
  }
  const active = candidates.filter((g) => g.storedStatus === 'ACTIVE');
  if (active.length === 0) {
    const latest = [...candidates].sort((a, b) => b.createdAt.localeCompare(a.createdAt))[0]!;
    grant = latest;
    if (latest.storedStatus === 'PENDING_APPROVAL') return deny(4, DECISION_CODES.GRANT_PENDING_APPROVAL, `Grant "${latest.name}" is pending approval.`, { type: 'grant', id: latest.id, name: latest.name });
    return deny(4, DECISION_CODES.GRANT_REVOKED, `Grant "${latest.name}" was revoked${latest.revokedAt ? ` at ${latest.revokedAt}` : ''}.`, { type: 'grant', id: latest.id, name: latest.name });
  }
  pass(4, `${active.length} active grant(s) found`);

  // 5. Validity window
  const valid = active.filter((g) => new Date(g.validFrom).getTime() <= input.now && new Date(g.expiresAt).getTime() > input.now);
  if (valid.length === 0) {
    grant = active[0]!;
    const expired = active.find((g) => new Date(g.expiresAt).getTime() <= input.now);
    if (expired) {
      grant = expired;
      return deny(5, DECISION_CODES.GRANT_EXPIRED, `Grant "${expired.name}" expired at ${expired.expiresAt}.`, { type: 'grant', id: expired.id, name: expired.name });
    }
    return deny(5, DECISION_CODES.GRANT_NOT_YET_VALID, `Grant "${grant.name}" is not valid until ${grant.validFrom}.`, { type: 'grant', id: grant.id, name: grant.name });
  }
  grant = valid[0]!;
  pass(5, `Valid until ${grant.expiresAt}`);

  // 6. Integration active
  if (input.integration.credentialStatus !== 'CONNECTED') {
    return deny(6, DECISION_CODES.INTEGRATION_UNAVAILABLE, `Integration "${input.integration.displayName}" is ${input.integration.credentialStatus.toLowerCase().replace('_', ' ')}.`, { type: 'grant', id: grant.id, name: grant.name });
  }
  pass(6, 'Integration credential status is CONNECTED');

  // 7. Scope
  const scoped = valid.filter((g) => g.scopes.includes(input.operation.id));
  if (scoped.length === 0) {
    return deny(7, DECISION_CODES.SCOPE_DENIED, `Operation ${input.operation.id} is not included in grant scopes (${grant.scopes.join(', ')}).`, { type: 'grant', id: grant.id, name: grant.name });
  }
  grant = scoped[0]!;
  pass(7, `${input.operation.id} is granted`);

  // 8. Resource restrictions
  const repo = (input.resource.repository ?? '').toLowerCase();
  const repoAllowed = (list: string[]) => list.length === 0 || list.some((r) => r.toLowerCase() === repo);
  const resourceOk = scoped.filter((g) => repoAllowed(g.resourceConstraints.repositories));
  if (resourceOk.length === 0) {
    return deny(8, DECISION_CODES.RESOURCE_DENIED, `${input.operation.resourceLabel} ${input.resource.repository || '(none)'} is outside the grant resource restriction (${grant.resourceConstraints.repositories.join(', ')}).`, { type: 'grant', id: grant.id, name: grant.name });
  }
  grant = resourceOk[0]!;
  if (!repoAllowed(input.integration.allowedResources)) {
    return deny(8, DECISION_CODES.RESOURCE_DENIED, `${input.operation.resourceLabel} ${input.resource.repository} is not in the integration's allowed resources.`, { type: 'grant', id: grant.id, name: grant.name });
  }
  pass(8, grant.resourceConstraints.repositories.length ? `${input.operation.resourceLabel} matches restriction ${grant.resourceConstraints.repositories.join(', ')}` : 'No resource restriction on grant');

  // 9. Rate limit
  const used = input.recentRequests(grant.id);
  if (used >= grant.rateLimitPerMinute) {
    return deny(9, DECISION_CODES.RATE_LIMITED, `Rate limit of ${grant.rateLimitPerMinute} requests/minute exceeded for grant "${grant.name}".`, { type: 'grant', id: grant.id, name: grant.name });
  }
  pass(9, `${used + 1} of ${grant.rateLimitPerMinute} requests in the current minute`);

  // 10. Source IP
  if (!ipAllowed(input.sourceIp, grant.allowedCidrs) || !ipAllowed(input.sourceIp, input.agent.allowedCidrs)) {
    return deny(10, DECISION_CODES.IP_DENIED, `Source IP ${input.sourceIp} is not in the allowed CIDR ranges.`, { type: 'grant', id: grant.id, name: grant.name });
  }
  pass(10, grant.allowedCidrs.length || input.agent.allowedCidrs.length ? `Source IP ${input.sourceIp} allowed` : 'No IP restriction configured');

  const allowPolicies = enabled.filter((p) => p.effect === 'ALLOW' && policyMatches(p, pctx)).map((p) => ({ id: p.id, name: p.name }));
  return {
    decision: 'ALLOW',
    code: DECISION_CODES.ALLOWED,
    reason: `Authorized by grant "${grant.name}"${allowPolicies.length ? `; also matches allow policy "${allowPolicies[0]!.name}"` : ''}.`,
    grant,
    matchedRule: { type: 'grant', id: grant.id, name: grant.name },
    checks,
    allowPolicies,
  };
}
