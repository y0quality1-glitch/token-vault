import { DECISION_CODES, actingUserLabel, argumentHolds, operationSelectorMatches, userPermissionProblem, type ActingUser, type DecisionCheck, type MatchedRule, type OperationDef, type OperationFacts, type Policy, type RequestContent } from '@token-vault/shared';
import { ipAllowed, ipInCidr } from '../../lib/net';
import type { AgentRecord, GrantRecord, IntegrationRecord } from '../../store/types';

/**
 * Deterministic authorization (spec section "Screen 10 - Policies").
 *
 *  1. Authenticate caller                 (performed by the broker before calling evaluate)
 *  2. Agent is active                     (and no emergency stop in the organization)
 *  3. Explicit DENY policies              (explicit deny always wins over allow; argument rules included)
 *  4. Grant exists and is active          (not revoked / pending approval)
 *  5. Grant validity period               (valid_from <= now < expires_at)
 *  6. Integration is active
 *  7. Operation within grant scopes
 *  8. Resource restrictions               (grant + integration allow-lists)
 *  9. Acting user                         (the grant allows acting for this user, or for none; the user's own permissions)
 * 10. Delegation limits                   (a sub-agent: only the delegated grant, operations, resources and request cap)
 * 11. Rate limit and budgets              (per minute; requests per 24 h; writes per hour)
 * 12. Source IP restriction               (grant + agent CIDRs)
 * 13. Human approval                      (REQUIRE_APPROVAL policies)
 * Deny by default if any mandatory check fails. Matching ALLOW policies are recorded
 * for traceability but never substitute for a grant. A REQUIRE_APPROVAL policy only
 * applies to a request that every other check allows: the request then waits until a
 * human approves that exact request (the broker verifies the approval it presents).
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
  'Acting user',
  'Delegation limits',
  'Rate limit and budgets',
  'Source IP restriction',
  'Human approval',
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
  /**
   * A human approval of exactly this request, already verified by the caller (approved,
   * unused, unexpired, same agent and request digest). Null or absent: none was presented.
   */
  approval?: { id: string; approvedBy: string } | null;
  /** What the request contains, for argument rules. Absent: argument rules are not evaluated (treated as matching). */
  request?: RequestContent;
  /** Emergency stop state of the agent's organization. */
  organization?: { emergencyStoppedAt?: string | null; emergencyStopReason?: string | null } | null;
  /** Authorized requests of a grant in the last 24 hours, and its authorized writes in the last hour (only for grants with budgets). */
  budgetUsage?: (grantId: string) => { requestsLast24h: number; writesLastHour: number };
  /** The verified user the agent acts for (null or absent: the agent acts for itself). */
  user?: ActingUser | null;
  /**
   * The sub-agent delegation the request came through (already checked: unrevoked and
   * unexpired along its chain). Null or absent: the agent itself.
   */
  delegation?: { id: string; label: string; grantId: string; operations: string[]; resources: string[]; maxRequests: number | null; used: number } | null;
}

export interface EvaluationResult {
  decision: 'ALLOW' | 'DENY';
  code: string;
  reason: string;
  grant: GrantRecord | null;
  matchedRule: MatchedRule;
  checks: DecisionCheck[];
  allowPolicies: { id: string; name: string }[];
  /** The REQUIRE_APPROVAL policy that applied (decision APPROVAL_REQUIRED, or ALLOW with an approval). */
  approvalPolicy?: { id: string; name: string } | null;
}

export interface PolicyContext {
  agent: Pick<AgentRecord, 'id' | 'agentType'>;
  integration: Pick<IntegrationRecord, 'id' | 'provider' | 'environment'>;
  operationId: string;
  /** The operation's application and risk, for selectors such as "github.*" or "risk:write". */
  operation?: OperationFacts;
  sourceIp?: string;
  now?: number;
  /** Absent (e.g. when listing which policies may apply to a grant): argument rules count as matching. */
  request?: RequestContent;
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
  // Application and risk selectors need the operation's facts; without them only "*" and exact ids match.
  const opMatches = ctx.operation ? c.operations.some((s) => operationSelectorMatches(s, ctx.operation!)) : c.operations.includes('*') || c.operations.includes(ctx.operationId);
  if (!opMatches) return false;
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
  if (c.arguments && c.arguments.length > 0 && ctx.request) {
    if (!c.arguments.every((rule) => argumentHolds(rule, ctx.request!))) return false;
  }
  return true;
}

/**
 * An enabled REQUIRE_APPROVAL policy that applies to every request of this agent, integration
 * and operation: no time window, source IP or argument rules that could let a request through
 * without approval. Granting a destructive operation needs one.
 */
export function approvalPolicyCovering(policies: Policy[], ctx: Omit<PolicyContext, 'request' | 'sourceIp' | 'now'>): Policy | null {
  return (
    policies.find((p) => {
      const c = p.conditions;
      const unconditional = !c.timeWindow && !(c.sourceCidrs ?? []).length && !(c.arguments ?? []).length;
      return p.enabled && p.effect === 'REQUIRE_APPROVAL' && unconditional && policyMatches(p, ctx);
    }) ?? null
  );
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
  if (input.organization?.emergencyStoppedAt) {
    const why = input.organization.emergencyStopReason ? ` Reason: "${input.organization.emergencyStopReason}".` : '';
    return deny(2, DECISION_CODES.EMERGENCY_STOP, `An administrator stopped all agent access in this organization at ${input.organization.emergencyStoppedAt}.${why}`);
  }
  if (input.agent.status !== 'ACTIVE') return deny(2, DECISION_CODES.AGENT_DISABLED, 'Agent is disabled.');
  pass(2, 'Agent status is ACTIVE; no emergency stop');

  // 3. Explicit deny policies (priority ascending: lower number evaluated first)
  const pctx: PolicyContext = {
    agent: input.agent,
    integration: input.integration,
    operationId: input.operation.id,
    operation: { id: input.operation.id, provider: input.operation.provider, risk: input.operation.risk },
    sourceIp: input.sourceIp,
    now: input.now,
    // Argument rules on user.* see the acting user.
    request: input.request ? { ...input.request, user: input.user ?? null } : undefined,
  };
  const enabled = input.policies.filter((p) => p.enabled).sort((a, b) => a.priority - b.priority);
  const denyPolicy = enabled.find((p) => p.effect === 'DENY' && policyMatches(p, pctx));
  if (denyPolicy) {
    return deny(3, DECISION_CODES.POLICY_DENIED, `Explicit deny policy "${denyPolicy.name}" matched.`, { type: 'policy', id: denyPolicy.id, name: denyPolicy.name });
  }
  pass(3, `No enabled deny policy matched (${enabled.filter((p) => p.effect === 'DENY').length} evaluated)`);

  // 4. Grant exists and is active (a sub-agent may use only the grant it was delegated)
  const dlg = input.delegation ?? null;
  const candidates = input.grants.filter((g) => g.storedStatus !== 'SUPERSEDED' && (!dlg || g.id === dlg.grantId));
  if (dlg && candidates.length === 0) {
    return deny(4, DECISION_CODES.DELEGATION_DENIED, `Sub-agent "${dlg.label}" (delegation ${dlg.id}) may use only grant ${dlg.grantId}, which does not cover ${input.integration.displayName}.`);
  }
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

  // 9. Acting user: the grant must allow acting for this user (or for none), within the user's own permissions.
  const user = input.user ?? null;
  const userFits = (g: GrantRecord) => {
    const mode = g.onBehalfOf ?? 'ALLOWED';
    if (!user) return mode !== 'REQUIRED';
    if (mode === 'NOT_ALLOWED') return false;
    const groups = g.allowedUserGroups ?? [];
    return groups.length === 0 || groups.some((x) => user.groups.some((ug) => ug.toLowerCase() === x.toLowerCase()));
  };
  const forUser = resourceOk.filter(userFits);
  if (forUser.length === 0) {
    const rule: MatchedRule = { type: 'grant', id: grant.id, name: grant.name };
    if (!user) return deny(9, DECISION_CODES.USER_REQUIRED, `Grant "${grant.name}" lets ${input.agent.name} act only on behalf of a signed-in user; send the user's token as on_behalf_of.`, rule);
    if (resourceOk.every((g) => (g.onBehalfOf ?? 'ALLOWED') === 'NOT_ALLOWED')) return deny(9, DECISION_CODES.USER_NOT_ALLOWED, `Grant "${grant.name}" lets ${input.agent.name} act only for itself, not on behalf of users.`, rule);
    return deny(9, DECISION_CODES.USER_NOT_ALLOWED, `${actingUserLabel(user)} is not in a group grant "${grant.name}" allows (${(grant.allowedUserGroups ?? []).join(', ')}).`, rule);
  }
  grant = forUser[0]!;
  if (user) {
    const problem = userPermissionProblem(user, pctx.operation!, input.resource.repository);
    if (problem) return deny(9, DECISION_CODES.USER_PERMISSION_DENIED, problem, { type: 'grant', id: grant.id, name: grant.name });
    pass(9, `On behalf of ${actingUserLabel(user)} (verified by ${user.issuer})${user.permissions ? "; within the user's own permissions" : ''}`);
  } else {
    pass(9, 'The agent acts for itself');
  }

  // 10. Delegation limits
  if (dlg) {
    const rule: MatchedRule = { type: 'grant', id: grant.id, name: grant.name };
    const who = `Sub-agent "${dlg.label}" (delegation ${dlg.id})`;
    if (!dlg.operations.includes(input.operation.id)) return deny(10, DECISION_CODES.DELEGATION_DENIED, `${who} was delegated ${dlg.operations.join(', ')}, not ${input.operation.id}.`, rule);
    const res = (input.resource.repository ?? '').toLowerCase();
    if (dlg.resources.length && !dlg.resources.some((r) => r.toLowerCase() === res)) return deny(10, DECISION_CODES.DELEGATION_DENIED, `${who} was delegated ${dlg.resources.join(', ')}, not ${input.resource.repository || '(no resource)'}.`, rule);
    if (dlg.maxRequests !== null && dlg.used >= dlg.maxRequests) return deny(10, DECISION_CODES.DELEGATION_DENIED, `${who} has used all ${dlg.maxRequests} requests it was delegated.`, rule);
    pass(10, `Via ${who}${dlg.maxRequests !== null ? `; ${dlg.used + 1} of ${dlg.maxRequests} requests` : ''}`);
  } else {
    pass(10, 'Not delegated: the agent itself');
  }

  // 11. Rate limit
  const used = input.recentRequests(grant.id);
  if (used >= grant.rateLimitPerMinute) {
    return deny(11, DECISION_CODES.RATE_LIMITED, `Rate limit of ${grant.rateLimitPerMinute} requests/minute exceeded for grant "${grant.name}".`, { type: 'grant', id: grant.id, name: grant.name });
  }
  const budget = grant.maxRequestsPerDay || grant.maxWritesPerHour ? input.budgetUsage?.(grant.id) : undefined;
  const budgetNotes: string[] = [];
  if (budget && grant.maxRequestsPerDay) {
    if (budget.requestsLast24h >= grant.maxRequestsPerDay) {
      return deny(11, DECISION_CODES.BUDGET_EXCEEDED, `Grant "${grant.name}" allows ${grant.maxRequestsPerDay} requests per 24 hours, and ${budget.requestsLast24h} were authorized in the last 24 hours.`, { type: 'grant', id: grant.id, name: grant.name });
    }
    budgetNotes.push(`${budget.requestsLast24h + 1} of ${grant.maxRequestsPerDay} requests in 24 h`);
  }
  if (budget && grant.maxWritesPerHour && input.operation.mutating) {
    if (budget.writesLastHour >= grant.maxWritesPerHour) {
      return deny(11, DECISION_CODES.BUDGET_EXCEEDED, `Grant "${grant.name}" allows ${grant.maxWritesPerHour} write operations per hour, and ${budget.writesLastHour} were authorized in the last hour.`, { type: 'grant', id: grant.id, name: grant.name });
    }
    budgetNotes.push(`${budget.writesLastHour + 1} of ${grant.maxWritesPerHour} writes in 1 h`);
  }
  pass(11, [`${used + 1} of ${grant.rateLimitPerMinute} requests in the current minute`, ...budgetNotes].join('; '));

  // 12. Source IP
  if (!ipAllowed(input.sourceIp, grant.allowedCidrs) || !ipAllowed(input.sourceIp, input.agent.allowedCidrs)) {
    return deny(12, DECISION_CODES.IP_DENIED, `Source IP ${input.sourceIp} is not in the allowed CIDR ranges.`, { type: 'grant', id: grant.id, name: grant.name });
  }
  pass(12, grant.allowedCidrs.length || input.agent.allowedCidrs.length ? `Source IP ${input.sourceIp} allowed` : 'No IP restriction configured');

  // 13. Human approval (only for requests every other check allows)
  const approvalPolicy = enabled.find((p) => p.effect === 'REQUIRE_APPROVAL' && policyMatches(p, pctx));
  const approvalRef = approvalPolicy ? { id: approvalPolicy.id, name: approvalPolicy.name } : null;
  // A destructive operation runs only with a human's approval: if no approval policy applies
  // (it was disabled, or its conditions don't hold for this request), it never runs.
  if (input.operation.destructive && !approvalPolicy) {
    return deny(13, DECISION_CODES.APPROVAL_POLICY_MISSING, `${input.operation.label} is destructive and runs only with human approval, but no enabled Require approval policy applies to this request.`, { type: 'grant', id: grant.id, name: grant.name });
  }
  if (approvalPolicy && !input.approval) {
    const result = deny(13, DECISION_CODES.APPROVAL_REQUIRED, `Policy "${approvalPolicy.name}" requires a human to approve this request before it runs.`, { type: 'policy', id: approvalPolicy.id, name: approvalPolicy.name });
    return { ...result, approvalPolicy: approvalRef };
  }
  if (approvalPolicy) pass(13, `Approved by ${input.approval!.approvedBy} (approval ${input.approval!.id}) as policy "${approvalPolicy.name}" requires`);
  else pass(13, input.approval ? `No approval policy applies any more; approval ${input.approval.id} is used anyway` : 'No approval policy matched');

  const allowPolicies = enabled.filter((p) => p.effect === 'ALLOW' && policyMatches(p, pctx)).map((p) => ({ id: p.id, name: p.name }));
  return {
    decision: 'ALLOW',
    code: DECISION_CODES.ALLOWED,
    reason: `Authorized by grant "${grant.name}"${allowPolicies.length ? `; also matches allow policy "${allowPolicies[0]!.name}"` : ''}.`,
    grant,
    matchedRule: { type: 'grant', id: grant.id, name: grant.name },
    checks,
    allowPolicies,
    approvalPolicy: approvalRef,
  };
}
