import { describe, expect, it } from 'vitest';
import { argumentHolds, argumentProblem, getOperation, resourcePatternMatches, type ActingUser, operationSelectorProblem, scopeSelectors, selectorApplication, type Policy } from '@token-vault/shared';
import { approvalPolicyCovering, evaluate, policyMatches } from '../src/modules/policy-engine/engine';
import type { GrantRecord } from '../src/store/types';
import { sanitize } from '../src/lib/sanitize';
import { ipInCidr } from '../src/lib/net';

const now = Date.parse('2026-11-04T12:00:00Z');
const agent = { id: 'agt_1', name: 'GitHub Assistant', status: 'ACTIVE' as const, agentType: 'AI_AGENT' as const, allowedCidrs: [] };
const integration = { id: 'int_1', displayName: 'Demo GitHub', provider: 'github' as const, environment: 'development' as const, credentialStatus: 'CONNECTED' as const, allowedResources: [] };

function grant(overrides: Partial<GrantRecord> = {}): GrantRecord {
  return {
    id: 'grt_1',
    organizationId: 'org_1',
    agentId: 'agt_1',
    integrationId: 'int_1',
    name: 'GitHub Issue Creation',
    environment: 'development',
    scopes: ['github.repositories.read', 'github.issues.create'],
    resourceConstraints: { repositories: ['demo-org/demo-repo'] },
    rateLimitPerMinute: 2,
    allowedCidrs: [],
    validFrom: '2026-11-01T00:00:00Z',
    expiresAt: '2026-11-10T00:00:00Z',
    approvalRequired: false,
    storedStatus: 'ACTIVE',
    version: 1,
    previousVersionId: null,
    createdBy: 'usr_1',
    createdAt: '2026-11-01T00:00:00Z',
    approvedBy: null,
    approvedAt: null,
    revokedAt: null,
    revokedBy: null,
    revocationReason: null,
    lastUsedAt: null,
    usageCount: 0,
    ...overrides,
  };
}

const denyDestructive: Policy = {
  id: 'pol_1',
  organizationId: 'org_1',
  name: 'Block destructive',
  description: '',
  effect: 'DENY',
  priority: 10,
  enabled: true,
  conditions: { agentSelector: { type: 'any' }, integrationSelector: { type: 'provider', value: 'github' }, operations: ['github.repositories.delete'], environment: 'any' },
  createdAt: '',
  updatedAt: '',
};

const requireApprovalForIssues: Policy = {
  ...denyDestructive,
  id: 'pol_2',
  name: 'Approve issue creation',
  effect: 'REQUIRE_APPROVAL',
  priority: 20,
  conditions: { ...denyDestructive.conditions, operations: ['github.issues.create'] },
};

function run(opts: {
  op?: string;
  repo?: string;
  grants?: GrantRecord[];
  policies?: Policy[];
  used?: number;
  agentStatus?: 'ACTIVE' | 'DISABLED';
  ip?: string;
  integrationStatus?: 'CONNECTED' | 'DISABLED';
  approval?: { id: string; approvedBy: string } | null;
  input?: Record<string, unknown>;
  stoppedAt?: string | null;
  budget?: { requestsLast24h: number; writesLastHour: number };
  user?: ActingUser | null;
  delegation?: { id: string; label: string; grantId: string; operations: string[]; resources: string[]; maxRequests: number | null; used: number } | null;
}) {
  return evaluate({
    agent: { ...agent, status: opts.agentStatus ?? 'ACTIVE' },
    integration: { ...integration, credentialStatus: opts.integrationStatus ?? 'CONNECTED' },
    grants: opts.grants ?? [grant()],
    policies: opts.policies ?? [denyDestructive],
    operation: getOperation(opts.op ?? 'github.issues.create')!,
    resource: { repository: opts.repo ?? 'demo-org/demo-repo' },
    sourceIp: opts.ip ?? '127.0.0.1',
    now,
    recentRequests: () => opts.used ?? 0,
    approval: opts.approval ?? null,
    request: { resource: { repository: opts.repo ?? 'demo-org/demo-repo' }, input: opts.input ?? {} },
    organization: { emergencyStoppedAt: opts.stoppedAt ?? null, emergencyStopReason: opts.stoppedAt ? 'Incident 42' : null },
    budgetUsage: () => opts.budget ?? { requestsLast24h: 0, writesLastHour: 0 },
    user: opts.user ?? null,
    delegation: opts.delegation ?? null,
  });
}

describe('policy engine', () => {
  it('Scenario A: allows a granted operation on the allowed repository', () => {
    const r = run({});
    expect(r.decision).toBe('ALLOW');
    expect(r.matchedRule).toMatchObject({ type: 'grant', id: 'grt_1' });
    expect(r.checks.every((c) => c.passed)).toBe(true);
  });
  it('Scenario B: explicit deny policy wins for destructive operations', () => {
    expect(run({ op: 'github.repositories.delete' })).toMatchObject({ decision: 'DENY', code: 'POLICY_DENIED' });
  });
  it('Scenario B: denies an ungranted operation', () => {
    expect(run({ op: 'github.issues.list' })).toMatchObject({ decision: 'DENY', code: 'SCOPE_DENIED' });
  });
  it('Scenario C: denies a repository outside the restriction', () => {
    expect(run({ repo: 'demo-org/other-repo' })).toMatchObject({ decision: 'DENY', code: 'RESOURCE_DENIED' });
  });
  it('Scenario D: denies after revocation', () => {
    expect(run({ grants: [grant({ storedStatus: 'REVOKED', revokedAt: '2026-11-04T11:00:00Z' })] })).toMatchObject({ code: 'GRANT_REVOKED' });
  });
  it('Scenario E: denies an expired grant', () => {
    expect(run({ grants: [grant({ expiresAt: '2026-11-04T11:59:59Z' })] })).toMatchObject({ code: 'GRANT_EXPIRED' });
  });
  it('denies by default without a grant, for disabled agents, pending grants, disabled integrations, rate limits and IPs', () => {
    expect(run({ grants: [] }).code).toBe('GRANT_MISSING');
    expect(run({ agentStatus: 'DISABLED' }).code).toBe('AGENT_DISABLED');
    expect(run({ grants: [grant({ storedStatus: 'PENDING_APPROVAL' })] }).code).toBe('GRANT_PENDING_APPROVAL');
    expect(run({ integrationStatus: 'DISABLED' }).code).toBe('INTEGRATION_UNAVAILABLE');
    expect(run({ used: 2 }).code).toBe('RATE_LIMITED');
    expect(run({ grants: [grant({ allowedCidrs: ['10.0.0.0/8'] })] }).code).toBe('IP_DENIED');
  });
  it('ignores disabled policies and honours time windows', () => {
    expect(run({ op: 'github.repositories.delete', policies: [{ ...denyDestructive, enabled: false }] }).code).toBe('SCOPE_DENIED');
    const windowed = { ...denyDestructive, conditions: { ...denyDestructive.conditions, operations: ['*'], timeWindow: { startHour: 2, endHour: 4 } } };
    expect(policyMatches(windowed, { agent, integration, operationId: 'x', now })).toBe(false);
    expect(policyMatches(windowed, { agent, integration, operationId: 'x', now: Date.parse('2026-11-04T03:00:00Z') })).toBe(true);
  });
});

describe('REQUIRE_APPROVAL policies', () => {
  const policies = [denyDestructive, requireApprovalForIssues];

  it('holds a request every other check allows until a human approves it', () => {
    const r = run({ policies });
    expect(r).toMatchObject({ decision: 'DENY', code: 'APPROVAL_REQUIRED', approvalPolicy: { id: 'pol_2' }, matchedRule: { type: 'policy', id: 'pol_2' } });
    expect(r.checks.slice(0, 12).every((c) => c.passed)).toBe(true);
    expect(r.checks[12]).toMatchObject({ step: 13, name: 'Human approval', passed: false });
  });
  it('allows the request with a verified approval', () => {
    const r = run({ policies, approval: { id: 'apv_1', approvedBy: 'Sam Security' } });
    expect(r).toMatchObject({ decision: 'ALLOW', code: 'ALLOWED', approvalPolicy: { id: 'pol_2' } });
    expect(r.checks[12]?.detail).toContain('Sam Security');
  });
  it('never asks for approval of a request another check denies', () => {
    expect(run({ policies, repo: 'demo-org/other-repo' }).code).toBe('RESOURCE_DENIED');
    expect(run({ policies, grants: [grant({ storedStatus: 'REVOKED' })], approval: { id: 'apv_1', approvedBy: 'x' } }).code).toBe('GRANT_REVOKED');
    expect(run({ policies, used: 2, approval: { id: 'apv_1', approvedBy: 'x' } }).code).toBe('RATE_LIMITED');
  });
  it('does not apply to operations or policies outside its conditions', () => {
    expect(run({ policies, op: 'github.repositories.read' }).code).toBe('ALLOWED');
    expect(run({ policies: [denyDestructive, { ...requireApprovalForIssues, enabled: false }] }).code).toBe('ALLOWED');
  });
  it('explicit deny still wins over a required approval', () => {
    const both = [{ ...denyDestructive, conditions: { ...denyDestructive.conditions, operations: ['github.issues.create'] } }, requireApprovalForIssues];
    expect(run({ policies: both, approval: { id: 'apv_1', approvedBy: 'x' } }).code).toBe('POLICY_DENIED');
  });
});

describe('argument rules', () => {
  const rule = (args: Policy['conditions']['arguments'], effect: Policy['effect'] = 'DENY'): Policy => ({ ...denyDestructive, id: 'pol_args', name: 'Argument rule', effect, conditions: { ...denyDestructive.conditions, operations: ['github.issues.create'], arguments: args } });

  it('applies a policy only when every rule holds', () => {
    const noSecrets = rule([{ field: 'input.title', op: 'matches', value: 'pass(word)?|secret' }]);
    expect(run({ policies: [noSecrets], input: { title: 'Rotate the SECRET' } }).code).toBe('POLICY_DENIED');
    expect(run({ policies: [noSecrets], input: { title: 'Release notes' } }).code).toBe('ALLOWED');
    const both = rule([{ field: 'input.title', op: 'contains', value: 'urgent' }, { field: 'resource.repository', op: 'equals', value: 'DEMO-ORG/demo-repo' }]);
    expect(run({ policies: [both], input: { title: 'urgent fix' } }).code).toBe('POLICY_DENIED');
    expect(run({ policies: [both], input: { title: 'later' } }).code).toBe('ALLOWED');
  });
  it('requires approval above a numeric threshold, failing closed on non-numbers', () => {
    const big = rule([{ field: 'input.amount', op: 'greater_than', value: 500 }], 'REQUIRE_APPROVAL');
    expect(run({ policies: [big], input: { amount: 900 } }).code).toBe('APPROVAL_REQUIRED');
    expect(run({ policies: [big], input: { amount: '120' } }).code).toBe('ALLOWED');
    expect(run({ policies: [big], input: { amount: 'lots' } }).code).toBe('APPROVAL_REQUIRED');
  });
  it('supports lists, lengths and negations', () => {
    expect(argumentHolds({ field: 'input.label', op: 'in', value: ['bug', 'docs'] }, { resource: {}, input: { label: 'Docs' } })).toBe(true);
    expect(argumentHolds({ field: 'input.label', op: 'not_in', value: ['bug'] }, { resource: {}, input: {} })).toBe(true);
    expect(argumentHolds({ field: 'input.body', op: 'longer_than', value: 5 }, { resource: {}, input: { body: '123456' } })).toBe(true);
    expect(argumentHolds({ field: 'resource.path', op: 'not_matches', value: '^docs/' }, { resource: { path: 'src/x.ts' }, input: {} })).toBe(true);
  });
  it('rejects malformed rules when a policy is saved', () => {
    expect(argumentProblem({ field: 'title', op: 'equals', value: 'x' })).toMatch(/input\.<name>/);
    expect(argumentProblem({ field: 'input.title', op: 'matches', value: '(' })).toMatch(/not a valid regular expression/);
    expect(argumentProblem({ field: 'input.amount', op: 'greater_than', value: '5' })).toMatch(/number/);
    expect(argumentProblem({ field: 'input.title', op: 'in', value: ['a'] })).toBeNull();
  });
});

describe('budgets', () => {
  const budgeted = grant({ rateLimitPerMinute: 100, maxRequestsPerDay: 50, maxWritesPerHour: 3 });
  it('denies once a daily request budget is used up', () => {
    expect(run({ grants: [budgeted], op: 'github.repositories.read', budget: { requestsLast24h: 50, writesLastHour: 0 } })).toMatchObject({ code: 'BUDGET_EXCEEDED' });
    const ok = run({ grants: [budgeted], op: 'github.repositories.read', budget: { requestsLast24h: 49, writesLastHour: 0 } });
    expect(ok.code).toBe('ALLOWED');
    expect(ok.checks[10]?.detail).toContain('50 of 50 requests in 24 h');
  });
  it('counts writes against the hourly write budget, but not reads', () => {
    expect(run({ grants: [budgeted], budget: { requestsLast24h: 10, writesLastHour: 3 } }).code).toBe('BUDGET_EXCEEDED');
    expect(run({ grants: [budgeted], op: 'github.repositories.read', budget: { requestsLast24h: 10, writesLastHour: 3 } }).code).toBe('ALLOWED');
  });
});

describe('emergency stop', () => {
  it('denies every request, before any other check', () => {
    const r = run({ stoppedAt: '2026-11-04T11:00:00Z' });
    expect(r).toMatchObject({ decision: 'DENY', code: 'EMERGENCY_STOP' });
    expect(r.reason).toContain('Incident 42');
    expect(r.checks[1]).toMatchObject({ step: 2, passed: false });
  });
});

describe('operation selectors', () => {
  const policy = (ops: string[], effect: Policy['effect'] = 'DENY'): Policy => ({ ...denyDestructive, id: 'pol_sel', name: 'Selector', effect, conditions: { ...denyDestructive.conditions, integrationSelector: { type: 'any' }, operations: ops } });

  it('matches by application and by risk, including operations not listed by id', () => {
    expect(run({ policies: [policy(['github.*'])] }).code).toBe('POLICY_DENIED');
    expect(run({ policies: [policy(['risk:write'])] }).code).toBe('POLICY_DENIED'); // issues.create is a write
    expect(run({ policies: [policy(['risk:write'])], op: 'github.repositories.read' }).code).toBe('ALLOWED');
    expect(run({ policies: [policy(['github:read'])], op: 'github.repositories.read' }).code).toBe('POLICY_DENIED');
    expect(run({ policies: [policy(['slack.*'])] }).code).toBe('ALLOWED');
  });
  it('requires approval for every write with one selector', () => {
    expect(run({ policies: [policy(['risk:write'], 'REQUIRE_APPROVAL')] }).code).toBe('APPROVAL_REQUIRED');
  });
  it('narrows selectors when a policy is limited to one application', () => {
    const providerOf = (id: string) => id.split('.')[0];
    expect(scopeSelectors(['*'], 'github', providerOf)).toEqual(['github.*']);
    expect(scopeSelectors(['risk:write', 'slack.messages.post', 'github.issues.create', 'slack.*'], 'github', providerOf)).toEqual(['github:write', 'github.issues.create']);
    expect(scopeSelectors(['risk:write', 'slack.*'], null, providerOf)).toEqual(['risk:write', 'slack.*']);
    expect(selectorApplication('github:destructive', providerOf)).toBe('github');
    expect(selectorApplication('risk:read', providerOf)).toBeNull();
  });
  it('validates selectors against the known catalog', () => {
    const known = { operationIds: ['github.issues.create'], providers: ['github'] };
    expect(operationSelectorProblem('github.*', known)).toBeNull();
    expect(operationSelectorProblem('risk:destructive', known)).toBeNull();
    expect(operationSelectorProblem('jira.*', known)).toMatch(/Unknown application/);
    expect(operationSelectorProblem('github.issues.close', known)).toMatch(/Unknown operation/);
  });
});

describe('destructive operations', () => {
  const del = 'github.repositories.delete';
  const granted = grant({ scopes: [del, 'github.repositories.read'] });
  const approvalForDestructive: Policy = { ...requireApprovalForIssues, id: 'pol_del', name: 'Approve destructive', conditions: { ...requireApprovalForIssues.conditions, operations: ['risk:destructive'] } };

  it('never run without an approval policy, even when granted', () => {
    expect(run({ op: del, grants: [granted], policies: [] })).toMatchObject({ decision: 'DENY', code: 'APPROVAL_POLICY_MISSING' });
    expect(run({ op: del, grants: [granted], policies: [], approval: { id: 'apv_1', approvedBy: 'x' } }).code).toBe('APPROVAL_POLICY_MISSING');
  });
  it('wait for a human under an approval policy, then run with the approval', () => {
    expect(run({ op: del, grants: [granted], policies: [approvalForDestructive] }).code).toBe('APPROVAL_REQUIRED');
    expect(run({ op: del, grants: [granted], policies: [approvalForDestructive], approval: { id: 'apv_1', approvedBy: 'Sam' } }).code).toBe('ALLOWED');
  });
  it('an explicit deny still wins', () => {
    expect(run({ op: del, grants: [granted], policies: [denyDestructive, approvalForDestructive], approval: { id: 'apv_1', approvedBy: 'Sam' } }).code).toBe('POLICY_DENIED');
  });
  it('can be granted only under an unconditional approval policy', () => {
    const ctx = { agent, integration, operationId: del, operation: { id: del, provider: 'github', risk: 'destructive' as const } };
    expect(approvalPolicyCovering([approvalForDestructive], ctx)?.id).toBe('pol_del');
    expect(approvalPolicyCovering([{ ...approvalForDestructive, enabled: false }], ctx)).toBeNull();
    expect(approvalPolicyCovering([{ ...approvalForDestructive, conditions: { ...approvalForDestructive.conditions, timeWindow: { startHour: 9, endHour: 17 } } }], ctx)).toBeNull();
    expect(approvalPolicyCovering([{ ...approvalForDestructive, conditions: { ...approvalForDestructive.conditions, arguments: [{ field: 'resource.repository', op: 'equals', value: 'a/b' }] } }], ctx)).toBeNull();
    expect(approvalPolicyCovering([{ ...approvalForDestructive, effect: 'DENY' }], ctx)).toBeNull();
  });
});

describe('sanitize & net helpers', () => {
  it('redacts secret-looking keys and values', () => {
    const out = sanitize({ secret: 'x', authorization: 'Bearer abc', note: 'token tvak_0123456789ab_abcdefghijklmnopqrstuvwx', credentialReference: 'cref_1' });
    expect(out).toEqual({ secret: '[REDACTED]', authorization: '[REDACTED]', note: 'token [REDACTED]', credentialReference: 'cref_1' });
  });
  it('redacts PEM private keys anywhere in a value', () => {
    const pem = '-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\n-----END PRIVATE KEY-----';
    expect(sanitize({ note: `key: ${pem} end` })).toEqual({ note: 'key: [REDACTED] end' });
  });
  it('matches IPv4 CIDRs', () => {
    expect(ipInCidr('10.1.2.3', '10.0.0.0/8')).toBe(true);
    expect(ipInCidr('192.168.1.1', '10.0.0.0/8')).toBe(false);
    expect(ipInCidr('127.0.0.1', '127.0.0.1')).toBe(true);
  });
});

describe('acting on behalf of a user', () => {
  const ada: ActingUser = { sub: 'u_ada', email: 'ada@example.com', name: 'Ada', groups: ['engineering'], issuerId: 'uis_1', issuer: 'https://login.example.com' };

  it('ALLOWED grants work with and without a user, and the check names the user', () => {
    expect(run({}).checks[8]).toMatchObject({ step: 9, name: 'Acting user', passed: true, detail: 'The agent acts for itself' });
    const r = run({ user: ada });
    expect(r.decision).toBe('ALLOW');
    expect(r.checks[8]?.detail).toContain('Ada (ada@example.com)');
  });
  it('REQUIRED grants deny requests without a user; NOT_ALLOWED grants deny requests with one', () => {
    expect(run({ grants: [grant({ onBehalfOf: 'REQUIRED' })] }).code).toBe('USER_REQUIRED');
    expect(run({ grants: [grant({ onBehalfOf: 'REQUIRED' })], user: ada }).decision).toBe('ALLOW');
    expect(run({ grants: [grant({ onBehalfOf: 'NOT_ALLOWED' })], user: ada }).code).toBe('USER_NOT_ALLOWED');
  });
  it('allowed user groups are matched case-insensitively', () => {
    expect(run({ grants: [grant({ allowedUserGroups: ['Engineering'] })], user: ada }).decision).toBe('ALLOW');
    const r = run({ grants: [grant({ allowedUserGroups: ['finance'] })], user: ada });
    expect(r).toMatchObject({ code: 'USER_NOT_ALLOWED' });
    expect(r.reason).toContain('finance');
  });
  it('picks the grant that fits the user when several apply', () => {
    const forUsers = grant({ id: 'grt_users', onBehalfOf: 'REQUIRED' });
    const forItself = grant({ id: 'grt_self', onBehalfOf: 'NOT_ALLOWED' });
    expect(run({ grants: [forUsers, forItself] }).grant?.id).toBe('grt_self');
    expect(run({ grants: [forUsers, forItself], user: ada }).grant?.id).toBe('grt_users');
  });
  it("the user's own permissions narrow the grant (operations and resources)", () => {
    const limited = (permissions: ActingUser['permissions']) => run({ user: { ...ada, permissions } });
    expect(limited({ operations: ['github:write'] }).decision).toBe('ALLOW');
    expect(limited({ operations: ['risk:read'] }).code).toBe('USER_PERMISSION_DENIED');
    expect(limited({ resources: ['demo-org/*'] }).decision).toBe('ALLOW');
    const outside = limited({ resources: ['other-org/*'] });
    expect(outside.code).toBe('USER_PERMISSION_DENIED');
    expect(outside.reason).toContain('demo-org/demo-repo');
    expect(resourcePatternMatches('Demo-Org/*', 'demo-org/x')).toBe(true);
    expect(resourcePatternMatches('demo-org/demo', 'demo-org/demo-repo')).toBe(false);
  });
  it('policies see the user through argument rules (user.groups matches any group; negated rules need all)', () => {
    const contractors: Policy = { ...denyDestructive, id: 'pol_c', name: 'No contractors', conditions: { ...denyDestructive.conditions, operations: ['*'], arguments: [{ field: 'user.groups', op: 'in', value: ['contractors'] }] } };
    expect(run({ policies: [contractors], user: { ...ada, groups: ['engineering', 'contractors'] } }).code).toBe('POLICY_DENIED');
    expect(run({ policies: [contractors], user: ada }).decision).toBe('ALLOW');
    expect(run({ policies: [contractors] }).decision).toBe('ALLOW');
    const noUser: Policy = { ...contractors, id: 'pol_n', name: 'Users only', conditions: { ...contractors.conditions, arguments: [{ field: 'user.sub', op: 'equals', value: '' }] } };
    expect(run({ policies: [noUser] }).code).toBe('POLICY_DENIED');
    expect(run({ policies: [noUser], user: ada }).decision).toBe('ALLOW');
    expect(argumentHolds({ field: 'user.groups', op: 'not_in', value: ['contractors'] }, { resource: {}, input: {}, user: { ...ada, groups: ['engineering', 'contractors'] } })).toBe(false);
    expect(argumentProblem({ field: 'user.password', op: 'equals', value: 'x' })).toContain('user.sub');
  });
});

describe('delegation to sub-agents', () => {
  const dlg = { id: 'dlg_1', label: 'Triage helper', grantId: 'grt_1', operations: ['github.issues.create'], resources: ['demo-org/demo-repo'], maxRequests: 3, used: 0 };

  it('runs a delegated request against the parent grant, and names the sub-agent', () => {
    const r = run({ delegation: dlg });
    expect(r.decision).toBe('ALLOW');
    expect(r.checks[9]).toMatchObject({ step: 10, name: 'Delegation limits', passed: true, detail: expect.stringContaining('Triage helper') });
    expect(run({}).checks[9]?.detail).toBe('Not delegated: the agent itself');
  });
  it('allows only the delegated operations, resources and number of requests', () => {
    expect(run({ delegation: dlg, op: 'github.repositories.read' }).code).toBe('DELEGATION_DENIED');
    expect(run({ delegation: { ...dlg, resources: ['demo-org/other'] } }).code).toBe('DELEGATION_DENIED');
    expect(run({ delegation: { ...dlg, resources: [] } }).decision).toBe('ALLOW');
    expect(run({ delegation: { ...dlg, used: 3 } }).reason).toContain('all 3 requests');
  });
  it('uses only the delegated grant, and still fails when the parent grant does', () => {
    expect(run({ delegation: { ...dlg, grantId: 'grt_other' } }).code).toBe('DELEGATION_DENIED');
    expect(run({ delegation: dlg, grants: [grant({ storedStatus: 'REVOKED' })] }).code).toBe('GRANT_REVOKED');
    expect(run({ delegation: dlg, repo: 'demo-org/elsewhere' }).code).toBe('RESOURCE_DENIED');
    // A second, broader grant of the parent agent is not reachable through the delegation.
    const broad = grant({ id: 'grt_broad', scopes: ['github.issues.list'] });
    expect(run({ delegation: dlg, grants: [grant(), broad], op: 'github.issues.list' }).code).toBe('SCOPE_DENIED');
  });
});
