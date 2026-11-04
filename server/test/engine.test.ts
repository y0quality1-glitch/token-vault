import { describe, expect, it } from 'vitest';
import { getOperation, type Policy } from '@token-vault/shared';
import { evaluate, policyMatches } from '../src/modules/policy-engine/engine';
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

function run(opts: { op?: string; repo?: string; grants?: GrantRecord[]; policies?: Policy[]; used?: number; agentStatus?: 'ACTIVE' | 'DISABLED'; ip?: string; integrationStatus?: 'CONNECTED' | 'DISABLED' }) {
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
