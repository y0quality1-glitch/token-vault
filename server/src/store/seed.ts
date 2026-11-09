import {
  DECISION_LABELS,
  DEFAULT_WEBHOOK_INSTANCE_ID,
  SEED_CREDENTIAL_REFS,
  type AccessRequest,
  type AuditEvent,
  type DecisionCheck,
  type Policy,
} from '@token-vault/shared';
import { config } from '../config';
import { chainBatch } from '../modules/audit/chain';
import { generateAgentCredential, hashSecret } from '../lib/crypto';
import { correlationId, newId, requestId } from '../lib/ids';
import { sql } from 'drizzle-orm';
import type { Organization } from '@token-vault/shared';
import { db as pg, transaction, type Executor } from '../db/client';
import * as t from '../db/schema';
import type { AgentRecord, GrantRecord, IntegrationRecord, MemberRecord, UserRecord, WebhookRecord } from './types';

/**
 * Demonstration seed data (spec section 12). All credentials here are MOCK.
 * Seeded agents receive random API keys that are immediately discarded: rotate an
 * agent's credential in the console to obtain a usable one (shown once).
 */
export const DEMO_PASSWORD = 'TokenVault-Demo-2026';

export const IDS = {
  demoOrg: 'org_demo0000000001',
  sandboxOrg: 'org_sandbox0000001',
  owner: 'usr_owner000000001',
  vaultAdmin: 'usr_vadmin00000001',
  securityAdmin: 'usr_secadm00000001',
  developer: 'usr_dev00000000001',
  auditor: 'usr_audit000000001',
  webhook: 'wh_local0000000001',
  intDemo: 'int_github_001',
  intStaging: 'int_github_002',
  intPartner: 'int_github_003',
  agtAssistant: 'agt_github_assist01',
  agtRelease: 'agt_release_notes01',
  agtTriage: 'agt_issue_triage01',
  grtIssue: 'grt_issue_creation01',
  grtStaging: 'grt_staging_read001',
  grtRelease: 'grt_release_read001',
  grtTriage: 'grt_triage_list0001',
  grtPartner: 'grt_partner_sync001',
};

const iso = (offsetMs: number) => new Date(Date.now() + offsetMs).toISOString();
const MIN = 60_000;
const HOUR = 60 * MIN;
const DAY = 24 * HOUR;

let cachedPasswordHash: string | null = null;

/** In-memory snapshot assembled before a single transactional insert. */
interface SeedData {
  organizations: Organization[];
  users: UserRecord[];
  members: MemberRecord[];
  webhooks: WebhookRecord[];
  integrations: IntegrationRecord[];
  agents: AgentRecord[];
  grants: GrantRecord[];
  policies: Policy[];
  accessRequests: AccessRequest[];
  auditEvents: AuditEvent[];
}

let db: SeedData;

export function buildSeed(): SeedData {
  db = { organizations: [], users: [], members: [], webhooks: [], integrations: [], agents: [], grants: [], policies: [], accessRequests: [], auditEvents: [] };
  const passwordHash = (cachedPasswordHash ??= hashSecret(DEMO_PASSWORD));

  db.organizations = [
    { id: IDS.demoOrg, name: 'Demo Organization', slug: 'demo-org', status: 'ACTIVE', environment: 'development', createdAt: iso(-30 * DAY), updatedAt: iso(-2 * DAY) },
    { id: IDS.sandboxOrg, name: 'Sandbox Organization', slug: 'sandbox-org', status: 'ACTIVE', environment: 'development', createdAt: iso(-1 * DAY), updatedAt: iso(-1 * DAY) },
  ];

  const users: [string, string, string][] = [
    [IDS.owner, 'owner@demo.test', 'Avery Chen'],
    [IDS.vaultAdmin, 'vault.admin@demo.test', 'Jordan Patel'],
    [IDS.securityAdmin, 'security@demo.test', 'Sam Okafor'],
    [IDS.developer, 'developer@demo.test', 'Riley Morgan'],
    [IDS.auditor, 'auditor@demo.test', 'Casey Liu'],
  ];
  db.users = users.map(([id, email, fullName]): UserRecord => ({ id, email, fullName, status: 'ACTIVE', createdAt: iso(-30 * DAY), passwordHash }));

  const m = (id: string, organizationId: string, userId: string, role: MemberRecord['role']): MemberRecord => ({ id, organizationId, userId, role, createdAt: iso(-30 * DAY) });
  db.members = [
    m('mem_0001', IDS.demoOrg, IDS.owner, 'OWNER'),
    m('mem_0002', IDS.demoOrg, IDS.vaultAdmin, 'VAULT_ADMIN'),
    m('mem_0003', IDS.demoOrg, IDS.securityAdmin, 'SECURITY_ADMIN'),
    m('mem_0004', IDS.demoOrg, IDS.developer, 'DEVELOPER'),
    m('mem_0005', IDS.demoOrg, IDS.auditor, 'AUDITOR'),
    // The owner also belongs to an empty sandbox org, used to walk through first-time setup.
    m('mem_0006', IDS.sandboxOrg, IDS.owner, 'OWNER'),
  ];

  const webhook: WebhookRecord = {
    id: IDS.webhook,
    organizationId: IDS.demoOrg,
    name: 'Local Customer Vault',
    endpointUrl: config.defaultWebhookUrl,
    environment: 'development',
    description: 'Docker/local process simulating the customer-isolated vault runtime.',
    // Mutual TLS when the deployment is set up for it (https URL and a client certificate).
    authenticationType: config.defaultWebhookUrl.startsWith('https://') && config.webhookTls.cert ? 'MTLS' : 'SHARED_SECRET_HMAC',
    signingSecretRef: config.webhookSigningSecretRef,
    status: 'CONNECTED',
    instanceId: DEFAULT_WEBHOOK_INSTANCE_ID,
    softwareVersion: '0.1.0-poc',
    lastHeartbeatAt: iso(-25_000),
    lastError: null,
    simulateOutage: false,
    registrationChallenge: null,
    healthHistory: [],
    createdAt: iso(-21 * DAY),
    verifiedAt: iso(-21 * DAY),
  };
  db.webhooks = [webhook];

  const integ = (id: string, displayName: string, environment: IntegrationRecord['environment'], accountLabel: string, ref: string, allowedResources: string[], createdAgo: number, description: string): IntegrationRecord => ({
    id,
    organizationId: IDS.demoOrg,
    webhookId: IDS.webhook,
    provider: 'github',
    displayName,
    environment,
    accountLabel,
    authType: 'PAT',
    credentialReference: ref,
    credentialStatus: 'CONNECTED',
    maskedIdentifier: '', // filled from the webhook on first successful sync
    credentialFingerprint: '',
    allowedResources,
    description,
    createdBy: IDS.vaultAdmin,
    createdAt: iso(-createdAgo),
    updatedAt: iso(-createdAgo),
    lastValidatedAt: iso(-2 * HOUR),
    rotatedAt: null,
    rotationIntervalDays: null,
    deletedAt: null,
  });
  db.integrations = [
    integ(IDS.intDemo, 'Demo GitHub', 'development', 'demo-org', SEED_CREDENTIAL_REFS.demoGithub.ref, ['demo-org/demo-repo', 'demo-org/other-repo', 'demo-org/docs'], 20 * DAY, 'Fine-grained PAT scoped to the demo-org test organization.'),
    integ(IDS.intStaging, 'GitHub Staging', 'staging', 'demo-org-staging', SEED_CREDENTIAL_REFS.stagingGithub.ref, [], 14 * DAY, 'Staging automation token.'),
    integ(IDS.intPartner, 'Partner GitHub', 'development', 'partner-org', SEED_CREDENTIAL_REFS.partnerGithub.ref, ['partner-org/shared-repo'], 6 * DAY, 'Shared repository with an external partner.'),
  ];

  const agent = (id: string, name: string, description: string, agentType: AgentRecord['agentType'], environment: AgentRecord['environment'], ownerUserId: string, ownerTeam: string, status: AgentRecord['status'], createdAgo: number, lastAccessAgo: number | null): AgentRecord => {
    const cred = generateAgentCredential(); // plaintext discarded immediately
    return {
      id,
      organizationId: IDS.demoOrg,
      name,
      description,
      agentType,
      environment,
      ownerUserId,
      ownerTeam,
      callbackUrl: '',
      allowedCidrs: [],
      credentialKeyId: cred.keyId,
      credentialHash: cred.hash,
      credentialIssuedAt: iso(-createdAgo),
      previousCredentialKeyId: null,
      previousCredentialHash: null,
      previousCredentialExpiresAt: null,
      previousCredentialLastUsedAt: null,
      status,
      lastAccessAt: lastAccessAgo === null ? null : iso(-lastAccessAgo),
      createdAt: iso(-createdAgo),
    };
  };
  db.agents = [
    agent(IDS.agtAssistant, 'GitHub Assistant', 'LLM coding assistant that files and triages issues.', 'AI_AGENT', 'development', IDS.developer, 'Platform AI', 'ACTIVE', 12 * DAY, 18 * MIN),
    agent(IDS.agtRelease, 'Release Notes Bot', 'Compiles release notes from merged issues.', 'APPLICATION', 'staging', IDS.developer, 'Release Engineering', 'ACTIVE', 9 * DAY, 3 * HOUR),
    agent(IDS.agtTriage, 'Issue Triage Agent', 'Legacy triage agent, decommissioned.', 'AI_AGENT', 'development', IDS.vaultAdmin, 'Platform AI', 'DISABLED', 25 * DAY, 2 * DAY),
  ];

  const grant = (g: Partial<GrantRecord> & Pick<GrantRecord, 'id' | 'agentId' | 'integrationId' | 'name' | 'scopes'>): GrantRecord => ({
    organizationId: IDS.demoOrg,
    environment: 'development',
    resourceConstraints: { repositories: [] },
    rateLimitPerMinute: 30,
    allowedCidrs: [],
    validFrom: iso(-5 * DAY),
    expiresAt: iso(30 * DAY),
    approvalRequired: false,
    storedStatus: 'ACTIVE',
    version: 1,
    previousVersionId: null,
    createdBy: IDS.vaultAdmin,
    createdAt: iso(-5 * DAY),
    approvedBy: null,
    approvedAt: null,
    revokedAt: null,
    revokedBy: null,
    revocationReason: null,
    lastUsedAt: null,
    usageCount: 0,
    ...g,
  });
  db.grants = [
    grant({
      id: IDS.grtIssue,
      agentId: IDS.agtAssistant,
      integrationId: IDS.intDemo,
      name: 'GitHub Issue Creation',
      scopes: ['github.repositories.read', 'github.issues.list', 'github.issues.create'],
      resourceConstraints: { repositories: ['demo-org/demo-repo'] },
      rateLimitPerMinute: 10,
      validFrom: iso(-4 * DAY),
      expiresAt: iso(7 * DAY),
      createdAt: iso(-4 * DAY),
      lastUsedAt: iso(-18 * MIN),
      lastReviewedAt: iso(-3 * DAY),
      lastReviewedBy: IDS.securityAdmin,
    }),
    grant({
      id: IDS.grtStaging,
      agentId: IDS.agtAssistant,
      integrationId: IDS.intStaging,
      name: 'Staging Read Access',
      environment: 'staging',
      scopes: ['github.repositories.read'],
      validFrom: iso(-10 * DAY),
      expiresAt: iso(-1 * DAY), // expired: demonstrates Scenario E
      createdAt: iso(-10 * DAY),
      lastUsedAt: iso(-2 * DAY),
    }),
    grant({
      id: IDS.grtRelease,
      agentId: IDS.agtRelease,
      integrationId: IDS.intStaging,
      name: 'Release Notes Read',
      environment: 'staging',
      scopes: ['github.repositories.read', 'github.contents.read', 'github.issues.list'],
      validFrom: iso(-40 * DAY), // never reviewed in 40 days: due for access review
      expiresAt: iso(2 * DAY - 3 * HOUR), // expiring soon
      createdAt: iso(-40 * DAY),
      lastUsedAt: iso(-3 * HOUR),
    }),
    grant({
      id: IDS.grtTriage,
      agentId: IDS.agtTriage,
      integrationId: IDS.intDemo,
      name: 'Triage Issue Listing',
      scopes: ['github.issues.list'],
      storedStatus: 'REVOKED',
      revokedAt: iso(-2 * DAY),
      revokedBy: IDS.securityAdmin,
      revocationReason: 'Agent decommissioned',
      createdAt: iso(-25 * DAY),
    }),
    grant({
      id: IDS.grtPartner,
      agentId: IDS.agtRelease,
      integrationId: IDS.intPartner,
      name: 'Partner Issue Sync',
      scopes: ['github.issues.list'],
      resourceConstraints: { repositories: ['partner-org/shared-repo'] },
      approvalRequired: true,
      storedStatus: 'PENDING_APPROVAL',
      createdBy: IDS.vaultAdmin,
      createdAt: iso(-5 * HOUR),
      validFrom: iso(-5 * HOUR),
      expiresAt: iso(14 * DAY),
    }),
  ];

  const policy = (p: Omit<Policy, 'organizationId' | 'createdAt' | 'updatedAt'>): Policy => ({ ...p, organizationId: IDS.demoOrg, createdAt: iso(-15 * DAY), updatedAt: iso(-15 * DAY) });
  db.policies = [
    policy({
      id: 'pol_block_destructive',
      name: 'Block destructive GitHub operations',
      description: 'Explicitly denies repository deletion and content writes for every agent, regardless of grants.',
      effect: 'DENY',
      priority: 10,
      enabled: true,
      conditions: { agentSelector: { type: 'any' }, integrationSelector: { type: 'provider', value: 'github' }, operations: ['github.repositories.delete', 'github.contents.write'], environment: 'any', timeWindow: null, sourceCidrs: [] },
    }),
    policy({
      id: 'pol_staging_maintenance',
      name: 'Staging maintenance window',
      description: 'Denies staging access during the nightly maintenance window (02:00-04:00 UTC).',
      effect: 'DENY',
      priority: 20,
      enabled: true,
      conditions: { agentSelector: { type: 'any' }, integrationSelector: { type: 'provider', value: 'github' }, operations: ['*'], environment: 'staging', timeWindow: { startHour: 2, endHour: 4 }, sourceCidrs: [] },
    }),
    policy({
      id: 'pol_partner_write_freeze',
      name: 'Freeze partner repository writes',
      description: 'Blocks issue creation on the partner integration while the contract is under review.',
      effect: 'DENY',
      priority: 30,
      enabled: false,
      conditions: { agentSelector: { type: 'any' }, integrationSelector: { type: 'integration', value: IDS.intPartner }, operations: ['github.issues.create'], environment: 'any', timeWindow: null, sourceCidrs: [] },
    }),
    policy({
      id: 'pol_ai_read_dev',
      name: 'AI agents may read in development',
      description: 'Baseline allow rule for read-only operations by AI agents in development. Grants are still required.',
      effect: 'ALLOW',
      priority: 100,
      enabled: true,
      conditions: { agentSelector: { type: 'agentType', value: 'AI_AGENT' }, integrationSelector: { type: 'provider', value: 'github' }, operations: ['github.repositories.read', 'github.contents.read', 'github.issues.list'], environment: 'development', timeWindow: null, sourceCidrs: [] },
    }),
  ];
  // Secure default for the empty sandbox organization: destructive operations are always denied.
  db.policies.push({
    ...db.policies[0]!,
    id: 'pol_sandbox_block_destructive',
    organizationId: IDS.sandboxOrg,
    description: 'Baseline guardrail created with the organization. Explicitly denies destructive GitHub operations.',
  });

  seedHistory();
  return db;
}

// ------------------------------------------------------------------ historical activity
function seedHistory() {
  const requests: AccessRequest[] = [];
  const events: AuditEvent[] = [];

  const agents = {
    assistant: { id: IDS.agtAssistant, name: 'GitHub Assistant' },
    release: { id: IDS.agtRelease, name: 'Release Notes Bot' },
    triage: { id: IDS.agtTriage, name: 'Issue Triage Agent' },
  };
  const integrations = {
    demo: { id: IDS.intDemo, name: 'Demo GitHub' },
    staging: { id: IDS.intStaging, name: 'GitHub Staging' },
  };

  type Spec = [number, keyof typeof agents, keyof typeof integrations, string, string, string, number | null, number];
  // [minutesAgo, agent, integration, operation, repository, decisionCode, upstreamStatus, durationMs]
  const specs: Spec[] = [
    [18, 'assistant', 'demo', 'github.issues.create', 'demo-org/demo-repo', 'ALLOWED', 201, 214],
    [22, 'assistant', 'demo', 'github.issues.list', 'demo-org/demo-repo', 'ALLOWED', 200, 132],
    [47, 'assistant', 'demo', 'github.contents.read', 'demo-org/demo-repo', 'SCOPE_DENIED', null, 4],
    [65, 'assistant', 'demo', 'github.repositories.read', 'demo-org/demo-repo', 'ALLOWED', 200, 118],
    [96, 'assistant', 'demo', 'github.issues.create', 'demo-org/other-repo', 'RESOURCE_DENIED', null, 3],
    [140, 'release', 'staging', 'github.issues.list', 'demo-org/demo-repo', 'ALLOWED', 200, 151],
    [180, 'release', 'staging', 'github.contents.read', 'demo-org/demo-repo', 'ALLOWED', 200, 167],
    [215, 'assistant', 'demo', 'github.repositories.delete', 'demo-org/demo-repo', 'POLICY_DENIED', null, 2],
    [260, 'assistant', 'demo', 'github.issues.list', 'demo-org/demo-repo', 'ALLOWED', 200, 109],
    [320, 'release', 'staging', 'github.repositories.read', 'demo-org/demo-repo', 'ALLOWED', 200, 142],
    [410, 'assistant', 'demo', 'github.issues.create', 'demo-org/demo-repo', 'WEBHOOK_UNAVAILABLE', null, 5003],
    [415, 'assistant', 'demo', 'github.issues.create', 'demo-org/demo-repo', 'ALLOWED', 201, 233],
    [530, 'triage', 'demo', 'github.issues.list', 'demo-org/demo-repo', 'AGENT_DISABLED', null, 3],
    [610, 'assistant', 'staging', 'github.repositories.read', 'demo-org/demo-repo', 'GRANT_EXPIRED', null, 3],
    [720, 'assistant', 'demo', 'github.repositories.read', 'demo-org/demo-repo', 'ALLOWED', 200, 121],
    [850, 'release', 'staging', 'github.issues.list', 'demo-org/demo-repo', 'ALLOWED', 200, 139],
    [960, 'assistant', 'demo', 'github.issues.list', 'demo-org/demo-repo', 'ALLOWED', 200, 126],
    [1080, 'assistant', 'demo', 'github.issues.create', 'demo-org/demo-repo', 'ALLOWED', 201, 248],
    [1190, 'triage', 'demo', 'github.issues.list', 'demo-org/demo-repo', 'AGENT_DISABLED', null, 2],
    [1300, 'release', 'staging', 'github.repositories.read', 'demo-org/demo-repo', 'ALLOWED', 200, 133],
    [1380, 'assistant', 'demo', 'github.issues.list', 'demo-org/demo-repo', 'ALLOWED', 200, 117],
  ];

  const reasons: Record<string, string> = {
    ALLOWED: 'All authorization checks passed.',
    SCOPE_DENIED: 'Operation github.contents.read is not included in grant scopes.',
    RESOURCE_DENIED: 'Repository demo-org/other-repo is outside the grant resource restriction.',
    POLICY_DENIED: 'Explicit deny policy "Block destructive GitHub operations" matched.',
    WEBHOOK_UNAVAILABLE: 'Authorized, but the customer webhook did not respond within 5000 ms. No credential was used.',
    AGENT_DISABLED: 'Agent is disabled.',
    GRANT_EXPIRED: 'Grant "Staging Read Access" expired.',
  };

  for (const [ago, agentKey, intKey, operation, repository, code, upstream, duration] of specs) {
    const agent = agents[agentKey];
    const integration = integrations[intKey];
    const allowed = code === 'ALLOWED' || code === 'WEBHOOK_UNAVAILABLE';
    const grantId =
      agentKey === 'assistant' && intKey === 'demo' ? IDS.grtIssue : agentKey === 'assistant' ? IDS.grtStaging : agentKey === 'release' ? IDS.grtRelease : IDS.grtTriage;
    const grantName = db.grants.find((g) => g.id === grantId)?.name ?? null;
    const corr = correlationId();
    const createdAt = iso(-ago * MIN);
    const checks: DecisionCheck[] = [{ step: 1, name: 'Authenticate caller', passed: true, detail: 'Agent credential verified (historical record).' }];
    const req: AccessRequest = {
      id: requestId(),
      organizationId: IDS.demoOrg,
      agentId: agent.id,
      agentName: agent.name,
      integrationId: integration.id,
      integrationName: integration.name,
      grantId: code === 'AGENT_DISABLED' || code === 'POLICY_DENIED' ? null : grantId,
      grantName: code === 'AGENT_DISABLED' || code === 'POLICY_DENIED' ? null : grantName,
      operation,
      resource: { repository },
      decision: allowed ? 'ALLOW' : 'DENY',
      decisionCode: code,
      decisionReason: reasons[code] ?? DECISION_LABELS[code] ?? code,
      matchedRule: code === 'POLICY_DENIED' ? { type: 'policy', id: 'pol_block_destructive', name: 'Block destructive GitHub operations' } : allowed ? { type: 'grant', id: grantId, name: grantName ?? undefined } : { type: 'default', name: 'Deny by default' },
      executionStatus: code === 'ALLOWED' ? 'SUCCEEDED' : code === 'WEBHOOK_UNAVAILABLE' ? 'FAILED' : 'NOT_EXECUTED',
      upstreamStatusCode: upstream,
      webhookStatus: code === 'ALLOWED' ? 'OK' : code === 'WEBHOOK_UNAVAILABLE' ? 'TIMEOUT' : 'NOT_CALLED',
      durationMs: duration,
      correlationId: corr,
      sourceIp: '10.20.4.17',
      source: 'agent-api',
      idempotencyKey: operation === 'github.issues.create' ? `hist-${ago}` : null,
      checks,
      createdAt,
    };
    requests.push(req);
    events.push({
      id: newId('evt'),
      organizationId: IDS.demoOrg,
      actorType: 'AGENT',
      actorId: agent.id,
      actorName: agent.name,
      eventType: code === 'ALLOWED' ? 'access.allowed' : code === 'WEBHOOK_UNAVAILABLE' ? 'access.execution_failed' : 'access.denied',
      targetType: 'integration',
      targetId: integration.id,
      targetName: integration.name,
      outcome: code === 'ALLOWED' ? 'SUCCESS' : code === 'WEBHOOK_UNAVAILABLE' ? 'FAILURE' : 'DENIED',
      severity: code === 'ALLOWED' ? 'info' : code === 'POLICY_DENIED' || code === 'AGENT_DISABLED' ? 'critical' : 'warning',
      metadata: { requestId: req.id, operation, repository, decisionCode: code },
      correlationId: corr,
      createdAt,
    });
  }

  const admin = (agoMs: number, actorId: string, eventType: string, targetType: string, targetId: string, targetName: string, metadata: Record<string, unknown> = {}, severity: AuditEvent['severity'] = 'info') =>
    events.push({
      id: newId('evt'),
      organizationId: IDS.demoOrg,
      actorType: 'USER',
      actorId,
      actorName: db.users.find((u) => u.id === actorId)!.fullName,
      eventType,
      targetType,
      targetId,
      targetName,
      outcome: 'SUCCESS',
      severity,
      metadata,
      correlationId: correlationId(),
      createdAt: iso(-agoMs),
    });

  admin(21 * DAY, IDS.vaultAdmin, 'webhook.registered', 'webhook', IDS.webhook, 'Local Customer Vault', { environment: 'development', authenticationType: 'SHARED_SECRET_HMAC' });
  admin(21 * DAY - 2 * MIN, IDS.vaultAdmin, 'webhook.verified', 'webhook', IDS.webhook, 'Local Customer Vault', { instanceId: DEFAULT_WEBHOOK_INSTANCE_ID });
  admin(20 * DAY, IDS.vaultAdmin, 'integration.connected', 'integration', IDS.intDemo, 'Demo GitHub', { provider: 'github', credentialReference: SEED_CREDENTIAL_REFS.demoGithub.ref });
  admin(14 * DAY, IDS.vaultAdmin, 'integration.connected', 'integration', IDS.intStaging, 'GitHub Staging', { provider: 'github', credentialReference: SEED_CREDENTIAL_REFS.stagingGithub.ref });
  admin(15 * DAY, IDS.securityAdmin, 'policy.created', 'policy', 'pol_block_destructive', 'Block destructive GitHub operations', { effect: 'DENY' });
  admin(12 * DAY, IDS.developer, 'agent.registered', 'agent', IDS.agtAssistant, 'GitHub Assistant', { agentType: 'AI_AGENT' });
  admin(9 * DAY, IDS.developer, 'agent.registered', 'agent', IDS.agtRelease, 'Release Notes Bot', { agentType: 'APPLICATION' });
  admin(40 * DAY, IDS.vaultAdmin, 'grant.created', 'grant', IDS.grtRelease, 'Release Notes Read', { scopes: ['github.repositories.read', 'github.contents.read', 'github.issues.list'] });
  admin(6 * DAY, IDS.vaultAdmin, 'integration.connected', 'integration', IDS.intPartner, 'Partner GitHub', { provider: 'github', credentialReference: SEED_CREDENTIAL_REFS.partnerGithub.ref });
  admin(4 * DAY, IDS.vaultAdmin, 'grant.created', 'grant', IDS.grtIssue, 'GitHub Issue Creation', { scopes: ['github.repositories.read', 'github.issues.list', 'github.issues.create'], repositories: ['demo-org/demo-repo'] });
  admin(2 * DAY, IDS.securityAdmin, 'grant.revoked', 'grant', IDS.grtTriage, 'Triage Issue Listing', { reason: 'Agent decommissioned' }, 'warning');
  admin(2 * DAY - 5 * MIN, IDS.securityAdmin, 'agent.disabled', 'agent', IDS.agtTriage, 'Issue Triage Agent', {}, 'warning');
  admin(5 * HOUR, IDS.vaultAdmin, 'grant.created', 'grant', IDS.grtPartner, 'Partner Issue Sync', { approvalRequired: true, status: 'PENDING_APPROVAL' });
  admin(1 * DAY, IDS.owner, 'auth.login', 'user', IDS.owner, 'Avery Chen', { method: 'password' });

  db.accessRequests = requests.sort((a, b) => b.createdAt.localeCompare(a.createdAt));
  db.auditEvents = events.sort((a, b) => b.createdAt.localeCompare(a.createdAt));

  db.webhooks[0]!.healthHistory = Array.from({ length: 8 }, (_, i) => ({
    at: iso(-(i + 1) * 30_000),
    ok: true,
    latencyMs: 8 + ((i * 7) % 11),
    detail: 'Signed health challenge verified (seed)',
  }));
}

// ------------------------------------------------------------------ persistence
const TABLES_IN_INSERT_ORDER = ['organizations', 'users', 'organization_members', 'webhooks', 'integrations', 'agents', 'grants', 'grant_requests', 'policies', 'access_requests', 'audit_events'];

async function insertSeed(data: SeedData, ex: Executor) {
  await ex.insert(t.organizations).values(data.organizations);
  await ex.insert(t.users).values(data.users);
  await ex.insert(t.organizationMembers).values(data.members);
  await ex.insert(t.webhooks).values(data.webhooks);
  await ex.insert(t.integrations).values(data.integrations);
  await ex.insert(t.agents).values(data.agents);
  await ex.insert(t.grants).values(data.grants);
  await ex.insert(t.policies).values(data.policies);
  // Seeded audit history is chained like live records (oldest first, per organization).
  await ex.insert(t.accessRequests).values(chainBatch(config.auditSigningKey, 'access_requests', data.accessRequests));
  await ex.insert(t.auditEvents).values(chainBatch(config.auditSigningKey, 'audit_events', data.auditEvents));
}

/** Seeds demo data only when the database has no organizations yet. Returns true if it seeded. */
export async function seedIfEmpty(): Promise<boolean> {
  return transaction(async (tx) => {
    // Serialize concurrent starters on one advisory lock.
    await tx.execute(sql`select pg_advisory_xact_lock(7316001)`);
    const existing = await tx.select({ id: t.organizations.id }).from(t.organizations).limit(1);
    if (existing.length > 0) return false;
    await insertSeed(buildSeed(), tx);
    return true;
  });
}

/**
 * Wipes all control-plane data and restores the seeded demo state, atomically.
 * Sessions are kept (seeded user IDs are stable), so signed-in admins stay signed in.
 * TRUNCATE bypasses the append-only row triggers on the audit tables by design: this
 * is the POC's demo reset, not an operation a production system would expose.
 */
export async function resetDatabase(ex: Executor = pg) {
  const run = async (tx: Executor) => {
    await tx.execute(sql.raw(`TRUNCATE ${[...TABLES_IN_INSERT_ORDER, 'provider_catalog_state', 'oauth_pending'].join(', ')} CASCADE`));
    await insertSeed(buildSeed(), tx);
  };
  if (ex === pg) await transaction(run);
  else await run(ex);
}
