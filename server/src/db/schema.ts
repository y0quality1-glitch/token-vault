import { bigint, boolean, customType, index, integer, jsonb, pgTable, text, uniqueIndex } from 'drizzle-orm/pg-core';
import type {
  AgentStatus,
  AgentType,
  AuditActorType,
  AuditOutcome,
  CredentialStatus,
  Decision,
  DecisionCheck,
  Environment,
  ExecutionStatus,
  GrantStoredStatus,
  HealthCheckResult,
  MatchedRule,
  PolicyConditions,
  PolicyEffect,
  ProviderId,
  Role,
  WebhookAuthType,
  WebhookStatus,
} from '@token-vault/shared';

/**
 * Control-plane schema (spec section 9). Credential material is deliberately absent:
 * integrations hold only a reference into the customer webhook's encrypted store, and
 * agents hold only a scrypt hash of their API key.
 *
 * Timestamps are `timestamptz(3)` in the database and ISO-8601 strings in TypeScript,
 * matching the domain types shared with the client.
 */
const ts = customType<{ data: string; driverData: string | Date }>({
  dataType: () => 'timestamp(3) with time zone',
  fromDriver: (v) => (v instanceof Date ? v : new Date(v)).toISOString(),
  toDriver: (v) => v,
});

export const organizations = pgTable('organizations', {
  id: text('id').primaryKey(),
  name: text('name').notNull(),
  slug: text('slug').notNull().unique(),
  status: text('status').$type<'ACTIVE' | 'SUSPENDED'>().notNull(),
  environment: text('environment').$type<Environment>().notNull(),
  createdAt: ts('created_at').notNull(),
  updatedAt: ts('updated_at').notNull(),
});

export const users = pgTable('users', {
  id: text('id').primaryKey(),
  email: text('email').notNull().unique(),
  passwordHash: text('password_hash').notNull(),
  fullName: text('full_name').notNull(),
  status: text('status').$type<'ACTIVE' | 'DISABLED'>().notNull(),
  createdAt: ts('created_at').notNull(),
});

export const organizationMembers = pgTable(
  'organization_members',
  {
    id: text('id').primaryKey(),
    organizationId: text('organization_id')
      .notNull()
      .references(() => organizations.id, { onDelete: 'cascade' }),
    userId: text('user_id')
      .notNull()
      .references(() => users.id, { onDelete: 'cascade' }),
    role: text('role').$type<Role>().notNull(),
    createdAt: ts('created_at').notNull(),
  },
  (t) => [uniqueIndex('organization_members_org_user_uq').on(t.organizationId, t.userId)],
);

/**
 * Admin sessions. The primary key is the SHA-256 of the cookie token, so a database
 * read does not yield usable session tokens. No FK to users: sessions survive a demo
 * reset (seeded user IDs are stable) and are validated against users on every request.
 */
export const sessions = pgTable(
  'sessions',
  {
    tokenHash: text('token_hash').primaryKey(),
    userId: text('user_id').notNull(),
    organizationId: text('organization_id'),
    createdAt: ts('created_at').notNull(),
    expiresAt: ts('expires_at').notNull(),
  },
  (t) => [index('sessions_expires_at_idx').on(t.expiresAt)],
);

export const webhooks = pgTable(
  'webhooks',
  {
    id: text('id').primaryKey(),
    organizationId: text('organization_id')
      .notNull()
      .references(() => organizations.id, { onDelete: 'cascade' }),
    name: text('name').notNull(),
    endpointUrl: text('endpoint_url').notNull(),
    environment: text('environment').$type<Environment>().notNull(),
    description: text('description').notNull().default(''),
    authenticationType: text('authentication_type').$type<WebhookAuthType>().notNull(),
    /** Name of the env var holding the signing secret. Never the value. */
    signingSecretRef: text('signing_secret_ref').notNull(),
    status: text('status').$type<WebhookStatus>().notNull(),
    instanceId: text('instance_id'),
    softwareVersion: text('software_version'),
    lastHeartbeatAt: ts('last_heartbeat_at'),
    lastError: text('last_error'),
    simulateOutage: boolean('simulate_outage').notNull().default(false),
    registrationChallenge: text('registration_challenge'),
    healthHistory: jsonb('health_history').$type<HealthCheckResult[]>().notNull().default([]),
    createdAt: ts('created_at').notNull(),
    verifiedAt: ts('verified_at'),
  },
  (t) => [index('webhooks_org_idx').on(t.organizationId)],
);

export const integrations = pgTable(
  'integrations',
  {
    id: text('id').primaryKey(),
    organizationId: text('organization_id')
      .notNull()
      .references(() => organizations.id, { onDelete: 'cascade' }),
    webhookId: text('webhook_id')
      .notNull()
      .references(() => webhooks.id),
    provider: text('provider').$type<ProviderId>().notNull(),
    displayName: text('display_name').notNull(),
    environment: text('environment').$type<Environment>().notNull(),
    accountLabel: text('account_label').notNull(),
    authType: text('auth_type').$type<'PAT' | 'OAUTH'>().notNull(),
    /** Opaque pointer into the customer webhook's encrypted store. */
    credentialReference: text('credential_reference').notNull(),
    credentialStatus: text('credential_status').$type<CredentialStatus>().notNull(),
    maskedIdentifier: text('masked_identifier').notNull().default(''),
    credentialFingerprint: text('credential_fingerprint').notNull().default(''),
    allowedResources: jsonb('allowed_resources').$type<string[]>().notNull().default([]),
    description: text('description').notNull().default(''),
    createdBy: text('created_by').notNull(),
    createdAt: ts('created_at').notNull(),
    updatedAt: ts('updated_at').notNull(),
    lastValidatedAt: ts('last_validated_at'),
    rotatedAt: ts('rotated_at'),
    /** Soft delete: grants and audit records keep referring to the integration. */
    deletedAt: ts('deleted_at'),
  },
  (t) => [index('integrations_org_idx').on(t.organizationId)],
);

export const agents = pgTable(
  'agents',
  {
    id: text('id').primaryKey(),
    organizationId: text('organization_id')
      .notNull()
      .references(() => organizations.id, { onDelete: 'cascade' }),
    name: text('name').notNull(),
    description: text('description').notNull().default(''),
    agentType: text('agent_type').$type<AgentType>().notNull(),
    environment: text('environment').$type<Environment>().notNull(),
    ownerUserId: text('owner_user_id')
      .notNull()
      .references(() => users.id),
    ownerTeam: text('owner_team').notNull(),
    callbackUrl: text('callback_url').notNull().default(''),
    allowedCidrs: jsonb('allowed_cidrs').$type<string[]>().notNull().default([]),
    credentialKeyId: text('credential_key_id').notNull().unique(),
    /** scrypt hash of the agent API key; the key itself is never stored. */
    credentialHash: text('credential_hash').notNull(),
    credentialIssuedAt: ts('credential_issued_at').notNull(),
    status: text('status').$type<AgentStatus>().notNull(),
    lastAccessAt: ts('last_access_at'),
    createdAt: ts('created_at').notNull(),
  },
  (t) => [index('agents_org_idx').on(t.organizationId)],
);

export const grants = pgTable(
  'grants',
  {
    id: text('id').primaryKey(),
    organizationId: text('organization_id')
      .notNull()
      .references(() => organizations.id, { onDelete: 'cascade' }),
    agentId: text('agent_id')
      .notNull()
      .references(() => agents.id),
    integrationId: text('integration_id')
      .notNull()
      .references(() => integrations.id),
    name: text('name').notNull(),
    environment: text('environment').$type<Environment>().notNull(),
    scopes: jsonb('scopes').$type<string[]>().notNull(),
    resourceConstraints: jsonb('resource_constraints').$type<{ repositories: string[] }>().notNull(),
    rateLimitPerMinute: integer('rate_limit_per_minute').notNull(),
    allowedCidrs: jsonb('allowed_cidrs').$type<string[]>().notNull().default([]),
    validFrom: ts('valid_from').notNull(),
    expiresAt: ts('expires_at').notNull(),
    approvalRequired: boolean('approval_required').notNull().default(false),
    storedStatus: text('status').$type<GrantStoredStatus>().notNull(),
    version: integer('version').notNull().default(1),
    previousVersionId: text('previous_version_id'),
    createdBy: text('created_by').notNull(),
    createdAt: ts('created_at').notNull(),
    approvedBy: text('approved_by'),
    approvedAt: ts('approved_at'),
    revokedAt: ts('revoked_at'),
    revokedBy: text('revoked_by'),
    revocationReason: text('revocation_reason'),
    lastUsedAt: ts('last_used_at'),
    usageCount: integer('usage_count').notNull().default(0),
    /** Access reviews: last time a reviewer certified this grant should keep existing. */
    lastReviewedAt: ts('last_reviewed_at'),
    lastReviewedBy: text('last_reviewed_by'),
  },
  (t) => [index('grants_org_idx').on(t.organizationId), index('grants_agent_integration_idx').on(t.agentId, t.integrationId)],
);

export const policies = pgTable(
  'policies',
  {
    id: text('id').primaryKey(),
    organizationId: text('organization_id')
      .notNull()
      .references(() => organizations.id, { onDelete: 'cascade' }),
    name: text('name').notNull(),
    description: text('description').notNull().default(''),
    effect: text('effect').$type<PolicyEffect>().notNull(),
    conditions: jsonb('conditions').$type<PolicyConditions>().notNull(),
    priority: integer('priority').notNull(),
    enabled: boolean('enabled').notNull(),
    createdAt: ts('created_at').notNull(),
    updatedAt: ts('updated_at').notNull(),
  },
  (t) => [index('policies_org_idx').on(t.organizationId)],
);

/**
 * Append-only (enforced by a trigger in migration 0001). Agent / integration / grant
 * IDs are not foreign keys on purpose: audit records must outlive the entities they describe.
 */
export const accessRequests = pgTable(
  'access_requests',
  {
    id: text('id').primaryKey(),
    organizationId: text('organization_id')
      .notNull()
      .references(() => organizations.id, { onDelete: 'cascade' }),
    agentId: text('agent_id'),
    agentName: text('agent_name').notNull(),
    integrationId: text('integration_id'),
    integrationName: text('integration_name').notNull(),
    grantId: text('grant_id'),
    grantName: text('grant_name'),
    operation: text('operation').notNull(),
    resource: jsonb('resource').$type<Record<string, string>>().notNull(),
    decision: text('decision').$type<Decision>().notNull(),
    decisionCode: text('decision_code').notNull(),
    decisionReason: text('decision_reason').notNull(),
    matchedRule: jsonb('matched_rule').$type<MatchedRule | null>(),
    executionStatus: text('execution_status').$type<ExecutionStatus>().notNull(),
    upstreamStatusCode: integer('upstream_status_code'),
    webhookStatus: text('webhook_status').notNull(),
    durationMs: integer('duration_ms').notNull(),
    correlationId: text('correlation_id').notNull(),
    sourceIp: text('source_ip').notNull(),
    source: text('source').$type<'agent-api' | 'playground'>().notNull(),
    idempotencyKey: text('idempotency_key'),
    checks: jsonb('checks').$type<DecisionCheck[]>().notNull(),
    createdAt: ts('created_at').notNull(),
    // Tamper evidence (migration 0003): per-organization hash chain + HMAC with a key held outside the database.
    // NULL on rows written before chaining existed ("legacy").
    seq: bigint('seq', { mode: 'number' }),
    prevHash: text('prev_hash'),
    hash: text('hash'),
    mac: text('mac'),
  },
  (t) => [
    uniqueIndex('access_requests_org_seq_uq').on(t.organizationId, t.seq),
    index('access_requests_org_created_idx').on(t.organizationId, t.createdAt),
    index('access_requests_grant_idx').on(t.grantId),
    index('access_requests_agent_idx').on(t.agentId),
    index('access_requests_correlation_idx').on(t.correlationId),
  ],
);

/** Append-only (enforced by a trigger in migration 0001). Metadata is sanitized before insert. */
export const auditEvents = pgTable(
  'audit_events',
  {
    id: text('id').primaryKey(),
    organizationId: text('organization_id')
      .notNull()
      .references(() => organizations.id, { onDelete: 'cascade' }),
    actorType: text('actor_type').$type<AuditActorType>().notNull(),
    actorId: text('actor_id').notNull(),
    actorName: text('actor_name').notNull(),
    eventType: text('event_type').notNull(),
    targetType: text('target_type').notNull(),
    targetId: text('target_id').notNull(),
    targetName: text('target_name').notNull(),
    outcome: text('outcome').$type<AuditOutcome>().notNull(),
    severity: text('severity').$type<'info' | 'warning' | 'critical'>().notNull(),
    metadata: jsonb('metadata').$type<Record<string, unknown>>().notNull(),
    correlationId: text('correlation_id').notNull(),
    createdAt: ts('created_at').notNull(),
    // Tamper evidence (migration 0003): per-organization hash chain + HMAC with a key held outside the database.
    // NULL on rows written before chaining existed ("legacy").
    seq: bigint('seq', { mode: 'number' }),
    prevHash: text('prev_hash'),
    hash: text('hash'),
    mac: text('mac'),
  },
  (t) => [uniqueIndex('audit_events_org_seq_uq').on(t.organizationId, t.seq), index('audit_events_org_created_idx').on(t.organizationId, t.createdAt), index('audit_events_correlation_idx').on(t.correlationId)],
);

/**
 * Just-in-time access requests: an agent asks for a time-limited grant; a human approves
 * (creating the grant) or rejects it. EXPIRED is computed at read time from expires_at.
 */
export const grantRequests = pgTable(
  'grant_requests',
  {
    id: text('id').primaryKey(),
    organizationId: text('organization_id')
      .notNull()
      .references(() => organizations.id, { onDelete: 'cascade' }),
    agentId: text('agent_id')
      .notNull()
      .references(() => agents.id),
    integrationId: text('integration_id')
      .notNull()
      .references(() => integrations.id),
    operations: jsonb('operations').$type<string[]>().notNull(),
    repositories: jsonb('repositories').$type<string[]>().notNull().default([]),
    /** Written by the agent: untrusted text, shown to approvers as a quote. */
    justification: text('justification').notNull(),
    requestedDurationMinutes: integer('requested_duration_minutes').notNull(),
    /** The denied access request (audit record) that prompted this, if any. */
    deniedRequestId: text('denied_request_id'),
    status: text('status').$type<'PENDING' | 'APPROVED' | 'REJECTED'>().notNull(),
    createdAt: ts('created_at').notNull(),
    /** A pending request lapses after this time. */
    expiresAt: ts('expires_at').notNull(),
    decidedBy: text('decided_by'),
    decidedAt: ts('decided_at'),
    decisionNote: text('decision_note'),
    approvedDurationMinutes: integer('approved_duration_minutes'),
    /** The grant created on approval. */
    grantId: text('grant_id'),
  },
  (t) => [index('grant_requests_org_status_idx').on(t.organizationId, t.status), index('grant_requests_agent_idx').on(t.agentId)],
);
