import { sql } from 'drizzle-orm';
import { bigint, boolean, customType, index, integer, jsonb, pgTable, text, uniqueIndex } from 'drizzle-orm/pg-core';
import type {
  AccessMode,
  ActingUser,
  DelegationRef,
  FilteringSummary,
  TraceRef,
  ResponseFilter,
  OnBehalfOfMode,
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
  /** Emergency stop: while set, every agent request in the organization is denied. */
  emergencyStoppedAt: ts('emergency_stopped_at'),
  emergencyStoppedBy: text('emergency_stopped_by'),
  emergencyStopReason: text('emergency_stop_reason'),
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
    authType: text('auth_type').notNull(),
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
    /** Rotation reminder interval in days (null = none). Reminders only; nothing is blocked. */
    rotationIntervalDays: integer('rotation_interval_days'),
    /** BROKERED (the webhook calls the application), DECISION_ONLY or SHORT_LIVED_CREDENTIAL (the caller does). */
    accessMode: text('access_mode').$type<AccessMode>().notNull().default('BROKERED'),
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
    /**
     * The key replaced by the last rotation, still accepted until previous_credential_expires_at
     * (grace period, so the agent can switch without failed requests). Hash only, like the current key.
     */
    previousCredentialKeyId: text('previous_credential_key_id').unique(),
    previousCredentialHash: text('previous_credential_hash'),
    previousCredentialExpiresAt: ts('previous_credential_expires_at'),
    previousCredentialLastUsedAt: ts('previous_credential_last_used_at'),
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
    /** Budgets (null: no limit), counted from the access log: requests per rolling 24 h, writes per rolling hour. */
    maxRequestsPerDay: integer('max_requests_per_day'),
    maxWritesPerHour: integer('max_writes_per_hour'),
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
    /** Acting for users: ALLOWED (may), REQUIRED (must), NOT_ALLOWED (must not carry a user token). */
    onBehalfOf: text('on_behalf_of').$type<OnBehalfOfMode>().notNull().default('ALLOWED'),
    /** The acting user must be in one of these groups (empty: any verified user). */
    allowedUserGroups: jsonb('allowed_user_groups').$type<string[]>().notNull().default([]),
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
    /** FILTER policies only: what to mask, remove or check in results. */
    responseFilter: jsonb('response_filter').$type<ResponseFilter | null>(),
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
    /** The user the agent acted for (null: for itself). Left out of the chained content when null (see audit/chain.ts). */
    onBehalfOf: jsonb('on_behalf_of').$type<ActingUser | null>(),
    /** The sub-agent delegation the request came through (null: the agent itself). Left out of the chained content when null. */
    delegation: jsonb('delegation').$type<DelegationRef | null>(),
    /** What response filtering did (counts only). Left out of the chained content when null. */
    filtering: jsonb('filtering').$type<FilteringSummary | null>(),
    /** Agent session and W3C trace context (null: none sent). Left out of the chained content when null. */
    trace: jsonb('trace').$type<TraceRef | null>(),
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
    // Audit → Sessions: requests of one session.
    index('access_requests_org_session_idx').on(t.organizationId, sql`(${t.trace}->>'sessionId')`),
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

/**
 * Human approval of one exact request (REQUIRE_APPROVAL policies). The approval is bound to
 * request_digest (integration, operation, resource, input), is single use, and must be used
 * within a short window after approval. EXPIRED is computed at read time from expires_at.
 */
export const operationApprovals = pgTable(
  'operation_approvals',
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
    /** The policy that required approval (name kept in case the policy is edited or deleted). */
    policyId: text('policy_id').notNull(),
    policyName: text('policy_name').notNull(),
    operation: text('operation').notNull(),
    resource: jsonb('resource').$type<Record<string, string>>().notNull(),
    /** Exactly what the agent will send: the approver sees this. Untrusted text. */
    input: jsonb('input').$type<Record<string, unknown>>().notNull(),
    /** sha256 of the canonical request; a request with this approval must match it. */
    requestDigest: text('request_digest').notNull(),
    status: text('status').$type<'PENDING' | 'APPROVED' | 'REJECTED' | 'EXECUTED'>().notNull(),
    /** The access request (audit record) that asked for approval. */
    requestedByRequestId: text('requested_by_request_id').notNull(),
    createdAt: ts('created_at').notNull(),
    /** PENDING: lapses at this time. APPROVED: must be executed by this time. */
    expiresAt: ts('expires_at').notNull(),
    decidedBy: text('decided_by'),
    decidedAt: ts('decided_at'),
    decisionNote: text('decision_note'),
    /** The user the agent asked to act for: the approval covers only requests for this user. */
    onBehalfOf: jsonb('on_behalf_of').$type<ActingUser | null>(),
    /** The sub-agent delegation that asked (null: the agent itself); part of the approved request. */
    delegation: jsonb('delegation').$type<DelegationRef | null>(),
    /** Where the approval request was posted (Slack), so the message can be updated once decided. */
    notifications: jsonb('notifications').$type<{ slack?: { channel: string; ts: string } } | null>(),
    executedAt: ts('executed_at'),
    executedRequestId: text('executed_request_id'),
  },
  (t) => [
    index('operation_approvals_org_status_idx').on(t.organizationId, t.status),
    index('operation_approvals_agent_digest_idx').on(t.agentId, t.requestDigest),
  ],
);

/**
 * Last verified provider catalog (one row). Envelopes are re-verified against the pinned
 * CMS key when loaded, so this row cannot inject a definition; high_water keeps replayed
 * older versions refused across restarts.
 */
export const providerCatalogState = pgTable('provider_catalog_state', {
  id: integer('id').primaryKey(),
  envelopes: jsonb('envelopes').notNull(),
  highWater: jsonb('high_water').$type<Record<string, number>>().notNull(),
  savedAt: ts('saved_at').notNull(),
});

/**
 * OAuth connections in progress. The state is bound to the admin who started the flow
 * (only its hash is stored), single use, and expires after 10 minutes. The client secret
 * and PKCE verifier are never here: they are in the customer webhook.
 */
export const oauthPending = pgTable('oauth_pending', {
  stateHash: text('state_hash').primaryKey(),
  organizationId: text('organization_id').notNull(),
  userId: text('user_id').notNull(),
  webhookId: text('webhook_id').notNull(),
  credentialReference: text('credential_reference').notNull(),
  draft: jsonb('draft').$type<Record<string, unknown>>().notNull(),
  createdAt: ts('created_at').notNull(),
  expiresAt: ts('expires_at').notNull(),
});

/**
 * Identity providers trusted to vouch for the users agents act for. Only public keys are
 * stored: user tokens are signed by the customer, never by Token Vault.
 */
export const userIssuers = pgTable(
  'user_issuers',
  {
    id: text('id').primaryKey(),
    organizationId: text('organization_id')
      .notNull()
      .references(() => organizations.id, { onDelete: 'cascade' }),
    name: text('name').notNull(),
    issuer: text('issuer').notNull(),
    audience: text('audience').notNull(),
    publicKey: text('public_key').notNull(),
    keyFingerprint: text('key_fingerprint').notNull(),
    groupsClaim: text('groups_claim').notNull().default('groups'),
    maxTokenLifetimeSeconds: integer('max_token_lifetime_seconds').notNull().default(3600),
    enabled: boolean('enabled').notNull().default(true),
    createdAt: ts('created_at').notNull(),
    updatedAt: ts('updated_at').notNull(),
    lastUsedAt: ts('last_used_at'),
  },
  (t) => [uniqueIndex('user_issuers_org_issuer_uq').on(t.organizationId, t.issuer)],
);

/**
 * Delegations to sub-agents: narrower, short-lived slices of an agent's grant with their own
 * credential (tvdt_<keyId>_<secret>, scrypt hash only). Revocation is a timestamp, never a
 * delete, so access records keep pointing at it.
 */
export const delegations = pgTable(
  'delegations',
  {
    id: text('id').primaryKey(),
    organizationId: text('organization_id')
      .notNull()
      .references(() => organizations.id, { onDelete: 'cascade' }),
    agentId: text('agent_id')
      .notNull()
      .references(() => agents.id),
    grantId: text('grant_id').notNull(),
    parentDelegationId: text('parent_delegation_id'),
    depth: integer('depth').notNull(),
    label: text('label').notNull(),
    operations: jsonb('operations').$type<string[]>().notNull(),
    resources: jsonb('resources').$type<string[]>().notNull().default([]),
    maxRequests: integer('max_requests'),
    onBehalfOf: jsonb('on_behalf_of').$type<ActingUser | null>(),
    keyId: text('key_id').notNull().unique(),
    credentialHash: text('credential_hash').notNull(),
    createdAt: ts('created_at').notNull(),
    expiresAt: ts('expires_at').notNull(),
    revokedAt: ts('revoked_at'),
    revokedBy: text('revoked_by'),
    revocationReason: text('revocation_reason'),
    lastUsedAt: ts('last_used_at'),
  },
  (t) => [index('delegations_org_idx').on(t.organizationId), index('delegations_agent_idx').on(t.agentId), index('delegations_grant_idx').on(t.grantId), index('delegations_parent_idx').on(t.parentDelegationId)],
);

/**
 * Slack approvals, one workspace and channel per organization. The bot token and signing
 * secret are Token Vault's own secrets, sealed with lib/secret-box (never returned by the API).
 */
export const slackSettings = pgTable('slack_settings', {
  organizationId: text('organization_id')
    .primaryKey()
    .references(() => organizations.id, { onDelete: 'cascade' }),
  teamId: text('team_id').notNull(),
  teamName: text('team_name').notNull(),
  botUserId: text('bot_user_id').notNull(),
  channelId: text('channel_id').notNull(),
  botTokenSealed: text('bot_token_sealed').notNull(),
  botTokenHint: text('bot_token_hint').notNull(),
  signingSecretSealed: text('signing_secret_sealed').notNull(),
  enabled: boolean('enabled').notNull().default(true),
  updatedAt: ts('updated_at').notNull(),
  updatedBy: text('updated_by').notNull(),
}, (t) => [uniqueIndex('slack_settings_team_uq').on(t.teamId)]);
