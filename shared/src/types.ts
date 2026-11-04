// Domain types shared by the control plane API and the admin console.
// NOTE: nothing in here ever carries a provider secret. Credential material lives
// only inside the customer webhook runtime; the control plane holds references.

export type Role = 'OWNER' | 'VAULT_ADMIN' | 'SECURITY_ADMIN' | 'DEVELOPER' | 'AUDITOR';
export type Environment = 'development' | 'staging' | 'production';
export type ISODate = string;

export interface Organization {
  id: string;
  name: string;
  slug: string;
  status: 'ACTIVE' | 'SUSPENDED';
  environment: Environment;
  createdAt: ISODate;
  updatedAt: ISODate;
}

export interface User {
  id: string;
  email: string;
  fullName: string;
  status: 'ACTIVE' | 'DISABLED';
  createdAt: ISODate;
}

export interface OrganizationMembership {
  id: string;
  organizationId: string;
  organizationName: string;
  organizationSlug: string;
  role: Role;
}

export interface Member {
  id: string;
  organizationId: string;
  userId: string;
  email: string;
  fullName: string;
  role: Role;
  createdAt: ISODate;
}

export interface SessionInfo {
  user: User;
  memberships: OrganizationMembership[];
  currentOrganization: Organization | null;
  role: Role | null;
  permissions: string[];
}

// ---------------------------------------------------------------- Webhook
export type WebhookStatus = 'PENDING' | 'CONNECTED' | 'UNHEALTHY' | 'DISCONNECTED';
export type WebhookAuthType = 'SHARED_SECRET_HMAC' | 'MTLS';

export interface HealthCheckResult {
  at: ISODate;
  ok: boolean;
  latencyMs: number | null;
  detail: string;
}

export interface Webhook {
  id: string;
  organizationId: string;
  name: string;
  endpointUrl: string;
  environment: Environment;
  description: string;
  authenticationType: WebhookAuthType;
  /** Name of the environment variable holding the signing secret. Never the value. */
  signingSecretRef: string;
  status: WebhookStatus;
  instanceId: string | null;
  softwareVersion: string | null;
  lastHeartbeatAt: ISODate | null;
  lastError: string | null;
  /** Demo control: forces execution to fail as if the webhook were unreachable. */
  simulateOutage: boolean;
  registrationChallenge: string | null;
  healthHistory: HealthCheckResult[];
  createdAt: ISODate;
  verifiedAt: ISODate | null;
}

// ---------------------------------------------------------------- Integrations
export type ProviderId = 'github' | 'google' | 'slack' | 'openai';
export type CredentialStatus = 'CONNECTED' | 'DISABLED' | 'INVALID' | 'ROTATION_REQUIRED';

export interface CatalogEntry {
  provider: ProviderId;
  name: string;
  description: string;
  authMethods: string[];
  available: boolean;
  connectedCount: number;
}

export interface Integration {
  id: string;
  organizationId: string;
  webhookId: string;
  webhookName: string;
  provider: ProviderId;
  displayName: string;
  environment: Environment;
  accountLabel: string;
  authType: 'PAT' | 'OAUTH';
  /** Opaque pointer to the encrypted credential inside the customer webhook. */
  credentialReference: string;
  credentialStatus: CredentialStatus;
  /** e.g. "ghp_••••••••3f9a" (computed by the webhook, never the secret). */
  maskedIdentifier: string;
  credentialFingerprint: string;
  allowedResources: string[];
  description: string;
  createdBy: string;
  createdByName: string;
  createdAt: ISODate;
  updatedAt: ISODate;
  lastValidatedAt: ISODate | null;
  rotatedAt: ISODate | null;
}

export interface IntegrationDetail extends Integration {
  grantedAgents: { agentId: string; agentName: string; grantId: string; grantName: string; status: GrantStatus; scopes: string[] }[];
}

// ---------------------------------------------------------------- Agents
export type AgentType = 'AI_AGENT' | 'APPLICATION' | 'SERVICE';
export type AgentStatus = 'ACTIVE' | 'DISABLED';

export interface Agent {
  id: string;
  organizationId: string;
  name: string;
  description: string;
  agentType: AgentType;
  environment: Environment;
  ownerUserId: string;
  ownerName: string;
  ownerTeam: string;
  callbackUrl: string;
  allowedCidrs: string[];
  /** Public key identifier embedded in the API credential prefix. */
  credentialKeyId: string;
  credentialIssuedAt: ISODate;
  status: AgentStatus;
  activeGrants: number;
  lastAccessAt: ISODate | null;
  createdAt: ISODate;
}

export interface IssuedCredential {
  /** Shown exactly once. The control plane stores only a scrypt hash. */
  apiKey: string;
  keyId: string;
  issuedAt: ISODate;
}

export interface ApiClient {
  keyId: string;
  maskedKey: string;
  agentId: string;
  agentName: string;
  agentStatus: AgentStatus;
  issuedAt: ISODate;
  lastUsedAt: ISODate | null;
}

// ---------------------------------------------------------------- Grants
export type GrantStoredStatus = 'ACTIVE' | 'PENDING_APPROVAL' | 'REVOKED' | 'SUPERSEDED';
export type GrantStatus = GrantStoredStatus | 'EXPIRED' | 'SCHEDULED';

export interface Grant {
  id: string;
  organizationId: string;
  agentId: string;
  agentName: string;
  integrationId: string;
  integrationName: string;
  name: string;
  environment: Environment;
  scopes: string[];
  resourceConstraints: { repositories: string[] };
  rateLimitPerMinute: number;
  allowedCidrs: string[];
  validFrom: ISODate;
  expiresAt: ISODate;
  approvalRequired: boolean;
  storedStatus: GrantStoredStatus;
  /** Effective status, computed at read time from stored status + validity window. */
  status: GrantStatus;
  version: number;
  previousVersionId: string | null;
  createdBy: string;
  createdByName: string;
  createdAt: ISODate;
  approvedBy: string | null;
  approvedAt: ISODate | null;
  revokedAt: ISODate | null;
  revokedBy: string | null;
  revocationReason: string | null;
  lastUsedAt: ISODate | null;
  usageCount: number;
}

export interface GrantDetail extends Grant {
  usage: { allowed: number; denied: number; last24h: number };
  recentRequests: AccessRequest[];
  versions: { id: string; version: number; status: GrantStatus; createdAt: ISODate }[];
  matchingPolicies: { id: string; name: string; effect: PolicyEffect }[];
}

// ---------------------------------------------------------------- Policies
export type PolicyEffect = 'ALLOW' | 'DENY';

export interface PolicyConditions {
  agentSelector: { type: 'any' | 'agent' | 'agentType'; value?: string };
  integrationSelector: { type: 'any' | 'integration' | 'provider'; value?: string };
  /** Operation ids, or ["*"] for any operation. */
  operations: string[];
  environment: Environment | 'any';
  /** Policy applies only between these UTC hours [startHour, endHour). */
  timeWindow?: { startHour: number; endHour: number } | null;
  /** Policy applies only to requests from these IPv4 CIDRs. */
  sourceCidrs?: string[];
}

export interface Policy {
  id: string;
  organizationId: string;
  name: string;
  description: string;
  effect: PolicyEffect;
  conditions: PolicyConditions;
  priority: number;
  enabled: boolean;
  createdAt: ISODate;
  updatedAt: ISODate;
}

// ---------------------------------------------------------------- Access decisions & audit
export type Decision = 'ALLOW' | 'DENY';
export type ExecutionStatus = 'SUCCEEDED' | 'FAILED' | 'NOT_EXECUTED';

export interface DecisionCheck {
  step: number;
  name: string;
  passed: boolean | null; // null = skipped (an earlier check failed)
  detail: string;
}

export interface MatchedRule {
  type: 'grant' | 'policy' | 'default';
  id?: string;
  name?: string;
}

export interface AccessRequest {
  id: string;
  organizationId: string;
  agentId: string | null;
  agentName: string;
  integrationId: string | null;
  integrationName: string;
  grantId: string | null;
  grantName: string | null;
  operation: string;
  resource: Record<string, string>;
  decision: Decision;
  decisionCode: string;
  decisionReason: string;
  matchedRule: MatchedRule | null;
  executionStatus: ExecutionStatus;
  upstreamStatusCode: number | null;
  webhookStatus: string;
  durationMs: number;
  correlationId: string;
  sourceIp: string;
  source: 'agent-api' | 'playground';
  idempotencyKey: string | null;
  checks: DecisionCheck[];
  createdAt: ISODate;
}

export type AuditActorType = 'USER' | 'AGENT' | 'SYSTEM';
export type AuditOutcome = 'SUCCESS' | 'DENIED' | 'FAILURE';

export interface AuditEvent {
  id: string;
  organizationId: string;
  actorType: AuditActorType;
  actorId: string;
  actorName: string;
  eventType: string;
  targetType: string;
  targetId: string;
  targetName: string;
  outcome: AuditOutcome;
  severity: 'info' | 'warning' | 'critical';
  /** Sanitized; never contains secrets, tokens, authorization headers or request bodies. */
  metadata: Record<string, unknown>;
  correlationId: string;
  createdAt: ISODate;
}

// ---------------------------------------------------------------- Dashboard
export interface DashboardSummary {
  counts: {
    connectedIntegrations: number;
    registeredAgents: number;
    activeGrants: number;
    requests24h: number;
    denied24h: number;
  };
  webhook: { status: WebhookStatus | 'NOT_CONFIGURED'; name: string | null; lastHeartbeatAt: ISODate | null; count: number };
  hourly: { hour: string; allowed: number; denied: number }[];
  recentActivity: AccessRequest[];
  integrations: Pick<Integration, 'id' | 'displayName' | 'provider' | 'credentialStatus' | 'environment' | 'lastValidatedAt'>[];
  agentActivity: { agentId: string; agentName: string; status: AgentStatus; requests24h: number; denied24h: number; lastAccessAt: ISODate | null }[];
  alerts: { id: string; severity: 'warning' | 'critical' | 'info'; title: string; detail: string; link: string; at: ISODate }[];
  expiringGrants: Pick<Grant, 'id' | 'name' | 'agentName' | 'integrationName' | 'expiresAt' | 'status'>[];
  setup: { webhook: boolean; integration: boolean; agent: boolean; grant: boolean; request: boolean };
}

// ---------------------------------------------------------------- Agent execution API
export interface ExecuteRequestBody {
  integration_id: string;
  operation: string;
  resource?: { repository?: string; path?: string };
  input?: Record<string, unknown>;
  idempotency_key?: string;
}

export interface ExecuteResponseBody {
  request_id: string;
  correlation_id: string;
  decision: Decision;
  decision_code: string;
  reason: string;
  matched_rule: MatchedRule | null;
  grant_id: string | null;
  execution: {
    status: ExecutionStatus;
    webhook_status: string;
    upstream_status: number | null;
    duration_ms: number;
    simulated: boolean;
    idempotent_replay: boolean;
  };
  result: unknown;
  checks: DecisionCheck[];
}

export interface ApiErrorBody {
  error: { code: string; message: string; details?: unknown };
}

export interface Paginated<T> {
  items: T[];
  total: number;
}
