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
/** A provider definition key (e.g. "github"). */
export type ProviderId = string;
export type CredentialStatus = 'CONNECTED' | 'DISABLED' | 'INVALID' | 'ROTATION_REQUIRED';

export type CatalogEntry = import('./operations').CatalogItem & {
  connectedCount: number;
};

export interface Integration {
  id: string;
  organizationId: string;
  webhookId: string;
  webhookName: string;
  provider: ProviderId;
  displayName: string;
  environment: Environment;
  accountLabel: string;
  /** Id of the provider definition's auth method, e.g. PAT, GITHUB_APP (per-request App tokens) or API_KEY. */
  authType: string;
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
  /** Access reviews: when a reviewer last certified the grant (null: never reviewed). */
  lastReviewedAt?: ISODate | null;
  lastReviewedBy?: string | null;
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
  /** Tamper evidence: position in the organization's hash chain (null for pre-chain records). */
  seq?: number | null;
  prevHash?: string | null;
  hash?: string | null;
  mac?: string | null;
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
  /** Tamper evidence: position in the organization's hash chain (null for pre-chain records). */
  seq?: number | null;
  prevHash?: string | null;
  hash?: string | null;
  mac?: string | null;
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
  /** Resource fields named by the provider definition (GitHub: repository, path). */
  resource?: { repository?: string; path?: string; [field: string]: string | undefined };
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
    /** GitHub App integrations: the short-lived token minted for this request (never the token itself). */
    credential?: CredentialUseInfo | null;
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

/** GET /agent/v1/capabilities: the calling agent's own grants and their current status (superseded versions omitted). */
export interface AgentCapabilitiesBody {
  agent: { id: string; name: string; status: 'ACTIVE' | 'DISABLED'; organization: string };
  grants: {
    grant_id: string;
    name: string;
    status: GrantStatus;
    integration_id: string;
    integration_name: string;
    provider: ProviderId;
    integration_available: boolean;
    operations: string[];
    repositories: string[];
    rate_limit_per_minute: number;
    valid_from: ISODate;
    expires_at: ISODate;
  }[];
}

/** A resource field an operation takes (the primary resource grants are scoped to, or an extra one). */
export interface AgentResourceField {
  name: string;
  label: string;
  /** Anchored regular expression every value must match. */
  pattern: string;
  case_insensitive: boolean;
  example: string | null;
}

/**
 * GET /agent/v1/operations: the shape of every operation of the applications this agent
 * has a grant on, so clients (the MCP server) can offer them as typed tools. Definitions
 * are not secret; whether a call is allowed is still decided per request.
 */
export interface AgentOperationsBody {
  /** Changes whenever any of these definitions changes (digests of the versions in use). */
  version: string;
  providers: {
    key: string;
    name: string;
    description: string;
    version: number;
    resource: AgentResourceField;
    resource_fields: AgentResourceField[];
    operations: {
      id: string;
      label: string;
      description: string;
      risk: 'read' | 'write' | 'destructive';
      /** Whether the primary resource must be given. */
      requires_resource: boolean;
      input: { name: string; type: 'string' | 'number' | 'boolean'; label: string | null; required: boolean; max_length: number | null }[];
    }[];
  }[];
}

// ---------------------------------------------------------------- Just-in-time access requests
export type GrantRequestStatus = 'PENDING' | 'APPROVED' | 'REJECTED' | 'EXPIRED';

export interface GrantRequest {
  id: string;
  organizationId: string;
  agentId: string;
  agentName: string;
  agentOwnerUserId: string;
  integrationId: string;
  integrationName: string;
  operations: string[];
  repositories: string[];
  /** Written by the agent: untrusted text. */
  justification: string;
  requestedDurationMinutes: number;
  deniedRequestId: string | null;
  status: GrantRequestStatus;
  createdAt: ISODate;
  expiresAt: ISODate;
  decidedBy: string | null;
  decidedByName: string | null;
  decidedAt: ISODate | null;
  decisionNote: string | null;
  approvedDurationMinutes: number | null;
  grantId: string | null;
}

/** Agent API view of its own access request. */
export interface AgentAccessRequestBody {
  access_request_id: string;
  status: GrantRequestStatus;
  integration_id: string;
  operations: string[];
  repositories: string[];
  requested_duration_minutes: number;
  created_at: ISODate;
  expires_at: ISODate;
  decided_at: ISODate | null;
  decision_note: string | null;
  grant_id: string | null;
  grant_expires_at: ISODate | null;
}

// ---------------------------------------------------------------- Audit integrity
export type IntegrityProblemKind = 'hash_mismatch' | 'mac_invalid' | 'broken_link' | 'sequence_gap';

export interface ChainVerification {
  table: 'audit_events' | 'access_requests';
  ok: boolean;
  totalRecords: number;
  chainedRecords: number;
  /** Rows written before chaining existed; not covered by verification. */
  legacyRecords: number;
  headSeq: number | null;
  headHash: string | null;
  problems: { seq: number | null; id: string; kind: IntegrityProblemKind; detail: string }[];
}

export interface IntegrityReport {
  ok: boolean;
  verifiedAt: ISODate;
  chains: ChainVerification[];
}

// ---------------------------------------------------------------- Access reviews
export interface AccessReviewItem {
  grant: Grant;
  lastReviewedAt: ISODate | null;
  lastReviewedByName: string | null;
  reviewDueAt: ISODate;
  due: boolean;
  uses30d: number;
  denied30d: number;
}

export interface AccessReviewSummary {
  intervalDays: number;
  due: number;
  unused30d: number;
  expiringSoon: number;
  items: AccessReviewItem[];
}

/** Non-secret description of a per-request credential minted by the customer webhook. */
export type CredentialUseInfo =
  | {
      type: 'github_app_installation_token';
      repositories: string[];
      permissions: Record<string, string>;
      expires_at: ISODate;
      revoked: boolean;
    }
  | {
      /** An OAuth access token held by the webhook; refreshed when it was about to expire or was rejected. */
      type: 'oauth2_access_token';
      refreshed: boolean;
      expires_at: ISODate | null;
      scopes: string[];
    };
