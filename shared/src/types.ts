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
  /** Emergency stop: while set, every agent request in the organization is denied (EMERGENCY_STOP). */
  emergencyStoppedAt?: ISODate | null;
  emergencyStoppedBy?: string | null;
  emergencyStopReason?: string | null;
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
  /** Rotation reminder: the credential is due this many days after its last rotation (null = no reminder). */
  rotationIntervalDays: number | null;
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
  /** Key replaced by the last rotation, still accepted until previousCredentialExpiresAt (grace period). */
  previousCredentialKeyId: string | null;
  previousCredentialExpiresAt: ISODate | null;
  /** Last time the previous key was used: when it stops changing, the agent has switched. */
  previousCredentialLastUsedAt: ISODate | null;
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
  /** Budget: authorized requests in any rolling 24 hours (null: no limit). */
  maxRequestsPerDay?: number | null;
  /** Budget: authorized write operations (anything but reads) in any rolling hour (null: no limit). */
  maxWritesPerHour?: number | null;
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
  /** Acting for users: whether requests must, may or must not carry a signed user token (default ALLOWED). */
  onBehalfOf?: OnBehalfOfMode;
  /** When set, the acting user must be in one of these groups (from the user token). Empty: any user. */
  allowedUserGroups?: string[];
}

/**
 * Acting on behalf of a user. ALLOWED: the agent may act for itself or for a user.
 * REQUIRED: every request must carry a valid user token. NOT_ALLOWED: the agent acts only for itself.
 */
export type OnBehalfOfMode = 'ALLOWED' | 'REQUIRED' | 'NOT_ALLOWED';

/** The user an agent acted for, from a verified user token. */
export interface ActingUser {
  /** The token's subject: the user's id in the customer's identity system. */
  sub: string;
  email?: string | null;
  name?: string | null;
  groups: string[];
  /**
   * What this user may let an agent do, from the token's "token_vault" claim (absent: no
   * limit beyond the grant). Operations are selectors (github.issues.create, github.*, github:write,
   * risk:read); resources are values of the operation's primary resource, "*" at the end
   * matching any suffix (demo-org/*).
   */
  permissions?: { operations?: string[]; resources?: string[] } | null;
  /** The registered issuer that vouched for the user. */
  issuerId: string;
  issuer: string;
}

/**
 * An identity provider (or the customer's own application) trusted to vouch for the users
 * agents act for. Tokens are JWTs signed with an asymmetric key (RS256, ES256 or EdDSA).
 */
export interface UserIssuer {
  id: string;
  organizationId: string;
  name: string;
  /** Must equal the token's "iss" claim. */
  issuer: string;
  /** Must be one of the token's "aud" values. */
  audience: string;
  /** Public key, PEM or JWK (JSON). Never a secret. */
  publicKey: string;
  /** Short fingerprint of the key, for display. */
  keyFingerprint: string;
  /** Claim holding the user's groups (default "groups"). */
  groupsClaim: string;
  /** Longest accepted token lifetime (exp - iat), in seconds. */
  maxTokenLifetimeSeconds: number;
  enabled: boolean;
  createdAt: ISODate;
  updatedAt: ISODate;
  lastUsedAt?: ISODate | null;
}

/**
 * Delegation to a sub-agent: a narrower, short-lived slice of one of an agent's grants,
 * used with its own one-time token (tvdt_…). It can only narrow: operations and resources
 * within the grant (or the parent delegation), an earlier expiry, an optional request cap.
 * Every request still runs against the parent agent's grant, so revoking that grant (or
 * disabling the agent, or revoking any delegation up the chain) stops it.
 */
export interface Delegation {
  id: string;
  organizationId: string;
  /** The agent whose grant is delegated. */
  agentId: string;
  grantId: string;
  /** Set when a sub-agent delegated further (depth 2 or 3). */
  parentDelegationId: string | null;
  depth: number;
  /** What the sub-agent is for, as the delegating agent described it (agent-written). */
  label: string;
  operations: string[];
  /** Allowed values of the primary resource. Empty: whatever the grant allows. */
  resources: string[];
  /** Cap on authorized requests over the delegation's life (null: none beyond the grant's limits). */
  maxRequests: number | null;
  /** The user every request is made for, when the delegation was created on behalf of one. */
  onBehalfOf: ActingUser | null;
  keyId: string;
  createdAt: ISODate;
  expiresAt: ISODate;
  revokedAt: ISODate | null;
  /** "agent:<id>", "delegation:<id>" or a console user id. */
  revokedBy: string | null;
  revocationReason: string | null;
  lastUsedAt: ISODate | null;
}

export type DelegationStatus = 'ACTIVE' | 'EXPIRED' | 'REVOKED';

/** Console view of a delegation. */
export interface DelegationView extends Delegation {
  /** Effective status: REVOKED also when a delegation up the chain was revoked. */
  status: DelegationStatus;
  statusReason: string | null;
  agentName: string;
  grantName: string;
  integrationId: string;
  integrationName: string;
  /** Authorized requests made with it so far. */
  used: number;
}

/**
 * What an access record keeps about the agent session and W3C trace context of a request.
 * `sessionId` groups requests: the agent's session_id, or the trace id when it sent none.
 */
export interface TraceRef {
  sessionId: string;
  /** The agent's own label for the session (agent-written, untrusted). */
  sessionLabel: string | null;
  /** W3C trace id (32 hex): from the agent's traceparent, or generated. */
  traceId: string;
  /** The agent's span that made this call (from traceparent), if any. */
  parentSpanId: string | null;
  /** Token Vault's span for this request (16 hex); passed on to the webhook. */
  spanId: string;
}

/** A session: requests one agent made in one conversation, task or job (Audit → Sessions). */
export interface SessionSummary {
  sessionId: string;
  sessionLabel: string | null;
  agentId: string | null;
  agentName: string;
  requests: number;
  allowed: number;
  denied: number;
  /** Requests held for human approval (APPROVAL_REQUIRED). */
  held: number;
  firstAt: ISODate;
  lastAt: ISODate;
  integrations: string[];
  /** Users the agent acted for during the session (subjects). */
  users: string[];
  /** Sub-agents (delegation labels) that took part. */
  subAgents: string[];
}

export interface SessionDetail extends SessionSummary {
  /** Every request of the session, oldest first. */
  timeline: AccessRequest[];
  /** Approvals asked for during the session. */
  approvals: { id: string; status: OperationApprovalStatus; operation: string; createdAt: ISODate; requestId: string }[];
}

/** What an access record keeps about response filtering (counts and signals, never the values). */
export interface FilteringSummary {
  policyIds: string[];
  policyNames: string[];
  /** Values masked per kind (a list, so a kind such as "secret" is never mistaken for secret material by audit sanitizing). */
  masked: { kind: string; count: number }[];
  removedFields: number;
  injection: { detected: boolean; signals: { path: string; signal: string }[] };
  withheld: boolean;
  /** Who applied the filter: the customer webhook, or the control plane when the webhook did not. */
  appliedBy: 'webhook' | 'control-plane';
}

/** What an access record or approval keeps about the delegation a request came through. */
export interface DelegationRef {
  id: string;
  label: string;
  depth: number;
  parentId: string | null;
}

export interface GrantDetail extends Grant {
  usage: { allowed: number; denied: number; last24h: number };
  recentRequests: AccessRequest[];
  versions: { id: string; version: number; status: GrantStatus; createdAt: ISODate }[];
  matchingPolicies: { id: string; name: string; effect: PolicyEffect }[];
  /** Budget consumption, when the grant has budgets. */
  budgetUsage?: { requestsLast24h: number; writesLastHour: number } | null;
}

// ---------------------------------------------------------------- Policies
/** REQUIRE_APPROVAL: a request that every other check allows still waits until a human approves that exact request. */
export type PolicyEffect = 'ALLOW' | 'DENY' | 'REQUIRE_APPROVAL' | 'FILTER';

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
  /** Argument rules: the policy applies only when every one of these holds for the request. */
  arguments?: ArgumentCondition[];
}

/**
 * A condition on what the request contains. `field` is `input.<name>` or `resource.<name>`.
 * A missing field is the empty string. Numeric operators treat a value that is not a number
 * as matching, so a deny or approval rule fails closed.
 */
export type ArgumentOperator = 'equals' | 'not_equals' | 'contains' | 'not_contains' | 'matches' | 'not_matches' | 'in' | 'not_in' | 'longer_than' | 'greater_than' | 'less_than';

export interface ArgumentCondition {
  field: string;
  op: ArgumentOperator;
  /** A string, a number (longer_than, greater_than, less_than), or a list (in, not_in). */
  value: string | number | string[];
}

export interface Policy {
  id: string;
  organizationId: string;
  name: string;
  description: string;
  effect: PolicyEffect;
  conditions: PolicyConditions;
  /** FILTER policies: what to mask, remove or check in results before the agent gets them. */
  responseFilter?: import('./response-filter').ResponseFilter | null;
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
  /** The user the agent acted for (absent: the agent acted for itself). */
  onBehalfOf?: ActingUser | null;
  /** The sub-agent delegation the request came through (absent: the agent itself). */
  delegation?: DelegationRef | null;
  /** What response filtering did to the result (counts only, never values). Absent: no filter applied. */
  filtering?: FilteringSummary | null;
  /** The agent session and trace the request belongs to (absent: the agent sent neither). */
  trace?: TraceRef | null;
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
  /** An APPROVED operation approval for exactly this request (same integration, operation, resource and input). */
  approval_id?: string;
  /** A signed user token (JWT from a registered issuer): the agent acts for that user. */
  on_behalf_of?: string;
  /**
   * The agent's session (a conversation, task or job) this call is part of. Calls with the same
   * session id are shown together under Audit → Sessions. Letters, digits and . _ : - only.
   */
  session_id?: string;
  /** A short human-readable name for the session, e.g. the task the agent is working on. Agent-written. */
  session_label?: string;
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
  /** Set when a REQUIRE_APPROVAL policy applies: the approval this request waits for, or the one it used. */
  approval?: { approval_id: string; status: OperationApprovalStatus; expires_at: ISODate } | null;
  /** The verified user the request was made for (absent: the agent acted for itself). */
  acting_for?: { sub: string; email: string | null; name: string | null; issuer: string } | null;
  /** The delegation the request came through, when a sub-agent sent it. */
  delegation?: { delegation_id: string; label: string; used: number; max_requests: number | null } | null;
  /** The trace this request was recorded under: echo of the session, the W3C trace id, and Token Vault's own span id. */
  trace?: { session_id: string; trace_id: string; span_id: string; parent_span_id: string | null } | null;
  /**
   * Set when a Filter responses policy applied: what was masked, removed or flagged. When
   * `withheld` is true the operation ran but `result` is null (decision code RESPONSE_WITHHELD).
   */
  filtering?: {
    policies: string[];
    masked: { kind: string; count: number }[];
    removed_fields: number;
    prompt_injection: { detected: boolean; signals: { path: string; signal: string }[] };
    withheld: boolean;
  } | null;
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
  /** Set when the caller is a sub-agent: its one grant is narrowed to the delegation. */
  delegation?: AgentDelegationBody | null;
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
    /** Budgets (null: no limit): authorized requests per rolling 24 hours, write operations per rolling hour. */
    max_requests_per_day: number | null;
    max_writes_per_hour: number | null;
    /** Whether requests must (REQUIRED), may (ALLOWED) or must not (NOT_ALLOWED) carry a user token. */
    on_behalf_of: OnBehalfOfMode;
    allowed_user_groups: string[];
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

// ---------------------------------------------------------------- Operation approvals (REQUIRE_APPROVAL policies)
/**
 * PENDING: waiting for a human. APPROVED: the agent may run this exact request once, until
 * expiresAt. EXECUTED: it was run. REJECTED, EXPIRED: it can no longer run.
 */
export type OperationApprovalStatus = 'PENDING' | 'APPROVED' | 'REJECTED' | 'EXPIRED' | 'EXECUTED';

export interface OperationApproval {
  id: string;
  organizationId: string;
  agentId: string;
  agentName: string;
  agentOwnerUserId: string;
  integrationId: string;
  integrationName: string;
  policyId: string;
  policyName: string;
  operation: string;
  resource: Record<string, string>;
  /** Exactly what the agent will send if approved. Written by the agent: untrusted. */
  input: Record<string, unknown>;
  status: OperationApprovalStatus;
  /** The access request (audit record) that asked for approval. */
  requestedByRequestId: string;
  createdAt: ISODate;
  /** PENDING: lapses at this time. APPROVED: must be run by this time. */
  expiresAt: ISODate;
  decidedBy: string | null;
  decidedByName: string | null;
  decidedAt: ISODate | null;
  decisionNote: string | null;
  executedAt: ISODate | null;
  executedRequestId: string | null;
  /** The user the agent asked to act for: the approval covers only requests for this user. */
  onBehalfOf?: ActingUser | null;
  /** The sub-agent delegation that asked (absent: the agent itself). */
  delegation?: DelegationRef | null;
  /** The agent session the held request was part of, so the approver can see what led to it. */
  session?: { sessionId: string; sessionLabel: string | null; earlierRequests: number } | null;
}

/** Settings → Notifications: where approval requests are posted in Slack. Secrets are never returned. */
export interface SlackSettingsView {
  configured: boolean;
  enabled: boolean;
  teamId: string | null;
  teamName: string | null;
  channelId: string | null;
  botUserId: string | null;
  /** Last characters of the bot token, e.g. "xoxb-…f3a9". */
  botTokenHint: string | null;
  /** Paste into the Slack app's Interactivity "Request URL". */
  interactionsUrl: string;
  updatedAt: ISODate | null;
  updatedByName: string | null;
}

/** Agent API view of a delegation (never includes its token, except once on creation). */
export interface AgentDelegationBody {
  delegation_id: string;
  label: string;
  grant_id: string;
  parent_delegation_id: string | null;
  depth: number;
  operations: string[];
  resources: string[];
  max_requests: number | null;
  used: number;
  on_behalf_of: { sub: string; email: string | null; issuer: string } | null;
  status: DelegationStatus;
  status_reason: string | null;
  created_at: ISODate;
  expires_at: ISODate;
  revoked_at: ISODate | null;
}

/** Agent API view of an approval its request is waiting for. */
export interface AgentApprovalBody {
  approval_id: string;
  status: OperationApprovalStatus;
  integration_id: string;
  operation: string;
  resource: Record<string, string>;
  input: Record<string, unknown>;
  created_at: ISODate;
  expires_at: ISODate;
  decided_at: ISODate | null;
  decision_note: string | null;
  executed_request_id: string | null;
  /** The user the request acts for: running it again needs a valid token for this user. */
  on_behalf_of?: { sub: string; issuer: string } | null;
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
