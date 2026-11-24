import type { Environment } from '../types';
import type { SecretCategory, SecretPayload } from './schema';

/**
 * Secrets as the control plane serves them (spec 4.9.5). Values never appear here: a secret
 * carries its metadata and a masked summary of its active version; only an authorized
 * retrieval returns a payload.
 */

/** Lifecycle states (spec 4.9.10). */
export const SECRET_STATUSES = ['PENDING', 'ACTIVE', 'EXPIRING', 'EXPIRED', 'ROTATION_PENDING', 'ROTATING', 'REVOKED', 'ARCHIVED', 'DELETED'] as const;
export type SecretStatus = (typeof SECRET_STATUSES)[number];

/** States in which the active version may be retrieved (spec 4.9.6, 4.9.10). */
export const RETRIEVABLE_SECRET_STATUSES: readonly SecretStatus[] = ['ACTIVE', 'EXPIRING', 'ROTATION_PENDING', 'ROTATING'];

/** States from which a secret can be revoked; revoked and archived ones can be archived or deleted. */
export const SECRET_TRANSITIONS: Record<'activate' | 'revoke' | 'archive' | 'delete', readonly SecretStatus[]> = {
  activate: ['PENDING'],
  revoke: ['PENDING', 'ACTIVE', 'EXPIRING', 'EXPIRED', 'ROTATION_PENDING', 'ROTATING'],
  archive: ['REVOKED', 'EXPIRED'],
  delete: ['PENDING', 'REVOKED', 'EXPIRED', 'ARCHIVED'],
};

export type SecretVersionState = 'ACTIVE' | 'PREVIOUS' | 'DESTROYED';

/** Project and workspace labels (spec 4.9.2 objective 4), until a project module exists. */
export const SECRET_SCOPE_SLUG = /^[a-z0-9][a-z0-9-]{0,62}$/;
export const SECRET_NAME = /^[A-Za-z0-9][A-Za-z0-9 ._/-]{0,119}$/;
export const SECRET_TAG = /^[a-z0-9][a-z0-9:._-]{0,39}$/;

export interface SecretVersionView {
  id: string;
  version: number;
  state: SecretVersionState;
  /** Keyed HMAC of the payload: tells versions apart without revealing them. */
  fingerprint: string;
  /** Non-sensitive fields as they are, sensitive ones masked. */
  summary: Record<string, string>;
  typeVersion: number;
  reason: string;
  /** Set for a rollback: the version whose value was copied. */
  copiedFrom: number | null;
  /** When a newer version replaced it (retention and grace periods count from here). */
  supersededAt: string | null;
  createdBy: { id: string; name: string };
  createdAt: string;
  destroyedAt: string | null;
}

export interface SecretView {
  id: string;
  organizationId: string;
  name: string;
  description: string;
  typeKey: string;
  typeName: string;
  category: SecretCategory;
  project: string;
  workspace: string;
  environment: Environment;
  tags: string[];
  metadata: SecretPayload;
  status: SecretStatus;
  activeVersion: number | null;
  /** Masked summary of the active version. */
  summary: Record<string, string>;
  fingerprint: string | null;
  webhookId: string;
  integrationId: string | null;
  expiresAt: string | null;
  rotation: SecretRotationSettings;
  lastRetrievedAt: string | null;
  createdBy: { id: string; name: string };
  createdAt: string;
  updatedBy: { id: string; name: string };
  updatedAt: string;
}

export interface SecretDetail extends SecretView {
  versions: SecretVersionView[];
  /** Latest rotation runs, newest first. */
  rotationJobs: SecretRotationJobView[];
  /** Expiry warning and version retention that apply, and where each comes from. */
  policy: EffectiveSecretPolicy;
  /** What the signed-in member may do with this secret now. */
  can: { retrieve: boolean; updateValue: boolean; updateMetadata: boolean; manageVersions: boolean; activate: boolean; revoke: boolean; archive: boolean; delete: boolean };
}

/** An authorized retrieval (spec 4.9.6): only the fields asked for and allowed. */
export interface SecretRetrieval {
  id: string;
  name: string;
  typeKey: string;
  version: number;
  payload: SecretPayload;
  expiresAt: string | null;
  retrievedAt: string;
}

// ── application access (spec 4.9.9, 4.9.15) ─────────────────────────

/**
 * Which secrets a grant covers: one secret (`secretId`), or every secret matching a selector
 * (all given keys must match). Selector grants follow secrets created later.
 */
export interface SecretSelector {
  project?: string;
  workspace?: string;
  environment?: Environment;
  typeKey?: string;
  tag?: string;
}

export type SecretGrantStatus = 'ACTIVE' | 'REVOKED' | 'EXPIRED';
export type SecretGrantVersions = 'ACTIVE' | 'ANY';

export interface SecretAccessGrantView {
  id: string;
  organizationId: string;
  agent: { id: string; name: string };
  secret: { id: string; name: string } | null;
  selector: SecretSelector | null;
  description: string;
  /** Fields the agent may read; empty: every field. */
  fields: string[];
  versions: SecretGrantVersions;
  allowedCidrs: string[];
  requireApproval: boolean;
  validFrom: string;
  expiresAt: string | null;
  status: SecretGrantStatus;
  createdBy: { id: string; name: string };
  createdAt: string;
  revokedAt: string | null;
  revokedBy: string | null;
  revocationReason: string | null;
  lastUsedAt: string | null;
  useCount: number;
}

export type SecretApprovalStatus = 'PENDING' | 'APPROVED' | 'REJECTED' | 'USED' | 'EXPIRED';

/** A held retrieval (grant with requireApproval): valid once, for this exact request, for 15 minutes. */
export interface SecretRetrievalApprovalView {
  id: string;
  grantId: string;
  agent: { id: string; name: string };
  secret: { id: string; name: string };
  version: number | null;
  fields: string[];
  reason: string;
  status: SecretApprovalStatus;
  requestedAt: string;
  expiresAt: string;
  decidedBy: { id: string; name: string } | null;
  decidedAt: string | null;
  note: string;
  usedAt: string | null;
}

/** Agent API: a secret this agent may read (metadata, never a value). */
export interface AgentSecretInfo {
  secret_id: string;
  name: string;
  type_key: string;
  project: string;
  workspace: string;
  environment: Environment;
  status: SecretStatus;
  active_version: number | null;
  expires_at: string | null;
  grant_id: string;
  fields: string[];
  versions: SecretGrantVersions;
  requires_approval: boolean;
}

/** Agent API: POST /agent/v1/secret/retrieve answer. */
export interface AgentSecretRetrieval {
  secret_id: string;
  name: string;
  type_key: string;
  version: number;
  payload: SecretPayload;
  expires_at: string | null;
  retrieved_at: string;
  grant_id: string;
  request_id: string;
}

// ── rotation, expiry policies, notifications (spec 4.9.11, 4.9.12, 4.9.18) ──

/**
 * How a scheduled rotation gets its new value:
 *  - manual: the secret becomes ROTATION_PENDING and people are notified; it rotates when someone stores the new value;
 *  - generated: the customer webhook creates the new value itself (types with `generate` fields).
 * Rotation through the provider that issued a credential arrives with dynamic secrets.
 */
export const SECRET_ROTATION_STRATEGIES = ['manual', 'generated'] as const;
export type SecretRotationStrategy = (typeof SECRET_ROTATION_STRATEGIES)[number];

export interface SecretRotationSettings {
  enabled: boolean;
  intervalDays: number | null;
  strategy: SecretRotationStrategy;
  /** Hours during which the replaced version stays retrievable (grants allowing any version) and is never destroyed. */
  graceHours: number;
  nextRotationAt: string | null;
  lastRotatedAt: string | null;
  /** Whether the type has fields the webhook can generate. */
  generatable: boolean;
}

export const SECRET_ROTATION_TRIGGERS = ['SCHEDULED', 'MANUAL', 'EXPIRY'] as const;
export type SecretRotationTrigger = (typeof SECRET_ROTATION_TRIGGERS)[number];
export const SECRET_ROTATION_JOB_STATUSES = ['PENDING', 'RUNNING', 'WAITING_FOR_VALUE', 'SUCCEEDED', 'FAILED', 'CANCELLED'] as const;
export type SecretRotationJobStatus = (typeof SECRET_ROTATION_JOB_STATUSES)[number];

/** One rotation of one secret (table rotation_jobs): its history and failures. */
export interface SecretRotationJobView {
  id: string;
  secret: { id: string; name: string };
  trigger: SecretRotationTrigger;
  strategy: SecretRotationStrategy;
  status: SecretRotationJobStatus;
  attempts: number;
  fromVersion: number | null;
  toVersion: number | null;
  errorCode: string | null;
  errorMessage: string | null;
  requestedBy: { id: string; name: string } | null;
  scheduledFor: string;
  startedAt: string | null;
  finishedAt: string | null;
  nextAttemptAt: string | null;
  createdAt: string;
}

export const SECRET_POLICY_SCOPES = ['ORGANIZATION', 'PROJECT', 'WORKSPACE'] as const;
export type SecretPolicyScope = (typeof SECRET_POLICY_SCOPES)[number];

/** The settings a secret policy can carry; null: not set at this level (a broader one applies). */
export interface SecretPolicySettings {
  /** Days before expiry when a secret becomes EXPIRING (the type's default otherwise). */
  expiryWarningDays: number | null;
  /** Expiry given to new secrets, and to a secret after each rotation. */
  defaultExpiresInDays: number | null;
  /** Inactive versions kept: the newest n ... */
  keepVersions: number | null;
  /** ... and every version replaced less than d days ago. Older ones are destroyed. */
  keepDays: number | null;
}

/**
 * Expiry and retention settings at organization, project or workspace level (spec 4.9.12,
 * 4.9.8). The most specific level that sets a value wins; the secret's own expiry date and
 * rotation settings override all of them.
 */
export interface SecretPolicyView extends SecretPolicySettings {
  id: string;
  scope: SecretPolicyScope;
  project: string | null;
  workspace: string | null;
  updatedBy: { id: string; name: string };
  updatedAt: string;
}

export type SecretPolicySource = SecretPolicyScope | 'TYPE' | 'NONE';
export interface EffectiveSecretPolicy {
  expiryWarningDays: { value: number; source: SecretPolicySource };
  defaultExpiresInDays: { value: number | null; source: SecretPolicySource };
  keepVersions: { value: number | null; source: SecretPolicySource };
  keepDays: { value: number | null; source: SecretPolicySource };
}

/** Lifecycle events people can be notified about (spec 4.9.18). Payloads never carry a value. */
export const SECRET_NOTIFICATION_EVENTS = [
  'secret.created',
  'secret.updated',
  'secret.expiring',
  'secret.expired',
  'secret.rotation_scheduled',
  'secret.rotation_succeeded',
  'secret.rotation_failed',
  'secret.access_denied',
  'secret.revoked',
  'secret.provider_failure',
] as const;
export type SecretNotificationEvent = (typeof SECRET_NOTIFICATION_EVENTS)[number];

export const SECRET_NOTIFICATION_EVENT_LABELS: Record<SecretNotificationEvent, string> = {
  'secret.created': 'Secret created',
  'secret.updated': 'Secret updated',
  'secret.expiring': 'Secret expiring',
  'secret.expired': 'Secret expired',
  'secret.rotation_scheduled': 'Rotation scheduled',
  'secret.rotation_succeeded': 'Rotation successful',
  'secret.rotation_failed': 'Rotation failed',
  'secret.access_denied': 'Secret access denied',
  'secret.revoked': 'Secret revoked',
  'secret.provider_failure': 'Provider failure',
};

export const NOTIFICATION_CHANNEL_KINDS = ['EMAIL', 'WEBHOOK', 'SLACK'] as const;
export type NotificationChannelKind = (typeof NOTIFICATION_CHANNEL_KINDS)[number];

/** Which secrets a channel hears about (all given keys must match; empty: every secret). */
export interface NotificationScope {
  project?: string;
  environment?: Environment;
}

export interface NotificationChannelView {
  id: string;
  name: string;
  kind: NotificationChannelKind;
  enabled: boolean;
  events: SecretNotificationEvent[];
  scope: NotificationScope;
  /** EMAIL: recipients. */
  recipients: string[];
  /** WEBHOOK: where events are POSTed, and a hint of the signing secret (shown in full once, on creation). */
  url: string | null;
  signingSecretHint: string | null;
  /** SLACK: the channel (the organization's Slack connection posts there; its default channel when null). */
  slackChannelId: string | null;
  createdBy: { id: string; name: string };
  createdAt: string;
  updatedAt: string;
  lastDelivery: { status: NotificationDeliveryStatus; at: string; error: string | null } | null;
}

export type NotificationDeliveryStatus = 'PENDING' | 'DELIVERED' | 'FAILED';

export interface NotificationDeliveryView {
  id: string;
  channel: { id: string; name: string; kind: NotificationChannelKind };
  event: SecretNotificationEvent | 'notification.test';
  secret: { id: string; name: string } | null;
  status: NotificationDeliveryStatus;
  attempts: number;
  lastError: string | null;
  createdAt: string;
  deliveredAt: string | null;
  nextAttemptAt: string | null;
}

/**
 * What a channel receives (the body of an outbound webhook; email and Slack render it as text).
 * Webhook requests carry `Token-Vault-Signature: t=<unix seconds>,v1=<hex HMAC-SHA256 of "t.body">`
 * with the channel's signing secret, plus `Token-Vault-Event` and `Token-Vault-Delivery`.
 */
export interface SecretNotificationPayload {
  id: string;
  event: SecretNotificationEvent | 'notification.test';
  occurredAt: string;
  organization: { id: string; name: string };
  secret: { id: string; name: string; typeKey: string; project: string; workspace: string; environment: Environment; status: SecretStatus; activeVersion: number | null; expiresAt: string | null } | null;
  /** Event specifics: versions, reason codes, the actor's name. Never a value. */
  details: Record<string, string | number | boolean | null>;
  consoleUrl: string | null;
}
