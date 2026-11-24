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
  rotation: { enabled: boolean; intervalDays: number | null; nextRotationAt: string | null };
  lastRetrievedAt: string | null;
  createdBy: { id: string; name: string };
  createdAt: string;
  updatedBy: { id: string; name: string };
  updatedAt: string;
}

export interface SecretDetail extends SecretView {
  versions: SecretVersionView[];
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
