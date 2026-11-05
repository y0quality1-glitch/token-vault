/** Contract between the provider CMS API and its admin UI. */

export type CmsRole = 'EDITOR' | 'PUBLISHER' | 'ADMIN';
export type VersionStatus = 'DRAFT' | 'IN_REVIEW' | 'PUBLISHED' | 'SUPERSEDED';

export interface CmsUser {
  id: string;
  email: string;
  fullName: string;
  role: CmsRole;
}

export interface CmsSession {
  user: CmsUser;
}

export interface CmsApplicationSummary {
  key: string;
  name: string;
  description: string;
  archived: boolean;
  publishedVersion: number | null;
  publishedAt: string | null;
  openVersion: { version: number; status: 'DRAFT' | 'IN_REVIEW' } | null;
  operationCount: number;
  updatedAt: string;
}

export interface CmsVersionSummary {
  version: number;
  status: VersionStatus;
  digest: string | null;
  createdBy: string;
  createdAt: string;
  authors: string[];
  submittedBy: string | null;
  submittedAt: string | null;
  reviewedBy: string | null;
  reviewedAt: string | null;
  reviewNote: string | null;
  publishedAt: string | null;
}

export interface CmsDiff {
  /** Compared with the currently published version (null when nothing is published yet). */
  againstVersion: number | null;
  /** baseUrl or allowedHosts differ (or first publication): approval must acknowledge it. */
  hostChange: boolean;
  changes: { area: string; kind: 'added' | 'removed' | 'changed' }[];
}

export interface CmsVersionDetail extends CmsVersionSummary {
  key: string;
  definition: unknown;
  /** Validation problems; a version can only be submitted with none. */
  issues: string[];
  diff: CmsDiff;
  /** One signature per CMS key that has signed this version (published versions only). */
  signatures: { keyId: string; signedAt: string; active: boolean }[];
  /** What the current user may do with this version, and why not. */
  can: { edit: boolean; submit: boolean; withdraw: boolean; review: boolean; reviewBlockedReason: string | null };
}

export interface CmsApplicationDetail extends CmsApplicationSummary {
  createdBy: string;
  createdAt: string;
  versions: CmsVersionSummary[];
}

export interface CmsAuditEvent {
  id: number;
  at: string;
  actorName: string;
  action: string;
  applicationKey: string | null;
  version: number | null;
  details: Record<string, unknown>;
}

export interface CmsPreviewResult {
  request: { method: string; url: string; headers: string[]; body: unknown };
  /** The operation's declared mock response passed through its response allow-list. */
  mockResponse: { status: number; body: unknown } | null;
  error: string | null;
}

// ---------------------------------------------------------------- Token Vault: providers API

/** A provider as the console needs it, derived from the definition the control plane trusts. */
export interface ProviderInfo {
  key: string;
  name: string;
  description: string;
  version: number;
  source: 'bundled' | 'catalog';
  digest: string | null;
  resource: { name: string; label: string; pattern: string; example?: string };
  resourceFields: Record<string, { label: string; pattern: string; example?: string }>;
  auth: { id: string; label: string; description: string; kind: 'bearer' | 'header' | 'basic' | 'plugin'; plugin?: string; secretHint?: string; secretPattern?: string }[];
  operations: (import('./operations').OperationDef & {
    input: Record<string, { type: 'string' | 'number' | 'boolean'; label?: string; required: boolean; maxLength?: number; multiline?: boolean }>;
  })[];
}

export interface ProvidersResponse {
  providers: ProviderInfo[];
  /** Catalog sync state (null when the control plane uses bundled definitions only). */
  catalog: { url: string; keyIds: string[]; lastSuccessAt: string | null; lastError: string | null; restoredFrom: string | null } | null;
}
