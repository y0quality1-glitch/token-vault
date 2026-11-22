import { BaseEntity, Column, Entity, PrimaryColumn } from 'typeorm';
import type { Environment, GrantStoredStatus, OnBehalfOfMode } from '@token-vault/shared';
import { tsColumn } from './columns';

/** Table `grants` (see the baseline migration for constraints, indexes and triggers). */
@Entity('grants')
export class GrantEntity extends BaseEntity {
  @PrimaryColumn({ name: 'id', type: 'text' })
  id!: string;

  @Column({ name: 'organization_id', type: 'text' })
  organizationId!: string;

  @Column({ name: 'agent_id', type: 'text' })
  agentId!: string;

  @Column({ name: 'integration_id', type: 'text' })
  integrationId!: string;

  @Column({ name: 'name', type: 'text' })
  name!: string;

  @Column({ name: 'environment', type: 'text' })
  environment!: Environment;

  @Column({ name: 'scopes', type: 'jsonb' })
  scopes!: string[];

  @Column({ name: 'resource_constraints', type: 'jsonb' })
  resourceConstraints!: { repositories: string[] };

  @Column({ name: 'rate_limit_per_minute', type: 'integer' })
  rateLimitPerMinute!: number;

  /** Budgets (null: no limit), counted from the access log: requests per rolling 24 h, writes per rolling hour. */
  @Column({ name: 'max_requests_per_day', type: 'integer', nullable: true })
  maxRequestsPerDay!: number | null;

  @Column({ name: 'max_writes_per_hour', type: 'integer', nullable: true })
  maxWritesPerHour!: number | null;

  @Column({ name: 'allowed_cidrs', type: 'jsonb', default: () => "'[]'::jsonb" })
  allowedCidrs!: string[];

  @tsColumn('valid_from')
  validFrom!: string;

  @tsColumn('expires_at')
  expiresAt!: string;

  @Column({ name: 'approval_required', type: 'boolean', default: false })
  approvalRequired!: boolean;

  @Column({ name: 'status', type: 'text' })
  storedStatus!: GrantStoredStatus;

  @Column({ name: 'version', type: 'integer', default: 1 })
  version!: number;

  @Column({ name: 'previous_version_id', type: 'text', nullable: true })
  previousVersionId!: string | null;

  @Column({ name: 'created_by', type: 'text' })
  createdBy!: string;

  @tsColumn('created_at')
  createdAt!: string;

  @Column({ name: 'approved_by', type: 'text', nullable: true })
  approvedBy!: string | null;

  @tsColumn('approved_at', true)
  approvedAt!: string | null;

  @tsColumn('revoked_at', true)
  revokedAt!: string | null;

  @Column({ name: 'revoked_by', type: 'text', nullable: true })
  revokedBy!: string | null;

  @Column({ name: 'revocation_reason', type: 'text', nullable: true })
  revocationReason!: string | null;

  @tsColumn('last_used_at', true)
  lastUsedAt!: string | null;

  @Column({ name: 'usage_count', type: 'integer', default: 0 })
  usageCount!: number;

  /** Access reviews: last time a reviewer certified this grant should keep existing. */
  @tsColumn('last_reviewed_at', true)
  lastReviewedAt!: string | null;

  @Column({ name: 'last_reviewed_by', type: 'text', nullable: true })
  lastReviewedBy!: string | null;

  /** Acting for users: ALLOWED (may), REQUIRED (must), NOT_ALLOWED (must not carry a user token). */
  @Column({ name: 'on_behalf_of', type: 'text', default: 'ALLOWED' })
  onBehalfOf!: OnBehalfOfMode;

  /** The acting user must be in one of these groups (empty: any verified user). */
  @Column({ name: 'allowed_user_groups', type: 'jsonb', default: () => "'[]'::jsonb" })
  allowedUserGroups!: string[];
}
