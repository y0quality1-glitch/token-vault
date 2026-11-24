import { BaseEntity, Column, Entity, PrimaryColumn } from 'typeorm';
import type { SecretExportFile, SecretExportStatus, SecretLeaseStatus, SecretTypeDefinition } from '@token-vault/shared';
import { tsColumn } from './columns';

/**
 * Table `secret_leases` (spec 4.9.3 J): a short-lived credential issued from a dynamic secret to
 * an agent or a member. The credential itself is never stored here; `username` is the provider
 * identity (a role or session name) needed to lengthen or end it.
 */
@Entity('secret_leases')
export class SecretLeaseEntity extends BaseEntity {
  @PrimaryColumn({ name: 'id', type: 'text' })
  id!: string;

  @Column({ name: 'organization_id', type: 'text' })
  organizationId!: string;

  @Column({ name: 'secret_id', type: 'text' })
  secretId!: string;

  @Column({ name: 'holder_type', type: 'text' })
  holderType!: 'AGENT' | 'USER';

  @Column({ name: 'holder_id', type: 'text' })
  holderId!: string;

  @Column({ name: 'holder_name', type: 'text' })
  holderName!: string;

  @Column({ name: 'grant_id', type: 'text', nullable: true })
  grantId!: string | null;

  @Column({ name: 'username', type: 'text' })
  username!: string;

  @Column({ name: 'status', type: 'text' })
  status!: SecretLeaseStatus;

  @Column({ name: 'renewable', type: 'boolean', default: false })
  renewable!: boolean;

  @Column({ name: 'reason', type: 'text', default: '' })
  reason!: string;

  @tsColumn('created_at')
  createdAt!: string;

  @tsColumn('expires_at')
  expiresAt!: string;

  @tsColumn('max_expires_at')
  maxExpiresAt!: string;

  @tsColumn('renewed_at', true)
  renewedAt!: string | null;

  @Column({ name: 'renew_count', type: 'integer', default: 0 })
  renewCount!: number;

  @tsColumn('revoked_at', true)
  revokedAt!: string | null;

  @Column({ name: 'revoked_by', type: 'text', nullable: true })
  revokedBy!: string | null;

  @Column({ name: 'revocation_reason', type: 'text', nullable: true })
  revocationReason!: string | null;

  @Column({ name: 'last_error', type: 'text', nullable: true })
  lastError!: string | null;
}

/** Table `custom_secret_types` (spec 4.9.3 K): an organization's own secret types, validated by the same schema. */
@Entity('custom_secret_types')
export class CustomSecretTypeEntity extends BaseEntity {
  @PrimaryColumn({ name: 'id', type: 'text' })
  id!: string;

  @Column({ name: 'organization_id', type: 'text' })
  organizationId!: string;

  @Column({ name: 'key', type: 'text' })
  key!: string;

  @Column({ name: 'version', type: 'integer' })
  version!: number;

  @Column({ name: 'definition', type: 'jsonb' })
  definition!: SecretTypeDefinition;

  @Column({ name: 'digest', type: 'text' })
  digest!: string;

  @Column({ name: 'created_by', type: 'text' })
  createdBy!: string;

  @Column({ name: 'created_by_name', type: 'text' })
  createdByName!: string;

  @tsColumn('created_at')
  createdAt!: string;

  @Column({ name: 'updated_by', type: 'text' })
  updatedBy!: string;

  @Column({ name: 'updated_by_name', type: 'text' })
  updatedByName!: string;

  @tsColumn('updated_at')
  updatedAt!: string;

  @tsColumn('archived_at', true)
  archivedAt!: string | null;
}

/**
 * Table `secret_export_requests` (spec 4.9.14): an export asked for, approved by someone else,
 * prepared (encrypted with the requester's passphrase) and downloaded once through a short-lived link.
 */
@Entity('secret_export_requests')
export class SecretExportRequestEntity extends BaseEntity {
  @PrimaryColumn({ name: 'id', type: 'text' })
  id!: string;

  @Column({ name: 'organization_id', type: 'text' })
  organizationId!: string;

  @Column({ name: 'requested_by', type: 'text' })
  requestedBy!: string;

  @Column({ name: 'requested_by_name', type: 'text' })
  requestedByName!: string;

  @Column({ name: 'secret_ids', type: 'jsonb' })
  secretIds!: string[];

  @Column({ name: 'reason', type: 'text' })
  reason!: string;

  @Column({ name: 'status', type: 'text' })
  status!: SecretExportStatus;

  @tsColumn('created_at')
  createdAt!: string;

  @Column({ name: 'decided_by', type: 'text', nullable: true })
  decidedBy!: string | null;

  @Column({ name: 'decided_by_name', type: 'text', nullable: true })
  decidedByName!: string | null;

  @tsColumn('decided_at', true)
  decidedAt!: string | null;

  @Column({ name: 'note', type: 'text', default: '' })
  note!: string;

  @tsColumn('expires_at', true)
  expiresAt!: string | null;

  @Column({ name: 'file', type: 'jsonb', nullable: true })
  file!: SecretExportFile | null;

  @Column({ name: 'download_token_hash', type: 'text', nullable: true })
  downloadTokenHash!: string | null;

  @tsColumn('downloaded_at', true)
  downloadedAt!: string | null;
}
