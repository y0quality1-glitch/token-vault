import { BaseEntity, Column, Entity, PrimaryColumn } from 'typeorm';
import type { AccessMode, CredentialStatus, Environment, ProviderId } from '@token-vault/shared';
import { tsColumn } from './columns';

/** Table `integrations` (see the baseline migration for constraints, indexes and triggers). */
@Entity('integrations')
export class IntegrationEntity extends BaseEntity {
  @PrimaryColumn({ name: 'id', type: 'text' })
  id!: string;

  @Column({ name: 'organization_id', type: 'text' })
  organizationId!: string;

  @Column({ name: 'webhook_id', type: 'text' })
  webhookId!: string;

  @Column({ name: 'provider', type: 'text' })
  provider!: ProviderId;

  @Column({ name: 'display_name', type: 'text' })
  displayName!: string;

  @Column({ name: 'environment', type: 'text' })
  environment!: Environment;

  @Column({ name: 'account_label', type: 'text' })
  accountLabel!: string;

  @Column({ name: 'auth_type', type: 'text' })
  authType!: string;

  /** Opaque pointer into the customer webhook's encrypted store. */
  @Column({ name: 'credential_reference', type: 'text' })
  credentialReference!: string;

  @Column({ name: 'credential_status', type: 'text' })
  credentialStatus!: CredentialStatus;

  @Column({ name: 'masked_identifier', type: 'text', default: '' })
  maskedIdentifier!: string;

  @Column({ name: 'credential_fingerprint', type: 'text', default: '' })
  credentialFingerprint!: string;

  @Column({ name: 'allowed_resources', type: 'jsonb', default: () => "'[]'::jsonb" })
  allowedResources!: string[];

  @Column({ name: 'description', type: 'text', default: '' })
  description!: string;

  @Column({ name: 'created_by', type: 'text' })
  createdBy!: string;

  @tsColumn('created_at')
  createdAt!: string;

  @tsColumn('updated_at')
  updatedAt!: string;

  @tsColumn('last_validated_at', true)
  lastValidatedAt!: string | null;

  @tsColumn('rotated_at', true)
  rotatedAt!: string | null;

  /** Rotation reminder interval in days (null = none). Reminders only; nothing is blocked. */
  @Column({ name: 'rotation_interval_days', type: 'integer', nullable: true })
  rotationIntervalDays!: number | null;

  /** BROKERED (the webhook calls the application), DECISION_ONLY or SHORT_LIVED_CREDENTIAL (the caller does). */
  @Column({ name: 'access_mode', type: 'text', default: 'BROKERED' })
  accessMode!: AccessMode;

  /** Soft delete: grants and audit records keep referring to the integration. */
  @tsColumn('deleted_at', true)
  deletedAt!: string | null;
}
