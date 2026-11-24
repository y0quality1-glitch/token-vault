import { BaseEntity, Column, Entity, PrimaryColumn } from 'typeorm';
import type { Environment, SecretCategory, SecretPayload, SecretRotationStrategy, SecretStatus } from '@token-vault/shared';
import { tsColumn } from './columns';

/**
 * Table `secrets` (Secret Management, spec 4.9.5): a secret's metadata. The value lives only
 * on the customer webhook (`webhook_id`), one encrypted record per version; this table never
 * holds a value. See migration 1795000000000-Secrets for constraints and indexes.
 */
@Entity('secrets')
export class SecretEntity extends BaseEntity {
  @PrimaryColumn({ name: 'id', type: 'text' })
  id!: string;

  @Column({ name: 'organization_id', type: 'text' })
  organizationId!: string;

  @Column({ name: 'name', type: 'text' })
  name!: string;

  @Column({ name: 'description', type: 'text', default: '' })
  description!: string;

  @Column({ name: 'type_key', type: 'text' })
  typeKey!: string;

  @Column({ name: 'category', type: 'text' })
  category!: SecretCategory;

  @Column({ name: 'project', type: 'text', default: 'default' })
  project!: string;

  @Column({ name: 'workspace', type: 'text', default: 'default' })
  workspace!: string;

  @Column({ name: 'environment', type: 'text' })
  environment!: Environment;

  @Column({ name: 'tags', type: 'jsonb', default: () => "'[]'::jsonb" })
  tags!: string[];

  @Column({ name: 'metadata', type: 'jsonb', default: () => "'{}'::jsonb" })
  metadata!: SecretPayload;

  @Column({ name: 'status', type: 'text' })
  status!: SecretStatus;

  @Column({ name: 'active_version', type: 'integer', nullable: true })
  activeVersion!: number | null;

  @Column({ name: 'webhook_id', type: 'text' })
  webhookId!: string;

  @Column({ name: 'integration_id', type: 'text', nullable: true })
  integrationId!: string | null;

  @tsColumn('expires_at', true)
  expiresAt!: string | null;

  @Column({ name: 'rotation_enabled', type: 'boolean', default: false })
  rotationEnabled!: boolean;

  @Column({ name: 'rotation_interval_days', type: 'integer', nullable: true })
  rotationIntervalDays!: number | null;

  @tsColumn('next_rotation_at', true)
  nextRotationAt!: string | null;

  /** manual: people store the new value when asked; generated: the webhook creates it (spec 4.9.11). */
  @Column({ name: 'rotation_strategy', type: 'text', default: 'manual' })
  rotationStrategy!: SecretRotationStrategy;

  /** Hours the replaced version stays usable after a rotation. */
  @Column({ name: 'rotation_grace_hours', type: 'integer', default: 24 })
  rotationGraceHours!: number;

  @tsColumn('last_rotated_at', true)
  lastRotatedAt!: string | null;

  /** Provider health (spec 4.9.16): the last connection check by the webhook, for types it can reach. */
  @Column({ name: 'provider_status', type: 'text', nullable: true })
  providerStatus!: 'OK' | 'FAILING' | null;

  @tsColumn('provider_checked_at', true)
  providerCheckedAt!: string | null;

  @Column({ name: 'provider_error', type: 'text', nullable: true })
  providerError!: string | null;

  @tsColumn('last_retrieved_at', true)
  lastRetrievedAt!: string | null;

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

  @tsColumn('deleted_at', true)
  deletedAt!: string | null;
}
