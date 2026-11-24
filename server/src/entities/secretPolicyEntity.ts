import { BaseEntity, Column, Entity, PrimaryColumn } from 'typeorm';
import type { SecretPolicyScope } from '@token-vault/shared';
import { tsColumn } from './columns';

/**
 * Table `secret_policies` (spec 4.9.12, 4.9.8): expiry warning, default expiry and version
 * retention for an organization, a project or a workspace. The most specific level that sets
 * a value wins.
 */
@Entity('secret_policies')
export class SecretPolicyEntity extends BaseEntity {
  @PrimaryColumn({ name: 'id', type: 'text' })
  id!: string;

  @Column({ name: 'organization_id', type: 'text' })
  organizationId!: string;

  @Column({ name: 'scope', type: 'text' })
  scope!: SecretPolicyScope;

  @Column({ name: 'project', type: 'text', nullable: true })
  project!: string | null;

  @Column({ name: 'workspace', type: 'text', nullable: true })
  workspace!: string | null;

  @Column({ name: 'expiry_warning_days', type: 'integer', nullable: true })
  expiryWarningDays!: number | null;

  @Column({ name: 'default_expires_in_days', type: 'integer', nullable: true })
  defaultExpiresInDays!: number | null;

  @Column({ name: 'keep_versions', type: 'integer', nullable: true })
  keepVersions!: number | null;

  @Column({ name: 'keep_days', type: 'integer', nullable: true })
  keepDays!: number | null;

  @Column({ name: 'updated_by', type: 'text' })
  updatedBy!: string;

  @Column({ name: 'updated_by_name', type: 'text' })
  updatedByName!: string;

  @tsColumn('updated_at')
  updatedAt!: string;
}
