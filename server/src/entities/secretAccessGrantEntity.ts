import { BaseEntity, Column, Entity, PrimaryColumn } from 'typeorm';
import type { SecretGrantVersions, SecretSelector } from '@token-vault/shared';
import { tsColumn } from './columns';

/**
 * Table `secret_access_grants` (spec 4.9.9, 4.9.15): lets one agent (a service account or an AI
 * agent) retrieve one secret, or every secret matching a selector. Default deny: without an
 * active, valid grant an agent reads nothing.
 */
@Entity('secret_access_grants')
export class SecretAccessGrantEntity extends BaseEntity {
  @PrimaryColumn({ name: 'id', type: 'text' })
  id!: string;

  @Column({ name: 'organization_id', type: 'text' })
  organizationId!: string;

  @Column({ name: 'agent_id', type: 'text' })
  agentId!: string;

  @Column({ name: 'secret_id', type: 'text', nullable: true })
  secretId!: string | null;

  @Column({ name: 'selector', type: 'jsonb', nullable: true })
  selector!: SecretSelector | null;

  @Column({ name: 'description', type: 'text', default: '' })
  description!: string;

  @Column({ name: 'fields', type: 'jsonb', default: () => "'[]'::jsonb" })
  fields!: string[];

  @Column({ name: 'versions', type: 'text', default: 'ACTIVE' })
  versions!: SecretGrantVersions;

  @Column({ name: 'allowed_cidrs', type: 'jsonb', default: () => "'[]'::jsonb" })
  allowedCidrs!: string[];

  @Column({ name: 'require_approval', type: 'boolean', default: false })
  requireApproval!: boolean;

  @tsColumn('valid_from')
  validFrom!: string;

  @tsColumn('expires_at', true)
  expiresAt!: string | null;

  @Column({ name: 'status', type: 'text' })
  status!: 'ACTIVE' | 'REVOKED';

  @Column({ name: 'created_by', type: 'text' })
  createdBy!: string;

  @Column({ name: 'created_by_name', type: 'text' })
  createdByName!: string;

  @tsColumn('created_at')
  createdAt!: string;

  @tsColumn('revoked_at', true)
  revokedAt!: string | null;

  @Column({ name: 'revoked_by', type: 'text', nullable: true })
  revokedBy!: string | null;

  @Column({ name: 'revocation_reason', type: 'text', nullable: true })
  revocationReason!: string | null;

  @tsColumn('last_used_at', true)
  lastUsedAt!: string | null;

  @Column({ name: 'use_count', type: 'integer', default: 0 })
  useCount!: number;
}
