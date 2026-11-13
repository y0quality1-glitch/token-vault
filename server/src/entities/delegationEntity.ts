import { BaseEntity, Column, Entity, PrimaryColumn } from 'typeorm';
import type { ActingUser } from '@token-vault/shared';
import { tsColumn } from './columns';

/** Table `delegations` (see the baseline migration for constraints, indexes and triggers). */
@Entity('delegations')
export class DelegationEntity extends BaseEntity {
  @PrimaryColumn({ name: 'id', type: 'text' })
  id!: string;

  @Column({ name: 'organization_id', type: 'text' })
  organizationId!: string;

  @Column({ name: 'agent_id', type: 'text' })
  agentId!: string;

  @Column({ name: 'grant_id', type: 'text' })
  grantId!: string;

  @Column({ name: 'parent_delegation_id', type: 'text', nullable: true })
  parentDelegationId!: string | null;

  @Column({ name: 'depth', type: 'integer' })
  depth!: number;

  @Column({ name: 'label', type: 'text' })
  label!: string;

  @Column({ name: 'operations', type: 'jsonb' })
  operations!: string[];

  @Column({ name: 'resources', type: 'jsonb', default: () => "'[]'::jsonb" })
  resources!: string[];

  @Column({ name: 'max_requests', type: 'integer', nullable: true })
  maxRequests!: number | null;

  @Column({ name: 'on_behalf_of', type: 'jsonb', nullable: true })
  onBehalfOf!: ActingUser | null;

  @Column({ name: 'key_id', type: 'text', unique: true })
  keyId!: string;

  @Column({ name: 'credential_hash', type: 'text' })
  credentialHash!: string;

  @tsColumn('created_at')
  createdAt!: string;

  @tsColumn('expires_at')
  expiresAt!: string;

  @tsColumn('revoked_at', true)
  revokedAt!: string | null;

  @Column({ name: 'revoked_by', type: 'text', nullable: true })
  revokedBy!: string | null;

  @Column({ name: 'revocation_reason', type: 'text', nullable: true })
  revocationReason!: string | null;

  @tsColumn('last_used_at', true)
  lastUsedAt!: string | null;
}
