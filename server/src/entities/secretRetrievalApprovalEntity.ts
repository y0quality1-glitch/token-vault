import { BaseEntity, Column, Entity, PrimaryColumn } from 'typeorm';
import type { SecretApprovalStatus } from '@token-vault/shared';
import { tsColumn } from './columns';

/**
 * Table `secret_retrieval_approvals`: a retrieval held because its grant requires approval
 * (spec 4.9.9). An approval covers this agent, secret, version and field set, once, before
 * `expires_at`; the agent's owner cannot approve it.
 */
@Entity('secret_retrieval_approvals')
export class SecretRetrievalApprovalEntity extends BaseEntity {
  @PrimaryColumn({ name: 'id', type: 'text' })
  id!: string;

  @Column({ name: 'organization_id', type: 'text' })
  organizationId!: string;

  @Column({ name: 'grant_id', type: 'text' })
  grantId!: string;

  @Column({ name: 'agent_id', type: 'text' })
  agentId!: string;

  @Column({ name: 'secret_id', type: 'text' })
  secretId!: string;

  @Column({ name: 'version', type: 'integer', nullable: true })
  version!: number | null;

  @Column({ name: 'fields', type: 'jsonb', default: () => "'[]'::jsonb" })
  fields!: string[];

  @Column({ name: 'reason', type: 'text', default: '' })
  reason!: string;

  @Column({ name: 'status', type: 'text' })
  status!: SecretApprovalStatus;

  @tsColumn('requested_at')
  requestedAt!: string;

  @tsColumn('expires_at')
  expiresAt!: string;

  @Column({ name: 'decided_by', type: 'text', nullable: true })
  decidedBy!: string | null;

  @Column({ name: 'decided_by_name', type: 'text', nullable: true })
  decidedByName!: string | null;

  @tsColumn('decided_at', true)
  decidedAt!: string | null;

  @Column({ name: 'note', type: 'text', default: '' })
  note!: string;

  @tsColumn('used_at', true)
  usedAt!: string | null;
}
