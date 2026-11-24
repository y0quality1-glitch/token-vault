import { BaseEntity, Column, Entity, PrimaryColumn } from 'typeorm';
import type { SecretApprovalStatus, KeyOperation } from '@token-vault/shared';
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

  /** What is held: a retrieval, a lease, or a key operation (spec 4.9.3 E). */
  @Column({ name: 'operation', type: 'text', default: 'retrieve' })
  operation!: 'retrieve' | 'lease' | KeyOperation;

  /** Key operations: SHA-256 of the input, so the approval covers that exact input. */
  @Column({ name: 'input_digest', type: 'text', nullable: true })
  inputDigest!: string | null;
}
