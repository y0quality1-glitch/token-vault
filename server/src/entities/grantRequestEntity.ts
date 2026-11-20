import { BaseEntity, Column, Entity, PrimaryColumn } from 'typeorm';
import { tsColumn } from './columns';

/** Table `grant_requests` (see the baseline migration for constraints, indexes and triggers). */
@Entity('grant_requests')
export class GrantRequestEntity extends BaseEntity {
  @PrimaryColumn({ name: 'id', type: 'text' })
  id!: string;

  @Column({ name: 'organization_id', type: 'text' })
  organizationId!: string;

  @Column({ name: 'agent_id', type: 'text' })
  agentId!: string;

  @Column({ name: 'integration_id', type: 'text' })
  integrationId!: string;

  @Column({ name: 'operations', type: 'jsonb' })
  operations!: string[];

  @Column({ name: 'repositories', type: 'jsonb', default: () => "'[]'::jsonb" })
  repositories!: string[];

  /** Written by the agent: untrusted text, shown to approvers as a quote. */
  @Column({ name: 'justification', type: 'text' })
  justification!: string;

  @Column({ name: 'requested_duration_minutes', type: 'integer' })
  requestedDurationMinutes!: number;

  /** The denied access request (audit record) that prompted this, if any. */
  @Column({ name: 'denied_request_id', type: 'text', nullable: true })
  deniedRequestId!: string | null;

  @Column({ name: 'status', type: 'text' })
  status!: 'PENDING' | 'APPROVED' | 'REJECTED';

  @tsColumn('created_at')
  createdAt!: string;

  /** A pending request lapses after this time. */
  @tsColumn('expires_at')
  expiresAt!: string;

  @Column({ name: 'decided_by', type: 'text', nullable: true })
  decidedBy!: string | null;

  @tsColumn('decided_at', true)
  decidedAt!: string | null;

  @Column({ name: 'decision_note', type: 'text', nullable: true })
  decisionNote!: string | null;

  @Column({ name: 'approved_duration_minutes', type: 'integer', nullable: true })
  approvedDurationMinutes!: number | null;

  /** The grant created on approval. */
  @Column({ name: 'grant_id', type: 'text', nullable: true })
  grantId!: string | null;
}
