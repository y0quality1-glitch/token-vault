import { BaseEntity, Column, Entity, PrimaryColumn } from 'typeorm';
import type { ActingUser, DelegationRef } from '@token-vault/shared';
import { tsColumn } from './columns';

/** Table `operation_approvals` (see the baseline migration for constraints, indexes and triggers). */
@Entity('operation_approvals')
export class OperationApprovalEntity extends BaseEntity {
  @PrimaryColumn({ name: 'id', type: 'text' })
  id!: string;

  @Column({ name: 'organization_id', type: 'text' })
  organizationId!: string;

  @Column({ name: 'agent_id', type: 'text' })
  agentId!: string;

  @Column({ name: 'integration_id', type: 'text' })
  integrationId!: string;

  /** The policy that required approval (name kept in case the policy is edited or deleted). */
  @Column({ name: 'policy_id', type: 'text' })
  policyId!: string;

  @Column({ name: 'policy_name', type: 'text' })
  policyName!: string;

  @Column({ name: 'operation', type: 'text' })
  operation!: string;

  @Column({ name: 'resource', type: 'jsonb' })
  resource!: Record<string, string>;

  /** Exactly what the agent will send: the approver sees this. Untrusted text. */
  @Column({ name: 'input', type: 'jsonb' })
  input!: Record<string, unknown>;

  /** sha256 of the canonical request; a request with this approval must match it. */
  @Column({ name: 'request_digest', type: 'text' })
  requestDigest!: string;

  @Column({ name: 'status', type: 'text' })
  status!: 'PENDING' | 'APPROVED' | 'REJECTED' | 'EXECUTED';

  /** The access request (audit record) that asked for approval. */
  @Column({ name: 'requested_by_request_id', type: 'text' })
  requestedByRequestId!: string;

  @tsColumn('created_at')
  createdAt!: string;

  /** PENDING: lapses at this time. APPROVED: must be executed by this time. */
  @tsColumn('expires_at')
  expiresAt!: string;

  @Column({ name: 'decided_by', type: 'text', nullable: true })
  decidedBy!: string | null;

  @tsColumn('decided_at', true)
  decidedAt!: string | null;

  @Column({ name: 'decision_note', type: 'text', nullable: true })
  decisionNote!: string | null;

  /** The user the agent asked to act for: the approval covers only requests for this user. */
  @Column({ name: 'on_behalf_of', type: 'jsonb', nullable: true })
  onBehalfOf!: ActingUser | null;

  /** The sub-agent delegation that asked (null: the agent itself); part of the approved request. */
  @Column({ name: 'delegation', type: 'jsonb', nullable: true })
  delegation!: DelegationRef | null;

  /** Where the approval request was posted (Slack), so the message can be updated once decided. */
  @Column({ name: 'notifications', type: 'jsonb', nullable: true })
  notifications!: { slack?: { channel: string; ts: string } } | null;

  @tsColumn('executed_at', true)
  executedAt!: string | null;

  @Column({ name: 'executed_request_id', type: 'text', nullable: true })
  executedRequestId!: string | null;
}
