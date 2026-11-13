import { BaseEntity, Column, Entity, PrimaryColumn } from 'typeorm';
import type { ActingUser, Decision, DecisionCheck, DelegationRef, ExecutionStatus, FilteringSummary, MatchedRule, TraceRef } from '@token-vault/shared';
import { tsColumn, bigintNumber } from './columns';

/** Table `access_requests` (see the baseline migration for constraints, indexes and triggers). */
@Entity('access_requests')
export class AccessRequestEntity extends BaseEntity {
  @PrimaryColumn({ name: 'id', type: 'text' })
  id!: string;

  @Column({ name: 'organization_id', type: 'text' })
  organizationId!: string;

  @Column({ name: 'agent_id', type: 'text', nullable: true })
  agentId!: string | null;

  @Column({ name: 'agent_name', type: 'text' })
  agentName!: string;

  @Column({ name: 'integration_id', type: 'text', nullable: true })
  integrationId!: string | null;

  @Column({ name: 'integration_name', type: 'text' })
  integrationName!: string;

  @Column({ name: 'grant_id', type: 'text', nullable: true })
  grantId!: string | null;

  @Column({ name: 'grant_name', type: 'text', nullable: true })
  grantName!: string | null;

  @Column({ name: 'operation', type: 'text' })
  operation!: string;

  @Column({ name: 'resource', type: 'jsonb' })
  resource!: Record<string, string>;

  @Column({ name: 'decision', type: 'text' })
  decision!: Decision;

  @Column({ name: 'decision_code', type: 'text' })
  decisionCode!: string;

  @Column({ name: 'decision_reason', type: 'text' })
  decisionReason!: string;

  @Column({ name: 'matched_rule', type: 'jsonb', nullable: true })
  matchedRule!: MatchedRule | null;

  @Column({ name: 'execution_status', type: 'text' })
  executionStatus!: ExecutionStatus;

  @Column({ name: 'upstream_status_code', type: 'integer', nullable: true })
  upstreamStatusCode!: number | null;

  @Column({ name: 'webhook_status', type: 'text' })
  webhookStatus!: string;

  @Column({ name: 'duration_ms', type: 'integer' })
  durationMs!: number;

  @Column({ name: 'correlation_id', type: 'text' })
  correlationId!: string;

  @Column({ name: 'source_ip', type: 'text' })
  sourceIp!: string;

  @Column({ name: 'source', type: 'text' })
  source!: 'agent-api' | 'playground';

  @Column({ name: 'idempotency_key', type: 'text', nullable: true })
  idempotencyKey!: string | null;

  @Column({ name: 'checks', type: 'jsonb' })
  checks!: DecisionCheck[];

  @tsColumn('created_at')
  createdAt!: string;

  /** The user the agent acted for (null: for itself). Left out of the chained content when null (see audit/chain.ts). */
  @Column({ name: 'on_behalf_of', type: 'jsonb', nullable: true })
  onBehalfOf!: ActingUser | null;

  /** The sub-agent delegation the request came through (null: the agent itself). Left out of the chained content when null. */
  @Column({ name: 'delegation', type: 'jsonb', nullable: true })
  delegation!: DelegationRef | null;

  /** What response filtering did (counts only). Left out of the chained content when null. */
  @Column({ name: 'filtering', type: 'jsonb', nullable: true })
  filtering!: FilteringSummary | null;

  /** Agent session and W3C trace context (null: none sent). Left out of the chained content when null. */
  @Column({ name: 'trace', type: 'jsonb', nullable: true })
  trace!: TraceRef | null;

  // Tamper evidence (migration 0003): per-organization hash chain + HMAC with a key held outside the database.
  // NULL on rows written before chaining existed ("legacy").
  @Column({ name: 'seq', type: 'bigint', nullable: true, transformer: bigintNumber })
  seq!: number | null;

  @Column({ name: 'prev_hash', type: 'text', nullable: true })
  prevHash!: string | null;

  @Column({ name: 'hash', type: 'text', nullable: true })
  hash!: string | null;

  @Column({ name: 'mac', type: 'text', nullable: true })
  mac!: string | null;
}
