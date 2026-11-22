import { BaseEntity, Column, Entity, PrimaryColumn } from 'typeorm';
import type { AuditActorType, AuditOutcome } from '@token-vault/shared';
import { tsColumn, bigintNumber } from './columns';

/** Table `audit_events` (see the baseline migration for constraints, indexes and triggers). */
@Entity('audit_events')
export class AuditEventEntity extends BaseEntity {
  @PrimaryColumn({ name: 'id', type: 'text' })
  id!: string;

  @Column({ name: 'organization_id', type: 'text' })
  organizationId!: string;

  @Column({ name: 'actor_type', type: 'text' })
  actorType!: AuditActorType;

  @Column({ name: 'actor_id', type: 'text' })
  actorId!: string;

  @Column({ name: 'actor_name', type: 'text' })
  actorName!: string;

  @Column({ name: 'event_type', type: 'text' })
  eventType!: string;

  @Column({ name: 'target_type', type: 'text' })
  targetType!: string;

  @Column({ name: 'target_id', type: 'text' })
  targetId!: string;

  @Column({ name: 'target_name', type: 'text' })
  targetName!: string;

  @Column({ name: 'outcome', type: 'text' })
  outcome!: AuditOutcome;

  @Column({ name: 'severity', type: 'text' })
  severity!: 'info' | 'warning' | 'critical';

  @Column({ name: 'metadata', type: 'jsonb' })
  metadata!: Record<string, unknown>;

  @Column({ name: 'correlation_id', type: 'text' })
  correlationId!: string;

  @tsColumn('created_at')
  createdAt!: string;

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
