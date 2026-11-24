import { BaseEntity, Column, Entity, PrimaryColumn } from 'typeorm';
import type { SecretRotationJobStatus, SecretRotationStrategy, SecretRotationTrigger } from '@token-vault/shared';
import { tsColumn } from './columns';

/**
 * Table `rotation_jobs` (spec 4.9.11): one rotation of one secret, scheduled, manual or because
 * the secret is about to expire; its attempts, outcome and failure. At most one is open per
 * secret (PENDING, RUNNING or WAITING_FOR_VALUE).
 */
@Entity('rotation_jobs')
export class RotationJobEntity extends BaseEntity {
  @PrimaryColumn({ name: 'id', type: 'text' })
  id!: string;

  @Column({ name: 'organization_id', type: 'text' })
  organizationId!: string;

  @Column({ name: 'secret_id', type: 'text' })
  secretId!: string;

  @Column({ name: 'trigger', type: 'text' })
  trigger!: SecretRotationTrigger;

  @Column({ name: 'strategy', type: 'text' })
  strategy!: SecretRotationStrategy;

  @Column({ name: 'status', type: 'text' })
  status!: SecretRotationJobStatus;

  @Column({ name: 'attempts', type: 'integer', default: 0 })
  attempts!: number;

  @Column({ name: 'from_version', type: 'integer', nullable: true })
  fromVersion!: number | null;

  @Column({ name: 'to_version', type: 'integer', nullable: true })
  toVersion!: number | null;

  @Column({ name: 'error_code', type: 'text', nullable: true })
  errorCode!: string | null;

  @Column({ name: 'error_message', type: 'text', nullable: true })
  errorMessage!: string | null;

  @Column({ name: 'requested_by', type: 'text', nullable: true })
  requestedBy!: string | null;

  @Column({ name: 'requested_by_name', type: 'text', nullable: true })
  requestedByName!: string | null;

  @tsColumn('scheduled_for')
  scheduledFor!: string;

  @tsColumn('started_at', true)
  startedAt!: string | null;

  @tsColumn('finished_at', true)
  finishedAt!: string | null;

  @tsColumn('next_attempt_at', true)
  nextAttemptAt!: string | null;

  @tsColumn('created_at')
  createdAt!: string;
}
