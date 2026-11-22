import { BaseEntity, Column, Entity, PrimaryColumn } from 'typeorm';
import type { Environment } from '@token-vault/shared';
import { tsColumn } from './columns';

/** Table `organizations` (see the baseline migration for constraints, indexes and triggers). */
@Entity('organizations')
export class OrganizationEntity extends BaseEntity {
  @PrimaryColumn({ name: 'id', type: 'text' })
  id!: string;

  @Column({ name: 'name', type: 'text' })
  name!: string;

  @Column({ name: 'slug', type: 'text', unique: true })
  slug!: string;

  @Column({ name: 'status', type: 'text' })
  status!: 'ACTIVE' | 'SUSPENDED';

  @Column({ name: 'environment', type: 'text' })
  environment!: Environment;

  @tsColumn('created_at')
  createdAt!: string;

  @tsColumn('updated_at')
  updatedAt!: string;

  /** Emergency stop: while set, every agent request in the organization is denied. */
  @tsColumn('emergency_stopped_at', true)
  emergencyStoppedAt!: string | null;

  @Column({ name: 'emergency_stopped_by', type: 'text', nullable: true })
  emergencyStoppedBy!: string | null;

  @Column({ name: 'emergency_stop_reason', type: 'text', nullable: true })
  emergencyStopReason!: string | null;
}
