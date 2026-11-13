import { BaseEntity, Column, Entity, PrimaryColumn } from 'typeorm';
import type { PolicyConditions, PolicyEffect, ResponseFilter } from '@token-vault/shared';
import { tsColumn } from './columns';

/** Table `policies` (see the baseline migration for constraints, indexes and triggers). */
@Entity('policies')
export class PolicyEntity extends BaseEntity {
  @PrimaryColumn({ name: 'id', type: 'text' })
  id!: string;

  @Column({ name: 'organization_id', type: 'text' })
  organizationId!: string;

  @Column({ name: 'name', type: 'text' })
  name!: string;

  @Column({ name: 'description', type: 'text', default: '' })
  description!: string;

  @Column({ name: 'effect', type: 'text' })
  effect!: PolicyEffect;

  @Column({ name: 'conditions', type: 'jsonb' })
  conditions!: PolicyConditions;

  /** FILTER policies only: what to mask, remove or check in results. */
  @Column({ name: 'response_filter', type: 'jsonb', nullable: true })
  responseFilter!: ResponseFilter | null;

  @Column({ name: 'priority', type: 'integer' })
  priority!: number;

  @Column({ name: 'enabled', type: 'boolean' })
  enabled!: boolean;

  @tsColumn('created_at')
  createdAt!: string;

  @tsColumn('updated_at')
  updatedAt!: string;
}
