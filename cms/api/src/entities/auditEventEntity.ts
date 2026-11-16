import { BaseEntity, Column, Entity, PrimaryGeneratedColumn } from 'typeorm';
import { tsColumn } from './y0Entity';

/** The CMS audit log. Append-only: UPDATE and DELETE are rejected by a database trigger. */
@Entity('cms_audit_events')
export class AuditEventEntity extends BaseEntity {
  /** bigserial: the driver returns it as a string (see AuditService). */
  @PrimaryGeneratedColumn('increment', { type: 'bigint' })
  id!: string;

  @tsColumn('at')
  at!: string;

  @Column({ name: 'actor_id', type: 'text' })
  actor_id!: string;

  @Column({ name: 'actor_name', type: 'text' })
  actor_name!: string;

  @Column({ type: 'text' })
  action!: string;

  @Column({ name: 'application_key', type: 'text', nullable: true })
  application_key!: string | null;

  @Column({ type: 'integer', nullable: true })
  version!: number | null;

  @Column({ type: 'jsonb' })
  details!: Record<string, unknown>;
}
