import { BaseEntity, Column, Entity, PrimaryColumn } from 'typeorm';
import { tsColumn } from './columns';

/** Table `sessions` (see the baseline migration for constraints, indexes and triggers). */
@Entity('sessions')
export class UserLoginsEntity extends BaseEntity {
  @PrimaryColumn({ name: 'token_hash', type: 'text' })
  tokenHash!: string;

  @Column({ name: 'user_id', type: 'text' })
  userId!: string;

  @Column({ name: 'organization_id', type: 'text', nullable: true })
  organizationId!: string | null;

  @tsColumn('created_at')
  createdAt!: string;

  @tsColumn('expires_at')
  expiresAt!: string;
}
