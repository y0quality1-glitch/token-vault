import { BaseEntity, Column, Entity, PrimaryColumn } from 'typeorm';
import type { Role } from '@token-vault/shared';
import { tsColumn } from './columns';

/** Table `organization_members` (see the baseline migration for constraints, indexes and triggers). */
@Entity('organization_members')
export class OrganizationMemberEntity extends BaseEntity {
  @PrimaryColumn({ name: 'id', type: 'text' })
  id!: string;

  @Column({ name: 'organization_id', type: 'text' })
  organizationId!: string;

  @Column({ name: 'user_id', type: 'text' })
  userId!: string;

  @Column({ name: 'role', type: 'text' })
  role!: Role;

  @tsColumn('created_at')
  createdAt!: string;
}
