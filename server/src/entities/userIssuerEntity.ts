import { BaseEntity, Column, Entity, PrimaryColumn } from 'typeorm';
import { tsColumn } from './columns';

/** Table `user_issuers` (see the baseline migration for constraints, indexes and triggers). */
@Entity('user_issuers')
export class UserIssuerEntity extends BaseEntity {
  @PrimaryColumn({ name: 'id', type: 'text' })
  id!: string;

  @Column({ name: 'organization_id', type: 'text' })
  organizationId!: string;

  @Column({ name: 'name', type: 'text' })
  name!: string;

  @Column({ name: 'issuer', type: 'text' })
  issuer!: string;

  @Column({ name: 'audience', type: 'text' })
  audience!: string;

  @Column({ name: 'public_key', type: 'text' })
  publicKey!: string;

  @Column({ name: 'key_fingerprint', type: 'text' })
  keyFingerprint!: string;

  @Column({ name: 'groups_claim', type: 'text', default: 'groups' })
  groupsClaim!: string;

  @Column({ name: 'max_token_lifetime_seconds', type: 'integer', default: 3600 })
  maxTokenLifetimeSeconds!: number;

  @Column({ name: 'enabled', type: 'boolean', default: true })
  enabled!: boolean;

  @tsColumn('created_at')
  createdAt!: string;

  @tsColumn('updated_at')
  updatedAt!: string;

  @tsColumn('last_used_at', true)
  lastUsedAt!: string | null;
}
