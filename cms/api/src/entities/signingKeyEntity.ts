import { BaseEntity, Column, Entity, PrimaryColumn } from 'typeorm';
import { tsColumn } from './y0Entity';

/** Every key the CMS has signed with (public part only; private keys never touch the database). */
@Entity('cms_signing_keys')
export class SigningKeyEntity extends BaseEntity {
  @PrimaryColumn({ name: 'key_id', type: 'text' })
  key_id!: string;

  @Column({ type: 'text' })
  algorithm!: string;

  /** Null for keys known only from signatures made before this table existed. */
  @Column({ name: 'public_key_pem', type: 'text', nullable: true })
  public_key_pem!: string | null;

  @tsColumn('first_used_at')
  first_used_at!: string;
}
