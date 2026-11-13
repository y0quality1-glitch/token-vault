import { Column, Entity } from 'typeorm';
import type { CmsRole } from '@token-vault/shared';
import { Y0Entity } from './y0Entity';

@Entity('cms_users')
export class UserEntity extends Y0Entity {
  @Column({ type: 'text', unique: true })
  email!: string;

  @Column({ name: 'full_name', type: 'text' })
  full_name!: string;

  @Column({ type: 'text' })
  role!: CmsRole;

  @Column({ name: 'password_hash', type: 'text' })
  password_hash!: string;
}
