import { BaseEntity, Column, Entity, PrimaryColumn } from 'typeorm';
import { tsColumn } from './columns';

/** Table `users` (see the baseline migration for constraints, indexes and triggers). */
@Entity('users')
export class UserEntity extends BaseEntity {
  @PrimaryColumn({ name: 'id', type: 'text' })
  id!: string;

  @Column({ name: 'email', type: 'text', unique: true })
  email!: string;

  @Column({ name: 'password_hash', type: 'text' })
  passwordHash!: string;

  @Column({ name: 'full_name', type: 'text' })
  fullName!: string;

  @Column({ name: 'status', type: 'text' })
  status!: 'ACTIVE' | 'DISABLED';

  @tsColumn('created_at')
  createdAt!: string;
}
