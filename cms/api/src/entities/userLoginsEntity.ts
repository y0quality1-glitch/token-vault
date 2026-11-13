import { BaseEntity, Column, Entity, PrimaryColumn } from 'typeorm';
import { tsColumn } from './y0Entity';

/**
 * Sign-in sessions (template: user_logins). Only the SHA-256 of the session token is stored
 * (template fix B-08), so a database read does not yield usable tokens. Logging out deletes
 * the row, which ends the session even though the JWT has not expired.
 */
@Entity('cms_sessions')
export class UserLoginsEntity extends BaseEntity {
  @PrimaryColumn({ name: 'token_hash', type: 'text' })
  token_hash!: string;

  @Column({ name: 'user_id', type: 'text' })
  user_id!: string;

  @tsColumn('expires_at')
  expires_at!: string;

  @tsColumn('created_at')
  created_at!: string;
}
