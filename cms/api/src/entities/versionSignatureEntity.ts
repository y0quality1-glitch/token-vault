import { BaseEntity, Column, Entity, PrimaryColumn } from 'typeorm';
import { tsColumn } from './y0Entity';

/**
 * Signatures of published versions, one per key (append-only: database trigger). When the CMS
 * starts with a new key it signs every published version again, so consumers pinning either
 * the old or the new key keep accepting the catalog during a rotation.
 */
@Entity('cms_version_signatures')
export class VersionSignatureEntity extends BaseEntity {
  @PrimaryColumn({ name: 'version_id', type: 'text' })
  version_id!: string;

  @PrimaryColumn({ name: 'key_id', type: 'text' })
  key_id!: string;

  @Column({ type: 'text' })
  signature!: string;

  @tsColumn('signed_at')
  signed_at!: string;
}
