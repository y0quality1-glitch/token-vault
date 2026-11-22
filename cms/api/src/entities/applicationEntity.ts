import { Column, Entity } from 'typeorm';
import type { CatalogKind } from '@token-vault/shared';
import { Y0Entity, tsColumn } from './y0Entity';

/**
 * A catalog entry: an application (provider definition) or a secret type. Both share the
 * key space and the draft → review → sign → publish workflow. Archiving is the soft delete.
 */
@Entity('applications')
export class ApplicationEntity extends Y0Entity {
  @Column({ type: 'text', unique: true })
  key!: string;

  @Column({ type: 'text', default: 'provider' })
  kind!: CatalogKind;

  @Column({ type: 'text' })
  name!: string;

  @Column({ type: 'text', default: '' })
  description!: string;

  @Column({ name: 'created_by', type: 'text' })
  created_by!: string;

  @tsColumn('updated_at')
  updated_at!: string;

  @tsColumn('archived_at', true)
  archived_at!: string | null;
}
