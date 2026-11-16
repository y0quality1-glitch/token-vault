import { Column, Entity } from 'typeorm';
import { Y0Entity, tsColumn } from './y0Entity';

/** An application in the provider catalog. Archiving is its soft delete (archived_at). */
@Entity('applications')
export class ApplicationEntity extends Y0Entity {
  @Column({ type: 'text', unique: true })
  key!: string;

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
