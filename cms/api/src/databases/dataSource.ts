import { DataSource } from 'typeorm';
import { DB_POOL_MAX, DB_READ_URL, DB_SSL, DB_URL } from '../config';
import { ApplicationEntity } from '../entities/applicationEntity';
import { AuditEventEntity } from '../entities/auditEventEntity';
import { SigningKeyEntity } from '../entities/signingKeyEntity';
import { UserEntity } from '../entities/userEntity';
import { UserLoginsEntity } from '../entities/userLoginsEntity';
import { VersionEntity } from '../entities/versionEntity';
import { VersionSignatureEntity } from '../entities/versionSignatureEntity';
import { Baseline1730000000000 } from './migrations/1730000000000-Baseline';

/** Every entity, listed explicitly (template fix B-04: a missing entity fails at start-up, not per request). */
export const ENTITIES = [UserEntity, UserLoginsEntity, ApplicationEntity, VersionEntity, AuditEventEntity, SigningKeyEntity, VersionSignatureEntity];

/**
 * TypeORM DataSource (template: databases/dataSource.ts). Writes and transactions use
 * CMS_DATABASE_URL; with CMS_DATABASE_READ_URL set, plain reads go to that replica. TLS
 * validates certificates when enabled (template fix B-19).
 */
export const getPostgresConnection = () => {
  const ssl = DB_SSL ? { rejectUnauthorized: true } : false;
  return new DataSource({
    name: 'default',
    type: 'postgres',
    ...(DB_READ_URL ? { replication: { master: { url: DB_URL }, slaves: [{ url: DB_READ_URL }] } } : { url: DB_URL }),
    ssl,
    entities: ENTITIES,
    migrations: [Baseline1730000000000],
    migrationsTableName: 'cms_migrations',
    synchronize: false,
    logging: false,
    extra: { max: DB_POOL_MAX, idleTimeoutMillis: 30_000, connectionTimeoutMillis: 10_000, keepAlive: true },
  });
};
