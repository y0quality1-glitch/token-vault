import { DataSource } from 'typeorm';
import { config } from '../config';
import { ENTITIES } from '../entities';
import { Baseline1730000000000 } from './migrations/1730000000000-Baseline';

/**
 * TypeORM DataSource (template: databases/dataSource.ts). Every entity and migration is listed
 * explicitly (template fix B-04), so the esbuild bundle needs no file globbing. With
 * DATABASE_READ_URL set, plain reads go to that replica; writes and transactions to DATABASE_URL.
 * TLS validates certificates when DATABASE_SSL=require (template fix B-19).
 */
export const getPostgresConnection = () =>
  new DataSource({
    name: 'default',
    type: 'postgres',
    ...(config.databaseReadUrl ? { replication: { master: { url: config.databaseUrl }, slaves: [{ url: config.databaseReadUrl }] } } : { url: config.databaseUrl }),
    ssl: config.databaseSsl ? { rejectUnauthorized: true } : false,
    entities: ENTITIES,
    migrations: [Baseline1730000000000],
    migrationsTableName: 'tv_migrations',
    synchronize: false,
    logging: false,
    extra: { max: config.dbPoolMax, idleTimeoutMillis: 30_000, connectionTimeoutMillis: 10_000, keepAlive: true },
  });
