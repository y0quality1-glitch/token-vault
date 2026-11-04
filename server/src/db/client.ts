import { resolve } from 'node:path';
import pg from 'pg';
import { drizzle } from 'drizzle-orm/node-postgres';
import { migrate } from 'drizzle-orm/node-postgres/migrator';
import { config } from '../config';
import * as schema from './schema';

export const pool = new pg.Pool({ connectionString: config.databaseUrl, max: config.dbPoolMax });
pool.on('error', (err) => console.error('[api] idle database client error:', err.message));

export const db = drizzle(pool, { schema });

export type Db = typeof db;
export type Tx = Parameters<Parameters<Db['transaction']>[0]>[0];
/** Repositories accept either the pool-backed client or an open transaction. */
export type Executor = Db | Tx;

export function transaction<T>(fn: (tx: Tx) => Promise<T>): Promise<T> {
  return db.transaction(fn);
}

export async function runMigrations() {
  await migrate(db, { migrationsFolder: resolve(import.meta.dirname, '../../drizzle') });
}

export async function closeDatabase() {
  await pool.end();
}
