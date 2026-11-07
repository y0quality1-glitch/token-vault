import { resolve } from 'node:path';
import pg from 'pg';
import { drizzle } from 'drizzle-orm/node-postgres';
import { migrate } from 'drizzle-orm/node-postgres/migrator';
import { config } from '../config';
import * as schema from './schema';

export const pool = new pg.Pool({ connectionString: config.databaseUrl, max: config.dbPoolMax });
pool.on('error', (err) => console.error('[cms] idle database client error:', describeError(err)));

export const db = drizzle(pool, { schema });
export type Db = typeof db;
export type Tx = Parameters<Parameters<Db['transaction']>[0]>[0];
export type Executor = Db | Tx;

export const transaction = <T>(fn: (tx: Tx) => Promise<T>) => db.transaction(fn);

export async function runMigrations() {
  await migrate(db, { migrationsFolder: process.env.MIGRATIONS_DIR ?? resolve(import.meta.dirname, '../../drizzle') /* container images set MIGRATIONS_DIR */ });
}

export async function closeDatabase() {
  await pool.end();
}

/** Log-safe error text: ORM errors embed SQL parameters in `message`; prefer the driver's cause. */
export function describeError(err: unknown): string {
  const e = err as Error & { cause?: Error & { code?: string } };
  if (e?.cause?.message) return `${e.cause.code ?? ''} ${e.cause.message}`.trim();
  return e?.message ?? String(err);
}
