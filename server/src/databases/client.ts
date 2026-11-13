import type { EntityManager } from 'typeorm';
import AppDatabase from './database';

/**
 * What repositories and services use: an Executor (the shared EntityManager, or a
 * transaction's) and `transaction()`. Repositories take an optional Executor so callers can
 * compose several writes in one transaction.
 */
export type Executor = EntityManager;
export type Tx = EntityManager;

/**
 * The connection's EntityManager, resolved on use (the DataSource is initialized at start-up,
 * after modules are loaded). Used as the default Executor: `ex: Executor = db`.
 */
export const db: EntityManager = new Proxy({} as EntityManager, {
  get(_target, prop) {
    const manager = AppDatabase.getInstance().manager;
    const value = Reflect.get(manager, prop, manager);
    return typeof value === 'function' ? value.bind(manager) : value;
  },
});

export const transaction = <T>(fn: (tx: EntityManager) => Promise<T>): Promise<T> => AppDatabase.getInstance().executeInTransaction(fn);

/** Connects and applies pending migrations (start-up, tests). */
export async function runMigrations(): Promise<string[]> {
  const database = AppDatabase.getInstance();
  await database.connectToDB();
  return database.runMigrations();
}

export async function closeDatabase(): Promise<void> {
  await AppDatabase.getInstance().close();
}
