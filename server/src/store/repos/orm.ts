import type { EntityTarget, ObjectLiteral } from 'typeorm';
import type { Executor } from '../../databases/client';

/** Small helpers shared by the repositories (TypeORM). */

/**
 * findOneBy that never widens: TypeORM ignores `undefined` values in a where object, so a
 * missing id would match any row. Any missing key value returns null instead.
 */
export async function oneBy<E extends ObjectLiteral>(ex: Executor, entity: EntityTarget<E>, where: Record<string, unknown>): Promise<E | null> {
  if (Object.values(where).some((v) => v === undefined || v === null)) return null;
  return ex.findOneBy(entity, where as never);
}

/** Throws when a key value is missing, so an update or delete can never widen to other rows. */
export function keys(where: Record<string, unknown>): Record<string, unknown> {
  for (const [k, v] of Object.entries(where)) if (v === undefined || v === null) throw new Error(`Missing ${k} in a keyed update or delete`);
  return where;
}

/** UPDATE … WHERE <keys> (never all rows). Returns the number of rows changed. */
export async function updateBy<E extends ObjectLiteral>(ex: Executor, entity: EntityTarget<E>, where: Record<string, unknown>, patch: object): Promise<number> {
  return (await ex.update(entity, keys(where) as never, patch as never)).affected ?? 0;
}

/** DELETE … WHERE <keys> (never all rows). Returns the number of rows deleted. */
export async function deleteBy<E extends ObjectLiteral>(ex: Executor, entity: EntityTarget<E>, where: Record<string, unknown>): Promise<number> {
  return (await ex.delete(entity, keys(where) as never)).affected ?? 0;
}

/** Inserts a record and returns the stored row (with database defaults filled in). */
export async function insertRow<E extends ObjectLiteral>(ex: Executor, entity: EntityTarget<E>, record: object, key: Record<string, unknown>): Promise<E> {
  await ex.insert(entity, record as never);
  return (await ex.findOneBy(entity, key as never))!;
}

/** Updates the row matching `where` and returns it (undefined when nothing matched, as before). */
export async function updateRow<E extends ObjectLiteral>(ex: Executor, entity: EntityTarget<E>, where: Record<string, unknown>, patch: object): Promise<E> {
  await ex.update(entity, keys(where) as never, patch as never);
  return (await ex.findOneBy(entity, where as never)) as E;
}

/**
 * Conditional update (e.g. "only while still PENDING"): the UPDATE itself decides, so concurrent
 * callers cannot both succeed. Returns the updated row, or null when the condition did not hold.
 */
export async function updateWhere<E extends ObjectLiteral>(ex: Executor, entity: EntityTarget<E>, where: string, params: Record<string, unknown>, patch: object): Promise<E | null> {
  const r = await ex.createQueryBuilder().update(entity).set(patch as never).where(where, params).returning('id').execute();
  const id = (r.raw as { id: string }[])[0]?.id;
  return id ? ex.findOneBy(entity, { id } as never) : null;
}

/** Escapes LIKE wildcards in user input. */
export const escapeLike = (s: string) => s.replace(/[\\%_]/g, (c) => `\\${c}`);
