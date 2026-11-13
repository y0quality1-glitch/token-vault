import { Brackets, type EntityManager, type EntityTarget, type ObjectLiteral, type SelectQueryBuilder } from 'typeorm';
import type { ClassConstructor } from 'class-transformer';
import type { CmsUser } from '@token-vault/shared';
import { ServiceError } from '../core/ApiError';
import type { Pagination, Y0Params } from '../core/Y0Params';
import AppDatabase from '../databases/database';
import type { Y0Model } from '../databases/repository/y0Model/y0Model.model';

export interface Page<T> {
  records: T[];
  totalRecords: number;
}

/**
 * Base service (template: services/baseService.ts, Template Method). It owns the generic flows;
 * a module supplies its entity, model, DTO and name, and overrides the hooks it needs:
 *
 *   getAll        prepareFilter → applyGlobalSearch → getManyAndCount → postProcessAfterGetData
 *   getById       findEntity → postProcessAfterGetById
 *   createRecord  (one transaction) createPreProcess → saveData → createPostProcess
 *   getData       prepareQuery (override) → postProcessAfterGetAll
 *   getDataById   prepareQueryById (override) → postProcessGetById
 *
 * Fixes from the template's review are built in: pages are always limited (B-09), search uses
 * ILIKE with bound parameters (B-10), create runs in one transaction (B-11), and an invalid id
 * is a 400, not a 500 (B-15). Hard and soft delete are not offered: published definitions are
 * signed records that are never deleted (applications are archived instead).
 */
export abstract class BaseServices<E extends ObjectLiteral, V = unknown> {
  protected constructor(protected readonly entity: EntityTarget<E>) {}

  protected get db(): AppDatabase {
    return AppDatabase.getInstance();
  }

  // ── module contract ─────────────────────────────────────────────
  abstract getModel(): Y0Model;
  abstract getDTO(): ClassConstructor<object>;
  getModuleName(): string {
    return '';
  }
  /** Columns (with the `main.` alias) that /getall's `search` matches. */
  getGlobalSearchColumns(): string[] {
    return [];
  }
  /** The column getById looks records up by. */
  protected idColumn(): string {
    return 'id';
  }

  // ── getAll ──────────────────────────────────────────────────────
  protected prepareFilter(qb: SelectQueryBuilder<E>, param: Pagination): SelectQueryBuilder<E> {
    qb.orderBy('main.created_at', param.sortType ?? 'DESC');
    return qb.skip((param.pageNumber - 1) * param.pageSize).take(param.pageSize);
  }

  protected applyGlobalSearch(qb: SelectQueryBuilder<E>, param: Pagination): SelectQueryBuilder<E> {
    const columns = this.getGlobalSearchColumns();
    const text = param.filter.search;
    if (text && columns.length) {
      const pattern = `%${text.replace(/[\\%_]/g, (c) => `\\${c}`)}%`;
      qb.andWhere(new Brackets((w) => columns.forEach((col, i) => w.orWhere(`${col} ILIKE :search${i}`, { [`search${i}`]: pattern }))));
    }
    return qb;
  }

  protected async postProcessAfterGetData(records: E[], _param: Pagination, _user?: CmsUser): Promise<V[]> {
    return records as unknown as V[];
  }

  async getAll(param: Pagination, user?: CmsUser): Promise<Page<V>> {
    const qb = this.db.manager.createQueryBuilder(this.entity, 'main');
    this.prepareFilter(qb, param);
    this.applyGlobalSearch(qb, param);
    const [records, totalRecords] = await qb.getManyAndCount();
    return { records: records.length ? await this.postProcessAfterGetData(records, param, user) : [], totalRecords };
  }

  // ── getById ─────────────────────────────────────────────────────
  protected async findEntity(m: EntityManager, id: string | null): Promise<E> {
    if (!id) throw new ServiceError('E10073');
    const row = await m.findOneBy(this.entity, { [this.idColumn()]: id } as never);
    if (!row) throw new ServiceError('E10075', `${this.getModuleName() || 'Record'} "${id}" not found`);
    return row;
  }

  protected async postProcessAfterGetById(record: E, _user?: CmsUser): Promise<V> {
    return record as unknown as V;
  }

  async getById(param: Y0Params, user?: CmsUser): Promise<V> {
    return this.postProcessAfterGetById(await this.findEntity(this.db.manager, param.id), user);
  }

  // ── create ──────────────────────────────────────────────────────
  protected async createPreProcess(_m: EntityManager, model: Y0Model, _user: CmsUser): Promise<Y0Model> {
    return model;
  }

  /** Writes the record. Modules that create records override it. */
  protected async saveData(_m: EntityManager, _model: Y0Model, _user: CmsUser): Promise<E> {
    throw new ServiceError('E10001', `${this.getModuleName()} records are not created through /save`);
  }

  protected async createPostProcess(_m: EntityManager, result: E, _model: Y0Model, _user: CmsUser): Promise<unknown> {
    return result;
  }

  /** Runs the whole create flow in one transaction: a failure leaves nothing behind. */
  async createRecord(model: Y0Model, user: CmsUser): Promise<unknown> {
    return this.db.executeInTransaction(async (m) => {
      const prepared = await this.createPreProcess(m, model, user);
      const saved = await this.saveData(m, prepared, user);
      return this.createPostProcess(m, saved, prepared, user);
    });
  }

  // ── custom queries ─────────────────────────────────────────────
  protected async prepareQuery(_param: unknown, _user?: CmsUser): Promise<Page<E>> {
    throw new ServiceError('E10001', `${this.getModuleName()} has no custom list`);
  }

  protected async postProcessAfterGetAll(records: E[]): Promise<V[]> {
    return records as unknown as V[];
  }

  async getData(param: unknown, user?: CmsUser): Promise<Page<V>> {
    const { records, totalRecords } = await this.prepareQuery(param, user);
    return { records: records.length ? await this.postProcessAfterGetAll(records) : [], totalRecords };
  }

  protected async prepareQueryById(_param: unknown, _user?: CmsUser): Promise<unknown> {
    throw new ServiceError('E10001', `${this.getModuleName()} has no custom lookup`);
  }

  protected async postProcessGetById(result: unknown): Promise<unknown> {
    return result;
  }

  async getDataById(param: unknown, user?: CmsUser): Promise<unknown> {
    return this.postProcessGetById(await this.prepareQueryById(param, user));
  }
}
