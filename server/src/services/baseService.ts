import { Brackets, type EntityManager, type EntityTarget, type ObjectLiteral, type SelectQueryBuilder } from 'typeorm';
import { Pagination } from '../core/Y0Params';
import { db, transaction } from '../databases/client';
import { notFound } from '../lib/errors';
import type { AdminContext } from '../types/express';

export type OrgContext = AdminContext & { org: { id: string; name: string } };

export interface Page<V> {
  records: V[];
  totalRecords: number;
}

/**
 * Base service (template: services/baseService.ts, Template Method). It owns the generic flows;
 * a module supplies its entity and name and overrides the hooks it needs:
 *
 *   getAll        prepareFilter → applyFilters → applyGlobalSearch → getManyAndCount → postProcessAfterGetData
 *   getById       findEntity → postProcessAfterGetById
 *   createRecord  (one transaction) createPreProcess → saveData → createPostProcess
 *
 * Every query is scoped to the caller's organization (organizationColumn), so a module cannot
 * forget it. Fixes from the template's review are built in: lists are always limited (B-09),
 * search uses ILIKE with escaped, bound input (B-10), create runs in one transaction (B-11), and
 * a missing id is a 404, never a widened query.
 */
export abstract class BaseServices<E extends ObjectLiteral, V = E> {
  protected constructor(protected readonly entity: EntityTarget<E>) {}

  // ── module contract ─────────────────────────────────────────────
  abstract getModuleName(): string;
  /** Columns (with the `main.` alias) that `search` matches. */
  getGlobalSearchColumns(): string[] {
    return [];
  }
  /** The column scoping every query to one organization (null: the table is not org-scoped). */
  protected organizationColumn(): string | null {
    return 'main.organization_id';
  }
  /** The property getById looks records up by. */
  protected idProperty(): string {
    return 'id';
  }

  // ── getAll ──────────────────────────────────────────────────────
  protected prepareFilter(qb: SelectQueryBuilder<E>, orgId: string, _param: Pagination): SelectQueryBuilder<E> {
    const col = this.organizationColumn();
    if (col) qb.where(`${col} = :orgId`, { orgId });
    return qb.orderBy('main.created_at', 'DESC');
  }

  /** Module filters (`param.filters`, e.g. agentId). Unknown filters are ignored. */
  protected applyFilters(qb: SelectQueryBuilder<E>, _param: Pagination): SelectQueryBuilder<E> {
    return qb;
  }

  protected applyGlobalSearch(qb: SelectQueryBuilder<E>, param: Pagination): SelectQueryBuilder<E> {
    const columns = this.getGlobalSearchColumns();
    if (param.search && columns.length) {
      const pattern = `%${param.search.replace(/[\\%_]/g, (c) => `\\${c}`)}%`;
      qb.andWhere(new Brackets((w) => columns.forEach((c) => w.orWhere(`${c} ILIKE :search`, { search: pattern }))));
    }
    return qb;
  }

  protected async postProcessAfterGetData(records: E[], _orgId: string, _param: Pagination): Promise<V[]> {
    return records as unknown as V[];
  }

  async getAll(orgId: string, body: unknown = {}): Promise<Page<V>> {
    const param = Pagination.from(body);
    const qb = db.createQueryBuilder(this.entity, 'main');
    this.prepareFilter(qb, orgId, param);
    this.applyFilters(qb, param);
    this.applyGlobalSearch(qb, param);
    // OFFSET/LIMIT: joins used for search or order are one-to-one, so rows map 1:1 to records.
    qb.offset((param.pageNumber - 1) * param.pageSize).limit(param.pageSize);
    const [records, totalRecords] = await qb.getManyAndCount();
    return { records: records.length ? await this.postProcessAfterGetData(records, orgId, param) : [], totalRecords };
  }

  // ── getById ─────────────────────────────────────────────────────
  protected async findEntity(orgId: string, id: string, ex: EntityManager = db): Promise<E> {
    const where: Record<string, unknown> = { [this.idProperty()]: id };
    if (this.organizationColumn()) where.organizationId = orgId;
    const record = id && orgId ? await ex.findOneBy(this.entity, where as never) : null;
    if (!record) throw notFound(this.getModuleName());
    return record;
  }

  protected async postProcessAfterGetById(record: E, _orgId: string): Promise<V> {
    return record as unknown as V;
  }

  async getById(orgId: string, id: string): Promise<V> {
    return this.postProcessAfterGetById(await this.findEntity(orgId, id), orgId);
  }

  // ── create ──────────────────────────────────────────────────────
  protected async createPreProcess<D>(_ex: EntityManager, _ctx: OrgContext, dto: D): Promise<D> {
    return dto;
  }

  /** Writes the record. Modules that create records through createRecord override it. */
  protected async saveData(_ex: EntityManager, _ctx: OrgContext, _dto: unknown): Promise<E> {
    throw new Error(`${this.getModuleName()} does not create records through createRecord`);
  }

  protected async createPostProcess(_ex: EntityManager, _ctx: OrgContext, record: E): Promise<unknown> {
    return record;
  }

  /** Runs the whole create flow in one transaction: a failure leaves nothing behind. */
  async createRecord(ctx: OrgContext, dto: unknown): Promise<unknown> {
    return transaction(async (ex) => {
      const prepared = await this.createPreProcess(ex, ctx, dto);
      const saved = await this.saveData(ex, ctx, prepared);
      return this.createPostProcess(ex, ctx, saved);
    });
  }
}
