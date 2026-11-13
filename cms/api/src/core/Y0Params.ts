import { PAGE_SIZE_DEFAULT, PAGE_SIZE_MAX } from '../config';

/** Generic parameter classes (template: core/Y0Params.ts). Ids are text in this service. */
export class Y0Params {
  id: string | null = null;
}

export class Filter {
  search = '';
  /** Audit log: only events for this application key. */
  application: string | null = null;
}

/**
 * Paging for /getall. Template fix B-09: pages start at 1 and are always limited; pageSize is
 * clamped to PAGE_SIZE_MAX, so a client can never ask for a whole table.
 */
export class Pagination extends Y0Params {
  pageNumber = 1;
  pageSize = PAGE_SIZE_DEFAULT;
  filter: Filter = new Filter();
  sortBy: string | null = null;
  sortType: 'ASC' | 'DESC' | null = null;

  static from(body: Record<string, unknown> | undefined): Pagination {
    const p = new Pagination();
    const n = (v: unknown, d: number) => (typeof v === 'number' && Number.isInteger(v) ? v : typeof v === 'string' && /^\d+$/.test(v) ? Number(v) : d);
    p.pageNumber = Math.max(1, n(body?.pageNumber, 1));
    p.pageSize = Math.min(PAGE_SIZE_MAX, Math.max(1, n(body?.pageSize, PAGE_SIZE_DEFAULT)));
    p.filter.search = typeof body?.search === 'string' ? body.search.trim().slice(0, 100) : '';
    p.filter.application = typeof body?.application === 'string' && body.application ? body.application.slice(0, 40) : null;
    if (body?.sortType === 'ASC' || body?.sortType === 'DESC') p.sortType = body.sortType;
    if (typeof body?.sortBy === 'string') p.sortBy = body.sortBy;
    return p;
  }
}
