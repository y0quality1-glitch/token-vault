/** Paging limits for /getall (template fix B-09: a list is always limited). */
export const PAGE_SIZE_DEFAULT = 500;
export const PAGE_SIZE_MAX = 500;

/**
 * Paging, search and filters of a /getall body (template: core/Y0Params.ts). Pages start at 1;
 * pageSize is clamped, so a client can never read a whole table. `filters` holds the module's
 * own filters (string values only, as the old query parameters were).
 */
export class Pagination {
  pageNumber = 1;
  pageSize = PAGE_SIZE_DEFAULT;
  search = '';
  filters: Record<string, string> = {};

  static from(body: unknown): Pagination {
    const b = (body && typeof body === 'object' ? body : {}) as Record<string, unknown>;
    const p = new Pagination();
    const int = (v: unknown, d: number) => (typeof v === 'number' && Number.isInteger(v) ? v : typeof v === 'string' && /^\d+$/.test(v) ? Number(v) : d);
    p.pageNumber = Math.max(1, int(b.pageNumber, 1));
    p.pageSize = Math.min(PAGE_SIZE_MAX, Math.max(1, int(b.pageSize, PAGE_SIZE_DEFAULT)));
    p.search = typeof b.search === 'string' ? b.search.trim().slice(0, 100) : '';
    for (const [k, v] of Object.entries(b)) if (typeof v === 'string' && v && !['pageNumber', 'pageSize', 'search'].includes(k)) p.filters[k] = v.slice(0, 200);
    return p;
  }
}
