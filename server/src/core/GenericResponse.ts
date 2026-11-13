/** Template status codes (core/GenericResponse in docs/fileStructure.md). */
export enum StatusCode {
  SUCCESS = '10000',
  FAILURE = '10001',
}

/**
 * The response envelope of every admin and agent route:
 *
 *   { status: "10000", msg, error: null, details, totalRecords }               success
 *   { status: "10001", msg: "", error, code, details, totalRecords: 0 }         failure
 *
 * `details` is the route's payload. For lists it is `{ items, total, ... }`; `totalRecords` is the
 * number of matching records across all pages (`total`), or the number of items.
 * On failure `code` is the stable machine-readable code and `details` holds extra data such as
 * `{ fields }`. The HTTP status carries the outcome as well.
 */
export class GenericResponse<T> {
  status: StatusCode = StatusCode.SUCCESS;
  msg = '';
  error: string | null = null;
  code?: string;
  details: T | null = null;
  totalRecords = 0;

  static success<T>(msg: string, details: T): GenericResponse<T> {
    const r = new GenericResponse<T>();
    r.msg = msg;
    r.details = details;
    const items = (details as { items?: unknown } | null)?.items;
    const total = (details as { total?: unknown } | null)?.total;
    r.totalRecords = typeof total === 'number' ? total : Array.isArray(items) ? items.length : Array.isArray(details) ? details.length : 0;
    return r;
  }

  static failure(error: string, code: string, details: unknown = null): GenericResponse<unknown> {
    const r = new GenericResponse<unknown>();
    r.status = StatusCode.FAILURE;
    r.error = error;
    r.code = code;
    r.details = details ?? null;
    return r;
  }
}
