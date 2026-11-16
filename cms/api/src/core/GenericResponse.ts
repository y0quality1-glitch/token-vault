import { StatusCode } from '../config';

/**
 * The response envelope every admin route returns (template: core/GenericResponse.ts):
 *
 *   { status: "10000", msg, error: null, details, totalRecords }       success
 *   { status: "10001", msg: "", error, code, details, totalRecords: 0 } failure
 *
 * On failure `code` is the stable machine-readable name (e.g. KEY_TAKEN) and `details` holds
 * extra data such as `{ fields: { key: "…" } }` or `{ issues: [...] }`.
 */
export class GenericResponse<T> {
  status: StatusCode = StatusCode.SUCCESS;
  msg = '';
  error: string | null = null;
  code?: string;
  details: T | null = null;
  totalRecords = 0;

  static success<T>(msg: string, details: T, totalRecords = 0): GenericResponse<T> {
    const r = new GenericResponse<T>();
    r.msg = msg;
    r.details = details;
    r.totalRecords = totalRecords;
    return r;
  }

  static failure(error: string, code: string, details: unknown = null): GenericResponse<unknown> {
    const r = new GenericResponse<unknown>();
    r.status = StatusCode.FAILURE;
    r.error = error;
    r.code = code;
    r.details = details;
    return r;
  }
}
