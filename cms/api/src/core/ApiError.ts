import type { Response } from 'express';
import { errorCode, type ErrorCodeId } from './ErrorCodes';
import { GenericResponse } from './GenericResponse';

/**
 * A rejection with a catalogue code (template: `reject({ code, message?, meta? })`). The
 * message defaults to the catalogue's; `meta` becomes the response's `details`.
 */
export class ServiceError extends Error {
  constructor(
    public code: ErrorCodeId,
    message?: string,
    public meta?: unknown,
  ) {
    super(message ?? errorCode(code).message);
  }
}

export const notFound = (what = 'Resource') => new ServiceError('E10001', `${what} not found`);
export const validationError = (fields: Record<string, string>, message = 'Request validation failed') => new ServiceError('E10004', message, { fields });

/**
 * Sends any error as the failure envelope (template: ApiError.handle). Unknown errors are
 * logged without request data and answered with a generic 500; Postgres constraint errors get
 * a readable message (template fix B-27: never throws while formatting).
 */
export function handleError(err: unknown, res: Response): void {
  if (err instanceof ServiceError) {
    const c = errorCode(err.code);
    res.status(c.status).json(GenericResponse.failure(err.message, c.name, err.meta ?? null));
    return;
  }
  const e = err as { type?: string; code?: string; detail?: string; status?: number; name?: string; message?: string; driverError?: { code?: string; detail?: string } };
  if (e?.type === 'entity.parse.failed' || (err instanceof SyntaxError && 'body' in (err as object))) return send(res, 'E10006');
  if (e?.type === 'entity.too.large') return send(res, 'E10010');
  const pg = e?.driverError ?? e;
  if (pg?.code === '23505') return send(res, 'E10007', `Already exists${pg.detail?.match(/\(([^)]+)\)=/)?.[1] ? `: ${pg.detail.match(/\(([^)]+)\)=/)![1]}` : ''}`);
  if (pg?.code === '23503') return send(res, 'E10007', 'Refers to a record that does not exist');
  console.error('[cms] unhandled error:', e?.name ?? 'Error', (pg as { message?: string })?.message ?? String(err));
  send(res, 'E10005');
}

function send(res: Response, id: ErrorCodeId, message?: string) {
  const c = errorCode(id);
  res.status(c.status).json(GenericResponse.failure(message ?? c.message, c.name));
}
