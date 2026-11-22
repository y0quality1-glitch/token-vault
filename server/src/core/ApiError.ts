import type { NextFunction, Request, Response } from 'express';
import { ZodError } from 'zod';
import { HttpError, describeError } from '../lib/errors';
import { sanitize } from '../lib/sanitize';
import { ErrorCodes, type ErrorCodeId } from './ErrorCodes';
import { GenericResponse } from './GenericResponse';

/** An HttpError for a catalogue code (template: reject('E10075')). */
export const catalogError = (id: ErrorCodeId, message?: string, details?: unknown) => new HttpError(ErrorCodes[id].status, ErrorCodes[id].name, message ?? ErrorCodes[id].message, details);

/**
 * Sends any error as the failure envelope (template: ApiError.handle). Messages and details are
 * sanitized (never request bodies or secrets); unknown errors are logged without request data
 * and answered with a generic 500 (template fix B-27: formatting never throws).
 */
export function handleError(err: unknown, res: Response): void {
  if (res.headersSent) return;
  if (err instanceof HttpError) {
    res.status(err.status).json(GenericResponse.failure(sanitize(err.message) as string, err.code, sanitize(err.details) ?? null));
    return;
  }
  const e = err as { type?: string; code?: string; detail?: string };
  if (err instanceof ZodError) return send(res, 'E10004');
  if (e?.type === 'entity.parse.failed' || (err instanceof SyntaxError && 'body' in (err as object))) return send(res, 'E10006');
  if (e?.type === 'entity.too.large') return send(res, 'E10010');
  console.error('[api] unhandled error:', (err as Error)?.name, sanitize(describeError(err)));
  send(res, 'E10005');
}

function send(res: Response, id: ErrorCodeId) {
  const c = ErrorCodes[id];
  res.status(c.status).json(GenericResponse.failure(c.message, c.name));
}

/** 4-argument Express error handler (template fix B-14: JSON errors, never an HTML page). */
export function errorMiddleware(err: unknown, _req: Request, res: Response, _next: NextFunction) {
  handleError(err, res);
}

export function notFoundMiddleware(_req: Request, res: Response) {
  handleError(catalogError('E10001'), res);
}
