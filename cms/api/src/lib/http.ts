import type { NextFunction, Request, Response } from 'express';
import type { ZodType, ZodTypeDef } from 'zod';
import { describeError } from '../db/client';

export class HttpError extends Error {
  constructor(
    public status: number,
    public code: string,
    message: string,
    public details?: unknown,
  ) {
    super(message);
  }
}

export const badRequest = (message: string, details?: unknown) => new HttpError(400, 'VALIDATION_ERROR', message, details);
export const unauthorized = (message = 'Authentication required') => new HttpError(401, 'UNAUTHENTICATED', message);
export const forbidden = (message = 'You do not have permission to perform this action', code = 'PERMISSION_DENIED') => new HttpError(403, code, message);
export const notFound = (what = 'Resource') => new HttpError(404, 'NOT_FOUND', `${what} not found`);
export const conflict = (message: string, code = 'CONFLICT') => new HttpError(409, code, message);

export function parse<T>(schema: ZodType<T, ZodTypeDef, unknown>, data: unknown): T {
  const r = schema.safeParse(data);
  if (!r.success) {
    const fields: Record<string, string> = {};
    for (const issue of r.error.issues) fields[issue.path.join('.') || '_'] = issue.message;
    throw badRequest('Request validation failed', { fields });
  }
  return r.data;
}

/** Logs method, path, status and latency only: never bodies or headers. */
export function requestLogger(req: Request, res: Response, next: NextFunction) {
  const started = Date.now();
  res.on('finish', () => console.log(`[cms] ${req.method} ${req.path} ${res.statusCode} ${Date.now() - started}ms`));
  next();
}

export function securityHeaders(_req: Request, res: Response, next: NextFunction) {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Cache-Control', 'no-store');
  next();
}

export function errorHandler(err: unknown, _req: Request, res: Response, _next: NextFunction) {
  if (err instanceof HttpError) {
    res.status(err.status).json({ error: { code: err.code, message: err.message, details: err.details } });
    return;
  }
  if (err instanceof SyntaxError && 'body' in err) {
    res.status(400).json({ error: { code: 'MALFORMED_JSON', message: 'Request body is not valid JSON' } });
    return;
  }
  if ((err as { type?: string })?.type === 'entity.too.large') {
    res.status(413).json({ error: { code: 'PAYLOAD_TOO_LARGE', message: 'Request body is too large' } });
    return;
  }
  console.error('[cms] unhandled error:', (err as Error)?.name, describeError(err));
  res.status(500).json({ error: { code: 'INTERNAL_ERROR', message: 'An unexpected error occurred' } });
}
