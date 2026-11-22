import type { NextFunction, Request, Response } from 'express';
import { ZodError } from 'zod';
import { HttpError, describeError } from '../lib/errors';
import { sanitize } from '../lib/sanitize';

/** Logs method, path, status and latency only. Bodies, headers and query strings are never logged. */
export function requestLogger(req: Request, res: Response, next: NextFunction) {
  const started = Date.now();
  res.on('finish', () => {
    console.log(`[api] ${req.method} ${req.path} ${res.statusCode} ${Date.now() - started}ms`);
  });
  next();
}

/** Baseline security headers for the API. */
export function securityHeaders(_req: Request, res: Response, next: NextFunction) {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Cache-Control', 'no-store');
  next();
}

export function notFoundHandler(_req: Request, res: Response) {
  res.status(404).json({ error: { code: 'NOT_FOUND', message: 'Route not found' } });
}

/** Sanitized error responses: never echo request bodies or stack traces. */
export function errorHandler(err: unknown, _req: Request, res: Response, _next: NextFunction) {
  if (err instanceof HttpError) {
    res.status(err.status).json({ error: { code: err.code, message: sanitize(err.message), details: sanitize(err.details) } });
    return;
  }
  if (err instanceof ZodError) {
    res.status(400).json({ error: { code: 'VALIDATION_ERROR', message: 'Request validation failed' } });
    return;
  }
  if (err instanceof SyntaxError && 'body' in err) {
    res.status(400).json({ error: { code: 'MALFORMED_JSON', message: 'Request body is not valid JSON' } });
    return;
  }
  console.error('[api] unhandled error:', (err as Error)?.name, sanitize(describeError(err)));
  res.status(500).json({ error: { code: 'INTERNAL_ERROR', message: 'An unexpected error occurred' } });
}
