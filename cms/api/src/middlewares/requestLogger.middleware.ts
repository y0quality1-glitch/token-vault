import { randomUUID } from 'node:crypto';
import type { NextFunction, Request, Response } from 'express';

/**
 * One line per request: id, method, path, status and latency. Never bodies, headers or query
 * strings (template fix B-23). The id is returned as X-Request-Id for correlating reports.
 */
export default function requestLogger(req: Request, res: Response, next: NextFunction) {
  const started = Date.now();
  const id = randomUUID().slice(0, 8);
  res.setHeader('X-Request-Id', id);
  res.on('finish', () => console.log(`[cms] ${id} ${req.method} ${req.originalUrl.split('?')[0]} ${res.statusCode} ${Date.now() - started}ms`));
  next();
}
