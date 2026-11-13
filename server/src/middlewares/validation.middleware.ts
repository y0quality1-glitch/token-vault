import { plainToInstance, type ClassConstructor } from 'class-transformer';
import { validate, type ValidationError } from 'class-validator';
import type { NextFunction, Request, RequestHandler, Response } from 'express';
import { handleError } from '../core/ApiError';
import { badRequest } from '../lib/errors';

/** class-validator errors as `{ "path.to.field": "message" }` (nested errors included). */
function toFields(errors: ValidationError[], prefix = ''): Record<string, string> {
  const out: Record<string, string> = {};
  for (const e of errors) {
    const path = prefix ? `${prefix}.${e.property}` : e.property;
    // Template fix B-12: nested errors carry no constraints of their own.
    const first = Object.values(e.constraints ?? {})[0];
    if (first) out[path] = first;
    if (e.children?.length) Object.assign(out, toFields(e.children, path));
  }
  return out;
}

/**
 * Validates `req.body` against a DTO class (template: validationFDMiddleware). Unknown fields are
 * dropped, the DTO's defaults apply, and on success `req.body` is the validated DTO. The DTO class
 * is never mutated, and a failure can't leave the request hanging (template fix B-12).
 */
export function validationMiddleware<T extends object>(type: ClassConstructor<T>): RequestHandler {
  return (req: Request, res: Response, next: NextFunction) => {
    const body = req.body && typeof req.body === 'object' && !Array.isArray(req.body) ? req.body : {};
    const dto = plainToInstance(type, body);
    validate(dto, { whitelist: true, forbidUnknownValues: true })
      .then((errors) => {
        if (errors.length) return handleError(badRequest('Request validation failed', { fields: toFields(errors) }), res);
        req.body = dto;
        next();
      })
      .catch((e) => handleError(e, res));
  };
}
