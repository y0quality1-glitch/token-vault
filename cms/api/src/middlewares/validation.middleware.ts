import { plainToInstance, type ClassConstructor } from 'class-transformer';
import { validate, type ValidationError } from 'class-validator';
import type { NextFunction, Request, RequestHandler, Response } from 'express';
import { handleError, validationError } from '../core/ApiError';

/** Flattens class-validator errors to `{ "path.to.field": "message" }` (nested errors included). */
function toFields(errors: ValidationError[], prefix = ''): Record<string, string> {
  const out: Record<string, string> = {};
  for (const e of errors) {
    const path = prefix ? `${prefix}.${e.property}` : e.property;
    // Template fix B-12: nested errors have no `constraints` of their own.
    const first = Object.values(e.constraints ?? {})[0];
    if (first) out[path] = first;
    if (e.children?.length) Object.assign(out, toFields(e.children, path));
  }
  return out;
}

/**
 * Validates the body against a DTO class (template: validationFDMiddleware). Unknown fields are
 * dropped (whitelist) and defaults from the DTO apply; on success `req.body` is the validated
 * DTO. The DTO class itself is never mutated (template fix B-12), and validation failures can't
 * leave a request hanging.
 */
export function validationMiddleware<T extends object>(type: ClassConstructor<T>): RequestHandler {
  return (req: Request, res: Response, next: NextFunction) => {
    const body = req.body && typeof req.body === 'object' && !Array.isArray(req.body) ? req.body : {};
    const dto = plainToInstance(type, body);
    validate(dto, { whitelist: true, forbidUnknownValues: true })
      .then((errors) => {
        if (errors.length) return handleError(validationError(toFields(errors)), res);
        req.body = dto;
        next();
      })
      .catch((e) => handleError(e, res));
  };
}
