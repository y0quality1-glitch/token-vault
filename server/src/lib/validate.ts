import type { ZodType, ZodTypeDef } from 'zod';
import { badRequest } from './errors';

export function parse<T>(schema: ZodType<T, ZodTypeDef, unknown>, data: unknown): T {
  const r = schema.safeParse(data);
  if (!r.success) {
    const fields: Record<string, string> = {};
    for (const issue of r.error.issues) fields[issue.path.join('.') || '_'] = issue.message;
    throw badRequest('Request validation failed', { fields });
  }
  return r.data;
}
