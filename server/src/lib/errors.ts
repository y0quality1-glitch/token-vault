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
export const forbidden = (message = 'You do not have permission to perform this action') => new HttpError(403, 'PERMISSION_DENIED', message);
export const notFound = (what = 'Resource') => new HttpError(404, 'NOT_FOUND', `${what} not found`);
export const conflict = (message: string) => new HttpError(409, 'CONFLICT', message);

/**
 * Log-safe one-line description of an error. ORM errors embed the SQL text and its
 * parameter values in `message`; the driver's own message lives in `cause`, so prefer it.
 */
export function describeError(err: unknown): string {
  const e = err as Error & { cause?: Error & { code?: string } };
  if (e?.cause?.message) return `${e.cause.code ?? ''} ${e.cause.message}`.trim();
  return e?.message ?? String(err);
}
