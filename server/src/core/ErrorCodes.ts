/**
 * Generic error catalogue (template: core/ErrorCodes.ts). Services throw HttpError with a
 * status and a stable code (domain codes such as GRANT_REVOKED or SEPARATION_OF_DUTIES live
 * with the code that raises them); these are the framework-level ones.
 */
export const ErrorCodes = {
  E10001: { name: 'NOT_FOUND', message: 'Route not found', status: 404 },
  E10002: { name: 'UNAUTHENTICATED', message: 'Authentication required', status: 401 },
  E10003: { name: 'PERMISSION_DENIED', message: 'You do not have permission to perform this action', status: 403 },
  E10004: { name: 'VALIDATION_ERROR', message: 'Request validation failed', status: 400 },
  E10005: { name: 'INTERNAL_ERROR', message: 'An unexpected error occurred', status: 500 },
  E10006: { name: 'MALFORMED_JSON', message: 'Request body is not valid JSON', status: 400 },
  E10007: { name: 'CONFLICT', message: 'There is a conflict with the current state of the resource', status: 409 },
  E10010: { name: 'PAYLOAD_TOO_LARGE', message: 'Request body is too large', status: 413 },
  E10011: { name: 'METHOD_NOT_ALLOWED', message: 'This route does not accept that method', status: 405 },
} as const;

export type ErrorCodeId = keyof typeof ErrorCodes;
