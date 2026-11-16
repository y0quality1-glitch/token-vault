/**
 * Error catalogue (template: core/ErrorCodes.ts). E10xxx are generic, E30xxx are CMS domain
 * errors. `name` is the stable machine-readable code clients branch on; `status` is the HTTP
 * status sent with it. Services reject with `new ServiceError('E30010', message?, meta?)`.
 */
export interface ErrorCode {
  type: 'generic' | 'domain';
  name: string;
  message: string;
  status: number;
}

export const ErrorCodes = {
  E10001: { type: 'generic', name: 'NOT_FOUND', message: 'The requested resource was not found.', status: 404 },
  E10002: { type: 'generic', name: 'UNAUTHENTICATED', message: 'Authentication required.', status: 401 },
  E10003: { type: 'generic', name: 'PERMISSION_DENIED', message: 'You do not have permission to perform this action.', status: 403 },
  E10004: { type: 'generic', name: 'VALIDATION_ERROR', message: 'The data provided did not pass validation.', status: 400 },
  E10005: { type: 'generic', name: 'INTERNAL_ERROR', message: 'An unexpected error occurred.', status: 500 },
  E10006: { type: 'generic', name: 'MALFORMED_JSON', message: 'Request body is not valid JSON.', status: 400 },
  E10007: { type: 'generic', name: 'CONFLICT', message: 'There is a conflict with the current state of the resource.', status: 409 },
  E10010: { type: 'generic', name: 'PAYLOAD_TOO_LARGE', message: 'Request body is too large.', status: 413 },
  E10011: { type: 'generic', name: 'METHOD_NOT_ALLOWED', message: 'This route does not accept that method.', status: 405 },
  E10073: { type: 'generic', name: 'INVALID_ID', message: 'The id is missing or invalid.', status: 400 },
  E10075: { type: 'generic', name: 'RECORD_NOT_FOUND', message: 'Record not found.', status: 404 },

  E30001: { type: 'domain', name: 'INVALID_CREDENTIALS', message: 'Invalid email or password.', status: 401 },
  E30002: { type: 'domain', name: 'TOO_MANY_ATTEMPTS', message: 'Too many failed attempts. Try again in a minute.', status: 429 },
  E30003: { type: 'domain', name: 'SESSION_EXPIRED', message: 'Your session has expired. Please sign in again.', status: 401 },
  E30004: { type: 'domain', name: 'ROLE_REQUIRED', message: 'Your role does not allow this action.', status: 403 },
  E30010: { type: 'domain', name: 'KEY_TAKEN', message: 'An application with this key already exists.', status: 409 },
  E30011: { type: 'domain', name: 'ARCHIVED', message: 'This application is archived.', status: 409 },
  E30012: { type: 'domain', name: 'OPEN_VERSION_EXISTS', message: 'Another version is still open.', status: 409 },
  E30013: { type: 'domain', name: 'NOT_EDITABLE', message: 'This version cannot be edited.', status: 409 },
  E30014: { type: 'domain', name: 'INVALID_STATE', message: 'The version is not in a state that allows this.', status: 409 },
  E30015: { type: 'domain', name: 'DEFINITION_INVALID', message: 'The definition does not pass validation.', status: 400 },
  E30016: { type: 'domain', name: 'SEPARATION_OF_DUTIES', message: 'Another publisher must review this version.', status: 403 },
  E30017: { type: 'domain', name: 'DIRECT_PUBLISH_DISABLED', message: 'Direct publishing is turned off.', status: 403 },
  E30018: { type: 'domain', name: 'HOST_CHANGE_UNACKNOWLEDGED', message: 'Confirm the hosts credentials will be sent to.', status: 409 },
  E30019: { type: 'domain', name: 'NOT_PUBLISHED', message: 'Nothing is published yet.', status: 409 },
  E30020: { type: 'domain', name: 'UNCHANGED', message: 'Nothing would change.', status: 409 },
} satisfies Record<string, ErrorCode>;

export type ErrorCodeId = keyof typeof ErrorCodes;

export function errorCode(id: string): ErrorCode & { id: string } {
  const known = (ErrorCodes as Record<string, ErrorCode>)[id];
  return known ? { id, ...known } : { id: 'E10005', ...ErrorCodes.E10005 };
}
