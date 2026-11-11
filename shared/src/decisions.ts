/** Stable, sanitized decision codes returned to agents and recorded in audit. */
export const DECISION_CODES = {
  ALLOWED: 'ALLOWED',
  AGENT_UNAUTHENTICATED: 'AGENT_UNAUTHENTICATED',
  AGENT_DISABLED: 'AGENT_DISABLED',
  MALFORMED_REQUEST: 'MALFORMED_REQUEST',
  UNKNOWN_OPERATION: 'UNKNOWN_OPERATION',
  INTEGRATION_NOT_FOUND: 'INTEGRATION_NOT_FOUND',
  POLICY_DENIED: 'POLICY_DENIED',
  GRANT_MISSING: 'GRANT_MISSING',
  GRANT_REVOKED: 'GRANT_REVOKED',
  GRANT_EXPIRED: 'GRANT_EXPIRED',
  GRANT_NOT_YET_VALID: 'GRANT_NOT_YET_VALID',
  GRANT_PENDING_APPROVAL: 'GRANT_PENDING_APPROVAL',
  INTEGRATION_UNAVAILABLE: 'INTEGRATION_UNAVAILABLE',
  SCOPE_DENIED: 'SCOPE_DENIED',
  RESOURCE_DENIED: 'RESOURCE_DENIED',
  RATE_LIMITED: 'RATE_LIMITED',
  IP_DENIED: 'IP_DENIED',
  /** A grant budget (requests per day, writes per hour) is used up. */
  BUDGET_EXCEEDED: 'BUDGET_EXCEEDED',
  /** An administrator stopped all agent access in the organization. */
  EMERGENCY_STOP: 'EMERGENCY_STOP',
  /** A REQUIRE_APPROVAL policy matched: the request waits for a human (approval in the response). */
  APPROVAL_REQUIRED: 'APPROVAL_REQUIRED',
  /** A destructive operation without an enabled REQUIRE_APPROVAL policy covering it: never runs. */
  APPROVAL_POLICY_MISSING: 'APPROVAL_POLICY_MISSING',
  /** A human rejected the approval for this request. */
  APPROVAL_REJECTED: 'APPROVAL_REJECTED',
  /** The approval_id sent is unknown, expired, already used, or for a different request. */
  APPROVAL_INVALID: 'APPROVAL_INVALID',
  WEBHOOK_UNAVAILABLE: 'WEBHOOK_UNAVAILABLE',
  UPSTREAM_ERROR: 'UPSTREAM_ERROR',
} as const;

export type DecisionCode = (typeof DECISION_CODES)[keyof typeof DECISION_CODES];

export const DECISION_LABELS: Record<string, string> = {
  ALLOWED: 'Authorized',
  AGENT_UNAUTHENTICATED: 'Unauthorized agent',
  AGENT_DISABLED: 'Agent disabled',
  MALFORMED_REQUEST: 'Malformed request',
  UNKNOWN_OPERATION: 'Unknown operation',
  INTEGRATION_NOT_FOUND: 'Integration not found',
  POLICY_DENIED: 'Denied by policy',
  GRANT_MISSING: 'Missing grant',
  GRANT_REVOKED: 'Revoked grant',
  GRANT_EXPIRED: 'Expired grant',
  GRANT_NOT_YET_VALID: 'Grant not yet valid',
  GRANT_PENDING_APPROVAL: 'Grant pending approval',
  INTEGRATION_UNAVAILABLE: 'Integration unavailable',
  SCOPE_DENIED: 'Scope denied',
  RESOURCE_DENIED: 'Resource restriction',
  RATE_LIMITED: 'Rate limit exceeded',
  IP_DENIED: 'Source IP denied',
  BUDGET_EXCEEDED: 'Budget used up',
  EMERGENCY_STOP: 'Emergency stop',
  APPROVAL_REQUIRED: 'Waiting for approval',
  APPROVAL_POLICY_MISSING: 'Destructive operation without approval policy',
  APPROVAL_REJECTED: 'Approval rejected',
  APPROVAL_INVALID: 'Invalid approval',
  WEBHOOK_UNAVAILABLE: 'Webhook unavailable',
  UPSTREAM_ERROR: 'Upstream provider error',
};
