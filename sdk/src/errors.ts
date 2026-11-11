import type { ExecuteResponseBody } from '@token-vault/shared';

/** Base class for every Token Vault SDK error. Never contains the API key. */
export class TokenVaultError extends Error {
  /** Stable code, e.g. GRANT_REVOKED, SCOPE_DENIED, WEBHOOK_UNAVAILABLE, NETWORK_ERROR. */
  readonly code: string;
  readonly httpStatus: number | null;
  /** Token Vault request ID, for matching against the audit log. */
  readonly requestId: string | null;
  /** The sanitized response body, when there was one. */
  readonly response: ExecuteResponseBody | null;

  constructor(message: string, opts: { code: string; httpStatus?: number | null; requestId?: string | null; response?: ExecuteResponseBody | null }) {
    super(message);
    this.name = new.target.name;
    this.code = opts.code;
    this.httpStatus = opts.httpStatus ?? null;
    this.requestId = opts.requestId ?? null;
    this.response = opts.response ?? null;
  }
}

/** The agent credential is missing, malformed, rotated or unknown (HTTP 401). */
export class AuthenticationError extends TokenVaultError {}

/** Token Vault denied the request: no grant, revoked, expired, out of scope, policy, rate limit… */
export class AccessDeniedError extends TokenVaultError {}

/**
 * Every check allows the request, but a policy requires a human to approve it first
 * (decision code APPROVAL_REQUIRED). Nothing ran. Wait with waitForApproval(approvalId),
 * then send the same request again, or call executeApproved(approvalId).
 */
export class ApprovalRequiredError extends AccessDeniedError {
  readonly approvalId: string;
  /** When the pending approval lapses if nobody decides. */
  readonly approvalExpiresAt: string;

  constructor(message: string, opts: ConstructorParameters<typeof TokenVaultError>[1] & { approvalId: string; approvalExpiresAt: string }) {
    super(message, opts);
    this.approvalId = opts.approvalId;
    this.approvalExpiresAt = opts.approvalExpiresAt;
  }
}

/**
 * The operation ran, but a Filter responses policy withheld its result (code RESPONSE_WITHHELD),
 * for example because it looked like prompt injection. Do not simply retry: the operation already
 * ran. `response.filtering` says why.
 */
export class ResponseWithheldError extends TokenVaultError {}

/** Authorized, but execution failed safely (customer webhook unavailable or upstream provider error). */
export class ExecutionFailedError extends TokenVaultError {}
