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

/** Authorized, but execution failed safely (customer webhook unavailable or upstream provider error). */
export class ExecutionFailedError extends TokenVaultError {}
