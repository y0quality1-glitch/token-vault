import { randomUUID } from 'node:crypto';
import type { AgentAccessRequestBody, AgentApprovalBody, AgentCapabilitiesBody, AgentDelegationBody, AgentOperationsBody, ExecuteRequestBody, ExecuteResponseBody } from '@token-vault/shared';
import { AccessDeniedError, ApprovalRequiredError, AuthenticationError, ExecutionFailedError, TokenVaultError } from './errors';

export type GitHubOperation = 'github.repositories.read' | 'github.contents.read' | 'github.issues.list' | 'github.issues.create';

export interface TokenVaultOptions {
  /** Control plane base URL. Default: $TOKEN_VAULT_URL, then http://localhost:4000. */
  baseUrl?: string;
  /**
   * This agent's Token Vault API credential (tvak_…), or a sub-agent's delegation token
   * (tvdt_…, from delegate()). Default: $TOKEN_VAULT_API_KEY.
   */
  apiKey?: string;
  /** Request timeout in milliseconds (default 30 000). */
  timeoutMs?: number;
  /** Optional organization slug, used only to attribute failed authentication in the audit log. */
  organization?: string;
  /** Custom fetch (tests, proxies). Default: global fetch. */
  fetch?: typeof fetch;
  /**
   * Called (once per expiry) when Token Vault says this key was rotated and is only
   * accepted until `expiresAt` (a rotation grace period): switch to the new key before then.
   */
  onKeyExpiry?: (expiresAt: string) => void;
  /**
   * Act on behalf of a user on every request: a signed user token (JWT) from an issuer
   * registered in Token Vault, or a function returning a fresh one. See forUser().
   */
  userToken?: UserTokenSource;
}

/** A user token, or a function that returns a fresh one (called before each request). */
export type UserTokenSource = string | (() => string | Promise<string>);

export interface ExecuteOptions {
  integrationId: string;
  operation: GitHubOperation | (string & {});
  /** Resource fields named by the provider definition (GitHub: repository, path; Slack: channel; …). */
  resource?: Record<string, string>;
  input?: Record<string, unknown>;
  /** Makes retries of creating operations safe. Generated automatically when omitted. */
  idempotencyKey?: string;
  /**
   * An approval of exactly this request (REQUIRE_APPROVAL policies). Optional: re-sending
   * the identical request after approval works without it.
   */
  approvalId?: string;
  /** Act on behalf of this user for this request (a signed user token). Overrides the client's userToken. */
  onBehalfOf?: string;
}

export interface DelegateOptions {
  /** The grant to delegate from (omit when a sub-agent delegates further: it can only use its own). */
  grantId?: string;
  /** What the sub-agent is for; shown to administrators and in the audit log. */
  label: string;
  /** Operations to delegate: within the grant (or this delegation), never destructive. */
  operations: string[];
  /** Primary resources (repositories, channels, …) to delegate. Empty: as the grant (or this delegation) allows. */
  resources?: string[];
  /** Lifetime in seconds (60 to 86 400, default 3600); never beyond the grant, the parent delegation or the user token. */
  expiresInSeconds?: number;
  /** Cap on authorized requests over the delegation's life. */
  maxRequests?: number;
  /** Delegate on behalf of this user (a signed user token): every request of the sub-agent is made for them. Defaults to the client's user (forUser). */
  onBehalfOf?: string;
}

/** A new delegation, with its token: give the token to the sub-agent; it is not shown again. */
export type DelegationResult = AgentDelegationBody & { token: string };

export interface WaitForApprovalOptions {
  /** Give up after this long (default 10 minutes). Throws a TokenVaultError with code APPROVAL_WAIT_TIMEOUT. */
  timeoutMs?: number;
  /** Polling interval (default 5 seconds, at least 1 second). */
  intervalMs?: number;
  signal?: AbortSignal;
}

export interface RequestAccessOptions {
  integrationId: string;
  operations: (GitHubOperation | (string & {}))[];
  repositories?: string[];
  /** Why the agent needs access. Shown to the approving human (10–500 characters). */
  justification: string;
  /** Requested grant lifetime, 15–480 minutes (default 60). Approvers may shorten it. */
  durationMinutes?: number;
  /** Request ID of the denial that prompted this request, for the approver's context. */
  deniedRequestId?: string;
}

export type AccessRequestResult = AgentAccessRequestBody & { duplicate?: boolean; message?: string };

export interface ExecuteResult<T = unknown> {
  /** Sanitized upstream response (never contains the provider credential). */
  data: T;
  requestId: string;
  upstreamStatus: number | null;
  simulated: boolean;
  durationMs: number;
  idempotentReplay: boolean;
  response: ExecuteResponseBody;
}

const KEY_PATTERN = /^tv(ak|dt)_[0-9a-f]{12}_[A-Za-z0-9_-]{20,64}$/;

/**
 * Client for the Token Vault agent API. The agent authenticates with its own API key;
 * it never sees the provider credential, which the customer webhook injects upstream.
 *
 * The API key is held in a private field, so it does not appear in logs,
 * JSON.stringify(client) or util.inspect(client).
 */
export class TokenVault {
  readonly baseUrl: string;
  readonly #apiKey: string;
  readonly #timeoutMs: number;
  readonly #organization: string | undefined;
  readonly #fetch: typeof fetch;
  readonly #onKeyExpiry: ((expiresAt: string) => void) | undefined;
  readonly #userToken: UserTokenSource | undefined;
  readonly #options: TokenVaultOptions;
  #keyExpiresAt: string | null = null;

  constructor(options: TokenVaultOptions = {}) {
    const apiKey = options.apiKey ?? process.env.TOKEN_VAULT_API_KEY ?? '';
    if (!KEY_PATTERN.test(apiKey)) {
      throw new AuthenticationError('A Token Vault agent API key (tvak_…) or delegation token (tvdt_…) is required: pass apiKey or set TOKEN_VAULT_API_KEY', { code: 'MISSING_API_KEY' });
    }
    this.#apiKey = apiKey;
    this.baseUrl = (options.baseUrl ?? process.env.TOKEN_VAULT_URL ?? 'http://localhost:4000').replace(/\/+$/, '');
    this.#timeoutMs = options.timeoutMs ?? 30_000;
    this.#organization = options.organization;
    this.#fetch = options.fetch ?? fetch;
    this.#onKeyExpiry = options.onKeyExpiry;
    this.#userToken = options.userToken;
    this.#options = { ...options, apiKey };
  }

  /**
   * A client that acts on behalf of one user: every request carries that user's token, and
   * Token Vault limits it to what both the agent's grant and the user's token permit.
   * Pass a function to fetch a fresh token per request. The token is never logged or serialized.
   */
  forUser(userToken: UserTokenSource): TokenVault {
    return new TokenVault({ ...this.#options, userToken });
  }

  /** True when this client is a sub-agent, authenticated with a delegation token (tvdt_…). */
  get isDelegated(): boolean {
    return this.#apiKey.startsWith('tvdt_');
  }

  /** True when this client acts on behalf of a user. */
  get actsForUser(): boolean {
    return this.#userToken !== undefined;
  }

  /**
   * Set when Token Vault reported that this key was rotated and stops working at this time
   * (grace period); null while the key is the agent's current one.
   */
  get keyExpiresAt(): string | null {
    return this.#keyExpiresAt;
  }

  /** Public key identifier of the configured credential (safe to log). */
  get keyId(): string {
    return this.#apiKey.split('_')[1]!;
  }

  toJSON() {
    return { baseUrl: this.baseUrl, keyId: this.keyId, actsForUser: this.actsForUser };
  }

  [Symbol.for('nodejs.util.inspect.custom')]() {
    return `TokenVault { baseUrl: '${this.baseUrl}', keyId: '${this.keyId}'${this.actsForUser ? ', actsForUser: true' : ''} }`;
  }

  /**
   * Requests an operation and returns the sanitized result. Throws AccessDeniedError,
   * ExecutionFailedError or AuthenticationError (all TokenVaultError) otherwise.
   */
  async execute<T = unknown>(options: ExecuteOptions): Promise<ExecuteResult<T>> {
    const { httpStatus, body } = await this.executeRaw(options);
    if (body.decision === 'ALLOW' && body.execution.status === 'SUCCEEDED') {
      return {
        data: body.result as T,
        requestId: body.request_id,
        upstreamStatus: body.execution.upstream_status,
        simulated: body.execution.simulated,
        durationMs: body.execution.duration_ms,
        idempotentReplay: body.execution.idempotent_replay,
        response: body,
      };
    }
    const opts = { code: body.decision_code, httpStatus, requestId: body.request_id, response: body };
    if (body.decision_code === 'AGENT_UNAUTHENTICATED') throw new AuthenticationError(body.reason, opts);
    if (body.decision_code === 'APPROVAL_REQUIRED' && body.approval) {
      throw new ApprovalRequiredError(body.reason, { ...opts, approvalId: body.approval.approval_id, approvalExpiresAt: body.approval.expires_at });
    }
    if (body.decision === 'DENY') throw new AccessDeniedError(body.reason, opts);
    throw new ExecutionFailedError(body.reason, opts);
  }

  /** Like execute(), but returns the full decision for every outcome instead of throwing. */
  async executeRaw(options: ExecuteOptions): Promise<{ httpStatus: number; body: ExecuteResponseBody }> {
    const payload: ExecuteRequestBody = {
      integration_id: options.integrationId,
      operation: options.operation,
      resource: options.resource ?? {},
      input: options.input ?? {},
      idempotency_key: options.idempotencyKey ?? `sdk-${randomUUID()}`,
      ...(options.approvalId ? { approval_id: options.approvalId } : {}),
    };
    const userToken = options.onBehalfOf ?? (typeof this.#userToken === 'function' ? await this.#userToken() : this.#userToken);
    if (userToken) payload.on_behalf_of = userToken;
    const res = await this.#request('POST', '/agent/v1/execute', payload);
    const body = (await this.#json(res)) as ExecuteResponseBody | null;
    if (!body || typeof body.decision !== 'string') {
      throw new TokenVaultError(`Unexpected response from Token Vault (HTTP ${res.status})`, { code: 'UNEXPECTED_RESPONSE', httpStatus: res.status });
    }
    return { httpStatus: res.status, body };
  }

  /** What this agent may currently do: its grants, operations and repository restrictions. */
  async capabilities(): Promise<AgentCapabilitiesBody> {
    const res = await this.#request('GET', '/agent/v1/capabilities');
    const body = await this.#json(res);
    if (res.status === 401) throw new AuthenticationError('Agent credential is invalid, rotated or unknown', { code: 'AGENT_UNAUTHENTICATED', httpStatus: 401 });
    if (!res.ok) throw new TokenVaultError(`Capabilities request failed (HTTP ${res.status})`, { code: 'UNEXPECTED_RESPONSE', httpStatus: res.status });
    return body as AgentCapabilitiesBody;
  }

  /**
   * The shape of every operation of the applications this agent has a grant on (resource
   * fields, inputs, risk), from the signed provider definitions Token Vault uses.
   */
  async operations(): Promise<AgentOperationsBody> {
    const res = await this.#request('GET', '/agent/v1/operations');
    const body = await this.#json(res);
    if (res.status === 401) throw new AuthenticationError('Agent credential is invalid, rotated or unknown', { code: 'AGENT_UNAUTHENTICATED', httpStatus: 401 });
    if (!res.ok) throw new TokenVaultError(`Operations request failed (HTTP ${res.status})`, { code: 'UNEXPECTED_RESPONSE', httpStatus: res.status });
    return body as AgentOperationsBody;
  }

  /**
   * Asks a human for time-limited access (just-in-time). Resolves with the PENDING request;
   * an identical pending request is returned instead of creating a duplicate.
   */
  async requestAccess(options: RequestAccessOptions): Promise<AccessRequestResult> {
    const res = await this.#request('POST', '/agent/v1/access-requests', {
      integration_id: options.integrationId,
      operations: options.operations,
      repositories: options.repositories ?? [],
      justification: options.justification,
      duration_minutes: options.durationMinutes ?? 60,
      ...(options.deniedRequestId ? { denied_request_id: options.deniedRequestId } : {}),
    });
    const body = (await this.#json(res)) as (AccessRequestResult & { error?: { code: string; message: string } }) | null;
    if (res.status === 401) throw new AuthenticationError('Agent credential is invalid, rotated or unknown', { code: 'AGENT_UNAUTHENTICATED', httpStatus: 401 });
    if (!res.ok || !body) throw new TokenVaultError(body?.error?.message ?? `Access request failed (HTTP ${res.status})`, { code: body?.error?.code ?? 'UNEXPECTED_RESPONSE', httpStatus: res.status });
    return body;
  }

  /**
   * Hands a narrower, short-lived slice of a grant to a sub-agent. Returns the delegation
   * with its token, shown once: start the sub-agent with `new TokenVault({ apiKey: d.token })`.
   * Everything the sub-agent does is checked against this agent's grant too, and revoking
   * the delegation (or the grant) stops it and everything it delegated further.
   */
  async delegate(options: DelegateOptions): Promise<DelegationResult> {
    const userToken = options.onBehalfOf ?? (this.isDelegated ? undefined : typeof this.#userToken === 'function' ? await this.#userToken() : this.#userToken);
    const res = await this.#request('POST', '/agent/v1/delegations', {
      ...(options.grantId ? { grant_id: options.grantId } : {}),
      label: options.label,
      operations: options.operations,
      resources: options.resources ?? [],
      ...(options.expiresInSeconds ? { expires_in_seconds: options.expiresInSeconds } : {}),
      ...(options.maxRequests ? { max_requests: options.maxRequests } : {}),
      ...(userToken ? { on_behalf_of: userToken } : {}),
    });
    return this.#delegationResult<DelegationResult>(res, 'Delegation failed');
  }

  /** Delegations this agent made (a sub-agent: those it made further), with their status and use. */
  async listDelegations(): Promise<AgentDelegationBody[]> {
    const res = await this.#request('GET', '/agent/v1/delegations');
    return (await this.#delegationResult<{ items: AgentDelegationBody[] }>(res, 'Listing delegations failed')).items;
  }

  /** Revokes a delegation; everything delegated from it stops too. */
  async revokeDelegation(id: string, reason = ''): Promise<AgentDelegationBody> {
    const res = await this.#request('POST', `/agent/v1/delegations/${encodeURIComponent(id)}/revoke`, { reason });
    return this.#delegationResult<AgentDelegationBody>(res, 'Revoking the delegation failed');
  }

  async #delegationResult<T>(res: Response, what: string): Promise<T> {
    const body = (await this.#json(res)) as (T & { error?: { code: string; message: string; details?: { fields?: Record<string, string> } } }) | null;
    if (res.status === 401) throw new AuthenticationError('Credential is invalid, revoked, expired or unknown', { code: 'AGENT_UNAUTHENTICATED', httpStatus: 401 });
    if (!res.ok || !body) {
      const fields = body?.error?.details?.fields;
      const detail = fields ? `: ${Object.values(fields).join('; ')}` : '';
      throw new TokenVaultError(`${body?.error?.message ?? `${what} (HTTP ${res.status})`}${detail}`, { code: body?.error?.code ?? 'UNEXPECTED_RESPONSE', httpStatus: res.status });
    }
    return body;
  }

  /** Status of one of this agent's own access requests (PENDING, APPROVED, REJECTED, EXPIRED). */
  async getAccessRequest(id: string): Promise<AgentAccessRequestBody> {
    const res = await this.#request('GET', `/agent/v1/access-requests/${encodeURIComponent(id)}`);
    const body = await this.#json(res);
    if (res.status === 401) throw new AuthenticationError('Agent credential is invalid, rotated or unknown', { code: 'AGENT_UNAUTHENTICATED', httpStatus: 401 });
    if (res.status === 404) throw new TokenVaultError(`Access request ${id} not found`, { code: 'NOT_FOUND', httpStatus: 404 });
    if (!res.ok) throw new TokenVaultError(`Access request lookup failed (HTTP ${res.status})`, { code: 'UNEXPECTED_RESPONSE', httpStatus: res.status });
    return body as AgentAccessRequestBody;
  }

  /** An approval one of this agent's requests waits for: PENDING, APPROVED, REJECTED, EXPIRED or EXECUTED. */
  async getApproval(id: string): Promise<AgentApprovalBody> {
    const res = await this.#request('GET', `/agent/v1/approvals/${encodeURIComponent(id)}`);
    const body = await this.#json(res);
    if (res.status === 401) throw new AuthenticationError('Agent credential is invalid, rotated or unknown', { code: 'AGENT_UNAUTHENTICATED', httpStatus: 401 });
    if (res.status === 404) throw new TokenVaultError(`Approval ${id} not found`, { code: 'NOT_FOUND', httpStatus: 404 });
    if (!res.ok) throw new TokenVaultError(`Approval lookup failed (HTTP ${res.status})`, { code: 'UNEXPECTED_RESPONSE', httpStatus: res.status });
    return body as AgentApprovalBody;
  }

  /** Polls an approval until a human decides (or it lapses), and returns it. */
  async waitForApproval(id: string, options: WaitForApprovalOptions = {}): Promise<AgentApprovalBody> {
    const deadline = Date.now() + (options.timeoutMs ?? 10 * 60_000);
    const interval = Math.max(1000, options.intervalMs ?? 5000);
    for (;;) {
      const a = await this.getApproval(id);
      if (a.status !== 'PENDING') return a;
      if (Date.now() + interval > deadline) throw new TokenVaultError(`Approval ${id} is still pending`, { code: 'APPROVAL_WAIT_TIMEOUT' });
      await new Promise<void>((resolve, reject) => {
        const t = setTimeout(resolve, interval);
        options.signal?.addEventListener('abort', () => (clearTimeout(t), reject(options.signal!.reason)), { once: true });
      });
    }
  }

  /**
   * Runs the request an approval was given for, exactly as it was approved (same
   * integration, operation, resource, input and user). Throws like execute(). When the
   * request was made for a user, this client must act for that user (forUser) or
   * `onBehalfOf` must carry a fresh token for them.
   */
  async executeApproved<T = unknown>(approvalId: string, options: { onBehalfOf?: string } = {}): Promise<ExecuteResult<T>> {
    const a = await this.getApproval(approvalId);
    return this.execute<T>({ integrationId: a.integration_id, operation: a.operation, resource: a.resource, input: a.input, approvalId, ...(options.onBehalfOf ? { onBehalfOf: options.onBehalfOf } : {}) });
  }

  /** One of this agent's own past requests, by request ID. */
  async getRequest(requestId: string): Promise<Record<string, unknown>> {
    const res = await this.#request('GET', `/agent/v1/requests/${encodeURIComponent(requestId)}`);
    const body = await this.#json(res);
    if (res.status === 401) throw new AuthenticationError('Agent credential is invalid, rotated or unknown', { code: 'AGENT_UNAUTHENTICATED', httpStatus: 401 });
    if (res.status === 404) throw new TokenVaultError(`Request ${requestId} not found`, { code: 'NOT_FOUND', httpStatus: 404 });
    if (!res.ok) throw new TokenVaultError(`Request lookup failed (HTTP ${res.status})`, { code: 'UNEXPECTED_RESPONSE', httpStatus: res.status });
    return body as Record<string, unknown>;
  }

  async #request(method: 'GET' | 'POST', path: string, body?: unknown): Promise<Response> {
    const headers: Record<string, string> = { authorization: `Bearer ${this.#apiKey}`, accept: 'application/json' };
    if (body !== undefined) headers['content-type'] = 'application/json';
    if (this.#organization) headers['x-token-vault-org'] = this.#organization;
    let res: Response;
    try {
      res = await this.#fetch(`${this.baseUrl}${path}`, { method, headers, body: body === undefined ? undefined : JSON.stringify(body), signal: AbortSignal.timeout(this.#timeoutMs) });
    } catch (e) {
      const timeout = (e as Error).name === 'TimeoutError';
      throw new TokenVaultError(timeout ? `Token Vault did not respond within ${this.#timeoutMs} ms` : `Cannot reach Token Vault at ${this.baseUrl}`, { code: timeout ? 'TIMEOUT' : 'NETWORK_ERROR' });
    }
    if (res.status !== 401) {
      const expires = res.headers?.get?.('token-vault-key-expires') ?? null;
      if (expires && expires !== this.#keyExpiresAt) this.#onKeyExpiry?.(expires);
      this.#keyExpiresAt = expires;
    }
    return res;
  }

  async #json(res: Response): Promise<unknown> {
    try {
      return await res.json();
    } catch {
      return null;
    }
  }
}
