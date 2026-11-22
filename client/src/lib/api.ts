import type { ExecuteRequestBody, ExecuteResponseBody } from '@token-vault/shared';

/**
 * Response envelope used by every admin (/api/v1) and agent (/agent/v1) route.
 * `details` is the route's payload on success and the error's extra data on failure.
 */
export interface ApiEnvelope<T = unknown> {
  status: '10000' | '10001';
  msg: string;
  error: string | null;
  code?: string;
  details: T;
  totalRecords: number;
}

function isEnvelope(json: unknown): json is ApiEnvelope {
  return typeof json === 'object' && json !== null && ((json as { status?: unknown }).status === '10000' || (json as { status?: unknown }).status === '10001');
}

export class ApiError extends Error {
  constructor(
    public status: number,
    public code: string,
    message: string,
    public details?: { fields?: Record<string, string> } & Record<string, unknown>,
  ) {
    super(message);
  }
  get fieldErrors(): Record<string, string> {
    return this.details?.fields ?? {};
  }
}

async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
  let res: Response;
  try {
    res = await fetch(`/api/v1${path}`, {
      method,
      credentials: 'same-origin', // httpOnly session cookie; no tokens in JS-accessible storage
      headers: body === undefined ? undefined : { 'content-type': 'application/json' },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
  } catch {
    throw new ApiError(0, 'NETWORK_ERROR', 'Cannot reach the Token Vault API. Is the control plane running on port 4000?');
  }
  const text = await res.text();
  let json: unknown = {};
  try {
    json = text ? JSON.parse(text) : {};
  } catch {
    json = {};
  }
  const envelope = isEnvelope(json) ? json : null;
  if (!res.ok || envelope?.status === '10001') {
    if (res.status === 401 && !path.startsWith('/auth/')) window.dispatchEvent(new CustomEvent('tv:unauthorized'));
    const status = res.ok ? 400 : res.status;
    if (envelope) {
      const details = envelope.details && typeof envelope.details === 'object' ? (envelope.details as ApiError['details']) : undefined;
      throw new ApiError(status, envelope.code ?? 'HTTP_' + status, envelope.error ?? (res.statusText || 'Request failed'), details);
    }
    // Non-envelope failure (e.g. a proxy error page or a legacy { error: { code, message, details } } body).
    const legacy = (json as { error?: { code?: string; message?: string; details?: unknown } }).error;
    throw new ApiError(status, legacy?.code ?? 'HTTP_' + status, legacy?.message ?? res.statusText, legacy?.details as ApiError['details']);
  }
  return (envelope ? envelope.details : json) as T;
}

export const api = {
  get: <T>(path: string) => request<T>('GET', path),
  post: <T>(path: string, body: unknown = {}) => request<T>('POST', path, body),
  patch: <T>(path: string, body: unknown) => request<T>('PATCH', path, body),
  put: <T>(path: string, body: unknown) => request<T>('PUT', path, body),
  del: <T>(path: string) => request<T>('DELETE', path),
};

/**
 * Calls the agent execution API exactly as an external agent would: authenticated
 * only by the agent API credential. The admin session cookie is NOT sent.
 * The decision (allowed or denied) is always in the envelope's `details`.
 */
export async function executeAsAgent(apiKey: string, body: ExecuteRequestBody, orgSlug: string): Promise<{ httpStatus: number; body: ExecuteResponseBody }> {
  const res = await fetch('/agent/v1/request/execute', {
    method: 'POST',
    credentials: 'omit',
    headers: {
      'content-type': 'application/json',
      authorization: `Bearer ${apiKey}`,
      'x-token-vault-org': orgSlug,
      'x-token-vault-client': 'playground',
    },
    body: JSON.stringify(body),
  });
  let json: unknown = null;
  try {
    json = await res.json();
  } catch {
    json = null;
  }
  const payload = isEnvelope(json) ? json.details : json;
  if (!payload || typeof payload !== 'object' || !('decision' in payload)) {
    // Not a decision (e.g. rate limited, wrong method, proxy error): surface the envelope's error.
    const env = isEnvelope(json) ? json : null;
    throw new ApiError(res.status, env?.code ?? 'HTTP_' + res.status, env?.error ?? (res.statusText || 'Unexpected response from the agent API'));
  }
  return { httpStatus: res.status, body: payload as ExecuteResponseBody };
}

/** Drops empty filter values, so POST query bodies carry only the filters that are set (as the old query strings did). */
export function compact(params: Record<string, string | undefined | null>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(params)) if (v) out[k] = v;
  return out;
}
