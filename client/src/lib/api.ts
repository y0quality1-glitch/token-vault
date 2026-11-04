import type { ApiErrorBody, ExecuteRequestBody, ExecuteResponseBody } from '@token-vault/shared';

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
  const json = text ? JSON.parse(text) : {};
  if (!res.ok) {
    const err = (json as ApiErrorBody).error ?? { code: 'HTTP_' + res.status, message: res.statusText };
    if (res.status === 401 && !path.startsWith('/auth/')) window.dispatchEvent(new CustomEvent('tv:unauthorized'));
    throw new ApiError(res.status, err.code, err.message, err.details as ApiError['details']);
  }
  return json as T;
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
 */
export async function executeAsAgent(apiKey: string, body: ExecuteRequestBody, orgSlug: string): Promise<{ httpStatus: number; body: ExecuteResponseBody }> {
  const res = await fetch('/agent/v1/execute', {
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
  return { httpStatus: res.status, body: (await res.json()) as ExecuteResponseBody };
}

export function qs(params: Record<string, string | undefined | null>): string {
  const p = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) if (v) p.set(k, v);
  const s = p.toString();
  return s ? `?${s}` : '';
}
