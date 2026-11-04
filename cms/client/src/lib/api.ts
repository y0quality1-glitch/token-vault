import type { ApiErrorBody } from '@token-vault/shared';

/** Same shape as the console's ApiError, so the shared UI components and hooks work unchanged. */
export class ApiError extends Error {
  constructor(
    public status: number,
    public code: string,
    message: string,
    public details?: { fields?: Record<string, string>; issues?: string[] } & Record<string, unknown>,
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
    res = await fetch(path.startsWith('/catalog/') ? path : `/api/v1${path}`, {
      method,
      credentials: 'same-origin', // httpOnly session cookie only
      headers: body === undefined ? undefined : { 'content-type': 'application/json' },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
  } catch {
    throw new ApiError(0, 'NETWORK_ERROR', 'Cannot reach the CMS API. Is it running on port 4200?');
  }
  const text = await res.text();
  const json = text ? JSON.parse(text) : {};
  if (!res.ok) {
    const err = (json as ApiErrorBody).error ?? { code: 'HTTP_' + res.status, message: res.statusText };
    if (res.status === 401 && !path.startsWith('/auth/')) window.dispatchEvent(new CustomEvent('cms:unauthorized'));
    throw new ApiError(res.status, err.code, err.message, err.details as ApiError['details']);
  }
  return json as T;
}

export const api = {
  get: <T>(path: string) => request<T>('GET', path),
  post: <T>(path: string, body: unknown = {}) => request<T>('POST', path, body),
  put: <T>(path: string, body: unknown) => request<T>('PUT', path, body),
};
