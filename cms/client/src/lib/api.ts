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

/** The CMS API's response envelope (admin routes). The signed catalog (/catalog/v1) is served as-is. */
interface Envelope<T> {
  status: string;
  msg: string;
  error: string | null;
  code?: string;
  details: T;
  totalRecords: number;
}

/** A /getall page: the records and the total across pages. */
export interface Page<T> {
  items: T[];
  totalRecords: number;
}

const SUCCESS = '10000';

async function raw<T>(method: string, path: string, body?: unknown): Promise<{ data: T; totalRecords: number }> {
  const catalog = path.startsWith('/catalog/');
  let res: Response;
  try {
    res = await fetch(catalog ? path : `/api/v1${path}`, {
      method,
      credentials: 'same-origin', // httpOnly session cookie only
      headers: body === undefined ? undefined : { 'content-type': 'application/json' },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
  } catch {
    throw new ApiError(0, 'NETWORK_ERROR', 'Cannot reach the CMS API. Is it running on port 4200?');
  }
  const text = await res.text();
  let json: unknown = {};
  try {
    json = text ? JSON.parse(text) : {};
  } catch {
    throw new ApiError(res.status, 'HTTP_' + res.status, res.statusText || 'Unexpected response from the CMS API');
  }
  const env = json as Partial<Envelope<T>>;
  if (!res.ok || (env.status !== undefined && env.status !== SUCCESS)) {
    if (res.status === 401 && !path.startsWith('/auth/')) window.dispatchEvent(new CustomEvent('cms:unauthorized'));
    throw new ApiError(res.status, env.code ?? 'HTTP_' + res.status, env.error ?? res.statusText, (env.details ?? undefined) as ApiError['details']);
  }
  if (catalog) return { data: json as T, totalRecords: 0 };
  return { data: env.details as T, totalRecords: env.totalRecords ?? 0 };
}

const request = async <T>(method: string, path: string, body?: unknown): Promise<T> => (await raw<T>(method, path, body)).data;

export const api = {
  get: <T>(path: string) => request<T>('GET', path),
  post: <T>(path: string, body: unknown = {}) => request<T>('POST', path, body),
  put: <T>(path: string, body: unknown) => request<T>('PUT', path, body),
  /** POST a /getall route: `{ items, totalRecords }`. */
  page: async <T>(path: string, body: unknown = {}): Promise<Page<T>> => {
    const r = await raw<T[]>('POST', path, body);
    return { items: r.data, totalRecords: r.totalRecords };
  },
};
