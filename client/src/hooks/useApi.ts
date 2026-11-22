import { useCallback, useEffect, useRef, useState } from 'react';
import { ApiError, api } from '@/lib/api';

export interface ApiState<T> {
  data: T | null;
  error: ApiError | null;
  loading: boolean;
  reload: () => Promise<void>;
  setData: (d: T) => void;
}

/**
 * Generic data-fetching hook with reload and race protection. `key` identifies the request:
 * the fetcher runs on mount and whenever `key` changes (null = don't fetch). `reload()` re-runs
 * the latest fetcher.
 */
export function useQuery<T>(key: string | null, fetcher: () => Promise<T>): ApiState<T> {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<ApiError | null>(null);
  const [loading, setLoading] = useState(key !== null);
  const seq = useRef(0);
  const fetcherRef = useRef(fetcher);
  fetcherRef.current = fetcher;

  const load = useCallback(async () => {
    if (key === null) return;
    const id = ++seq.current;
    setLoading(true);
    try {
      const d = await fetcherRef.current();
      if (id === seq.current) {
        setData(d);
        setError(null);
      }
    } catch (e) {
      if (id === seq.current) setError(e instanceof ApiError ? e : new ApiError(0, 'UNKNOWN', String(e)));
    } finally {
      if (id === seq.current) setLoading(false);
    }
  }, [key]);

  useEffect(() => {
    void load();
  }, [load]);

  return { data, error, loading, reload: load, setData };
}

/** Minimal data-fetching hook (GET) with reload and race protection. */
export function useApi<T>(path: string | null): ApiState<T> {
  return useQuery<T>(path, () => api.get<T>(path as string));
}

/**
 * Data-fetching hook for POST queries (list/report routes such as `/agent/getall` that take
 * their filters in a JSON body). Refetches when `path` or the serialized `body` changes.
 */
export function usePost<T>(path: string | null, body: unknown = {}): ApiState<T> {
  const serialized = JSON.stringify(body ?? {});
  return useQuery<T>(path === null ? null : `POST ${path} ${serialized}`, () => api.post<T>(path as string, JSON.parse(serialized)));
}

/** Wraps an async mutation with pending state and field-level validation errors. */
export function useMutation<A extends unknown[], R>(fn: (...args: A) => Promise<R>) {
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<ApiError | null>(null);
  const run = useCallback(
    async (...args: A): Promise<R | undefined> => {
      setPending(true);
      setError(null);
      try {
        return await fn(...args);
      } catch (e) {
        setError(e instanceof ApiError ? e : new ApiError(0, 'UNKNOWN', String(e)));
        return undefined;
      } finally {
        setPending(false);
      }
    },
    [fn],
  );
  return { run, pending, error, setError, fieldErrors: error?.fieldErrors ?? {} };
}
