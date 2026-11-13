import { useCallback, useEffect, useRef, useState } from 'react';
import type { ApiState } from '@tv-hooks/useApi';
import { ApiError } from '@/lib/api';

/**
 * Like the console's useApi, for the CMS API's POST queries (/getall, /getdatabyid): runs
 * `fetcher` on mount and whenever `key` changes, with reload and race protection.
 */
export function useQuery<T>(key: string | null, fetcher: () => Promise<T>): ApiState<T> {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<ApiError | null>(null);
  const [loading, setLoading] = useState(key !== null);
  const seq = useRef(0);
  const fetchRef = useRef(fetcher);
  fetchRef.current = fetcher;

  const load = useCallback(async () => {
    if (key === null) return;
    const id = ++seq.current;
    setLoading(true);
    try {
      const d = await fetchRef.current();
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
