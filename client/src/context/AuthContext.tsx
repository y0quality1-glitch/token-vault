import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from 'react';
import type { Permission, SessionInfo } from '@token-vault/shared';
import { ApiError, api } from '@/lib/api';

interface AuthValue {
  session: SessionInfo | null;
  loading: boolean;
  login: (email: string, password: string) => Promise<SessionInfo>;
  logout: () => Promise<void>;
  selectOrganization: (organizationId: string) => Promise<SessionInfo>;
  refresh: () => Promise<void>;
  can: (permission: Permission) => boolean;
}

const AuthContext = createContext<AuthValue | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [session, setSession] = useState<SessionInfo | null>(null);
  const [loading, setLoading] = useState(true);

  const refresh = useCallback(async () => {
    try {
      setSession(await api.get<SessionInfo>('/auth/me'));
    } catch (e) {
      if (e instanceof ApiError && e.status === 401) setSession(null);
      else throw e;
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void refresh().catch(() => setLoading(false));
    const onUnauthorized = () => setSession(null);
    window.addEventListener('tv:unauthorized', onUnauthorized);
    return () => window.removeEventListener('tv:unauthorized', onUnauthorized);
  }, [refresh]);

  const value = useMemo<AuthValue>(
    () => ({
      session,
      loading,
      refresh,
      login: async (email, password) => {
        const s = await api.post<SessionInfo>('/auth/login', { email, password });
        setSession(s);
        return s;
      },
      logout: async () => {
        await api.post('/auth/logout').catch(() => undefined);
        setSession(null);
      },
      selectOrganization: async (organizationId) => {
        const s = await api.post<SessionInfo>('/auth/select-organization', { organizationId });
        setSession(s);
        return s;
      },
      can: (permission) => !!session?.permissions.includes(permission),
    }),
    [session, loading, refresh],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error('useAuth must be used inside AuthProvider');
  return ctx;
}
