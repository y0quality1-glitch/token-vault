import { createContext, useCallback, useContext, useEffect, useState, type ReactNode } from 'react';
import type { CmsSession, CmsUser } from '@token-vault/shared';
import { ApiError, api } from '@/lib/api';

interface AuthState {
  user: CmsUser | null;
  loading: boolean;
  login: (email: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
}

const Ctx = createContext<AuthState | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<CmsUser | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api
      .get<CmsSession>('/auth/me')
      .then((s) => setUser(s.user))
      .catch((e) => {
        if (!(e instanceof ApiError) || e.status !== 401) console.warn('session check failed');
      })
      .finally(() => setLoading(false));
    const onUnauthorized = () => setUser(null);
    window.addEventListener('cms:unauthorized', onUnauthorized);
    return () => window.removeEventListener('cms:unauthorized', onUnauthorized);
  }, []);

  const login = useCallback(async (email: string, password: string) => {
    const s = await api.post<CmsSession>('/auth/login', { email, password });
    setUser(s.user);
  }, []);
  const logout = useCallback(async () => {
    await api.post('/auth/logout').catch(() => undefined);
    setUser(null);
  }, []);

  return <Ctx.Provider value={{ user, loading, login, logout }}>{children}</Ctx.Provider>;
}

export function useAuth() {
  const v = useContext(Ctx);
  if (!v) throw new Error('useAuth outside AuthProvider');
  return v;
}

export const ROLE_LABELS: Record<CmsUser['role'], string> = { EDITOR: 'Editor', PUBLISHER: 'Publisher', ADMIN: 'Administrator' };
