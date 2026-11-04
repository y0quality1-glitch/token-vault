import type { ReactNode } from 'react';
import { Navigate, useLocation } from 'react-router-dom';
import type { Permission } from '@token-vault/shared';
import { useAuth } from '@/context/AuthContext';
import { PermissionDenied, Spinner } from '@/components/ui/feedback';

export function RequireAuth({ children }: { children: ReactNode }) {
  const { session, loading } = useAuth();
  const location = useLocation();
  if (loading) return <Spinner className="min-h-screen" label="Loading Token Vault…" />;
  if (!session) return <Navigate to="/login" replace state={{ from: location.pathname }} />;
  if (!session.currentOrganization) return <Navigate to="/select-org" replace />;
  return <>{children}</>;
}

/** Route-level permission gate that renders the permission-denied state. */
export function RequirePermission({ permission, children }: { permission: Permission; children: ReactNode }) {
  const { can, session } = useAuth();
  if (!can(permission)) {
    return <PermissionDenied required={permission} message={`Your role (${session?.role?.replace('_', ' ').toLowerCase()}) does not include access to this area.`} />;
  }
  return <>{children}</>;
}

/** Inline gate for actions: renders children only when permitted. */
export function Can({ permission, children, fallback = null }: { permission: Permission; children: ReactNode; fallback?: ReactNode }) {
  const { can } = useAuth();
  return <>{can(permission) ? children : fallback}</>;
}
