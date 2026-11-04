import { useState } from 'react';
import { Navigate, useNavigate } from 'react-router-dom';
import { Building2, ChevronRight, ShieldCheck } from 'lucide-react';
import { ROLE_LABELS } from '@token-vault/shared';
import { useAuth } from '@/context/AuthContext';
import { Spinner } from '@/components/ui/feedback';
import { useToast } from '@/components/ui/toast';

export function SelectOrgPage() {
  const { session, loading, selectOrganization, logout } = useAuth();
  const navigate = useNavigate();
  const toast = useToast();
  const [pending, setPending] = useState<string | null>(null);

  if (loading) return <Spinner className="min-h-screen" />;
  if (!session) return <Navigate to="/login" replace />;

  return (
    <div className="flex min-h-screen items-center justify-center bg-slate-50 px-4">
      <div className="w-full max-w-md">
        <div className="mb-6 flex items-center gap-2">
          <ShieldCheck className="h-7 w-7 text-brand-600" />
          <span className="text-lg font-semibold">Token Vault</span>
        </div>
        <h1 className="text-xl font-semibold tracking-tight text-slate-900">Select an organization</h1>
        <p className="mt-1 text-sm text-slate-500">Signed in as {session.user.email}. You belong to {session.memberships.length} organizations.</p>
        <div className="mt-6 space-y-2">
          {session.memberships.map((m) => (
            <button
              key={m.organizationId}
              disabled={!!pending}
              onClick={async () => {
                setPending(m.organizationId);
                try {
                  await selectOrganization(m.organizationId);
                  navigate('/', { replace: true });
                } catch (e) {
                  toast.error('Could not select organization', (e as Error).message);
                  setPending(null);
                }
              }}
              className="flex w-full items-center gap-3 rounded-xl border border-slate-200 bg-white p-4 text-left shadow-card transition hover:border-brand-300 hover:shadow-md disabled:opacity-60"
            >
              <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-brand-50 text-brand-600">
                <Building2 className="h-5 w-5" />
              </div>
              <div className="min-w-0 flex-1">
                <p className="font-medium text-slate-900">{m.organizationName}</p>
                <p className="text-sm text-slate-500">
                  {ROLE_LABELS[m.role]} · <span className="font-mono text-xs">{m.organizationSlug}</span>
                </p>
              </div>
              <ChevronRight className="h-4 w-4 text-slate-400" />
            </button>
          ))}
        </div>
        <button onClick={() => logout().then(() => navigate('/login'))} className="mt-6 text-sm text-slate-500 hover:text-slate-800">
          Sign in with a different account
        </button>
      </div>
    </div>
  );
}
