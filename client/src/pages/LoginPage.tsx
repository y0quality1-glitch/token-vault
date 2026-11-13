import { useState, type FormEvent } from 'react';
import { Navigate, useNavigate } from 'react-router-dom';
import { Bot, KeyRound, Lock, ShieldCheck } from 'lucide-react';
import { ROLE_LABELS, type Role } from '@token-vault/shared';
import { useAuth } from '@/context/AuthContext';
import { ApiError, api } from '@/lib/api';
import { Button } from '@/components/ui/button';
import { Field, Input } from '@/components/ui/form';
import { Callout } from '@/components/ui/feedback';
import { Dialog } from '@/components/ui/dialog';

const DEMO_ACCOUNTS: { email: string; role: Role; note: string }[] = [
  { email: 'owner@demo.test', role: 'OWNER', note: 'Two organizations: shows org selection' },
  { email: 'vault.admin@demo.test', role: 'VAULT_ADMIN', note: 'Webhook, integrations, grants' },
  { email: 'security@demo.test', role: 'SECURITY_ADMIN', note: 'Policies, approvals, revocation' },
  { email: 'developer@demo.test', role: 'DEVELOPER', note: 'Agents only; no audit access' },
  { email: 'auditor@demo.test', role: 'AUDITOR', note: 'Read-only' },
];
const DEMO_PASSWORD = 'TokenVault-Demo-2026';

export function LoginPage() {
  const { session, login, loading } = useAuth();
  const navigate = useNavigate();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [formError, setFormError] = useState<string | null>(null);
  const [pending, setPending] = useState(false);
  const [forgotOpen, setForgotOpen] = useState(false);
  const [forgotMsg, setForgotMsg] = useState<string | null>(null);

  if (!loading && session) return <Navigate to={session.currentOrganization ? '/' : '/select-org'} replace />;

  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    const errs: Record<string, string> = {};
    if (!/^\S+@\S+\.\S+$/.test(email)) errs.email = 'Enter a valid email address';
    if (!password) errs.password = 'Password is required';
    setErrors(errs);
    setFormError(null);
    if (Object.keys(errs).length) return;
    setPending(true);
    try {
      const s = await login(email, password);
      navigate(s.currentOrganization ? '/' : '/select-org', { replace: true });
    } catch (err) {
      setFormError(err instanceof ApiError ? err.message : 'Sign-in failed');
      setPassword('');
    } finally {
      setPending(false);
    }
  }

  return (
    <div className="grid min-h-screen lg:grid-cols-[1.1fr_1fr]">
      <div className="relative hidden flex-col justify-between overflow-hidden bg-slate-950 p-12 text-white lg:flex">
        <div className="absolute inset-0 bg-[radial-gradient(circle_at_20%_20%,rgba(59,101,245,0.35),transparent_45%),radial-gradient(circle_at_80%_80%,rgba(16,185,129,0.18),transparent_40%)]" />
        <div className="relative flex items-center gap-3">
          <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-brand-600">
            <ShieldCheck className="h-6 w-6" />
          </div>
          <span className="text-lg font-semibold">Token Vault</span>
        </div>
        <div className="relative max-w-lg space-y-8">
          <div>
            <h1 className="text-3xl font-semibold leading-tight tracking-tight">Identity-aware credential authorization and brokering for applications and AI agents.</h1>
            <p className="mt-3 text-slate-400">Agents perform authorized operations without ever possessing your long-lived provider credentials.</p>
          </div>
          <ul className="space-y-4">
            {[
              { icon: Bot, t: 'Who is requesting access?', d: 'Every agent authenticates with its own identity.' },
              { icon: KeyRound, t: 'What are they allowed to access?', d: 'Scoped, time-bound grants per integration, operation and resource.' },
              { icon: Lock, t: 'Where is the credential handled?', d: 'Only inside your customer-controlled webhook / vault runtime.' },
            ].map((x) => (
              <li key={x.t} className="flex gap-3">
                <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-white/10">
                  <x.icon className="h-4 w-4" />
                </div>
                <div>
                  <p className="font-medium">{x.t}</p>
                  <p className="text-sm text-slate-400">{x.d}</p>
                </div>
              </li>
            ))}
          </ul>
        </div>
        <p className="relative text-xs text-slate-500">Proof of concept. Mock data and simulated provider calls; not for production use.</p>
      </div>

      <div className="flex items-center justify-center bg-white px-6 py-12">
        <div className="w-full max-w-sm">
          <div className="mb-8 lg:hidden">
            <div className="flex items-center gap-2">
              <ShieldCheck className="h-7 w-7 text-brand-600" />
              <span className="text-lg font-semibold">Token Vault</span>
            </div>
          </div>
          <h2 className="text-xl font-semibold tracking-tight text-slate-900">Sign in to your workspace</h2>
          <p className="mt-1 text-sm text-slate-500">Use your organization account.</p>

          <form onSubmit={onSubmit} className="mt-6 space-y-4" noValidate>
            {formError && <Callout tone="danger">{formError}</Callout>}
            <Field label="Email" htmlFor="email" error={errors.email}>
              <Input id="email" type="email" autoComplete="username" value={email} onChange={(e) => setEmail(e.target.value)} invalid={!!errors.email} placeholder="you@company.com" />
            </Field>
            <Field label="Password" htmlFor="password" error={errors.password}>
              <Input id="password" type="password" autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} invalid={!!errors.password} />
            </Field>
            <div className="flex justify-end">
              <button type="button" className="text-sm text-brand-700 hover:underline" onClick={() => setForgotOpen(true)}>
                Forgot password?
              </button>
            </div>
            <Button type="submit" className="w-full" size="lg" loading={pending}>
              Sign in
            </Button>
          </form>

          <div className="mt-8 rounded-lg border border-slate-200 bg-slate-50 p-4">
            <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">Demo accounts (mock)</p>
            <p className="mt-1 text-xs text-slate-500">
              Password for all: <code className="font-mono text-slate-700">{DEMO_PASSWORD}</code>
            </p>
            <div className="mt-3 space-y-1">
              {DEMO_ACCOUNTS.map((a) => (
                <button
                  key={a.email}
                  type="button"
                  onClick={() => {
                    setEmail(a.email);
                    setPassword(DEMO_PASSWORD);
                    setErrors({});
                  }}
                  className="flex w-full items-center justify-between rounded-md px-2 py-1.5 text-left hover:bg-white"
                >
                  <span>
                    <span className="block text-sm font-medium text-slate-800">{ROLE_LABELS[a.role]}</span>
                    <span className="block text-xs text-slate-500">{a.note}</span>
                  </span>
                  <span className="font-mono text-[11px] text-slate-400">{a.email.split('@')[0]}</span>
                </button>
              ))}
            </div>
          </div>
        </div>
      </div>

      <Dialog
        open={forgotOpen}
        onClose={() => {
          setForgotOpen(false);
          setForgotMsg(null);
        }}
        title="Reset password"
        description="Password reset is a placeholder in the POC."
        footer={
          <Button
            onClick={async () => {
              try {
                const r = await api.post<{ message: string }>('/auth/forgotPassword', { email: email || 'unknown@demo.test' });
                setForgotMsg(r.message);
              } catch (e) {
                setForgotMsg((e as Error).message);
              }
            }}
          >
            Send reset link
          </Button>
        }
      >
        <div className="space-y-3">
          <Field label="Email" htmlFor="forgot-email">
            <Input id="forgot-email" value={email} onChange={(e) => setEmail(e.target.value)} placeholder="you@company.com" />
          </Field>
          {forgotMsg && <Callout tone="info">{forgotMsg}</Callout>}
        </div>
      </Dialog>
    </div>
  );
}
