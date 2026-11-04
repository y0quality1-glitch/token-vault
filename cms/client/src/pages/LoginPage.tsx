import { useState, type FormEvent } from 'react';
import { Blocks } from 'lucide-react';
import { Button } from '@ui/button';
import { Card, CardBody } from '@ui/card';
import { FormError } from '@ui/feedback';
import { Field, Input } from '@ui/form';
import { useAuth } from '@/auth';
import { ApiError } from '@/lib/api';

const DEMO = [
  { email: 'editor@cms.test', role: 'Editor: drafts and submits' },
  { email: 'publisher@cms.test', role: 'Publisher: reviews and publishes' },
  { email: 'admin@cms.test', role: 'Administrator: everything, incl. archive' },
];

export function LoginPage() {
  const { login } = useAuth();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState<ApiError | null>(null);
  const [pending, setPending] = useState(false);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setPending(true);
    setError(null);
    try {
      await login(email, password);
    } catch (err) {
      setError(err instanceof ApiError ? err : new ApiError(0, 'UNKNOWN', String(err)));
    } finally {
      setPending(false);
    }
  };

  return (
    <div className="flex min-h-screen items-center justify-center px-4">
      <div className="w-full max-w-md space-y-6">
        <div className="flex items-center gap-3">
          <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-brand-600 text-white">
            <Blocks className="h-5 w-5" />
          </div>
          <div>
            <h1 className="text-lg font-semibold text-slate-900">Token Vault CMS</h1>
            <p className="text-sm text-slate-500">Author, review and publish provider definitions</p>
          </div>
        </div>
        <Card>
          <CardBody>
            <form onSubmit={submit} className="space-y-4">
              <FormError error={error} />
              <Field label="Email" htmlFor="email" error={error?.fieldErrors.email}>
                <Input id="email" type="email" autoComplete="username" value={email} onChange={(e) => setEmail(e.target.value)} />
              </Field>
              <Field label="Password" htmlFor="password" error={error?.fieldErrors.password}>
                <Input id="password" type="password" autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} />
              </Field>
              <Button type="submit" loading={pending} className="w-full">
                Sign in
              </Button>
            </form>
          </CardBody>
        </Card>
        <div className="rounded-lg border border-dashed border-slate-300 p-4 text-sm text-slate-600">
          <p className="font-medium text-slate-800">Demo accounts (password TokenVault-Demo-2026)</p>
          <ul className="mt-2 space-y-1">
            {DEMO.map((d) => (
              <li key={d.email}>
                <button type="button" className="font-mono text-brand-700 hover:underline" onClick={() => setEmail(d.email)}>
                  {d.email}
                </button>{' '}
                <span className="text-slate-500">· {d.role}</span>
              </li>
            ))}
          </ul>
        </div>
      </div>
    </div>
  );
}
