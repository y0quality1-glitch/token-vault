import { useState, type FormEvent } from 'react';
import { Link, Navigate, useNavigate, useParams } from 'react-router-dom';
import { ArrowRight, CheckCircle2, Github, Lock, ShieldCheck } from 'lucide-react';
import { PERMISSIONS, type Environment, type IntegrationDetail, type Webhook } from '@token-vault/shared';
import { useApi, useMutation } from '@/hooks/useApi';
import { useAuth } from '@/context/AuthContext';
import { api } from '@/lib/api';
import { Button } from '@/components/ui/button';
import { Card, CardBody, CardHeader, DetailList } from '@/components/ui/card';
import { Field, Input, RadioCard, Select, Textarea } from '@/components/ui/form';
import { Callout, FormError, PermissionDenied, Spinner } from '@/components/ui/feedback';
import { PageHeader } from '@/components/ui/navigation';
import { Mono } from '@/components/ui/secret';
import { Badge, StatusBadge } from '@/components/ui/badge';
import { useToast } from '@/components/ui/toast';
import { splitList } from '@/lib/utils';

export function ConnectIntegrationPage() {
  const { provider } = useParams();
  const { can } = useAuth();
  const navigate = useNavigate();
  const toast = useToast();
  const webhooks = useApi<{ items: Webhook[] }>('/webhooks');
  const connected = webhooks.data?.items.filter((w) => w.status === 'CONNECTED') ?? [];

  const [form, setForm] = useState({ displayName: '', environment: 'development' as Environment, accountLabel: '', webhookId: '', description: '', allowedResources: '' });
  const [authType, setAuthType] = useState<'PAT' | 'GITHUB_APP'>('GITHUB_APP');
  const [app, setApp] = useState({ appId: '', installationId: '', keySource: 'stored' as 'stored' | 'webhook_env' });
  // Credential material lives only in this component's state until submission, then is cleared.
  const [secret, setSecret] = useState('');
  const [privateKey, setPrivateKey] = useState('');
  const [localErrors, setLocalErrors] = useState<Record<string, string>>({});
  const [created, setCreated] = useState<IntegrationDetail | null>(null);
  const submit = useMutation((body: unknown) => api.post<IntegrationDetail>('/integrations', body));

  if (provider !== 'github') return <Navigate to="/integrations/catalog" replace />;
  if (!can(PERMISSIONS.INTEGRATION_MANAGE)) return <PermissionDenied required={PERMISSIONS.INTEGRATION_MANAGE} message="Only Vault Administrators and Owners can register credentials." />;
  if (webhooks.loading && !webhooks.data) return <Spinner />;

  const set = (k: keyof typeof form) => (e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement>) => setForm((f) => ({ ...f, [k]: e.target.value }));
  const errors = { ...submit.fieldErrors, ...localErrors };
  const webhookId = form.webhookId || connected[0]?.id || '';

  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    const errs: Record<string, string> = {};
    if (form.displayName.trim().length < 3) errs.displayName = 'Name must be at least 3 characters';
    if (authType === 'PAT') {
      if (!form.accountLabel.trim()) errs.accountLabel = 'Account / organization label is required';
      if (secret.length < 20) errs.secret = 'Token must be at least 20 characters';
      if (/\s/.test(secret)) errs.secret = 'Token must not contain whitespace';
    } else {
      if (!/^\d{1,12}$/.test(app.appId.trim())) errs.appId = 'Enter the numeric App ID from the GitHub App settings';
      if (app.installationId.trim() && !/^\d{1,15}$/.test(app.installationId.trim())) errs.installationId = 'Installation ID is numeric';
      if (app.keySource === 'stored' && !/-----BEGIN [A-Z ]*PRIVATE KEY-----/.test(privateKey)) errs.privateKey = 'Paste or load the PEM private key downloaded from the GitHub App settings';
    }
    if (!webhookId) errs.webhookId = 'Select a connected webhook';
    setLocalErrors(errs);
    if (Object.keys(errs).length) return;
    const common = { provider: 'github', ...form, webhookId, allowedResources: splitList(form.allowedResources) };
    const result = await submit.run(
      authType === 'PAT'
        ? { ...common, authType, secret }
        : { ...common, authType, appId: app.appId.trim(), installationId: app.installationId.trim(), keySource: app.keySource, ...(app.keySource === 'stored' ? { privateKey } : {}) },
    );
    if (result) {
      setSecret(''); // never keep credential material after submission
      setPrivateKey('');
      setCreated(result);
      toast.success('GitHub connected', 'The credential is encrypted inside your customer webhook.');
    }
  }

  if (created) {
    return (
      <div className="mx-auto max-w-3xl">
        <PageHeader title="Integration connected" breadcrumbs={[{ label: 'Integrations', to: '/integrations/catalog' }, { label: 'Connect GitHub' }]} />
        <Card>
          <CardBody className="space-y-5">
            <div className="flex items-center gap-3">
              <CheckCircle2 className="h-8 w-8 text-emerald-600" />
              <div>
                <p className="font-semibold text-slate-900">{created.displayName} is connected</p>
                <p className="text-sm text-slate-500">
                  {created.authType === 'GITHUB_APP'
                    ? `The webhook "${created.webhookName}" verified the App with GitHub. It will mint a narrowed, short-lived token for each authorized request.`
                    : `The secret was forwarded to "${created.webhookName}", encrypted, and cleared from the browser and control plane.`}
                </p>
              </div>
            </div>
            <DetailList
              items={[
                { label: 'Status', value: <StatusBadge status={created.credentialStatus} /> },
                { label: 'Credential reference', value: <Mono>{created.credentialReference}</Mono> },
                { label: 'Masked identifier', value: created.maskedIdentifier, mono: true },
                { label: 'Fingerprint', value: created.credentialFingerprint, mono: true },
              ]}
            />
            <Callout tone="security">
              {created.authType === 'GITHUB_APP'
                ? 'No long-lived GitHub token exists for this integration. The private key (if uploaded) is never displayed again; to replace it, use Rotate / replace credential.'
                : 'The submitted token will never be displayed again. To change it, use Rotate / replace credential on the integration.'}
            </Callout>
            <div className="flex flex-wrap gap-2">
              <Button onClick={() => navigate('/agents?register=1')}>
                Next: register an agent <ArrowRight className="h-4 w-4" />
              </Button>
              <Button variant="outline" onClick={() => navigate(`/integrations/${created.id}`)}>
                View integration
              </Button>
            </div>
          </CardBody>
        </Card>
      </div>
    );
  }

  return (
    <div>
      <PageHeader
        title={
          <span className="flex items-center gap-2">
            <Github className="h-5 w-5" /> Connect GitHub
          </span>
        }
        description="Register a GitHub App or a Personal Access Token with your customer-controlled vault."
        breadcrumbs={[{ label: 'Integrations', to: '/integrations/catalog' }, { label: 'Integration Catalog', to: '/integrations/catalog' }, { label: 'Connect GitHub' }]}
      />
      {connected.length === 0 ? (
        <Callout
          tone="warning"
          title="A connected customer webhook is required"
          action={
            <Button size="sm" onClick={() => navigate('/webhook/setup')}>
              Configure webhook
            </Button>
          }
        >
          Credentials are stored by your webhook / vault agent, not by Token Vault. Register and verify a webhook first.
        </Callout>
      ) : (
        <div className="grid gap-6 xl:grid-cols-[1.4fr_1fr]">
          <Card>
            <CardHeader title="Credential details" />
            <form onSubmit={onSubmit} noValidate autoComplete="off">
              <CardBody className="space-y-4">
                <FormError error={submit.error} />
                <div className="grid gap-4 sm:grid-cols-2">
                  <Field label="Integration name" htmlFor="displayName" required error={errors.displayName}>
                    <Input id="displayName" value={form.displayName} onChange={set('displayName')} placeholder="Demo GitHub" invalid={!!errors.displayName} />
                  </Field>
                  <Field label="Environment" htmlFor="environment" required error={errors.environment}>
                    <Select id="environment" value={form.environment} onChange={set('environment')}>
                      <option value="development">Development</option>
                      <option value="staging">Staging</option>
                      <option value="production">Production</option>
                    </Select>
                  </Field>
                  <Field label="GitHub account / organization label" htmlFor="accountLabel" required={authType === 'PAT'} error={errors.accountLabel} hint={authType === 'GITHUB_APP' ? 'Optional: defaults to the account the App is installed on' : undefined}>
                    <Input id="accountLabel" value={form.accountLabel} onChange={set('accountLabel')} placeholder="demo-org" invalid={!!errors.accountLabel} />
                  </Field>
                  <Field label="Customer webhook" htmlFor="webhookId" required error={errors.webhookId}>
                    <Select id="webhookId" value={webhookId} onChange={set('webhookId')}>
                      {connected.map((w) => (
                        <option key={w.id} value={w.id}>
                          {w.name} ({w.environment})
                        </option>
                      ))}
                    </Select>
                  </Field>
                </div>
                <div>
                  <p className="mb-2 text-sm font-medium text-slate-700">Authentication</p>
                  <div className="grid gap-3 md:grid-cols-2">
                    <RadioCard checked={authType === 'GITHUB_APP'} onChange={() => setAuthType('GITHUB_APP')} title="GitHub App" badge={<Badge tone="green">Recommended for production</Badge>} description="Only the App's private key is stored. Each request gets a 1-hour token minted for one repository and one permission, revoked after use." />
                    <RadioCard checked={authType === 'PAT'} onChange={() => setAuthType('PAT')} title="Personal access token" description="A long-lived token stored encrypted and used as-is for every request. Simplest for demos." />
                  </div>
                </div>
                {authType === 'PAT' ? (
                  <Field
                    label={
                      <span className="flex items-center gap-1.5">
                        <Lock className="h-3.5 w-3.5 text-slate-400" /> Personal Access Token
                      </span>
                    }
                    htmlFor="secret"
                    required
                    error={errors.secret}
                    hint="Use a mock token (e.g. mock_ghp_…) or a fine-grained PAT for a dedicated test organization only."
                  >
                    <Input id="secret" type="password" autoComplete="new-password" spellCheck={false} value={secret} onChange={(e) => setSecret(e.target.value)} placeholder="ghp_••••••••••••••••••••" invalid={!!errors.secret} className="font-mono" />
                  </Field>
                ) : (
                  <div className="space-y-4 rounded-lg border border-slate-200 p-4">
                    <div className="grid gap-4 sm:grid-cols-2">
                      <Field label="App ID" htmlFor="appId" required error={errors.appId} hint="GitHub → Settings → Developer settings → GitHub Apps → your App">
                        <Input id="appId" inputMode="numeric" value={app.appId} onChange={(e) => setApp({ ...app, appId: e.target.value })} placeholder="123456" invalid={!!errors.appId} className="font-mono" />
                      </Field>
                      <Field label="Installation ID (optional)" htmlFor="installationId" error={errors.installationId} hint="Leave empty if the App is installed on exactly one account">
                        <Input id="installationId" inputMode="numeric" value={app.installationId} onChange={(e) => setApp({ ...app, installationId: e.target.value })} placeholder="auto-detect" invalid={!!errors.installationId} className="font-mono" />
                      </Field>
                    </div>
                    <div className="space-y-2">
                      <p className="text-sm font-medium text-slate-700">Private key</p>
                      <div className="grid gap-3 md:grid-cols-2">
                        <RadioCard checked={app.keySource === 'stored'} onChange={() => setApp({ ...app, keySource: 'stored' })} title="Store it in the customer vault" description="Uploaded once, encrypted by the webhook. Never shown again." />
                        <RadioCard checked={app.keySource === 'webhook_env'} onChange={() => setApp({ ...app, keySource: 'webhook_env' })} title="Already configured on the webhook" description="The key never passes through Token Vault (GITHUB_APP_PRIVATE_KEY in the webhook's environment)." />
                      </div>
                    </div>
                    {app.keySource === 'stored' && (
                      <Field
                        label={
                          <span className="flex items-center gap-1.5">
                            <Lock className="h-3.5 w-3.5 text-slate-400" /> Private key (PEM)
                          </span>
                        }
                        htmlFor="privateKey"
                        required
                        error={errors.privateKey}
                        hint={
                          <label className="cursor-pointer text-brand-700 hover:underline">
                            Load .pem file
                            <input
                              type="file"
                              accept=".pem,.key,application/x-pem-file"
                              className="sr-only"
                              onChange={async (e) => {
                                const f = e.target.files?.[0];
                                if (f) setPrivateKey(await f.text());
                                e.target.value = '';
                              }}
                            />
                          </label>
                        }
                      >
                        <Textarea id="privateKey" rows={4} spellCheck={false} autoComplete="off" value={privateKey} onChange={(e) => setPrivateKey(e.target.value)} placeholder="-----BEGIN RSA PRIVATE KEY-----" invalid={!!errors.privateKey} className="font-mono text-xs [-webkit-text-security:disc]" />
                      </Field>
                    )}
                  </div>
                )}
                <Field label="Allowed repositories (optional)" htmlFor="allowedResources" error={errors.allowedResources} hint="owner/repository, comma or newline separated. Grants may only target these repositories.">
                  <Textarea id="allowedResources" rows={2} value={form.allowedResources} onChange={set('allowedResources')} placeholder="demo-org/demo-repo" className="font-mono text-xs" />
                </Field>
                <Field label="Description" htmlFor="description">
                  <Textarea id="description" rows={2} value={form.description} onChange={set('description')} />
                </Field>
              </CardBody>
              <div className="flex justify-end gap-2 border-t border-slate-100 px-5 py-3.5">
                <Button variant="outline" onClick={() => navigate('/integrations/catalog')}>
                  Cancel
                </Button>
                <Button type="submit" loading={submit.pending}>
                  <ShieldCheck className="h-4 w-4" /> Store in customer vault
                </Button>
              </div>
            </form>
          </Card>

          <div className="space-y-4">
            <Card>
              <CardHeader title="How your credential is handled" />
              <CardBody>
                <ol className="space-y-3 text-sm">
                  {(authType === 'PAT'
                    ? [
                        'Submitted over TLS to the Token Vault backend. Never placed in browser storage, URLs or logs.',
                        'Forwarded in a signed, short-lived request to your customer webhook.',
                        'The webhook encrypts it with AES-256-GCM using a key from your environment.',
                        'The webhook returns only a credential reference and a masked identifier.',
                        'Token Vault stores the reference and metadata. The secret is discarded.',
                      ]
                    : [
                        'The webhook verifies the App ID and key with GitHub and finds the installation.',
                        'The private key is encrypted in the webhook, or never leaves it if configured there.',
                        'For each authorized request the webhook mints a token for that one repository and the one permission the operation needs.',
                        'The token is used once and revoked; it expires within an hour regardless.',
                        'Token Vault only ever sees the App ID, installation and the scope of each minted token.',
                      ]
                  ).map((t, i) => (
                    <li key={i} className="flex gap-2.5">
                      <span className="flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-emerald-50 text-[11px] font-semibold text-emerald-700">{i + 1}</span>
                      <span className="text-slate-600">{t}</span>
                    </li>
                  ))}
                </ol>
              </CardBody>
            </Card>
            <Callout tone="warning" title="Do not use production credentials">
              This is a proof of concept. Restrict any real token to a dedicated test organization with minimum permissions. See <Link to="/guide" className="underline">Demo guide</Link>.
            </Callout>
          </div>
        </div>
      )}
    </div>
  );
}
