import { useState, type FormEvent } from 'react';
import { Link, Navigate, useNavigate, useParams } from 'react-router-dom';
import { ArrowRight, CheckCircle2, ExternalLink, Lock, ShieldCheck } from 'lucide-react';
import { ProviderIcon } from '@/components/ui/provider-icon';
import { PERMISSIONS, type Environment, type IntegrationDetail, type Webhook } from '@token-vault/shared';
import { useApi, useMutation } from '@/hooks/useApi';
import { useAuth } from '@/context/AuthContext';
import { api } from '@/lib/api';
import { Button } from '@/components/ui/button';
import { Card, CardBody, CardHeader, DetailList } from '@/components/ui/card';
import { Field, Input, RadioCard, Select, Textarea } from '@/components/ui/form';
import { Callout, FormError, PermissionDenied, Spinner } from '@/components/ui/feedback';
import { PageHeader } from '@/components/ui/navigation';
import { CopyButton, Mono } from '@/components/ui/secret';
import { Badge, StatusBadge } from '@/components/ui/badge';
import { useToast } from '@/components/ui/toast';
import { splitList } from '@/lib/utils';
import { useProviders } from '@/lib/providers';

export function ConnectIntegrationPage() {
  const { provider: key } = useParams();
  const { providers, loaded } = useProviders();
  const def = providers.find((p) => p.key === key);
  const { can } = useAuth();
  const navigate = useNavigate();
  const toast = useToast();
  const webhooks = useApi<{ items: Webhook[] }>('/webhooks');
  const connected = webhooks.data?.items.filter((w) => w.status === 'CONNECTED') ?? [];

  const [form, setForm] = useState({ displayName: '', environment: 'development' as Environment, accountLabel: '', webhookId: '', description: '', allowedResources: '' });
  // Auth methods come from the provider definition; the first one is the default.
  const [authChoice, setAuthChoice] = useState('');
  const [app, setApp] = useState({ appId: '', installationId: '', keySource: 'stored' as 'stored' | 'webhook_env' });
  // Credential material lives only in this component's state until submission, then is cleared.
  const [secret, setSecret] = useState('');
  const [privateKey, setPrivateKey] = useState('');
  const [localErrors, setLocalErrors] = useState<Record<string, string>>({});
  const [created, setCreated] = useState<IntegrationDetail | null>(null);
  const submit = useMutation((body: unknown) => api.post<IntegrationDetail>('/integrations', body));
  const oauthStart = useMutation((body: unknown) => api.post<{ authorizeUrl: string }>('/integrations/oauth/start', body));
  const [oauthClient, setOauthClient] = useState({ clientId: '', clientSecret: '' });

  if (!loaded) return <Spinner />;
  if (!def) return <Navigate to="/integrations/catalog" replace />;
  if (!can(PERMISSIONS.INTEGRATION_MANAGE)) return <PermissionDenied required={PERMISSIONS.INTEGRATION_MANAGE} message="Only Vault Administrators and Owners can register credentials." />;
  if (webhooks.loading && !webhooks.data) return <Spinner />;

  const set = (k: keyof typeof form) => (e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement>) => setForm((f) => ({ ...f, [k]: e.target.value }));
  const errors = { ...submit.fieldErrors, ...oauthStart.fieldErrors, ...localErrors };
  const webhookId = form.webhookId || connected[0]?.id || '';
  const provider = def; // narrowed for the async handler below
  const method = def.auth.find((a) => a.id === authChoice) ?? def.auth[0]!;
  const authType = method.id;
  const isApp = method.kind === 'plugin' && method.plugin === 'github_app';
  const isOAuth = method.kind === 'oauth2';
  const redirectUri = `${window.location.origin}/oauth/callback`;
  const isPat = method.id === 'PAT';
  const resourceLabel = def.resource.label.toLowerCase();

  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    const errs: Record<string, string> = {};
    if (form.displayName.trim().length < 3) errs.displayName = 'Name must be at least 3 characters';
    if (isPat) {
      if (!form.accountLabel.trim()) errs.accountLabel = 'Account / organization label is required';
      if (secret.length < 20) errs.secret = 'Token must be at least 20 characters';
      if (/\s/.test(secret)) errs.secret = 'Token must not contain whitespace';
    } else if (isOAuth) {
      if (!oauthClient.clientId.trim()) errs.clientId = 'Enter the client ID of your OAuth app';
      if (oauthClient.clientSecret.length < 8) errs.clientSecret = 'Enter the client secret of your OAuth app';
    } else if (!isApp) {
      if (secret.length < 8) errs.secret = 'The secret is too short';
      else if (method.secretPattern && !new RegExp(method.secretPattern).test(secret)) errs.secret = method.secretHint ?? 'The secret does not have the expected format';
    } else {
      if (!/^\d{1,12}$/.test(app.appId.trim())) errs.appId = 'Enter the numeric App ID from the GitHub App settings';
      if (app.installationId.trim() && !/^\d{1,15}$/.test(app.installationId.trim())) errs.installationId = 'Installation ID is numeric';
      if (app.keySource === 'stored' && !/-----BEGIN [A-Z ]*PRIVATE KEY-----/.test(privateKey)) errs.privateKey = 'Paste or load the PEM private key downloaded from the GitHub App settings';
    }
    if (!webhookId) errs.webhookId = 'Select a connected webhook';
    setLocalErrors(errs);
    if (Object.keys(errs).length) return;
    const common = { provider: provider.key, ...form, webhookId, allowedResources: splitList(form.allowedResources) };
    if (isOAuth) {
      // The client secret goes to the customer webhook; the browser then visits the provider's consent screen.
      const started = await oauthStart.run({ ...common, authType, clientId: oauthClient.clientId.trim(), clientSecret: oauthClient.clientSecret });
      setOauthClient((c) => ({ ...c, clientSecret: '' }));
      if (started) window.location.assign(started.authorizeUrl);
      return;
    }
    const result = await submit.run(
      !isApp
        ? { ...common, authType, secret }
        : { ...common, authType, appId: app.appId.trim(), installationId: app.installationId.trim(), keySource: app.keySource, ...(app.keySource === 'stored' ? { privateKey } : {}) },
    );
    if (result) {
      setSecret(''); // never keep credential material after submission
      setPrivateKey('');
      setCreated(result);
      toast.success(`${provider.name} connected`, 'The credential is encrypted inside your customer webhook.');
    }
  }

  if (created) {
    return (
      <div className="mx-auto max-w-3xl">
        <PageHeader title="Integration connected" breadcrumbs={[{ label: 'Integrations', to: '/integrations/catalog' }, { label: `Connect ${def.name}` }]} />
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
            <ProviderIcon name={def.catalog.icon} className="h-5 w-5" /> Connect {def.name}
          </span>
        }
        description={`Register a ${def.auth.map((a) => a.label).join(' or ')} with your customer-controlled vault.${def.source === 'catalog' ? ` Definition v${def.version}, signed by the provider CMS.` : ''}`}
        breadcrumbs={[{ label: 'Integrations', to: '/integrations/catalog' }, { label: 'Integration Catalog', to: '/integrations/catalog' }, { label: `Connect ${def.name}` }]}
      />
      {def.catalog.availability !== 'available' ? (
        <Callout
          tone="info"
          title={`${def.name} is coming soon`}
          action={
            <Button size="sm" variant="outline" onClick={() => navigate('/integrations/catalog')}>
              Back to the catalog
            </Button>
          }
        >
          It is listed in the catalog, but your platform team has not made it available for connection yet.
        </Callout>
      ) : connected.length === 0 ? (
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
                <FormError error={submit.error ?? oauthStart.error} />
                <div className="grid gap-4 sm:grid-cols-2">
                  <Field label="Integration name" htmlFor="displayName" required error={errors.displayName}>
                    <Input id="displayName" value={form.displayName} onChange={set('displayName')} placeholder={`Demo ${def.name}`} invalid={!!errors.displayName} />
                  </Field>
                  <Field label="Environment" htmlFor="environment" required error={errors.environment}>
                    <Select id="environment" value={form.environment} onChange={set('environment')}>
                      <option value="development">Development</option>
                      <option value="staging">Staging</option>
                      <option value="production">Production</option>
                    </Select>
                  </Field>
                  <Field label={`${def.name} account / organization label`} htmlFor="accountLabel" required={isPat} error={errors.accountLabel} hint={isApp ? 'Optional: defaults to the account the App is installed on' : isPat ? undefined : 'Optional'}>
                    <Input id="accountLabel" value={form.accountLabel} onChange={set('accountLabel')} placeholder={def.key === 'github' ? 'demo-org' : ''} invalid={!!errors.accountLabel} />
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
                    {def.auth.map((a) => (
                      <RadioCard
                        key={a.id}
                        checked={a.id === method.id}
                        onChange={() => setAuthChoice(a.id)}
                        title={a.label}
                        badge={a.kind === 'plugin' ? <Badge tone="green">Recommended for production</Badge> : undefined}
                        description={a.description || (a.kind === 'basic' ? 'Username and password, sent as HTTP basic auth.' : 'A secret stored encrypted by your webhook and attached to every request.')}
                      />
                    ))}
                  </div>
                </div>
                {isOAuth ? (
                  <div className="space-y-4 rounded-lg border border-slate-200 p-4">
                    <Callout tone="info" title="Register an OAuth app at the provider first">
                      Use this redirect URI: <span className="font-mono">{redirectUri}</span> <CopyButton value={redirectUri} label="Copy" />
                      {method.oauth?.scopes.length ? (
                        <>
                          <br />
                          Scopes requested: <span className="font-mono">{method.oauth.scopes.join(' ')}</span>
                        </>
                      ) : null}
                    </Callout>
                    <div className="grid gap-4 sm:grid-cols-2">
                      <Field label="Client ID" htmlFor="clientId" required error={errors.clientId}>
                        <Input id="clientId" value={oauthClient.clientId} onChange={(e) => setOauthClient({ ...oauthClient, clientId: e.target.value })} invalid={!!errors.clientId} className="font-mono" />
                      </Field>
                      <Field
                        label={
                          <span className="flex items-center gap-1.5">
                            <Lock className="h-3.5 w-3.5 text-slate-400" /> Client secret
                          </span>
                        }
                        htmlFor="clientSecret"
                        required
                        error={errors.clientSecret}
                      >
                        <Input id="clientSecret" type="password" autoComplete="new-password" spellCheck={false} value={oauthClient.clientSecret} onChange={(e) => setOauthClient({ ...oauthClient, clientSecret: e.target.value })} invalid={!!errors.clientSecret} className="font-mono" />
                      </Field>
                    </div>
                  </div>
                ) : !isApp ? (
                  <Field
                    label={
                      <span className="flex items-center gap-1.5">
                        <Lock className="h-3.5 w-3.5 text-slate-400" /> {method.label}
                      </span>
                    }
                    htmlFor="secret"
                    required
                    error={errors.secret}
                    hint={isPat ? 'Use a mock token (e.g. mock_ghp_…) or a fine-grained PAT for a dedicated test organization only.' : method.kind === 'basic' ? 'Enter username:password' : method.secretHint}
                  >
                    <Input id="secret" type="password" autoComplete="new-password" spellCheck={false} value={secret} onChange={(e) => setSecret(e.target.value)} placeholder={isPat ? 'ghp_••••••••••••••••••••' : ''} invalid={!!errors.secret} className="font-mono" />
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
                <Field label={`Allowed ${resourceLabel} values (optional)`} htmlFor="allowedResources" error={errors.allowedResources} hint={`${def.resource.label}${def.resource.example ? ` (e.g. ${def.resource.example})` : ''}, comma or newline separated. Grants may only target these.`}>
                  <Textarea id="allowedResources" rows={2} value={form.allowedResources} onChange={set('allowedResources')} placeholder={def.resource.example ?? ''} className="font-mono text-xs" />
                </Field>
                <Field label="Description" htmlFor="description">
                  <Textarea id="description" rows={2} value={form.description} onChange={set('description')} />
                </Field>
              </CardBody>
              <div className="flex justify-end gap-2 border-t border-slate-100 px-5 py-3.5">
                <Button variant="outline" onClick={() => navigate('/integrations/catalog')}>
                  Cancel
                </Button>
                <Button type="submit" loading={submit.pending || oauthStart.pending}>
                  {isOAuth ? (
                    <>
                      <ExternalLink className="h-4 w-4" /> Continue to {method.oauth?.authorizeHost ?? 'the provider'}
                    </>
                  ) : (
                    <>
                      <ShieldCheck className="h-4 w-4" /> Store in customer vault
                    </>
                  )}
                </Button>
              </div>
            </form>
          </Card>

          <div className="space-y-4">
            <Card>
              <CardHeader title="How your credential is handled" />
              <CardBody>
                <ol className="space-y-3 text-sm">
                  {(isOAuth
                    ? [
                        'The client secret is forwarded in a signed request to your customer webhook and encrypted there.',
                        'The webhook creates a PKCE verifier and a one-time state; your browser goes to the provider to approve access.',
                        'The provider sends you back here with a single-use code, which only the webhook can redeem (it holds the verifier and the secret).',
                        'Access and refresh tokens are stored encrypted in the webhook and refreshed there before they expire.',
                        'Token Vault never sees the client secret or any token.',
                      ]
                    : !isApp
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
