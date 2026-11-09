import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { ArrowRight, CheckCircle2, Plus, RefreshCw, Server, XCircle } from 'lucide-react';
import { PERMISSIONS, type Environment, type Webhook } from '@token-vault/shared';
import { useApi, useMutation } from '@/hooks/useApi';
import { useAuth } from '@/context/AuthContext';
import { api } from '@/lib/api';
import { Button } from '@/components/ui/button';
import { Card, CardBody, CardHeader, DetailList } from '@/components/ui/card';
import { Badge, EnvBadge, StatusBadge } from '@/components/ui/badge';
import { Field, Input, RadioCard, Select, Textarea } from '@/components/ui/form';
import { Callout, ErrorState, FormError, PageSkeleton } from '@/components/ui/feedback';
import { Dialog } from '@/components/ui/dialog';
import { PageHeader, Stepper } from '@/components/ui/navigation';
import { Mono } from '@/components/ui/secret';
import { useToast } from '@/components/ui/toast';
import { TrustBoundary } from '@/components/TrustBoundary';
import { formatDateTime, relativeTime } from '@/lib/utils';

interface HealthResult {
  ok: boolean;
  latencyMs: number | null;
  detail: string;
  instanceId?: string;
  version?: string;
}

/** What the control plane can do on the webhook link (from GET /webhooks). */
interface Transport {
  mtlsAvailable: boolean;
  requireTls: boolean;
  trustsCustomCa: boolean;
}

export function WebhookSetupPage() {
  const { can } = useAuth();
  const { data, error, loading, reload } = useApi<{ items: Webhook[]; defaultEndpointUrl: string; transport?: Transport }>('/webhooks');
  const [wizard, setWizard] = useState(false);
  const [editing, setEditing] = useState<Webhook | null>(null);
  const navigate = useNavigate();

  if (error) return <ErrorState error={error} onRetry={reload} />;
  if (loading && !data) return <PageSkeleton />;
  if (!data) return null;
  const showWizard = wizard || (data.items.length === 0 && can(PERMISSIONS.WEBHOOK_MANAGE));

  return (
    <div className="space-y-6">
      <PageHeader
        title="Webhook / Vault Agent Setup"
        description="Connect your customer-hosted credential execution environment to the Token Vault control plane."
        breadcrumbs={[{ label: 'Webhook / Vault Agent' }, { label: 'Webhook Setup' }]}
        actions={
          !showWizard &&
          can(PERMISSIONS.WEBHOOK_MANAGE) && (
            <Button onClick={() => setWizard(true)}>
              <Plus className="h-4 w-4" /> Register webhook
            </Button>
          )
        }
      />

      <Card>
        <CardHeader title="Trust boundary" description="The browser and the control plane never receive stored credentials. The webhook exposes signed, authenticated operations only, never a public endpoint that returns secrets." />
        <CardBody>
          <TrustBoundary />
        </CardBody>
      </Card>

      {showWizard ? (
        <SetupWizard
          defaultUrl={data.defaultEndpointUrl}
          transport={data.transport}
          onCancel={data.items.length ? () => setWizard(false) : undefined}
          onDone={() => {
            setWizard(false);
            void reload();
          }}
        />
      ) : data.items.length === 0 ? (
        <Callout tone="info" title="No webhook registered">
          Ask a Vault Administrator or Owner to register your customer webhook.
        </Callout>
      ) : (
        <div className="grid gap-4 lg:grid-cols-2">
          {data.items.map((w) => (
            <Card key={w.id}>
              <CardHeader
                title={
                  <span className="flex items-center gap-2">
                    <Server className="h-4 w-4 text-slate-400" /> {w.name}
                  </span>
                }
                actions={<StatusBadge status={w.status} />}
              />
              <CardBody className="space-y-4">
                <DetailList
                  items={[
                    { label: 'Endpoint URL', value: w.endpointUrl, mono: true },
                    { label: 'Environment', value: <EnvBadge env={w.environment} /> },
                    { label: 'Authentication', value: w.authenticationType === 'SHARED_SECRET_HMAC' ? 'Signed requests (HMAC-SHA256)' : 'Mutual TLS + signed requests' },
                    { label: 'Signing secret', value: <span className="font-mono text-xs">{w.signingSecretRef}</span> },
                    { label: 'Last heartbeat', value: relativeTime(w.lastHeartbeatAt) },
                    { label: 'Software version', value: w.softwareVersion ?? '—' },
                    { label: 'Webhook ID', value: <Mono>{w.id}</Mono> },
                    { label: 'Registered', value: formatDateTime(w.createdAt) },
                  ]}
                />
                {w.lastError && <Callout tone="danger">{w.lastError}</Callout>}
                <div className="flex flex-wrap gap-2">
                  <Button variant="outline" size="sm" onClick={() => navigate('/webhook/health')}>
                    Health & connectivity
                  </Button>
                  {can(PERMISSIONS.WEBHOOK_MANAGE) && (
                    <Button variant="outline" size="sm" onClick={() => setEditing(w)}>
                      Change URL or authentication
                    </Button>
                  )}
                  {w.status === 'PENDING' && can(PERMISSIONS.WEBHOOK_MANAGE) && (
                    <Button size="sm" onClick={() => setWizard(true)}>
                      Resume verification
                    </Button>
                  )}
                </div>
              </CardBody>
            </Card>
          ))}
        </div>
      )}
      {editing && (
        <TransportDialog
          webhook={editing}
          transport={data.transport}
          onClose={() => setEditing(null)}
          onSaved={() => {
            setEditing(null);
            void reload();
          }}
        />
      )}
    </div>
  );
}

/**
 * Moves a webhook (e.g. to https://) or switches it to mutual TLS. The webhook's pinned identity
 * must still match, so this cannot point Token Vault at a different webhook; a signed health
 * check runs right away so a mistake shows at once.
 */
function TransportDialog({ webhook, transport, onClose, onSaved }: { webhook: Webhook; transport?: Transport; onClose: () => void; onSaved: () => void }) {
  const toast = useToast();
  const [url, setUrl] = useState(webhook.endpointUrl);
  const [authType, setAuthType] = useState(webhook.authenticationType);
  const save = useMutation(async () => {
    const w = await api.patch<Webhook>(`/webhooks/${webhook.id}`, { endpointUrl: url, authenticationType: authType });
    const r = await api.post<{ result: HealthResult }>(`/webhooks/${w.id}/test`);
    return r.result;
  });
  return (
    <Dialog
      open
      onClose={onClose}
      title={`Change ${webhook.name}`}
      description="Token Vault verifies the webhook's pinned identity at the new address, so this cannot point it at a different webhook."
      footer={
        <>
          <Button variant="outline" onClick={onClose}>
            Cancel
          </Button>
          <Button
            loading={save.pending}
            onClick={async () => {
              const r = await save.run();
              if (!r) return;
              if (r.ok) toast.success('Saved and verified', r.detail);
              else toast.error('Saved, but the health check failed', r.detail);
              onSaved();
            }}
          >
            Save and verify
          </Button>
        </>
      }
    >
      <div className="space-y-4">
        <FormError error={save.error} />
        <Field label="Endpoint URL" htmlFor="transportUrl" error={save.fieldErrors.endpointUrl} hint={transport?.requireTls ? 'WEBHOOK_REQUIRE_TLS is on: https:// only.' : undefined}>
          <Input id="transportUrl" className="font-mono" value={url} onChange={(e) => setUrl(e.target.value.trim())} />
        </Field>
        <Field label="Authentication" htmlFor="transportAuth" hint={transport?.mtlsAvailable ? 'Mutual TLS needs an https:// URL.' : 'Mutual TLS needs a control-plane client certificate (CONTROL_PLANE_TLS_CERT / _KEY).'}>
          <Select id="transportAuth" value={authType} onChange={(e) => setAuthType(e.target.value as Webhook['authenticationType'])}>
            <option value="SHARED_SECRET_HMAC">Signed requests (HMAC-SHA256)</option>
            <option value="MTLS" disabled={!transport?.mtlsAvailable}>
              Mutual TLS + signed requests
            </option>
          </Select>
        </Field>
      </div>
    </Dialog>
  );
}

const STEPS = ['Register endpoint', 'Configure authentication', 'Verify connectivity', 'Complete'];

function SetupWizard({ defaultUrl, transport, onCancel, onDone }: { defaultUrl: string; transport?: Transport; onCancel?: () => void; onDone: () => void }) {
  const toast = useToast();
  const navigate = useNavigate();
  const [step, setStep] = useState(0);
  const [form, setForm] = useState({ name: 'Local Customer Vault', endpointUrl: defaultUrl, environment: 'development' as Environment, description: '' });
  const [webhook, setWebhook] = useState<Webhook | null>(null);
  const [result, setResult] = useState<HealthResult | null>(null);
  const create = useMutation((body: unknown) => api.post<Webhook>('/webhooks', body));
  const verify = useMutation((id: string) => api.post<{ webhook: Webhook; result: HealthResult }>(`/webhooks/${id}/test`));
  const [authType, setAuthType] = useState<'SHARED_SECRET_HMAC' | 'MTLS'>('SHARED_SECRET_HMAC');
  const configure = useMutation((id: string) => api.patch<Webhook>(`/webhooks/${id}`, { authenticationType: authType }));
  const mtlsPossible = !!transport?.mtlsAvailable && !!webhook?.endpointUrl.startsWith('https://');
  useEffect(() => {
    if (mtlsPossible) setAuthType('MTLS');
  }, [mtlsPossible]);
  const fe = create.fieldErrors;

  useEffect(() => setResult(null), [step]);

  return (
    <Card>
      <div className="border-b border-slate-100 px-5 py-4">
        <Stepper steps={STEPS} current={step} />
      </div>
      <CardBody className="min-h-[18rem] space-y-4">
        {step === 0 && (
          <>
            <h2 className="text-sm font-semibold text-slate-900">Step 1: Register endpoint</h2>
            <FormError error={create.error} />
            <div className="grid gap-4 md:grid-cols-2">
              <Field label="Webhook display name" required error={fe.name}>
                <Input value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} invalid={!!fe.name} />
              </Field>
              <Field label="Environment" required>
                <Select value={form.environment} onChange={(e) => setForm({ ...form, environment: e.target.value as Environment })}>
                  <option value="development">Development</option>
                  <option value="staging">Staging</option>
                  <option value="production">Production</option>
                </Select>
              </Field>
              <Field label="Base URL" required error={fe.endpointUrl} hint="The local POC webhook runs at http://localhost:4100. Production requires https://." className="md:col-span-2">
                <Input value={form.endpointUrl} onChange={(e) => setForm({ ...form, endpointUrl: e.target.value })} className="font-mono text-sm" invalid={!!fe.endpointUrl} />
              </Field>
              <Field label="Description" className="md:col-span-2">
                <Textarea rows={2} value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} />
              </Field>
            </div>
          </>
        )}

        {step === 1 && webhook && (
          <>
            <h2 className="text-sm font-semibold text-slate-900">Step 2: Configure authentication</h2>
            <div className="grid gap-3 md:grid-cols-2">
              <RadioCard
                checked={authType === 'SHARED_SECRET_HMAC'}
                onChange={() => setAuthType('SHARED_SECRET_HMAC')}
                title="Signed requests (HMAC-SHA256)"
                badge={<Badge tone="blue">Always on</Badge>}
                description="Requests and responses are signed with a secret both sides read from their environment, with timestamp, nonce, body hash, expiry and audience."
              />
              <RadioCard
                checked={authType === 'MTLS'}
                disabled={!mtlsPossible}
                onChange={() => setAuthType('MTLS')}
                title="Mutual TLS + signed requests"
                badge={<Badge tone={mtlsPossible ? 'green' : 'gray'}>{mtlsPossible ? 'Recommended' : 'Not set up'}</Badge>}
                description={
                  mtlsPossible
                    ? 'Both sides prove their identity with certificates before any request is read; the webhook is never called without TLS. Signed requests still apply on top.'
                    : !transport?.mtlsAvailable
                      ? 'Needs a control-plane client certificate (CONTROL_PLANE_TLS_CERT / _KEY) and a webhook serving HTTPS. See docs/DEPLOYMENT.md.'
                      : 'Needs an https:// webhook URL.'
                }
              />
            </div>
            <div className="grid gap-4 md:grid-cols-2">
              <div className="rounded-lg border border-slate-200 p-4">
                <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">One-time registration challenge</p>
                <p className="mt-2 font-mono text-sm text-slate-900">{webhook.registrationChallenge}</p>
                <p className="mt-2 text-xs text-slate-500">Sent in the first signed health check. The webhook must answer with an HMAC over this challenge and its instance ID to prove it holds the signing secret.</p>
              </div>
              <div className="rounded-lg border border-slate-200 p-4">
                <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">Signing secret location</p>
                <ul className="mt-2 space-y-1 font-mono text-xs text-slate-700">
                  <li>server/.env → WEBHOOK_SIGNING_SECRET</li>
                  <li>webhook/.env → WEBHOOK_SIGNING_SECRET</li>
                </ul>
                <p className="mt-2 text-xs text-slate-500">Generated by <code>npm run setup</code>, git-ignored, never stored in the database and never displayed in the console.</p>
              </div>
            </div>
            <FormError error={configure.error} />
          </>
        )}

        {step === 2 && webhook && (
          <>
            <h2 className="text-sm font-semibold text-slate-900">Step 3: Verify connectivity</h2>
            <p className="text-sm text-slate-600">
              Token Vault sends a signed health-check challenge to <span className="font-mono">{webhook.endpointUrl}/internal/v1/health</span>, then validates the webhook identity and the response signature.
            </p>
            <Button
              loading={verify.pending}
              onClick={async () => {
                const r = await verify.run(webhook.id);
                if (r) {
                  setWebhook(r.webhook);
                  setResult(r.result);
                  if (r.result.ok) toast.success('Webhook verified', `Instance ${r.result.instanceId}`);
                }
              }}
            >
              <RefreshCw className="h-4 w-4" /> {result && !result.ok ? 'Retry verification' : 'Send signed health challenge'}
            </Button>
            <FormError error={verify.error} />
            {result &&
              (result.ok ? (
                <div className="flex items-start gap-3 rounded-lg border border-emerald-200 bg-emerald-50 p-4">
                  <CheckCircle2 className="h-5 w-5 text-emerald-600" />
                  <div className="text-sm">
                    <p className="font-medium text-emerald-900">Connected</p>
                    <p className="text-emerald-800">
                      {result.detail}. Instance <span className="font-mono">{result.instanceId}</span>, version {result.version}, {result.latencyMs} ms.
                    </p>
                  </div>
                </div>
              ) : (
                <div className="flex items-start gap-3 rounded-lg border border-red-200 bg-red-50 p-4">
                  <XCircle className="h-5 w-5 text-red-600" />
                  <div className="text-sm">
                    <p className="font-medium text-red-900">Failed</p>
                    <p className="text-red-800">{result.detail}</p>
                    <ul className="mt-2 list-disc pl-4 text-xs text-red-800">
                      <li>Start the webhook runtime: <code>npm run dev -w webhook</code></li>
                      <li>Check that the base URL is reachable from the control plane</li>
                      <li>Ensure WEBHOOK_SIGNING_SECRET is identical in server/.env and webhook/.env</li>
                    </ul>
                  </div>
                </div>
              ))}
          </>
        )}

        {step === 3 && webhook && (
          <>
            <div className="flex items-center gap-3">
              <CheckCircle2 className="h-8 w-8 text-emerald-600" />
              <div>
                <h2 className="font-semibold text-slate-900">Webhook connected</h2>
                <p className="text-sm text-slate-500">Your customer vault is ready to store credentials and execute brokered requests.</p>
              </div>
            </div>
            <DetailList
              columns={3}
              items={[
                { label: 'Webhook ID', value: <Mono>{webhook.id}</Mono> },
                { label: 'Endpoint', value: webhook.endpointUrl, mono: true },
                { label: 'Environment', value: <EnvBadge env={webhook.environment} /> },
                { label: 'Health status', value: <StatusBadge status={webhook.status} /> },
                { label: 'Instance ID', value: webhook.instanceId, mono: true },
                { label: 'Software version', value: webhook.softwareVersion },
              ]}
            />
          </>
        )}
      </CardBody>
      <div className="flex items-center justify-between gap-2 border-t border-slate-100 px-5 py-3.5">
        <div>
          {step === 0 && onCancel && (
            <Button variant="outline" onClick={onCancel}>
              Cancel
            </Button>
          )}
        </div>
        <div className="flex gap-2">
          {step === 0 && (
            <Button
              loading={create.pending}
              onClick={async () => {
                const w = await create.run(form);
                if (w) {
                  setWebhook(w);
                  setStep(1);
                }
              }}
            >
              Register endpoint <ArrowRight className="h-4 w-4" />
            </Button>
          )}
          {step === 1 && webhook && (
            <Button
              loading={configure.pending}
              onClick={async () => {
                const w = await configure.run(webhook.id);
                if (w) {
                  setWebhook(w);
                  setStep(2);
                }
              }}
            >
              Continue <ArrowRight className="h-4 w-4" />
            </Button>
          )}
          {step === 2 && (
            <Button disabled={!result?.ok} onClick={() => setStep(3)}>
              Continue <ArrowRight className="h-4 w-4" />
            </Button>
          )}
          {step === 3 && (
            <>
              <Button variant="outline" onClick={onDone}>
                Done
              </Button>
              <Button onClick={() => navigate('/integrations/catalog')}>
                Next: connect an integration <ArrowRight className="h-4 w-4" />
              </Button>
            </>
          )}
        </div>
      </div>
    </Card>
  );
}
