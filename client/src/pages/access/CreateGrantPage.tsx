import { useEffect, useMemo, useState } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { ArrowLeft, ArrowRight, Bot, CheckCircle2, FlaskConical, Github, Lock } from 'lucide-react';
import { PERMISSIONS, type Agent, type GrantDetail, type Integration } from '@token-vault/shared';
import { getProvider, operationLabel, useProviders } from '@/lib/providers';
import { useApi, useMutation } from '@/hooks/useApi';
import { useAuth } from '@/context/AuthContext';
import { api } from '@/lib/api';
import { Button } from '@/components/ui/button';
import { Card, CardBody, DetailList } from '@/components/ui/card';
import { Badge, EnvBadge, StatusBadge } from '@/components/ui/badge';
import { Checkbox, Field, Input, Switch } from '@/components/ui/form';
import { Callout, EmptyState, FormError, PermissionDenied, Spinner } from '@/components/ui/feedback';
import { PageHeader, Stepper } from '@/components/ui/navigation';
import { useToast } from '@/components/ui/toast';
import { AGENT_TYPE_LABELS, cn, formatDateTime, fromLocalInput, splitList, toLocalInput } from '@/lib/utils';

const STEPS = ['Select agent', 'Select integration', 'Select permissions', 'Configure restrictions', 'Review and create'];

export function CreateGrantPage() {
  const { operations, grantable } = useProviders();
  const { can } = useAuth();
  const navigate = useNavigate();
  const toast = useToast();
  const [params] = useSearchParams();
  const agents = useApi<{ items: Agent[] }>('/agents');
  const integrations = useApi<{ items: Integration[] }>('/integrations');

  const [step, setStep] = useState(0);
  const [agentId, setAgentId] = useState(params.get('agentId') ?? '');
  const [integrationId, setIntegrationId] = useState(params.get('integrationId') ?? '');
  const [scopes, setScopes] = useState<string[]>([]);
  const [r, setR] = useState(() => ({
    name: '',
    repositories: '',
    validFrom: toLocalInput(new Date()),
    expiresAt: toLocalInput(new Date(Date.now() + 7 * 86400e3)),
    rateLimitPerMinute: '10',
    allowedCidrs: '',
    approvalRequired: false,
  }));
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [created, setCreated] = useState<GrantDetail | null>(null);
  const submit = useMutation((body: unknown) => api.post<GrantDetail>('/grants', body));

  const agent = agents.data?.items.find((a) => a.id === agentId);
  const integration = integrations.data?.items.find((i) => i.id === integrationId);
  const provider = integration ? getProvider(integration.provider) : undefined;
  const resourceLabel = provider?.resource.label ?? 'Repository';

  useEffect(() => {
    if (agent && integration && !r.name) setR((x) => ({ ...x, name: `${agent.name} → ${integration.displayName}` }));
  }, [agent, integration, r.name]);
  useEffect(() => {
    if (params.get('agentId') && params.get('integrationId')) setStep(2);
    else if (params.get('agentId')) setStep(1);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Map server field errors back onto the step that owns them.
  useEffect(() => {
    const fe = submit.fieldErrors;
    if (Object.keys(fe).length === 0) return;
    if (fe.agentId) setStep(0);
    else if (fe.integrationId) setStep(1);
    else if (fe.scopes) setStep(2);
    else setStep(3);
  }, [submit.fieldErrors]);

  const allErrors = { ...submit.fieldErrors, ...errors };
  const repos = useMemo(() => splitList(r.repositories), [r.repositories]);

  if (!can(PERMISSIONS.GRANT_MANAGE)) return <PermissionDenied required={PERMISSIONS.GRANT_MANAGE} message="Only Vault Administrators and Owners can create access grants." />;
  if ((agents.loading && !agents.data) || (integrations.loading && !integrations.data)) return <Spinner />;

  function validateStep(s: number): boolean {
    const e: Record<string, string> = {};
    if (s === 0 && !agentId) e.agentId = 'Select an agent';
    if (s === 1 && !integrationId) e.integrationId = 'Select an integration';
    if (s === 2 && scopes.length === 0) e.scopes = 'Select at least one permission';
    if (s === 3) {
      if (r.name.trim().length < 3) e.name = 'Grant name must be at least 3 characters';
      const from = new Date(r.validFrom).getTime();
      const to = new Date(r.expiresAt).getTime();
      if (!r.validFrom || Number.isNaN(from)) e.validFrom = 'Enter a valid start date/time';
      if (!r.expiresAt || Number.isNaN(to)) e.expiresAt = 'Enter a valid expiry';
      else if (to <= from) e.expiresAt = 'Expiry must be after the start time';
      else if (to <= Date.now()) e.expiresAt = 'Expiry must be in the future';
      const rate = Number(r.rateLimitPerMinute);
      if (!Number.isInteger(rate) || rate < 1 || rate > 600) e.rateLimitPerMinute = 'Enter a whole number between 1 and 600';
      const pattern = provider ? new RegExp(provider.resource.pattern) : /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/;
      const bad = repos.find((x) => !pattern.test(x));
      if (bad) e.repositories = `"${bad}" is not a valid ${resourceLabel.toLowerCase()}${provider?.resource.example ? ` (e.g. ${provider.resource.example})` : ''}`;
      else if (integration?.allowedResources.length) {
        const outside = repos.filter((x) => !integration.allowedResources.some((a) => a.toLowerCase() === x.toLowerCase()));
        if (outside.length) e.repositories = `Not allowed by the integration: ${outside.join(', ')}`;
      }
    }
    setErrors(e);
    return Object.keys(e).length === 0;
  }

  async function create() {
    const result = await submit.run({
      name: r.name,
      agentId,
      integrationId,
      environment: integration!.environment,
      scopes,
      repositories: repos,
      validFrom: fromLocalInput(r.validFrom),
      expiresAt: fromLocalInput(r.expiresAt),
      rateLimitPerMinute: Number(r.rateLimitPerMinute),
      allowedCidrs: splitList(r.allowedCidrs),
      approvalRequired: r.approvalRequired,
    });
    if (result) {
      setCreated(result);
      toast.success('Grant created', result.status === 'ACTIVE' ? 'The agent is authorized immediately.' : 'Awaiting Security Administrator approval.');
    }
  }

  if (created) {
    return (
      <div className="mx-auto max-w-2xl">
        <PageHeader title="Grant created" breadcrumbs={[{ label: 'Access Management' }, { label: 'Access Grants', to: '/access/grants' }, { label: 'New grant' }]} />
        <Card>
          <CardBody className="space-y-5">
            <div className="flex items-center gap-3">
              <CheckCircle2 className="h-8 w-8 text-emerald-600" />
              <div>
                <p className="font-semibold text-slate-900">{created.name}</p>
                <p className="text-sm text-slate-500">
                  {created.agentName} → {created.integrationName}
                </p>
              </div>
              <div className="ml-auto">
                <StatusBadge status={created.status} />
              </div>
            </div>
            {created.status === 'PENDING_APPROVAL' && <Callout tone="warning">Requests will be denied with GRANT_PENDING_APPROVAL until a Security Administrator approves this grant (simulated approval).</Callout>}
            <div className="flex flex-wrap gap-2">
              <Button onClick={() => navigate('/playground')}>
                <FlaskConical className="h-4 w-4" /> Test in playground
              </Button>
              <Button variant="outline" onClick={() => navigate(`/access/grants/${created.id}`)}>
                View grant
              </Button>
            </div>
          </CardBody>
        </Card>
      </div>
    );
  }

  const activeAgents = agents.data?.items ?? [];
  const connectedIntegrations = integrations.data?.items ?? [];

  return (
    <div>
      <PageHeader title="Create access grant" description="Authorize a specific agent to use a specific integration under defined restrictions." breadcrumbs={[{ label: 'Access Management' }, { label: 'Access Grants', to: '/access/grants' }, { label: 'New grant' }]} />
      <Card>
        <div className="border-b border-slate-100 px-5 py-4">
          <Stepper steps={STEPS} current={step} />
        </div>
        <CardBody className="min-h-[22rem] space-y-4">
          <FormError error={submit.error} />

          {step === 0 && (
            <>
              <h2 className="text-sm font-semibold text-slate-900">Step 1: Select agent</h2>
              {allErrors.agentId && <p className="text-sm text-red-600">{allErrors.agentId}</p>}
              {activeAgents.length === 0 ? (
                <EmptyState icon={<Bot className="h-5 w-5" />} title="No agents registered" action={<Button onClick={() => navigate('/agents?register=1')}>Register agent</Button>} />
              ) : (
                <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
                  {activeAgents.map((a) => (
                    <SelectCard key={a.id} selected={agentId === a.id} disabled={a.status !== 'ACTIVE'} onClick={() => setAgentId(a.id)}>
                      <div className="flex items-start justify-between gap-2">
                        <span className="font-medium text-slate-900">{a.name}</span>
                        <StatusBadge status={a.status} />
                      </div>
                      <p className="mt-1 text-xs text-slate-500">
                        {AGENT_TYPE_LABELS[a.agentType]} · {a.environment} · owner {a.ownerName}
                      </p>
                      {a.status !== 'ACTIVE' && <p className="mt-1 text-xs text-amber-700">Disabled agents cannot receive grants</p>}
                    </SelectCard>
                  ))}
                </div>
              )}
            </>
          )}

          {step === 1 && (
            <>
              <h2 className="text-sm font-semibold text-slate-900">Step 2: Select integration</h2>
              {allErrors.integrationId && <p className="text-sm text-red-600">{allErrors.integrationId}</p>}
              {connectedIntegrations.length === 0 ? (
                <EmptyState icon={<Github className="h-5 w-5" />} title="No integrations connected" action={<Button onClick={() => navigate('/integrations/connect/github')}>Connect GitHub</Button>} />
              ) : (
                <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
                  {connectedIntegrations.map((i) => (
                    <SelectCard key={i.id} selected={integrationId === i.id} disabled={i.credentialStatus !== 'CONNECTED'} onClick={() => setIntegrationId(i.id)}>
                      <div className="flex items-start justify-between gap-2">
                        <span className="flex items-center gap-1.5 font-medium text-slate-900">
                          <Github className="h-4 w-4" /> {i.displayName}
                        </span>
                        <StatusBadge status={i.credentialStatus} />
                      </div>
                      <div className="mt-2 flex items-center gap-2">
                        <EnvBadge env={i.environment} />
                        <span className="font-mono text-[11px] text-slate-500">{i.credentialReference}</span>
                      </div>
                    </SelectCard>
                  ))}
                </div>
              )}
              {agent && integration && agent.environment !== integration.environment && <Callout tone="warning">The agent ({agent.environment}) and integration ({integration.environment}) are in different environments. The grant will use the integration's environment.</Callout>}
            </>
          )}

          {step === 2 && (
            <>
              <h2 className="text-sm font-semibold text-slate-900">Step 3: Select permissions</h2>
              {allErrors.scopes && <p className="text-sm text-red-600">{allErrors.scopes}</p>}
              <div className="grid gap-3 md:grid-cols-2">
                {grantable.filter((o) => !integration || o.provider === integration.provider).map((o) => (
                  <div key={o.id} className={cn('rounded-lg border p-3.5', scopes.includes(o.id) ? 'border-brand-400 bg-brand-50/40' : 'border-slate-200')}>
                    <Checkbox id={o.id} checked={scopes.includes(o.id)} onChange={(v) => setScopes((s) => (v ? [...s, o.id] : s.filter((x) => x !== o.id)))} label={o.label} description={<span className="font-mono">{o.id} · {o.description}</span>} />
                  </div>
                ))}
              </div>
              <div className="rounded-lg border border-dashed border-slate-200 p-3.5">
                <p className="flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wide text-slate-500">
                  <Lock className="h-3.5 w-3.5" /> Not available in this POC
                </p>
                <div className="mt-2 flex flex-wrap gap-2">
                  {operations.filter((o) => !o.grantable && (!integration || o.provider === integration.provider)).map((o) => (
                    <Badge key={o.id} tone="gray">
                      {o.label}
                    </Badge>
                  ))}
                </div>
                <p className="mt-2 text-xs text-slate-500">Destructive operations cannot be granted and are additionally blocked by an explicit deny policy.</p>
              </div>
            </>
          )}

          {step === 3 && (
            <>
              <h2 className="text-sm font-semibold text-slate-900">Step 4: Configure restrictions</h2>
              <div className="grid gap-4 md:grid-cols-2">
                <Field label="Grant name" required error={allErrors.name}>
                  <Input value={r.name} onChange={(e) => setR({ ...r, name: e.target.value })} invalid={!!allErrors.name} />
                </Field>
                <Field label="Environment" hint="Inherited from the integration">
                  <Input value={integration?.environment ?? ''} disabled />
                </Field>
                <Field label={`Allowed ${resourceLabel.toLowerCase()} (optional)`} error={allErrors.repositories ?? allErrors['repositories.0']} hint={integration?.allowedResources.length ? `Integration allows: ${integration.allowedResources.join(', ')}` : `Leave empty to allow any ${resourceLabel.toLowerCase()} the integration can reach.`}>
                  <Input aria-label="Allowed resource" value={r.repositories} onChange={(e) => setR({ ...r, repositories: e.target.value })} placeholder={provider?.resource.example ?? 'demo-org/demo-repo'} className="font-mono text-xs" invalid={!!allErrors.repositories} />
                </Field>
                <Field label="Maximum requests per minute" required error={allErrors.rateLimitPerMinute}>
                  <Input type="number" min={1} max={600} value={r.rateLimitPerMinute} onChange={(e) => setR({ ...r, rateLimitPerMinute: e.target.value })} invalid={!!allErrors.rateLimitPerMinute} />
                </Field>
                <Field label="Valid from" required error={allErrors.validFrom}>
                  <Input type="datetime-local" value={r.validFrom} onChange={(e) => setR({ ...r, validFrom: e.target.value })} invalid={!!allErrors.validFrom} />
                </Field>
                <Field label="Expiry date/time" required error={allErrors.expiresAt}>
                  <Input type="datetime-local" value={r.expiresAt} onChange={(e) => setR({ ...r, expiresAt: e.target.value })} invalid={!!allErrors.expiresAt} />
                </Field>
                <Field label="Allowed source IP / CIDR (optional)" error={allErrors['allowedCidrs.0']} hint="IPv4 CIDRs, comma separated. The playground calls from 127.0.0.1.">
                  <Input value={r.allowedCidrs} onChange={(e) => setR({ ...r, allowedCidrs: e.target.value })} placeholder="10.20.0.0/16" className="font-mono text-xs" />
                </Field>
                <div className="flex items-start justify-between gap-4 rounded-lg border border-slate-200 p-3.5">
                  <div>
                    <p className="text-sm font-medium text-slate-800">Approval required</p>
                    <p className="text-xs text-slate-500">Grant stays Pending until a Security Administrator approves it (simulated).</p>
                  </div>
                  <Switch checked={r.approvalRequired} onChange={(v) => setR({ ...r, approvalRequired: v })} label="Approval required" />
                </div>
              </div>
            </>
          )}

          {step === 4 && agent && integration && (
            <>
              <h2 className="text-sm font-semibold text-slate-900">Step 5: Review and create</h2>
              <div className="rounded-lg border border-slate-200 bg-slate-50/60 p-4 text-sm leading-relaxed text-slate-700">
                <strong>{agent.name}</strong> may perform <strong>{scopes.map(operationLabel).join(', ')}</strong> on <strong>{integration.displayName}</strong>
                {repos.length ? (
                  <>
                    {' '}
                    limited to <strong>{repos.join(', ')}</strong>
                  </>
                ) : (
                  ' on any allowed repository'
                )}
                , from <strong>{formatDateTime(fromLocalInput(r.validFrom))}</strong> until <strong>{formatDateTime(fromLocalInput(r.expiresAt))}</strong>, at most <strong>{r.rateLimitPerMinute} requests/minute</strong>.
                {r.approvalRequired && ' Requires approval before it becomes active.'}
              </div>
              <DetailList
                columns={3}
                items={[
                  { label: 'Agent', value: `${agent.name} (${agent.id})` },
                  { label: 'Integration', value: `${integration.displayName} · ${integration.credentialReference}` },
                  { label: 'Allowed operations', value: <div className="flex flex-wrap gap-1">{scopes.map((s) => <Badge key={s} tone="blue">{operationLabel(s)}</Badge>)}</div> },
                  { label: 'Resource restrictions', value: repos.length ? repos.join(', ') : 'None' },
                  { label: 'Validity period', value: `${formatDateTime(fromLocalInput(r.validFrom))} → ${formatDateTime(fromLocalInput(r.expiresAt))}` },
                  { label: 'Rate limit', value: `${r.rateLimitPerMinute} / minute` },
                  { label: 'Source IP restriction', value: r.allowedCidrs || 'None' },
                  { label: 'Approval status', value: r.approvalRequired ? <StatusBadge status="PENDING_APPROVAL" /> : <StatusBadge status="ACTIVE" /> },
                ]}
              />
            </>
          )}
        </CardBody>
        <div className="flex items-center justify-between gap-2 border-t border-slate-100 px-5 py-3.5">
          <Button variant="outline" onClick={() => (step === 0 ? navigate('/access/grants') : setStep(step - 1))}>
            <ArrowLeft className="h-4 w-4" /> {step === 0 ? 'Cancel' : 'Back'}
          </Button>
          {step < 4 ? (
            <Button onClick={() => validateStep(step) && setStep(step + 1)}>
              Continue <ArrowRight className="h-4 w-4" />
            </Button>
          ) : (
            <Button loading={submit.pending} onClick={create}>
              Create grant
            </Button>
          )}
        </div>
      </Card>
    </div>
  );
}

function SelectCard({ selected, disabled, onClick, children }: { selected: boolean; disabled?: boolean; onClick: () => void; children: React.ReactNode }) {
  return (
    <button type="button" disabled={disabled} onClick={onClick} className={cn('rounded-lg border p-3.5 text-left transition disabled:cursor-not-allowed disabled:opacity-50', selected ? 'border-brand-500 bg-brand-50/50 ring-1 ring-brand-500' : 'border-slate-200 hover:border-slate-300')}>
      {children}
    </button>
  );
}
