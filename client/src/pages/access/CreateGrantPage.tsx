import { useEffect, useMemo, useState } from 'react';
import { Link, useNavigate, useSearchParams } from 'react-router-dom';
import { ArrowLeft, ArrowRight, Bot, CheckCircle2, FlaskConical, Github, Lock } from 'lucide-react';
import { PERMISSIONS, type Agent, type GrantDetail, type Integration, type OnBehalfOfMode } from '@token-vault/shared';
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
import { ActingForFields, actingForText } from '@/components/grant/ActingFor';
import { AGENT_TYPE_LABELS, budgetText, budgetValue, cn, formatDateTime, fromLocalInput, splitList, toLocalInput } from '@/lib/utils';

const STEPS = ['Select agent', 'Select integrations', 'Select permissions', 'Configure restrictions', 'Review and create'];

/** What differs per application: the grant's name and its resource restriction. */
type PerIntegration = { name: string; repositories: string };

/**
 * Create grant wizard. Choosing one integration creates one grant (POST /grants). Choosing
 * several creates one grant per integration in a single all-or-nothing request
 * (POST /grants/batch): operations, resources and names per application; validity, rate
 * limit, budgets, user and IP settings shared.
 */
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
  const [integrationIds, setIntegrationIds] = useState<string[]>(params.get('integrationId') ? [params.get('integrationId')!] : []);
  const [scopesBy, setScopesBy] = useState<Record<string, string[]>>({});
  const [perInt, setPerInt] = useState<Record<string, PerIntegration>>({});
  const [r, setR] = useState(() => ({
    validFrom: toLocalInput(new Date()),
    expiresAt: toLocalInput(new Date(Date.now() + 7 * 86400e3)),
    rateLimitPerMinute: '10',
    maxRequestsPerDay: '',
    maxWritesPerHour: '',
    allowedCidrs: '',
    approvalRequired: false,
    onBehalfOf: 'ALLOWED' as OnBehalfOfMode,
    allowedUserGroups: '',
  }));
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [created, setCreated] = useState<GrantDetail[] | null>(null);
  const submitOne = useMutation((body: unknown) => api.post<GrantDetail>('/grants', body));
  const submitMany = useMutation((body: unknown) => api.post<{ items: GrantDetail[] }>('/grants/batch', body));
  const submit = integrationIds.length > 1 ? submitMany : submitOne;

  const agent = agents.data?.items.find((a) => a.id === agentId);
  const selected = useMemo(() => integrationIds.map((id) => integrations.data?.items.find((i) => i.id === id)).filter((i): i is Integration => !!i), [integrationIds, integrations.data]);
  const multi = selected.length > 1;

  // Default grant names: "<agent> → <integration>".
  useEffect(() => {
    if (!agent) return;
    setPerInt((p) => {
      const next = { ...p };
      for (const i of selected) if (!next[i.id]?.name) next[i.id] = { repositories: next[i.id]?.repositories ?? '', name: `${agent.name} → ${i.displayName}` };
      return next;
    });
  }, [agent, selected]);
  useEffect(() => {
    if (params.get('agentId') && params.get('integrationId')) setStep(2);
    else if (params.get('agentId')) setStep(1);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Server field errors: single creation uses plain names; several use items.<n>.<field>, mapped back to the integration.
  const serverErrors = useMemo(() => {
    const out: Record<string, string> = {};
    for (const [k, v] of Object.entries(submit.fieldErrors)) {
      const m = /^items\.(\d+)\.(\w+)/.exec(k);
      if (m) out[`${m[2]}:${integrationIds[Number(m[1])]}`] = v;
      else if (!multi && ['scopes', 'repositories', 'name', 'integrationId'].includes(k.split('.')[0]!)) out[`${k.split('.')[0]}:${integrationIds[0]}`] = v;
      else out[k] = v;
    }
    return out;
  }, [submit.fieldErrors, integrationIds, multi]);
  useEffect(() => {
    const keys = Object.keys(serverErrors);
    if (keys.length === 0) return;
    if (keys.some((k) => k === 'agentId')) setStep(0);
    else if (keys.some((k) => k.startsWith('integrationId') || k === 'items')) setStep(1);
    else if (keys.some((k) => k.startsWith('scopes'))) setStep(2);
    else setStep(3);
  }, [serverErrors]);

  const allErrors: Record<string, string> = { ...serverErrors, ...errors };

  if (!can(PERMISSIONS.GRANT_MANAGE)) return <PermissionDenied required={PERMISSIONS.GRANT_MANAGE} message="Only Vault Administrators and Owners can create access grants." />;
  if ((agents.loading && !agents.data) || (integrations.loading && !integrations.data)) return <Spinner />;

  const scopesOf = (id: string) => scopesBy[id] ?? [];
  const reposOf = (id: string) => splitList(perInt[id]?.repositories ?? '');
  const toggleIntegration = (id: string) => setIntegrationIds((ids) => (ids.includes(id) ? ids.filter((x) => x !== id) : [...ids, id]));
  const setScope = (id: string, op: string, on: boolean) => setScopesBy((s) => ({ ...s, [id]: on ? [...(s[id] ?? []), op] : (s[id] ?? []).filter((x) => x !== op) }));
  const setItem = (id: string, patch: Partial<PerIntegration>) => setPerInt((p) => ({ ...p, [id]: { name: p[id]?.name ?? '', repositories: p[id]?.repositories ?? '', ...patch } }));

  function validateStep(s: number): boolean {
    const e: Record<string, string> = {};
    if (s === 0 && !agentId) e.agentId = 'Select an agent';
    if (s === 1 && integrationIds.length === 0) e.integrationId = 'Select at least one integration';
    if (s === 1 && integrationIds.length > 10) e.integrationId = 'Select at most 10 integrations at once';
    if (s === 2) for (const i of selected) if (scopesOf(i.id).length === 0) e[`scopes:${i.id}`] = multi ? `Select at least one permission for ${i.displayName}` : 'Select at least one permission';
    if (s === 3) {
      for (const i of selected) {
        if ((perInt[i.id]?.name ?? '').trim().length < 3) e[`name:${i.id}`] = 'Grant name must be at least 3 characters';
        const provider = getProvider(i.provider);
        const label = (provider?.resource.label ?? 'Repository').toLowerCase();
        const pattern = provider ? new RegExp(provider.resource.pattern) : /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/;
        const repos = reposOf(i.id);
        const bad = repos.find((x) => !pattern.test(x));
        if (bad) e[`repositories:${i.id}`] = `"${bad}" is not a valid ${label}${provider?.resource.example ? ` (e.g. ${provider.resource.example})` : ''}`;
        else if (i.allowedResources.length) {
          const outside = repos.filter((x) => !i.allowedResources.some((a) => a.toLowerCase() === x.toLowerCase()));
          if (outside.length) e[`repositories:${i.id}`] = `Not allowed by the integration: ${outside.join(', ')}`;
        }
      }
      const names = selected.map((i) => (perInt[i.id]?.name ?? '').trim().toLowerCase());
      selected.forEach((i, n) => {
        if (names.indexOf(names[n]!) !== n) e[`name:${i.id}`] = 'Each grant needs its own name';
      });
      const from = new Date(r.validFrom).getTime();
      const to = new Date(r.expiresAt).getTime();
      if (!r.validFrom || Number.isNaN(from)) e.validFrom = 'Enter a valid start date/time';
      if (!r.expiresAt || Number.isNaN(to)) e.expiresAt = 'Enter a valid expiry';
      else if (to <= from) e.expiresAt = 'Expiry must be after the start time';
      else if (to <= Date.now()) e.expiresAt = 'Expiry must be in the future';
      const rate = Number(r.rateLimitPerMinute);
      if (!Number.isInteger(rate) || rate < 1 || rate > 600) e.rateLimitPerMinute = 'Enter a whole number between 1 and 600';
      if (budgetValue(r.maxRequestsPerDay) === undefined) e.maxRequestsPerDay = 'Leave empty, or enter a whole number of at least 1';
      if (budgetValue(r.maxWritesPerHour) === undefined) e.maxWritesPerHour = 'Leave empty, or enter a whole number of at least 1';
    }
    setErrors(e);
    return Object.keys(e).length === 0;
  }

  async function create() {
    const shared = {
      agentId,
      validFrom: fromLocalInput(r.validFrom),
      expiresAt: fromLocalInput(r.expiresAt),
      rateLimitPerMinute: Number(r.rateLimitPerMinute),
      maxRequestsPerDay: budgetValue(r.maxRequestsPerDay) ?? null,
      maxWritesPerHour: budgetValue(r.maxWritesPerHour) ?? null,
      allowedCidrs: splitList(r.allowedCidrs),
      approvalRequired: r.approvalRequired,
      onBehalfOf: r.onBehalfOf,
      allowedUserGroups: r.onBehalfOf === 'NOT_ALLOWED' ? [] : splitList(r.allowedUserGroups),
    };
    let result: GrantDetail[] | undefined;
    if (multi) {
      result = (await submitMany.run({ ...shared, items: selected.map((i) => ({ integrationId: i.id, name: perInt[i.id]?.name.trim(), scopes: scopesOf(i.id), repositories: reposOf(i.id) })) }))?.items;
    } else {
      const i = selected[0]!;
      const one = await submitOne.run({ ...shared, name: perInt[i.id]?.name ?? '', integrationId: i.id, environment: i.environment, scopes: scopesOf(i.id), repositories: reposOf(i.id) });
      result = one ? [one] : undefined;
    }
    if (result) {
      setCreated(result);
      const pending = result.some((g) => g.status !== 'ACTIVE');
      toast.success(result.length > 1 ? `${result.length} grants created` : 'Grant created', pending ? 'Awaiting Security Administrator approval.' : 'The agent is authorized immediately.');
    }
  }

  if (created) {
    const first = created[0]!;
    return (
      <div className="mx-auto max-w-2xl">
        <PageHeader title={created.length > 1 ? `${created.length} grants created` : 'Grant created'} breadcrumbs={[{ label: 'Access Management' }, { label: 'Access Grants', to: '/access/grants' }, { label: 'New grant' }]} />
        <Card>
          <CardBody className="space-y-5">
            {created.length > 1 && <p className="text-sm text-slate-600">One grant per application, so each can be edited, reviewed or revoked on its own. The agent uses all of them with its one API key.</p>}
            <ul className="space-y-3">
              {created.map((g) => (
                <li key={g.id} className="flex items-center gap-3">
                  <CheckCircle2 className="h-6 w-6 shrink-0 text-emerald-600" />
                  <div className="min-w-0">
                    <p className="font-semibold text-slate-900">
                      {created.length > 1 ? (
                        <Link className="hover:underline" to={`/access/grants/${g.id}`}>
                          {g.name}
                        </Link>
                      ) : (
                        g.name
                      )}
                    </p>
                    <p className="text-sm text-slate-500">
                      {g.agentName} → {g.integrationName} · {g.scopes.map(operationLabel).join(', ')}
                    </p>
                  </div>
                  <div className="ml-auto">
                    <StatusBadge status={g.status} />
                  </div>
                </li>
              ))}
            </ul>
            {created.some((g) => g.status === 'PENDING_APPROVAL') && <Callout tone="warning">Requests will be denied with GRANT_PENDING_APPROVAL until a Security Administrator approves {created.length > 1 ? 'these grants' : 'this grant'} (simulated approval).</Callout>}
            <div className="flex flex-wrap gap-2">
              <Button onClick={() => navigate('/playground')}>
                <FlaskConical className="h-4 w-4" /> Test in playground
              </Button>
              <Button variant="outline" onClick={() => navigate(created.length > 1 ? `/agents/${first.agentId}` : `/access/grants/${first.id}`)}>
                {created.length > 1 ? 'View agent' : 'View grant'}
              </Button>
            </div>
          </CardBody>
        </Card>
      </div>
    );
  }

  const activeAgents = agents.data?.items ?? [];
  const connectedIntegrations = integrations.data?.items ?? [];

  /** Permission checkboxes of one integration (ids are unique per integration). */
  function permissionsFor(i: Integration) {
    const mine = scopesOf(i.id);
    const destructive = operations.filter((o) => o.destructive && o.provider === i.provider);
    const err = allErrors[`scopes:${i.id}`];
    return (
      <div className="space-y-3">
        {err && <p className="text-sm text-red-600">{err}</p>}
        <div className="grid gap-3 md:grid-cols-2">
          {grantable.filter((o) => o.provider === i.provider).map((o) => (
            <div key={o.id} className={cn('rounded-lg border p-3.5', mine.includes(o.id) ? 'border-brand-400 bg-brand-50/40' : 'border-slate-200')}>
              <Checkbox id={`${i.id}-${o.id}`} checked={mine.includes(o.id)} onChange={(v) => setScope(i.id, o.id, v)} label={o.label} description={<span className="font-mono">{o.id} · {o.description}</span>} />
            </div>
          ))}
        </div>
        {destructive.length > 0 && (
          <div className="rounded-lg border border-red-200 bg-red-50/40 p-3.5">
            <p className="flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wide text-red-800">
              <Lock className="h-3.5 w-3.5" /> Destructive: every request needs a human's approval
            </p>
            <p className="mt-1 text-xs text-slate-600">
              These can be granted only if an enabled <strong>Require approval</strong> policy covers them for this agent (without a time window, source IP or argument rules). Each request then waits under Approvals, and the customer webhook must allow destructive operations. A Deny policy still wins.
            </p>
            <div className="mt-3 grid gap-3 md:grid-cols-2">
              {destructive.map((o) => (
                <div key={o.id} className={cn('rounded-lg border bg-white p-3.5', mine.includes(o.id) ? 'border-red-400' : 'border-slate-200')}>
                  <Checkbox id={`${i.id}-${o.id}`} checked={mine.includes(o.id)} onChange={(v) => setScope(i.id, o.id, v)} label={o.label} description={<span className="font-mono">{o.id} · {o.description}</span>} />
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    );
  }

  /** Name and resources of one integration's grant. */
  function itemFields(i: Integration) {
    const provider = getProvider(i.provider);
    const resourceLabel = provider?.resource.label ?? 'Repository';
    const suffix = multi ? ` for ${i.displayName}` : '';
    const nameErr = allErrors[`name:${i.id}`];
    const repoErr = allErrors[`repositories:${i.id}`] ?? allErrors[`repositories.0:${i.id}`];
    return (
      <>
        <Field label={`Grant name${suffix}`} required error={nameErr}>
          <Input aria-label={`Grant name${suffix}`} value={perInt[i.id]?.name ?? ''} onChange={(e) => setItem(i.id, { name: e.target.value })} invalid={!!nameErr} />
        </Field>
        <Field label={`Allowed ${resourceLabel.toLowerCase()} (optional)`} error={repoErr} hint={i.allowedResources.length ? `Integration allows: ${i.allowedResources.join(', ')}` : `Leave empty to allow any ${resourceLabel.toLowerCase()} the integration can reach.`}>
          <Input aria-label={`Allowed resource${suffix}`} value={perInt[i.id]?.repositories ?? ''} onChange={(e) => setItem(i.id, { repositories: e.target.value })} placeholder={provider?.resource.example ?? 'demo-org/demo-repo'} className="font-mono text-xs" invalid={!!repoErr} />
        </Field>
      </>
    );
  }

  const sentence = (i: Integration) => {
    const repos = reposOf(i.id);
    return (
      <>
        <strong>{scopesOf(i.id).map(operationLabel).join(', ')}</strong> on <strong>{i.displayName}</strong>
        {repos.length ? (
          <>
            {' '}
            limited to <strong>{repos.join(', ')}</strong>
          </>
        ) : (
          ' on any allowed resource'
        )}
      </>
    );
  };

  return (
    <div>
      <PageHeader title="Create access grant" description="Authorize a specific agent to use one or more integrations under defined restrictions." breadcrumbs={[{ label: 'Access Management' }, { label: 'Access Grants', to: '/access/grants' }, { label: 'New grant' }]} />
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
              <div className="flex flex-wrap items-baseline justify-between gap-2">
                <h2 className="text-sm font-semibold text-slate-900">Step 2: Select integrations</h2>
                <p className="text-xs text-slate-500">{integrationIds.length > 1 ? `${integrationIds.length} selected: one grant will be created for each` : 'Select one, or several to grant access to multiple applications at once'}</p>
              </div>
              {(allErrors.integrationId || allErrors.items) && <p className="text-sm text-red-600">{allErrors.integrationId ?? allErrors.items}</p>}
              {selected.map((i) => allErrors[`integrationId:${i.id}`] && <p key={i.id} className="text-sm text-red-600">{i.displayName}: {allErrors[`integrationId:${i.id}`]}</p>)}
              {connectedIntegrations.length === 0 ? (
                <EmptyState icon={<Github className="h-5 w-5" />} title="No integrations connected" action={<Button onClick={() => navigate('/integrations/connect/github')}>Connect GitHub</Button>} />
              ) : (
                <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
                  {connectedIntegrations.map((i) => (
                    <SelectCard key={i.id} selected={integrationIds.includes(i.id)} disabled={i.credentialStatus !== 'CONNECTED'} onClick={() => toggleIntegration(i.id)}>
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
              {agent && selected.some((i) => i.environment !== agent.environment) && <Callout tone="warning">The agent ({agent.environment}) and {multi ? 'some integrations' : `the integration (${selected[0]!.environment})`} are in different environments. Each grant uses its integration's environment.</Callout>}
            </>
          )}

          {step === 2 && (
            <>
              <h2 className="text-sm font-semibold text-slate-900">Step 3: Select permissions</h2>
              {multi ? (
                selected.map((i) => (
                  <section key={i.id} className="space-y-2 rounded-lg border border-slate-200 p-4">
                    <h3 className="flex items-center gap-2 text-sm font-semibold text-slate-900">
                      {i.displayName} <span className="text-xs font-normal text-slate-500">{getProvider(i.provider)?.name ?? i.provider}</span>
                    </h3>
                    {permissionsFor(i)}
                  </section>
                ))
              ) : (
                selected[0] && permissionsFor(selected[0])
              )}
            </>
          )}

          {step === 3 && (
            <>
              <h2 className="text-sm font-semibold text-slate-900">Step 4: Configure restrictions</h2>
              {multi ? (
                <div className="space-y-3">
                  <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">Per application</p>
                  {selected.map((i) => (
                    <div key={i.id} className="grid gap-4 rounded-lg border border-slate-200 p-4 md:grid-cols-2">
                      {itemFields(i)}
                    </div>
                  ))}
                  <p className="pt-2 text-xs font-semibold uppercase tracking-wide text-slate-500">For all {selected.length} grants</p>
                </div>
              ) : null}
              <div className="grid gap-4 md:grid-cols-2">
                {!multi && selected[0] && (
                  <>
                    {itemFields(selected[0])}
                    <Field label="Environment" hint="Inherited from the integration">
                      <Input value={selected[0].environment} disabled />
                    </Field>
                  </>
                )}
                <Field label="Maximum requests per minute" required error={allErrors.rateLimitPerMinute} hint={multi ? 'Per grant, so per application.' : undefined}>
                  <Input aria-label="Maximum requests per minute" type="number" min={1} max={600} value={r.rateLimitPerMinute} onChange={(e) => setR({ ...r, rateLimitPerMinute: e.target.value })} invalid={!!allErrors.rateLimitPerMinute} />
                </Field>
                <Field label="Budget: requests per 24 hours (optional)" error={allErrors.maxRequestsPerDay} hint={`Authorized requests in any rolling 24 hours${multi ? ', per application' : ''}. Empty: no limit.`}>
                  <Input type="number" min={1} value={r.maxRequestsPerDay} onChange={(e) => setR({ ...r, maxRequestsPerDay: e.target.value })} invalid={!!allErrors.maxRequestsPerDay} placeholder="No limit" />
                </Field>
                <Field label="Budget: writes per hour (optional)" error={allErrors.maxWritesPerHour} hint="Operations that change data, in any rolling hour. Reads don't count. Empty: no limit.">
                  <Input type="number" min={1} value={r.maxWritesPerHour} onChange={(e) => setR({ ...r, maxWritesPerHour: e.target.value })} invalid={!!allErrors.maxWritesPerHour} placeholder="No limit" />
                </Field>
                <Field label="Valid from" required error={allErrors.validFrom}>
                  <Input type="datetime-local" value={r.validFrom} onChange={(e) => setR({ ...r, validFrom: e.target.value })} invalid={!!allErrors.validFrom} />
                </Field>
                <Field label="Expiry date/time" required error={allErrors.expiresAt}>
                  <Input type="datetime-local" value={r.expiresAt} onChange={(e) => setR({ ...r, expiresAt: e.target.value })} invalid={!!allErrors.expiresAt} />
                </Field>
                <ActingForFields mode={r.onBehalfOf} groups={r.allowedUserGroups} errors={allErrors} onChange={(v) => setR({ ...r, ...(v.mode ? { onBehalfOf: v.mode } : {}), ...(v.groups !== undefined ? { allowedUserGroups: v.groups } : {}) })} />
                <Field label="Allowed source IP / CIDR (optional)" error={allErrors['allowedCidrs.0']} hint="IPv4 CIDRs, comma separated. The playground calls from 127.0.0.1.">
                  <Input value={r.allowedCidrs} onChange={(e) => setR({ ...r, allowedCidrs: e.target.value })} placeholder="10.20.0.0/16" className="font-mono text-xs" />
                </Field>
                <div className="flex items-start justify-between gap-4 rounded-lg border border-slate-200 p-3.5">
                  <div>
                    <p className="text-sm font-medium text-slate-800">Approval required</p>
                    <p className="text-xs text-slate-500">{multi ? 'The grants stay' : 'Grant stays'} Pending until a Security Administrator approves {multi ? 'them' : 'it'} (simulated).</p>
                  </div>
                  <Switch checked={r.approvalRequired} onChange={(v) => setR({ ...r, approvalRequired: v })} label="Approval required" />
                </div>
              </div>
            </>
          )}

          {step === 4 && agent && selected.length > 0 && (
            <>
              <h2 className="text-sm font-semibold text-slate-900">Step 5: Review and create</h2>
              <div className="rounded-lg border border-slate-200 bg-slate-50/60 p-4 text-sm leading-relaxed text-slate-700">
                {multi ? (
                  <>
                    <strong>{agent.name}</strong> may perform:
                    <ul className="my-2 list-disc space-y-1 pl-5">
                      {selected.map((i) => (
                        <li key={i.id}>{sentence(i)}</li>
                      ))}
                    </ul>
                    from <strong>{formatDateTime(fromLocalInput(r.validFrom))}</strong> until <strong>{formatDateTime(fromLocalInput(r.expiresAt))}</strong>, at most <strong>{r.rateLimitPerMinute} requests/minute</strong> per application. {selected.length} separate grants will be created, all or none.
                  </>
                ) : (
                  <>
                    <strong>{agent.name}</strong> may perform {sentence(selected[0]!)}, from <strong>{formatDateTime(fromLocalInput(r.validFrom))}</strong> until <strong>{formatDateTime(fromLocalInput(r.expiresAt))}</strong>, at most <strong>{r.rateLimitPerMinute} requests/minute</strong>.
                  </>
                )}
                {r.approvalRequired && ' Requires approval before it becomes active.'}
              </div>
              <DetailList
                columns={3}
                items={[
                  { label: 'Agent', value: `${agent.name} (${agent.id})` },
                  ...(multi
                    ? selected.map((i) => ({
                        label: perInt[i.id]?.name || i.displayName,
                        value: (
                          <div className="space-y-1">
                            <div className="flex flex-wrap gap-1">
                              {scopesOf(i.id).map((s) => (
                                <Badge key={s} tone="blue">
                                  {operationLabel(s)}
                                </Badge>
                              ))}
                            </div>
                            <div className="text-xs text-slate-500">
                              {i.displayName} · {reposOf(i.id).length ? reposOf(i.id).join(', ') : 'no resource restriction'}
                            </div>
                          </div>
                        ),
                      }))
                    : [
                        { label: 'Integration', value: `${selected[0]!.displayName} · ${selected[0]!.credentialReference}` },
                        { label: 'Allowed operations', value: <div className="flex flex-wrap gap-1">{scopesOf(selected[0]!.id).map((s) => <Badge key={s} tone="blue">{operationLabel(s)}</Badge>)}</div> },
                        { label: 'Resource restrictions', value: reposOf(selected[0]!.id).length ? reposOf(selected[0]!.id).join(', ') : 'None' },
                      ]),
                  { label: 'Validity period', value: `${formatDateTime(fromLocalInput(r.validFrom))} → ${formatDateTime(fromLocalInput(r.expiresAt))}` },
                  { label: 'Rate limit', value: `${r.rateLimitPerMinute} / minute${multi ? ' per application' : ''}` },
                  { label: 'Budgets', value: budgetText(budgetValue(r.maxRequestsPerDay) ?? null, budgetValue(r.maxWritesPerHour) ?? null) },
                  { label: 'Acting for users', value: actingForText(r.onBehalfOf, splitList(r.allowedUserGroups)) },
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
              {multi ? `Create ${selected.length} grants` : 'Create grant'}
            </Button>
          )}
        </div>
      </Card>
    </div>
  );
}

function SelectCard({ selected, disabled, onClick, children }: { selected: boolean; disabled?: boolean; onClick: () => void; children: React.ReactNode }) {
  return (
    <button type="button" aria-pressed={selected} disabled={disabled} onClick={onClick} className={cn('rounded-lg border p-3.5 text-left transition disabled:cursor-not-allowed disabled:opacity-50', selected ? 'border-brand-500 bg-brand-50/50 ring-1 ring-brand-500' : 'border-slate-200 hover:border-slate-300')}>
      {children}
    </button>
  );
}
