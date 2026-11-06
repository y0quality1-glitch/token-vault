import { useEffect, useState } from 'react';
import { Pencil, Plus, ScrollText } from 'lucide-react';
import { PERMISSIONS, type Agent, type Integration, type Policy, type PolicyConditions } from '@token-vault/shared';
import { operationLabel, useProviders } from '@/lib/providers';
import { useApi, useMutation } from '@/hooks/useApi';
import { useAuth } from '@/context/AuthContext';
import { api } from '@/lib/api';
import { Button } from '@/components/ui/button';
import { Card, CardBody, CardHeader } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Checkbox, Field, Input, Select, Switch, Textarea } from '@/components/ui/form';
import { Callout, EmptyState, ErrorState, FormError } from '@/components/ui/feedback';
import { Dialog } from '@/components/ui/dialog';
import { DataTable } from '@/components/ui/table';
import { PageHeader } from '@/components/ui/navigation';
import { useToast } from '@/components/ui/toast';
import { AGENT_TYPE_LABELS, splitList } from '@/lib/utils';

const EVALUATION = ['Authenticate caller', 'Verify agent is active', 'Explicit DENY policies (precedence over allow)', 'Grant exists and is active', 'Grant validity period', 'Integration is active', 'Operation in grant scopes', 'Resource restrictions', 'Rate limit', 'Source IP restriction', 'Deny by default if any check fails'];

export function PoliciesPage() {
  const { can } = useAuth();
  const toast = useToast();
  const { data, error, loading, reload, setData } = useApi<{ items: Policy[] }>('/policies');
  const agents = useApi<{ items: Agent[] }>('/agents');
  const integrations = useApi<{ items: Integration[] }>('/integrations');
  const [editing, setEditing] = useState<Policy | 'new' | null>(null);
  const manage = can(PERMISSIONS.POLICY_MANAGE);

  function describeConditions(c: PolicyConditions) {
    const who = c.agentSelector.type === 'any' ? 'Any agent' : c.agentSelector.type === 'agentType' ? AGENT_TYPE_LABELS[c.agentSelector.value as keyof typeof AGENT_TYPE_LABELS] ?? c.agentSelector.value : agents.data?.items.find((a) => a.id === c.agentSelector.value)?.name ?? c.agentSelector.value;
    const what = c.integrationSelector.type === 'any' ? 'any integration' : c.integrationSelector.type === 'provider' ? `provider ${c.integrationSelector.value}` : integrations.data?.items.find((i) => i.id === c.integrationSelector.value)?.displayName ?? c.integrationSelector.value;
    return `${who} · ${what}${c.environment !== 'any' ? ` · ${c.environment}` : ''}${c.timeWindow ? ` · ${String(c.timeWindow.startHour).padStart(2, '0')}:00–${String(c.timeWindow.endHour).padStart(2, '0')}:00 UTC` : ''}${c.sourceCidrs?.length ? ` · from ${c.sourceCidrs.join(', ')}` : ''}`;
  }

  async function toggle(p: Policy, enabled: boolean) {
    try {
      const { id: _i, organizationId: _o, createdAt: _c, updatedAt: _u, ...body } = p;
      const updated = await api.put<Policy>(`/policies/${p.id}`, { ...body, enabled });
      setData({ items: data!.items.map((x) => (x.id === p.id ? updated : x)) });
      toast.success(`Policy ${enabled ? 'enabled' : 'disabled'}`, p.name);
    } catch (e) {
      toast.error('Could not update policy', (e as Error).message);
    }
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="Policies"
        description="Simple organization-wide rules evaluated on every agent request, in addition to grants."
        breadcrumbs={[{ label: 'Access Management' }, { label: 'Policies' }]}
        actions={
          manage && (
            <Button onClick={() => setEditing('new')}>
              <Plus className="h-4 w-4" /> New policy
            </Button>
          )
        }
      />
      <div className="grid gap-6 xl:grid-cols-[1fr_20rem]">
        {error ? (
          <ErrorState error={error} onRetry={reload} />
        ) : (
          <Card>
            <DataTable
              rows={data?.items}
              loading={loading}
              rowKey={(p) => p.id}
              empty={<EmptyState icon={<ScrollText className="h-5 w-5" />} title="No policies" description="Grants alone govern access. Add explicit DENY rules for guardrails." />}
              columns={[
                { key: 'prio', header: 'Priority', cell: (p) => <span className="font-mono text-xs text-slate-600">{p.priority}</span> },
                {
                  key: 'name',
                  header: 'Policy',
                  cell: (p) => (
                    <div className="max-w-md">
                      <p className="font-medium text-slate-900">{p.name}</p>
                      <p className="text-xs text-slate-500">{describeConditions(p.conditions)}</p>
                    </div>
                  ),
                },
                { key: 'effect', header: 'Decision', cell: (p) => <Badge tone={p.effect === 'DENY' ? 'red' : 'green'} dot>{p.effect === 'DENY' ? 'Deny' : 'Allow'}</Badge> },
                {
                  key: 'ops',
                  header: 'Operations',
                  cell: (p) => (
                    <div className="flex max-w-xs flex-wrap gap-1">
                      {p.conditions.operations.map((o) => (
                        <Badge key={o} tone="gray">
                          {o === '*' ? 'Any operation' : operationLabel(o)}
                        </Badge>
                      ))}
                    </div>
                  ),
                  hideBelow: 'lg',
                },
                { key: 'enabled', header: 'Enabled', cell: (p) => <Switch checked={p.enabled} disabled={!manage} onChange={(v) => toggle(p, v)} label={`Toggle ${p.name}`} /> },
                {
                  key: 'edit',
                  header: '',
                  cell: (p) =>
                    manage && (
                      <Button size="icon" variant="ghost" onClick={() => setEditing(p)} aria-label={`Edit ${p.name}`}>
                        <Pencil className="h-4 w-4" />
                      </Button>
                    ),
                },
              ]}
            />
          </Card>
        )}
        <div className="space-y-4">
          <Card>
            <CardHeader title="Deterministic evaluation order" />
            <CardBody>
              <ol className="space-y-1.5 text-sm">
                {EVALUATION.map((s, i) => (
                  <li key={s} className="flex gap-2">
                    <span className="w-5 shrink-0 text-right font-mono text-xs leading-5 text-slate-400">{i + 1}.</span>
                    <span className="text-slate-700">{s}</span>
                  </li>
                ))}
              </ol>
            </CardBody>
          </Card>
          <Callout tone="security">ALLOW policies never replace a grant: they are recorded as matched rules for traceability. The matched rule and decision reason are recorded without any secret values.</Callout>
        </div>
      </div>
      <PolicyDialog
        policy={editing}
        agents={agents.data?.items ?? []}
        integrations={integrations.data?.items ?? []}
        onClose={() => setEditing(null)}
        onSaved={() => {
          setEditing(null);
          void reload();
        }}
      />
    </div>
  );
}

function PolicyDialog({ policy, agents, integrations, onClose, onSaved }: { policy: Policy | 'new' | null; agents: Agent[]; integrations: Integration[]; onClose: () => void; onSaved: () => void }) {
  const { operations, providers } = useProviders();
  const toast = useToast();
  const isNew = policy === 'new';
  const [f, setF] = useState({
    name: '',
    description: '',
    effect: 'DENY' as 'ALLOW' | 'DENY',
    priority: '50',
    enabled: true,
    agentType: 'any' as 'any' | 'agent' | 'agentType',
    agentValue: '',
    integrationType: 'any' as 'any' | 'integration' | 'provider',
    integrationValue: '',
    operations: [] as string[],
    environment: 'any',
    useWindow: false,
    startHour: '0',
    endHour: '6',
    sourceCidrs: '',
  });
  useEffect(() => {
    if (!policy) return;
    if (policy === 'new') {
      setF((x) => ({ ...x, name: '', description: '', effect: 'DENY', priority: '50', enabled: true, agentType: 'any', agentValue: '', integrationType: 'any', integrationValue: '', operations: [], environment: 'any', useWindow: false, sourceCidrs: '' }));
    } else {
      const c = policy.conditions;
      setF({
        name: policy.name,
        description: policy.description,
        effect: policy.effect,
        priority: String(policy.priority),
        enabled: policy.enabled,
        agentType: c.agentSelector.type,
        agentValue: c.agentSelector.value ?? '',
        integrationType: c.integrationSelector.type,
        integrationValue: c.integrationSelector.value ?? '',
        operations: c.operations,
        environment: c.environment,
        useWindow: !!c.timeWindow,
        startHour: String(c.timeWindow?.startHour ?? 0),
        endHour: String(c.timeWindow?.endHour ?? 6),
        sourceCidrs: (c.sourceCidrs ?? []).join(', '),
      });
    }
  }, [policy]);
  const save = useMutation((body: unknown) => (isNew ? api.post<Policy>('/policies', body) : api.put<Policy>(`/policies/${(policy as Policy).id}`, body)));
  const fe = save.fieldErrors;
  const anyOp = f.operations.includes('*');

  return (
    <Dialog
      open={!!policy}
      onClose={onClose}
      size="lg"
      title={isNew ? 'New policy' : 'Edit policy'}
      footer={
        <>
          <Button variant="outline" onClick={onClose}>
            Cancel
          </Button>
          <Button
            loading={save.pending}
            onClick={async () => {
              const r = await save.run({
                name: f.name,
                description: f.description,
                effect: f.effect,
                priority: Number(f.priority),
                enabled: f.enabled,
                conditions: {
                  agentSelector: { type: f.agentType, value: f.agentType === 'any' ? undefined : f.agentValue },
                  integrationSelector: { type: f.integrationType, value: f.integrationType === 'any' ? undefined : f.integrationValue },
                  operations: f.operations,
                  environment: f.environment,
                  timeWindow: f.useWindow ? { startHour: Number(f.startHour), endHour: Number(f.endHour) } : null,
                  sourceCidrs: splitList(f.sourceCidrs),
                },
              });
              if (r) {
                toast.success(isNew ? 'Policy created' : 'Policy saved', r.name);
                onSaved();
              }
            }}
          >
            {isNew ? 'Create policy' : 'Save policy'}
          </Button>
        </>
      }
    >
      <div className="space-y-4">
        <FormError error={save.error} />
        <div className="grid gap-4 sm:grid-cols-[1fr_8rem_8rem]">
          <Field label="Policy name" required error={fe.name}>
            <Input value={f.name} onChange={(e) => setF({ ...f, name: e.target.value })} invalid={!!fe.name} />
          </Field>
          <Field label="Decision" required>
            <Select value={f.effect} onChange={(e) => setF({ ...f, effect: e.target.value as 'ALLOW' | 'DENY' })}>
              <option value="DENY">Deny</option>
              <option value="ALLOW">Allow</option>
            </Select>
          </Field>
          <Field label="Priority" required error={fe.priority} hint="Lower runs first">
            <Input type="number" value={f.priority} onChange={(e) => setF({ ...f, priority: e.target.value })} />
          </Field>
        </div>
        <Field label="Description">
          <Textarea rows={2} value={f.description} onChange={(e) => setF({ ...f, description: e.target.value })} />
        </Field>
        <div className="grid gap-4 sm:grid-cols-2">
          <Field label="Agent selector">
            <div className="flex gap-2">
              <Select className="w-36" value={f.agentType} onChange={(e) => setF({ ...f, agentType: e.target.value as typeof f.agentType, agentValue: '' })}>
                <option value="any">Any agent</option>
                <option value="agentType">Agent type</option>
                <option value="agent">Specific agent</option>
              </Select>
              {f.agentType === 'agentType' && (
                <Select value={f.agentValue} onChange={(e) => setF({ ...f, agentValue: e.target.value })}>
                  <option value="">Select…</option>
                  {Object.entries(AGENT_TYPE_LABELS).map(([k, v]) => (
                    <option key={k} value={k}>
                      {v}
                    </option>
                  ))}
                </Select>
              )}
              {f.agentType === 'agent' && (
                <Select value={f.agentValue} onChange={(e) => setF({ ...f, agentValue: e.target.value })}>
                  <option value="">Select…</option>
                  {agents.map((a) => (
                    <option key={a.id} value={a.id}>
                      {a.name}
                    </option>
                  ))}
                </Select>
              )}
            </div>
          </Field>
          <Field label="Integration selector">
            <div className="flex gap-2">
              <Select className="w-36" value={f.integrationType} onChange={(e) => setF({ ...f, integrationType: e.target.value as typeof f.integrationType, integrationValue: e.target.value === 'provider' ? (providers[0]?.key ?? '') : '' })}>
                <option value="any">Any</option>
                <option value="provider">Provider</option>
                <option value="integration">Specific</option>
              </Select>
              {f.integrationType === 'provider' && (
                <Select value={f.integrationValue} onChange={(e) => setF({ ...f, integrationValue: e.target.value })}>
                  {providers.map((p) => (
                    <option key={p.key} value={p.key}>
                      {p.name}
                    </option>
                  ))}
                </Select>
              )}
              {f.integrationType === 'integration' && (
                <Select value={f.integrationValue} onChange={(e) => setF({ ...f, integrationValue: e.target.value })}>
                  <option value="">Select…</option>
                  {integrations.map((i) => (
                    <option key={i.id} value={i.id}>
                      {i.displayName}
                    </option>
                  ))}
                </Select>
              )}
            </div>
          </Field>
        </div>
        <div>
          <p className="mb-2 text-sm font-medium text-slate-700">Operations</p>
          {fe['conditions.operations'] && <p className="mb-2 text-xs text-red-600">{fe['conditions.operations']}</p>}
          <div className="grid gap-2 sm:grid-cols-2">
            <Checkbox checked={anyOp} onChange={(v) => setF({ ...f, operations: v ? ['*'] : [] })} label="Any operation" />
            {operations.map((o) => (
              <Checkbox key={o.id} disabled={anyOp} checked={f.operations.includes(o.id)} onChange={(v) => setF({ ...f, operations: v ? [...f.operations, o.id] : f.operations.filter((x) => x !== o.id) })} label={o.label} description={o.destructive ? 'Destructive' : undefined} />
            ))}
          </div>
        </div>
        <div className="grid gap-4 sm:grid-cols-2">
          <Field label="Environment">
            <Select value={f.environment} onChange={(e) => setF({ ...f, environment: e.target.value })}>
              <option value="any">Any</option>
              <option value="development">Development</option>
              <option value="staging">Staging</option>
              <option value="production">Production</option>
            </Select>
          </Field>
          <Field label="Source IP restriction (optional)" error={fe['conditions.sourceCidrs.0']} hint="Policy applies only to requests from these CIDRs">
            <Input className="font-mono text-xs" value={f.sourceCidrs} onChange={(e) => setF({ ...f, sourceCidrs: e.target.value })} placeholder="203.0.113.0/24" />
          </Field>
        </div>
        <div className="rounded-lg border border-slate-200 p-3.5">
          <Checkbox checked={f.useWindow} onChange={(v) => setF({ ...f, useWindow: v })} label="Time window (optional)" description="Policy applies only between these UTC hours" />
          {f.useWindow && (
            <div className="mt-3 flex items-center gap-2 text-sm">
              <Input type="number" min={0} max={23} className="w-20" value={f.startHour} onChange={(e) => setF({ ...f, startHour: e.target.value })} />
              <span className="text-slate-500">to</span>
              <Input type="number" min={0} max={24} className="w-20" value={f.endHour} onChange={(e) => setF({ ...f, endHour: e.target.value })} />
              <span className="text-slate-500">UTC</span>
            </div>
          )}
        </div>
        <div className="flex items-center justify-between rounded-lg border border-slate-200 p-3.5">
          <span className="text-sm font-medium text-slate-800">Enabled</span>
          <Switch checked={f.enabled} onChange={(v) => setF({ ...f, enabled: v })} label="Enabled" />
        </div>
      </div>
    </Dialog>
  );
}
