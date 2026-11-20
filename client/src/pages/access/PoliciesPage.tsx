import { useEffect, useState, type ReactNode } from 'react';
import { Pencil, Plus, ScrollText, Trash2 } from 'lucide-react';
import { ARGUMENT_OPERATORS, PERMISSIONS, USER_ARGUMENT_FIELDS, describeArgument, scopeSelectors, type Agent, type ArgumentCondition, type ArgumentOperator, type Integration, type Policy, type PolicyConditions, type PolicyEffect } from '@token-vault/shared';
import { getOperation, getProvider, useProviders } from '@/lib/providers';
import { OperationPicker, selectorLabel } from '@/components/policy/OperationPicker';
import { SearchSelect } from '@/components/policy/SearchSelect';
import { EMPTY_DRAFT, ResponseFilterEditor, describeFilter, fromDraft, toDraft, type FilterDraft } from '@/components/policy/ResponseFilterEditor';
import { useMutation, usePost } from '@/hooks/useApi';
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

const EVALUATION = ['Authenticate caller', 'Verify agent is active (and no emergency stop)', 'Explicit DENY policies (precedence over allow)', 'Grant exists and is active', 'Grant validity period', 'Integration is active', 'Operation in grant scopes', 'Resource restrictions', 'Acting user (the grant allows it, within the user token permissions)', 'Delegation limits (sub-agents: only what was delegated)', 'Rate limit and budgets', 'Source IP restriction', 'Human approval (Require approval policies)', 'Deny by default if any check fails'];

const EFFECTS: Record<PolicyEffect, { label: string; tone: 'red' | 'green' | 'amber' | 'violet' }> = {
  DENY: { label: 'Deny', tone: 'red' },
  ALLOW: { label: 'Allow', tone: 'green' },
  REQUIRE_APPROVAL: { label: 'Require approval', tone: 'amber' },
  FILTER: { label: 'Filter responses', tone: 'violet' },
};

export function PoliciesPage() {
  const { can } = useAuth();
  const toast = useToast();
  const { data, error, loading, reload, setData } = usePost<{ items: Policy[] }>('/policy/getall');
  const agents = usePost<{ items: Agent[] }>('/agent/getall');
  const integrations = usePost<{ items: Integration[] }>('/integration/getall');
  const [editing, setEditing] = useState<Policy | 'new' | null>(null);
  const manage = can(PERMISSIONS.POLICY_MANAGE);

  function describeConditions(c: PolicyConditions) {
    const who = c.agentSelector.type === 'any' ? 'Any agent' : c.agentSelector.type === 'agentType' ? AGENT_TYPE_LABELS[c.agentSelector.value as keyof typeof AGENT_TYPE_LABELS] ?? c.agentSelector.value : agents.data?.items.find((a) => a.id === c.agentSelector.value)?.name ?? c.agentSelector.value;
    const what = c.integrationSelector.type === 'any' ? 'any integration' : c.integrationSelector.type === 'provider' ? `provider ${c.integrationSelector.value}` : integrations.data?.items.find((i) => i.id === c.integrationSelector.value)?.displayName ?? c.integrationSelector.value;
    return `${who} · ${what}${c.environment !== 'any' ? ` · ${c.environment}` : ''}${c.timeWindow ? ` · ${String(c.timeWindow.startHour).padStart(2, '0')}:00–${String(c.timeWindow.endHour).padStart(2, '0')}:00 UTC` : ''}${c.sourceCidrs?.length ? ` · from ${c.sourceCidrs.join(', ')}` : ''}${c.arguments?.length ? ` · when ${c.arguments.map(describeArgument).join(' and ')}` : ''}`;
  }

  async function toggle(p: Policy, enabled: boolean) {
    try {
      const { id: _i, organizationId: _o, createdAt: _c, updatedAt: _u, ...body } = p;
      const updated = await api.post<Policy>('/policy/save', { ...body, id: p.id, enabled });
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
                      {p.effect === 'FILTER' && p.responseFilter && <p className="text-xs text-violet-700">{describeFilter(p.responseFilter)}</p>}
                    </div>
                  ),
                },
                { key: 'effect', header: 'Decision', cell: (p) => <Badge tone={EFFECTS[p.effect].tone} dot>{EFFECTS[p.effect].label}</Badge> },
                {
                  key: 'ops',
                  header: 'Operations',
                  cell: (p) => (
                    <div className="flex max-w-xs flex-wrap gap-1">
                      {p.conditions.operations.map((o) => (
                        <Badge key={o} tone={o.includes('destructive') ? 'red' : 'gray'}>
                          {selectorLabel(o)}
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
          <Callout tone="info" title="Filter responses">
            Never changes the decision: for allowed requests, it masks or removes sensitive values and checks for prompt injection in the result, in your webhook, before the agent sees it.
          </Callout>
          <Callout tone="info" title="Require approval">
            For requests every other check allows: the request waits until a Security Administrator approves that exact request under <strong>Approvals</strong>. The agent can then run it once, within 15 minutes.
          </Callout>
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
    effect: 'DENY' as PolicyEffect,
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
    args: [] as ArgRow[],
    filter: EMPTY_DRAFT as FilterDraft,
  });
  useEffect(() => {
    if (!policy) return;
    if (policy === 'new') {
      setF((x) => ({ ...x, name: '', description: '', effect: 'DENY', priority: '50', enabled: true, agentType: 'any', agentValue: '', integrationType: 'any', integrationValue: '', operations: [], environment: 'any', useWindow: false, sourceCidrs: '', args: [], filter: EMPTY_DRAFT }));
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
        args: (c.arguments ?? []).map(toRow),
        filter: toDraft(policy.responseFilter),
      });
    }
  }, [policy]);
  const save = useMutation((body: unknown) => (isNew ? api.post<Policy>('/policy/save', body) : api.post<Policy>('/policy/save', { ...(body as object), id: (policy as Policy).id })));
  const fe = save.fieldErrors;

  // "Where" decides "what": the application the policy is limited to, if any.
  const appOf = (type: typeof f.integrationType, value: string): string | null => (type === 'provider' ? value || null : type === 'integration' ? (integrations.find((i) => i.id === value)?.provider ?? null) : null);
  const application = appOf(f.integrationType, f.integrationValue);
  const connected = new Set<string>(integrations.map((i) => i.provider));
  const appOptions = providers
    .filter((p) => operations.some((o) => o.provider === p.key))
    .map((p) => ({ value: p.key, label: p.name, tag: connected.has(p.key) ? <Badge tone="green">Connected</Badge> : undefined }))
    .sort((a, b) => Number(!!b.tag) - Number(!!a.tag) || a.label.localeCompare(b.label));
  function setWhere(type: typeof f.integrationType, value: string) {
    // Operations of other applications could never match: drop them; tie broad ones to the application.
    const next = appOf(type, value);
    setF((x) => ({ ...x, integrationType: type, integrationValue: value, operations: scopeSelectors(x.operations, next, (id) => getOperation(id)?.provider) }));
  }

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
                  arguments: f.args.map(fromRow),
                },
                responseFilter: f.effect === 'FILTER' ? fromDraft(f.filter) : null,
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
        <div className="grid gap-4 sm:grid-cols-[1fr_11rem_8rem]">
          <Field label="Policy name" required error={fe.name}>
            <Input value={f.name} onChange={(e) => setF({ ...f, name: e.target.value })} invalid={!!fe.name} />
          </Field>
          <Field label="Decision" required>
            <Select value={f.effect} onChange={(e) => setF({ ...f, effect: e.target.value as PolicyEffect })}>
              <option value="DENY">Deny</option>
              <option value="REQUIRE_APPROVAL">Require approval</option>
              <option value="ALLOW">Allow</option>
              <option value="FILTER">Filter responses</option>
            </Select>
          </Field>
          <Field label="Priority" required error={fe.priority} hint="Lower runs first">
            <Input type="number" value={f.priority} onChange={(e) => setF({ ...f, priority: e.target.value })} />
          </Field>
        </div>
        {f.effect === 'REQUIRE_APPROVAL' && (
          <Callout tone="info">Matching requests that every other check allows wait for a human. Approvers see the exact operation, resource and input under Access Management → Approvals.</Callout>
        )}
        {f.effect === 'FILTER' && <ResponseFilterEditor value={f.filter} onChange={(filter) => setF({ ...f, filter })} error={fe.responseFilter} />}
        <Field label="Description">
          <Textarea rows={2} value={f.description} onChange={(e) => setF({ ...f, description: e.target.value })} />
        </Field>
        <PolicySummary f={f} agents={agents} integrations={integrations} />
        <Section title="Who" hint="Which agents the policy applies to" error={fe['conditions.agentSelector']}>
          <Segmented
            label="Agents"
            value={f.agentType}
            options={[
              { value: 'any', label: 'Any agent' },
              { value: 'agentType', label: 'Agent type' },
              { value: 'agent', label: 'Specific agent' },
            ]}
            onChange={(v) => setF({ ...f, agentType: v as typeof f.agentType, agentValue: v === 'agentType' ? 'AI_AGENT' : '' })}
          />
          {f.agentType === 'agentType' && (
            <Select aria-label="Agent type" className="mt-2 sm:w-64" value={f.agentValue} onChange={(e) => setF({ ...f, agentValue: e.target.value })}>
              {Object.entries(AGENT_TYPE_LABELS).map(([k, v]) => (
                <option key={k} value={k}>
                  {v}
                </option>
              ))}
            </Select>
          )}
          {f.agentType === 'agent' && (
            <div className="mt-2">
              <SearchSelect
                label="Search agents"
                placeholder={`Search ${agents.length} agents by name or team…`}
                value={f.agentValue}
                onChange={(v) => setF({ ...f, agentValue: v })}
                options={agents.map((a) => ({ value: a.id, label: a.name, hint: `${AGENT_TYPE_LABELS[a.agentType] ?? a.agentType} · ${a.ownerTeam}${a.status === 'DISABLED' ? ' · disabled' : ''}` }))}
              />
            </div>
          )}
        </Section>

        <Section title="Where" hint="Which applications or integrations. Choosing one limits the operations below to it." error={fe['conditions.integrationSelector']}>
          <Segmented
            label="Applications"
            value={f.integrationType}
            options={[
              { value: 'any', label: 'Any application' },
              { value: 'provider', label: 'One application' },
              { value: 'integration', label: 'One integration' },
            ]}
            onChange={(v) => setWhere(v as typeof f.integrationType, '')}
          />
          {f.integrationType === 'provider' && (
            <div className="mt-2">
              <SearchSelect label="Search applications" placeholder={`Search ${appOptions.length} applications…`} value={f.integrationValue} onChange={(v) => setWhere('provider', v)} options={appOptions} />
            </div>
          )}
          {f.integrationType === 'integration' && (
            <div className="mt-2">
              <SearchSelect
                label="Search integrations"
                placeholder={`Search ${integrations.length} integrations…`}
                value={f.integrationValue}
                onChange={(v) => setWhere('integration', v)}
                options={integrations.map((i) => ({ value: i.id, label: i.displayName, hint: `${getProvider(i.provider)?.name ?? i.provider} · ${i.environment}` }))}
              />
            </div>
          )}
        </Section>

        <Section title="What" hint={application ? `Operations of ${getProvider(application)?.name ?? application}` : 'Operations in any application'} error={fe['conditions.operations']}>
          <OperationPicker key={policy === 'new' ? 'new' : (policy?.id ?? 'none')} value={f.operations} onChange={(operations) => setF({ ...f, operations })} application={application} providers={providers} operations={operations} connected={connected} />
        </Section>

        <ArgumentRules rows={f.args} onChange={(args) => setF({ ...f, args })} error={fe['conditions.arguments']} />
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

// ---------------------------------------------------------------- argument rules
type ArgRow = { field: string; op: ArgumentOperator; value: string };
const kindOf = (op: ArgumentOperator) => ARGUMENT_OPERATORS.find((o) => o.op === op)?.value ?? 'text';
const toRow = (c: ArgumentCondition): ArgRow => ({ field: c.field, op: c.op, value: Array.isArray(c.value) ? c.value.join(', ') : String(c.value) });
function fromRow(r: ArgRow): ArgumentCondition {
  const kind = kindOf(r.op);
  // Numbers and lists are converted here; the server validates them.
  return { field: r.field.trim(), op: r.op, value: kind === 'number' ? Number(r.value) : kind === 'list' ? splitList(r.value) : r.value };
}

function ArgumentRules({ rows, onChange, error }: { rows: ArgRow[]; onChange: (rows: ArgRow[]) => void; error?: string }) {
  const set = (i: number, patch: Partial<ArgRow>) => onChange(rows.map((r, j) => (j === i ? { ...r, ...patch } : r)));
  return (
    <div className="rounded-lg border border-slate-200 p-3.5">
      <p className="text-sm font-medium text-slate-800">Argument rules (optional)</p>
      <p className="text-xs text-slate-500">
        The policy applies only when every rule holds for what the request contains. Fields are <span className="font-mono">input.&lt;name&gt;</span> or <span className="font-mono">resource.&lt;name&gt;</span>; text comparisons ignore case.
      </p>
      <p className="mt-1 text-xs text-slate-500">
        To act on the user an agent works for, use <span className="font-mono">user.sub</span>, <span className="font-mono">user.email</span>, <span className="font-mono">user.groups</span> (any of the user's groups) or <span className="font-mono">user.issuer</span>. They are empty when the agent acts for itself, so <span className="font-mono">user.sub equals ""</span> means "no user".
      </p>
      <datalist id="argument-fields">
        <option value="input." />
        <option value="resource." />
        {USER_ARGUMENT_FIELDS.map((f) => (
          <option key={f} value={f} />
        ))}
      </datalist>
      {error && <p className="mt-2 text-xs text-red-600">{error}</p>}
      <div className="mt-3 space-y-2">
        {rows.map((r, i) => (
          <div key={i} className="grid gap-2 sm:grid-cols-[1fr_13rem_1fr_auto]">
            <Input aria-label={`Rule ${i + 1} field`} list="argument-fields" className="font-mono text-xs" value={r.field} onChange={(e) => set(i, { field: e.target.value })} placeholder="input.title" />
            <Select aria-label={`Rule ${i + 1} operator`} value={r.op} onChange={(e) => set(i, { op: e.target.value as ArgumentOperator })}>
              {ARGUMENT_OPERATORS.map((o) => (
                <option key={o.op} value={o.op}>
                  {o.label}
                </option>
              ))}
            </Select>
            <Input
              aria-label={`Rule ${i + 1} value`}
              className="font-mono text-xs"
              type={kindOf(r.op) === 'number' ? 'number' : 'text'}
              value={r.value}
              onChange={(e) => set(i, { value: e.target.value })}
              placeholder={kindOf(r.op) === 'list' ? 'bug, docs' : kindOf(r.op) === 'number' ? '500' : r.op.includes('matches') ? 'pass(word)?|secret' : 'value'}
            />
            <Button size="icon" variant="ghost" onClick={() => onChange(rows.filter((_, j) => j !== i))} aria-label={`Remove rule ${i + 1}`}>
              <Trash2 className="h-4 w-4" />
            </Button>
          </div>
        ))}
      </div>
      {rows.length < 10 && (
        <Button className="mt-2" size="sm" variant="outline" onClick={() => onChange([...rows, { field: 'input.', op: 'contains', value: '' }])}>
          <Plus className="h-4 w-4" /> Add rule
        </Button>
      )}
    </div>
  );
}

// ---------------------------------------------------------------- layout helpers
function Section({ title, hint, error, children }: { title: string; hint?: string; error?: string; children: ReactNode }) {
  return (
    <section className="space-y-2">
      <div className="flex flex-wrap items-baseline gap-x-2">
        <h3 className="text-sm font-semibold text-slate-900">{title}</h3>
        {hint && <p className="text-xs text-slate-500">{hint}</p>}
      </div>
      {error && <p className="text-xs text-red-600">{error}</p>}
      {children}
    </section>
  );
}

function Segmented({ label, value, options, onChange }: { label: string; value: string; options: { value: string; label: string }[]; onChange: (v: string) => void }) {
  return (
    <div role="radiogroup" aria-label={label} className="inline-flex flex-wrap rounded-lg bg-slate-100 p-1">
      {options.map((o) => (
        <button
          key={o.value}
          type="button"
          role="radio"
          aria-checked={value === o.value}
          onClick={() => onChange(o.value)}
          className={value === o.value ? 'rounded-md bg-white px-3 py-1.5 text-sm font-medium text-slate-900 shadow-sm' : 'rounded-md px-3 py-1.5 text-sm text-slate-600 hover:text-slate-900'}
        >
          {o.label}
        </button>
      ))}
    </div>
  );
}

interface SummaryInput {
  effect: PolicyEffect;
  agentType: string;
  agentValue: string;
  integrationType: string;
  integrationValue: string;
  operations: string[];
  environment: string;
  useWindow: boolean;
  startHour: string;
  endHour: string;
  sourceCidrs: string;
  args: unknown[];
}

/** The policy in one sentence, updated as it is edited. */
function PolicySummary({ f, agents, integrations }: { f: SummaryInput; agents: Agent[]; integrations: Integration[] }) {
  const decision = { DENY: 'Deny', REQUIRE_APPROVAL: 'Require approval for', ALLOW: 'Record as allowed', FILTER: 'Filter the results of' }[f.effect];
  const who =
    f.agentType === 'any'
      ? 'any agent'
      : f.agentType === 'agentType'
        ? `every ${AGENT_TYPE_LABELS[f.agentValue as keyof typeof AGENT_TYPE_LABELS] ?? 'agent of a type'}`
        : (agents.find((a) => a.id === f.agentValue)?.name ?? 'a specific agent (choose one)');
  const what = f.operations.length === 0 ? 'no operations yet' : f.operations.slice(0, 3).map(selectorLabel).join(', ') + (f.operations.length > 3 ? ` and ${f.operations.length - 3} more` : '');
  const where =
    f.integrationType === 'any'
      ? 'in any application'
      : f.integrationType === 'provider'
        ? f.integrationValue
          ? `on ${getProvider(f.integrationValue)?.name ?? f.integrationValue} integrations`
          : 'in one application (choose it)'
        : `on ${integrations.find((i) => i.id === f.integrationValue)?.displayName ?? 'one integration (choose it)'}`;
  const cidrs = splitList(f.sourceCidrs);
  const extras = [
    f.environment !== 'any' ? `in ${f.environment}` : null,
    f.useWindow ? `between ${f.startHour.padStart(2, '0')}:00 and ${f.endHour.padStart(2, '0')}:00 UTC` : null,
    cidrs.length ? `from ${cidrs.join(', ')}` : null,
    f.args.length ? `when ${f.args.length} argument rule${f.args.length > 1 ? 's hold' : ' holds'}` : null,
  ].filter(Boolean);
  return (
    <p className="rounded-lg border border-slate-200 bg-slate-50 px-3.5 py-2.5 text-sm text-slate-700" aria-label="Policy summary">
      <span className="font-semibold text-slate-900">{decision}</span> {who}: <span className="font-medium text-slate-900">{what}</span> {where}
      {extras.length ? `, ${extras.join(', ')}` : ''}.
    </p>
  );
}
