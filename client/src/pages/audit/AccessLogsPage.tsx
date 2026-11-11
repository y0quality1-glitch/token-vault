import { useEffect, useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { Activity, CheckCircle2, CircleDashed, Download, Search, UserRound, XCircle } from 'lucide-react';
import { DECISION_LABELS, actingUserLabel, type AccessRequest, type Agent, type AuditEvent, type Integration } from '@token-vault/shared';
import { operationLabel, useProviders } from '@/lib/providers';
import { useApi } from '@/hooks/useApi';
import { qs } from '@/lib/api';
import { Button } from '@/components/ui/button';
import { Card, DetailList } from '@/components/ui/card';
import { Badge, DecisionBadge, StatusBadge } from '@/components/ui/badge';
import { Input, Select } from '@/components/ui/form';
import { Callout, EmptyState, ErrorState, Spinner } from '@/components/ui/feedback';
import { Drawer } from '@/components/ui/dialog';
import { DataTable } from '@/components/ui/table';
import { PageHeader } from '@/components/ui/navigation';
import { JsonView, Mono } from '@/components/ui/secret';
import { permissionsText } from '@/pages/settings/UserIdentityPage';
import { cn, formatDateTime, formatDuration, fromLocalInput } from '@/lib/utils';

export function AccessLogsPage() {
  const { operations } = useProviders();
  const [params, setParams] = useSearchParams();
  const [filters, setFilters] = useState({
    agentId: '',
    integrationId: '',
    decision: params.get('decision') ?? '',
    operation: '',
    from: '',
    to: '',
    search: '',
    grantId: params.get('grantId') ?? '',
    user: params.get('user') ?? '',
  });
  const query = qs({ ...filters, from: fromLocalInput(filters.from), to: fromLocalInput(filters.to) });
  const { data, error, loading, reload } = useApi<{ items: AccessRequest[]; total: number }>(`/access-requests${query}`);
  const agents = useApi<{ items: Agent[] }>('/agents');
  const integrations = useApi<{ items: Integration[] }>('/integrations');
  const selectedId = params.get('request');

  const set = (k: keyof typeof filters) => (e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement>) => setFilters((f) => ({ ...f, [k]: e.target.value }));
  const open = (id: string | null) => {
    const p = new URLSearchParams(params);
    if (id) p.set('request', id);
    else p.delete('request');
    setParams(p, { replace: true });
  };

  function exportJson() {
    const blob = new Blob([JSON.stringify(data?.items ?? [], null, 2)], { type: 'application/json' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `token-vault-access-logs-${new Date().toISOString().slice(0, 19)}.json`;
    a.click();
    URL.revokeObjectURL(a.href);
  }

  return (
    <div className="space-y-4">
      <PageHeader
        title="Access Logs"
        description="Every agent access decision, allowed or denied. Records are append-only and sanitized."
        breadcrumbs={[{ label: 'Audit & Activity' }, { label: 'Access Logs' }]}
        actions={
          <Button variant="outline" onClick={exportJson} disabled={!data?.items.length}>
            <Download className="h-4 w-4" /> Export JSON
          </Button>
        }
      />
      <Card className="p-4">
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4 xl:grid-cols-7">
          <div className="relative xl:col-span-2">
            <Search className="absolute left-2.5 top-2.5 h-4 w-4 text-slate-400" />
            <Input className="pl-8" placeholder="Request ID, correlation ID, agent…" value={filters.search} onChange={set('search')} />
          </div>
          <Select value={filters.agentId} onChange={set('agentId')} aria-label="Agent">
            <option value="">All agents</option>
            {agents.data?.items.map((a) => (
              <option key={a.id} value={a.id}>
                {a.name}
              </option>
            ))}
          </Select>
          <Select value={filters.integrationId} onChange={set('integrationId')} aria-label="Integration">
            <option value="">All integrations</option>
            {integrations.data?.items.map((i) => (
              <option key={i.id} value={i.id}>
                {i.displayName}
              </option>
            ))}
          </Select>
          <Select value={filters.decision} onChange={set('decision')} aria-label="Decision">
            <option value="">Allow & deny</option>
            <option value="ALLOW">Allow</option>
            <option value="DENY">Deny</option>
          </Select>
          <Select value={filters.operation} onChange={set('operation')} aria-label="Operation">
            <option value="">All operations</option>
            {operations.map((o) => (
              <option key={o.id} value={o.id}>
                {o.label}
              </option>
            ))}
          </Select>
          <Button variant="ghost" onClick={() => setFilters({ agentId: '', integrationId: '', decision: '', operation: '', from: '', to: '', search: '', grantId: '', user: '' })}>
            Reset filters
          </Button>
        </div>
        <div className="mt-3 flex flex-wrap items-center gap-3 text-sm">
          <div className="relative">
            <UserRound className="absolute left-2.5 top-2.5 h-4 w-4 text-slate-400" />
            <Input className="w-56 pl-8" placeholder="On behalf of user…" aria-label="On behalf of user" value={filters.user} onChange={set('user')} />
          </div>
          <label className="flex items-center gap-2 text-slate-600">
            From <Input type="datetime-local" className="w-auto" value={filters.from} onChange={set('from')} />
          </label>
          <label className="flex items-center gap-2 text-slate-600">
            To <Input type="datetime-local" className="w-auto" value={filters.to} onChange={set('to')} />
          </label>
          {filters.grantId && (
            <Badge tone="blue">
              Grant {filters.grantId}
              <button className="ml-1" onClick={() => setFilters((f) => ({ ...f, grantId: '' }))} aria-label="Clear grant filter">
                ×
              </button>
            </Badge>
          )}
          <span className="ml-auto text-xs text-slate-500">{data ? `${data.total} records` : ''}</span>
        </div>
      </Card>

      {error ? (
        <ErrorState error={error} onRetry={reload} />
      ) : (
        <Card>
          <DataTable
            rows={data?.items}
            loading={loading}
            rowKey={(r) => r.id}
            onRowClick={(r) => open(r.id)}
            empty={<EmptyState icon={<Activity className="h-5 w-5" />} title="No access records match these filters" />}
            columns={[
              { key: 't', header: 'Timestamp', cell: (r) => <span className="whitespace-nowrap text-slate-500">{formatDateTime(r.createdAt)}</span> },
              { key: 'id', header: 'Request ID', cell: (r) => <Mono>{r.id}</Mono>, hideBelow: 'xl' },
              {
                key: 'agent',
                header: 'Actor / Agent',
                cell: (r) => (
                  <div className="min-w-0">
                    <span className="font-medium text-slate-800">{r.agentName}</span>
                    {r.delegation && <span className="block text-xs text-slate-500">via sub-agent {r.delegation.label}</span>}
                    {r.onBehalfOf && (
                      <span className="flex items-center gap-1 text-xs text-slate-500" title={`Verified by ${r.onBehalfOf.issuer}`}>
                        <UserRound className="h-3 w-3" /> for {actingUserLabel(r.onBehalfOf)}
                      </span>
                    )}
                  </div>
                ),
              },
              { key: 'int', header: 'Integration', cell: (r) => r.integrationName, hideBelow: 'lg' },
              { key: 'op', header: 'Operation', cell: (r) => operationLabel(r.operation), hideBelow: 'md' },
              { key: 'd', header: 'Decision', cell: (r) => <DecisionBadge decision={r.decision} code={r.decisionCode} /> },
              { key: 'reason', header: 'Reason', cell: (r) => <span className="text-slate-500">{DECISION_LABELS[r.decisionCode] ?? r.decisionCode}</span>, hideBelow: 'lg' },
              { key: 'src', header: 'Source', cell: (r) => <span className="text-xs text-slate-500">{r.source} · {r.sourceIp}</span>, hideBelow: 'xl' },
              { key: 'dur', header: 'Duration', cell: (r) => <span className="text-slate-500">{formatDuration(r.durationMs)}</span>, hideBelow: 'md' },
            ]}
          />
        </Card>
      )}
      <AccessDetailDrawer id={selectedId} onClose={() => open(null)} />
    </div>
  );
}

function AccessDetailDrawer({ id, onClose }: { id: string | null; onClose: () => void }) {
  const { data, error, loading } = useApi<AccessRequest & { auditEvents: AuditEvent[] }>(id ? `/access-requests/${id}` : null);
  const [shown, setShown] = useState<typeof data>(null);
  useEffect(() => {
    if (data && data.id === id) setShown(data);
  }, [data, id]);
  const r = shown?.id === id ? shown : null;

  return (
    <Drawer open={!!id} onClose={onClose} title="Audit detail" subtitle={id ?? ''}>
      {error ? (
        <ErrorState error={error} />
      ) : loading || !r ? (
        <Spinner />
      ) : (
        <div className="space-y-6">
          <div className="flex items-center gap-2">
            <DecisionBadge decision={r.decision} code={r.decisionCode} />
            <StatusBadge status={r.executionStatus} />
          </div>
          <Callout tone={r.decision === 'ALLOW' && r.executionStatus !== 'FAILED' ? 'info' : 'danger'} title={DECISION_LABELS[r.decisionCode] ?? r.decisionCode}>
            {r.decisionReason}
          </Callout>
          <DetailList
            items={[
              { label: 'Event ID', value: r.auditEvents[0]?.id ?? '—', mono: true },
              { label: 'Request ID', value: r.id, mono: true },
              ...(r.delegation ? [{ label: 'Via sub-agent', value: `${r.delegation.label} (delegation ${r.delegation.id}, level ${r.delegation.depth})` }] : []),
              { label: 'On behalf of', value: r.onBehalfOf ? `${actingUserLabel(r.onBehalfOf)} · ${r.onBehalfOf.sub}` : 'The agent itself' },
              ...(r.onBehalfOf ? [{ label: 'Verified by', value: r.onBehalfOf.issuer }, { label: 'User groups', value: r.onBehalfOf.groups.join(', ') || 'none' }, { label: "User's permissions", value: permissionsText(r.onBehalfOf.permissions) }] : []),
              { label: 'Agent ID', value: r.agentId ? <Link className="text-brand-700 hover:underline" to={`/agents/${r.agentId}`}>{r.agentId}</Link> : 'Unauthenticated', mono: true },
              { label: 'Grant ID', value: r.grantId ? <Link className="text-brand-700 hover:underline" to={`/access/grants/${r.grantId}`}>{r.grantId}</Link> : '—', mono: true },
              { label: 'Integration ID', value: r.integrationId ?? '—', mono: true },
              { label: 'Requested operation', value: `${operationLabel(r.operation)} (${r.operation})` },
              { label: 'Resource', value: Object.entries(r.resource).map(([k, v]) => `${k}: ${v}`).join(', ') || '—', mono: true },
              { label: 'Decision', value: r.decision },
              { label: 'Matched rule', value: r.matchedRule ? `${r.matchedRule.type}${r.matchedRule.name ? `: ${r.matchedRule.name}` : ''}` : '—' },
              { label: 'Webhook execution status', value: r.webhookStatus, mono: true },
              { label: 'Upstream response code', value: r.upstreamStatusCode ?? '—' },
              { label: 'Duration', value: formatDuration(r.durationMs) },
              { label: 'Timestamp', value: formatDateTime(r.createdAt) },
              { label: 'Source', value: `${r.source} · ${r.sourceIp}` },
              { label: 'Correlation ID', value: r.correlationId, mono: true },
              { label: 'Idempotency key', value: r.idempotencyKey ?? '—', mono: true },
              { label: 'Chain position', value: r.seq ? `#${r.seq} · ${r.hash?.slice(0, 16)}…` : 'Predates the chain', mono: true },
            ]}
          />
          {r.checks.length > 0 && (
            <div>
              <p className="mb-2 text-xs font-semibold uppercase tracking-wide text-slate-500">Decision trace</p>
              <ol className="space-y-1">
                {r.checks.map((c) => (
                  <li key={c.step} className="flex items-start gap-2 text-sm">
                    {c.passed === true ? <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-emerald-600" /> : c.passed === false ? <XCircle className="mt-0.5 h-4 w-4 shrink-0 text-red-600" /> : <CircleDashed className="mt-0.5 h-4 w-4 shrink-0 text-slate-300" />}
                    <span className={cn(c.passed === null && 'text-slate-400')}>
                      {c.step}. {c.name}
                      {c.passed !== null && <span className="text-slate-500"> · {c.detail}</span>}
                    </span>
                  </li>
                ))}
              </ol>
            </div>
          )}
          {r.auditEvents.length > 0 && (
            <div>
              <p className="mb-2 text-xs font-semibold uppercase tracking-wide text-slate-500">Correlated audit events (sanitized)</p>
              <JsonView value={r.auditEvents.map((e) => ({ id: e.id, eventType: e.eventType, outcome: e.outcome, metadata: e.metadata }))} />
            </div>
          )}
          <p className="text-xs text-slate-500">Not logged by design: API keys, OAuth tokens, authorization headers, passwords and secret request bodies.</p>
        </div>
      )}
    </Drawer>
  );
}
