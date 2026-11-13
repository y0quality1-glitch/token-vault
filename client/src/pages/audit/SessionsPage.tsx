import { useEffect, useState } from 'react';
import { Link, useNavigate, useParams, useSearchParams } from 'react-router-dom';
import { GitBranch, ListTree, Search, UserRound } from 'lucide-react';
import { DECISION_LABELS, actingUserLabel, sessionDisplayName, type Agent, type SessionDetail, type SessionSummary } from '@token-vault/shared';
import { operationLabel } from '@/lib/providers';
import { usePost } from '@/hooks/useApi';
import { compact } from '@/lib/api';
import { Card, CardBody, CardHeader, DetailList } from '@/components/ui/card';
import { Badge, DecisionBadge, StatusBadge } from '@/components/ui/badge';
import { Input, Select } from '@/components/ui/form';
import { Callout, EmptyState, ErrorState, PageSkeleton } from '@/components/ui/feedback';
import { DataTable } from '@/components/ui/table';
import { PageHeader } from '@/components/ui/navigation';
import { Mono } from '@/components/ui/secret';
import { formatDateTime, formatDuration, formatTime, relativeTime } from '@/lib/utils';

const sessionLink = (s: { sessionId: string; agentId: string | null }) => `/audit/sessions/${encodeURIComponent(s.sessionId)}${s.agentId ? `?agentId=${encodeURIComponent(s.agentId)}` : ''}`;

/** Audit → Sessions: what each agent did in each conversation, task or job. */
export function SessionsPage() {
  const navigate = useNavigate();
  const [search, setSearch] = useState('');
  const [agentId, setAgentId] = useState('');
  const [debounced, setDebounced] = useState('');
  useEffect(() => {
    const t = setTimeout(() => setDebounced(search.trim()), 250);
    return () => clearTimeout(t);
  }, [search]);
  const { data, error, loading, reload } = usePost<{ items: SessionSummary[] }>('/session/getall', compact({ search: debounced, agentId }));
  const agents = usePost<{ items: Agent[] }>('/agent/getall');

  return (
    <div className="space-y-4">
      <PageHeader title="Sessions" description="Agent requests grouped by the conversation, task or job they belong to, so you can see why something happened, not only that it did." breadcrumbs={[{ label: 'Audit & Activity' }, { label: 'Sessions' }]} />
      <Card className="p-4">
        <div className="grid gap-3 sm:grid-cols-[1fr_16rem]">
          <div className="relative">
            <Search className="absolute left-2.5 top-2.5 h-4 w-4 text-slate-400" />
            <Input className="pl-8" aria-label="Search sessions" placeholder="Session id, label, trace id or agent…" value={search} onChange={(e) => setSearch(e.target.value)} />
          </div>
          <Select aria-label="Agent" value={agentId} onChange={(e) => setAgentId(e.target.value)}>
            <option value="">All agents</option>
            {agents.data?.items.map((a) => (
              <option key={a.id} value={a.id}>
                {a.name}
              </option>
            ))}
          </Select>
        </div>
      </Card>
      {error ? (
        <ErrorState error={error} onRetry={reload} />
      ) : (
        <Card>
          <DataTable
            rows={data?.items}
            loading={loading}
            rowKey={(s) => `${s.agentId}:${s.sessionId}`}
            onRowClick={(s) => navigate(sessionLink(s))}
            empty={
              <EmptyState
                icon={<ListTree className="h-5 w-5" />}
                title="No sessions yet"
                description="Requests appear here when an agent sends a session_id or a W3C traceparent. The MCP server and the SDK's session() do this for you."
              />
            }
            columns={[
              {
                key: 'session',
                header: 'Session',
                cell: (s) => (
                  <div className="min-w-0">
                    <div className="truncate font-medium text-slate-900">{s.sessionLabel ?? <span className="font-mono text-xs">{s.sessionId}</span>}</div>
                    {s.sessionLabel && <div className="truncate font-mono text-[11px] text-slate-500">{s.sessionId}</div>}
                  </div>
                ),
              },
              { key: 'agent', header: 'Agent', cell: (s) => <span className="text-slate-700">{s.agentName}</span> },
              {
                key: 'requests',
                header: 'Requests',
                cell: (s) => (
                  <div className="flex flex-wrap items-center gap-1">
                    <span className="mr-1 font-medium text-slate-800">{s.requests}</span>
                    {s.denied > 0 && <Badge tone="red">{s.denied} denied</Badge>}
                    {s.held > 0 && <Badge tone="amber">{s.held} held</Badge>}
                  </div>
                ),
              },
              { key: 'apps', header: 'Integrations', cell: (s) => <span className="text-xs text-slate-600">{s.integrations.join(', ')}</span>, hideBelow: 'lg' },
              {
                key: 'who',
                header: 'Users and sub-agents',
                cell: (s) => (
                  <div className="space-y-0.5 text-xs text-slate-600">
                    {s.users.length > 0 && (
                      <div className="flex items-center gap-1">
                        <UserRound className="h-3 w-3" /> {s.users.join(', ')}
                      </div>
                    )}
                    {s.subAgents.length > 0 && (
                      <div className="flex items-center gap-1">
                        <GitBranch className="h-3 w-3" /> {s.subAgents.join(', ')}
                      </div>
                    )}
                  </div>
                ),
                hideBelow: 'xl',
              },
              { key: 'last', header: 'Last activity', cell: (s) => <span className="whitespace-nowrap text-slate-500">{relativeTime(s.lastAt)}</span> },
            ]}
          />
        </Card>
      )}
    </div>
  );
}

/** One session: what the agent did, in order. */
export function SessionDetailPage() {
  const { sessionId = '' } = useParams();
  const [params] = useSearchParams();
  const agentId = params.get('agentId');
  const { data: s, error, loading, reload } = usePost<SessionDetail>('/session/getdatabyid', { id: sessionId, ...compact({ agentId }) });
  if (error) return <ErrorState error={error} onRetry={reload} />;
  if (loading || !s) return <PageSkeleton />;

  return (
    <div className="space-y-4">
      <PageHeader title={s.sessionLabel ?? 'Session'} description={`${s.agentName} · ${s.requests} request${s.requests === 1 ? '' : 's'} · ${formatDateTime(s.firstAt)} to ${formatTime(s.lastAt)}`} breadcrumbs={[{ label: 'Audit & Activity' }, { label: 'Sessions', to: '/audit/sessions' }, { label: sessionDisplayName(s) }]} />
      {s.sessionLabel && <Callout tone="info">The session label was written by the agent: treat it as a description, not proof of intent.</Callout>}
      <div className="grid gap-4 xl:grid-cols-3">
        <Card className="xl:col-span-2">
          <CardHeader title="Timeline" description="Every request of the session, oldest first" />
          <ol className="divide-y divide-slate-100">
            {s.timeline.map((r, i) => (
              <li key={r.id} className="flex flex-wrap items-start gap-3 px-5 py-3 text-sm">
                <span className="w-6 shrink-0 pt-0.5 text-right font-mono text-xs text-slate-400">{i + 1}</span>
                <span className="w-20 shrink-0 pt-0.5 font-mono text-xs text-slate-500">{formatTime(r.createdAt)}</span>
                <div className="min-w-0 flex-1">
                  <div className="flex flex-wrap items-center gap-2">
                    <Link className="font-medium text-slate-900 hover:underline" to={`/audit/access-logs?request=${r.id}`}>
                      {operationLabel(r.operation)}
                    </Link>
                    <span className="font-mono text-xs text-slate-500">{Object.values(r.resource).join(' · ')}</span>
                    <DecisionBadge decision={r.decision} code={r.decisionCode} />
                    {r.filtering && <Badge tone={r.filtering.injection.detected ? 'amber' : 'violet'}>{r.filtering.withheld ? 'Withheld' : r.filtering.injection.detected ? 'Flagged' : 'Filtered'}</Badge>}
                  </div>
                  <div className="mt-0.5 text-xs text-slate-500">
                    {r.integrationName}
                    {r.delegation ? ` · via sub-agent ${r.delegation.label}` : ''}
                    {r.onBehalfOf ? ` · for ${actingUserLabel(r.onBehalfOf)}` : ''}
                    {r.decision === 'DENY' ? ` · ${DECISION_LABELS[r.decisionCode] ?? r.decisionCode}: ${r.decisionReason}` : ''}
                    {r.decision === 'ALLOW' ? ` · ${formatDuration(r.durationMs)}` : ''}
                  </div>
                </div>
              </li>
            ))}
          </ol>
        </Card>
        <div className="space-y-4">
          <Card>
            <CardHeader title="Summary" />
            <CardBody>
              <DetailList
                columns={1}
                items={[
                  { label: 'Session id', value: s.sessionId, mono: true },
                  { label: 'Agent', value: s.agentId ? <Link className="text-brand-700 hover:underline" to={`/agents/${s.agentId}`}>{s.agentName}</Link> : s.agentName },
                  { label: 'Requests', value: `${s.allowed} allowed · ${s.denied} denied · ${s.held} held for approval` },
                  { label: 'Integrations', value: s.integrations.join(', ') || '—' },
                  { label: 'Users acted for', value: s.users.join(', ') || 'None (the agent itself)' },
                  { label: 'Sub-agents', value: s.subAgents.join(', ') || 'None' },
                  { label: 'Trace ids', value: <Mono>{[...new Set(s.timeline.map((r) => r.trace?.traceId).filter(Boolean))].join(', ')}</Mono> },
                ]}
              />
            </CardBody>
          </Card>
          {s.approvals.length > 0 && (
            <Card>
              <CardHeader title="Approvals in this session" />
              <CardBody className="space-y-2">
                {s.approvals.map((a) => (
                  <Link key={a.id} to={`/access/approvals?approval=${a.id}`} className="flex items-center justify-between gap-2 rounded-md border border-slate-200 px-3 py-2 text-sm hover:bg-slate-50">
                    <span>{operationLabel(a.operation)}</span>
                    <StatusBadge status={a.status} />
                  </Link>
                ))}
              </CardBody>
            </Card>
          )}
        </div>
      </div>
    </div>
  );
}

export { sessionLink };
