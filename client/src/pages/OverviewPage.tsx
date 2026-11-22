import { Link, useNavigate } from 'react-router-dom';
import { Activity, AlertTriangle, ArrowRight, Bot, CheckCircle2, Circle, Clock, KeyRound, Plug, ShieldAlert, ShieldX, Webhook } from 'lucide-react';
import { DECISION_LABELS, PERMISSIONS, type DashboardSummary } from '@token-vault/shared';
import { operationLabel } from '@/lib/providers';
import { usePost } from '@/hooks/useApi';
import { useAuth } from '@/context/AuthContext';
import { Button } from '@/components/ui/button';
import { Card, CardBody, CardHeader, StatCard } from '@/components/ui/card';
import { DecisionBadge, StatusBadge } from '@/components/ui/badge';
import { DataTable } from '@/components/ui/table';
import { EmptyState, ErrorState, PageSkeleton } from '@/components/ui/feedback';
import { PageHeader } from '@/components/ui/navigation';
import { cn, relativeTime } from '@/lib/utils';
import { EmergencyStopCard } from '@/components/EmergencyStop';

export function OverviewPage() {
  const { session, can } = useAuth();
  const navigate = useNavigate();
  const { data, error, loading, reload } = usePost<DashboardSummary>('/dashboard/getdata');

  if (error) return <ErrorState error={error} onRetry={reload} />;
  if (loading && !data) return <PageSkeleton />;
  if (!data) return null;

  const setupDone = Object.values(data.setup).every(Boolean);
  const steps = [
    { done: data.setup.webhook, label: 'Register and verify the customer webhook', to: '/webhook/setup', perm: PERMISSIONS.WEBHOOK_MANAGE },
    { done: data.setup.integration, label: 'Connect GitHub through the webhook', to: '/integrations/connect/github', perm: PERMISSIONS.INTEGRATION_MANAGE },
    { done: data.setup.agent, label: 'Register an AI agent', to: '/agents?register=1', perm: PERMISSIONS.AGENT_MANAGE },
    { done: data.setup.grant, label: 'Create a scoped access grant', to: '/access/grants/new', perm: PERMISSIONS.GRANT_MANAGE },
    { done: data.setup.request, label: 'Send an agent request from the playground', to: '/playground', perm: null },
  ];
  const webhookTone = data.webhook.status === 'CONNECTED' ? 'success' : data.webhook.status === 'NOT_CONFIGURED' || data.webhook.status === 'PENDING' ? 'warning' : 'danger';

  return (
    <div className="space-y-6">
      <PageHeader
        title="Overview"
        description={`Vault health and access activity for ${session?.currentOrganization?.name}.`}
        actions={
          <>
            {can(PERMISSIONS.WEBHOOK_MANAGE) && (
              <Button variant="outline" onClick={() => navigate('/webhook/setup')}>
                <Webhook className="h-4 w-4" /> Configure Webhook
              </Button>
            )}
            {can(PERMISSIONS.INTEGRATION_MANAGE) && (
              <Button variant="outline" onClick={() => navigate('/integrations/catalog')}>
                <Plug className="h-4 w-4" /> Connect Integration
              </Button>
            )}
            {can(PERMISSIONS.AGENT_MANAGE) && (
              <Button variant="outline" onClick={() => navigate('/agents?register=1')}>
                <Bot className="h-4 w-4" /> Register Agent
              </Button>
            )}
            {can(PERMISSIONS.GRANT_MANAGE) && (
              <Button onClick={() => navigate('/access/grants/new')}>
                <KeyRound className="h-4 w-4" /> Create Access Grant
              </Button>
            )}
          </>
        }
      />

      {!setupDone && (
        <Card>
          <CardHeader title="Get started" description="Complete the primary setup journey to broker your first agent request." />
          <CardBody>
            <ol className="grid gap-2 md:grid-cols-2 xl:grid-cols-5">
              {steps.map((s, i) => {
                const allowed = s.perm === null || can(s.perm);
                const next = !s.done && steps.slice(0, i).every((x) => x.done);
                return (
                  <li key={s.label}>
                    <button
                      disabled={!allowed}
                      onClick={() => navigate(s.to)}
                      className={cn('flex h-full w-full items-start gap-2.5 rounded-lg border p-3 text-left text-sm transition disabled:cursor-not-allowed disabled:opacity-60', next ? 'border-brand-300 bg-brand-50/60 hover:border-brand-400' : 'border-slate-200 hover:border-slate-300')}
                      title={allowed ? undefined : 'Your role cannot perform this step'}
                    >
                      {s.done ? <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-emerald-600" /> : <Circle className={cn('mt-0.5 h-4 w-4 shrink-0', next ? 'text-brand-600' : 'text-slate-300')} />}
                      <span className={cn(s.done ? 'text-slate-500 line-through' : 'text-slate-800')}>
                        <span className="mr-1 text-xs text-slate-400">{i + 1}.</span>
                        {s.label}
                      </span>
                    </button>
                  </li>
                );
              })}
            </ol>
          </CardBody>
        </Card>
      )}

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-6">
        <StatCard label="Connected integrations" value={data.counts.connectedIntegrations} icon={<Plug className="h-4 w-4" />} onClick={() => navigate('/integrations/connected')} />
        <StatCard label="Registered agents" value={data.counts.registeredAgents} icon={<Bot className="h-4 w-4" />} onClick={() => navigate('/agents')} />
        <StatCard label="Active grants" value={data.counts.activeGrants} icon={<KeyRound className="h-4 w-4" />} onClick={() => navigate('/access/grants')} />
        <StatCard label="Access requests (24h)" value={data.counts.requests24h} icon={<Activity className="h-4 w-4" />} onClick={can(PERMISSIONS.AUDIT_READ) ? () => navigate('/audit/access-logs') : undefined} />
        <StatCard label="Denied requests (24h)" value={data.counts.denied24h} tone={data.counts.denied24h ? 'danger' : 'default'} icon={<ShieldX className="h-4 w-4" />} onClick={can(PERMISSIONS.AUDIT_READ) ? () => navigate('/audit/access-logs?decision=DENY') : undefined} />
        <StatCard
          label="Webhook health"
          value={<StatusBadge status={data.webhook.status} className="text-sm" />}
          tone={webhookTone}
          icon={<Webhook className="h-4 w-4" />}
          hint={data.webhook.name ? `${data.webhook.name} · ${relativeTime(data.webhook.lastHeartbeatAt)}` : 'No webhook registered'}
          onClick={() => navigate('/webhook/health')}
        />
      </div>

      <div className="grid gap-6 xl:grid-cols-3">
        <Card className="xl:col-span-2">
          <CardHeader
            title="Recent access activity"
            icon={<Activity className="h-4 w-4" />}
            actions={
              can(PERMISSIONS.AUDIT_READ) && (
                <Link to="/audit/access-logs" className="flex items-center gap-1 text-sm text-brand-700 hover:underline">
                  View all <ArrowRight className="h-3.5 w-3.5" />
                </Link>
              )
            }
          />
          <DataTable
            dense
            rows={data.recentActivity}
            rowKey={(r) => r.id}
            onRowClick={can(PERMISSIONS.AUDIT_READ) ? (r) => navigate(`/audit/access-logs?request=${r.id}`) : undefined}
            empty={<EmptyState icon={<Activity className="h-5 w-5" />} title="No access requests yet" description="Requests from agents and the Access Playground will appear here." action={<Button size="sm" onClick={() => navigate('/playground')}>Open playground</Button>} />}
            columns={[
              { key: 'time', header: 'Time', cell: (r) => <span className="whitespace-nowrap text-slate-500">{relativeTime(r.createdAt)}</span> },
              { key: 'agent', header: 'Agent', cell: (r) => <span className="font-medium text-slate-800">{r.agentName}</span> },
              { key: 'op', header: 'Operation', cell: (r) => operationLabel(r.operation), hideBelow: 'md' },
              { key: 'int', header: 'Integration', cell: (r) => r.integrationName, hideBelow: 'lg' },
              { key: 'decision', header: 'Decision', cell: (r) => <DecisionBadge decision={r.decision} code={r.decisionCode} /> },
              { key: 'reason', header: 'Reason', cell: (r) => <span className="text-slate-500">{DECISION_LABELS[r.decisionCode] ?? r.decisionCode}</span>, hideBelow: 'xl' },
            ]}
          />
        </Card>

        <Card>
          <CardHeader title="Security alerts" icon={<ShieldAlert className="h-4 w-4" />} />
          <CardBody className="space-y-3">
            {data.alerts.length === 0 ? (
              <EmptyState icon={<CheckCircle2 className="h-5 w-5" />} title="No active alerts" className="py-6" />
            ) : (
              data.alerts.map((a) => (
                <Link key={a.id} to={a.link} className="flex gap-3 rounded-lg border border-slate-100 p-3 transition hover:border-slate-200 hover:bg-slate-50">
                  <AlertTriangle className={cn('mt-0.5 h-4 w-4 shrink-0', a.severity === 'critical' ? 'text-red-600' : a.severity === 'warning' ? 'text-amber-600' : 'text-brand-600')} />
                  <div className="min-w-0">
                    <p className="text-sm font-medium text-slate-800">{a.title}</p>
                    <p className="line-clamp-2 text-xs text-slate-500">{a.detail}</p>
                    <p className="mt-1 text-[11px] text-slate-400">{relativeTime(a.at)}</p>
                  </div>
                </Link>
              ))
            )}
          </CardBody>
        </Card>
      </div>

      <div className="grid gap-6 lg:grid-cols-3">
        <Card>
          <CardHeader title="Integration connection status" icon={<Plug className="h-4 w-4" />} />
          <CardBody className="space-y-1">
            {data.integrations.length === 0 ? (
              <EmptyState title="No integrations" description="Connect GitHub through your customer webhook." className="py-6" action={can(PERMISSIONS.INTEGRATION_MANAGE) && <Button size="sm" onClick={() => navigate('/integrations/catalog')}>Connect integration</Button>} />
            ) : (
              data.integrations.map((i) => (
                <Link key={i.id} to={`/integrations/${i.id}`} className="flex items-center justify-between gap-2 rounded-md px-2 py-2 hover:bg-slate-50">
                  <span className="min-w-0">
                    <span className="block truncate text-sm font-medium text-slate-800">{i.displayName}</span>
                    <span className="block text-xs text-slate-500">
                      {i.environment} · validated {relativeTime(i.lastValidatedAt)}
                    </span>
                  </span>
                  <StatusBadge status={i.credentialStatus} />
                </Link>
              ))
            )}
          </CardBody>
        </Card>

        <Card>
          <CardHeader title="Agent activity (24h)" icon={<Bot className="h-4 w-4" />} />
          <CardBody className="space-y-1">
            {data.agentActivity.length === 0 ? (
              <EmptyState title="No agents" description="Register an agent to issue it an API credential." className="py-6" action={can(PERMISSIONS.AGENT_MANAGE) && <Button size="sm" onClick={() => navigate('/agents?register=1')}>Register agent</Button>} />
            ) : (
              data.agentActivity.map((a) => (
                <Link key={a.agentId} to={`/agents/${a.agentId}`} className="flex items-center justify-between gap-2 rounded-md px-2 py-2 hover:bg-slate-50">
                  <span className="min-w-0">
                    <span className="block truncate text-sm font-medium text-slate-800">{a.agentName}</span>
                    <span className="block text-xs text-slate-500">Last access {relativeTime(a.lastAccessAt)}</span>
                  </span>
                  <span className="text-right text-xs">
                    <span className="block font-medium text-slate-700">{a.requests24h} requests</span>
                    <span className={cn('block', a.denied24h ? 'text-red-600' : 'text-slate-400')}>{a.denied24h} denied</span>
                  </span>
                </Link>
              ))
            )}
          </CardBody>
        </Card>

        <Card>
          <CardHeader title="Grants expiring soon" description="Within 7 days" icon={<Clock className="h-4 w-4" />} />
          <CardBody className="space-y-1">
            {data.expiringGrants.length === 0 ? (
              <EmptyState title="Nothing expiring" className="py-6" />
            ) : (
              data.expiringGrants.map((g) => (
                <Link key={g.id} to={`/access/grants/${g.id}`} className="flex items-center justify-between gap-2 rounded-md px-2 py-2 hover:bg-slate-50">
                  <span className="min-w-0">
                    <span className="block truncate text-sm font-medium text-slate-800">{g.name}</span>
                    <span className="block truncate text-xs text-slate-500">
                      {g.agentName} → {g.integrationName}
                    </span>
                  </span>
                  <span className="whitespace-nowrap text-xs font-medium text-amber-700">{relativeTime(g.expiresAt)}</span>
                </Link>
              ))
            )}
          </CardBody>
        </Card>
      </div>

      <EmergencyStopCard />
    </div>
  );
}
