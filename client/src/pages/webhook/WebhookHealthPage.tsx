import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Activity, FlaskConical, HeartPulse, RefreshCw, Webhook as WebhookIcon } from 'lucide-react';
import { PERMISSIONS, type Webhook } from '@token-vault/shared';
import { usePost } from '@/hooks/useApi';
import { useAuth } from '@/context/AuthContext';
import { api } from '@/lib/api';
import { Button } from '@/components/ui/button';
import { Card, CardBody, CardHeader, DetailList, StatCard } from '@/components/ui/card';
import { StatusBadge } from '@/components/ui/badge';
import { Switch } from '@/components/ui/form';
import { Callout, EmptyState, ErrorState, PageSkeleton } from '@/components/ui/feedback';
import { DataTable } from '@/components/ui/table';
import { PageHeader } from '@/components/ui/navigation';
import { useToast } from '@/components/ui/toast';
import { cn, formatDuration, formatTime, relativeTime } from '@/lib/utils';

export function WebhookHealthPage() {
  const { can } = useAuth();
  const navigate = useNavigate();
  const toast = useToast();
  const { data, error, loading, reload } = usePost<{ items: Webhook[] }>('/webhook/getall');
  const [busy, setBusy] = useState<string | null>(null);
  const manage = can(PERMISSIONS.WEBHOOK_MANAGE);

  if (error) return <ErrorState error={error} onRetry={reload} />;
  if (loading && !data) return <PageSkeleton />;

  async function test(w: Webhook) {
    setBusy(w.id);
    try {
      const r = await api.post<{ result: { ok: boolean; detail: string; latencyMs: number | null } }>('/webhook/test', { id: w.id });
      if (r.result.ok) toast.success('Health check passed', `${r.result.latencyMs} ms · ${r.result.detail}`);
      else toast.error('Health check failed', r.result.detail);
      await reload();
    } catch (e) {
      toast.error('Health check failed', (e as Error).message);
    } finally {
      setBusy(null);
    }
  }

  async function outage(w: Webhook, enabled: boolean) {
    setBusy(w.id);
    try {
      await api.post('/webhook/simulateOutage', { id: w.id, enabled });
      toast.info(enabled ? 'Simulated outage enabled' : 'Simulated outage cleared', enabled ? 'Brokered requests will now fail safely with WEBHOOK_UNAVAILABLE.' : 'Health re-checked against the real webhook.');
      await reload();
    } catch (e) {
      toast.error('Could not change outage simulation', (e as Error).message);
    } finally {
      setBusy(null);
    }
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="Health & Connectivity"
        description="Signed heartbeats verify the identity and availability of each customer webhook every 30 seconds."
        breadcrumbs={[{ label: 'Webhook / Vault Agent' }, { label: 'Health & Connectivity' }]}
        actions={
          <Button variant="outline" onClick={reload}>
            <RefreshCw className="h-4 w-4" /> Refresh
          </Button>
        }
      />
      {!data?.items.length ? (
        <Card>
          <EmptyState icon={<WebhookIcon className="h-5 w-5" />} title="No webhook registered" description="Register your customer webhook to begin health monitoring." action={<Button onClick={() => navigate('/webhook/setup')}>Configure webhook</Button>} />
        </Card>
      ) : (
        data.items.map((w) => {
          const checks = w.healthHistory;
          const okRate = checks.length ? Math.round((checks.filter((c) => c.ok).length / checks.length) * 100) : null;
          const lat = checks.filter((c) => c.latencyMs !== null).map((c) => c.latencyMs!);
          const avg = lat.length ? Math.round(lat.reduce((a, b) => a + b, 0) / lat.length) : null;
          return (
            <div key={w.id} className="space-y-4">
              <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
                <StatCard label={w.name} value={<StatusBadge status={w.status} className="text-sm" />} icon={<HeartPulse className="h-4 w-4" />} tone={w.status === 'CONNECTED' ? 'success' : w.status === 'PENDING' ? 'warning' : 'danger'} hint={w.endpointUrl} />
                <StatCard label="Last heartbeat" value={<span className="text-lg">{relativeTime(w.lastHeartbeatAt)}</span>} icon={<Activity className="h-4 w-4" />} />
                <StatCard label="Success rate (recent)" value={okRate === null ? '—' : `${okRate}%`} icon={<HeartPulse className="h-4 w-4" />} tone={okRate !== null && okRate < 100 ? 'warning' : 'default'} />
                <StatCard label="Average latency" value={formatDuration(avg)} icon={<Activity className="h-4 w-4" />} />
              </div>

              <div className="grid gap-6 xl:grid-cols-3">
                <Card className="xl:col-span-2">
                  <CardHeader
                    title="Health check history"
                    description="Each check is a signed challenge; the response signature and webhook identity are verified."
                    actions={
                      manage && (
                        <Button size="sm" loading={busy === w.id} onClick={() => test(w)}>
                          Run health check
                        </Button>
                      )
                    }
                  />
                  <div className="flex gap-0.5 px-5 pt-4" aria-label="Recent check results">
                    {[...checks].reverse().map((c, i) => (
                      <span key={i} title={`${formatTime(c.at)} · ${c.detail}`} className={cn('h-6 flex-1 rounded-sm', c.ok ? 'bg-emerald-400' : 'bg-red-400')} />
                    ))}
                  </div>
                  <DataTable
                    dense
                    rows={checks.slice(0, 12)}
                    rowKey={(c) => c.at + c.detail}
                    empty={<EmptyState title="No checks yet" />}
                    columns={[
                      { key: 'at', header: 'Time', cell: (c) => <span className="whitespace-nowrap text-slate-500">{formatTime(c.at)}</span> },
                      { key: 'ok', header: 'Result', cell: (c) => <StatusBadge status={c.ok ? 'HEALTHY' : 'UNHEALTHY'} /> },
                      { key: 'lat', header: 'Latency', cell: (c) => formatDuration(c.latencyMs) },
                      { key: 'detail', header: 'Detail', cell: (c) => <span className="text-slate-500">{c.detail}</span>, hideBelow: 'md' },
                    ]}
                  />
                </Card>

                <div className="space-y-6">
                  <Card>
                    <CardHeader title="Webhook identity" />
                    <CardBody>
                      <DetailList
                        columns={1}
                        items={[
                          { label: 'Instance ID', value: w.instanceId ?? 'Not verified', mono: true },
                          { label: 'Software version', value: w.softwareVersion ?? '—' },
                          { label: 'Authentication', value: 'HMAC-SHA256 signed requests + signed responses' },
                          { label: 'Last error', value: w.lastError ?? 'None' },
                        ]}
                      />
                    </CardBody>
                  </Card>
                  {manage && (
                    <Card>
                      <CardHeader
                        title={
                          <span className="flex items-center gap-2">
                            <FlaskConical className="h-4 w-4 text-violet-600" /> Simulate outage
                          </span>
                        }
                        description="Demo control for Scenario F"
                        actions={<Switch checked={w.simulateOutage} disabled={busy === w.id} onChange={(v) => outage(w, v)} label="Simulate outage" />}
                      />
                      <CardBody>
                        <p className="text-sm text-slate-600">While enabled, the control plane treats this webhook as unreachable. Authorized requests fail safely with WEBHOOK_UNAVAILABLE and no credential is used or exposed.</p>
                      </CardBody>
                    </Card>
                  )}
                </div>
              </div>
              {w.status !== 'CONNECTED' && w.lastError && <Callout tone="danger" title="Webhook is not healthy">{w.lastError}</Callout>}
            </div>
          );
        })
      )}
    </div>
  );
}
