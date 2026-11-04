import { useState } from 'react';
import { ShieldAlert, Search } from 'lucide-react';
import type { AuditEvent } from '@token-vault/shared';
import { useApi } from '@/hooks/useApi';
import { qs } from '@/lib/api';
import { Card, DetailList } from '@/components/ui/card';
import { Badge, StatusBadge } from '@/components/ui/badge';
import { Input, Select } from '@/components/ui/form';
import { EmptyState, ErrorState } from '@/components/ui/feedback';
import { Drawer } from '@/components/ui/dialog';
import { DataTable } from '@/components/ui/table';
import { PageHeader } from '@/components/ui/navigation';
import { JsonView, Mono } from '@/components/ui/secret';
import { formatDateTime } from '@/lib/utils';
import { IntegrityPanel } from '@/components/IntegrityPanel';

const CATEGORIES = [
  { value: '', label: 'All event types' },
  { value: 'access.', label: 'Access decisions' },
  { value: 'grant.', label: 'Grants' },
  { value: 'agent.', label: 'Agents' },
  { value: 'integration.', label: 'Integrations' },
  { value: 'webhook.', label: 'Webhooks' },
  { value: 'policy.', label: 'Policies' },
  { value: 'member.', label: 'Members' },
  { value: 'auth.', label: 'Authentication' },
  { value: 'grant_request.', label: 'Access requests' },
  { value: 'demo.', label: 'Demo controls' },
];

export function SecurityEventsPage() {
  const [f, setF] = useState({ eventType: '', outcome: '', actorType: '', search: '' });
  const { data, error, loading, reload } = useApi<{ items: AuditEvent[]; total: number }>(`/audit-events${qs({ ...f, category: 'security' })}`);
  const [selected, setSelected] = useState<AuditEvent | null>(null);
  const set = (k: keyof typeof f) => (e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement>) => setF((x) => ({ ...x, [k]: e.target.value }));

  return (
    <div className="space-y-4">
      <PageHeader title="Security Events" description="Administrative actions, denials, revocations and webhook health changes. Successful access events are in Access Logs." breadcrumbs={[{ label: 'Audit & Activity' }, { label: 'Security Events' }]} />
      <IntegrityPanel onChanged={reload} />
      <Card className="p-4">
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
          <div className="relative">
            <Search className="absolute left-2.5 top-2.5 h-4 w-4 text-slate-400" />
            <Input className="pl-8" placeholder="Search actor, target, event…" value={f.search} onChange={set('search')} />
          </div>
          <Select value={f.eventType} onChange={set('eventType')} aria-label="Event type">
            {CATEGORIES.map((c) => (
              <option key={c.value} value={c.value}>
                {c.label}
              </option>
            ))}
          </Select>
          <Select value={f.outcome} onChange={set('outcome')} aria-label="Outcome">
            <option value="">All outcomes</option>
            <option value="SUCCESS">Success</option>
            <option value="DENIED">Denied</option>
            <option value="FAILURE">Failure</option>
          </Select>
          <Select value={f.actorType} onChange={set('actorType')} aria-label="Actor type">
            <option value="">All actors</option>
            <option value="USER">Users</option>
            <option value="AGENT">Agents</option>
            <option value="SYSTEM">System</option>
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
            rowKey={(e) => e.id}
            onRowClick={setSelected}
            empty={<EmptyState icon={<ShieldAlert className="h-5 w-5" />} title="No security events match these filters" />}
            columns={[
              { key: 't', header: 'Timestamp', cell: (e) => <span className="whitespace-nowrap text-slate-500">{formatDateTime(e.createdAt)}</span> },
              { key: 'sev', header: 'Severity', cell: (e) => <Badge tone={e.severity === 'critical' ? 'red' : e.severity === 'warning' ? 'amber' : 'gray'}>{e.severity}</Badge>, hideBelow: 'md' },
              { key: 'type', header: 'Event', cell: (e) => <span className="font-mono text-xs text-slate-700">{e.eventType}</span> },
              { key: 'actor', header: 'Actor', cell: (e) => <span>{e.actorName}<span className="block text-xs text-slate-400">{e.actorType.toLowerCase()}</span></span> },
              { key: 'target', header: 'Target', cell: (e) => <span>{e.targetName}<span className="block text-xs text-slate-400">{e.targetType}</span></span>, hideBelow: 'lg' },
              { key: 'outcome', header: 'Outcome', cell: (e) => <StatusBadge status={e.outcome} /> },
            ]}
          />
        </Card>
      )}
      <Drawer open={!!selected} onClose={() => setSelected(null)} title={selected?.eventType ?? ''} subtitle={selected?.id}>
        {selected && (
          <div className="space-y-5">
            <DetailList
              items={[
                { label: 'Event ID', value: <Mono>{selected.id}</Mono> },
                { label: 'Timestamp', value: formatDateTime(selected.createdAt) },
                { label: 'Actor', value: `${selected.actorName} (${selected.actorType.toLowerCase()})` },
                { label: 'Actor ID', value: selected.actorId, mono: true },
                { label: 'Target', value: `${selected.targetName} (${selected.targetType})` },
                { label: 'Target ID', value: selected.targetId, mono: true },
                { label: 'Outcome', value: <StatusBadge status={selected.outcome} /> },
                { label: 'Severity', value: selected.severity },
                { label: 'Correlation ID', value: selected.correlationId, mono: true },
                { label: 'Chain position', value: selected.seq ? `#${selected.seq} · ${selected.hash?.slice(0, 16)}…` : 'Predates the chain', mono: true },
              ]}
            />
            <div>
              <p className="mb-2 text-xs font-semibold uppercase tracking-wide text-slate-500">Metadata (sanitized)</p>
              <JsonView value={selected.metadata} />
            </div>
          </div>
        )}
      </Drawer>
    </div>
  );
}
