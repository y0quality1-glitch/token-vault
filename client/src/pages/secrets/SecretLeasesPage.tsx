import { useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { RefreshCw, ShieldOff, Timer } from 'lucide-react';
import type { SecretLeaseStatus, SecretLeaseView } from '@token-vault/shared';
import { usePost } from '@/hooks/useApi';
import { Button } from '@/components/ui/button';
import { Card } from '@/components/ui/card';
import { Callout, EmptyState, ErrorState } from '@/components/ui/feedback';
import { DataTable, FilterTabs } from '@/components/ui/table';
import { PageHeader } from '@/components/ui/navigation';
import { SecretsSectionTabs } from './secretAccess';
import { LeaseHolder, LeaseOutcome, LeaseTimes, RevokeLeaseDialog, useCanEndLease } from './secretLeases';
import { LeaseStatusBadge } from './secretUi';

type Filter = 'all' | SecretLeaseStatus;

/** Every lease issued from a dynamic secret in the organization (spec 4.9.3 J). */
export function SecretLeasesPage() {
  const { data, error, loading, reload } = usePost<{ items: SecretLeaseView[] }>('/secretLease/getall');
  const [filter, setFilter] = useState<Filter>('all');
  const [revoking, setRevoking] = useState<SecretLeaseView | null>(null);
  const canEnd = useCanEndLease();
  const items = useMemo(() => data?.items ?? [], [data]);
  const count = (f: SecretLeaseStatus) => items.filter((l) => l.status === f).length;
  const rows = filter === 'all' ? items : items.filter((l) => l.status === filter);

  return (
    <div>
      <PageHeader
        title="Leases"
        description="Short-lived credentials issued from dynamic secrets. The customer webhook creates each one at the provider and removes it when the lease ends; Token Vault never keeps the credential."
        breadcrumbs={[{ label: 'Secrets', to: '/secrets' }, { label: 'Leases' }]}
        actions={
          <Button variant="outline" onClick={() => void reload()} loading={loading && !!data}>
            <RefreshCw className="h-4 w-4" /> Refresh
          </Button>
        }
      />
      <SecretsSectionTabs current="/secrets/leases" />
      {count('REVOKE_FAILED') > 0 && (
        <Callout tone="warning" title="Provider cleanup pending" className="mb-4">
          {count('REVOKE_FAILED')} ended lease(s) could not be removed at the provider yet. Token Vault already refuses them, and the cleanup is retried automatically.
        </Callout>
      )}
      <div className="mb-4">
        <FilterTabs
          value={filter}
          onChange={setFilter}
          options={[
            { value: 'all', label: 'All', count: items.length },
            { value: 'ACTIVE', label: 'Active', count: count('ACTIVE') },
            { value: 'REVOKE_FAILED', label: 'Cleanup pending', count: count('REVOKE_FAILED') },
            { value: 'EXPIRED', label: 'Expired', count: count('EXPIRED') },
            { value: 'REVOKED', label: 'Ended', count: count('REVOKED') },
          ]}
        />
      </div>
      {error ? (
        <ErrorState error={error} onRetry={reload} />
      ) : (
        <Card data-testid="leases">
          <DataTable
            rows={rows}
            loading={loading && !data}
            rowKey={(l) => l.id}
            empty={
              <EmptyState
                icon={<Timer className="h-5 w-5" />}
                title={filter === 'all' ? 'No leases yet' : 'No leases here'}
                description="Leases appear when an application asks for one with tv.secrets.lease(), or when a member issues one from a dynamic secret's page."
              />
            }
            columns={[
              {
                key: 'secret',
                header: 'Secret',
                cell: (l) => (
                  <div className="min-w-0" data-testid="lease-row" data-status={l.status} data-lease-id={l.id} data-secret-id={l.secret.id}>
                    <Link className="font-medium text-brand-700 hover:underline" to={`/secrets/${l.secret.id}`}>
                      {l.secret.name}
                    </Link>
                    <span className="block text-xs text-slate-500">{l.secret.typeKey}</span>
                  </div>
                ),
              },
              { key: 'holder', header: 'Holder', cell: (l) => <LeaseHolder lease={l} /> },
              { key: 'username', header: 'Username', cell: (l) => <code className="break-all font-mono text-[12px] text-slate-700">{l.username}</code>, hideBelow: 'lg' },
              { key: 'status', header: 'Status', cell: (l) => <LeaseStatusBadge status={l.status} /> },
              { key: 'times', header: 'Times', cell: (l) => <LeaseTimes lease={l} />, hideBelow: 'md' },
              { key: 'renewals', header: 'Renewals', cell: (l) => <span className="text-slate-600">{l.renewable ? l.renewCount : '—'}</span>, hideBelow: 'xl' },
              { key: 'outcome', header: 'Ended', cell: (l) => <LeaseOutcome lease={l} />, hideBelow: 'lg' },
              {
                key: 'actions',
                header: '',
                className: 'text-right',
                cell: (l) =>
                  canEnd(l) ? (
                    <Button variant="ghost" size="sm" className="text-red-700 hover:bg-red-50 hover:text-red-800" onClick={() => setRevoking(l)} data-testid="lease-revoke">
                      <ShieldOff className="h-3.5 w-3.5" /> End lease
                    </Button>
                  ) : null,
              },
            ]}
          />
        </Card>
      )}
      {revoking && (
        <RevokeLeaseDialog
          lease={revoking}
          onClose={() => setRevoking(null)}
          onDone={() => {
            setRevoking(null);
            void reload();
          }}
        />
      )}
    </div>
  );
}
