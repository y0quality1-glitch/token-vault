import { useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { RefreshCw } from 'lucide-react';
import type { SecretRotationJobStatus, SecretRotationJobView } from '@token-vault/shared';
import { usePost } from '@/hooks/useApi';
import { formatDateTime, relativeTime } from '@/lib/utils';
import { Button } from '@/components/ui/button';
import { Card } from '@/components/ui/card';
import { EmptyState, ErrorState } from '@/components/ui/feedback';
import { DataTable, FilterTabs } from '@/components/ui/table';
import { PageHeader } from '@/components/ui/navigation';
import { SecretsSectionTabs } from './secretAccess';
import { ROTATION_STRATEGY_SHORT, ROTATION_TRIGGER_LABELS, RotationJobStatusBadge, rotationVersions } from './secretUi';

type Filter = 'all' | 'waiting' | 'pending' | 'succeeded' | 'failed';
const FILTER_STATUSES: Record<Exclude<Filter, 'all'>, SecretRotationJobStatus[]> = {
  waiting: ['WAITING_FOR_VALUE'],
  pending: ['PENDING', 'RUNNING'],
  succeeded: ['SUCCEEDED'],
  failed: ['FAILED'],
};

/** Every rotation in the organization (spec 4.9.11): scheduled, rotate-now and expiry-driven runs. */
export function SecretRotationsPage() {
  const { data, error, loading, reload } = usePost<{ items: SecretRotationJobView[] }>('/secret/getRotations');
  const [filter, setFilter] = useState<Filter>('all');
  const items = useMemo(() => data?.items ?? [], [data]);
  const count = (f: Exclude<Filter, 'all'>) => items.filter((j) => FILTER_STATUSES[f].includes(j.status)).length;
  const rows = filter === 'all' ? items : items.filter((j) => FILTER_STATUSES[filter].includes(j.status));

  return (
    <div>
      <PageHeader
        title="Rotations"
        description="Every rotation of every secret, newest first. Manual rotations wait for someone to store the new value; generated ones are created by the customer webhook and retried when it fails."
        breadcrumbs={[{ label: 'Secrets', to: '/secrets' }, { label: 'Rotations' }]}
        actions={
          <Button variant="outline" onClick={() => void reload()} loading={loading && !!data}>
            <RefreshCw className="h-4 w-4" /> Refresh
          </Button>
        }
      />
      <SecretsSectionTabs current="/secrets/rotations" />
      <div className="mb-4">
        <FilterTabs
          value={filter}
          onChange={setFilter}
          options={[
            { value: 'all', label: 'All', count: items.length },
            { value: 'waiting', label: 'Waiting for value', count: count('waiting') },
            { value: 'pending', label: 'Pending or retrying', count: count('pending') },
            { value: 'succeeded', label: 'Succeeded', count: count('succeeded') },
            { value: 'failed', label: 'Failed', count: count('failed') },
          ]}
        />
      </div>
      {error ? (
        <ErrorState error={error} onRetry={reload} />
      ) : (
        <Card data-testid="rotations">
          <DataTable
            rows={rows}
            loading={loading && !data}
            rowKey={(j) => j.id}
            empty={
              <EmptyState
                icon={<RefreshCw className="h-5 w-5" />}
                title={filter === 'all' ? 'No rotations yet' : 'No rotations here'}
                description="Rotations appear when a secret with scheduled rotation is due, or when someone uses Rotate now on a secret."
              />
            }
            columns={[
              {
                key: 'secret',
                header: 'Secret',
                cell: (j) => (
                  <div className="min-w-0" data-testid="rotation-row" data-status={j.status} data-trigger={j.trigger} data-secret-id={j.secret.id}>
                    <Link className="font-medium text-brand-700 hover:underline" to={`/secrets/${j.secret.id}`}>
                      {j.secret.name}
                    </Link>
                    {j.requestedBy && <span className="block text-xs text-slate-500">by {j.requestedBy.name}</span>}
                  </div>
                ),
              },
              { key: 'trigger', header: 'Trigger', cell: (j) => <span className="text-slate-600">{ROTATION_TRIGGER_LABELS[j.trigger] ?? j.trigger}</span>, hideBelow: 'md' },
              { key: 'strategy', header: 'Strategy', cell: (j) => <span className="text-slate-600">{ROTATION_STRATEGY_SHORT[j.strategy] ?? j.strategy}</span>, hideBelow: 'lg' },
              { key: 'status', header: 'Status', cell: (j) => <RotationJobStatusBadge job={j} /> },
              { key: 'versions', header: 'Versions', cell: (j) => <span className="whitespace-nowrap font-mono text-[13px] text-slate-600">{rotationVersions(j)}</span>, hideBelow: 'md' },
              { key: 'attempts', header: 'Attempts', cell: (j) => <span className="text-slate-600">{j.attempts}</span>, hideBelow: 'xl' },
              {
                key: 'error',
                header: 'Error',
                cell: (j) =>
                  j.errorMessage || j.errorCode ? (
                    <span className="block max-w-xs break-words text-xs text-red-700">
                      {j.errorMessage}
                      {j.errorCode && <span className="ml-1 font-mono opacity-70">({j.errorCode})</span>}
                    </span>
                  ) : (
                    <span className="text-slate-400">—</span>
                  ),
                hideBelow: 'lg',
              },
              {
                key: 'when',
                header: 'When',
                cell: (j) => (
                  <span className="whitespace-nowrap text-xs text-slate-500">
                    <span className="block" title={formatDateTime(j.scheduledFor)}>
                      due {relativeTime(j.scheduledFor)}
                    </span>
                    {j.finishedAt && (
                      <span className="block" title={formatDateTime(j.finishedAt)}>
                        finished {relativeTime(j.finishedAt)}
                      </span>
                    )}
                    {!j.finishedAt && j.nextAttemptAt && (
                      <span className="block" title={formatDateTime(j.nextAttemptAt)}>
                        next attempt {relativeTime(j.nextAttemptAt)}
                      </span>
                    )}
                  </span>
                ),
                hideBelow: 'md',
              },
            ]}
          />
        </Card>
      )}
    </div>
  );
}
