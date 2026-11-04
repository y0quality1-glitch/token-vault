import { useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { KeyRound, Plus } from 'lucide-react';
import { PERMISSIONS, operationLabel, type Grant, type GrantStatus } from '@token-vault/shared';
import { useApi } from '@/hooks/useApi';
import { useAuth } from '@/context/AuthContext';
import { Button } from '@/components/ui/button';
import { Card } from '@/components/ui/card';
import { Badge, StatusBadge } from '@/components/ui/badge';
import { DataTable, FilterTabs } from '@/components/ui/table';
import { EmptyState, ErrorState } from '@/components/ui/feedback';
import { PageHeader } from '@/components/ui/navigation';
import { formatDateTime, relativeTime } from '@/lib/utils';

type Filter = 'all' | 'ACTIVE' | 'PENDING_APPROVAL' | 'EXPIRED' | 'REVOKED';

export function GrantsPage() {
  const navigate = useNavigate();
  const { can } = useAuth();
  const { data, error, loading, reload } = useApi<{ items: Grant[] }>('/grants');
  const [filter, setFilter] = useState<Filter>('all');
  const visible = useMemo(() => (data?.items ?? []).filter((g) => g.status !== 'SUPERSEDED'), [data]);
  const count = (s: GrantStatus) => visible.filter((g) => g.status === s).length;
  const rows = filter === 'all' ? visible : visible.filter((g) => g.status === filter);

  return (
    <div>
      <PageHeader
        title="Access Grants"
        description="Each grant authorizes one agent to use one integration for specific operations, resources and a bounded time window."
        breadcrumbs={[{ label: 'Access Management' }, { label: 'Access Grants' }]}
        actions={
          can(PERMISSIONS.GRANT_MANAGE) && (
            <Button onClick={() => navigate('/access/grants/new')}>
              <Plus className="h-4 w-4" /> Create grant
            </Button>
          )
        }
      />
      <div className="mb-4">
        <FilterTabs
          value={filter}
          onChange={setFilter}
          options={[
            { value: 'all', label: 'All', count: visible.length },
            { value: 'ACTIVE', label: 'Active', count: count('ACTIVE') },
            { value: 'PENDING_APPROVAL', label: 'Pending', count: count('PENDING_APPROVAL') },
            { value: 'EXPIRED', label: 'Expired', count: count('EXPIRED') },
            { value: 'REVOKED', label: 'Revoked', count: count('REVOKED') },
          ]}
        />
      </div>
      {error ? (
        <ErrorState error={error} onRetry={reload} />
      ) : (
        <Card>
          <DataTable
            rows={rows}
            loading={loading}
            rowKey={(g) => g.id}
            onRowClick={(g) => navigate(`/access/grants/${g.id}`)}
            empty={<EmptyState icon={<KeyRound className="h-5 w-5" />} title={visible.length ? 'No grants with this status' : 'No access grants'} description="Agents are denied by default until a grant authorizes them." action={can(PERMISSIONS.GRANT_MANAGE) && !visible.length && <Button onClick={() => navigate('/access/grants/new')}>Create grant</Button>} />}
            columns={[
              { key: 'name', header: 'Grant', cell: (g) => <span className="font-medium text-slate-900">{g.name}{g.version > 1 && <span className="ml-1 text-xs font-normal text-slate-400">v{g.version}</span>}</span> },
              { key: 'agent', header: 'Agent', cell: (g) => g.agentName },
              { key: 'int', header: 'Integration', cell: (g) => g.integrationName, hideBelow: 'md' },
              {
                key: 'perm',
                header: 'Permissions',
                cell: (g) => (
                  <div className="flex max-w-xs flex-wrap gap-1">
                    {g.scopes.map((s) => (
                      <Badge key={s} tone="blue">
                        {operationLabel(s)}
                      </Badge>
                    ))}
                  </div>
                ),
                hideBelow: 'xl',
              },
              { key: 'status', header: 'Status', cell: (g) => <StatusBadge status={g.status} /> },
              { key: 'by', header: 'Created by', cell: (g) => g.createdByName, hideBelow: 'xl' },
              { key: 'exp', header: 'Expiry', cell: (g) => <span title={formatDateTime(g.expiresAt)} className="whitespace-nowrap text-slate-500">{relativeTime(g.expiresAt)}</span>, hideBelow: 'md' },
              { key: 'used', header: 'Last used', cell: (g) => <span className="text-slate-500">{relativeTime(g.lastUsedAt)}</span>, hideBelow: 'lg' },
            ]}
          />
        </Card>
      )}
    </div>
  );
}
