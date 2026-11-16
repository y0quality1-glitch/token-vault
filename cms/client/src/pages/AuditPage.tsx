import { Link } from 'react-router-dom';
import type { CmsAuditEvent } from '@token-vault/shared';
import { Badge } from '@ui/badge';
import { Card } from '@ui/card';
import { ErrorState } from '@ui/feedback';
import { PageHeader } from '@ui/navigation';
import { DataTable } from '@ui/table';
import { api } from '@/lib/api';
import { useQuery } from '@/lib/hooks';
import { formatDateTime } from '@/lib/utils';

const TONE: Record<string, 'green' | 'amber' | 'red' | 'blue' | 'gray'> = {
  'version.published': 'green',
  'version.submitted': 'amber',
  'version.rejected': 'red',
  'application.archived': 'red',
  'application.created': 'blue',
};

export function AuditPage() {
  const log = useQuery('audit', () => api.page<CmsAuditEvent>('/audit/getall', { pageSize: 200 }));
  return (
    <>
      <PageHeader title="Audit log" description="Every change to applications and versions. Append-only: the database rejects updates and deletes." />
      {log.error ? (
        <ErrorState error={log.error} onRetry={log.reload} />
      ) : (
        <Card>
          <DataTable
            dense
            loading={log.loading}
            rows={log.data?.items}
            rowKey={(e) => String(e.id)}
            columns={[
              { key: 'at', header: 'Time', cell: (e) => <span className="whitespace-nowrap text-sm text-slate-500">{formatDateTime(e.at)}</span> },
              { key: 'actor', header: 'Actor', cell: (e) => <span className="text-sm">{e.actorName}</span> },
              { key: 'action', header: 'Action', cell: (e) => <Badge tone={TONE[e.action] ?? 'gray'}>{e.action}</Badge> },
              {
                key: 'target',
                header: 'Application',
                cell: (e) =>
                  e.applicationKey ? (
                    <Link className="font-mono text-sm text-brand-700 hover:underline" to={e.version ? `/applications/${e.applicationKey}/versions/${e.version}` : `/applications/${e.applicationKey}`}>
                      {e.applicationKey}
                      {e.version ? ` v${e.version}` : ''}
                    </Link>
                  ) : (
                    '—'
                  ),
              },
              {
                key: 'details',
                header: 'Details',
                hideBelow: 'lg',
                cell: (e) => <span className="block max-w-md truncate font-mono text-xs text-slate-500">{Object.keys(e.details).length ? JSON.stringify(e.details) : ''}</span>,
              },
            ]}
          />
        </Card>
      )}
    </>
  );
}
