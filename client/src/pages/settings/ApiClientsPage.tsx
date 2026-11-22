import { useNavigate } from 'react-router-dom';
import { KeyRound } from 'lucide-react';
import type { ApiClient } from '@token-vault/shared';
import { usePost } from '@/hooks/useApi';
import { Card } from '@/components/ui/card';
import { StatusBadge } from '@/components/ui/badge';
import { Callout, EmptyState, ErrorState } from '@/components/ui/feedback';
import { DataTable } from '@/components/ui/table';
import { PageHeader } from '@/components/ui/navigation';
import { Mono } from '@/components/ui/secret';
import { formatDateTime, relativeTime } from '@/lib/utils';

export function ApiClientsPage() {
  const navigate = useNavigate();
  const { data, error, loading, reload } = usePost<{ items: ApiClient[] }>('/apiClient/getall');
  return (
    <div className="space-y-4">
      <PageHeader title="API Clients" description="Agent API credentials issued by this organization." breadcrumbs={[{ label: 'Settings' }, { label: 'API Clients' }]} />
      <Callout tone="security" title="Only key identifiers are visible">
        Token Vault stores a scrypt hash of each credential. The key ID is public and used for lookup; the secret portion was displayed once at issuance and cannot be recovered. Rotate from the agent's page to issue a replacement.
      </Callout>
      {error ? (
        <ErrorState error={error} onRetry={reload} />
      ) : (
        <Card>
          <DataTable
            rows={data?.items}
            loading={loading}
            rowKey={(c) => c.agentId}
            onRowClick={(c) => navigate(`/agents/${c.agentId}`)}
            empty={<EmptyState icon={<KeyRound className="h-5 w-5" />} title="No API clients" description="Register an agent to issue its first credential." />}
            columns={[
              { key: 'key', header: 'Credential', cell: (c) => <Mono>{c.maskedKey}</Mono> },
              { key: 'agent', header: 'Agent', cell: (c) => <span className="font-medium text-slate-800">{c.agentName}</span> },
              { key: 'status', header: 'Agent status', cell: (c) => <StatusBadge status={c.agentStatus} /> },
              { key: 'issued', header: 'Issued', cell: (c) => <span className="text-slate-500">{formatDateTime(c.issuedAt)}</span>, hideBelow: 'md' },
              { key: 'used', header: 'Last used', cell: (c) => <span className="text-slate-500">{relativeTime(c.lastUsedAt)}</span>, hideBelow: 'md' },
            ]}
          />
        </Card>
      )}
    </div>
  );
}
