import { useNavigate } from 'react-router-dom';
import { Plug, Plus } from 'lucide-react';
import { PERMISSIONS, type Integration } from '@token-vault/shared';
import { usePost } from '@/hooks/useApi';
import { useAuth } from '@/context/AuthContext';
import { Button } from '@/components/ui/button';
import { Card } from '@/components/ui/card';
import { EnvBadge, StatusBadge } from '@/components/ui/badge';
import { DataTable } from '@/components/ui/table';
import { EmptyState, ErrorState } from '@/components/ui/feedback';
import { PageHeader } from '@/components/ui/navigation';
import { Mono } from '@/components/ui/secret';
import { relativeTime } from '@/lib/utils';

export function ConnectedIntegrationsPage() {
  const navigate = useNavigate();
  const { can } = useAuth();
  const { data, error, loading, reload } = usePost<{ items: Integration[] }>('/integration/getall');
  return (
    <div>
      <PageHeader
        title="Connected Integrations"
        description="Control-plane records hold only credential references and non-secret metadata."
        breadcrumbs={[{ label: 'Integrations' }, { label: 'Connected Integrations' }]}
        actions={
          can(PERMISSIONS.INTEGRATION_MANAGE) && (
            <Button onClick={() => navigate('/integrations/catalog')}>
              <Plus className="h-4 w-4" /> Connect integration
            </Button>
          )
        }
      />
      {error ? (
        <ErrorState error={error} onRetry={reload} />
      ) : (
        <Card>
          <DataTable
            rows={data?.items}
            loading={loading}
            rowKey={(i) => i.id}
            onRowClick={(i) => navigate(`/integrations/${i.id}`)}
            empty={<EmptyState icon={<Plug className="h-5 w-5" />} title="No integrations connected" description="Connect GitHub to register a credential with your customer webhook." action={can(PERMISSIONS.INTEGRATION_MANAGE) && <Button onClick={() => navigate('/integrations/connect/github')}>Connect GitHub</Button>} />}
            columns={[
              {
                key: 'name',
                header: 'Integration',
                cell: (i) => (
                  <div>
                    <p className="font-medium text-slate-900">{i.displayName}</p>
                    <p className="text-xs text-slate-500">GitHub · {i.accountLabel}</p>
                  </div>
                ),
              },
              { key: 'env', header: 'Environment', cell: (i) => <EnvBadge env={i.environment} />, hideBelow: 'md' },
              { key: 'ref', header: 'Credential reference', cell: (i) => <Mono>{i.credentialReference}</Mono>, hideBelow: 'lg' },
              { key: 'masked', header: 'Masked identifier', cell: (i) => <span className="font-mono text-xs text-slate-600">{i.maskedIdentifier || '—'}</span>, hideBelow: 'xl' },
              { key: 'webhook', header: 'Customer webhook', cell: (i) => i.webhookName, hideBelow: 'xl' },
              { key: 'status', header: 'Status', cell: (i) => <StatusBadge status={i.credentialStatus} /> },
              { key: 'validated', header: 'Last validated', cell: (i) => <span className="text-slate-500">{relativeTime(i.lastValidatedAt)}</span>, hideBelow: 'md' },
            ]}
          />
        </Card>
      )}
    </div>
  );
}
