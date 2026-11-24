import { useMemo, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { Filter, ShieldOff } from 'lucide-react';
import { PERMISSIONS, type SecretAccessGrantView } from '@token-vault/shared';
import { usePost } from '@/hooks/useApi';
import { useAuth } from '@/context/AuthContext';
import { compact } from '@/lib/api';
import { Button } from '@/components/ui/button';
import { Card } from '@/components/ui/card';
import { Select } from '@/components/ui/form';
import { EmptyState, ErrorState } from '@/components/ui/feedback';
import { PageHeader } from '@/components/ui/navigation';
import { useToast } from '@/components/ui/toast';
import { GrantDialog, GrantsTable, RevokeGrantDialog, SecretsSectionTabs, selectorText, useAgents } from './secretAccess';
import { useSecretTypes } from './secretUi';

/** Every secret access grant in the organization; selector grants are created here. */
export function SecretAccessPage() {
  const { can } = useAuth();
  const toast = useToast();
  const types = useSecretTypes();
  const agents = useAgents();
  const [params, setParams] = useSearchParams();
  const agentId = params.get('agentId') ?? '';
  const [status, setStatus] = useState('');
  const [granting, setGranting] = useState(false);
  const [revoking, setRevoking] = useState<SecretAccessGrantView | null>(null);
  const { data, error, loading, reload } = usePost<{ items: SecretAccessGrantView[]; total: number }>('/secretAccess/getall', compact({ agentId, status }));
  const manage = can(PERMISSIONS.SECRET_MANAGE_ACCESS);
  const agentOptions = useMemo(() => [...(agents.data?.items ?? [])].sort((a, b) => a.name.localeCompare(b.name)), [agents.data]);
  const filtered = !!(agentId || status);

  return (
    <div>
      <PageHeader
        title="Secret access"
        description="Which agents may retrieve which secrets. Default deny: an agent reads a secret only through an active grant, either for that secret or for a selector that matches it."
        breadcrumbs={[{ label: 'Secrets', to: '/secrets' }, { label: 'Access grants' }]}
        actions={
          manage && (
            <Button onClick={() => setGranting(true)} data-testid="secret-grant-new">
              <Filter className="h-4 w-4" /> Grant by selector
            </Button>
          )
        }
      />
      <SecretsSectionTabs current="/secrets/access" />
      <div className="mb-4 flex flex-wrap gap-2" data-testid="secret-grant-filters">
        <Select
          className="w-56"
          value={agentId}
          onChange={(e) => setParams(e.target.value ? { agentId: e.target.value } : {}, { replace: true })}
          aria-label="Filter by agent"
          data-testid="secret-grant-filter-agent"
        >
          <option value="">All agents</option>
          {agentOptions.map((a) => (
            <option key={a.id} value={a.id}>
              {a.name}
            </option>
          ))}
        </Select>
        <Select className="w-44" value={status} onChange={(e) => setStatus(e.target.value)} aria-label="Filter by status" data-testid="secret-grant-filter-status">
          <option value="">All statuses</option>
          <option value="ACTIVE">Active</option>
          <option value="REVOKED">Revoked</option>
          <option value="EXPIRED">Expired</option>
        </Select>
      </div>
      {error ? (
        <ErrorState error={error} onRetry={reload} />
      ) : (
        <Card data-testid="secret-grant-list">
          <GrantsTable
            grants={data?.items}
            loading={loading}
            onRevoke={manage ? setRevoking : undefined}
            empty={
              <EmptyState
                icon={<ShieldOff className="h-5 w-5" />}
                title={filtered ? 'No grants match the filters' : 'No agent can read any secret yet'}
                description={filtered ? 'Change or clear the filters.' : 'Grant access on a secret’s page, or here by selector (project, workspace, environment, type or tag).'}
                action={!filtered && manage && <Button onClick={() => setGranting(true)}>Grant by selector</Button>}
              />
            }
          />
        </Card>
      )}
      {granting && (
        <GrantDialog
          types={types.data?.types ?? []}
          defaultAgentId={agentId || undefined}
          onClose={() => setGranting(false)}
          onDone={async (g) => {
            setGranting(false);
            toast.success('Access granted', `${g.agent.name} can now read secrets matching ${selectorText(g.selector)}.`);
            await reload();
          }}
        />
      )}
      {revoking && (
        <RevokeGrantDialog
          grant={revoking}
          onClose={() => setRevoking(null)}
          onDone={async () => {
            setRevoking(null);
            await reload();
          }}
        />
      )}
    </div>
  );
}
