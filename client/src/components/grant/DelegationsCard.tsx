import { useState } from 'react';
import { GitBranch } from 'lucide-react';
import { PERMISSIONS, actingUserLabel, type DelegationView } from '@token-vault/shared';
import { useMutation, usePost } from '@/hooks/useApi';
import { useAuth } from '@/context/AuthContext';
import { api } from '@/lib/api';
import { operationLabel } from '@/lib/providers';
import { Button } from '@/components/ui/button';
import { Card, CardHeader } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Field, Input } from '@/components/ui/form';
import { EmptyState, ErrorState, FormError } from '@/components/ui/feedback';
import { Dialog } from '@/components/ui/dialog';
import { DataTable } from '@/components/ui/table';
import { useToast } from '@/components/ui/toast';
import { formatDateTime, relativeTime } from '@/lib/utils';

const STATUS_TONE = { ACTIVE: 'green', EXPIRED: 'gray', REVOKED: 'red' } as const;

/**
 * Sub-agent delegations of an agent or of a grant. Revoking one stops it and everything
 * delegated from it; revoking the grant or disabling the agent stops them all.
 */
export function DelegationsCard({ agentId, grantId }: { agentId?: string; grantId?: string }) {
  const { can } = useAuth();
  const toast = useToast();
  const query = agentId ? { agentId } : { grantId: grantId ?? '' };
  const { data, error, loading, reload } = usePost<{ items: DelegationView[] }>('/delegation/getall', query);
  const [revoking, setRevoking] = useState<DelegationView | null>(null);
  const [reason, setReason] = useState('');
  const revoke = useMutation((id: string, why: string) => api.post<DelegationView>('/delegation/revoke', { id, reason: why }));
  const items = data?.items ?? [];
  const byId = new Map(items.map((d) => [d.id, d]));

  return (
    <Card>
      <CardHeader
        title="Sub-agent delegations"
        icon={<GitBranch className="h-4 w-4" />}
        description="Narrower, short-lived slices of a grant that the agent handed to sub-agents. Labels are agent-written."
      />
      {error ? (
        <ErrorState error={error} onRetry={reload} />
      ) : (
        <DataTable
          rows={data?.items}
          loading={loading}
          rowKey={(d) => d.id}
          empty={<EmptyState icon={<GitBranch className="h-5 w-5" />} title="No delegations" description="When this agent delegates to a sub-agent (SDK: delegate()), it shows here." />}
          columns={[
            {
              key: 'label',
              header: 'Sub-agent',
              cell: (d) => (
                <div className="min-w-0">
                  <div className="font-medium text-slate-800">
                    {d.depth > 1 && <span className="text-slate-400">{'↳ '.repeat(d.depth - 1)}</span>}
                    {d.label}
                  </div>
                  <div className="text-xs text-slate-500">
                    {d.parentDelegationId ? `from ${byId.get(d.parentDelegationId)?.label ?? d.parentDelegationId} · ` : ''}
                    {agentId ? d.grantName : d.agentName}
                    {d.onBehalfOf ? ` · for ${actingUserLabel(d.onBehalfOf)}` : ''}
                  </div>
                </div>
              ),
            },
            {
              key: 'ops',
              header: 'Delegated',
              cell: (d) => (
                <div className="space-y-1">
                  <div className="flex flex-wrap gap-1">
                    {d.operations.map((o) => (
                      <Badge key={o} tone="blue">
                        {operationLabel(o)}
                      </Badge>
                    ))}
                  </div>
                  <div className="font-mono text-xs text-slate-500">{d.resources.length ? d.resources.join(', ') : 'any resource the grant allows'}</div>
                </div>
              ),
              hideBelow: 'md',
            },
            { key: 'use', header: 'Requests', cell: (d) => <span className="text-slate-600">{d.maxRequests ? `${d.used} of ${d.maxRequests}` : d.used}</span>, hideBelow: 'lg' },
            {
              key: 'status',
              header: 'Status',
              cell: (d) => (
                <div title={d.statusReason ?? undefined}>
                  <Badge tone={STATUS_TONE[d.status]} dot>
                    {d.status === 'ACTIVE' ? 'Active' : d.status === 'EXPIRED' ? 'Expired' : d.revokedAt ? 'Revoked' : 'Revoked (parent)'}
                  </Badge>
                  <div className="mt-0.5 text-xs text-slate-500">{d.status === 'ACTIVE' ? `until ${formatDateTime(d.expiresAt)}` : d.revokedAt ? relativeTime(d.revokedAt) : ''}</div>
                </div>
              ),
            },
            {
              key: 'actions',
              header: '',
              cell: (d) =>
                d.status === 'ACTIVE' &&
                can(PERMISSIONS.GRANT_REVOKE) && (
                  <Button size="sm" variant="danger-outline" onClick={() => setRevoking(d)}>
                    Revoke
                  </Button>
                ),
            },
          ]}
        />
      )}
      <Dialog
        open={!!revoking}
        onClose={() => setRevoking(null)}
        size="sm"
        title="Revoke this delegation?"
        description={`Sub-agent "${revoking?.label ?? ''}" and every delegation made from it stop working from the next request. The agent's own grant is not changed.`}
        footer={
          <>
            <Button variant="outline" onClick={() => setRevoking(null)}>
              Cancel
            </Button>
            <Button
              variant="danger"
              loading={revoke.pending}
              onClick={async () => {
                if (!revoking) return;
                const r = await revoke.run(revoking.id, reason);
                if (r) {
                  toast.success('Delegation revoked', r.label);
                  setRevoking(null);
                  setReason('');
                  reload();
                }
              }}
            >
              Revoke delegation
            </Button>
          </>
        }
      >
        <FormError error={revoke.error} />
        <Field label="Reason" htmlFor="dlg-reason" required error={revoke.fieldErrors.reason}>
          <Input id="dlg-reason" value={reason} onChange={(e) => setReason(e.target.value)} placeholder="Sub-agent misbehaving" />
        </Field>
      </Dialog>
    </Card>
  );
}
