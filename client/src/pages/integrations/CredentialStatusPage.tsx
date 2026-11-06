import { useState } from 'react';
import { Link } from 'react-router-dom';
import { KeyRound, RefreshCw } from 'lucide-react';
import { PERMISSIONS, rotationState, type Integration } from '@token-vault/shared';
import { useApi } from '@/hooks/useApi';
import { useAuth } from '@/context/AuthContext';
import { api } from '@/lib/api';
import { Button } from '@/components/ui/button';
import { Card } from '@/components/ui/card';
import { StatusBadge } from '@/components/ui/badge';
import { DataTable } from '@/components/ui/table';
import { Callout, EmptyState, ErrorState } from '@/components/ui/feedback';
import { PageHeader } from '@/components/ui/navigation';
import { Mono } from '@/components/ui/secret';
import { useToast } from '@/components/ui/toast';
import { formatDateTime, relativeTime } from '@/lib/utils';

export function CredentialStatusPage() {
  const { can } = useAuth();
  const toast = useToast();
  const { data, error, loading, reload } = useApi<{ items: Integration[] }>('/integrations');
  const [testing, setTesting] = useState<string | null>(null);

  async function test(i: Integration) {
    setTesting(i.id);
    try {
      const r = await api.post<{ valid: boolean; upstreamStatus: number | null; simulated: boolean }>(`/integrations/${i.id}/test`);
      if (r.valid) toast.success(`${i.displayName}: credential valid`, `Upstream responded ${r.upstreamStatus}${r.simulated ? ' (simulated)' : ''}.`);
      else toast.error(`${i.displayName}: credential invalid`, `Upstream responded ${r.upstreamStatus ?? 'n/a'}.`);
      await reload();
    } catch (e) {
      toast.error('Test failed', (e as Error).message);
    } finally {
      setTesting(null);
    }
  }

  const [checkingAll, setCheckingAll] = useState(false);
  async function checkAll() {
    setCheckingAll(true);
    try {
      const r = await api.post<{ valid: number; rejected: number; unknown: number; skipped: number }>('/integrations/check-credentials');
      const summary = `${r.valid} valid, ${r.rejected} rejected${r.unknown ? `, ${r.unknown} could not be checked` : ''}${r.skipped ? `, ${r.skipped} skipped (disabled or webhook unhealthy)` : ''}.`;
      if (r.rejected) toast.error('Some credentials were rejected', `${summary} Rejected integrations are now marked invalid.`);
      else toast.success('Credentials checked', summary);
      await reload();
    } catch (e) {
      toast.error('Check failed', (e as Error).message);
    } finally {
      setCheckingAll(false);
    }
  }

  return (
    <div className="space-y-4">
      <PageHeader
        title="Credential Status"
        description="Lifecycle and validation state of every credential held by your customer webhook. Every credential is also re-tested with its provider on a schedule; one the provider rejects is marked invalid."
        breadcrumbs={[{ label: 'Integrations' }, { label: 'Credential Status' }]}
        actions={
          can(PERMISSIONS.INTEGRATION_MANAGE) && (
            <Button variant="outline" loading={checkingAll} onClick={checkAll}>
              <RefreshCw className="h-4 w-4" /> Check all now
            </Button>
          )
        }
      />
      <Callout tone="security" title="What you are looking at">
        Token Vault never holds the secret value. The <strong>credential reference</strong> points to an AES-256-GCM encrypted record inside the customer webhook; the <strong>fingerprint</strong> is a keyed HMAC computed by the webhook so you can detect changes without seeing the secret.
      </Callout>
      {error ? (
        <ErrorState error={error} onRetry={reload} />
      ) : (
        <Card>
          <DataTable
            rows={data?.items}
            loading={loading}
            rowKey={(i) => i.id}
            empty={<EmptyState icon={<KeyRound className="h-5 w-5" />} title="No credentials registered" />}
            columns={[
              { key: 'name', header: 'Integration', cell: (i) => <Link to={`/integrations/${i.id}`} className="font-medium text-slate-900 hover:text-brand-700">{i.displayName}</Link> },
              { key: 'ref', header: 'Reference', cell: (i) => <Mono>{i.credentialReference}</Mono> },
              { key: 'fp', header: 'Fingerprint', cell: (i) => <span className="font-mono text-xs text-slate-500">{i.credentialFingerprint || '—'}</span>, hideBelow: 'lg' },
              { key: 'masked', header: 'Masked', cell: (i) => <span className="font-mono text-xs">{i.maskedIdentifier || '—'}</span>, hideBelow: 'md' },
              { key: 'status', header: 'Status', cell: (i) => <StatusBadge status={i.credentialStatus} /> },
              { key: 'validated', header: 'Last validated', cell: (i) => <span title={formatDateTime(i.lastValidatedAt)} className="text-slate-500">{relativeTime(i.lastValidatedAt)}</span>, hideBelow: 'md' },
              { key: 'rotated', header: 'Rotated', cell: (i) => <span className="text-slate-500">{i.rotatedAt ? relativeTime(i.rotatedAt) : 'Never'}</span>, hideBelow: 'xl' },
              {
                key: 'rotateBy',
                header: 'Rotate by',
                cell: (i) => {
                  const r = rotationState(i);
                  if (r.state === 'none') return <span className="text-slate-400">No reminder</span>;
                  return (
                    <span title={formatDateTime(r.dueAt)} className={r.state === 'overdue' ? 'font-medium text-amber-700' : r.state === 'due_soon' ? 'text-sky-700' : 'text-slate-500'}>
                      {r.state === 'overdue' ? `Overdue ${r.days}d` : `In ${r.days}d`}
                    </span>
                  );
                },
                hideBelow: 'lg',
              },
              {
                key: 'actions',
                header: '',
                cell: (i) =>
                  can(PERMISSIONS.INTEGRATION_MANAGE) && (
                    <Button size="sm" variant="outline" loading={testing === i.id} onClick={() => test(i)}>
                      <RefreshCw className="h-3.5 w-3.5" /> Test
                    </Button>
                  ),
              },
            ]}
          />
        </Card>
      )}
    </div>
  );
}
