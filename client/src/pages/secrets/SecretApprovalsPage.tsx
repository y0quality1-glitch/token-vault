import { useEffect, useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { Check, Hand, RefreshCw, X } from 'lucide-react';
import { PERMISSIONS, type SecretApprovalStatus, type SecretRetrievalApprovalView } from '@token-vault/shared';
import { useMutation, usePost } from '@/hooks/useApi';
import { useAuth } from '@/context/AuthContext';
import { api } from '@/lib/api';
import { formatDateTime, relativeTime } from '@/lib/utils';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card } from '@/components/ui/card';
import { Field, Textarea } from '@/components/ui/form';
import { Callout, EmptyState, ErrorState } from '@/components/ui/feedback';
import { Dialog } from '@/components/ui/dialog';
import { DataTable, FilterTabs } from '@/components/ui/table';
import { PageHeader } from '@/components/ui/navigation';
import { useToast } from '@/components/ui/toast';
import { SecretsSectionTabs, decisionErrorTitle } from './secretAccess';
import { ApprovalOperation, keyOperationLabel } from './secretKeys';

type Filter = SecretApprovalStatus | 'all';
const STATUS: Record<SecretApprovalStatus, { label: string; tone: 'amber' | 'green' | 'red' | 'gray' | 'blue' }> = {
  PENDING: { label: 'Waiting', tone: 'amber' },
  APPROVED: { label: 'Approved', tone: 'green' },
  USED: { label: 'Used', tone: 'blue' },
  REJECTED: { label: 'Rejected', tone: 'red' },
  EXPIRED: { label: 'Expired', tone: 'gray' },
};

function ApprovalStatusBadge({ status }: { status: SecretApprovalStatus }) {
  const s = STATUS[status] ?? { label: status, tone: 'gray' as const };
  return (
    <span data-testid="secret-approval-status" data-status={status}>
      <Badge tone={s.tone} dot>
        {s.label}
      </Badge>
    </span>
  );
}

/**
 * Retrievals held by grants that require approval (spec 4.9.9). Approving lets the agent repeat that
 * exact retrieval once, within 15 minutes; the agent's owner cannot decide (separation of duties).
 */
export function SecretApprovalsPage() {
  const { can } = useAuth();
  const { data, error, loading, reload } = usePost<{ items: SecretRetrievalApprovalView[] }>('/secretAccess/getApprovals');
  const [filter, setFilter] = useState<Filter>('all');
  const [deciding, setDeciding] = useState<{ approval: SecretRetrievalApprovalView; outcome: 'approve' | 'reject' } | null>(null);
  const manage = can(PERMISSIONS.SECRET_MANAGE_ACCESS);

  // Pending requests lapse after 15 minutes: keep the list current.
  useEffect(() => {
    const t = setInterval(() => void reload(), 30_000);
    return () => clearInterval(t);
  }, [reload]);

  const items = useMemo(() => [...(data?.items ?? [])].sort((a, b) => Number(b.status === 'PENDING') - Number(a.status === 'PENDING') || Date.parse(b.requestedAt) - Date.parse(a.requestedAt)), [data]);
  const count = (s: SecretApprovalStatus) => items.filter((r) => r.status === s).length;
  const rows = filter === 'all' ? items : items.filter((r) => r.status === filter);

  return (
    <div>
      <PageHeader
        title="Secret retrievals"
        description="Retrievals held by a grant that requires approval. Approving lets the agent repeat exactly that retrieval once, within 15 minutes. The agent's owner cannot decide its requests."
        breadcrumbs={[{ label: 'Secrets', to: '/secrets' }, { label: 'Retrieval approvals' }]}
        actions={
          <Button variant="outline" onClick={() => void reload()} loading={loading && !!data}>
            <RefreshCw className="h-4 w-4" /> Refresh
          </Button>
        }
      />
      <SecretsSectionTabs current="/secrets/approvals" />
      <div className="mb-4">
        <FilterTabs
          value={filter}
          onChange={setFilter}
          options={[
            { value: 'all', label: 'All', count: items.length },
            { value: 'PENDING', label: 'Waiting', count: count('PENDING') },
            { value: 'APPROVED', label: 'Approved', count: count('APPROVED') },
            { value: 'USED', label: 'Used', count: count('USED') },
            { value: 'REJECTED', label: 'Rejected', count: count('REJECTED') },
            { value: 'EXPIRED', label: 'Expired', count: count('EXPIRED') },
          ]}
        />
      </div>
      {!manage && count('PENDING') > 0 && (
        <Callout tone="info" className="mb-4">
          Only members with secret:manage_access can approve or reject retrievals.
        </Callout>
      )}
      {error ? (
        <ErrorState error={error} onRetry={reload} />
      ) : (
        <Card data-testid="secret-approvals">
          <DataTable
            rows={rows}
            loading={loading && !data}
            rowKey={(r) => r.id}
            empty={
              <EmptyState
                icon={<Hand className="h-5 w-5" />}
                title={filter === 'PENDING' ? 'Nothing is waiting for approval' : 'No held retrievals here'}
                description={
                  <>
                    Retrievals appear here when an agent asks for a secret through a grant with <strong>Require approval</strong>. Manage grants under{' '}
                    <Link className="text-brand-700 hover:underline" to="/secrets/access">
                      Access grants
                    </Link>
                    .
                  </>
                }
              />
            }
            columns={[
              {
                key: 'agent',
                header: 'Agent',
                cell: (r) => (
                  <div className="min-w-0" data-testid="secret-approval-row" data-approval-id={r.id} data-status={r.status}>
                    <Link className="font-medium text-brand-700 hover:underline" to={`/agents/${r.agent.id}`}>
                      {r.agent.name}
                    </Link>
                  </div>
                ),
              },
              {
                key: 'secret',
                header: 'Secret',
                cell: (r) => (
                  <span>
                    <Link className="text-brand-700 hover:underline" to={`/secrets/${r.secret.id}`}>
                      {r.secret.name}
                    </Link>
                    <span className="ml-1.5 text-xs text-slate-500">{r.version ? `v${r.version}` : 'active version'}</span>
                  </span>
                ),
              },
              { key: 'operation', header: 'Asks to', cell: (r) => <ApprovalOperation approval={r} /> },
              {
                key: 'fields',
                header: 'Fields',
                cell: (r) =>
                  r.operation !== 'retrieve' && r.operation !== 'lease' ? (
                    <span className="text-slate-400">—</span>
                  ) : r.fields.length ? (
                    <div className="flex max-w-[12rem] flex-wrap gap-1">
                      {r.fields.map((f) => (
                        <Badge key={f}>{f}</Badge>
                      ))}
                    </div>
                  ) : (
                    <span className="text-slate-500">All allowed</span>
                  ),
                hideBelow: 'lg',
              },
              { key: 'reason', header: 'Reason (from the agent)', cell: (r) => <span className="block max-w-xs break-words text-slate-600">{r.reason || '—'}</span>, hideBelow: 'md' },
              {
                key: 'when',
                header: 'Requested / expires',
                cell: (r) => (
                  <span className="whitespace-nowrap text-xs text-slate-500">
                    <span className="block" title={formatDateTime(r.requestedAt)}>
                      {relativeTime(r.requestedAt)}
                    </span>
                    {(r.status === 'PENDING' || r.status === 'APPROVED') && (
                      <span className="block" title={formatDateTime(r.expiresAt)}>
                        lapses {relativeTime(r.expiresAt)}
                      </span>
                    )}
                  </span>
                ),
                hideBelow: 'md',
              },
              {
                key: 'status',
                header: 'Status',
                cell: (r) => (
                  <div>
                    <ApprovalStatusBadge status={r.status} />
                    {r.decidedBy && (
                      <span className="mt-0.5 block text-xs text-slate-500" title={r.note || undefined}>
                        by {r.decidedBy.name}
                        {r.decidedAt ? ` ${relativeTime(r.decidedAt)}` : ''}
                      </span>
                    )}
                    {r.note && <span className="block max-w-[14rem] truncate text-xs italic text-slate-500">“{r.note}”</span>}
                  </div>
                ),
              },
              {
                key: 'actions',
                header: '',
                className: 'text-right',
                cell: (r) =>
                  manage && r.status === 'PENDING' ? (
                    <div className="flex justify-end gap-1">
                      <Button size="sm" onClick={() => setDeciding({ approval: r, outcome: 'approve' })} data-testid="secret-approval-approve">
                        <Check className="h-3.5 w-3.5" /> Approve
                      </Button>
                      <Button size="sm" variant="danger-outline" onClick={() => setDeciding({ approval: r, outcome: 'reject' })} data-testid="secret-approval-reject">
                        <X className="h-3.5 w-3.5" /> Reject
                      </Button>
                    </div>
                  ) : null,
              },
            ]}
          />
        </Card>
      )}
      {deciding && (
        <DecisionDialog
          key={`${deciding.approval.id}-${deciding.outcome}`}
          approval={deciding.approval}
          outcome={deciding.outcome}
          onClose={() => setDeciding(null)}
          onDone={async () => {
            setDeciding(null);
            await reload();
          }}
          onStale={reload}
        />
      )}
    </div>
  );
}

function DecisionDialog({ approval: r, outcome, onClose, onDone, onStale }: { approval: SecretRetrievalApprovalView; outcome: 'approve' | 'reject'; onClose: () => void; onDone: () => Promise<void>; onStale: () => Promise<void> }) {
  const toast = useToast();
  const [note, setNote] = useState('');
  const save = useMutation((n: string) => api.post<SecretRetrievalApprovalView>(`/secretAccess/${outcome}`, { id: r.id, ...(n.trim() ? { note: n.trim() } : {}) }));
  const approving = outcome === 'approve';
  // Retrievals and leases keep their wording; key operations are "requests".
  const retrieval = r.operation === 'retrieve' || r.operation === 'lease' || !r.operation;
  const what = r.operation === 'lease' ? `get a lease from ${r.secret.name}` : retrieval ? `retrieve ${r.secret.name}${r.version ? ` v${r.version}` : ''}${r.fields.length ? ` (${r.fields.join(', ')})` : ''}` : `${keyOperationLabel(r.operation).toLowerCase()} with ${r.secret.name}${r.version ? ` v${r.version}` : ''}, for exactly this input`;

  async function submit() {
    const res = await save.run(note);
    if (res) {
      toast.success(approving ? (retrieval ? 'Retrieval approved' : 'Request approved') : retrieval ? 'Retrieval rejected' : 'Request rejected', approving ? `${r.agent.name} can ${what} once within 15 minutes.` : undefined);
      await onDone();
    } else {
      // The request may have expired or been decided meanwhile: refresh the list behind the dialog.
      void onStale();
    }
  }

  return (
    <Dialog
      open
      onClose={onClose}
      size="sm"
      title={retrieval ? (approving ? 'Approve this retrieval' : 'Reject this retrieval') : approving ? 'Approve this request' : 'Reject this request'}
      description={approving ? `${r.agent.name} may then ${what} once, within 15 minutes. Every other check runs again at that moment.` : `${r.agent.name} is refused and sees your note.`}
      footer={
        <>
          <Button variant="outline" onClick={onClose}>
            Cancel
          </Button>
          <Button variant={approving ? 'primary' : 'danger'} loading={save.pending} onClick={submit} data-testid="secret-approval-confirm">
            {retrieval ? (approving ? 'Approve retrieval' : 'Reject retrieval') : approving ? 'Approve' : 'Reject'}
          </Button>
        </>
      }
    >
      <div className="space-y-3" data-testid="secret-approval-dialog">
        {!retrieval && <ApprovalOperation approval={r} />}
        {r.reason && (
          <div className="rounded-md border border-amber-200 bg-amber-50/60 p-2.5 text-sm text-slate-700">
            <p className="text-xs font-semibold uppercase tracking-wide text-amber-800">Reason given by the agent</p>
            <p className="mt-1 break-words">{r.reason}</p>
            <p className="mt-1 text-xs text-amber-800">Agent-supplied text may be inaccurate or manipulative.</p>
          </div>
        )}
        {save.error && (
          <div data-testid="secret-error" data-code={save.error.code}>
            <Callout tone="danger" title={decisionErrorTitle(save.error)}>
              {save.error.message}
              {save.error.code && !save.error.code.startsWith('HTTP_') && <span className="ml-1.5 font-mono text-[11px] opacity-70">({save.error.code})</span>}
            </Callout>
          </div>
        )}
        <Field label={approving ? 'Note (recorded in the audit log)' : 'Note to the agent (optional)'} htmlFor="secret-approval-note">
          <Textarea id="secret-approval-note" rows={3} maxLength={300} value={note} onChange={(e) => setNote(e.target.value)} data-testid="secret-approval-note" />
        </Field>
      </div>
    </Dialog>
  );
}
