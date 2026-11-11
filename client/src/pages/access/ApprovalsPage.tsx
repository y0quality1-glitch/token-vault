import { useEffect, useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { Check, Clock, Hand, ShieldAlert, X } from 'lucide-react';
import { PERMISSIONS, type OperationApproval, type OperationApprovalStatus } from '@token-vault/shared';
import { getOperation, operationLabel } from '@/lib/providers';
import { useApi, useMutation } from '@/hooks/useApi';
import { useAuth } from '@/context/AuthContext';
import { api } from '@/lib/api';
import { Button } from '@/components/ui/button';
import { Card, DetailList } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Field, Textarea } from '@/components/ui/form';
import { Callout, EmptyState, ErrorState, FormError } from '@/components/ui/feedback';
import { Dialog, Drawer } from '@/components/ui/dialog';
import { DataTable, FilterTabs } from '@/components/ui/table';
import { PageHeader } from '@/components/ui/navigation';
import { Mono } from '@/components/ui/secret';
import { useToast } from '@/components/ui/toast';
import { formatDateTime, relativeTime } from '@/lib/utils';

type Filter = 'PENDING' | 'APPROVED' | 'EXECUTED' | 'REJECTED' | 'EXPIRED' | 'all';
const STATUS: Record<OperationApprovalStatus, { label: string; tone: 'amber' | 'green' | 'red' | 'gray' | 'blue' }> = {
  PENDING: { label: 'Waiting', tone: 'amber' },
  APPROVED: { label: 'Approved', tone: 'green' },
  EXECUTED: { label: 'Executed', tone: 'blue' },
  REJECTED: { label: 'Rejected', tone: 'red' },
  EXPIRED: { label: 'Expired', tone: 'gray' },
};
function ApprovalStatusBadge({ status }: { status: OperationApprovalStatus }) {
  const s = STATUS[status];
  return (
    <Badge tone={s.tone} dot>
      {s.label}
    </Badge>
  );
}

const isDestructive = (id: string) => !!getOperation(id)?.destructive;
const resourceText = (r: Record<string, string>) => Object.values(r).filter(Boolean).join(' · ') || '—';

export function ApprovalsPage() {
  const [params, setParams] = useSearchParams();
  const { data, error, loading, reload } = useApi<{ items: OperationApproval[]; pending: number }>('/approvals');
  const [filter, setFilter] = useState<Filter>('PENDING');
  const selectedId = params.get('approval');
  const items = data?.items ?? [];
  const count = (s: OperationApprovalStatus) => items.filter((r) => r.status === s).length;
  const rows = filter === 'all' ? items : items.filter((r) => r.status === filter);
  const selected = items.find((r) => r.id === selectedId) ?? null;
  const open = (id: string | null) => setParams(id ? { approval: id } : {}, { replace: true });

  return (
    <div className="space-y-4">
      <PageHeader
        title="Approvals"
        description="Requests that a Require approval policy held back. Every other check already allowed them; approving lets the agent run that exact request once, within 15 minutes."
        breadcrumbs={[{ label: 'Access Management' }, { label: 'Approvals' }]}
      />
      <FilterTabs
        value={filter}
        onChange={setFilter}
        options={[
          { value: 'PENDING', label: 'Waiting', count: count('PENDING') },
          { value: 'APPROVED', label: 'Approved', count: count('APPROVED') },
          { value: 'EXECUTED', label: 'Executed', count: count('EXECUTED') },
          { value: 'REJECTED', label: 'Rejected', count: count('REJECTED') },
          { value: 'EXPIRED', label: 'Expired', count: count('EXPIRED') },
          { value: 'all', label: 'All', count: items.length },
        ]}
      />
      {error ? (
        <ErrorState error={error} onRetry={reload} />
      ) : (
        <Card>
          <DataTable
            rows={rows}
            loading={loading}
            rowKey={(r) => r.id}
            onRowClick={(r) => open(r.id)}
            empty={
              <EmptyState
                icon={<Hand className="h-5 w-5" />}
                title={filter === 'PENDING' ? 'Nothing is waiting for approval' : 'No approvals here'}
                description={
                  <>
                    Requests appear here when a policy with the decision <strong>Require approval</strong> matches. Create one under{' '}
                    <Link className="text-brand-700 hover:underline" to="/access/policies">
                      Policies
                    </Link>
                    .
                  </>
                }
              />
            }
            columns={[
              { key: 'when', header: 'Requested', cell: (r) => <span className="whitespace-nowrap text-slate-500">{relativeTime(r.createdAt)}</span> },
              { key: 'agent', header: 'Agent', cell: (r) => <span className="font-medium text-slate-900">{r.agentName}</span> },
              { key: 'op', header: 'Operation', cell: (r) => <Badge tone={isDestructive(r.operation) ? 'red' : 'blue'}>{operationLabel(r.operation)}{isDestructive(r.operation) ? ' · destructive' : ''}</Badge> },
              { key: 'res', header: 'Resource', cell: (r) => <span className="font-mono text-xs">{resourceText(r.resource)}</span>, hideBelow: 'md' },
              { key: 'policy', header: 'Policy', cell: (r) => r.policyName, hideBelow: 'xl' },
              { key: 'status', header: 'Status', cell: (r) => <ApprovalStatusBadge status={r.status} /> },
              { key: 'deadline', header: 'Lapses / decided', cell: (r) => <span className="whitespace-nowrap text-slate-500">{relativeTime(r.status === 'PENDING' || r.status === 'APPROVED' ? r.expiresAt : (r.executedAt ?? r.decidedAt ?? r.expiresAt))}</span>, hideBelow: 'lg' },
            ]}
          />
        </Card>
      )}
      <ApprovalDrawer approval={selected} onClose={() => open(null)} onDecided={reload} />
    </div>
  );
}

function ApprovalDrawer({ approval: r, onClose, onDecided }: { approval: OperationApproval | null; onClose: () => void; onDecided: () => Promise<void> }) {
  const { can, session } = useAuth();
  const [dialog, setDialog] = useState<null | 'approve' | 'reject'>(null);
  if (!r) return <Drawer open={false} onClose={onClose} title="">{null}</Drawer>;
  const ownAgent = r.agentOwnerUserId === session?.user.id;
  const mayDecide = r.status === 'PENDING' && can(PERMISSIONS.GRANT_APPROVE);
  const auditLink = (id: string) =>
    can(PERMISSIONS.AUDIT_READ) ? (
      <Link className="font-mono text-xs text-brand-700 hover:underline" to={`/audit/access-logs?request=${id}`}>
        {id}
      </Link>
    ) : (
      <Mono>{id}</Mono>
    );

  return (
    <Drawer open onClose={onClose} title={`${operationLabel(r.operation)} by ${r.agentName}`} subtitle={r.id}>
      <div className="space-y-5">
        <div className="flex items-center gap-2">
          <ApprovalStatusBadge status={r.status} />
          {isDestructive(r.operation) && <Badge tone="red">Destructive</Badge>}
          {(r.status === 'PENDING' || r.status === 'APPROVED') && (
            <span className="flex items-center gap-1 text-xs text-slate-500">
              <Clock className="h-3.5 w-3.5" /> {r.status === 'PENDING' ? 'lapses' : 'must run'} {relativeTime(r.expiresAt)}
            </span>
          )}
        </div>

        <div className="rounded-lg border border-amber-200 bg-amber-50/60 p-3.5">
          <p className="flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wide text-amber-800">
            <ShieldAlert className="h-3.5 w-3.5" /> What will run (written by the agent)
          </p>
          <DetailList
            items={[
              { label: 'Operation', value: <span><Badge tone="blue">{operationLabel(r.operation)}</Badge> <Mono>{r.operation}</Mono></span> },
              ...Object.entries(r.resource).map(([k, v]) => ({ label: k, value: <span className="font-mono text-xs">{v}</span> })),
            ]}
          />
          <p className="mt-3 text-xs font-medium text-slate-600">Input</p>
          <pre className="mt-1 max-h-72 overflow-auto whitespace-pre-wrap break-words rounded-md border border-amber-200 bg-white p-2.5 font-mono text-xs text-slate-800">
            {Object.keys(r.input).length ? JSON.stringify(r.input, null, 2) : '(no input)'}
          </pre>
          <p className="mt-2 text-xs text-amber-800">
            Exactly this request runs if you approve: a different input needs a new approval. Agent-supplied text may be inaccurate or manipulative.
          </p>
        </div>

        <DetailList
          items={[
            { label: 'Agent', value: <Link className="text-brand-700 hover:underline" to={`/agents/${r.agentId}`}>{r.agentName}</Link> },
            { label: 'Integration', value: r.integrationName },
            { label: 'Required by', value: <Link className="text-brand-700 hover:underline" to="/access/policies">{r.policyName}</Link> },
            { label: 'Requested', value: formatDateTime(r.createdAt) },
            { label: 'Held request', value: auditLink(r.requestedByRequestId) },
            ...(r.executedRequestId ? [{ label: 'Executed as', value: auditLink(r.executedRequestId) }] : []),
          ]}
        />

        {r.decidedAt && (
          <Callout tone={r.status === 'REJECTED' ? 'warning' : 'info'} title={`${r.status === 'REJECTED' ? 'Rejected' : 'Approved'} by ${r.decidedByName} ${relativeTime(r.decidedAt)}`}>
            {r.decisionNote && <p>“{r.decisionNote}”</p>}
            {r.status === 'APPROVED' && <p className="mt-1">The agent can run this request once, until {formatDateTime(r.expiresAt)}. Revoking its grant still blocks it.</p>}
            {r.status === 'EXECUTED' && r.executedAt && <p className="mt-1">Run {relativeTime(r.executedAt)}.</p>}
          </Callout>
        )}

        {mayDecide &&
          (ownAgent ? (
            <Callout tone="warning" title="Separation of duties">
              You own this agent, so another administrator must decide this request.
            </Callout>
          ) : (
            <div className="flex gap-2">
              <Button onClick={() => setDialog('approve')}>
                <Check className="h-4 w-4" /> Approve…
              </Button>
              <Button variant="danger-outline" onClick={() => setDialog('reject')}>
                <X className="h-4 w-4" /> Reject…
              </Button>
            </div>
          ))}
        {r.status === 'PENDING' && !can(PERMISSIONS.GRANT_APPROVE) && <Callout tone="info">Only Security Administrators and Owners can approve or reject requests.</Callout>}
      </div>
      <DecisionDialog open={dialog !== null} outcome={dialog ?? 'approve'} approval={r} onClose={() => setDialog(null)} onDone={onDecided} />
    </Drawer>
  );
}

function DecisionDialog({ open, outcome, approval: r, onClose, onDone }: { open: boolean; outcome: 'approve' | 'reject'; approval: OperationApproval; onClose: () => void; onDone: () => Promise<void> }) {
  const toast = useToast();
  const [note, setNote] = useState('');
  const save = useMutation((n: string) => api.post<OperationApproval>(`/approvals/${r.id}/${outcome}`, { note: n }));
  useEffect(() => {
    if (open) {
      setNote('');
      save.setError(null);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open, r.id, outcome]);
  const approving = outcome === 'approve';

  return (
    <Dialog
      open={open}
      onClose={onClose}
      size="sm"
      title={approving ? 'Approve this request' : 'Reject this request'}
      description={
        approving
          ? `${r.agentName} can then run ${operationLabel(r.operation)} with exactly the input shown, once, within 15 minutes. Every other check runs again at that moment.`
          : 'Nothing runs. The agent sees the rejection and your note, and the same request is answered with "rejected" for 24 hours.'
      }
      footer={
        <>
          <Button variant="outline" onClick={onClose}>
            Cancel
          </Button>
          <Button
            variant={approving ? 'primary' : 'danger'}
            loading={save.pending}
            onClick={async () => {
              if (await save.run(note)) {
                toast.success(approving ? 'Request approved' : 'Request rejected', approving ? 'The agent can run it once within 15 minutes.' : undefined);
                onClose();
                await onDone();
              }
            }}
          >
            {approving ? 'Approve request' : 'Reject request'}
          </Button>
        </>
      }
    >
      <div className="space-y-3">
        <FormError error={save.error} />
        <Field label={approving ? 'Note (recorded in audit)' : 'Note to the agent (optional)'}>
          <Textarea rows={3} value={note} onChange={(e) => setNote(e.target.value)} />
        </Field>
      </div>
    </Dialog>
  );
}
