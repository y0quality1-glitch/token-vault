import { useEffect, useMemo, useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { Check, Clock, Inbox, Quote, X } from 'lucide-react';
import { PERMISSIONS, type GrantRequest, type GrantRequestStatus } from '@token-vault/shared';
import { operationLabel } from '@/lib/providers';
import { useApi, useMutation } from '@/hooks/useApi';
import { useAuth } from '@/context/AuthContext';
import { api } from '@/lib/api';
import { Button } from '@/components/ui/button';
import { Card, DetailList } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Checkbox, Field, Input, Select, Textarea } from '@/components/ui/form';
import { Callout, EmptyState, ErrorState, FormError } from '@/components/ui/feedback';
import { Dialog, Drawer } from '@/components/ui/dialog';
import { DataTable, FilterTabs } from '@/components/ui/table';
import { PageHeader } from '@/components/ui/navigation';
import { Mono } from '@/components/ui/secret';
import { useToast } from '@/components/ui/toast';
import { formatDateTime, relativeTime, splitList } from '@/lib/utils';

type Filter = 'PENDING' | 'APPROVED' | 'REJECTED' | 'EXPIRED' | 'all';
const DURATIONS = [15, 30, 60, 120, 240, 480, 1440];
const REQUEST_STATUS: Record<GrantRequestStatus, { label: string; tone: 'amber' | 'green' | 'red' | 'gray' }> = {
  PENDING: { label: 'Pending', tone: 'amber' },
  APPROVED: { label: 'Approved', tone: 'green' },
  REJECTED: { label: 'Rejected', tone: 'red' },
  EXPIRED: { label: 'Expired', tone: 'gray' },
};
function RequestStatusBadge({ status }: { status: GrantRequestStatus }) {
  const s = REQUEST_STATUS[status];
  return (
    <Badge tone={s.tone} dot>
      {s.label}
    </Badge>
  );
}

const minutes = (m: number) => (m >= 60 ? `${m / 60} h` : `${m} min`);

export function AccessRequestsPage() {
  const [params, setParams] = useSearchParams();
  const { data, error, loading, reload } = useApi<{ items: GrantRequest[]; pending: number }>('/grant-requests');
  const [filter, setFilter] = useState<Filter>('PENDING');
  const selectedId = params.get('request');
  const items = data?.items ?? [];
  const count = (s: GrantRequestStatus) => items.filter((r) => r.status === s).length;
  const rows = filter === 'all' ? items : items.filter((r) => r.status === filter);
  const selected = items.find((r) => r.id === selectedId) ?? null;
  const open = (id: string | null) => setParams(id ? { request: id } : {}, { replace: true });

  return (
    <div className="space-y-4">
      <PageHeader
        title="Access Requests"
        description="Agents that were denied can ask for time-limited access. Approving creates an expiring grant; every step is audited."
        breadcrumbs={[{ label: 'Access Management' }, { label: 'Access Requests' }]}
      />
      <FilterTabs
        value={filter}
        onChange={setFilter}
        options={[
          { value: 'PENDING', label: 'Pending', count: count('PENDING') },
          { value: 'APPROVED', label: 'Approved', count: count('APPROVED') },
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
            empty={<EmptyState icon={<Inbox className="h-5 w-5" />} title={filter === 'PENDING' ? 'No requests awaiting a decision' : 'No requests here'} description="Agents submit requests through the agent API, the SDK or the MCP tool token_vault_request_access." />}
            columns={[
              { key: 'when', header: 'Requested', cell: (r) => <span className="whitespace-nowrap text-slate-500">{relativeTime(r.createdAt)}</span> },
              { key: 'agent', header: 'Agent', cell: (r) => <span className="font-medium text-slate-900">{r.agentName}</span> },
              { key: 'int', header: 'Integration', cell: (r) => r.integrationName, hideBelow: 'lg' },
              { key: 'ops', header: 'Operations', cell: (r) => <div className="flex max-w-xs flex-wrap gap-1">{r.operations.map((o) => <Badge key={o} tone="blue">{operationLabel(o)}</Badge>)}</div> },
              { key: 'repos', header: 'Repository', cell: (r) => <span className="font-mono text-xs">{r.repositories.length ? r.repositories.join(', ') : 'any'}</span>, hideBelow: 'md' },
              { key: 'dur', header: 'Duration', cell: (r) => minutes(r.approvedDurationMinutes ?? r.requestedDurationMinutes), hideBelow: 'xl' },
              { key: 'status', header: 'Status', cell: (r) => <RequestStatusBadge status={r.status} /> },
              { key: 'deadline', header: 'Lapses / decided', cell: (r) => <span className="whitespace-nowrap text-slate-500">{r.status === 'PENDING' ? relativeTime(r.expiresAt) : relativeTime(r.decidedAt ?? r.expiresAt)}</span>, hideBelow: 'lg' },
            ]}
          />
        </Card>
      )}
      <RequestDrawer request={selected} onClose={() => open(null)} onDecided={reload} />
    </div>
  );
}

function RequestDrawer({ request: r, onClose, onDecided }: { request: GrantRequest | null; onClose: () => void; onDecided: () => Promise<void> }) {
  const { can, session } = useAuth();
  const [dialog, setDialog] = useState<null | 'approve' | 'reject'>(null);
  if (!r) return <Drawer open={false} onClose={onClose} title="">{null}</Drawer>;
  const ownAgent = r.agentOwnerUserId === session?.user.id;
  const mayDecide = r.status === 'PENDING' && can(PERMISSIONS.GRANT_APPROVE);

  return (
    <Drawer open onClose={onClose} title={`Access request from ${r.agentName}`} subtitle={r.id}>
      <div className="space-y-5">
        <div className="flex items-center gap-2">
          <RequestStatusBadge status={r.status} />
          {r.status === 'PENDING' && (
            <span className="flex items-center gap-1 text-xs text-slate-500">
              <Clock className="h-3.5 w-3.5" /> lapses {relativeTime(r.expiresAt)}
            </span>
          )}
        </div>

        <div className="rounded-lg border border-amber-200 bg-amber-50/60 p-3.5">
          <p className="flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wide text-amber-800">
            <Quote className="h-3.5 w-3.5" /> Justification (written by the agent)
          </p>
          <p className="mt-1.5 whitespace-pre-wrap break-words text-sm text-slate-800">{r.justification}</p>
          <p className="mt-2 text-xs text-amber-800">Agent-supplied text may be inaccurate or manipulative. Verify it against the agent's purpose before approving.</p>
        </div>

        <DetailList
          items={[
            { label: 'Agent', value: <Link className="text-brand-700 hover:underline" to={`/agents/${r.agentId}`}>{r.agentName}</Link> },
            { label: 'Integration', value: r.integrationName },
            { label: 'Operations', value: <div className="flex flex-wrap gap-1">{r.operations.map((o) => <Badge key={o} tone="blue">{operationLabel(o)}</Badge>)}</div> },
            { label: 'Repositories', value: r.repositories.length ? r.repositories.join(', ') : 'Any the integration allows' },
            { label: 'Requested duration', value: minutes(r.requestedDurationMinutes) },
            { label: 'Requested', value: formatDateTime(r.createdAt) },
            {
              label: 'Prompted by',
              value: r.deniedRequestId ? (
                can(PERMISSIONS.AUDIT_READ) ? (
                  <Link className="font-mono text-xs text-brand-700 hover:underline" to={`/audit/access-logs?request=${r.deniedRequestId}`}>{r.deniedRequestId}</Link>
                ) : (
                  <Mono>{r.deniedRequestId}</Mono>
                )
              ) : (
                '—'
              ),
            },
          ]}
        />

        {r.status !== 'PENDING' && r.decidedAt && (
          <Callout tone={r.status === 'APPROVED' ? 'info' : 'warning'} title={`${r.status === 'APPROVED' ? 'Approved' : 'Rejected'} by ${r.decidedByName} ${relativeTime(r.decidedAt)}`}>
            {r.decisionNote && <p>“{r.decisionNote}”</p>}
            {r.grantId && (
              <p className="mt-1">
                Granted for {minutes(r.approvedDurationMinutes ?? 0)}: <Link className="underline" to={`/access/grants/${r.grantId}`}>view grant</Link>
              </p>
            )}
          </Callout>
        )}

        {mayDecide &&
          (ownAgent ? (
            <Callout tone="warning" title="Separation of duties">You own this agent, so another administrator must decide this request.</Callout>
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
        {r.status === 'PENDING' && !can(PERMISSIONS.GRANT_APPROVE) && <Callout tone="info">Only Security Administrators and Owners can approve or reject access requests.</Callout>}
      </div>
      <ApproveDialog open={dialog === 'approve'} request={r} onClose={() => setDialog(null)} onDone={onDecided} />
      <RejectDialog open={dialog === 'reject'} request={r} onClose={() => setDialog(null)} onDone={onDecided} />
    </Drawer>
  );
}

function ApproveDialog({ open, request: r, onClose, onDone }: { open: boolean; request: GrantRequest; onClose: () => void; onDone: () => Promise<void> }) {
  const toast = useToast();
  const [duration, setDuration] = useState(r.requestedDurationMinutes);
  const [ops, setOps] = useState<string[]>(r.operations);
  const [repos, setRepos] = useState<string[]>(r.repositories);
  const [restrict, setRestrict] = useState('');
  const [rate, setRate] = useState('10');
  const [note, setNote] = useState('');
  const save = useMutation((body: unknown) => api.post<GrantRequest>(`/grant-requests/${r.id}/approve`, body));
  useEffect(() => {
    if (open) {
      setDuration(r.requestedDurationMinutes);
      setOps(r.operations);
      setRepos(r.repositories);
      setRestrict('');
      setRate('10');
      setNote('');
      save.setError(null);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open, r.id]);
  const durations = useMemo(() => [...new Set([...DURATIONS, r.requestedDurationMinutes])].sort((a, b) => a - b), [r.requestedDurationMinutes]);
  const fe = save.fieldErrors;
  const narrowed = ops.length < r.operations.length || (r.repositories.length > 0 && repos.length < r.repositories.length) || duration < r.requestedDurationMinutes || (!r.repositories.length && !!restrict.trim());

  return (
    <Dialog
      open={open}
      onClose={onClose}
      title="Approve access request"
      description={`Creates an expiring grant for ${r.agentName} on ${r.integrationName}. You can narrow the request, but not widen it.`}
      footer={
        <>
          <Button variant="outline" onClick={onClose}>
            Cancel
          </Button>
          <Button
            loading={save.pending}
            disabled={ops.length === 0 || (r.repositories.length > 0 && repos.length === 0)}
            onClick={async () => {
              const result = await save.run({
                durationMinutes: duration,
                operations: ops,
                repositories: r.repositories.length ? repos : splitList(restrict),
                rateLimitPerMinute: Number(rate),
                note,
              });
              if (result) {
                toast.success('Access approved', `Grant active for ${minutes(duration)}; the agent's next request is authorized.`);
                onClose();
                await onDone();
              }
            }}
          >
            Approve{narrowed ? ' narrowed access' : ''} for {minutes(duration)}
          </Button>
        </>
      }
    >
      <div className="space-y-4">
        <FormError error={save.error} />
        <div>
          <p className="mb-2 text-sm font-medium text-slate-700">Operations</p>
          {fe.operations && <p className="mb-1 text-xs text-red-600">{fe.operations}</p>}
          <div className="space-y-2">
            {r.operations.map((o) => (
              <Checkbox key={o} checked={ops.includes(o)} onChange={(v) => setOps(v ? [...ops, o] : ops.filter((x) => x !== o))} label={operationLabel(o)} description={<span className="font-mono">{o}</span>} />
            ))}
          </div>
        </div>
        {r.repositories.length > 0 ? (
          <div>
            <p className="mb-2 text-sm font-medium text-slate-700">Repositories</p>
            {fe.repositories && <p className="mb-1 text-xs text-red-600">{fe.repositories}</p>}
            <div className="space-y-2">
              {r.repositories.map((x) => (
                <Checkbox key={x} checked={repos.includes(x)} onChange={(v) => setRepos(v ? [...repos, x] : repos.filter((y) => y !== x))} label={<span className="font-mono text-xs">{x}</span>} />
              ))}
            </div>
          </div>
        ) : (
          <Field label="Restrict to repositories (recommended)" error={fe.repositories} hint="The agent asked for any repository. Comma-separated owner/repository; leave empty to allow any the integration allows.">
            <Input className="font-mono text-xs" value={restrict} onChange={(e) => setRestrict(e.target.value)} placeholder="demo-org/demo-repo" />
          </Field>
        )}
        <div className="grid gap-4 sm:grid-cols-2">
          <Field label="Duration" error={fe.durationMinutes} hint={`Requested: ${minutes(r.requestedDurationMinutes)}`}>
            <Select value={duration} onChange={(e) => setDuration(Number(e.target.value))}>
              {durations.map((d) => (
                <option key={d} value={d}>
                  {minutes(d)}
                </option>
              ))}
            </Select>
          </Field>
          <Field label="Max requests / minute" error={fe.rateLimitPerMinute}>
            <Input type="number" min={1} max={600} value={rate} onChange={(e) => setRate(e.target.value)} />
          </Field>
        </div>
        <Field label="Note (recorded in audit)">
          <Textarea rows={2} value={note} onChange={(e) => setNote(e.target.value)} />
        </Field>
      </div>
    </Dialog>
  );
}

function RejectDialog({ open, request: r, onClose, onDone }: { open: boolean; request: GrantRequest; onClose: () => void; onDone: () => Promise<void> }) {
  const toast = useToast();
  const [note, setNote] = useState('');
  const save = useMutation((n: string) => api.post<GrantRequest>(`/grant-requests/${r.id}/reject`, { note: n }));
  useEffect(() => {
    if (open) setNote('');
  }, [open]);
  return (
    <Dialog
      open={open}
      onClose={onClose}
      size="sm"
      title="Reject access request"
      description="The agent sees the rejection and your note. Requests stay denied."
      footer={
        <>
          <Button variant="outline" onClick={onClose}>
            Cancel
          </Button>
          <Button
            variant="danger"
            loading={save.pending}
            onClick={async () => {
              if (await save.run(note)) {
                toast.success('Request rejected');
                onClose();
                await onDone();
              }
            }}
          >
            Reject request
          </Button>
        </>
      }
    >
      <div className="space-y-3">
        <FormError error={save.error} />
        <Field label="Note to the agent (optional)">
          <Textarea rows={3} value={note} onChange={(e) => setNote(e.target.value)} placeholder="e.g. Use the staging integration instead." />
        </Field>
      </div>
    </Dialog>
  );
}
