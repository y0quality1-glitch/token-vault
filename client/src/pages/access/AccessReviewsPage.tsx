import { useState } from 'react';
import { Link } from 'react-router-dom';
import { CalendarClock, ClipboardCheck, ShieldOff, TimerOff } from 'lucide-react';
import { PERMISSIONS, type AccessReviewItem, type AccessReviewSummary } from '@token-vault/shared';
import { operationLabel } from '@/lib/providers';
import { usePost } from '@/hooks/useApi';
import { useAuth } from '@/context/AuthContext';
import { api } from '@/lib/api';
import { Button } from '@/components/ui/button';
import { Card, StatCard } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Field, Textarea } from '@/components/ui/form';
import { Callout, EmptyState, ErrorState } from '@/components/ui/feedback';
import { ConfirmDialog } from '@/components/ui/dialog';
import { DataTable, FilterTabs } from '@/components/ui/table';
import { PageHeader } from '@/components/ui/navigation';
import { useToast } from '@/components/ui/toast';
import { cn, formatDateTime, relativeTime } from '@/lib/utils';

type Filter = 'due' | 'unused' | 'all';

function ReviewBadges({ i }: { i: AccessReviewItem }) {
  const soon = new Date(i.grant.expiresAt).getTime() - Date.now() <= 3 * 86400e3;
  return (
    <div className="flex flex-wrap gap-1">
      {i.due ? <Badge tone="amber" dot>Review due</Badge> : <Badge tone="green" dot>Reviewed</Badge>}
      {i.uses30d === 0 && <Badge tone="gray">Unused 30 days</Badge>}
      {soon && <Badge tone="blue">Expires {relativeTime(i.grant.expiresAt)}</Badge>}
    </div>
  );
}

export function AccessReviewsPage() {
  const { can } = useAuth();
  const toast = useToast();
  const { data, error, loading, reload, setData } = usePost<AccessReviewSummary>('/accessReview/getdata');
  const [filter, setFilter] = useState<Filter>('due');
  const [selected, setSelected] = useState<string[]>([]);
  const [certifyIds, setCertifyIds] = useState<string[] | null>(null);
  const [revoke, setRevoke] = useState<AccessReviewItem | null>(null);
  const [note, setNote] = useState('');
  const [busy, setBusy] = useState(false);
  const canDecide = can(PERMISSIONS.GRANT_REVOKE);

  const items = data?.items ?? [];
  const rows = filter === 'due' ? items.filter((i) => i.due) : filter === 'unused' ? items.filter((i) => i.uses30d === 0) : items;
  const toggle = (id: string) => setSelected((s) => (s.includes(id) ? s.filter((x) => x !== id) : [...s, id]));

  async function certify(ids: string[]) {
    setBusy(true);
    try {
      const r = await api.post<{ certified: number; summary: AccessReviewSummary }>('/accessReview/certify', { grantIds: ids, note });
      setData(r.summary);
      setSelected([]);
      toast.success(`${r.certified} grant${r.certified > 1 ? 's' : ''} certified`, `Next review due in ${r.summary.intervalDays} days.`);
      setCertifyIds(null);
      setNote('');
    } catch (e) {
      toast.error('Could not certify', (e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  async function doRevoke(i: AccessReviewItem) {
    setBusy(true);
    try {
      await api.post('/grant/revoke', { id: i.grant.id, reason: note || 'Revoked during access review' });
      toast.success('Grant revoked', `${i.grant.agentName} loses access on its next request.`);
      setRevoke(null);
      setNote('');
      await reload();
    } catch (e) {
      toast.error('Could not revoke', (e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="space-y-4">
      <PageHeader
        title="Access Reviews"
        description={`Every active grant must be re-confirmed at least every ${data?.intervalDays ?? 30} days. Keep what is still needed; revoke the rest.`}
        breadcrumbs={[{ label: 'Access Management' }, { label: 'Access Reviews' }]}
        actions={
          canDecide &&
          selected.length > 0 && (
            <Button onClick={() => setCertifyIds(selected)}>
              <ClipboardCheck className="h-4 w-4" /> Keep {selected.length} selected
            </Button>
          )
        }
      />
      <div className="grid gap-4 sm:grid-cols-3">
        <StatCard label="Due for review" value={data?.due ?? '—'} tone={data?.due ? 'warning' : 'success'} icon={<CalendarClock className="h-4 w-4" />} onClick={() => setFilter('due')} />
        <StatCard label="Unused in 30 days" value={data?.unused30d ?? '—'} hint="Strong candidates for revocation" icon={<TimerOff className="h-4 w-4" />} onClick={() => setFilter('unused')} />
        <StatCard label="Expiring within 72 hours" value={data?.expiringSoon ?? '—'} icon={<ShieldOff className="h-4 w-4" />} onClick={() => setFilter('all')} />
      </div>
      {!canDecide && <Callout tone="info">You can see review status. Security Administrators, Vault Administrators and Owners decide reviews.</Callout>}
      <FilterTabs
        value={filter}
        onChange={(f) => {
          setFilter(f);
          setSelected([]);
        }}
        options={[
          { value: 'due', label: 'Due', count: data?.due },
          { value: 'unused', label: 'Unused', count: data?.unused30d },
          { value: 'all', label: 'All active', count: items.length },
        ]}
      />
      {error ? (
        <ErrorState error={error} onRetry={reload} />
      ) : (
        <Card>
          <DataTable
            rows={rows}
            loading={loading}
            rowKey={(i) => i.grant.id}
            empty={<EmptyState icon={<ClipboardCheck className="h-5 w-5" />} title={filter === 'due' ? 'No grants are due for review' : 'Nothing here'} description="Grants become due when they have not been reviewed within the review interval." />}
            columns={[
              ...(canDecide
                ? [
                    {
                      key: 'sel',
                      header: <span className="sr-only">Select</span>,
                      cell: (i: AccessReviewItem) => <input type="checkbox" aria-label={`Select ${i.grant.name}`} className="h-4 w-4 rounded border-slate-300 text-brand-600" checked={selected.includes(i.grant.id)} onChange={() => toggle(i.grant.id)} />,
                    },
                  ]
                : []),
              {
                key: 'grant',
                header: 'Grant',
                cell: (i) => (
                  <div>
                    <Link to={`/access/grants/${i.grant.id}`} className="font-medium text-slate-900 hover:text-brand-700">
                      {i.grant.name}
                    </Link>
                    <p className="text-xs text-slate-500">
                      {i.grant.agentName} → {i.grant.integrationName}
                    </p>
                  </div>
                ),
              },
              { key: 'ops', header: 'Operations', cell: (i) => <div className="flex max-w-xs flex-wrap gap-1">{i.grant.scopes.map((s) => <Badge key={s} tone="blue">{operationLabel(s)}</Badge>)}</div>, hideBelow: 'xl' },
              {
                key: 'reviewed',
                header: 'Last reviewed',
                cell: (i) => <span className={cn('whitespace-nowrap', i.due ? 'text-amber-700' : 'text-slate-500')} title={i.lastReviewedAt ? formatDateTime(i.lastReviewedAt) : undefined}>{i.lastReviewedAt ? `${relativeTime(i.lastReviewedAt)} · ${i.lastReviewedByName}` : 'Never'}</span>,
                hideBelow: 'md',
              },
              { key: 'uses', header: 'Uses (30d)', cell: (i) => <span className={cn('font-medium', i.uses30d === 0 ? 'text-slate-400' : 'text-slate-800')}>{i.uses30d}{i.denied30d > 0 && <span className="ml-1 text-xs font-normal text-red-600">+{i.denied30d} denied</span>}</span> },
              { key: 'status', header: 'Status', cell: (i) => <ReviewBadges i={i} /> },
              {
                key: 'actions',
                header: '',
                cell: (i) =>
                  canDecide && (
                    <div className="flex justify-end gap-2">
                      <Button size="sm" variant="outline" onClick={() => setCertifyIds([i.grant.id])}>
                        Keep
                      </Button>
                      <Button size="sm" variant="danger-outline" onClick={() => setRevoke(i)}>
                        Revoke
                      </Button>
                    </div>
                  ),
              },
            ]}
          />
        </Card>
      )}

      <ConfirmDialog
        open={!!certifyIds}
        onClose={() => setCertifyIds(null)}
        tone="primary"
        title={certifyIds && certifyIds.length > 1 ? `Keep ${certifyIds.length} grants?` : 'Keep this grant?'}
        description={`You confirm the access is still needed. The next review is due in ${data?.intervalDays ?? 30} days. This is recorded in the audit log.`}
        confirmLabel="Keep access"
        loading={busy}
        onConfirm={() => certifyIds && certify(certifyIds)}
      >
        <Field label="Note (optional, recorded in audit)">
          <Textarea rows={2} value={note} onChange={(e) => setNote(e.target.value)} />
        </Field>
      </ConfirmDialog>
      <ConfirmDialog
        open={!!revoke}
        onClose={() => setRevoke(null)}
        title="Revoke this grant?"
        description={revoke ? `${revoke.grant.agentName} loses access to ${revoke.grant.integrationName} on its next request.${revoke.uses30d === 0 ? ' It has not been used in 30 days.' : ''}` : ''}
        confirmLabel="Revoke grant"
        loading={busy}
        onConfirm={() => revoke && doRevoke(revoke)}
      >
        <Field label="Reason (recorded in audit)">
          <Textarea rows={2} value={note} onChange={(e) => setNote(e.target.value)} placeholder="e.g. No longer needed (access review)" />
        </Field>
      </ConfirmDialog>
    </div>
  );
}
