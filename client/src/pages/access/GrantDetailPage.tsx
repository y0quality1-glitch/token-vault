import { DelegationsCard } from '@/components/grant/DelegationsCard';
import { useEffect, useState } from 'react';
import { Link, useNavigate, useParams } from 'react-router-dom';
import { CalendarClock, CheckCircle2, FileClock, History, Pencil, ShieldOff, TimerOff } from 'lucide-react';
import { PERMISSIONS, type GrantDetail, type OnBehalfOfMode } from '@token-vault/shared';
import { operationLabel, useProviders } from '@/lib/providers';
import { useApi, useMutation } from '@/hooks/useApi';
import { useAuth } from '@/context/AuthContext';
import { api } from '@/lib/api';
import { Button } from '@/components/ui/button';
import { Card, CardBody, CardHeader, DetailList, StatCard } from '@/components/ui/card';
import { Badge, DecisionBadge, EnvBadge, StatusBadge } from '@/components/ui/badge';
import { Checkbox, Field, Input, Textarea } from '@/components/ui/form';
import { Callout, EmptyState, ErrorState, FormError, PageSkeleton } from '@/components/ui/feedback';
import { ConfirmDialog, Dialog } from '@/components/ui/dialog';
import { DataTable } from '@/components/ui/table';
import { PageHeader } from '@/components/ui/navigation';
import { Mono } from '@/components/ui/secret';
import { useToast } from '@/components/ui/toast';
import { ActingForFields, actingForText } from '@/components/grant/ActingFor';
import { formatDateTime, fromLocalInput, relativeTime, splitList, toLocalInput } from '@/lib/utils';

export function GrantDetailPage() {
  const { id } = useParams();
  const navigate = useNavigate();
  const toast = useToast();
  const { can } = useAuth();
  const { data: g, error, loading, reload, setData } = useApi<GrantDetail>(`/grant/getbyid/${id}`);
  const [dialog, setDialog] = useState<null | 'revoke' | 'extend' | 'edit' | 'expire'>(null);
  const [busy, setBusy] = useState(false);
  const [reason, setReason] = useState('');

  if (error) return <ErrorState error={error} onRetry={reload} />;
  if (loading && !g) return <PageSkeleton />;
  if (!g) return null;

  const mutable = !['REVOKED', 'SUPERSEDED'].includes(g.status);

  async function act(fn: () => Promise<GrantDetail>, msg: string) {
    setBusy(true);
    try {
      setData(await fn());
      toast.success(msg);
      setDialog(null);
    } catch (e) {
      toast.error('Action failed', (e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title={
          <>
            {g.name}
            {g.version > 1 && <span className="text-base font-normal text-slate-400">v{g.version}</span>}
          </>
        }
        badge={<StatusBadge status={g.status} />}
        description={`${g.agentName} → ${g.integrationName}`}
        breadcrumbs={[{ label: 'Access Management' }, { label: 'Access Grants', to: '/access/grants' }, { label: g.name }]}
        actions={
          <>
            {g.status === 'PENDING_APPROVAL' && can(PERMISSIONS.GRANT_APPROVE) && (
              <Button loading={busy} onClick={() => act(() => api.post<GrantDetail>('/grant/approve', { id: g.id }), 'Grant approved (simulated approval)')}>
                <CheckCircle2 className="h-4 w-4" /> Approve
              </Button>
            )}
            {mutable && can(PERMISSIONS.GRANT_MANAGE) && (
              <>
                <Button variant="outline" onClick={() => setDialog('edit')}>
                  <Pencil className="h-4 w-4" /> Edit restrictions
                </Button>
                <Button variant="outline" onClick={() => setDialog('extend')}>
                  <CalendarClock className="h-4 w-4" /> Extend expiry
                </Button>
                {g.status !== 'EXPIRED' && (
                  <Button variant="ghost" onClick={() => setDialog('expire')} title="Demo control for Scenario E">
                    <TimerOff className="h-4 w-4" /> Expire now
                  </Button>
                )}
              </>
            )}
            {can(PERMISSIONS.AUDIT_READ) && (
              <Button variant="outline" onClick={() => navigate(`/audit/access-logs?grantId=${g.id}`)}>
                <History className="h-4 w-4" /> View audit trail
              </Button>
            )}
            {mutable && can(PERMISSIONS.GRANT_REVOKE) && (
              <Button variant="danger" onClick={() => setDialog('revoke')}>
                <ShieldOff className="h-4 w-4" /> Revoke grant
              </Button>
            )}
          </>
        }
      />

      {g.status === 'REVOKED' && (
        <Callout tone="danger" title={`Revoked ${relativeTime(g.revokedAt)}`}>
          {g.revocationReason}. All subsequent requests using this grant are denied with GRANT_REVOKED.
        </Callout>
      )}
      {g.status === 'SUPERSEDED' && (
        <Callout tone="info" title="This version was superseded">
          A newer version of this grant holds the current restrictions. See the version history below.
        </Callout>
      )}
      {g.status === 'EXPIRED' && <Callout tone="warning" title={`Expired ${relativeTime(g.expiresAt)}`}>Extend the expiry to re-authorize the agent, or create a new grant.</Callout>}

      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        <StatCard label="Allowed requests" value={g.usage.allowed} tone="success" icon={<CheckCircle2 className="h-4 w-4" />} />
        <StatCard label="Denied requests" value={g.usage.denied} tone={g.usage.denied ? 'danger' : 'default'} icon={<ShieldOff className="h-4 w-4" />} />
        <StatCard label="Requests (24h)" value={g.usage.last24h} icon={<FileClock className="h-4 w-4" />} />
        <StatCard label="Last used" value={<span className="text-base">{relativeTime(g.lastUsedAt)}</span>} icon={<History className="h-4 w-4" />} />
      </div>

      <div className="grid gap-6 xl:grid-cols-3">
        <Card className="xl:col-span-2">
          <CardHeader title="Grant & policy summary" />
          <CardBody>
            <DetailList
              items={[
                { label: 'Grant ID', value: <Mono>{g.id}</Mono> },
                { label: 'Environment', value: <EnvBadge env={g.environment} /> },
                { label: 'Agent identity', value: <Link className="text-brand-700 hover:underline" to={`/agents/${g.agentId}`}>{g.agentName} ({g.agentId})</Link> },
                { label: 'Integration reference', value: <Link className="text-brand-700 hover:underline" to={`/integrations/${g.integrationId}`}>{g.integrationName} ({g.integrationId})</Link> },
                { label: 'Allowed operations', value: <div className="flex flex-wrap gap-1">{g.scopes.map((s) => <Badge key={s} tone="blue">{operationLabel(s)}</Badge>)}</div> },
                { label: 'Resource restrictions', value: g.resourceConstraints.repositories.length ? g.resourceConstraints.repositories.join(', ') : 'None' },
                { label: 'Valid from', value: formatDateTime(g.validFrom) },
                { label: 'Expires', value: `${formatDateTime(g.expiresAt)} (${relativeTime(g.expiresAt)})` },
                { label: 'Rate limit', value: `${g.rateLimitPerMinute} requests / minute` },
                {
                  label: 'Budgets',
                  value:
                    g.maxRequestsPerDay || g.maxWritesPerHour ? (
                      <div className="space-y-0.5">
                        {g.maxRequestsPerDay ? <p>{g.budgetUsage?.requestsLast24h ?? 0} of {g.maxRequestsPerDay} requests used in the last 24 h</p> : null}
                        {g.maxWritesPerHour ? <p>{g.budgetUsage?.writesLastHour ?? 0} of {g.maxWritesPerHour} writes used in the last hour</p> : null}
                      </div>
                    ) : (
                      'None'
                    ),
                },
                { label: 'Acting for users', value: actingForText(g.onBehalfOf, g.allowedUserGroups) },
                { label: 'Source IP restriction', value: g.allowedCidrs.length ? g.allowedCidrs.join(', ') : 'None' },
                { label: 'Approval', value: g.approvalRequired ? (g.approvedAt ? `Approved ${formatDateTime(g.approvedAt)}` : 'Required (pending)') : 'Not required' },
                { label: 'Created by', value: `${g.createdByName} · ${formatDateTime(g.createdAt)}` },
              ]}
            />
          </CardBody>
        </Card>
        <div className="space-y-6">
          <Card>
            <CardHeader title="Policies that also apply" />
            <CardBody className="space-y-2">
              {g.matchingPolicies.length === 0 ? (
                <p className="text-sm text-slate-500">No enabled policy matches this grant's operations.</p>
              ) : (
                g.matchingPolicies.map((p) => (
                  <Link key={p.id} to="/access/policies" className="flex items-center justify-between rounded-md border border-slate-100 px-3 py-2 text-sm hover:bg-slate-50">
                    <span className="text-slate-800">{p.name}</span>
                    <Badge tone={p.effect === 'DENY' ? 'red' : p.effect === 'REQUIRE_APPROVAL' ? 'amber' : 'green'}>{p.effect === 'REQUIRE_APPROVAL' ? 'REQUIRE APPROVAL' : p.effect}</Badge>
                  </Link>
                ))
              )}
              <p className="pt-1 text-xs text-slate-500">Explicit DENY policies always take precedence over this grant.</p>
            </CardBody>
          </Card>
          <Card>
            <CardHeader title="Version history" />
            <CardBody className="space-y-1">
              {g.versions.map((v) => (
                <Link key={v.id} to={`/access/grants/${v.id}`} className={`flex items-center justify-between rounded-md px-2 py-1.5 text-sm hover:bg-slate-50 ${v.id === g.id ? 'bg-slate-50 font-medium' : ''}`}>
                  <span>
                    v{v.version} <span className="text-xs text-slate-400">{formatDateTime(v.createdAt)}</span>
                  </span>
                  <StatusBadge status={v.status} />
                </Link>
              ))}
            </CardBody>
          </Card>
        </div>
      </div>

      <DelegationsCard grantId={g.id} />

      <Card>
        <CardHeader title="Access history" description="Most recent decisions that referenced this grant" />
        <DataTable
          rows={g.recentRequests}
          rowKey={(r) => r.id}
          onRowClick={can(PERMISSIONS.AUDIT_READ) ? (r) => navigate(`/audit/access-logs?request=${r.id}`) : undefined}
          empty={<EmptyState title="No requests have used this grant yet" />}
          columns={[
            { key: 't', header: 'Time', cell: (r) => <span className="whitespace-nowrap text-slate-500">{formatDateTime(r.createdAt)}</span> },
            { key: 'id', header: 'Request ID', cell: (r) => <Mono>{r.id}</Mono>, hideBelow: 'lg' },
            { key: 'op', header: 'Operation', cell: (r) => operationLabel(r.operation) },
            { key: 'd', header: 'Decision', cell: (r) => <DecisionBadge decision={r.decision} code={r.decisionCode} /> },
            { key: 'reason', header: 'Reason', cell: (r) => <span className="text-slate-500">{r.decisionReason}</span>, hideBelow: 'md' },
          ]}
        />
      </Card>

      <ConfirmDialog
        open={dialog === 'revoke'}
        onClose={() => setDialog(null)}
        title="Revoke grant?"
        description={`${g.agentName} will be denied on its very next request to ${g.integrationName}. Revocation is evaluated on every authorization check; there are no long-lived tokens to wait out.`}
        confirmLabel="Revoke grant"
        loading={busy}
        onConfirm={() => act(() => api.post<GrantDetail>('/grant/revoke', { id: g.id, reason }), 'Grant revoked')}
      >
        <Field label="Reason (recorded in audit)">
          <Textarea rows={2} value={reason} onChange={(e) => setReason(e.target.value)} placeholder="e.g. Demo: revocation test" />
        </Field>
      </ConfirmDialog>
      <ConfirmDialog
        open={dialog === 'expire'}
        onClose={() => setDialog(null)}
        title="Expire grant now?"
        description="Demo control (Scenario E): sets the expiry to the current time so the next request is denied with GRANT_EXPIRED. You can extend it again afterwards."
        confirmLabel="Expire now"
        loading={busy}
        onConfirm={() => act(() => api.post<GrantDetail>('/grant/expireNow', { id: g.id }), 'Grant expired')}
      />
      <ExtendDialog open={dialog === 'extend'} grant={g} onClose={() => setDialog(null)} onSaved={(x) => setData(x)} />
      <EditRestrictionsDialog open={dialog === 'edit'} grant={g} onClose={() => setDialog(null)} onSaved={(x) => navigate(`/access/grants/${x.id}`)} />
    </div>
  );
}

function ExtendDialog({ open, grant, onClose, onSaved }: { open: boolean; grant: GrantDetail; onClose: () => void; onSaved: (g: GrantDetail) => void }) {
  const toast = useToast();
  const [value, setValue] = useState('');
  const save = useMutation((expiresAt: string) => api.post<GrantDetail>('/grant/extend', { id: grant.id, expiresAt }));
  useEffect(() => {
    if (open) setValue(toLocalInput(new Date(Math.max(Date.now(), new Date(grant.expiresAt).getTime()) + 7 * 86400e3)));
  }, [open, grant.expiresAt]);
  return (
    <Dialog
      open={open}
      onClose={onClose}
      size="sm"
      title="Extend expiry"
      footer={
        <>
          <Button variant="outline" onClick={onClose}>
            Cancel
          </Button>
          <Button
            loading={save.pending}
            onClick={async () => {
              const r = await save.run(fromLocalInput(value));
              if (r) {
                onSaved(r);
                toast.success('Expiry extended');
                onClose();
              }
            }}
          >
            Save
          </Button>
        </>
      }
    >
      <div className="space-y-3">
        <FormError error={save.error} />
        <Field label="New expiry" error={save.fieldErrors.expiresAt} hint={`Current: ${formatDateTime(grant.expiresAt)}`}>
          <Input type="datetime-local" value={value} onChange={(e) => setValue(e.target.value)} />
        </Field>
      </div>
    </Dialog>
  );
}

function EditRestrictionsDialog({ open, grant, onClose, onSaved }: { open: boolean; grant: GrantDetail; onClose: () => void; onSaved: (g: GrantDetail) => void }) {
  // Destructive operations too: the server accepts them only where a Require approval policy covers them.
  const { operations: all } = useProviders();
  // Only operations of the grant's own provider can be added.
  const provider = grant.scopes.map((x) => all.find((o) => o.id === x)?.provider).find(Boolean);
  const grantable = provider ? all.filter((o) => o.provider === provider) : all;
  const toast = useToast();
  const [f, setF] = useState({ scopes: [] as string[], repositories: '', validFrom: '', expiresAt: '', rateLimitPerMinute: '', maxRequestsPerDay: '', maxWritesPerHour: '', allowedCidrs: '', onBehalfOf: 'ALLOWED' as OnBehalfOfMode, allowedUserGroups: '' });
  const save = useMutation((body: unknown) => api.post<GrantDetail>('/grant/newVersion', { id: grant.id, ...(body as object) }));
  useEffect(() => {
    if (open)
      setF({
        scopes: grant.scopes,
        repositories: grant.resourceConstraints.repositories.join(', '),
        validFrom: toLocalInput(grant.validFrom),
        expiresAt: toLocalInput(grant.expiresAt),
        rateLimitPerMinute: String(grant.rateLimitPerMinute),
        maxRequestsPerDay: grant.maxRequestsPerDay ? String(grant.maxRequestsPerDay) : '',
        maxWritesPerHour: grant.maxWritesPerHour ? String(grant.maxWritesPerHour) : '',
        allowedCidrs: grant.allowedCidrs.join(', '),
        onBehalfOf: grant.onBehalfOf ?? 'ALLOWED',
        allowedUserGroups: (grant.allowedUserGroups ?? []).join(', '),
      });
  }, [open, grant]);
  const fe = save.fieldErrors;
  return (
    <Dialog
      open={open}
      onClose={onClose}
      size="lg"
      title="Edit restrictions"
      description="For auditability, saving creates a new grant version. The current version is marked Superseded."
      footer={
        <>
          <Button variant="outline" onClick={onClose}>
            Cancel
          </Button>
          <Button
            loading={save.pending}
            onClick={async () => {
              const r = await save.run({
                scopes: f.scopes,
                repositories: splitList(f.repositories),
                validFrom: fromLocalInput(f.validFrom),
                expiresAt: fromLocalInput(f.expiresAt),
                rateLimitPerMinute: Number(f.rateLimitPerMinute),
                // Empty: no limit. Anything else goes to the server, which validates it.
                maxRequestsPerDay: f.maxRequestsPerDay.trim() ? Number(f.maxRequestsPerDay) : null,
                maxWritesPerHour: f.maxWritesPerHour.trim() ? Number(f.maxWritesPerHour) : null,
                allowedCidrs: splitList(f.allowedCidrs),
                onBehalfOf: f.onBehalfOf,
                allowedUserGroups: f.onBehalfOf === 'NOT_ALLOWED' ? [] : splitList(f.allowedUserGroups),
              });
              if (r) {
                toast.success(`Grant version v${r.version} created`);
                onClose();
                onSaved(r);
              }
            }}
          >
            Create new version
          </Button>
        </>
      }
    >
      <div className="space-y-4">
        <FormError error={save.error} />
        <div>
          <p className="mb-2 text-sm font-medium text-slate-700">Permissions</p>
          {fe.scopes && <p className="mb-2 text-xs text-red-600">{fe.scopes}</p>}
          <div className="grid gap-2 sm:grid-cols-2">
            {grantable.map((o) => (
              <Checkbox key={o.id} checked={f.scopes.includes(o.id)} onChange={(v) => setF({ ...f, scopes: v ? [...f.scopes, o.id] : f.scopes.filter((x) => x !== o.id) })} label={o.label} description={o.destructive ? 'Destructive: needs a Require approval policy' : undefined} />
            ))}
          </div>
        </div>
        <div className="grid gap-4 sm:grid-cols-2">
          <Field label="Allowed repository" error={fe.repositories ?? fe['repositories.0']}>
            <Input className="font-mono text-xs" value={f.repositories} onChange={(e) => setF({ ...f, repositories: e.target.value })} />
          </Field>
          <Field label="Max requests / minute" error={fe.rateLimitPerMinute}>
            <Input type="number" value={f.rateLimitPerMinute} onChange={(e) => setF({ ...f, rateLimitPerMinute: e.target.value })} />
          </Field>
          <Field label="Budget: requests per 24 hours" error={fe.maxRequestsPerDay} hint="Empty: no limit">
            <Input type="number" min={1} value={f.maxRequestsPerDay} onChange={(e) => setF({ ...f, maxRequestsPerDay: e.target.value })} placeholder="No limit" />
          </Field>
          <Field label="Budget: writes per hour" error={fe.maxWritesPerHour} hint="Reads don't count. Empty: no limit">
            <Input type="number" min={1} value={f.maxWritesPerHour} onChange={(e) => setF({ ...f, maxWritesPerHour: e.target.value })} placeholder="No limit" />
          </Field>
          <Field label="Valid from" error={fe.validFrom}>
            <Input type="datetime-local" value={f.validFrom} onChange={(e) => setF({ ...f, validFrom: e.target.value })} />
          </Field>
          <Field label="Expiry" error={fe.expiresAt}>
            <Input type="datetime-local" value={f.expiresAt} onChange={(e) => setF({ ...f, expiresAt: e.target.value })} />
          </Field>
          <ActingForFields mode={f.onBehalfOf} groups={f.allowedUserGroups} errors={fe} onChange={(v) => setF({ ...f, ...(v.mode ? { onBehalfOf: v.mode } : {}), ...(v.groups !== undefined ? { allowedUserGroups: v.groups } : {}) })} />
          <Field label="Allowed source CIDRs" error={fe['allowedCidrs.0']} className="sm:col-span-2">
            <Input className="font-mono text-xs" value={f.allowedCidrs} onChange={(e) => setF({ ...f, allowedCidrs: e.target.value })} />
          </Field>
        </div>
      </div>
    </Dialog>
  );
}
