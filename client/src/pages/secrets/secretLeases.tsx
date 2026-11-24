import { useState } from 'react';
import { AlertTriangle, Activity, Clock, KeyRound, Plus, ShieldOff, Timer } from 'lucide-react';
import { PERMISSIONS, type SecretDetail, type SecretLeaseIssued, type SecretLeaseView } from '@token-vault/shared';
import { useMutation } from '@/hooks/useApi';
import { useAuth } from '@/context/AuthContext';
import { api, type ApiError } from '@/lib/api';
import { formatDateTime, relativeTime } from '@/lib/utils';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardBody, CardHeader, DetailList } from '@/components/ui/card';
import { Field, Input, Textarea } from '@/components/ui/form';
import { Callout } from '@/components/ui/feedback';
import { Dialog } from '@/components/ui/dialog';
import { DataTable, type Column } from '@/components/ui/table';
import { CopyButton } from '@/components/ui/secret';
import { useToast } from '@/components/ui/toast';
import { ApiErrorCallout, LeaseStatusBadge, ProviderCapabilityBadges } from './secretUi';

/**
 * Providers and dynamic secrets (spec 4.9.3 J, 4.9.16): the provider health card and the leases
 * issued from a dynamic secret. Lease credentials are shown once, in a dialog, and dropped when it
 * closes; Token Vault never keeps them.
 */

/** Whether the signed-in member may end this lease: their own, or anyone's with secret:manage_access. */
export function useCanEndLease() {
  const { can, session } = useAuth();
  const userId = session?.user.id;
  return (l: SecretLeaseView) => (l.status === 'ACTIVE' || l.status === 'REVOKE_FAILED') && ((l.holder.type === 'USER' && l.holder.id === userId) || can(PERMISSIONS.SECRET_MANAGE_ACCESS));
}

/** Holder name with its kind (application or member). */
export function LeaseHolder({ lease }: { lease: SecretLeaseView }) {
  return (
    <span className="min-w-0">
      <span className="block text-slate-800">{lease.holder.name}</span>
      <span className="block text-xs text-slate-500">{lease.holder.type === 'AGENT' ? 'Application' : 'Member'}</span>
    </span>
  );
}

/** Lease times: created, expires, and the latest it can be renewed to. */
export function LeaseTimes({ lease: l }: { lease: SecretLeaseView }) {
  const live = l.status === 'ACTIVE';
  return (
    <span className="whitespace-nowrap text-xs text-slate-500">
      <span className="block" title={formatDateTime(l.createdAt)}>
        created {relativeTime(l.createdAt)}
      </span>
      <span className={live ? 'block text-slate-700' : 'block'} title={formatDateTime(l.expiresAt)}>
        {Date.parse(l.expiresAt) > Date.now() ? 'ends' : 'ended'} {relativeTime(l.expiresAt)}
      </span>
      {live && l.renewable && (
        <span className="block" title={formatDateTime(l.maxExpiresAt)}>
          at most until {formatDateTime(l.maxExpiresAt)}
        </span>
      )}
    </span>
  );
}

/** Why a lease ended, or why ending it at the provider is still pending. */
export function LeaseOutcome({ lease: l }: { lease: SecretLeaseView }) {
  if (!l.revocationReason && !l.lastError && !l.revokedBy) return <span className="text-slate-400">—</span>;
  return (
    <span className="block max-w-xs break-words text-xs">
      {l.revocationReason && <span className="block text-slate-600">{l.revocationReason}</span>}
      {l.revokedBy && <span className="block text-slate-500">by {l.revokedBy}{l.revokedAt ? `, ${relativeTime(l.revokedAt)}` : ''}</span>}
      {l.lastError && <span className="block text-red-700">{l.lastError}</span>}
      {l.status === 'REVOKE_FAILED' && <span className="block text-amber-700">The provider cleanup is retried automatically.</span>}
    </span>
  );
}

/** Ends a lease now (with an optional reason). */
export function RevokeLeaseDialog({ lease, onClose, onDone }: { lease: SecretLeaseView; onClose: () => void; onDone: () => void }) {
  const [reason, setReason] = useState('');
  const toast = useToast();
  const revoke = useMutation((body: unknown) => api.post<SecretLeaseView>('/secretLease/revoke', body));
  async function confirm() {
    const r = await revoke.run({ id: lease.id, ...(reason.trim() ? { reason: reason.trim() } : {}) });
    if (!r) return;
    if (r.status === 'REVOKE_FAILED') toast.error('Lease ended, provider cleanup pending', 'The credential is refused by Token Vault; removing it at the provider is retried automatically.');
    else toast.success('Lease ended', `${lease.username} can no longer be used.`);
    onDone();
  }
  return (
    <Dialog
      open
      onClose={onClose}
      size="sm"
      title={
        <span className="flex items-center gap-2">
          <AlertTriangle className="h-5 w-5 text-red-600" /> End lease
        </span>
      }
      footer={
        <>
          <Button variant="outline" onClick={onClose} disabled={revoke.pending}>
            Cancel
          </Button>
          <Button variant="danger" loading={revoke.pending} onClick={() => void confirm()} data-testid="secret-lease-revoke-confirm">
            End lease
          </Button>
        </>
      }
    >
      <div className="space-y-4 text-sm text-slate-600" data-testid="secret-lease-revoke-dialog">
        <p>
          The credential <strong className="break-all font-mono text-[13px]">{lease.username}</strong> held by {lease.holder.name} is removed at the provider now. Anything still using it stops working.
        </p>
        <Field label="Reason (optional)" htmlFor="secret-lease-revoke-reason" hint="Recorded in the audit log.">
          <Textarea id="secret-lease-revoke-reason" rows={2} maxLength={300} value={reason} onChange={(e) => setReason(e.target.value)} data-testid="secret-lease-revoke-reason" />
        </Field>
        <ApiErrorCallout error={revoke.error} />
      </div>
    </Dialog>
  );
}

// ── secret detail: provider ──────────────────────────────────────

const HEALTH: Record<'OK' | 'FAILING' | 'none', { label: string; tone: 'green' | 'red' | 'gray' }> = {
  OK: { label: 'OK', tone: 'green' },
  FAILING: { label: 'Failing', tone: 'red' },
  none: { label: 'Not monitored', tone: 'gray' },
};

/** What the customer webhook can do at the secret's provider, and the last health check. */
export function ProviderCard({ secret: s, onChanged }: { secret: SecretDetail; onChanged: () => Promise<void> }) {
  const toast = useToast();
  const [checking, setChecking] = useState(false);
  const [error, setError] = useState<ApiError | null>(null);
  const p = s.provider!;
  const status = p.status ?? 'none';
  const h = HEALTH[status];

  async function check() {
    setChecking(true);
    setError(null);
    try {
      const r = await api.post<{ ok: boolean; detail: string; code: string | null; checkedAt: string }>('/secret/checkProvider', { id: s.id });
      if (r.ok) toast.success('Provider check passed', r.detail || 'The stored credential works at the provider.');
      else toast.error('Provider check failed', `${r.detail}${r.code ? ` (${r.code})` : ''}`);
      await onChanged();
    } catch (e) {
      setError(e as ApiError);
      toast.error('Check failed', (e as Error).message);
    } finally {
      setChecking(false);
    }
  }

  return (
    <Card data-testid="secret-provider-card" data-status={status}>
      <CardHeader
        title="Provider"
        description="The customer webhook connects to where this credential is used. Token Vault never connects to it itself."
        icon={<Activity className="h-4 w-4" />}
        actions={
          p.capabilities.check && (
            <Button variant="outline" size="sm" loading={checking} onClick={() => void check()} data-testid="secret-provider-check">
              <Activity className="h-3.5 w-3.5" /> Check now
            </Button>
          )
        }
      />
      <CardBody className="space-y-4">
        <DetailList
          columns={3}
          items={[
            {
              label: 'Health',
              value: (
                <span data-testid="secret-provider-status" data-status={status}>
                  <Badge tone={h.tone} dot>
                    {h.label}
                  </Badge>
                </span>
              ),
            },
            { label: 'Last checked', value: p.checkedAt ? <span title={formatDateTime(p.checkedAt)}>{relativeTime(p.checkedAt)}</span> : 'Never' },
            { label: 'The webhook can', value: <ProviderCapabilityBadges capabilities={p.capabilities} /> },
          ]}
        />
        {p.error && (
          <div data-testid="secret-provider-error">
            <Callout tone="danger" title="Last check failed">
              {p.error}
            </Callout>
          </div>
        )}
        {status === 'none' && p.capabilities.check && <p className="text-xs text-slate-500">Not checked yet. Use “Check now” to connect with the stored credential and confirm it works.</p>}
        <ApiErrorCallout error={error} />
      </CardBody>
    </Card>
  );
}

// ── secret detail: leases ────────────────────────────────────────

/** Leases issued from a dynamic secret, with "Issue a lease" for members allowed to retrieve it. */
export function LeasesCard({ secret: s, onChanged }: { secret: SecretDetail; onChanged: () => Promise<void> }) {
  const { can } = useAuth();
  const canEnd = useCanEndLease();
  const [issuing, setIssuing] = useState(false);
  const [issued, setIssued] = useState<SecretLeaseIssued | null>(null);
  const [revoking, setRevoking] = useState<SecretLeaseView | null>(null);
  const canIssue = can(PERMISSIONS.SECRET_RETRIEVE) && s.status !== 'REVOKED' && s.status !== 'ARCHIVED' && s.status !== 'DELETED';
  const active = s.leases.filter((l) => l.status === 'ACTIVE').length;

  const columns: Column<SecretLeaseView>[] = [
    {
      key: 'holder',
      header: 'Holder',
      cell: (l) => (
        <div data-testid="secret-lease-row" data-status={l.status} data-lease-id={l.id}>
          <LeaseHolder lease={l} />
        </div>
      ),
    },
    { key: 'username', header: 'Username', cell: (l) => <code className="break-all font-mono text-[12px] text-slate-700">{l.username}</code>, hideBelow: 'md' },
    { key: 'status', header: 'Status', cell: (l) => <LeaseStatusBadge status={l.status} /> },
    { key: 'times', header: 'Times', cell: (l) => <LeaseTimes lease={l} />, hideBelow: 'md' },
    { key: 'renewals', header: 'Renewals', cell: (l) => <span className="text-slate-600">{l.renewable ? l.renewCount : 'Not renewable'}</span>, hideBelow: 'xl' },
    { key: 'outcome', header: 'Ended', cell: (l) => <LeaseOutcome lease={l} />, hideBelow: 'lg' },
    {
      key: 'actions',
      header: '',
      className: 'text-right',
      cell: (l) =>
        canEnd(l) ? (
          <Button variant="ghost" size="sm" className="text-red-700 hover:bg-red-50 hover:text-red-800" onClick={() => setRevoking(l)} data-testid="secret-lease-revoke">
            <ShieldOff className="h-3.5 w-3.5" /> End lease
          </Button>
        ) : null,
    },
  ];

  return (
    <Card data-testid="secret-leases-card">
      <CardHeader
        title="Leases"
        description={`${active} active. Each lease is a short-lived credential the customer webhook creates at the provider and removes when the lease ends.`}
        icon={<Timer className="h-4 w-4" />}
        actions={
          canIssue && (
            <Button size="sm" onClick={() => setIssuing(true)} data-testid="secret-lease-issue">
              <Plus className="h-3.5 w-3.5" /> Issue a lease
            </Button>
          )
        }
      />
      <CardBody className="border-b border-slate-100">
        <Callout tone="info">
          Applications get leases with <code className="font-mono text-[12px]">tv.secrets.lease()</code> or <code className="font-mono text-[12px]">POST /agent/v1/secret/lease</code>, through an access grant. Dynamic secrets are never retrieved by applications: they only ever receive their own lease.
        </Callout>
      </CardBody>
      <DataTable rows={s.leases} rowKey={(l) => l.id} columns={columns} dense empty={<p className="px-5 py-6 text-sm text-slate-500">No leases yet.</p>} />
      {issuing && (
        <IssueLeaseDialog
          secret={s}
          onClose={() => setIssuing(false)}
          onIssued={(l) => {
            setIssuing(false);
            setIssued(l);
          }}
        />
      )}
      {issued && (
        <LeaseCredentialsDialog
          lease={issued}
          onDone={() => {
            setIssued(null);
            void onChanged();
          }}
        />
      )}
      {revoking && (
        <RevokeLeaseDialog
          lease={revoking}
          onClose={() => setRevoking(null)}
          onDone={() => {
            setRevoking(null);
            void onChanged();
          }}
        />
      )}
    </Card>
  );
}

function IssueLeaseDialog({ secret, onClose, onIssued }: { secret: SecretDetail; onClose: () => void; onIssued: (l: SecretLeaseIssued) => void }) {
  const [minutes, setMinutes] = useState('');
  const [reason, setReason] = useState('');
  const [error, setError] = useState('');
  const issue = useMutation((body: unknown) => api.post<SecretLeaseIssued>('/secretLease/issue', body));
  const defaultTtl = secret.metadata.defaultTtlMinutes;
  const maxTtl = secret.metadata.maxTtlMinutes;

  async function submit() {
    const m = minutes.trim();
    if (m && (!/^\d+$/.test(m) || Number(m) < 1)) return setError('A whole number of minutes');
    setError('');
    const r = await issue.run({ secretId: secret.id, ...(m ? { ttlSeconds: Number(m) * 60 } : {}), ...(reason.trim() ? { reason: reason.trim() } : {}) });
    if (r) onIssued(r);
  }

  return (
    <Dialog
      open
      onClose={onClose}
      title={`Issue a lease from ${secret.name}`}
      description="The customer webhook creates a new short-lived credential at the provider. Issuing is recorded in the audit log."
      footer={
        <>
          <Button variant="outline" onClick={onClose}>
            Cancel
          </Button>
          <Button loading={issue.pending} onClick={() => void submit()} data-testid="secret-lease-issue-confirm">
            <KeyRound className="h-4 w-4" /> Issue lease
          </Button>
        </>
      }
    >
      <form
        className="space-y-4"
        data-testid="secret-lease-issue-form"
        onSubmit={(e) => {
          e.preventDefault();
          void submit();
        }}
      >
        <Field
          label="Length (minutes, optional)"
          htmlFor="secret-lease-minutes"
          error={error}
          hint={`${defaultTtl !== undefined ? `Default ${String(defaultTtl)} minutes.` : 'The type default applies when empty.'}${maxTtl !== undefined ? ` At most ${String(maxTtl)} minutes.` : ''}`}
        >
          <Input id="secret-lease-minutes" type="number" min={1} step={1} value={minutes} onChange={(e) => setMinutes(e.target.value)} invalid={!!error} data-testid="secret-lease-minutes" />
        </Field>
        <Field label="Reason (optional)" htmlFor="secret-lease-reason" hint="Recorded in the audit log.">
          <Textarea id="secret-lease-reason" rows={2} maxLength={300} value={reason} onChange={(e) => setReason(e.target.value)} placeholder="Investigating a slow query" data-testid="secret-lease-reason" />
        </Field>
        <Callout tone="security">The credentials are shown once, right after they are created. Token Vault does not keep them.</Callout>
        <ApiErrorCallout error={issue.error} />
      </form>
    </Dialog>
  );
}

/** The credentials of a new lease: shown once, cannot be dismissed by clicking outside. */
function LeaseCredentialsDialog({ lease, onDone }: { lease: SecretLeaseIssued; onDone: () => void }) {
  return (
    <Dialog
      open
      onClose={onDone}
      dismissible={false}
      size="lg"
      title={
        <span className="flex items-center gap-2">
          <KeyRound className="h-5 w-5 text-brand-600" /> Lease credentials
        </span>
      }
      description={`${lease.secret.name} · ${lease.username}`}
      footer={
        <Button onClick={onDone} data-testid="secret-lease-credentials-done">
          Done
        </Button>
      }
    >
      <div className="space-y-4" data-testid="secret-lease-credentials" data-lease-id={lease.id}>
        <div className="flex items-start gap-3 rounded-lg border border-amber-200 bg-amber-50 p-3 text-sm text-amber-900">
          <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-amber-600" />
          <span>
            <strong>Shown once.</strong> Token Vault does not keep these credentials. They stop working when the lease ends, at <strong>{formatDateTime(lease.expiresAt)}</strong>
            {lease.renewable ? `, or at most ${formatDateTime(lease.maxExpiresAt)} with renewals` : ''}.
          </span>
        </div>
        {Object.entries(lease.credentials).map(([k, v]) => (
          <div key={k} className="rounded-lg border border-slate-200 bg-slate-50 p-3" data-testid={`secret-lease-credential-${k}`}>
            <div className="flex items-center justify-between gap-2">
              <span className="text-xs font-medium uppercase tracking-wide text-slate-500">{k}</span>
              <CopyButton value={v} />
            </div>
            <code className="mt-2 block whitespace-pre-wrap break-all font-mono text-[13px] text-slate-900">{v}</code>
          </div>
        ))}
        <p className="flex items-center gap-1.5 text-xs text-slate-500">
          <Clock className="h-3.5 w-3.5" /> Copied values stay on your clipboard; clear it when done.
        </p>
      </div>
    </Dialog>
  );
}
