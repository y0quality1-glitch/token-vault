import { useEffect, useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { AlertTriangle, Check, Download, FileLock2, PackageOpen, RefreshCw, Search, X } from 'lucide-react';
import { PERMISSIONS, type SecretExportFile, type SecretExportRequestView, type SecretExportStatus, type SecretView } from '@token-vault/shared';
import { useMutation, usePost } from '@/hooks/useApi';
import { useAuth } from '@/context/AuthContext';
import { ApiError, api } from '@/lib/api';
import { cn, formatDateTime, relativeTime } from '@/lib/utils';
import { Badge, EnvBadge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card } from '@/components/ui/card';
import { Field, Input, Textarea } from '@/components/ui/form';
import { Callout, EmptyState, ErrorState, Spinner } from '@/components/ui/feedback';
import { Dialog } from '@/components/ui/dialog';
import { DataTable } from '@/components/ui/table';
import { PageHeader } from '@/components/ui/navigation';
import { useToast } from '@/components/ui/toast';
import { SecretsSectionTabs } from './secretAccess';
import { ApiErrorCallout } from './secretUi';

/** Shortest passphrase the server accepts. */
const MIN_PASSPHRASE = 12;
const MIN_REASON = 10;
const MAX_SECRETS = 100;

const STATUS: Record<SecretExportStatus, { label: string; tone: 'green' | 'red' | 'amber' | 'blue' | 'gray' | 'violet' }> = {
  PENDING: { label: 'Waiting for approval', tone: 'amber' },
  APPROVED: { label: 'Approved', tone: 'blue' },
  REJECTED: { label: 'Rejected', tone: 'red' },
  READY: { label: 'Ready to download', tone: 'violet' },
  DOWNLOADED: { label: 'Downloaded', tone: 'green' },
  EXPIRED: { label: 'Expired', tone: 'gray' },
};

type Prepared = { downloadUrl: string; expiresAt: string };
type DialogState = null | { kind: 'request' } | { kind: 'approve' | 'reject' | 'prepare'; request: SecretExportRequestView };

/** Saves the encrypted export file through a temporary object URL. */
function saveFile(file: SecretExportFile, id: string) {
  const blob = new Blob([JSON.stringify(file, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `token-vault-export-${id}.json`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

/** The download link the server returns is absolute under /api/v1; the api helper adds that prefix. */
function apiPath(downloadUrl: string): string {
  return downloadUrl.replace(/^\/api\/v1(?=\/)/, '');
}

/**
 * Export of secret values (spec 4.9.14): requested with a reason, approved by someone else,
 * then encrypted with a passphrase the requester chooses and downloaded once.
 */
export function SecretExportsPage() {
  const { can } = useAuth();
  const toast = useToast();
  const { data, error, loading, reload } = usePost<{ items: SecretExportRequestView[]; enabled: boolean }>('/secretExport/getall');
  const [dialog, setDialog] = useState<DialogState>(null);
  // Download links of exports prepared in this page (not the passphrase): kept so a failed download can be retried.
  const [prepared, setPrepared] = useState<Record<string, Prepared>>({});
  const [downloading, setDownloading] = useState<string | null>(null);
  const enabled = data?.enabled ?? true;
  const canRequest = can(PERMISSIONS.SECRET_EXPORT) && enabled;
  const close = () => setDialog(null);

  async function download(id: string, link: Prepared): Promise<boolean> {
    setDownloading(id);
    try {
      const file = await api.get<SecretExportFile>(apiPath(link.downloadUrl));
      saveFile(file, id);
      toast.success('Export downloaded', `Saved as token-vault-export-${id}.json. It opens only with your passphrase.`);
      setPrepared((p) => {
        const { [id]: _done, ...rest } = p;
        return rest;
      });
      return true;
    } catch (e) {
      toast.error('Download failed', (e as Error).message);
      if (e instanceof ApiError && e.code === 'EXPORT_GONE')
        setPrepared((p) => {
          const { [id]: _gone, ...rest } = p;
          return rest;
        });
      return false;
    } finally {
      setDownloading(null);
      await reload();
    }
  }

  return (
    <div>
      <PageHeader
        title="Exports"
        description="Taking secret values out of Token Vault. Every export needs a reason and another member’s approval, and produces a file encrypted with a passphrase you choose."
        breadcrumbs={[{ label: 'Secrets', to: '/secrets' }, { label: 'Exports' }]}
        actions={
          <>
            <Button variant="outline" onClick={() => void reload()} loading={loading && !!data}>
              <RefreshCw className="h-4 w-4" /> Refresh
            </Button>
            {can(PERMISSIONS.SECRET_EXPORT) && (
              <Button onClick={() => setDialog({ kind: 'request' })} disabled={!canRequest} data-testid="secret-export-request">
                <PackageOpen className="h-4 w-4" /> Request export
              </Button>
            )}
          </>
        }
      />
      <SecretsSectionTabs current="/secrets/exports" />
      {data && !data.enabled && (
        <div className="mb-4" data-testid="secret-export-disabled">
          <Callout tone="warning" title="Exports are turned off">
            This Token Vault does not allow secret values to be exported. An operator can turn it on with <code className="font-mono text-[12px]">SECRET_EXPORT_ENABLED=true</code> on the control plane. Past requests are still listed below.
          </Callout>
        </div>
      )}
      <Callout tone="security" className="mb-4">
        An exported file holds every value of the chosen secrets. It is encrypted with your passphrase and opens with <code className="font-mono text-[12px]">node scripts/decrypt-export.mjs &lt;file&gt;</code>. Nothing, not even Token Vault, can recover a lost passphrase. Delete the file once it is used.
      </Callout>
      {error ? (
        <ErrorState error={error} onRetry={reload} />
      ) : (
        <Card data-testid="secret-exports">
          <DataTable
            rows={data?.items}
            loading={loading && !data}
            rowKey={(r) => r.id}
            empty={<EmptyState icon={<FileLock2 className="h-5 w-5" />} title="No export requests" description="Requests appear here with their approval and download history." />}
            columns={[
              {
                key: 'requester',
                header: 'Requested',
                cell: (r) => (
                  <div className="min-w-0" data-testid="secret-export-row" data-status={r.status} data-export-id={r.id}>
                    <span className="block font-medium text-slate-900">{r.requestedBy.name}</span>
                    <span className="block text-xs text-slate-500" title={formatDateTime(r.createdAt)}>
                      {relativeTime(r.createdAt)}
                    </span>
                  </div>
                ),
              },
              {
                key: 'secrets',
                header: 'Secrets',
                cell: (r) => (
                  <div className="flex max-w-xs flex-wrap gap-x-2 gap-y-0.5 text-xs">
                    {r.secrets.slice(0, 5).map((s) => (
                      <Link key={s.id} className="text-brand-700 hover:underline" to={`/secrets/${s.id}`}>
                        {s.name}
                      </Link>
                    ))}
                    {r.secrets.length > 5 && <span className="text-slate-500">and {r.secrets.length - 5} more</span>}
                  </div>
                ),
              },
              { key: 'reason', header: 'Reason', cell: (r) => <span className="block max-w-xs break-words text-slate-600">{r.reason}</span>, hideBelow: 'lg' },
              {
                key: 'status',
                header: 'Status',
                cell: (r) => (
                  <span data-testid="secret-export-status" data-status={r.status}>
                    <Badge tone={STATUS[r.status]?.tone ?? 'gray'} dot>
                      {STATUS[r.status]?.label ?? r.status}
                    </Badge>
                  </span>
                ),
              },
              {
                key: 'decision',
                header: 'Decision',
                hideBelow: 'md',
                cell: (r) =>
                  r.decidedBy ? (
                    <span className="block max-w-xs break-words text-xs text-slate-600">
                      {r.decidedBy.name}
                      {r.decidedAt && <span className="text-slate-400"> · {relativeTime(r.decidedAt)}</span>}
                      {r.note && <span className="block text-slate-500">“{r.note}”</span>}
                    </span>
                  ) : (
                    <span className="text-slate-400">—</span>
                  ),
              },
              {
                key: 'expiry',
                header: 'Expires',
                hideBelow: 'xl',
                cell: (r) =>
                  r.downloadedAt ? (
                    <span className="text-xs text-slate-500" title={formatDateTime(r.downloadedAt)}>
                      downloaded {relativeTime(r.downloadedAt)}
                    </span>
                  ) : r.expiresAt && (r.status === 'APPROVED' || r.status === 'READY') ? (
                    <span className="text-xs text-slate-600" title={formatDateTime(r.expiresAt)}>
                      {r.status === 'APPROVED' ? 'prepare' : 'download'} {relativeTime(r.expiresAt)}
                    </span>
                  ) : (
                    <span className="text-slate-400">—</span>
                  ),
              },
              {
                key: 'actions',
                header: '',
                className: 'text-right',
                cell: (r) => (
                  <div className="flex flex-wrap justify-end gap-1">
                    {r.can.decide && enabled && (
                      <>
                        <Button size="sm" variant="outline" onClick={() => setDialog({ kind: 'approve', request: r })} data-testid="secret-export-approve">
                          <Check className="h-3.5 w-3.5" /> Approve
                        </Button>
                        <Button size="sm" variant="ghost" className="text-red-700 hover:bg-red-50 hover:text-red-800" onClick={() => setDialog({ kind: 'reject', request: r })} data-testid="secret-export-reject">
                          <X className="h-3.5 w-3.5" /> Reject
                        </Button>
                      </>
                    )}
                    {r.can.prepare && enabled && (
                      <Button size="sm" onClick={() => setDialog({ kind: 'prepare', request: r })} data-testid="secret-export-prepare">
                        <FileLock2 className="h-3.5 w-3.5" /> Prepare
                      </Button>
                    )}
                    {r.can.download && enabled && prepared[r.id] && (
                      <Button size="sm" loading={downloading === r.id} onClick={() => void download(r.id, prepared[r.id]!)} data-testid="secret-export-download">
                        <Download className="h-3.5 w-3.5" /> Download
                      </Button>
                    )}
                    {r.can.download && !prepared[r.id] && <span className="max-w-[12rem] text-right text-xs text-slate-500">The download link was given to the session that prepared it.</span>}
                  </div>
                ),
              },
            ]}
          />
        </Card>
      )}

      {dialog?.kind === 'request' && (
        <RequestExportDialog
          onClose={close}
          onDone={() => {
            close();
            toast.success('Export requested', 'Another member with access management must approve it.');
            void reload();
          }}
        />
      )}
      {(dialog?.kind === 'approve' || dialog?.kind === 'reject') && (
        <DecisionDialog
          request={dialog.request}
          outcome={dialog.kind}
          onClose={close}
          onDone={() => {
            toast.success(dialog.kind === 'approve' ? 'Export approved' : 'Export rejected');
            close();
            void reload();
          }}
        />
      )}
      {dialog?.kind === 'prepare' && (
        <PrepareDialog
          request={dialog.request}
          onClose={close}
          onPrepared={async (link) => {
            const id = dialog.request.id;
            close();
            setPrepared((p) => ({ ...p, [id]: link }));
            await download(id, link);
          }}
        />
      )}
    </div>
  );
}

function RequestExportDialog({ onClose, onDone }: { onClose: () => void; onDone: () => void }) {
  const [search, setSearch] = useState('');
  const [debounced, setDebounced] = useState('');
  const [selected, setSelected] = useState<Record<string, string>>({});
  const [reason, setReason] = useState('');
  const [errors, setErrors] = useState<Record<string, string>>({});
  useEffect(() => {
    const t = setTimeout(() => setDebounced(search.trim()), 300);
    return () => clearTimeout(t);
  }, [search]);
  const secrets = usePost<{ items: SecretView[]; total: number }>('/secret/getall', { ...(debounced ? { search: debounced } : {}), sortBy: 'name', sortOrder: 'asc', pageNumber: 1, pageSize: 100 });
  const submit = useMutation((body: unknown) => api.post<SecretExportRequestView>('/secretExport/request', body));
  const allErrors = { ...submit.fieldErrors, ...errors };
  const ids = Object.keys(selected);
  // Only secrets with a stored value can be exported.
  const rows = useMemo(() => (secrets.data?.items ?? []).filter((s) => s.activeVersion !== null && s.status !== 'DELETED'), [secrets.data]);

  function toggle(s: SecretView, on: boolean) {
    setSelected((cur) => {
      const next = { ...cur };
      if (on) next[s.id] = s.name;
      else delete next[s.id];
      return next;
    });
  }

  async function onSubmit() {
    const e: Record<string, string> = {};
    if (!ids.length) e.secretIds = 'Choose at least one secret';
    else if (ids.length > MAX_SECRETS) e.secretIds = `At most ${MAX_SECRETS} secrets per export`;
    if (reason.trim().length < MIN_REASON) e.reason = `Say why the values must leave Token Vault (at least ${MIN_REASON} characters)`;
    setErrors(e);
    if (Object.keys(e).length) return;
    const r = await submit.run({ secretIds: ids, reason: reason.trim() });
    if (r) onDone();
  }

  return (
    <Dialog
      open
      onClose={onClose}
      size="lg"
      title="Request an export"
      description="The values of the chosen secrets will leave Token Vault. Another member with access management must approve the request first."
      footer={
        <>
          <Button variant="outline" onClick={onClose}>
            Cancel
          </Button>
          <Button loading={submit.pending} onClick={() => void onSubmit()} data-testid="secret-export-submit">
            Request export of {ids.length} secret{ids.length === 1 ? '' : 's'}
          </Button>
        </>
      }
    >
      <div className="space-y-4" data-testid="secret-export-request-dialog">
        <div className="space-y-2">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <p className="text-sm font-medium text-slate-700">Secrets</p>
            <span className="text-xs text-slate-500">{ids.length} selected</span>
          </div>
          <div className="relative">
            <Search className="absolute left-2.5 top-2.5 h-4 w-4 text-slate-400" />
            <Input className="pl-8" placeholder="Search secrets by name" value={search} onChange={(e) => setSearch(e.target.value)} aria-label="Search secrets" data-testid="secret-export-search" />
          </div>
          <div className={cn('max-h-64 overflow-y-auto rounded-lg border', allErrors.secretIds ? 'border-red-300' : 'border-slate-200')}>
            {secrets.error ? (
              <p className="p-3 text-sm text-red-700">{secrets.error.message}</p>
            ) : secrets.loading && !secrets.data ? (
              <Spinner className="py-6" />
            ) : rows.length === 0 ? (
              <p className="p-3 text-sm text-slate-500">{debounced ? `No secrets match “${debounced}”.` : 'No secrets with a stored value.'}</p>
            ) : (
              <ul className="divide-y divide-slate-100">
                {rows.map((s) => (
                  <li key={s.id}>
                    <label className="flex cursor-pointer items-start gap-3 px-3 py-2 hover:bg-slate-50">
                      <input type="checkbox" className="mt-0.5 h-4 w-4 rounded border-slate-300 text-brand-600 focus:ring-brand-500" checked={!!selected[s.id]} onChange={(e) => toggle(s, e.target.checked)} data-testid={`secret-export-secret-${s.id}`} />
                      <span className="min-w-0 flex-1">
                        <span className="block truncate text-sm font-medium text-slate-800">{s.name}</span>
                        <span className="block truncate text-xs text-slate-500">
                          {s.typeName} · {s.project}/{s.workspace}
                        </span>
                      </span>
                      <EnvBadge env={s.environment} />
                    </label>
                  </li>
                ))}
              </ul>
            )}
          </div>
          {secrets.data && secrets.data.total > 100 && <p className="text-xs text-slate-500">Showing the first 100; search to find others. Selections are kept while you search.</p>}
          {allErrors.secretIds && <p className="text-xs text-red-600">{allErrors.secretIds}</p>}
        </div>
        <Field label="Reason" htmlFor="secret-export-reason" required error={allErrors.reason} hint="Shown to the approver and recorded in the audit log.">
          <Textarea id="secret-export-reason" rows={3} maxLength={500} value={reason} onChange={(e) => setReason(e.target.value)} invalid={!!allErrors.reason} placeholder="Migrating the payments database credentials to the new region" data-testid="secret-export-reason" />
        </Field>
        <ApiErrorCallout error={submit.error} shownFields={['secretIds', 'reason']} />
      </div>
    </Dialog>
  );
}

function DecisionDialog({ request, outcome, onClose, onDone }: { request: SecretExportRequestView; outcome: 'approve' | 'reject'; onClose: () => void; onDone: () => void }) {
  const [note, setNote] = useState('');
  const submit = useMutation((body: unknown) => api.post<SecretExportRequestView>(`/secretExport/${outcome}`, body));
  const approve = outcome === 'approve';
  async function confirm() {
    const r = await submit.run({ id: request.id, ...(note.trim() ? { note: note.trim() } : {}) });
    if (r) onDone();
  }
  return (
    <Dialog
      open
      onClose={onClose}
      title={approve ? 'Approve export' : 'Reject export'}
      description={`${request.requestedBy.name} asked to export ${request.secrets.length} secret(s).`}
      footer={
        <>
          <Button variant="outline" onClick={onClose} disabled={submit.pending}>
            Cancel
          </Button>
          <Button variant={approve ? 'danger' : 'primary'} loading={submit.pending} onClick={() => void confirm()} data-testid="secret-export-decision-confirm">
            {approve ? 'Approve export' : 'Reject export'}
          </Button>
        </>
      }
    >
      <div className="space-y-4 text-sm text-slate-600" data-testid="secret-export-decision-dialog">
        <div>
          <p className="text-xs font-medium uppercase tracking-wide text-slate-500">Reason given</p>
          <p className="mt-1 break-words text-slate-800">{request.reason}</p>
        </div>
        <div>
          <p className="text-xs font-medium uppercase tracking-wide text-slate-500">Secrets</p>
          <p className="mt-1 break-words text-slate-800">{request.secrets.map((s) => s.name).join(', ')}</p>
        </div>
        {approve && (
          <Callout tone="warning">
            Approving lets {request.requestedBy.name} download every value of these secrets, once, in a file only their passphrase opens. The approval lapses if they do not prepare it in time.
          </Callout>
        )}
        <Field label="Note (optional)" htmlFor="secret-export-decision-note" hint="Shown with the decision and recorded in the audit log.">
          <Textarea id="secret-export-decision-note" rows={2} maxLength={300} value={note} onChange={(e) => setNote(e.target.value)} data-testid="secret-export-decision-note" />
        </Field>
        <ApiErrorCallout error={submit.error} />
      </div>
    </Dialog>
  );
}

/** Asks twice for the passphrase; it lives only in this dialog and is cleared as soon as the request returns. */
function PrepareDialog({ request, onClose, onPrepared }: { request: SecretExportRequestView; onClose: () => void; onPrepared: (link: Prepared) => Promise<void> }) {
  const [passphrase, setPassphrase] = useState('');
  const [confirm, setConfirm] = useState('');
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<ApiError | null>(null);

  function close() {
    setPassphrase('');
    setConfirm('');
    onClose();
  }

  async function submit() {
    const e: Record<string, string> = {};
    if (passphrase.length < MIN_PASSPHRASE) e.passphrase = `At least ${MIN_PASSPHRASE} characters`;
    else if (confirm !== passphrase) e.confirm = 'The passphrases do not match';
    setErrors(e);
    if (Object.keys(e).length) return;
    setPending(true);
    setError(null);
    let link: Prepared | null = null;
    try {
      link = await api.post<Prepared>('/secretExport/prepare', { id: request.id, passphrase });
    } catch (err) {
      setError(err instanceof ApiError ? err : new ApiError(0, 'UNKNOWN', String(err)));
    } finally {
      // Never keep the passphrase after the request, whatever its outcome.
      setPassphrase('');
      setConfirm('');
      setPending(false);
    }
    if (link) await onPrepared(link);
  }

  const common = { type: 'password', autoComplete: 'new-password', spellCheck: false, 'data-1p-ignore': true, 'data-lpignore': 'true' } as const;
  return (
    <Dialog
      open
      onClose={close}
      dismissible={!pending}
      title="Prepare the export file"
      description={`${request.secrets.length} secret(s). The values are read from your customer webhook and encrypted with this passphrase.`}
      footer={
        <>
          <Button variant="outline" onClick={close} disabled={pending}>
            Cancel
          </Button>
          <Button loading={pending} onClick={() => void submit()} data-testid="secret-export-prepare-confirm">
            <Download className="h-4 w-4" /> Encrypt and download
          </Button>
        </>
      }
    >
      <form
        className="space-y-4"
        data-testid="secret-export-prepare-dialog"
        autoComplete="off"
        onSubmit={(e) => {
          e.preventDefault();
          void submit();
        }}
      >
        <div className="flex items-start gap-3 rounded-lg border border-red-200 bg-red-50 p-3 text-sm text-red-900">
          <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-red-600" />
          <div className="space-y-1">
            <p>
              <strong>Nothing can recover a lost passphrase.</strong> Token Vault does not keep it, and without it the file cannot be opened.
            </p>
            <p>
              The file is saved as <code className="font-mono text-[12px]">token-vault-export-{request.id}.json</code> and opens with <code className="font-mono text-[12px]">node scripts/decrypt-export.mjs &lt;file&gt;</code>. The download link works once, for 10 minutes.
            </p>
          </div>
        </div>
        <Field label="Passphrase" htmlFor="secret-export-passphrase" required error={errors.passphrase} hint={`At least ${MIN_PASSPHRASE} characters. Use a passphrase manager.`}>
          <Input id="secret-export-passphrase" {...common} value={passphrase} onChange={(e) => setPassphrase(e.target.value)} invalid={!!errors.passphrase} data-testid="secret-export-passphrase" />
        </Field>
        <Field label="Passphrase again" htmlFor="secret-export-passphrase-confirm" required error={errors.confirm}>
          <Input id="secret-export-passphrase-confirm" {...common} value={confirm} onChange={(e) => setConfirm(e.target.value)} invalid={!!errors.confirm} data-testid="secret-export-passphrase-confirm" />
        </Field>
        <ApiErrorCallout error={error} />
      </form>
    </Dialog>
  );
}
