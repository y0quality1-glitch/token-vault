import { useEffect, useState } from 'react';
import { Link, useNavigate, useParams } from 'react-router-dom';
import { Archive, Eye, EyeOff, KeyRound, Pencil, PlayCircle, RefreshCw, RotateCcw, ShieldOff, Sparkles, Timer, Trash2, Upload } from 'lucide-react';
import { PERMISSIONS, orderedFields, type EffectiveSecretPolicy, type SecretDetail, type SecretRetrieval, type SecretRotationJobView, type SecretTypeInfo, type SecretVersionView } from '@token-vault/shared';
import { useApi, useMutation } from '@/hooks/useApi';
import { useAuth } from '@/context/AuthContext';
import { api, type ApiError } from '@/lib/api';
import { formatDateTime, relativeTime } from '@/lib/utils';
import { Badge, EnvBadge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardBody, CardHeader, DetailList } from '@/components/ui/card';
import { Checkbox, Field, RadioCard, Textarea } from '@/components/ui/form';
import { Callout, ErrorState, PageSkeleton } from '@/components/ui/feedback';
import { ConfirmDialog, Dialog } from '@/components/ui/dialog';
import { DataTable, type Column } from '@/components/ui/table';
import { PageHeader } from '@/components/ui/navigation';
import { CopyButton, Mono } from '@/components/ui/secret';
import { useToast } from '@/components/ui/toast';
import {
  ApiErrorCallout,
  POLICY_SOURCE_LABELS,
  ROTATION_STRATEGY_SHORT,
  ROTATION_TRIGGER_LABELS,
  RotationJobStatusBadge,
  SecretStatusBadge,
  TypeFields,
  VersionStateBadge,
  categoryLabel,
  checkMetadata,
  checkPayload,
  initialValues,
  rotationVersions,
  useSecretTypes,
  type FieldValues,
} from './secretUi';
import { SecretAccessCard } from './secretAccess';
import { LeasesCard, ProviderCard } from './secretLeases';
import { LifecycleFields, NameFields, ROTATION_STRATEGY_LABELS, SETTINGS_FIELDS, settingsBody, settingsFromSecret, validateSettings, type SettingsValues } from './secretSettings';

type DialogState =
  | null
  | { kind: 'reveal'; version?: number }
  | { kind: 'value' | 'edit' | 'activate' | 'revoke' | 'archive' | 'delete' }
  | { kind: 'rotate'; mode: RotateMode }
  | { kind: 'rollback' | 'destroy'; version: number };

/** How long revealed values stay on screen. */
const REVEAL_SECONDS = 30;

export function SecretDetailPage() {
  const { id } = useParams();
  const navigate = useNavigate();
  const toast = useToast();
  const { can } = useAuth();
  const { data: s, error, loading, reload } = useApi<SecretDetail>(`/secret/getbyid/${id}`);
  const types = useSecretTypes();
  const [dialog, setDialog] = useState<DialogState>(null);
  const [busy, setBusy] = useState(false);
  const [actionError, setActionError] = useState<ApiError | null>(null);

  if (error) return <ErrorState error={error} onRetry={reload} />;
  if (loading && !s) return <PageSkeleton />;
  if (!s) return null;

  const type = types.data?.types.find((t) => t.key === s.typeKey) ?? null;
  const fieldLabel = (name: string) => type?.fields[name]?.label ?? name;
  const metadataLabels: [string, string][] = type ? orderedFields(type.metadata).map(([k, f]) => [k, f.label]) : Object.keys(s.metadata).map((k) => [k, k]);
  const canRotate = s.can.updateValue && can(PERMISSIONS.SECRET_ROTATE) && (type?.lifecycle.rotation ?? true);
  const close = () => setDialog(null);
  const openRotate = (mode?: RotateMode) => setDialog({ kind: 'rotate', mode: mode ?? (automaticRotation(s) && s.status !== 'ROTATION_PENDING' ? 'generate' : 'manual') });
  const dynamic = s.category === 'dynamic' || !!s.provider?.capabilities.lease;

  /** Runs a lifecycle action; errors are shown on the page and in the dialog. */
  async function act(path: string, body: Record<string, unknown>, msg: string): Promise<boolean> {
    setBusy(true);
    setActionError(null);
    try {
      await api.post(path, body);
      toast.success(msg);
      setDialog(null);
      await reload();
      return true;
    } catch (e) {
      setActionError(e as ApiError);
      toast.error('Action failed', (e as Error).message);
      return false;
    } finally {
      setBusy(false);
    }
  }

  async function remove() {
    setBusy(true);
    setActionError(null);
    try {
      const r = await api.del<{ destroyedVersions: number }>(`/secret/delete/${s!.id}`);
      toast.success('Secret deleted', `${r.destroyedVersions} version(s) destroyed on the customer webhook`);
      navigate('/secrets');
    } catch (e) {
      setActionError(e as ApiError);
      toast.error('Delete failed', (e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  const versionColumns = [
    { key: 'version', header: 'Version', cell: (v: SecretVersionView) => <span className="font-medium">v{v.version}</span> },
    { key: 'state', header: 'State', cell: (v: SecretVersionView) => <VersionStateBadge state={v.state} /> },
    { key: 'fp', header: 'Fingerprint', cell: (v: SecretVersionView) => <Mono className="block max-w-[12rem] truncate">{v.fingerprint}</Mono>, hideBelow: 'lg' as const },
    {
      key: 'reason',
      header: 'Reason',
      cell: (v: SecretVersionView) => (
        <span className="text-slate-600">
          {v.reason || '—'}
          {v.copiedFrom !== null && <span className="ml-1.5 text-xs text-slate-400">(copied from v{v.copiedFrom})</span>}
        </span>
      ),
    },
    {
      key: 'created',
      header: 'Created',
      cell: (v: SecretVersionView) => (
        <span className="text-slate-500">
          {v.createdBy.name}
          <span className="block text-xs">{formatDateTime(v.createdAt)}</span>
        </span>
      ),
      hideBelow: 'md' as const,
    },
    {
      key: 'replaced',
      header: 'Replaced',
      cell: (v: SecretVersionView) => (v.supersededAt ? <span className="text-slate-500" title={formatDateTime(v.supersededAt)} data-testid="secret-version-replaced">replaced {relativeTime(v.supersededAt)}</span> : <span className="text-slate-400">—</span>),
      hideBelow: 'lg' as const,
    },
    { key: 'destroyed', header: 'Destroyed', cell: (v: SecretVersionView) => <span className="text-slate-500">{v.destroyedAt ? formatDateTime(v.destroyedAt) : '—'}</span>, hideBelow: 'xl' as const },
    {
      key: 'actions',
      header: '',
      className: 'text-right',
      cell: (v: SecretVersionView) => (
        <div className="flex justify-end gap-1" data-testid={`secret-version-actions-${v.version}`}>
          {s.can.retrieve && v.state !== 'DESTROYED' && v.state !== 'ACTIVE' && (
            <Button variant="ghost" size="sm" onClick={() => setDialog({ kind: 'reveal', version: v.version })} data-testid={`secret-version-reveal-${v.version}`}>
              <Eye className="h-3.5 w-3.5" /> Reveal
            </Button>
          )}
          {s.can.manageVersions && v.state === 'PREVIOUS' && (
            <>
              <Button variant="ghost" size="sm" onClick={() => setDialog({ kind: 'rollback', version: v.version })} data-testid={`secret-version-rollback-${v.version}`}>
                <RotateCcw className="h-3.5 w-3.5" /> Roll back
              </Button>
              <Button variant="ghost" size="sm" className="text-red-700 hover:bg-red-50 hover:text-red-800" onClick={() => setDialog({ kind: 'destroy', version: v.version })} data-testid={`secret-version-destroy-${v.version}`}>
                <Trash2 className="h-3.5 w-3.5" /> Destroy
              </Button>
            </>
          )}
        </div>
      ),
    },
  ];

  const lifecycleActions = s.can.activate || s.can.revoke || s.can.archive || s.can.delete;

  return (
    <div className="space-y-6" data-testid="secret-detail">
      <PageHeader
        title={s.name}
        badge={
          <>
            <SecretStatusBadge status={s.status} />
            {s.customType && (
              <span data-testid="secret-custom-type">
                <Badge tone="amber">Custom type</Badge>
              </span>
            )}
            {dynamic && <Badge tone="violet">Dynamic</Badge>}
          </>
        }
        description={`${s.typeName} · ${s.project}/${s.workspace} · ${s.environment}`}
        breadcrumbs={[{ label: 'Secrets', to: '/secrets' }, { label: s.name }]}
        actions={
          <>
            {s.can.retrieve && (
              <Button onClick={() => setDialog({ kind: 'reveal' })} data-testid="secret-reveal">
                <Eye className="h-4 w-4" /> Reveal
              </Button>
            )}
            {s.can.updateValue && (
              <Button variant="outline" onClick={() => setDialog({ kind: 'value' })} data-testid="secret-update-value">
                <Upload className="h-4 w-4" /> New value
              </Button>
            )}
            {canRotate && (
              <Button variant="outline" onClick={() => openRotate()} data-testid="secret-rotate">
                <RefreshCw className="h-4 w-4" /> Rotate
              </Button>
            )}
            {s.can.updateMetadata && (
              <Button variant="outline" disabled={!type} onClick={() => setDialog({ kind: 'edit' })} data-testid="secret-edit">
                <Pencil className="h-4 w-4" /> Edit metadata
              </Button>
            )}
          </>
        }
      />

      {s.status === 'PENDING' && <Callout tone="warning" title="Pending activation">The secret cannot be retrieved until it is activated.</Callout>}
      {s.status === 'EXPIRED' && <Callout tone="danger" title={`Expired ${relativeTime(s.expiresAt)}`}>Retrieval is refused (SECRET_EXPIRED). Set a future expiry with “Edit metadata” to renew it, or store a new value.</Callout>}
      {s.status === 'EXPIRING' && <Callout tone="warning" title={`Expires ${relativeTime(s.expiresAt)}`}>Rotate the secret or extend its expiry.</Callout>}
      {s.status === 'ROTATION_PENDING' && (
        <div data-testid="secret-rotation-due">
          <Callout
            tone="warning"
            title="Rotation due: store the new value to complete it"
            action={
              canRotate ? (
                <Button size="sm" onClick={() => openRotate('manual')} data-testid="secret-rotation-due-action">
                  <Upload className="h-3.5 w-3.5" /> Store new value
                </Button>
              ) : undefined
            }
          >
            {s.rotation.nextRotationAt ? `The rotation was due ${relativeTime(s.rotation.nextRotationAt)}. ` : ''}The current value keeps working until the new one is stored.
            {!canRotate && ' Members with secret:rotate and write access to this secret can complete it.'}
          </Callout>
        </div>
      )}
      {s.status === 'ROTATING' && <Callout tone="info" title="Rotation in progress">The customer webhook is creating the new value. Refresh in a moment to see the result.</Callout>}
      {s.status === 'REVOKED' && <Callout tone="danger" title="Revoked">The secret can no longer be retrieved. Archive or delete it.</Callout>}
      {s.status === 'DELETED' && <Callout tone="danger" title="Deleted">Every version was destroyed on the customer webhook. Only this record remains.</Callout>}
      <ApiErrorCallout error={actionError} />

      <div className="grid gap-6 xl:grid-cols-3">
        <Card className="xl:col-span-2">
          <CardHeader title="Metadata" />
          <CardBody>
            <DetailList
              items={[
                { label: 'Secret ID', value: <Mono>{s.id}</Mono> },
                {
                  label: 'Type',
                  value: (
                    <span>
                      {s.typeName} <span className="text-slate-500">· {categoryLabel(s.category)}</span>
                    </span>
                  ),
                },
                { label: 'Project / workspace', value: <span className="font-mono text-[13px]">{s.project}/{s.workspace}</span> },
                { label: 'Environment', value: <EnvBadge env={s.environment} /> },
                { label: 'Description', value: s.description || '—' },
                {
                  label: 'Tags',
                  value: s.tags.length ? (
                    <div className="flex flex-wrap gap-1">
                      {s.tags.map((t) => (
                        <Badge key={t}>{t}</Badge>
                      ))}
                    </div>
                  ) : (
                    '—'
                  ),
                },
                ...metadataLabels.map(([k, label]) => ({
                  label,
                  value: s.metadata[k] === undefined ? '—' : typeof s.metadata[k] === 'object' ? JSON.stringify(s.metadata[k]) : String(s.metadata[k]),
                })),
                { label: 'Integration', value: s.integrationId ? <Link className="text-brand-700 hover:underline" to={`/integrations/${s.integrationId}`}>{s.integrationId}</Link> : '—' },
                { label: 'Created', value: `${formatDateTime(s.createdAt)} by ${s.createdBy.name}` },
                { label: 'Updated', value: `${formatDateTime(s.updatedAt)} by ${s.updatedBy.name}` },
              ]}
            />
          </CardBody>
        </Card>

        <div className="space-y-6">
          <Card data-testid="secret-summary">
            <CardHeader title="Active version" description="Sensitive fields are masked. Reveal to see the value." icon={<KeyRound className="h-4 w-4" />} />
            <CardBody className="space-y-4">
              {dynamic && (
                <p className="rounded-md border border-violet-200 bg-violet-50 px-3 py-2 text-xs text-violet-900" data-testid="secret-dynamic-note">
                  This is the administrative credential leases are created with; applications never receive it.
                </p>
              )}
              {s.activeVersion === null ? (
                <p className="text-sm text-slate-500">No active version.</p>
              ) : (
                <>
                  <DetailList
                    columns={1}
                    items={[
                      { label: 'Version', value: `v${s.activeVersion}` },
                      ...Object.entries(s.summary).map(([k, v]) => ({ label: fieldLabel(k), value: <span className="font-mono text-[13px]" data-testid={`secret-summary-${k}`}>{v}</span> })),
                      { label: 'Fingerprint', value: s.fingerprint ? <Mono className="break-all">{s.fingerprint}</Mono> : '—' },
                    ]}
                  />
                </>
              )}
            </CardBody>
          </Card>
          <Card>
            <CardHeader title="Expiry" icon={<Timer className="h-4 w-4" />} />
            <CardBody className="space-y-4">
              <DetailList
                columns={1}
                items={[
                  { label: 'Expires', value: s.expiresAt ? `${formatDateTime(s.expiresAt)} (${relativeTime(s.expiresAt)})` : 'Never' },
                  { label: 'Last retrieved', value: relativeTime(s.lastRetrievedAt) },
                ]}
              />
              <PolicyInfo policy={s.policy} />
            </CardBody>
          </Card>
          {lifecycleActions && (
            <Card>
              <CardHeader title="Lifecycle" />
              <CardBody className="flex flex-wrap gap-2">
                {s.can.activate && (
                  <Button variant="outline" onClick={() => setDialog({ kind: 'activate' })} data-testid="secret-activate">
                    <PlayCircle className="h-4 w-4" /> Activate
                  </Button>
                )}
                {s.can.archive && (
                  <Button variant="outline" onClick={() => setDialog({ kind: 'archive' })} data-testid="secret-archive">
                    <Archive className="h-4 w-4" /> Archive
                  </Button>
                )}
                {s.can.revoke && (
                  <Button variant="danger-outline" onClick={() => setDialog({ kind: 'revoke' })} data-testid="secret-revoke">
                    <ShieldOff className="h-4 w-4" /> Revoke
                  </Button>
                )}
                {s.can.delete && (
                  <Button variant="danger" onClick={() => setDialog({ kind: 'delete' })} data-testid="secret-delete">
                    <Trash2 className="h-4 w-4" /> Delete
                  </Button>
                )}
              </CardBody>
            </Card>
          )}
        </div>
      </div>

      {s.provider && <ProviderCard secret={s} onChanged={reload} />}
      {s.provider?.capabilities.lease && <LeasesCard secret={s} onChanged={reload} />}

      <RotationCard secret={s} canRotate={canRotate} canEdit={s.can.updateMetadata && !!type} onRotate={openRotate} onEdit={() => setDialog({ kind: 'edit' })} />

      <Card>
        <CardHeader title="Versions" description="Every value the secret has had. Versions are told apart by fingerprint; values are never listed." />
        <div data-testid="secret-versions">
          <DataTable rows={[...s.versions].sort((a, b) => b.version - a.version)} rowKey={(v) => v.id} columns={versionColumns} dense />
        </div>
      </Card>

      <SecretAccessCard key={s.id} secret={s} types={types.data?.types ?? []} />

      {/* Dialogs: keyed by secret, so nothing typed or revealed survives a change of page. */}
      {dialog?.kind === 'reveal' && <RevealDialog key={`${s.id}-${dialog.version ?? 'active'}`} secret={s} type={type} version={dialog.version} onClose={close} />}
      {(dialog?.kind === 'value' || dialog?.kind === 'rotate') && (
        <ValueDialog
          key={s.id}
          secret={s}
          type={type}
          rotate={dialog.kind === 'rotate'}
          initialMode={dialog.kind === 'rotate' ? dialog.mode : 'manual'}
          onClose={close}
          onDone={async (msg) => {
            toast.success(msg);
            setDialog(null);
            setActionError(null);
            await reload();
          }}
        />
      )}
      {dialog?.kind === 'edit' && type && (
        <EditMetadataDialog
          key={s.id}
          secret={s}
          type={type}
          onClose={close}
          onDone={async () => {
            toast.success('Metadata updated');
            setDialog(null);
            setActionError(null);
            await reload();
          }}
        />
      )}
      {dialog?.kind === 'activate' && <ReasonDialog title="Activate secret" description="The secret becomes Active and can be retrieved." confirmLabel="Activate" tone="primary" loading={busy} error={actionError} onClose={close} onConfirm={(reason) => act('/secret/activate', { id: s.id, reason }, 'Secret activated')} />}
      {dialog?.kind === 'archive' && <ReasonDialog title="Archive secret" description="Archived secrets are kept for the record and cannot be retrieved." confirmLabel="Archive" tone="primary" loading={busy} error={actionError} onClose={close} onConfirm={(reason) => act('/secret/archive', { id: s.id, reason }, 'Secret archived')} />}
      {dialog?.kind === 'revoke' && (
        <ReasonDialog title="Revoke secret" description={<>Every retrieval of <strong>{s.name}</strong> is refused from now on. This cannot be undone; store a new secret to replace it.</>} confirmLabel="Revoke" tone="danger" reasonLabel="Reason (recorded in the audit log)" loading={busy} error={actionError} onClose={close} onConfirm={(reason) => act('/secret/revoke', { id: s.id, reason }, 'Secret revoked')} />
      )}
      {dialog?.kind === 'rollback' && (
        <ReasonDialog title={`Roll back to version ${dialog.version}`} description={`A new active version is created with the value of v${dialog.version}. The current version is kept as a previous version.`} confirmLabel="Roll back" tone="primary" loading={busy} error={actionError} onClose={close} onConfirm={(reason) => act('/secret/rollback', { id: s.id, version: dialog.version, reason }, `Rolled back to the value of v${dialog.version}`)} />
      )}
      {dialog?.kind === 'destroy' && (
        <ReasonDialog title={`Destroy version ${dialog.version}`} description={`The value of v${dialog.version} is destroyed on the customer webhook and can never be retrieved or rolled back to. Its fingerprint stays in the history.`} confirmLabel="Destroy version" tone="danger" loading={busy} error={actionError} onClose={close} onConfirm={(reason) => act('/secret/destroyVersion', { id: s.id, version: dialog.version, reason }, `Version ${dialog.version} destroyed`)} />
      )}
      {dialog?.kind === 'delete' && (
        <ConfirmDialog
          open
          onClose={close}
          onConfirm={() => void remove()}
          loading={busy}
          title="Delete secret"
          confirmLabel="Delete secret"
          confirmText={s.name}
          description={
            <div className="space-y-2" data-testid="secret-delete-dialog">
              <p>
                Every version of <strong>{s.name}</strong> ({s.versions.filter((v) => v.state !== 'DESTROYED').length} stored) is destroyed on your customer webhook. The values cannot be recovered.
              </p>
              <p>A deleted record remains for the audit trail.</p>
              <ApiErrorCallout error={actionError} />
            </div>
          }
        />
      )}
    </div>
  );
}

// ── dialogs ──────────────────────────────────────────────────────

function ReasonDialog({ title, description, confirmLabel, tone, reasonLabel = 'Reason (optional)', loading, error, onClose, onConfirm }: { title: string; description: React.ReactNode; confirmLabel: string; tone: 'danger' | 'primary'; reasonLabel?: string; loading: boolean; error: ApiError | null; onClose: () => void; onConfirm: (reason: string) => void }) {
  const [reason, setReason] = useState('');
  return (
    <ConfirmDialog open onClose={onClose} onConfirm={() => onConfirm(reason.trim())} title={title} description={description} confirmLabel={confirmLabel} tone={tone} loading={loading}>
      <div className="space-y-3" data-testid="secret-confirm-dialog">
        <Field label={reasonLabel} htmlFor="secret-action-reason">
          <Textarea id="secret-action-reason" rows={2} maxLength={300} value={reason} onChange={(e) => setReason(e.target.value)} data-testid="secret-action-reason" />
        </Field>
        <ApiErrorCallout error={error} />
      </div>
    </ConfirmDialog>
  );
}

/**
 * Reveal with confirmation: asks for a reason and the fields wanted, then shows the values for
 * REVEAL_SECONDS. Values live only in this component's state and are dropped on close, on timeout
 * and on unmount (navigation).
 */
function RevealDialog({ secret, type, version, onClose }: { secret: SecretDetail; type: SecretTypeInfo | null; version?: number; onClose: () => void }) {
  const fields = type ? orderedFields(type.fields) : [];
  const [reason, setReason] = useState('');
  const [selected, setSelected] = useState<string[]>(() => fields.map(([k]) => k));
  const [result, setResult] = useState<SecretRetrieval | null>(null);
  const [left, setLeft] = useState(REVEAL_SECONDS);
  const [masked, setMasked] = useState<Record<string, boolean>>({});
  const retrieve = useMutation((body: unknown) => api.post<SecretRetrieval>('/secret/retrieve', body));

  useEffect(() => {
    if (!result) return;
    setLeft(REVEAL_SECONDS);
    const t = setInterval(() => setLeft((n) => n - 1), 1000);
    return () => clearInterval(t);
  }, [result]);
  useEffect(() => {
    if (result && left <= 0) {
      setResult(null);
      onClose();
    }
  }, [left, result, onClose]);

  function close() {
    setResult(null);
    onClose();
  }

  async function reveal() {
    const all = selected.length === fields.length;
    const r = await retrieve.run({ id: secret.id, ...(version ? { version } : {}), ...(!all && selected.length ? { fields: selected } : {}), reason: reason.trim() });
    if (r) setResult(r);
  }

  const label = (k: string) => type?.fields[k]?.label ?? k;
  return (
    <Dialog
      open
      onClose={close}
      size="lg"
      title={
        <span className="flex items-center gap-2">
          <Eye className="h-5 w-5 text-brand-600" /> {result ? `${secret.name} · v${result.version}` : `Reveal ${secret.name}${version ? ` · v${version}` : ''}`}
        </span>
      }
      description={result ? `Hidden again in ${left} s.` : 'Revealing a value is recorded in the audit log with your name and reason.'}
      footer={
        result ? (
          <Button onClick={close} data-testid="secret-reveal-hide">
            <EyeOff className="h-4 w-4" /> Hide now
          </Button>
        ) : (
          <>
            <Button variant="outline" onClick={close}>
              Cancel
            </Button>
            <Button loading={retrieve.pending} disabled={!!fields.length && !selected.length} onClick={reveal} data-testid="secret-reveal-confirm">
              <Eye className="h-4 w-4" /> Reveal value
            </Button>
          </>
        )
      }
    >
      <div className="space-y-4" data-testid="secret-reveal-dialog">
        {result ? (
          <div className="space-y-3" data-testid="secret-revealed-values">
            {Object.entries(result.payload).map(([k, v]) => {
              const sensitive = type?.fields[k]?.sensitive ?? true;
              const hidden = masked[k] ?? false;
              return (
                <div key={k} className="rounded-lg border border-slate-200 bg-slate-50 p-3" data-testid={`secret-value-${k}`}>
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-xs font-medium uppercase tracking-wide text-slate-500">
                      {label(k)}
                      {sensitive && <Badge tone="amber" className="ml-2 normal-case">sensitive</Badge>}
                    </span>
                    <div className="flex gap-2">
                      <Button variant="ghost" size="sm" onClick={() => setMasked((m) => ({ ...m, [k]: !hidden }))}>
                        {hidden ? 'Show' : 'Hide'}
                      </Button>
                      <CopyButton value={typeof v === 'object' ? JSON.stringify(v, null, 2) : String(v)} />
                    </div>
                  </div>
                  {typeof v === 'object' ? (
                    <div className="mt-2 space-y-1">
                      {Object.entries(v).map(([name, x]) => (
                        <div key={name} className="flex items-center justify-between gap-2">
                          <code className="min-w-0 break-all font-mono text-[13px] text-slate-900">
                            {name}={hidden ? '••••••••' : x}
                          </code>
                          <CopyButton value={x} />
                        </div>
                      ))}
                    </div>
                  ) : (
                    <code className="mt-2 block whitespace-pre-wrap break-all font-mono text-[13px] text-slate-900" data-testid={`secret-value-text-${k}`}>
                      {hidden ? '••••••••' : String(v)}
                    </code>
                  )}
                </div>
              );
            })}
            <p className="text-xs text-slate-500">Retrieved {formatDateTime(result.retrievedAt)}. Copied values stay on your clipboard; clear it when done.</p>
          </div>
        ) : (
          <>
            <Callout tone="security">The value is fetched from your customer webhook and shown for {REVEAL_SECONDS} seconds. It is not stored in this browser.</Callout>
            <Field label="Reason (optional)" htmlFor="secret-reveal-reason" hint="Recorded in the audit log.">
              <Textarea id="secret-reveal-reason" rows={2} maxLength={300} value={reason} onChange={(e) => setReason(e.target.value)} data-testid="secret-reveal-reason" />
            </Field>
            {fields.length > 1 && (
              <div className="space-y-2" data-testid="secret-reveal-fields">
                <p className="text-sm font-medium text-slate-700">Fields to reveal</p>
                <div className="grid gap-2 sm:grid-cols-2">
                  {fields.map(([k, f]) => (
                    <Checkbox key={k} id={`reveal-field-${k}`} checked={selected.includes(k)} onChange={(c) => setSelected((xs) => (c ? [...xs, k] : xs.filter((x) => x !== k)))} label={f.label} description={f.sensitive ? 'Sensitive' : undefined} />
                  ))}
                </div>
              </div>
            )}
            <ApiErrorCallout error={retrieve.error} />
          </>
        )}
      </div>
    </Dialog>
  );
}

/**
 * New value, or rotation. A rotation either takes the new value typed here, or (types with generated
 * fields) asks the customer webhook to create it. A typed value is cleared after submit and on close.
 */
function ValueDialog({ secret, type, rotate, initialMode, onClose, onDone }: { secret: SecretDetail; type: SecretTypeInfo | null; rotate: boolean; initialMode: RotateMode; onClose: () => void; onDone: (msg: string) => void }) {
  const [values, setValues] = useState<FieldValues>(() => (type ? initialValues(type.fields) : {}));
  const [reason, setReason] = useState('');
  const [errors, setErrors] = useState<Record<string, string>>({});
  // The automatic option: at the provider, or generated by the webhook.
  const auto = rotate ? automaticRotation(secret) : null;
  const canGenerate = auto !== null;
  const [mode, setMode] = useState<RotateMode>(canGenerate ? initialMode : 'manual');
  const generate = canGenerate && mode === 'generate';
  const submit = useMutation((body: unknown) => api.post<SecretDetail>(rotate ? '/secret/rotate' : '/secret/updateValue', body));
  const allErrors = { ...submit.fieldErrors, ...errors };
  const nextVersion = (Math.max(0, ...secret.versions.map((v) => v.version)) || 0) + 1;

  async function onSubmit() {
    if (generate) {
      const r = await submit.run({ id: secret.id, reason: reason.trim() });
      if (r) onDone(auto === 'provider' ? `Secret rotated at the provider. Version ${r.activeVersion ?? nextVersion} is the new credential.` : `Secret rotated. The webhook generated version ${r.activeVersion ?? nextVersion}.`);
      return;
    }
    if (!type) return;
    const p = checkPayload(type, values);
    setErrors(p.issues);
    if (Object.keys(p.issues).length) return;
    const r = await submit.run({ id: secret.id, payload: p.value, reason: reason.trim() });
    if (r) {
      setValues(initialValues(type.fields));
      onDone(rotate ? 'Secret rotated' : 'New value stored');
    }
  }

  return (
    <Dialog
      open
      onClose={onClose}
      size="lg"
      title={rotate ? `Rotate ${secret.name}` : `New value for ${secret.name}`}
      description={`The new value becomes version ${nextVersion} and the active one. The current version is kept as a previous version${rotate && secret.rotation.graceHours > 0 ? ` and stays usable for ${secret.rotation.graceHours} hours` : ''}.`}
      footer={
        <>
          <Button variant="outline" onClick={onClose}>
            Cancel
          </Button>
          <Button loading={submit.pending} disabled={!generate && !type} onClick={onSubmit} data-testid={rotate ? 'secret-rotate-confirm' : 'secret-value-submit'}>
            {generate && auto === 'provider' ? (
              <>
                <RefreshCw className="h-4 w-4" /> Rotate at the provider
              </>
            ) : generate ? (
              <>
                <Sparkles className="h-4 w-4" /> Generate and rotate
              </>
            ) : rotate ? (
              'Rotate'
            ) : (
              'Store new value'
            )}
          </Button>
        </>
      }
    >
      <form
        className="space-y-4"
        data-testid="secret-value-form"
        autoComplete="off"
        onSubmit={(e) => {
          e.preventDefault();
          void onSubmit();
        }}
      >
        {canGenerate && (
          <div className="grid gap-2 sm:grid-cols-2" data-testid="secret-rotate-mode" data-mode={mode}>
            <div data-testid="secret-rotate-generate">
              {auto === 'provider' ? (
                <div data-testid="secret-rotate-provider">
                  <RadioCard checked={mode === 'generate'} onChange={() => setMode('generate')} title="Change it at the provider" description="The customer webhook sets a new credential where it is used, checks it works, then stores it. Nobody sees it." />
                </div>
              ) : (
                <RadioCard checked={mode === 'generate'} onChange={() => setMode('generate')} title="Generate a new value" description="The customer webhook creates the new value. Nobody sees it." />
              )}
            </div>
            <div data-testid="secret-rotate-manual">
              <RadioCard checked={mode === 'manual'} onChange={() => setMode('manual')} title="Enter the new value" description="Type the value you already changed at its source." />
            </div>
          </div>
        )}
        {generate && auto === 'provider' ? (
          <Callout tone="security">The webhook changes the credential at the provider, connects with the new one to check it works, then stores it as the new version. If any step fails, the current credential keeps working and nothing changes here.</Callout>
        ) : generate ? (
          <Callout tone="security">The webhook generates the new value of the generated fields; the other fields keep their current values. If the webhook cannot do it, nothing changes.</Callout>
        ) : !type ? (
          <Callout tone="warning">The secret type {secret.typeKey} is not available, so its form cannot be shown.</Callout>
        ) : (
          <TypeFields prefix="payload" fields={type.fields} values={values} onChange={setValues} errors={allErrors} />
        )}
        <Field label="Reason (optional)" htmlFor="secret-value-reason" error={allErrors.reason}>
          <Textarea id="secret-value-reason" rows={2} maxLength={300} value={reason} onChange={(e) => setReason(e.target.value)} placeholder={rotate ? 'Scheduled rotation' : 'Password changed on the database'} />
        </Field>
        <ApiErrorCallout error={submit.error} shownFields={['reason']} />
      </form>
    </Dialog>
  );
}

// ── rotation and policy ──────────────────────────────────────────

/** `generate` is the automatic option, whichever it is (see automaticRotation). */
type RotateMode = 'generate' | 'manual';

/**
 * How "Rotate now" without a typed value works for this secret, as the server decides it: at the
 * provider when that is the strategy (or the only automatic way), else generated by the webhook.
 */
function automaticRotation(s: SecretDetail): 'provider' | 'generated' | null {
  const r = s.rotation;
  if (r.providerRotation && (r.strategy === 'provider' || !r.generatable)) return 'provider';
  if (r.generatable) return 'generated';
  return null;
}

function RotationCard({ secret: s, canRotate, canEdit, onRotate, onEdit }: { secret: SecretDetail; canRotate: boolean; canEdit: boolean; onRotate: (mode?: RotateMode) => void; onEdit: () => void }) {
  const r = s.rotation;
  const strategy = ROTATION_STRATEGY_LABELS[r.strategy];
  const columns: Column<SecretRotationJobView>[] = [
    {
      key: 'when',
      header: 'When',
      cell: (j) => (
        <div className="whitespace-nowrap" data-testid="secret-rotation-job-row" data-status={j.status} data-trigger={j.trigger}>
          <span className="block text-slate-700" title={formatDateTime(j.finishedAt ?? j.startedAt ?? j.scheduledFor)}>
            {relativeTime(j.finishedAt ?? j.startedAt ?? j.scheduledFor)}
          </span>
          {j.requestedBy && <span className="block text-xs text-slate-500">by {j.requestedBy.name}</span>}
        </div>
      ),
    },
    { key: 'trigger', header: 'Trigger', cell: (j) => <span className="text-slate-600">{ROTATION_TRIGGER_LABELS[j.trigger] ?? j.trigger}</span>, hideBelow: 'md' },
    { key: 'strategy', header: 'Strategy', cell: (j) => <span className="text-slate-600">{ROTATION_STRATEGY_SHORT[j.strategy] ?? j.strategy}</span>, hideBelow: 'lg' },
    { key: 'status', header: 'Status', cell: (j) => <RotationJobStatusBadge job={j} /> },
    { key: 'versions', header: 'Versions', cell: (j) => <span className="whitespace-nowrap font-mono text-[13px] text-slate-600">{rotationVersions(j)}</span> },
    { key: 'attempts', header: 'Attempts', cell: (j) => <span className="text-slate-600">{j.attempts}</span>, hideBelow: 'lg' },
    {
      key: 'error',
      header: 'Error',
      cell: (j) =>
        j.errorMessage || j.errorCode ? (
          <span className="block max-w-xs break-words text-xs text-red-700">
            {j.errorMessage}
            {j.errorCode && <span className="ml-1 font-mono opacity-70">({j.errorCode})</span>}
            {j.nextAttemptAt && j.status === 'PENDING' && <span className="block text-slate-500">next attempt {relativeTime(j.nextAttemptAt)}</span>}
          </span>
        ) : (
          <span className="text-slate-400">—</span>
        ),
      hideBelow: 'md',
    },
  ];
  return (
    <Card data-testid="secret-rotation-card" data-enabled={r.enabled ? 'true' : 'false'} data-strategy={r.strategy}>
      <CardHeader
        title="Rotation"
        description={r.enabled ? `Rotated every ${r.intervalDays} days.` : 'No scheduled rotation. The secret can still be rotated now.'}
        icon={<RefreshCw className="h-4 w-4" />}
        actions={
          <>
            {canEdit && (
              <Button variant="outline" size="sm" onClick={onEdit} data-testid="secret-rotation-edit">
                <Pencil className="h-3.5 w-3.5" /> Edit
              </Button>
            )}
            {canRotate && (
              <Button size="sm" onClick={() => onRotate()} data-testid="secret-rotate-now">
                <RefreshCw className="h-3.5 w-3.5" /> Rotate now
              </Button>
            )}
          </>
        }
      />
      <CardBody>
        <DetailList
          columns={3}
          items={[
            { label: 'Scheduled rotation', value: r.enabled ? `Every ${r.intervalDays} days` : 'Off' },
            {
              label: 'Strategy',
              value: (
                <span data-testid="secret-rotation-strategy-value" data-strategy={r.strategy}>
                  {strategy.label}: {strategy.description.charAt(0).toLowerCase() + strategy.description.slice(1, -1)}
                  {!r.generatable && !r.providerRotation && <span className="block text-xs text-slate-500">The webhook cannot generate values of this type or change them at the provider.</span>}
                  {r.providerRotation && r.strategy !== 'provider' && <span className="block text-xs text-slate-500">Rotation at the provider is available: choose it with “Edit”.</span>}
                </span>
              ),
            },
            { label: 'Grace period', value: r.graceHours === 0 ? 'None. The replaced version stops working at once.' : `${r.graceHours} hours after a rotation` },
            { label: 'Next rotation', value: r.enabled && r.nextRotationAt ? <span title={formatDateTime(r.nextRotationAt)}>{`${formatDateTime(r.nextRotationAt)} (${relativeTime(r.nextRotationAt)})`}</span> : '—' },
            { label: 'Last rotated', value: r.lastRotatedAt ? <span title={formatDateTime(r.lastRotatedAt)}>{relativeTime(r.lastRotatedAt)}</span> : 'Never' },
          ]}
        />
      </CardBody>
      <div className="border-t border-slate-100" data-testid="secret-rotation-history">
        <p className="px-5 pt-4 text-sm font-medium text-slate-700">Rotation history</p>
        <DataTable rows={s.rotationJobs} rowKey={(j) => j.id} columns={columns} dense empty={<p className="px-5 py-6 text-sm text-slate-500">This secret has not been rotated yet.</p>} />
      </div>
    </Card>
  );
}

function policyValue(key: keyof EffectiveSecretPolicy, v: number | null): string {
  if (v === null) return key === 'defaultExpiresInDays' ? 'No default expiry' : 'No limit';
  switch (key) {
    case 'expiryWarningDays':
      return `${v} days before expiry`;
    case 'defaultExpiresInDays':
      return `${v} days`;
    case 'keepVersions':
      return `Newest ${v}`;
    case 'keepDays':
      return `Replaced in the last ${v} days`;
  }
}

/** The expiry warning and version retention that apply to this secret, and the level each comes from. */
function PolicyInfo({ policy }: { policy: EffectiveSecretPolicy }) {
  const rows: [keyof EffectiveSecretPolicy, string][] = [
    ['expiryWarningDays', 'Expiry warning'],
    ['defaultExpiresInDays', 'Default expiry'],
    ['keepVersions', 'Keep versions'],
    ['keepDays', 'Keep versions by age'],
  ];
  return (
    <div className="border-t border-slate-100 pt-4" data-testid="secret-policy-info">
      <div className="mb-2 flex items-center justify-between gap-2">
        <p className="text-sm font-medium text-slate-700">Expiry and retention</p>
        <Link className="text-xs text-brand-700 hover:underline" to="/secrets/policies">
          Policies
        </Link>
      </div>
      <dl className="space-y-2">
        {rows.map(([k, label]) => (
          <div key={k} className="flex items-start justify-between gap-3 text-sm" data-testid={`secret-policy-info-${k}`} data-source={policy[k].source}>
            <dt className="text-slate-500">{label}</dt>
            <dd className="text-right text-slate-800">
              {policy[k].source === 'NONE' ? <span className="text-slate-400">Not set</span> : policyValue(k, policy[k].value)}
              <span className="block text-xs text-slate-400">{POLICY_SOURCE_LABELS[policy[k].source] ?? policy[k].source}</span>
            </dd>
          </div>
        ))}
      </dl>
    </div>
  );
}

function EditMetadataDialog({ secret, type, onClose, onDone }: { secret: SecretDetail; type: SecretTypeInfo; onClose: () => void; onDone: () => void }) {
  const original = settingsFromSecret(secret);
  const [settings, setSettings] = useState<SettingsValues>(original);
  const [metadata, setMetadata] = useState<FieldValues>(() => initialValues(type.metadata, secret.metadata));
  const [errors, setErrors] = useState<Record<string, string>>({});
  const submit = useMutation((body: unknown) => api.post<SecretDetail>('/secret/save', body));
  const allErrors = { ...submit.fieldErrors, ...errors };
  const expiryUnchanged = settings.expiresAt === original.expiresAt;

  async function onSubmit() {
    const m = checkMetadata(type, metadata);
    const e = { ...validateSettings(type, settings, { allowPastExpiry: expiryUnchanged }), ...m.issues };
    setErrors(e);
    if (Object.keys(e).length) return;
    const body = settingsBody(settings);
    const r = await submit.run({
      id: secret.id,
      ...body,
      // An unchanged expiry may be in the past (an expired secret): leave it as it is.
      expiresAt: expiryUnchanged ? undefined : body.expiresAt,
      rotationEnabled: type.lifecycle.rotation ? body.rotationEnabled : false,
      metadata: m.value,
    });
    if (r) onDone();
  }

  return (
    <Dialog
      open
      onClose={onClose}
      size="lg"
      title={`Edit ${secret.name}`}
      description="Metadata changes do not create a new version. The type, scope and value cannot be changed here."
      footer={
        <>
          <Button variant="outline" onClick={onClose}>
            Cancel
          </Button>
          <Button loading={submit.pending} onClick={onSubmit} data-testid="secret-edit-submit">
            Save changes
          </Button>
        </>
      }
    >
      <form
        className="space-y-5"
        data-testid="secret-edit-form"
        onSubmit={(e) => {
          e.preventDefault();
          void onSubmit();
        }}
      >
        <NameFields value={settings} onChange={setSettings} errors={allErrors} />
        {Object.keys(type.metadata).length > 0 && <TypeFields prefix="metadata" fields={type.metadata} values={metadata} onChange={setMetadata} errors={allErrors} />}
        <LifecycleFields type={type} value={settings} onChange={setSettings} errors={allErrors} providerRotation={secret.rotation.providerRotation} />
        <ApiErrorCallout error={submit.error} shownFields={SETTINGS_FIELDS} />
      </form>
    </Dialog>
  );
}
