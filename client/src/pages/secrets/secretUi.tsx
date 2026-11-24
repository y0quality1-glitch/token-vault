import { useMemo, useState, type ReactNode } from 'react';
import { Archive, Eye, EyeOff, Plus, Search, ShieldOff, TimerOff, Trash2, X } from 'lucide-react';
import {
  SECRET_CATEGORY_LABELS,
  orderedFields,
  validateSecretMetadata,
  validateSecretPayload,
  type SecretCategory,
  type SecretPayload,
  type SecretLeaseStatus,
  type SecretPolicySource,
  type SecretProviderCapabilities,
  type SecretRotationJobStatus,
  type SecretRotationJobView,
  type SecretRotationStrategy,
  type SecretRotationTrigger,
  type SecretStatus,
  type SecretTypeInfo,
  type SecretTypesResponse,
  type SecretVersionState,
} from '@token-vault/shared';
import { useQuery } from '@/hooks/useApi';
import { api, type ApiError } from '@/lib/api';
import { cn } from '@/lib/utils';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Callout } from '@/components/ui/feedback';
import { Checkbox, Field, Input, Select, Textarea } from '@/components/ui/form';

/**
 * Shared pieces of the Secrets section: status badges, the secret type list, and the form
 * generated from a secret type (payload and metadata fields). Values typed here stay in the
 * owning component's state only; they are never written to a global store or browser storage.
 */

// ── status ───────────────────────────────────────────────────────

type Tone = 'green' | 'red' | 'amber' | 'blue' | 'gray' | 'violet';
export const SECRET_STATUS_META: Record<SecretStatus, { label: string; tone: Tone; icon?: ReactNode; className?: string }> = {
  PENDING: { label: 'Pending', tone: 'amber' },
  ACTIVE: { label: 'Active', tone: 'green' },
  EXPIRING: { label: 'Expiring', tone: 'amber' },
  EXPIRED: { label: 'Expired', tone: 'red', icon: <TimerOff className="h-3 w-3" /> },
  ROTATION_PENDING: { label: 'Rotation pending', tone: 'blue' },
  ROTATING: { label: 'Rotating', tone: 'violet' },
  REVOKED: { label: 'Revoked', tone: 'red', icon: <ShieldOff className="h-3 w-3" />, className: 'bg-red-600 text-white ring-red-700' },
  ARCHIVED: { label: 'Archived', tone: 'gray', icon: <Archive className="h-3 w-3" /> },
  DELETED: { label: 'Deleted', tone: 'gray', icon: <Trash2 className="h-3 w-3" />, className: 'bg-slate-700 text-white ring-slate-800 line-through decoration-slate-400' },
};

export function SecretStatusBadge({ status }: { status: SecretStatus }) {
  const m = SECRET_STATUS_META[status] ?? { label: status, tone: 'gray' as Tone };
  return (
    <span data-testid="secret-status" data-status={status}>
      <Badge tone={m.tone} dot={!m.icon} className={m.className}>
        {m.icon}
        {m.label}
      </Badge>
    </span>
  );
}

const VERSION_TONES: Record<SecretVersionState, Tone> = { ACTIVE: 'green', PREVIOUS: 'gray', DESTROYED: 'red' };
export function VersionStateBadge({ state }: { state: SecretVersionState }) {
  return <Badge tone={VERSION_TONES[state]}>{state.charAt(0) + state.slice(1).toLowerCase()}</Badge>;
}

// ── rotation and policies ────────────────────────────────────────

const ROTATION_JOB_STATUS: Record<SecretRotationJobStatus, { label: string; tone: Tone }> = {
  PENDING: { label: 'Pending', tone: 'amber' },
  RUNNING: { label: 'Running', tone: 'violet' },
  WAITING_FOR_VALUE: { label: 'Waiting for value', tone: 'blue' },
  SUCCEEDED: { label: 'Succeeded', tone: 'green' },
  FAILED: { label: 'Failed', tone: 'red' },
  CANCELLED: { label: 'Cancelled', tone: 'gray' },
};

export function RotationJobStatusBadge({ job }: { job: Pick<SecretRotationJobView, 'status' | 'attempts'> }) {
  const m = ROTATION_JOB_STATUS[job.status] ?? { label: job.status, tone: 'gray' as Tone };
  // A pending job that has already been tried is waiting for its next attempt.
  const label = job.status === 'PENDING' && job.attempts > 0 ? 'Retrying' : m.label;
  return (
    <span data-testid="rotation-job-status" data-status={job.status}>
      <Badge tone={m.tone} dot>
        {label}
      </Badge>
    </span>
  );
}

// ── providers, leases and type sources ──────────────────────────

const LEASE_STATUS: Record<SecretLeaseStatus, { label: string; tone: Tone }> = {
  ACTIVE: { label: 'Active', tone: 'green' },
  EXPIRED: { label: 'Expired', tone: 'gray' },
  REVOKED: { label: 'Ended', tone: 'gray' },
  REVOKE_FAILED: { label: 'Cleanup pending', tone: 'amber' },
};

export function LeaseStatusBadge({ status }: { status: SecretLeaseStatus }) {
  const m = LEASE_STATUS[status] ?? { label: status, tone: 'gray' as Tone };
  return (
    <span data-testid="lease-status" data-status={status}>
      <Badge tone={m.tone} dot>
        {m.label}
      </Badge>
    </span>
  );
}

const CAPABILITY_LABELS: [keyof SecretProviderCapabilities, string, string][] = [
  ['lease', 'Leases', 'Issues short-lived credentials'],
  ['renew', 'Renew', 'Lengthens a lease at the provider'],
  ['revoke', 'Revoke', 'Ends a lease early at the provider'],
  ['rotate', 'Rotate', 'Changes the stored credential at the provider'],
  ['check', 'Health check', 'Connects and checks the stored credential works'],
];

/** What the customer webhook can do at the provider, as small badges. */
export function ProviderCapabilityBadges({ capabilities, className }: { capabilities: SecretProviderCapabilities; className?: string }) {
  const on = CAPABILITY_LABELS.filter(([k]) => capabilities[k]);
  return (
    <span className={cn('inline-flex flex-wrap gap-1', className)} data-testid="provider-capabilities">
      {on.map(([k, label, title]) => (
        <span key={k} title={title} data-capability={k}>
          <Badge tone="violet">{label}</Badge>
        </span>
      ))}
    </span>
  );
}

const TYPE_SOURCE: Record<SecretTypeInfo['source'], { label: string; tone: Tone }> = {
  catalog: { label: 'Catalog', tone: 'blue' },
  bundled: { label: 'Predefined', tone: 'gray' },
  custom: { label: 'Custom', tone: 'amber' },
};

export function TypeSourceBadge({ source }: { source: SecretTypeInfo['source'] }) {
  const m = TYPE_SOURCE[source] ?? { label: source, tone: 'gray' as Tone };
  return (
    <span data-testid="secret-type-source" data-source={source}>
      <Badge tone={m.tone}>{m.label}</Badge>
    </span>
  );
}

/** Custom types in the list response say whether they are archived (no new secrets of them). */
export function isArchivedType(t: SecretTypeInfo): boolean {
  return (t as SecretTypeInfo & { archived?: boolean }).archived === true;
}

export const ROTATION_TRIGGER_LABELS: Record<SecretRotationTrigger, string> = { SCHEDULED: 'Scheduled', MANUAL: 'Rotate now', EXPIRY: 'Expiry' };
export const ROTATION_STRATEGY_SHORT: Record<SecretRotationStrategy, string> = { manual: 'Manual', generated: 'Generated', provider: 'At the provider' };

/** `v3 → v4`, `v3 → …` while the new value is not stored yet. */
export function rotationVersions(j: Pick<SecretRotationJobView, 'fromVersion' | 'toVersion'>): string {
  if (j.fromVersion === null && j.toVersion === null) return '—';
  return `${j.fromVersion !== null ? `v${j.fromVersion}` : '—'} → ${j.toVersion !== null ? `v${j.toVersion}` : '…'}`;
}

export const POLICY_SOURCE_LABELS: Record<SecretPolicySource, string> = {
  TYPE: 'Type default',
  ORGANIZATION: 'Organization',
  PROJECT: 'Project',
  WORKSPACE: 'Workspace',
  NONE: 'Not set',
};

// ── types ────────────────────────────────────────────────────────

export function useSecretTypes() {
  return useQuery<SecretTypesResponse>('secret-types', () => api.post<SecretTypesResponse>('/secretType/getall', {}));
}

export function categoryLabel(c: SecretCategory | string): string {
  return SECRET_CATEGORY_LABELS[c as SecretCategory] ?? c;
}

/** Searchable type picker, grouped by category. */
export function SecretTypePicker({ types, value, onChange }: { types: SecretTypeInfo[]; value: string | null; onChange: (key: string) => void }) {
  const [q, setQ] = useState('');
  const groups = useMemo(() => {
    const needle = q.trim().toLowerCase();
    const match = (t: SecretTypeInfo) => !needle || [t.name, t.key, t.description, t.categoryLabel, ...t.tags].some((s) => s.toLowerCase().includes(needle));
    const out = new Map<string, SecretTypeInfo[]>();
    for (const t of types.filter((t) => !isArchivedType(t) && match(t)).sort((a, b) => a.name.localeCompare(b.name))) {
      const k = t.categoryLabel || categoryLabel(t.category);
      out.set(k, [...(out.get(k) ?? []), t]);
    }
    return [...out.entries()].sort(([a], [b]) => a.localeCompare(b));
  }, [types, q]);
  return (
    <div className="space-y-4" data-testid="secret-type-picker">
      <div className="relative w-full sm:w-80">
        <Search className="absolute left-2.5 top-2.5 h-4 w-4 text-slate-400" />
        <Input className="pl-8" placeholder="Search types (e.g. postgres, ssh, aws)" value={q} onChange={(e) => setQ(e.target.value)} aria-label="Search secret types" data-testid="secret-type-search" />
      </div>
      {groups.length === 0 && <p className="text-sm text-slate-500">No secret types match “{q}”.</p>}
      {groups.map(([label, ts]) => (
        <div key={label}>
          <p className="mb-2 text-xs font-semibold uppercase tracking-wide text-slate-500">{label}</p>
          <div className="grid gap-2 sm:grid-cols-2 xl:grid-cols-3">
            {ts.map((t) => (
              <button
                key={t.key}
                type="button"
                data-testid={`secret-type-${t.key}`}
                onClick={() => onChange(t.key)}
                className={cn(
                  'flex flex-col items-start rounded-lg border p-3 text-left transition',
                  value === t.key ? 'border-brand-500 bg-brand-50/50 ring-1 ring-brand-500' : 'border-slate-200 bg-white hover:border-slate-300',
                )}
              >
                <span className="text-sm font-medium text-slate-900">{t.name}</span>
                {t.description && <span className="mt-0.5 line-clamp-2 text-xs text-slate-500">{t.description}</span>}
                {(t.tags.length > 0 || t.source === 'custom' || t.provider?.lease) && (
                  <span className="mt-1.5 flex flex-wrap gap-1">
                    {t.source === 'custom' && <Badge tone="amber">Custom</Badge>}
                    {t.provider?.lease && <Badge tone="violet">Leases</Badge>}
                    {t.tags.slice(0, 4).map((tag) => (
                      <Badge key={tag}>{tag}</Badge>
                    ))}
                  </span>
                )}
              </button>
            ))}
          </div>
        </div>
      ))}
    </div>
  );
}

// ── generated form ──────────────────────────────────────────────

export interface KvRow {
  id: number;
  name: string;
  value: string;
}
export type FieldValue = string | boolean | KvRow[];
export type FieldValues = Record<string, FieldValue>;

/** A field of a payload or of the metadata (metadata fields are never sensitive). */
type AnyField = SecretTypeInfo['metadata'][string] & { sensitive?: boolean };

let kvSeq = 1;
const kvRow = (name = '', value = ''): KvRow => ({ id: kvSeq++, name, value });

/** Empty form values for a set of fields, or values taken from an existing (non-secret) record such as metadata. */
export function initialValues(fields: Record<string, AnyField>, existing?: SecretPayload): FieldValues {
  const out: FieldValues = {};
  for (const [name, f] of Object.entries(fields)) {
    const v = existing?.[name];
    if (f.kind === 'boolean') out[name] = typeof v === 'boolean' ? v : false;
    else if (f.kind === 'keyvalue') out[name] = v && typeof v === 'object' ? Object.entries(v).map(([k, x]) => kvRow(k, x)) : [];
    else out[name] = v === undefined || v === null ? '' : String(v);
  }
  return out;
}

/** The raw object sent to the API (empty fields left out; normalization is done by the validators). */
export function rawFromValues(fields: Record<string, AnyField>, values: FieldValues): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [name, f] of Object.entries(fields)) {
    const v = values[name];
    if (f.kind === 'boolean') out[name] = v === true;
    else if (f.kind === 'keyvalue') {
      const rows = (Array.isArray(v) ? v : []).filter((r) => r.name.trim() || r.value);
      if (rows.length) out[name] = Object.fromEntries(rows.map((r) => [r.name.trim(), r.value]));
    } else if (typeof v === 'string' && v !== '') out[name] = v;
  }
  return out;
}

/** Validates the payload against the type, as the server does. Issues keyed `payload.<field>`. */
export function checkPayload(type: SecretTypeInfo, values: FieldValues): { value: SecretPayload; issues: Record<string, string> } {
  const r = validateSecretPayload(type, rawFromValues(type.fields, values));
  return { value: r.value, issues: prefixed('payload', r.issues) };
}

/** Validates metadata against the type. Issues keyed `metadata.<field>`. */
export function checkMetadata(type: SecretTypeInfo, values: FieldValues): { value: SecretPayload; issues: Record<string, string> } {
  const r = validateSecretMetadata(type, rawFromValues(type.metadata, values));
  return { value: r.value, issues: prefixed('metadata', r.issues) };
}

function prefixed(prefix: string, issues: Record<string, string>): Record<string, string> {
  return Object.fromEntries(Object.entries(issues).map(([k, v]) => [k === prefix ? k : `${prefix}.${k}`, v]));
}

/** A password-style input with a show toggle; never pre-filled. */
function SensitiveControl({ id, multiline, value, onChange, invalid, placeholder, testId }: { id: string; multiline: boolean; value: string; onChange: (v: string) => void; invalid: boolean; placeholder?: string; testId: string }) {
  const [shown, setShown] = useState(false);
  const common = { id, value, invalid, placeholder, autoComplete: 'off', spellCheck: false, 'data-1p-ignore': true, 'data-lpignore': 'true', 'data-testid': testId } as const;
  return (
    <div className="relative">
      {multiline ? (
        <Textarea {...common} rows={5} className={cn('pr-10 font-mono text-[13px]', !shown && '[-webkit-text-security:disc]')} onChange={(e) => onChange(e.target.value)} />
      ) : (
        <Input {...common} type={shown ? 'text' : 'password'} className="pr-10 font-mono text-[13px]" autoComplete="new-password" onChange={(e) => onChange(e.target.value)} />
      )}
      <button type="button" className="absolute right-2 top-2 rounded p-0.5 text-slate-400 hover:text-slate-600" onClick={() => setShown((s) => !s)} aria-label={shown ? 'Hide value' : 'Show value'} data-testid={`${testId}-toggle`}>
        {shown ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
      </button>
    </div>
  );
}

function KeyValueControl({ id, rows, onChange, sensitive, testId }: { id: string; rows: KvRow[]; onChange: (rows: KvRow[]) => void; sensitive: boolean; testId: string }) {
  const [shown, setShown] = useState(false);
  const set = (i: number, patch: Partial<KvRow>) => onChange(rows.map((r, j) => (j === i ? { ...r, ...patch } : r)));
  return (
    <div className="space-y-2" id={id} data-testid={testId}>
      {rows.map((r, i) => (
        <div key={r.id} className="flex gap-2">
          <Input className="w-2/5 font-mono text-[13px]" placeholder="NAME" value={r.name} onChange={(e) => set(i, { name: e.target.value })} aria-label="Name" autoComplete="off" />
          <Input className="flex-1 font-mono text-[13px]" placeholder="value" type={sensitive && !shown ? 'password' : 'text'} autoComplete="new-password" value={r.value} onChange={(e) => set(i, { value: e.target.value })} aria-label="Value" />
          <Button variant="ghost" size="icon" onClick={() => onChange(rows.filter((_, j) => j !== i))} aria-label="Remove entry">
            <X className="h-4 w-4" />
          </Button>
        </div>
      ))}
      <div className="flex gap-2">
        <Button variant="outline" size="sm" onClick={() => onChange([...rows, kvRow()])}>
          <Plus className="h-3.5 w-3.5" /> Add entry
        </Button>
        {sensitive && rows.length > 0 && (
          <Button variant="ghost" size="sm" onClick={() => setShown((s) => !s)}>
            {shown ? <EyeOff className="h-3.5 w-3.5" /> : <Eye className="h-3.5 w-3.5" />} {shown ? 'Hide values' : 'Show values'}
          </Button>
        )}
      </div>
    </div>
  );
}

/**
 * One input per field of a secret type, in `orderedFields` order. `prefix` is `payload` or
 * `metadata`; errors are looked up as `<prefix>.<field>`.
 */
export function TypeFields({ fields, values, onChange, errors, prefix }: { fields: Record<string, AnyField>; values: FieldValues; onChange: (v: FieldValues) => void; errors: Record<string, string>; prefix: 'payload' | 'metadata' }) {
  const set = (name: string, v: FieldValue) => onChange({ ...values, [name]: v });
  const entries = orderedFields(fields);
  if (!entries.length) return null;
  return (
    <div className="grid gap-4 sm:grid-cols-2">
      {entries.map(([name, f]) => {
        const key = `${prefix}.${name}`;
        const id = `secret-${prefix}-${name}`;
        const testId = `secret-field-${key}`;
        const err = errors[key];
        const v = values[name];
        const sensitive = prefix === 'payload' && !!f.sensitive;
        const wide = ['multiline', 'pem', 'json', 'keyvalue'].includes(f.kind);
        let control: ReactNode;
        if (f.kind === 'boolean') {
          control = (
            <div data-testid={testId}>
              <Checkbox id={id} checked={v === true} onChange={(c) => set(name, c)} label={f.label} description={f.description || undefined} />
            </div>
          );
          return (
            <div key={name} className={wide ? 'sm:col-span-2' : undefined}>
              {control}
              {err && <p className="mt-1 text-xs text-red-600">{err}</p>}
            </div>
          );
        }
        if (f.kind === 'keyvalue') {
          control = <KeyValueControl id={id} rows={Array.isArray(v) ? v : []} onChange={(rows) => set(name, rows)} sensitive={sensitive} testId={testId} />;
        } else if (sensitive) {
          control = <SensitiveControl id={id} multiline={['multiline', 'pem', 'json'].includes(f.kind)} value={typeof v === 'string' ? v : ''} onChange={(x) => set(name, x)} invalid={!!err} placeholder={f.placeholder} testId={testId} />;
        } else if (f.kind === 'enum') {
          control = (
            <Select id={id} value={typeof v === 'string' ? v : ''} onChange={(e) => set(name, e.target.value)} invalid={!!err} data-testid={testId}>
              <option value="">{f.required ? 'Choose…' : '—'}</option>
              {(f.values ?? []).map((x) => (
                <option key={x} value={x}>
                  {x}
                </option>
              ))}
            </Select>
          );
        } else if (['multiline', 'pem', 'json'].includes(f.kind)) {
          control = <Textarea id={id} rows={f.kind === 'multiline' ? 3 : 5} className={f.kind === 'multiline' ? undefined : 'font-mono text-[13px]'} value={typeof v === 'string' ? v : ''} onChange={(e) => set(name, e.target.value)} invalid={!!err} placeholder={f.placeholder} spellCheck={false} data-testid={testId} />;
        } else {
          const numeric = ['number', 'integer', 'port'].includes(f.kind);
          const type = numeric ? 'number' : f.kind === 'email' ? 'email' : f.kind === 'url' ? 'url' : 'text';
          control = (
            <Input
              id={id}
              type={type}
              step={f.kind === 'number' ? 'any' : numeric ? 1 : undefined}
              min={f.kind === 'port' ? 1 : f.min}
              max={f.kind === 'port' ? 65535 : f.max}
              value={typeof v === 'string' ? v : ''}
              onChange={(e) => set(name, e.target.value)}
              invalid={!!err}
              placeholder={f.placeholder ?? (f.kind === 'datetime' ? '2026-12-31T23:59:00Z' : undefined)}
              autoComplete="off"
              data-testid={testId}
            />
          );
        }
        return (
          <Field key={name} label={f.label} htmlFor={id} required={f.required} error={err} hint={f.description || undefined} className={wide ? 'sm:col-span-2' : undefined}>
            {control}
          </Field>
        );
      })}
    </div>
  );
}

// ── errors ───────────────────────────────────────────────────────

const ERROR_TITLES: Record<string, string> = {
  SECRET_EXPIRED: 'The secret has expired',
  SECRET_DELETED: 'The secret is deleted',
  SECRET_INVALID_STATE: 'Not allowed in the secret’s current state',
  SECRET_NOT_WRITABLE: 'The secret cannot be changed',
  SECRET_VALUE_GONE: 'The value is no longer stored',
  SECRET_VERSIONING_OFF: 'This secret type keeps no versions',
  SECRET_VERSION_ACTIVE: 'That version is the active one',
  SECRET_VERSION_DESTROYED: 'That version was destroyed',
  SECRET_INVALID: 'The value no longer matches its secret type',
  SECRET_NOT_GENERATABLE: 'The webhook cannot generate values of this type',
  WEBHOOK_UNAVAILABLE: 'The customer webhook is unavailable',
  WEBHOOK_NOT_CONNECTED: 'No connected customer webhook',
  WEBHOOK_NOT_FOUND: 'The customer webhook was not found',
  WEBHOOK_REJECTED: 'The customer webhook refused the request',
  KEY_SERVICE_UNAVAILABLE: 'The key service is unavailable',
  SECRET_NOT_DYNAMIC: 'This secret does not issue leases',
  SECRET_NOT_ACTIVE: 'The secret is not active',
  LEASE_AT_MAXIMUM: 'The lease cannot be made longer',
  LEASE_NOT_RENEWABLE: 'This lease cannot be renewed',
  LEASES_NOT_REVOKED: 'Leases from this secret are still open',
  PROVIDER_UNAVAILABLE: 'The provider could not be reached',
  PROVIDER_HOST_NOT_ALLOWED: 'The customer webhook may not connect to this host',
  PROVIDER_AUTH_FAILED: 'The provider refused the stored credential',
  SECRET_TYPE_IN_USE: 'Secrets still use this type',
  EXPORT_DISABLED: 'Exports are turned off',
  EXPORT_RATE_LIMITED: 'Too many export requests',
  EXPORT_GONE: 'The download link has expired or was used',
  SEPARATION_OF_DUTIES: 'You cannot decide your own request',
  CERTIFICATE_KEY_MISMATCH: 'The certificate does not belong to the key',
  CERTIFICATE_EXPIRED: 'The certificate has expired',
  CERTIFICATE_ISSUER_INVALID: 'That CA secret cannot issue this certificate',
  CERTIFICATE_REQUEST_PENDING: 'A renewal request is already waiting',
  CERTIFICATE_REQUEST_NOT_PENDING: 'The renewal request is no longer waiting',
  CERTIFICATE_NOT_RENEWABLE: 'This certificate type cannot be renewed here',
  SECRET_NOT_A_KEY: 'This secret is not a key',
  KEY_VERSION_DISABLED: 'That key version is deactivated',
  RETRIEVE_NOT_PERMITTED: 'The grant does not allow reading the value',
  KEY_OPERATION_NOT_PERMITTED: 'The grant does not allow that key operation',
  KEY_OPERATION_NOT_ALLOWED: 'The key may not be used for that',
};

/** An API error with its code, shown inline (field errors are shown next to their inputs instead). */
export function ApiErrorCallout({ error, className, shownFields = [] }: { error: ApiError | null; className?: string; shownFields?: string[] }) {
  if (!error) return null;
  const fields = Object.keys(error.fieldErrors).length > 0;
  const unshown = Object.entries(error.fieldErrors).filter(([k]) => !shownFields.includes(k) && !k.startsWith('payload.') && !k.startsWith('metadata.'));
  const title = fields ? 'Please correct the highlighted fields' : (ERROR_TITLES[error.code] ?? (error.status === 403 ? 'Permission denied' : 'Request failed'));
  return (
    <div data-testid="secret-error" data-code={error.code}>
      <Callout tone="danger" title={title} className={className}>
        {fields ? (
          // Errors keyed to something not on this form (e.g. `payload` itself) still need to be seen.
          unshown.map(([k, v]) => (
              <p key={k}>
                {k}: {v}
              </p>
            ))
        ) : (
          <>
            {error.message}
            {error.code && !error.code.startsWith('HTTP_') && <span className="ml-1.5 font-mono text-[11px] opacity-70">({error.code})</span>}
          </>
        )}
      </Callout>
    </div>
  );
}
