import { useMemo, useState } from 'react';
import { Archive, Braces, Lock, Pencil, Plus, RotateCcw, Search, Shapes, Trash2 } from 'lucide-react';
import {
  CUSTOM_SECRET_TYPE_PREFIX,
  PERMISSIONS,
  SECRET_FIELD_KINDS,
  orderedFields,
  type SecretFieldKind,
  type SecretTypeInfo,
  type SecretTypesResponse,
} from '@token-vault/shared';
import { useMutation, usePost } from '@/hooks/useApi';
import { useAuth } from '@/context/AuthContext';
import { ApiError, api } from '@/lib/api';
import { cn, splitList } from '@/lib/utils';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardHeader } from '@/components/ui/card';
import { Field, Input, Select, Textarea } from '@/components/ui/form';
import { Callout, EmptyState, ErrorState } from '@/components/ui/feedback';
import { Dialog } from '@/components/ui/dialog';
import { DataTable, type Column } from '@/components/ui/table';
import { PageHeader } from '@/components/ui/navigation';
import { useToast } from '@/components/ui/toast';
import { SecretsSectionTabs } from './secretAccess';
import { ApiErrorCallout, ProviderCapabilityBadges, TypeSourceBadge, categoryLabel, isArchivedType } from './secretUi';

/**
 * Secret types (spec 4.9.3): the catalog and predefined types, and the organization's own
 * (custom) types. Custom types use the same schema, so every field is encrypted on the customer
 * webhook, sensitive fields are masked, and access, audit and lifecycle rules apply unchanged.
 */

type TypeRow = SecretTypeInfo & { archived?: boolean };
type Editing = null | { mode: 'new' } | { mode: 'edit'; type: TypeRow };

export function SecretTypesPage() {
  const { can } = useAuth();
  const toast = useToast();
  const canManage = can(PERMISSIONS.SECRET_MANAGE_TYPES);
  const [showArchived, setShowArchived] = useState(false);
  const [q, setQ] = useState('');
  const { data, error, loading, reload } = usePost<SecretTypesResponse>('/secretType/getall', showArchived ? { includeArchived: true } : {});
  const [editing, setEditing] = useState<Editing>(null);
  const [archiving, setArchiving] = useState<TypeRow | null>(null);
  const [restoring, setRestoring] = useState<string | null>(null);

  const groups = useMemo(() => {
    const needle = q.trim().toLowerCase();
    const match = (t: TypeRow) => !needle || [t.name, t.key, t.description, t.categoryLabel, ...t.tags].some((s) => s.toLowerCase().includes(needle));
    const out = new Map<string, TypeRow[]>();
    for (const t of ((data?.types ?? []) as TypeRow[]).filter(match).sort((a, b) => a.name.localeCompare(b.name))) {
      const k = t.categoryLabel || categoryLabel(t.category);
      out.set(k, [...(out.get(k) ?? []), t]);
    }
    // Custom types last, so the organization's own are easy to find.
    return [...out.entries()].sort(([a, x], [b, y]) => Number(x[0]?.category === 'custom') - Number(y[0]?.category === 'custom') || a.localeCompare(b));
  }, [data, q]);

  async function restore(t: TypeRow) {
    setRestoring(t.key);
    try {
      await api.post('/secretType/saveCustom', t);
      toast.success('Type restored', `New secrets of ${t.name} can be created again.`);
      await reload();
    } catch (e) {
      toast.error('Restore failed', (e as Error).message);
    } finally {
      setRestoring(null);
    }
  }

  const columns: Column<TypeRow>[] = [
    {
      key: 'name',
      header: 'Type',
      cell: (t) => (
        <div className="min-w-0 max-w-sm" data-testid="secret-type-row" data-key={t.key} data-source={t.source} data-archived={isArchivedType(t) ? 'true' : 'false'}>
          <p className="flex flex-wrap items-center gap-1.5 font-medium text-slate-900">
            {t.name}
            {isArchivedType(t) && <Badge>Archived</Badge>}
          </p>
          <p className="font-mono text-[11px] text-slate-500">
            {t.key} · v{t.version}
          </p>
          {t.description && <p className="mt-0.5 line-clamp-2 text-xs text-slate-500">{t.description}</p>}
        </div>
      ),
    },
    { key: 'source', header: 'Source', cell: (t) => <TypeSourceBadge source={t.source} /> },
    { key: 'fields', header: 'Fields', cell: (t) => <FieldPreview type={t} />, hideBelow: 'md' },
    { key: 'provider', header: 'Provider', cell: (t) => (t.provider ? <ProviderCapabilityBadges capabilities={t.provider} /> : <span className="text-slate-400">—</span>), hideBelow: 'lg' },
    {
      key: 'actions',
      header: '',
      className: 'text-right',
      cell: (t) =>
        canManage && t.source === 'custom' ? (
          <div className="flex justify-end gap-1">
            {isArchivedType(t) ? (
              <Button variant="ghost" size="sm" loading={restoring === t.key} onClick={() => void restore(t)} data-testid="secret-type-restore">
                <RotateCcw className="h-3.5 w-3.5" /> Restore
              </Button>
            ) : (
              <>
                <Button variant="ghost" size="sm" onClick={() => setEditing({ mode: 'edit', type: t })} data-testid="secret-type-edit">
                  <Pencil className="h-3.5 w-3.5" /> Edit
                </Button>
                <Button variant="ghost" size="sm" className="text-red-700 hover:bg-red-50 hover:text-red-800" onClick={() => setArchiving(t)} data-testid="secret-type-archive">
                  <Archive className="h-3.5 w-3.5" /> Archive
                </Button>
              </>
            )}
          </div>
        ) : null,
    },
  ];

  return (
    <div>
      <PageHeader
        title="Secret types"
        description="A type decides a secret’s fields, which of them are sensitive, how each is validated, and its lifecycle."
        breadcrumbs={[{ label: 'Secrets', to: '/secrets' }, { label: 'Secret types' }]}
        actions={
          canManage && (
            <Button onClick={() => setEditing({ mode: 'new' })} data-testid="secret-type-new">
              <Plus className="h-4 w-4" /> New custom type
            </Button>
          )
        }
      />
      <SecretsSectionTabs current="/secrets/types" />
      <Callout tone="security" className="mb-4" title="Custom types follow the same rules">
        Every field of a custom type is encrypted on your customer webhook, sensitive fields are masked everywhere, and access grants, approvals and the audit log apply unchanged. The server assigns each saved definition a new version; existing secrets keep their values.
      </Callout>
      {data?.catalog?.lastError && (
        <Callout tone="warning" className="mb-4" title="Catalog sync failed">
          {data.catalog.lastError}
        </Callout>
      )}
      <div className="mb-4 flex flex-wrap items-center gap-3">
        <div className="relative w-full sm:w-72">
          <Search className="absolute left-2.5 top-2.5 h-4 w-4 text-slate-400" />
          <Input className="pl-8" placeholder="Search types" value={q} onChange={(e) => setQ(e.target.value)} aria-label="Search secret types" data-testid="secret-types-search" />
        </div>
        <label className="flex items-center gap-2 text-sm text-slate-600">
          <input type="checkbox" className="h-4 w-4 rounded border-slate-300 text-brand-600 focus:ring-brand-500" checked={showArchived} onChange={(e) => setShowArchived(e.target.checked)} data-testid="secret-types-show-archived" />
          Show archived custom types
        </label>
      </div>
      {error ? (
        <ErrorState error={error} onRetry={reload} />
      ) : loading && !data ? (
        <Card>
          <DataTable rows={[]} loading rowKey={(t: TypeRow) => t.key} columns={columns} />
        </Card>
      ) : groups.length === 0 ? (
        <Card>
          <EmptyState icon={<Shapes className="h-5 w-5" />} title={q ? 'No types match' : 'No secret types'} description={q ? `Nothing matches “${q}”.` : undefined} />
        </Card>
      ) : (
        <div className="space-y-6" data-testid="secret-types">
          {groups.map(([label, types]) => (
            <Card key={label} data-testid="secret-type-group" data-category={types[0]?.category}>
              <CardHeader title={label} description={`${types.length} type${types.length === 1 ? '' : 's'}`} />
              <DataTable rows={types} rowKey={(t) => t.key} columns={columns} dense />
            </Card>
          ))}
        </div>
      )}

      {editing && (
        <TypeEditorDialog
          key={editing.mode === 'edit' ? editing.type.key : 'new'}
          existing={editing.mode === 'edit' ? editing.type : null}
          takenKeys={(data?.types ?? []).map((t) => t.key)}
          onClose={() => setEditing(null)}
          onSaved={(t) => {
            setEditing(null);
            toast.success(editing.mode === 'edit' ? 'Type updated' : 'Type created', `${t.name} · version ${t.version}`);
            void reload();
          }}
        />
      )}
      {archiving && (
        <ArchiveDialog
          type={archiving}
          onClose={() => setArchiving(null)}
          onDone={() => {
            toast.success('Type archived', `No new ${archiving.name} secrets can be created.`);
            setArchiving(null);
            void reload();
          }}
        />
      )}
    </div>
  );
}

function FieldPreview({ type }: { type: SecretTypeInfo }) {
  const fields = orderedFields(type.fields);
  return (
    <div className="flex max-w-md flex-wrap gap-1" data-testid="secret-type-fields">
      {fields.map(([name, f]) => (
        <span
          key={name}
          className={cn('inline-flex items-center gap-1 rounded-md px-1.5 py-0.5 text-[11px] ring-1 ring-inset', f.sensitive ? 'bg-amber-50 text-amber-900 ring-amber-600/20' : 'bg-slate-50 text-slate-700 ring-slate-500/20')}
          title={`${name} · ${f.kind}${f.sensitive ? ' · sensitive' : ''}${f.required ? ' · required' : ''}`}
          data-field={name}
          data-sensitive={f.sensitive ? 'true' : 'false'}
        >
          {f.sensitive && <Lock className="h-3 w-3" />}
          {f.label}
          {f.required && <span className="text-red-500">*</span>}
          <span className="text-slate-400">{f.kind}</span>
        </span>
      ))}
    </div>
  );
}

// ── editor ───────────────────────────────────────────────────────

interface FieldRow {
  id: number;
  name: string;
  label: string;
  kind: SecretFieldKind;
  sensitive: boolean;
  required: boolean;
  pattern: string;
  minLength: string;
  maxLength: string;
  /** enum values, comma separated */
  values: string;
  placeholder: string;
  description: string;
  /** Properties the form does not edit (min, max, generate): kept as they were. */
  extra: Record<string, unknown>;
}

interface Draft {
  slug: string;
  name: string;
  description: string;
  fields: FieldRow[];
  metadata: FieldRow[];
  identifiedBy: string;
  versioning: boolean;
  rotation: boolean;
  expiration: boolean;
  rotationIntervalDays: string;
  expiresInDays: string;
  expiryWarningDays: string;
  tags: string;
}

let rowSeq = 1;
const FORM_KEYS = ['label', 'kind', 'sensitive', 'required', 'pattern', 'minLength', 'maxLength', 'values', 'placeholder', 'description', 'order'];

function emptyRow(sensitive = true): FieldRow {
  return { id: rowSeq++, name: '', label: '', kind: 'text', sensitive, required: false, pattern: '', minLength: '', maxLength: '', values: '', placeholder: '', description: '', extra: {} };
}

function rowFrom(name: string, f: Record<string, unknown>): FieldRow {
  const extra = Object.fromEntries(Object.entries(f).filter(([k]) => !FORM_KEYS.includes(k)));
  const str = (v: unknown) => (v === undefined || v === null ? '' : String(v));
  return {
    id: rowSeq++,
    name,
    label: str(f.label),
    kind: (SECRET_FIELD_KINDS as readonly string[]).includes(String(f.kind)) ? (f.kind as SecretFieldKind) : 'text',
    sensitive: f.sensitive !== false,
    required: f.required === true,
    pattern: str(f.pattern),
    minLength: str(f.minLength),
    maxLength: str(f.maxLength),
    values: Array.isArray(f.values) ? f.values.join(', ') : '',
    placeholder: str(f.placeholder),
    description: str(f.description),
    extra,
  };
}

function rowsFrom(fields: unknown): FieldRow[] {
  if (!fields || typeof fields !== 'object') return [];
  const entries = Object.entries(fields as Record<string, Record<string, unknown>>).sort(([a, x], [b, y]) => Number(x?.order ?? 0) - Number(y?.order ?? 0) || a.localeCompare(b));
  return entries.map(([name, f]) => rowFrom(name, f && typeof f === 'object' ? f : {}));
}

function draftFrom(def: Record<string, unknown> | null): Draft {
  if (!def) {
    return { slug: '', name: '', description: '', fields: [emptyRow()], metadata: [], identifiedBy: '', versioning: true, rotation: true, expiration: true, rotationIntervalDays: '', expiresInDays: '', expiryWarningDays: '', tags: '' };
  }
  const key = typeof def.key === 'string' ? def.key : '';
  const lifecycle = (def.lifecycle ?? {}) as Record<string, unknown>;
  const defaults = (def.defaults ?? {}) as Record<string, unknown>;
  const str = (v: unknown) => (v === undefined || v === null ? '' : String(v));
  return {
    slug: key.startsWith(CUSTOM_SECRET_TYPE_PREFIX) ? key.slice(CUSTOM_SECRET_TYPE_PREFIX.length) : key,
    name: str(def.name),
    description: str(def.description),
    fields: rowsFrom(def.fields),
    metadata: rowsFrom(def.metadata),
    identifiedBy: Array.isArray(def.identifiedBy) ? def.identifiedBy.join(', ') : '',
    versioning: lifecycle.versioning !== false,
    rotation: lifecycle.rotation !== false,
    expiration: lifecycle.expiration !== false,
    rotationIntervalDays: str(defaults.rotationIntervalDays),
    expiresInDays: str(defaults.expiresInDays),
    expiryWarningDays: str(defaults.expiryWarningDays),
    tags: Array.isArray(def.tags) ? def.tags.join(', ') : '',
  };
}

function fieldsOf(rows: FieldRow[], withSensitive: boolean): Record<string, Record<string, unknown>> {
  const out: Record<string, Record<string, unknown>> = {};
  rows.forEach((r, i) => {
    const f: Record<string, unknown> = { ...r.extra, label: r.label.trim(), kind: r.kind, required: r.required, order: (i + 1) * 10 };
    if (withSensitive) f.sensitive = r.sensitive;
    if (r.description.trim()) f.description = r.description.trim();
    if (r.placeholder.trim()) f.placeholder = r.placeholder.trim();
    if (r.pattern.trim()) f.pattern = r.pattern.trim();
    if (r.minLength.trim()) f.minLength = Number(r.minLength);
    if (r.maxLength.trim()) f.maxLength = Number(r.maxLength);
    if (r.kind === 'enum') f.values = splitList(r.values);
    out[r.name.trim()] = f;
  });
  return out;
}

/** The definition sent to /secretType/saveCustom (category and version are set by the server). */
function definitionOf(d: Draft): Record<string, unknown> {
  const num = (v: string) => (v.trim() ? Number(v) : undefined);
  const defaults: Record<string, number> = {};
  if (d.rotation && num(d.rotationIntervalDays) !== undefined) defaults.rotationIntervalDays = num(d.rotationIntervalDays)!;
  if (d.expiration && num(d.expiresInDays) !== undefined) defaults.expiresInDays = num(d.expiresInDays)!;
  if (num(d.expiryWarningDays) !== undefined) defaults.expiryWarningDays = num(d.expiryWarningDays)!;
  return {
    key: `${CUSTOM_SECRET_TYPE_PREFIX}${d.slug.trim()}`,
    name: d.name.trim(),
    description: d.description.trim(),
    category: 'custom',
    fields: fieldsOf(d.fields, true),
    metadata: fieldsOf(d.metadata, false),
    identifiedBy: splitList(d.identifiedBy),
    lifecycle: { versioning: d.versioning, rotation: d.rotation, expiration: d.expiration },
    defaults,
    tags: splitList(d.tags),
  };
}

/** Strips what the list response adds, for the JSON view. */
function editableJson(t: TypeRow): Record<string, unknown> {
  const { categoryLabel: _l, digest: _d, source: _s, provider: _p, archived: _a, version: _v, ...def } = t;
  return def as unknown as Record<string, unknown>;
}

const SLUG = /^[a-z0-9][a-z0-9-]*$/;
const FIELD_NAME = /^[a-z][a-zA-Z0-9_]{0,39}$/;

function localIssues(d: Draft, isNew: boolean, takenKeys: string[]): string[] {
  const issues: string[] = [];
  const key = `${CUSTOM_SECRET_TYPE_PREFIX}${d.slug.trim()}`;
  if (!d.slug.trim()) issues.push('key: give the type a key');
  else if (!SLUG.test(d.slug.trim()) || key.length > 31) issues.push(`key: lower-case letters, digits and dashes, at most ${31 - CUSTOM_SECRET_TYPE_PREFIX.length} characters after "${CUSTOM_SECRET_TYPE_PREFIX}"`);
  else if (isNew && takenKeys.includes(key)) issues.push(`key: ${key} is already used`);
  if (!d.name.trim()) issues.push('name: give the type a name');
  if (!d.fields.length) issues.push('fields: add at least one field');
  const names = new Set<string>();
  for (const [where, rows] of [
    ['fields', d.fields],
    ['metadata', d.metadata],
  ] as const) {
    rows.forEach((r, i) => {
      const n = r.name.trim();
      if (!FIELD_NAME.test(n)) issues.push(`${where} #${i + 1}: the name starts with a lower-case letter, then letters, digits or _`);
      else if (names.has(n)) issues.push(`${where}.${n}: used twice`);
      names.add(n);
      if (!r.label.trim()) issues.push(`${where}.${n || `#${i + 1}`}: give it a label`);
      if (r.kind === 'enum' && !splitList(r.values).length) issues.push(`${where}.${n || `#${i + 1}`}: list the allowed values`);
    });
  }
  if (d.fields.length && !d.fields.some((f) => f.sensitive)) issues.push('fields: at least one field must be sensitive');
  return issues;
}

function TypeEditorDialog({ existing, takenKeys, onClose, onSaved }: { existing: TypeRow | null; takenKeys: string[]; onClose: () => void; onSaved: (t: SecretTypeInfo) => void }) {
  const [draft, setDraft] = useState<Draft>(() => draftFrom(existing ? editableJson(existing) : null));
  const [jsonMode, setJsonMode] = useState(false);
  const [json, setJson] = useState('');
  const [issues, setIssues] = useState<string[]>([]);
  const save = useMutation((body: unknown) => api.post<SecretTypeInfo>('/secretType/saveCustom', body));
  const set = (p: Partial<Draft>) => setDraft((d) => ({ ...d, ...p }));

  function toggleJson() {
    if (!jsonMode) {
      setJson(JSON.stringify(definitionOf(draft), null, 2));
      setIssues([]);
      setJsonMode(true);
      return;
    }
    try {
      const parsed = JSON.parse(json) as unknown;
      if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error('not an object');
      const next = draftFrom(parsed as Record<string, unknown>);
      // The key of an existing type cannot change.
      if (existing) next.slug = draftFrom(editableJson(existing)).slug;
      setDraft(next);
      setIssues([]);
      setJsonMode(false);
    } catch {
      setIssues(['definition: not valid JSON (an object is expected)']);
    }
  }

  async function onSubmit() {
    let body: Record<string, unknown>;
    if (jsonMode) {
      try {
        const parsed = JSON.parse(json) as unknown;
        if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error('not an object');
        body = parsed as Record<string, unknown>;
      } catch {
        setIssues(['definition: not valid JSON (an object is expected)']);
        return;
      }
      if (existing) body.key = existing.key;
    } else {
      const local = localIssues(draft, !existing, takenKeys);
      setIssues(local);
      if (local.length) return;
      body = definitionOf(draft);
    }
    setIssues([]);
    const r = await save.run(body);
    if (r) onSaved(r);
  }

  const serverIssues = save.error && Array.isArray(save.error.details?.issues) ? (save.error.details!.issues as string[]) : [];
  const shownIssues = issues.length ? issues : serverIssues;

  return (
    <Dialog
      open
      onClose={onClose}
      size="xl"
      title={existing ? `Edit ${existing.name}` : 'New custom type'}
      description={existing ? `Saving creates version ${existing.version + 1}. Existing secrets keep their values; new values are checked against the new version.` : 'The server assigns the version. Custom types are always in the Custom category.'}
      footer={
        <>
          <Button variant="ghost" className="mr-auto" onClick={toggleJson} data-testid="secret-type-json-toggle">
            <Braces className="h-4 w-4" /> {jsonMode ? 'Edit with the form' : 'Edit as JSON'}
          </Button>
          <Button variant="outline" onClick={onClose}>
            Cancel
          </Button>
          <Button loading={save.pending} onClick={() => void onSubmit()} data-testid="secret-type-save">
            {existing ? 'Save new version' : 'Create type'}
          </Button>
        </>
      }
    >
      <form
        className="space-y-6"
        data-testid="secret-type-form"
        onSubmit={(e) => {
          e.preventDefault();
          void onSubmit();
        }}
      >
        {shownIssues.length > 0 && (
          <div data-testid="secret-type-issues">
            <Callout tone="danger" title="The secret type is not valid">
              <ul className="list-disc space-y-0.5 pl-4">
                {shownIssues.map((i) => (
                  <li key={i} className="break-words">
                    {i}
                  </li>
                ))}
              </ul>
            </Callout>
          </div>
        )}
        {save.error && !serverIssues.length && <ApiErrorCallout error={save.error} />}

        {jsonMode ? (
          <Field label="Definition (JSON)" htmlFor="secret-type-json" hint={`Keys start with "${CUSTOM_SECRET_TYPE_PREFIX}". Fields: label, kind, sensitive (default true), required, pattern, minLength, maxLength, values, placeholder, description, order.`}>
            <Textarea id="secret-type-json" rows={22} className="font-mono text-[12px]" spellCheck={false} value={json} onChange={(e) => setJson(e.target.value)} data-testid="secret-type-json" />
          </Field>
        ) : (
          <>
            <div className="grid gap-4 sm:grid-cols-2">
              <Field label="Key" htmlFor="secret-type-key" required hint={existing ? 'The key cannot change.' : 'Lower-case letters, digits and dashes. Used in the API and SDK.'}>
                <div className="flex">
                  <span className="inline-flex h-9 items-center rounded-l-md border border-r-0 border-slate-300 bg-slate-50 px-2.5 font-mono text-[13px] text-slate-500">{CUSTOM_SECRET_TYPE_PREFIX}</span>
                  <Input id="secret-type-key" className="rounded-l-none font-mono text-[13px]" value={draft.slug} disabled={!!existing} onChange={(e) => set({ slug: e.target.value.toLowerCase() })} placeholder="partner-api" data-testid="secret-type-key" />
                </div>
              </Field>
              <Field label="Name" htmlFor="secret-type-name" required>
                <Input id="secret-type-name" value={draft.name} maxLength={60} onChange={(e) => set({ name: e.target.value })} placeholder="Partner API credentials" data-testid="secret-type-name" />
              </Field>
              <Field label="Description" htmlFor="secret-type-description" className="sm:col-span-2">
                <Textarea id="secret-type-description" rows={2} maxLength={500} value={draft.description} onChange={(e) => set({ description: e.target.value })} data-testid="secret-type-description" />
              </Field>
            </div>

            <FieldRows
              title="Value fields"
              description="Every field is encrypted on the customer webhook. Sensitive fields are masked everywhere and only shown by an audited reveal; at least one must be sensitive."
              rows={draft.fields}
              onChange={(fields) => set({ fields })}
              sensitive
              testPrefix="secret-type-field"
              addTestId="secret-type-add-field"
            />
            <FieldRows
              title="Details (metadata)"
              description="Descriptive attributes kept with the secret’s metadata in clear. Never put secrets here."
              rows={draft.metadata}
              onChange={(metadata) => set({ metadata })}
              sensitive={false}
              testPrefix="secret-type-meta"
              addTestId="secret-type-add-meta"
            />

            <div className="grid gap-4 sm:grid-cols-2">
              <Field label="Identified by" htmlFor="secret-type-identified" hint="Value fields that together identify the credential (e.g. username), comma separated. Used to spot duplicates.">
                <Input id="secret-type-identified" value={draft.identifiedBy} onChange={(e) => set({ identifiedBy: e.target.value })} placeholder="username" data-testid="secret-type-identified-by" />
              </Field>
              <Field label="Tags" htmlFor="secret-type-tags" hint="Comma separated, shown in the type picker.">
                <Input id="secret-type-tags" value={draft.tags} onChange={(e) => set({ tags: e.target.value })} placeholder="partner, api" data-testid="secret-type-tags" />
              </Field>
            </div>

            <div className="space-y-3">
              <p className="text-sm font-medium text-slate-700">Lifecycle</p>
              <div className="grid gap-3 sm:grid-cols-3">
                <PlainCheckbox id="secret-type-versioning" checked={draft.versioning} onChange={(versioning) => set({ versioning })} label="Versioning" description="Keep previous values as versions." testId="secret-type-versioning" />
                <PlainCheckbox id="secret-type-rotation" checked={draft.rotation} onChange={(rotation) => set({ rotation })} label="Rotation" description="Secrets can be rotated." testId="secret-type-rotation" />
                <PlainCheckbox id="secret-type-expiration" checked={draft.expiration} onChange={(expiration) => set({ expiration })} label="Expiration" description="Secrets can expire." testId="secret-type-expiration" />
              </div>
              <div className="grid gap-4 sm:grid-cols-3">
                <Field label="Default rotation (days)" htmlFor="secret-type-rotation-days">
                  <Input id="secret-type-rotation-days" type="number" min={1} max={3650} value={draft.rotationIntervalDays} disabled={!draft.rotation} onChange={(e) => set({ rotationIntervalDays: e.target.value })} data-testid="secret-type-rotation-days" />
                </Field>
                <Field label="Default expiry (days)" htmlFor="secret-type-expires-days">
                  <Input id="secret-type-expires-days" type="number" min={1} max={3650} value={draft.expiresInDays} disabled={!draft.expiration} onChange={(e) => set({ expiresInDays: e.target.value })} data-testid="secret-type-expires-days" />
                </Field>
                <Field label="Expiry warning (days)" htmlFor="secret-type-warning-days" hint="Default 14.">
                  <Input id="secret-type-warning-days" type="number" min={1} max={365} value={draft.expiryWarningDays} onChange={(e) => set({ expiryWarningDays: e.target.value })} data-testid="secret-type-warning-days" />
                </Field>
              </div>
            </div>
          </>
        )}
      </form>
    </Dialog>
  );
}

function PlainCheckbox({ id, checked, onChange, label, description, testId, disabled }: { id: string; checked: boolean; onChange: (v: boolean) => void; label: string; description?: string; testId: string; disabled?: boolean }) {
  return (
    <label htmlFor={id} className={cn('flex cursor-pointer items-start gap-2.5', disabled && 'cursor-not-allowed opacity-60')}>
      <input id={id} type="checkbox" className="mt-0.5 h-4 w-4 rounded border-slate-300 text-brand-600 focus:ring-brand-500" checked={checked} disabled={disabled} onChange={(e) => onChange(e.target.checked)} data-testid={testId} />
      <span>
        <span className="block text-sm font-medium text-slate-800">{label}</span>
        {description && <span className="block text-xs text-slate-500">{description}</span>}
      </span>
    </label>
  );
}

function FieldRows({ title, description, rows, onChange, sensitive, testPrefix, addTestId }: { title: string; description: string; rows: FieldRow[]; onChange: (rows: FieldRow[]) => void; sensitive: boolean; testPrefix: string; addTestId: string }) {
  const update = (i: number, p: Partial<FieldRow>) => onChange(rows.map((r, j) => (j === i ? { ...r, ...p } : r)));
  const move = (i: number, by: number) => {
    const j = i + by;
    if (j < 0 || j >= rows.length) return;
    const next = [...rows];
    [next[i], next[j]] = [next[j]!, next[i]!];
    onChange(next);
  };
  const textLike = (k: SecretFieldKind) => ['text', 'multiline', 'url', 'email', 'hostname', 'pem', 'json', 'datetime'].includes(k);
  return (
    <div className="space-y-3">
      <div>
        <p className="text-sm font-medium text-slate-700">{title}</p>
        <p className="text-xs text-slate-500">{description}</p>
      </div>
      {rows.map((r, i) => (
        <div key={r.id} className="space-y-3 rounded-lg border border-slate-200 p-3" data-testid={`${testPrefix}-row-${i}`}>
          <div className="grid gap-3 sm:grid-cols-3">
            <Field label="Name" htmlFor={`${testPrefix}-name-${i}`} hint="e.g. apiKey">
              <Input id={`${testPrefix}-name-${i}`} className="font-mono text-[13px]" value={r.name} onChange={(e) => update(i, { name: e.target.value })} data-testid={`${testPrefix}-name-${i}`} />
            </Field>
            <Field label="Label" htmlFor={`${testPrefix}-label-${i}`}>
              <Input id={`${testPrefix}-label-${i}`} value={r.label} maxLength={80} onChange={(e) => update(i, { label: e.target.value })} data-testid={`${testPrefix}-label-${i}`} />
            </Field>
            <Field label="Kind" htmlFor={`${testPrefix}-kind-${i}`}>
              <Select id={`${testPrefix}-kind-${i}`} value={r.kind} onChange={(e) => update(i, { kind: e.target.value as SecretFieldKind })} data-testid={`${testPrefix}-kind-${i}`}>
                {SECRET_FIELD_KINDS.map((k) => (
                  <option key={k} value={k}>
                    {k}
                  </option>
                ))}
              </Select>
            </Field>
          </div>
          <div className="flex flex-wrap items-center gap-x-5 gap-y-2">
            {sensitive && <PlainCheckbox id={`${testPrefix}-sensitive-${i}`} checked={r.sensitive} onChange={(v) => update(i, { sensitive: v })} label="Sensitive" testId={`${testPrefix}-sensitive-${i}`} />}
            <PlainCheckbox id={`${testPrefix}-required-${i}`} checked={r.required} onChange={(v) => update(i, { required: v })} label="Required" testId={`${testPrefix}-required-${i}`} />
            <div className="ml-auto flex gap-1">
              <Button variant="ghost" size="sm" disabled={i === 0} onClick={() => move(i, -1)} aria-label="Move up">
                ↑
              </Button>
              <Button variant="ghost" size="sm" disabled={i === rows.length - 1} onClick={() => move(i, 1)} aria-label="Move down">
                ↓
              </Button>
              <Button variant="ghost" size="sm" className="text-red-700 hover:bg-red-50" onClick={() => onChange(rows.filter((_, j) => j !== i))} data-testid={`${testPrefix}-remove-${i}`}>
                <Trash2 className="h-3.5 w-3.5" /> Remove
              </Button>
            </div>
          </div>
          <div className="grid gap-3 sm:grid-cols-3">
            {r.kind === 'enum' ? (
              <Field label="Allowed values" htmlFor={`${testPrefix}-values-${i}`} hint="Comma separated." className="sm:col-span-3">
                <Input id={`${testPrefix}-values-${i}`} value={r.values} onChange={(e) => update(i, { values: e.target.value })} placeholder="sandbox, live" data-testid={`${testPrefix}-values-${i}`} />
              </Field>
            ) : (
              <>
                <Field label="Pattern" htmlFor={`${testPrefix}-pattern-${i}`} hint={textLike(r.kind) ? 'Anchored regular expression, ^…$' : 'Text-like kinds only.'}>
                  <Input id={`${testPrefix}-pattern-${i}`} className="font-mono text-[13px]" value={r.pattern} disabled={!textLike(r.kind) && !r.pattern} onChange={(e) => update(i, { pattern: e.target.value })} placeholder="^pk_[A-Za-z0-9]+$" data-testid={`${testPrefix}-pattern-${i}`} />
                </Field>
                <Field label="Min length" htmlFor={`${testPrefix}-min-${i}`}>
                  <Input id={`${testPrefix}-min-${i}`} type="number" min={0} value={r.minLength} onChange={(e) => update(i, { minLength: e.target.value })} data-testid={`${testPrefix}-min-${i}`} />
                </Field>
                <Field label="Max length" htmlFor={`${testPrefix}-max-${i}`}>
                  <Input id={`${testPrefix}-max-${i}`} type="number" min={1} value={r.maxLength} onChange={(e) => update(i, { maxLength: e.target.value })} data-testid={`${testPrefix}-max-${i}`} />
                </Field>
              </>
            )}
            <Field label="Placeholder" htmlFor={`${testPrefix}-placeholder-${i}`} className="sm:col-span-1">
              <Input id={`${testPrefix}-placeholder-${i}`} value={r.placeholder} maxLength={200} onChange={(e) => update(i, { placeholder: e.target.value })} />
            </Field>
            <Field label="Help text" htmlFor={`${testPrefix}-help-${i}`} className="sm:col-span-2">
              <Input id={`${testPrefix}-help-${i}`} value={r.description} maxLength={300} onChange={(e) => update(i, { description: e.target.value })} />
            </Field>
          </div>
        </div>
      ))}
      <Button variant="outline" size="sm" onClick={() => onChange([...rows, emptyRow(sensitive)])} data-testid={addTestId}>
        <Plus className="h-3.5 w-3.5" /> Add {sensitive ? 'field' : 'detail'}
      </Button>
    </div>
  );
}

function ArchiveDialog({ type, onClose, onDone }: { type: TypeRow; onClose: () => void; onDone: () => void }) {
  const archive = useMutation(() => api.del<{ key: string; archived: true }>(`/secretType/archiveCustom/${encodeURIComponent(type.key)}`));
  async function confirm() {
    const r = await archive.run();
    if (r) onDone();
  }
  const inUse = archive.error instanceof ApiError && archive.error.code === 'SECRET_TYPE_IN_USE';
  return (
    <Dialog
      open
      onClose={onClose}
      size="sm"
      title={`Archive ${type.name}`}
      footer={
        <>
          <Button variant="outline" onClick={onClose} disabled={archive.pending}>
            Cancel
          </Button>
          <Button variant="danger" loading={archive.pending} disabled={inUse} onClick={() => void confirm()} data-testid="secret-type-archive-confirm">
            Archive type
          </Button>
        </>
      }
    >
      <div className="space-y-3 text-sm text-slate-600" data-testid="secret-type-archive-dialog">
        <p>No new secrets of this type can be created. Archiving is refused while any secret still uses it; the definition stays for the record and can be restored.</p>
        <ApiErrorCallout error={archive.error} />
      </div>
    </Dialog>
  );
}
