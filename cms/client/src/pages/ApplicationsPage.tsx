import { useMemo, useState, type ReactNode } from 'react';
import { KeyRound, Plus, Search } from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import { SECRET_CATEGORIES, SECRET_CATEGORY_LABELS, type CmsApplicationSummary, type SecretCategory } from '@token-vault/shared';
import { Badge } from '@ui/badge';
import { ProviderIcon } from '@ui/provider-icon';
import { Button } from '@ui/button';
import { Card } from '@ui/card';
import { Dialog } from '@ui/dialog';
import { ErrorState, FormError } from '@ui/feedback';
import { Field, Input, Select, Textarea } from '@ui/form';
import { PageHeader } from '@ui/navigation';
import { DataTable, type Column } from '@ui/table';
import { useMutation } from '@tv-hooks/useApi';
import { useQuery } from '@/lib/hooks';
import { useAuth } from '@/auth';
import { AvailabilityBadge } from '@/components/AvailabilityBadge';
import { VersionBadge } from '@/components/VersionBadge';
import { api } from '@/lib/api';
import { KINDS, secretCategoryLabel, type CatalogKind } from '@/lib/kinds';
import { relativeTime } from '@/lib/utils';

/** Lists the catalog entries of one kind: applications (provider definitions) or secret types. */
export function ApplicationsPage({ kind = 'provider' }: { kind?: CatalogKind }) {
  const k = KINDS[kind];
  const secretTypes = kind === 'secret_type';
  const { user } = useAuth();
  const navigate = useNavigate();
  const list = useQuery(secretTypes ? 'secret-types' : 'applications', () => api.page<CmsApplicationSummary>(`${k.apiBase}/getall`, { pageSize: 200 }));
  const [open, setOpen] = useState(false);
  const [search, setSearch] = useState('');
  const [category, setCategory] = useState('');
  const canCreate = user?.role === 'EDITOR' || user?.role === 'ADMIN';

  // Secret types: filtered by search and category, ordered by category then name.
  const rows = useMemo(() => {
    const items = list.data?.items;
    if (!items || !secretTypes) return items;
    const q = search.trim().toLowerCase();
    return items
      .filter((a) => (!category || a.category === category) && (!q || a.key.includes(q) || a.name.toLowerCase().includes(q) || a.description.toLowerCase().includes(q)))
      .sort((a, b) => SECRET_CATEGORIES.indexOf(a.category as SecretCategory) - SECRET_CATEGORIES.indexOf(b.category as SecretCategory) || a.name.localeCompare(b.name));
  }, [list.data, secretTypes, search, category]);

  const counts = useMemo(() => {
    const c: Record<string, number> = {};
    for (const a of list.data?.items ?? []) c[a.category] = (c[a.category] ?? 0) + 1;
    return c;
  }, [list.data]);

  return (
    <>
      <PageHeader
        title={k.plural}
        description={
          secretTypes
            ? 'Each secret type defines the structure of a secret: its fields, which of them are sensitive, how each is validated, the metadata kept with it and the lifecycle it supports. Published versions are signed and served to Token Vault and customer webhooks.'
            : 'Each application is a provider definition: where its API lives, how credentials are attached and which operations agents may be granted. Published versions are signed and served to Token Vault.'
        }
        actions={
          canCreate && (
            <Button onClick={() => setOpen(true)}>
              <Plus className="h-4 w-4" /> New {k.noun}
            </Button>
          )
        }
      />
      {list.error ? (
        <ErrorState error={list.error} onRetry={list.reload} />
      ) : (
        <Card>
          {secretTypes && (
            <div className="flex flex-col gap-3 border-b border-slate-100 p-4 sm:flex-row sm:items-center">
              <div className="relative flex-1">
                <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-400" />
                <Input aria-label="Search secret types" className="pl-9" placeholder="Search by name, key or description" value={search} onChange={(e) => setSearch(e.target.value)} />
              </div>
              <Select aria-label="Category" className="sm:w-80" value={category} onChange={(e) => setCategory(e.target.value)}>
                <option value="">All categories ({list.data?.items.length ?? 0})</option>
                {SECRET_CATEGORIES.filter((c) => counts[c]).map((c) => (
                  <option key={c} value={c}>
                    {SECRET_CATEGORY_LABELS[c]} ({counts[c]})
                  </option>
                ))}
              </Select>
            </div>
          )}
          <DataTable
            loading={list.loading}
            rows={rows}
            rowKey={(a) => a.key}
            onRowClick={(a) => navigate(`${k.basePath}/${a.key}`)}
            empty={secretTypes ? (list.data?.items.length ? 'No secret types match.' : 'No secret types yet.') : 'No applications yet.'}
            columns={secretTypes ? SECRET_TYPE_COLUMNS : APPLICATION_COLUMNS}
          />
        </Card>
      )}
      <NewEntryDialog kind={kind} open={open} onClose={() => setOpen(false)} onCreated={(key) => navigate(`${k.basePath}/${key}/versions/1`)} />
    </>
  );
}

const nameCell = (a: CmsApplicationSummary, icon: ReactNode) => (
  <div className="flex items-center gap-3">
    <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-md bg-slate-900 text-white">{icon}</div>
    <div>
      <p className="font-medium text-slate-900">{a.name}</p>
      <p className="font-mono text-xs text-slate-500">{a.key}</p>
    </div>
  </div>
);

const updatedColumn: Column<CmsApplicationSummary> = { key: 'updated', header: 'Updated', cell: (a) => <span className="text-sm text-slate-500">{relativeTime(a.updatedAt)}</span>, hideBelow: 'lg' };

const APPLICATION_COLUMNS: Column<CmsApplicationSummary>[] = [
  { key: 'name', header: 'Application', cell: (a) => nameCell(a, <ProviderIcon name={a.icon} className="h-4 w-4" />) },
  {
    key: 'published',
    header: 'Published',
    cell: (a) =>
      a.archived ? (
        <Badge tone="red">Archived</Badge>
      ) : a.publishedVersion && a.availability ? (
        <span className="flex items-center gap-2 text-sm" data-testid={`availability-${a.key}`}>
          v{a.publishedVersion} <AvailabilityBadge availability={a.availability} />
        </span>
      ) : (
        <span className="text-sm text-slate-400">Not yet</span>
      ),
  },
  {
    key: 'open',
    header: 'Open version',
    cell: (a) =>
      a.openVersion ? (
        <div className="space-y-0.5 text-sm">
          <span className="flex items-center gap-2">
            v{a.openVersion.version} <VersionBadge status={a.openVersion.status} />
          </span>
          {a.openVersion.availability !== (a.availability ?? 'available') && (
            <p className="text-xs text-slate-500">Changes it to {a.openVersion.availability === 'available' ? 'available' : 'coming soon'} when published</p>
          )}
        </div>
      ) : (
        <span className="text-sm text-slate-400">—</span>
      ),
  },
  { key: 'ops', header: 'Operations', cell: (a) => <span className="text-sm">{a.operationCount}</span>, hideBelow: 'md' },
  updatedColumn,
];

const SECRET_TYPE_COLUMNS: Column<CmsApplicationSummary>[] = [
  { key: 'name', header: 'Secret type', cell: (a) => nameCell(a, <KeyRound className="h-4 w-4" />) },
  { key: 'category', header: 'Category', cell: (a) => <span className="text-sm">{secretCategoryLabel(a.category)}</span>, hideBelow: 'md' },
  { key: 'fields', header: 'Fields', cell: (a) => <span className="text-sm">{a.fieldCount}</span>, hideBelow: 'md' },
  {
    key: 'published',
    header: 'Published',
    cell: (a) =>
      a.archived ? (
        <Badge tone="red">Archived</Badge>
      ) : a.publishedVersion ? (
        <span className="text-sm">v{a.publishedVersion}</span>
      ) : (
        <span className="text-sm text-slate-400">Not yet</span>
      ),
  },
  {
    key: 'open',
    header: 'Open version',
    cell: (a) =>
      a.openVersion ? (
        <span className="flex items-center gap-2 text-sm">
          v{a.openVersion.version} <VersionBadge status={a.openVersion.status} />
        </span>
      ) : (
        <span className="text-sm text-slate-400">—</span>
      ),
  },
  updatedColumn,
];

function NewEntryDialog({ kind, open, onClose, onCreated }: { kind: CatalogKind; open: boolean; onClose: () => void; onCreated: (key: string) => void }) {
  const k = KINDS[kind];
  const secretType = kind === 'secret_type';
  const [form, setForm] = useState({ key: '', name: '', description: '' });
  const create = useMutation((body: typeof form) => api.post<{ key: string }>(`${k.apiBase}/save`, body));
  const fe = create.fieldErrors;
  return (
    <Dialog
      open={open}
      onClose={onClose}
      title={`New ${k.noun}`}
      description="Starts version 1 as a draft from a working template you then edit."
      footer={
        <>
          <Button variant="outline" onClick={onClose}>
            Cancel
          </Button>
          <Button
            loading={create.pending}
            onClick={async () => {
              const r = await create.run(form);
              if (r) {
                setForm({ key: '', name: '', description: '' });
                onCreated(r.key);
              }
            }}
          >
            Create draft
          </Button>
        </>
      }
    >
      <div className="space-y-4">
        <FormError error={create.error} />
        <Field
          label="Key"
          htmlFor="appKey"
          required
          error={fe.key}
          hint={secretType ? 'Lower-case letters, digits and dashes, e.g. mongodb-atlas. Shares the key space with applications and cannot change later.' : 'Lower-case, e.g. jira. Prefixes every operation id and cannot change later.'}
        >
          <Input id="appKey" className="font-mono" value={form.key} onChange={(e) => setForm({ ...form, key: e.target.value.toLowerCase() })} placeholder={secretType ? 'mongodb-atlas' : 'jira'} invalid={!!fe.key} />
        </Field>
        <Field label="Name" htmlFor="appName" required error={fe.name}>
          <Input id="appName" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} placeholder={secretType ? 'MongoDB Atlas' : 'Jira Cloud'} invalid={!!fe.name} />
        </Field>
        <Field label="Description" htmlFor="appDescription" error={fe.description}>
          <Textarea id="appDescription" rows={2} value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} />
        </Field>
      </div>
    </Dialog>
  );
}
