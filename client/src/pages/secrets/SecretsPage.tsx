import { useEffect, useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { ArrowDown, ArrowUp, Filter, LockKeyhole, Plus, Search } from 'lucide-react';
import { PERMISSIONS, SECRET_CATEGORIES, SECRET_STATUSES, type SecretView } from '@token-vault/shared';
import { usePost } from '@/hooks/useApi';
import { useToast } from '@/components/ui/toast';
import { useAuth } from '@/context/AuthContext';
import { compact } from '@/lib/api';
import { ENV_LABELS, formatDateTime, relativeTime } from '@/lib/utils';
import { Button } from '@/components/ui/button';
import { Card } from '@/components/ui/card';
import { Badge, EnvBadge } from '@/components/ui/badge';
import { Input, Select } from '@/components/ui/form';
import { EmptyState, ErrorState } from '@/components/ui/feedback';
import { DataTable } from '@/components/ui/table';
import { PageHeader } from '@/components/ui/navigation';
import { GrantDialog, SecretsSectionTabs, selectorText } from './secretAccess';
import { SECRET_STATUS_META, SecretStatusBadge, categoryLabel, useSecretTypes } from './secretUi';

const PAGE_SIZE = 25;
type SortBy = 'name' | 'createdAt' | 'updatedAt' | 'expiresAt';

/** Secrets list (spec 4.9.13): metadata only, never a value. */
export function SecretsPage() {
  const navigate = useNavigate();
  const { can } = useAuth();
  const types = useSecretTypes();
  const [search, setSearch] = useState('');
  const [debounced, setDebounced] = useState('');
  const [category, setCategory] = useState('');
  const [typeKey, setTypeKey] = useState('');
  const [environment, setEnvironment] = useState('');
  const [status, setStatus] = useState('');
  const [project, setProject] = useState('');
  const [tag, setTag] = useState('');
  const [sortBy, setSortBy] = useState<SortBy>('updatedAt');
  const [sortOrder, setSortOrder] = useState<'asc' | 'desc'>('desc');
  const [page, setPage] = useState(1);
  const [granting, setGranting] = useState(false);
  const toast = useToast();

  useEffect(() => {
    const t = setTimeout(() => setDebounced(search.trim()), 300);
    return () => clearTimeout(t);
  }, [search]);
  const [dProject, setDProject] = useState('');
  const [dTag, setDTag] = useState('');
  useEffect(() => {
    const t = setTimeout(() => {
      setDProject(project.trim());
      setDTag(tag.trim());
    }, 300);
    return () => clearTimeout(t);
  }, [project, tag]);
  useEffect(() => setPage(1), [debounced, category, typeKey, environment, status, dProject, dTag, sortBy, sortOrder]);

  const body = { ...compact({ search: debounced, category, typeKey, environment, status, project: dProject, tag: dTag, sortBy, sortOrder }), pageNumber: page, pageSize: PAGE_SIZE };
  const { data, error, loading, reload } = usePost<{ items: SecretView[]; total: number }>('/secret/getall', body);
  const filtered = !!(debounced || category || typeKey || environment || status || dProject || dTag);
  const pages = Math.max(1, Math.ceil((data?.total ?? 0) / PAGE_SIZE));

  const typeOptions = useMemo(() => (types.data?.types ?? []).filter((t) => !category || t.category === category).sort((a, b) => a.name.localeCompare(b.name)), [types.data, category]);
  const categories = types.data?.categories.length ? types.data.categories : SECRET_CATEGORIES.map((key) => ({ key, label: categoryLabel(key), count: 0 }));

  return (
    <div>
      <PageHeader
        title="Secrets"
        description="Credentials and other secrets stored on your customer webhook. Token Vault keeps their metadata; values are only shown by an audited reveal."
        breadcrumbs={[{ label: 'Secrets' }]}
        actions={
          <>
            {can(PERMISSIONS.SECRET_MANAGE_ACCESS) && (
              <Button variant="outline" onClick={() => setGranting(true)} data-testid="secret-grant-by-selector">
                <Filter className="h-4 w-4" /> Grant by selector
              </Button>
            )}
            {can(PERMISSIONS.SECRET_CREATE) && (
              <Button onClick={() => navigate('/secrets/new')} data-testid="secret-new">
                <Plus className="h-4 w-4" /> New secret
              </Button>
            )}
          </>
        }
      />
      <SecretsSectionTabs current="/secrets" />
      {granting && (
        <GrantDialog
          types={types.data?.types ?? []}
          onClose={() => setGranting(false)}
          onDone={(g) => {
            setGranting(false);
            toast.success('Access granted', `${g.agent.name} can now read secrets matching ${selectorText(g.selector)}.`);
            navigate('/secrets/access');
          }}
        />
      )}
      <div className="mb-4 flex flex-wrap gap-2" data-testid="secret-filters">
        <div className="relative w-full sm:w-64">
          <Search className="absolute left-2.5 top-2.5 h-4 w-4 text-slate-400" />
          <Input className="pl-8" placeholder="Search name or description" value={search} onChange={(e) => setSearch(e.target.value)} aria-label="Search secrets" data-testid="secret-search" />
        </div>
        <Select
          className="w-52"
          value={category}
          onChange={(e) => {
            setCategory(e.target.value);
            setTypeKey('');
          }}
          aria-label="Filter by category"
          data-testid="secret-filter-category"
        >
          <option value="">All categories</option>
          {categories.map((c) => (
            <option key={c.key} value={c.key}>
              {c.label}
            </option>
          ))}
        </Select>
        <Select className="w-48" value={typeKey} onChange={(e) => setTypeKey(e.target.value)} aria-label="Filter by type" data-testid="secret-filter-type">
          <option value="">All types</option>
          {typeOptions.map((t) => (
            <option key={t.key} value={t.key}>
              {t.name}
            </option>
          ))}
        </Select>
        <Select className="w-44" value={environment} onChange={(e) => setEnvironment(e.target.value)} aria-label="Filter by environment" data-testid="secret-filter-environment">
          <option value="">All environments</option>
          {Object.entries(ENV_LABELS).map(([k, label]) => (
            <option key={k} value={k}>
              {label}
            </option>
          ))}
        </Select>
        <Select className="w-44" value={status} onChange={(e) => setStatus(e.target.value)} aria-label="Filter by status" data-testid="secret-filter-status">
          <option value="">All but deleted</option>
          {SECRET_STATUSES.map((s) => (
            <option key={s} value={s}>
              {SECRET_STATUS_META[s].label}
            </option>
          ))}
        </Select>
        <Input className="w-36" placeholder="Project" value={project} onChange={(e) => setProject(e.target.value)} aria-label="Filter by project" data-testid="secret-filter-project" />
        <Input className="w-36" placeholder="Tag" value={tag} onChange={(e) => setTag(e.target.value)} aria-label="Filter by tag" data-testid="secret-filter-tag" />
        <div className="flex gap-1">
          <Select className="w-40" value={sortBy} onChange={(e) => setSortBy(e.target.value as SortBy)} aria-label="Sort by" data-testid="secret-sort">
            <option value="updatedAt">Last updated</option>
            <option value="createdAt">Created</option>
            <option value="name">Name</option>
            <option value="expiresAt">Expiry</option>
          </Select>
          <Button variant="outline" size="icon" className="h-9 w-9" onClick={() => setSortOrder((o) => (o === 'asc' ? 'desc' : 'asc'))} aria-label={sortOrder === 'asc' ? 'Ascending' : 'Descending'} title={sortOrder === 'asc' ? 'Ascending' : 'Descending'} data-testid="secret-sort-order">
            {sortOrder === 'asc' ? <ArrowUp className="h-4 w-4" /> : <ArrowDown className="h-4 w-4" />}
          </Button>
        </div>
      </div>
      {error ? (
        <ErrorState error={error} onRetry={reload} />
      ) : (
        <Card data-testid="secret-list">
          <DataTable
            rows={data?.items}
            loading={loading}
            rowKey={(s) => s.id}
            onRowClick={(s) => navigate(`/secrets/${s.id}`)}
            empty={
              <EmptyState
                icon={<LockKeyhole className="h-5 w-5" />}
                title={filtered ? 'No secrets match the filters' : 'No secrets yet'}
                description={filtered ? 'Change or clear the filters.' : 'Store a database password, an API key, a certificate or any other secret. Its value is encrypted and kept on your customer webhook.'}
                action={!filtered && can(PERMISSIONS.SECRET_CREATE) && <Button onClick={() => navigate('/secrets/new')}>New secret</Button>}
              />
            }
            columns={[
              {
                key: 'name',
                header: 'Name',
                cell: (s) => (
                  <div className="min-w-0" data-testid="secret-row" data-secret-id={s.id}>
                    <p className="font-medium text-slate-900">{s.name}</p>
                    {s.description && <p className="max-w-xs truncate text-xs text-slate-500">{s.description}</p>}
                  </div>
                ),
              },
              {
                key: 'type',
                header: 'Type',
                cell: (s) => (
                  <div>
                    <p className="text-slate-800">{s.typeName}</p>
                    <p className="text-xs text-slate-500">{categoryLabel(s.category)}</p>
                  </div>
                ),
                hideBelow: 'md',
              },
              { key: 'scope', header: 'Project / workspace', cell: (s) => <span className="font-mono text-[12px] text-slate-600">{s.project}/{s.workspace}</span>, hideBelow: 'lg' },
              { key: 'env', header: 'Environment', cell: (s) => <EnvBadge env={s.environment} />, hideBelow: 'md' },
              { key: 'status', header: 'Status', cell: (s) => <SecretStatusBadge status={s.status} /> },
              { key: 'version', header: 'Version', cell: (s) => (s.activeVersion ? <span className="font-medium">v{s.activeVersion}</span> : <span className="text-slate-400">—</span>), hideBelow: 'lg' },
              {
                key: 'tags',
                header: 'Tags',
                cell: (s) =>
                  s.tags.length ? (
                    <div className="flex max-w-[14rem] flex-wrap gap-1">
                      {s.tags.map((t) => (
                        <Badge key={t}>{t}</Badge>
                      ))}
                    </div>
                  ) : (
                    <span className="text-slate-400">—</span>
                  ),
                hideBelow: 'xl',
              },
              {
                key: 'expires',
                header: 'Expires',
                cell: (s) => (s.expiresAt ? <span className={Date.parse(s.expiresAt) <= Date.now() ? 'text-red-700' : 'text-slate-600'} title={formatDateTime(s.expiresAt)}>{relativeTime(s.expiresAt)}</span> : <span className="text-slate-400">Never</span>),
                hideBelow: 'md',
              },
              { key: 'updated', header: 'Updated', cell: (s) => <span className="text-slate-500" title={formatDateTime(s.updatedAt)}>{relativeTime(s.updatedAt)}</span>, hideBelow: 'xl' },
            ]}
          />
          {data && data.total > PAGE_SIZE && (
            <div className="flex items-center justify-between border-t border-slate-100 px-4 py-2.5 text-sm text-slate-500">
              <span>
                {(page - 1) * PAGE_SIZE + 1}–{Math.min(page * PAGE_SIZE, data.total)} of {data.total}
              </span>
              <div className="flex gap-2">
                <Button variant="outline" size="sm" disabled={page <= 1} onClick={() => setPage((p) => p - 1)}>
                  Previous
                </Button>
                <Button variant="outline" size="sm" disabled={page >= pages} onClick={() => setPage((p) => p + 1)}>
                  Next
                </Button>
              </div>
            </div>
          )}
        </Card>
      )}
    </div>
  );
}
