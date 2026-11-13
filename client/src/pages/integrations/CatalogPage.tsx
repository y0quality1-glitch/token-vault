import { useEffect, useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { ExternalLink, Plug, Search } from 'lucide-react';
import { PERMISSIONS, type CatalogEntry } from '@token-vault/shared';
import { usePost } from '@/hooks/useApi';
import { useAuth } from '@/context/AuthContext';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { EmptyState, ErrorState, Skeleton } from '@/components/ui/feedback';
import { Input } from '@/components/ui/form';
import { FilterTabs } from '@/components/ui/table';
import { PageHeader } from '@/components/ui/navigation';
import { ProviderIcon } from '@/components/ui/provider-icon';
import { cn } from '@/lib/utils';
import { getProvider, loadProviders, useProviders } from '@/lib/providers';

/** How often the catalog is refreshed while the page is open (applications are published in the CMS at any time). */
const REFRESH_MS = 15_000;

/**
 * The Integration Catalog is entirely data: every tile, its category, icon, availability
 * and docs link come from a provider definition (bundled, or published and signed in the
 * provider CMS). It refreshes while open, so a newly published application appears
 * without a reload.
 */
export function CatalogPage() {
  const navigate = useNavigate();
  const { can } = useAuth();
  const { data, error, loading, reload } = usePost<{ items: CatalogEntry[] }>('/integration/getCatalog');
  const [filter, setFilter] = useState<'all' | 'connected' | 'not'>('all');
  const [category, setCategory] = useState<string>('all');
  const [query, setQuery] = useState('');
  useProviders(); // re-render when provider sources/versions load

  useEffect(() => {
    const refresh = () => {
      if (document.visibilityState !== 'visible') return;
      void reload();
      void loadProviders().catch(() => undefined);
    };
    const timer = window.setInterval(refresh, REFRESH_MS);
    window.addEventListener('focus', refresh);
    document.addEventListener('visibilitychange', refresh);
    return () => {
      window.clearInterval(timer);
      window.removeEventListener('focus', refresh);
      document.removeEventListener('visibilitychange', refresh);
    };
  }, [reload]);

  const all = data?.items ?? [];
  const categories = useMemo(() => [...new Set(all.map((i) => i.category))].sort(), [all]);
  const q = query.trim().toLowerCase();
  const items = all
    .filter((i) => (filter === 'all' ? true : filter === 'connected' ? i.connectedCount > 0 : i.connectedCount === 0))
    .filter((i) => category === 'all' || i.category === category)
    .filter((i) => !q || [i.name, i.description, i.category, ...i.tags, ...i.authMethods].some((s) => s.toLowerCase().includes(q)));

  return (
    <div>
      <PageHeader
        title="Integration Catalog"
        description="Select an external service to connect. Applications are published by your platform team in the provider CMS; credentials are stored by your customer webhook, never by Token Vault."
        breadcrumbs={[{ label: 'Integrations' }, { label: 'Integration Catalog' }]}
      />
      <div className="mb-4 flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
        <FilterTabs
          value={filter}
          onChange={setFilter}
          options={[
            { value: 'all', label: 'All', count: all.length },
            { value: 'connected', label: 'Connected', count: all.filter((i) => i.connectedCount > 0).length },
            { value: 'not', label: 'Not connected', count: all.filter((i) => i.connectedCount === 0).length },
          ]}
        />
        <div className="relative w-full lg:w-72">
          <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-400" />
          <Input aria-label="Search integrations" placeholder="Search by name, category or tag" className="pl-9" value={query} onChange={(e) => setQuery(e.target.value)} />
        </div>
      </div>
      {categories.length > 1 && (
        <div className="mb-5 flex flex-wrap gap-2" role="group" aria-label="Categories">
          {['all', ...categories].map((c) => (
            <button
              key={c}
              onClick={() => setCategory(c)}
              aria-pressed={category === c}
              className={cn('rounded-full border px-3 py-1 text-xs font-medium transition', category === c ? 'border-brand-600 bg-brand-50 text-brand-700' : 'border-slate-200 bg-white text-slate-600 hover:border-slate-300')}
            >
              {c === 'all' ? 'All categories' : c}
              <span className="ml-1.5 text-slate-400">{c === 'all' ? all.length : all.filter((i) => i.category === c).length}</span>
            </button>
          ))}
        </div>
      )}
      {error ? (
        <ErrorState error={error} onRetry={reload} />
      ) : loading && !data ? (
        <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
          {Array.from({ length: 4 }).map((_, i) => (
            <Skeleton key={i} className="h-56" />
          ))}
        </div>
      ) : items.length === 0 ? (
        <EmptyState icon={<Plug className="h-5 w-5" />} title={all.length ? 'No integrations match these filters' : 'No applications are published yet'} description={all.length ? undefined : 'Applications appear here as soon as they are published in the provider CMS.'} />
      ) : (
        <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
          {items.map((p) => (
            <div key={p.provider} data-testid={`catalog-${p.provider}`} className={cn('flex flex-col rounded-xl border bg-white p-5 shadow-card', p.available ? 'border-slate-200' : 'border-dashed border-slate-200')}>
              <div className="flex items-start justify-between">
                <div className={cn('flex h-11 w-11 items-center justify-center rounded-lg', p.available ? 'bg-slate-900 text-white' : 'bg-slate-100 text-slate-400')}>
                  <ProviderIcon name={p.icon} />
                </div>
                {p.connectedCount > 0 ? (
                  <Badge tone="green" dot>
                    {p.connectedCount} connected
                  </Badge>
                ) : p.available ? (
                  <Badge tone="gray">Not connected</Badge>
                ) : (
                  <Badge tone="amber">Coming soon</Badge>
                )}
              </div>
              <h3 className="mt-4 flex flex-wrap items-center gap-2 font-semibold text-slate-900">
                {p.name}
                {getProvider(p.provider)?.source === 'catalog' && (
                  <Badge tone="violet" className="font-normal">
                    CMS v{p.version}
                  </Badge>
                )}
              </h3>
              <p className="mt-0.5 text-xs font-medium uppercase tracking-wide text-slate-400">{p.category}</p>
              <p className="mt-2 flex-1 text-sm text-slate-500">{p.description}</p>
              {p.tags.length > 0 && (
                <div className="mt-3 flex flex-wrap gap-1">
                  {p.tags.map((t) => (
                    <span key={t} className="rounded bg-slate-100 px-1.5 py-0.5 text-[11px] text-slate-600">
                      {t}
                    </span>
                  ))}
                </div>
              )}
              <p className="mt-3 text-xs text-slate-500">
                Auth: <span className="font-medium text-slate-700">{p.authMethods.join(', ')}</span>
              </p>
              {p.docsUrl && (
                <a href={p.docsUrl} target="_blank" rel="noopener noreferrer" className="mt-1 inline-flex items-center gap-1 text-xs text-brand-700 hover:underline">
                  API documentation <ExternalLink className="h-3 w-3" />
                </a>
              )}
              <Button
                className="mt-4 w-full"
                variant={p.available ? 'primary' : 'outline'}
                disabled={!p.available || !can(PERMISSIONS.INTEGRATION_MANAGE)}
                title={!p.available ? 'Not available yet' : !can(PERMISSIONS.INTEGRATION_MANAGE) ? 'Requires Vault Administrator or Owner' : undefined}
                onClick={() => navigate(`/integrations/connect/${p.provider}`)}
              >
                {p.available ? (p.connectedCount ? 'Connect another' : 'Connect') : 'Coming soon'}
              </Button>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
