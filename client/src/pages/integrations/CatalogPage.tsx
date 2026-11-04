import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Bot, Github, Mail, MessageSquare, Plug } from 'lucide-react';
import { PERMISSIONS, type CatalogEntry } from '@token-vault/shared';
import { useApi } from '@/hooks/useApi';
import { useAuth } from '@/context/AuthContext';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { EmptyState, ErrorState, Skeleton } from '@/components/ui/feedback';
import { FilterTabs } from '@/components/ui/table';
import { PageHeader } from '@/components/ui/navigation';
import { cn } from '@/lib/utils';
import { getProvider, useProviders } from '@/lib/providers';

export const PROVIDER_ICONS: Record<string, React.ReactNode> = {
  github: <Github className="h-6 w-6" />,
  google: <Mail className="h-6 w-6" />,
  slack: <MessageSquare className="h-6 w-6" />,
  openai: <Bot className="h-6 w-6" />,
};

export function CatalogPage() {
  const navigate = useNavigate();
  const { can } = useAuth();
  const { data, error, loading, reload } = useApi<{ items: CatalogEntry[] }>('/integrations/catalog');
  const [filter, setFilter] = useState<'all' | 'connected' | 'not'>('all');
  useProviders(); // re-render when provider sources/versions load

  const items = (data?.items ?? []).filter((i) => (filter === 'all' ? true : filter === 'connected' ? i.connectedCount > 0 : i.connectedCount === 0));

  return (
    <div>
      <PageHeader title="Integration Catalog" description="Select an external service to connect. Credentials are stored by your customer webhook, never by Token Vault." breadcrumbs={[{ label: 'Integrations' }, { label: 'Integration Catalog' }]} />
      <div className="mb-4">
        <FilterTabs
          value={filter}
          onChange={setFilter}
          options={[
            { value: 'all', label: 'All', count: data?.items.length },
            { value: 'connected', label: 'Connected', count: data?.items.filter((i) => i.connectedCount > 0).length },
            { value: 'not', label: 'Not connected', count: data?.items.filter((i) => i.connectedCount === 0).length },
          ]}
        />
      </div>
      {error ? (
        <ErrorState error={error} onRetry={reload} />
      ) : loading && !data ? (
        <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
          {Array.from({ length: 4 }).map((_, i) => (
            <Skeleton key={i} className="h-56" />
          ))}
        </div>
      ) : items.length === 0 ? (
        <EmptyState icon={<Plug className="h-5 w-5" />} title="No integrations match this filter" />
      ) : (
        <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
          {items.map((p) => (
            <div key={p.provider} className={cn('flex flex-col rounded-xl border bg-white p-5 shadow-card', p.available ? 'border-slate-200' : 'border-dashed border-slate-200')}>
              <div className="flex items-start justify-between">
                <div className={cn('flex h-11 w-11 items-center justify-center rounded-lg', p.available ? 'bg-slate-900 text-white' : 'bg-slate-100 text-slate-400')}>{PROVIDER_ICONS[p.provider] ?? <Plug className="h-6 w-6" />}</div>
                {p.connectedCount > 0 ? (
                  <Badge tone="green" dot>
                    {p.connectedCount} connected
                  </Badge>
                ) : p.available ? (
                  <Badge tone="gray">Not connected</Badge>
                ) : (
                  <Badge tone="gray">Coming soon</Badge>
                )}
              </div>
              <h3 className="mt-4 flex items-center gap-2 font-semibold text-slate-900">
                {p.name}
                {getProvider(p.provider)?.source === 'catalog' && (
                  <Badge tone="violet" className="font-normal">
                    CMS v{getProvider(p.provider)!.version}
                  </Badge>
                )}
              </h3>
              <p className="mt-1 flex-1 text-sm text-slate-500">{p.description}</p>
              <p className="mt-3 text-xs text-slate-500">
                Auth: <span className="font-medium text-slate-700">{p.authMethods.join(', ')}</span>
              </p>
              <Button
                className="mt-4 w-full"
                variant={p.available ? 'primary' : 'outline'}
                disabled={!p.available || !can(PERMISSIONS.INTEGRATION_MANAGE)}
                title={!can(PERMISSIONS.INTEGRATION_MANAGE) ? 'Requires Vault Administrator or Owner' : undefined}
                onClick={() => navigate(`/integrations/connect/${p.provider}`)}
              >
                {p.available ? (p.connectedCount ? 'Connect another' : 'Connect') : 'Visual placeholder'}
              </Button>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
