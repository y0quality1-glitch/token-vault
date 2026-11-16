import { useState } from 'react';
import { Plus } from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import type { CmsApplicationSummary } from '@token-vault/shared';
import { Badge } from '@ui/badge';
import { ProviderIcon } from '@ui/provider-icon';
import { Button } from '@ui/button';
import { Card } from '@ui/card';
import { Dialog } from '@ui/dialog';
import { ErrorState, FormError } from '@ui/feedback';
import { Field, Input, Textarea } from '@ui/form';
import { PageHeader } from '@ui/navigation';
import { DataTable } from '@ui/table';
import { useMutation } from '@tv-hooks/useApi';
import { useQuery } from '@/lib/hooks';
import { useAuth } from '@/auth';
import { AvailabilityBadge } from '@/components/AvailabilityBadge';
import { VersionBadge } from '@/components/VersionBadge';
import { api } from '@/lib/api';
import { relativeTime } from '@/lib/utils';

export function ApplicationsPage() {
  const { user } = useAuth();
  const navigate = useNavigate();
  const list = useQuery('applications', () => api.page<CmsApplicationSummary>('/application/getall', { pageSize: 200 }));
  const [open, setOpen] = useState(false);
  const canCreate = user?.role === 'EDITOR' || user?.role === 'ADMIN';

  return (
    <>
      <PageHeader
        title="Applications"
        description="Each application is a provider definition: where its API lives, how credentials are attached and which operations agents may be granted. Published versions are signed and served to Token Vault."
        actions={
          canCreate && (
            <Button onClick={() => setOpen(true)}>
              <Plus className="h-4 w-4" /> New application
            </Button>
          )
        }
      />
      {list.error ? (
        <ErrorState error={list.error} onRetry={list.reload} />
      ) : (
        <Card>
          <DataTable
            loading={list.loading}
            rows={list.data?.items}
            rowKey={(a) => a.key}
            onRowClick={(a) => navigate(`/applications/${a.key}`)}
            empty="No applications yet."
            columns={[
              {
                key: 'name',
                header: 'Application',
                cell: (a) => (
                  <div className="flex items-center gap-3">
                    <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-md bg-slate-900 text-white">
                      <ProviderIcon name={a.icon} className="h-4 w-4" />
                    </div>
                    <div>
                      <p className="font-medium text-slate-900">{a.name}</p>
                      <p className="font-mono text-xs text-slate-500">{a.key}</p>
                    </div>
                  </div>
                ),
              },
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
              { key: 'updated', header: 'Updated', cell: (a) => <span className="text-sm text-slate-500">{relativeTime(a.updatedAt)}</span>, hideBelow: 'lg' },
            ]}
          />
        </Card>
      )}
      <NewApplicationDialog open={open} onClose={() => setOpen(false)} onCreated={(key) => navigate(`/applications/${key}/versions/1`)} />
    </>
  );
}

function NewApplicationDialog({ open, onClose, onCreated }: { open: boolean; onClose: () => void; onCreated: (key: string) => void }) {
  const [form, setForm] = useState({ key: '', name: '', description: '' });
  const create = useMutation((body: typeof form) => api.post<{ key: string }>('/application/save', body));
  const fe = create.fieldErrors;
  return (
    <Dialog
      open={open}
      onClose={onClose}
      title="New application"
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
        <Field label="Key" htmlFor="appKey" required error={fe.key} hint="Lower-case, e.g. jira. Prefixes every operation id and cannot change later.">
          <Input id="appKey" className="font-mono" value={form.key} onChange={(e) => setForm({ ...form, key: e.target.value.toLowerCase() })} placeholder="jira" invalid={!!fe.key} />
        </Field>
        <Field label="Name" htmlFor="appName" required error={fe.name}>
          <Input id="appName" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} placeholder="Jira Cloud" invalid={!!fe.name} />
        </Field>
        <Field label="Description" htmlFor="appDescription" error={fe.description}>
          <Textarea id="appDescription" rows={2} value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} />
        </Field>
      </div>
    </Dialog>
  );
}
