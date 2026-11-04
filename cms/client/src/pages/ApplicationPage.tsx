import { useState } from 'react';
import { Archive, GitBranchPlus } from 'lucide-react';
import { useNavigate, useParams } from 'react-router-dom';
import type { CmsApplicationDetail } from '@token-vault/shared';
import { Badge } from '@ui/badge';
import { Button } from '@ui/button';
import { Card, CardBody, CardHeader, DetailList } from '@ui/card';
import { Dialog } from '@ui/dialog';
import { ErrorState, FormError, PageSkeleton } from '@ui/feedback';
import { Field, Textarea } from '@ui/form';
import { PageHeader } from '@ui/navigation';
import { DataTable } from '@ui/table';
import { useToast } from '@ui/toast';
import { useApi, useMutation } from '@tv-hooks/useApi';
import { useAuth } from '@/auth';
import { VersionBadge } from '@/components/VersionBadge';
import { api } from '@/lib/api';
import { formatDateTime } from '@/lib/utils';

export function ApplicationPage() {
  const key = useParams().key!;
  const { user } = useAuth();
  const navigate = useNavigate();
  const toast = useToast();
  const app = useApi<CmsApplicationDetail>(`/applications/${key}`);
  const newVersion = useMutation(() => api.post<{ version: number }>(`/applications/${key}/versions`, {}));
  const [archiving, setArchiving] = useState(false);

  if (app.error) return <ErrorState error={app.error} onRetry={app.reload} />;
  if (!app.data) return <PageSkeleton />;
  const a = app.data;
  const isEditor = user?.role === 'EDITOR' || user?.role === 'ADMIN';

  return (
    <>
      <PageHeader
        breadcrumbs={[{ label: 'Applications', to: '/applications' }, { label: a.name }]}
        title={a.name}
        badge={a.archived ? <Badge tone="red">Archived</Badge> : a.publishedVersion ? <Badge tone="green">Published v{a.publishedVersion}</Badge> : <Badge>Not published</Badge>}
        description={a.description}
        actions={
          <>
            {isEditor && !a.archived && !a.openVersion && (
              <Button
                loading={newVersion.pending}
                onClick={async () => {
                  const r = await newVersion.run();
                  if (r) navigate(`/applications/${key}/versions/${r.version}`);
                }}
              >
                <GitBranchPlus className="h-4 w-4" /> New version
              </Button>
            )}
            {a.openVersion && (
              <Button onClick={() => navigate(`/applications/${key}/versions/${a.openVersion!.version}`)}>Open v{a.openVersion.version}</Button>
            )}
            {user?.role === 'ADMIN' && !a.archived && (
              <Button variant="outline" onClick={() => setArchiving(true)}>
                <Archive className="h-4 w-4" /> Archive
              </Button>
            )}
          </>
        }
      />
      <FormError error={newVersion.error} />
      <div className="grid gap-6 lg:grid-cols-3">
        <Card className="lg:col-span-2">
          <CardHeader title="Versions" description="Only one version can be open (draft or in review) at a time. Published versions are immutable." />
          <DataTable
            rows={a.versions}
            rowKey={(v) => String(v.version)}
            onRowClick={(v) => navigate(`/applications/${key}/versions/${v.version}`)}
            columns={[
              { key: 'v', header: 'Version', cell: (v) => <span className="font-medium">v{v.version}</span> },
              { key: 'status', header: 'Status', cell: (v) => <VersionBadge status={v.status} /> },
              { key: 'by', header: 'Created by', cell: (v) => <span className="text-sm">{v.createdBy}</span>, hideBelow: 'md' },
              { key: 'when', header: 'Published', cell: (v) => <span className="text-sm text-slate-500">{formatDateTime(v.publishedAt)}</span> },
              { key: 'digest', header: 'Digest', cell: (v) => <span className="font-mono text-xs text-slate-500">{v.digest ? v.digest.slice(0, 12) + '…' : '—'}</span>, hideBelow: 'lg' },
            ]}
          />
        </Card>
        <Card>
          <CardHeader title="Application" />
          <CardBody>
            <DetailList
              columns={1}
              items={[
                { label: 'Key', value: a.key, mono: true },
                { label: 'Operations (published)', value: a.operationCount },
                { label: 'Created by', value: a.createdBy },
                { label: 'Created', value: formatDateTime(a.createdAt) },
              ]}
            />
          </CardBody>
        </Card>
      </div>
      <ArchiveDialog
        open={archiving}
        appKey={key}
        onClose={() => setArchiving(false)}
        onDone={() => {
          toast.success('Application archived', 'It is no longer served in the catalog.');
          setArchiving(false);
          void app.reload();
        }}
      />
    </>
  );
}

function ArchiveDialog({ open, appKey, onClose, onDone }: { open: boolean; appKey: string; onClose: () => void; onDone: () => void }) {
  const [reason, setReason] = useState('');
  const archive = useMutation(() => api.post(`/applications/${appKey}/archive`, { reason }));
  return (
    <Dialog
      open={open}
      onClose={onClose}
      title="Archive application"
      description="It disappears from the signed catalog, so Token Vault stops offering it. Its versions are kept for the record."
      footer={
        <>
          <Button variant="outline" onClick={onClose}>
            Cancel
          </Button>
          <Button variant="danger" loading={archive.pending} onClick={async () => (await archive.run()) && onDone()}>
            Archive
          </Button>
        </>
      }
    >
      <div className="space-y-4">
        <FormError error={archive.error} />
        <Field label="Reason" htmlFor="archiveReason" required error={archive.fieldErrors.reason}>
          <Textarea id="archiveReason" rows={2} value={reason} onChange={(e) => setReason(e.target.value)} />
        </Field>
      </div>
    </Dialog>
  );
}
