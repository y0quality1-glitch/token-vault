import { useState } from 'react';
import { Archive, Eye, EyeOff, GitBranchPlus } from 'lucide-react';
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
import { AvailabilityBadge } from '@/components/AvailabilityBadge';
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
  const [availabilityTarget, setAvailabilityTarget] = useState<'available' | 'coming_soon' | null>(null);

  if (app.error) return <ErrorState error={app.error} onRetry={app.reload} />;
  if (!app.data) return <PageSkeleton />;
  const a = app.data;
  const isEditor = user?.role === 'EDITOR' || user?.role === 'ADMIN';

  return (
    <>
      <PageHeader
        breadcrumbs={[{ label: 'Applications', to: '/applications' }, { label: a.name }]}
        title={a.name}
        badge={
          a.archived ? (
            <Badge tone="red">Archived</Badge>
          ) : a.publishedVersion ? (
            <>
              <Badge tone="green">Published v{a.publishedVersion}</Badge>
              {a.availability && <AvailabilityBadge availability={a.availability} />}
            </>
          ) : (
            <Badge>Not published</Badge>
          )
        }
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
            {user?.role === 'ADMIN' && !a.archived && a.availability && (
              <Button
                variant={a.availability === 'coming_soon' ? 'primary' : 'outline'}
                disabled={!!a.openVersion}
                title={a.openVersion ? `v${a.openVersion.version} is open: set the availability in that version, or withdraw it first` : undefined}
                onClick={() => setAvailabilityTarget(a.availability === 'coming_soon' ? 'available' : 'coming_soon')}
              >
                {a.availability === 'coming_soon' ? (
                  <>
                    <Eye className="h-4 w-4" /> Make available
                  </>
                ) : (
                  <>
                    <EyeOff className="h-4 w-4" /> Mark as coming soon
                  </>
                )}
              </Button>
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
      {availabilityTarget && (
        <AvailabilityDialog
          appKey={key}
          name={a.name}
          nextVersion={Math.max(0, ...a.versions.map((v) => v.version)) + 1}
          target={availabilityTarget}
          onClose={() => setAvailabilityTarget(null)}
          onDone={(r) => {
            setAvailabilityTarget(null);
            toast.success(`Published v${r.version}`, r.availability === 'available' ? 'Token Vault offers it for connection after its next sync (about 30 seconds).' : 'Token Vault lists it as coming soon after its next sync.');
            void app.reload();
          }}
        />
      )}
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

function AvailabilityDialog({ appKey, name, nextVersion, target, onClose, onDone }: { appKey: string; name: string; nextVersion: number; target: 'available' | 'coming_soon'; onClose: () => void; onDone: (r: { version: number; availability: string }) => void }) {
  const [note, setNote] = useState('');
  const change = useMutation(() => api.post<{ version: number; availability: string }>(`/applications/${appKey}/availability`, { availability: target, note }));
  const available = target === 'available';
  return (
    <Dialog
      open
      onClose={onClose}
      title={available ? `Make ${name} available` : `Mark ${name} as coming soon`}
      description={`Publishes v${nextVersion} right away with only the availability changed. It is signed and recorded in the audit log.`}
      footer={
        <>
          <Button variant="outline" onClick={onClose}>
            Cancel
          </Button>
          <Button variant={available ? 'primary' : 'danger'} loading={change.pending} onClick={async () => (await change.run().then((r) => r && onDone(r)))}>
            {available ? 'Make available' : 'Mark as coming soon'}
          </Button>
        </>
      }
    >
      <div className="space-y-4">
        <FormError error={change.error} />
        <p className="text-sm text-slate-600">
          {available
            ? 'Admins in Token Vault can then connect it from the Integration Catalog. Its API hosts, authentication and operations stay exactly as reviewed.'
            : 'It stays in the Integration Catalog, but nobody can connect it. Integrations that are already connected keep working.'}
        </p>
        <Field label="Note (optional)" htmlFor="availabilityNote" hint="Recorded with the version and in the audit log">
          <Textarea id="availabilityNote" rows={2} value={note} onChange={(e) => setNote(e.target.value)} />
        </Field>
      </div>
    </Dialog>
  );
}

