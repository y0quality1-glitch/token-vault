import { useEffect, useState } from 'react';
import { Link, useNavigate, useParams } from 'react-router-dom';
import { Ban, Github, Pencil, Play, Power, RefreshCw, Trash2 } from 'lucide-react';
import { PERMISSIONS, operationLabel, type IntegrationDetail } from '@token-vault/shared';
import { useApi, useMutation } from '@/hooks/useApi';
import { useAuth } from '@/context/AuthContext';
import { api } from '@/lib/api';
import { Button } from '@/components/ui/button';
import { Card, CardBody, CardHeader, DetailList } from '@/components/ui/card';
import { Badge, EnvBadge, StatusBadge } from '@/components/ui/badge';
import { Field, Input, Textarea } from '@/components/ui/form';
import { Callout, EmptyState, ErrorState, FormError, PageSkeleton } from '@/components/ui/feedback';
import { ConfirmDialog, Dialog } from '@/components/ui/dialog';
import { DataTable } from '@/components/ui/table';
import { PageHeader } from '@/components/ui/navigation';
import { Mono } from '@/components/ui/secret';
import { useToast } from '@/components/ui/toast';
import { formatDateTime, relativeTime, splitList } from '@/lib/utils';

export function IntegrationDetailPage() {
  const { id } = useParams();
  const navigate = useNavigate();
  const toast = useToast();
  const { can } = useAuth();
  const { data: i, error, loading, reload, setData } = useApi<IntegrationDetail>(`/integrations/${id}`);
  const [dialog, setDialog] = useState<null | 'edit' | 'rotate' | 'disable' | 'delete'>(null);
  const [busy, setBusy] = useState(false);
  const manage = can(PERMISSIONS.INTEGRATION_MANAGE);

  if (error) return <ErrorState error={error} onRetry={reload} />;
  if (loading && !i) return <PageSkeleton />;
  if (!i) return null;

  async function action(fn: () => Promise<void>) {
    setBusy(true);
    try {
      await fn();
    } catch (e) {
      toast.error('Action failed', (e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title={
          <span className="flex items-center gap-2">
            <Github className="h-5 w-5" /> {i.displayName}
          </span>
        }
        badge={<StatusBadge status={i.credentialStatus} />}
        description={i.description || undefined}
        breadcrumbs={[{ label: 'Integrations' }, { label: 'Connected Integrations', to: '/integrations/connected' }, { label: i.displayName }]}
        actions={
          manage && (
            <>
              <Button
                variant="outline"
                loading={busy}
                onClick={() =>
                  action(async () => {
                    const r = await api.post<{ valid: boolean; upstreamStatus: number | null; integration: IntegrationDetail }>(`/integrations/${i.id}/test`);
                    setData(r.integration);
                    if (r.valid) toast.success('Connection test passed', `Webhook decrypted the credential; upstream responded ${r.upstreamStatus} (simulated).`);
                    else toast.error('Connection test failed', `Upstream responded ${r.upstreamStatus ?? 'n/a'}. Rotate the credential.`);
                  })
                }
              >
                <Play className="h-4 w-4" /> Test connection
              </Button>
              <Button variant="outline" onClick={() => setDialog('edit')}>
                <Pencil className="h-4 w-4" /> Edit metadata
              </Button>
              <Button variant="outline" onClick={() => setDialog('rotate')}>
                <RefreshCw className="h-4 w-4" /> Rotate / replace
              </Button>
              {i.credentialStatus === 'DISABLED' ? (
                <Button
                  variant="outline"
                  onClick={() =>
                    action(async () => {
                      setData(await api.post<IntegrationDetail>(`/integrations/${i.id}/enable`));
                      toast.success('Integration enabled');
                    })
                  }
                >
                  <Power className="h-4 w-4" /> Enable
                </Button>
              ) : (
                <Button variant="danger-outline" onClick={() => setDialog('disable')}>
                  <Ban className="h-4 w-4" /> Disable
                </Button>
              )}
              <Button variant="danger-outline" onClick={() => setDialog('delete')}>
                <Trash2 className="h-4 w-4" /> Delete
              </Button>
            </>
          )
        }
      />

      <div className="grid gap-6 xl:grid-cols-3">
        <Card className="xl:col-span-2">
          <CardHeader title="Integration details" />
          <CardBody>
            <DetailList
              items={[
                { label: 'Provider', value: 'GitHub (Personal Access Token)' },
                { label: 'Environment', value: <EnvBadge env={i.environment} /> },
                { label: 'Account / organization', value: i.accountLabel },
                { label: 'Integration ID', value: <Mono>{i.id}</Mono> },
                { label: 'Connected by', value: i.createdByName },
                { label: 'Created', value: formatDateTime(i.createdAt) },
                { label: 'Last validated', value: `${formatDateTime(i.lastValidatedAt)} (${relativeTime(i.lastValidatedAt)})` },
                { label: 'Last rotated', value: i.rotatedAt ? formatDateTime(i.rotatedAt) : 'Never' },
                {
                  label: 'Allowed resources',
                  value: i.allowedResources.length ? (
                    <div className="flex flex-wrap gap-1">
                      {i.allowedResources.map((r) => (
                        <Mono key={r}>{r}</Mono>
                      ))}
                    </div>
                  ) : (
                    'Any repository the token can reach'
                  ),
                },
              ]}
            />
          </CardBody>
        </Card>

        <Card>
          <CardHeader title="Credential (reference only)" description="Held by your customer webhook" />
          <CardBody className="space-y-4">
            <DetailList
              columns={1}
              items={[
                { label: 'Credential reference', value: <Mono>{i.credentialReference}</Mono> },
                { label: 'Masked identifier', value: i.maskedIdentifier || 'Pending sync', mono: true },
                { label: 'Fingerprint', value: i.credentialFingerprint || '—', mono: true },
                { label: 'Customer webhook', value: <Link to="/webhook/health" className="text-brand-700 hover:underline">{i.webhookName}</Link> },
              ]}
            />
            <Callout tone="security">The secret value is not stored in Token Vault and cannot be displayed. Only the webhook can decrypt it, and only to inject it into an authorized upstream call.</Callout>
          </CardBody>
        </Card>
      </div>

      <Card>
        <CardHeader
          title="Granted agents & allowed scopes"
          actions={
            can(PERMISSIONS.GRANT_MANAGE) &&
            i.credentialStatus === 'CONNECTED' && (
              <Button size="sm" onClick={() => navigate(`/access/grants/new?integrationId=${i.id}`)}>
                Create grant
              </Button>
            )
          }
        />
        <DataTable
          rows={i.grantedAgents}
          rowKey={(g) => g.grantId}
          onRowClick={(g) => navigate(`/access/grants/${g.grantId}`)}
          empty={<EmptyState title="No agents have been granted access" description="Create an access grant to authorize an agent to use this integration." />}
          columns={[
            { key: 'agent', header: 'Agent', cell: (g) => <span className="font-medium text-slate-800">{g.agentName}</span> },
            { key: 'grant', header: 'Grant', cell: (g) => g.grantName },
            {
              key: 'scopes',
              header: 'Allowed operations',
              cell: (g) => (
                <div className="flex flex-wrap gap-1">
                  {g.scopes.map((s) => (
                    <Badge key={s} tone="blue">
                      {operationLabel(s)}
                    </Badge>
                  ))}
                </div>
              ),
              hideBelow: 'md',
            },
            { key: 'status', header: 'Status', cell: (g) => <StatusBadge status={g.status} /> },
          ]}
        />
      </Card>

      <EditMetadataDialog open={dialog === 'edit'} integration={i} onClose={() => setDialog(null)} onSaved={(x) => setData(x)} />
      <RotateDialog open={dialog === 'rotate'} integration={i} onClose={() => setDialog(null)} onSaved={(x) => setData(x)} />
      <ConfirmDialog
        open={dialog === 'disable'}
        onClose={() => setDialog(null)}
        title="Disable integration?"
        description={`Agents will be denied access to "${i.displayName}" on their next request (INTEGRATION_UNAVAILABLE). The credential stays encrypted in the webhook and can be re-enabled.`}
        confirmLabel="Disable integration"
        loading={busy}
        onConfirm={() =>
          action(async () => {
            setData(await api.post<IntegrationDetail>(`/integrations/${i.id}/disable`));
            setDialog(null);
            toast.success('Integration disabled');
          })
        }
      />
      <ConfirmDialog
        open={dialog === 'delete'}
        onClose={() => setDialog(null)}
        title="Delete integration?"
        description="The customer webhook will be asked to crypto-shred the stored credential, and all grants for this integration will be revoked. This cannot be undone."
        confirmText={i.displayName}
        confirmLabel="Delete integration"
        loading={busy}
        onConfirm={() =>
          action(async () => {
            const r = await api.del<{ credentialShredded: boolean; grantsRevoked: number }>(`/integrations/${i.id}`);
            toast.success('Integration deleted', `${r.grantsRevoked} grant(s) revoked. Credential ${r.credentialShredded ? 'shredded by webhook' : 'could not be reached for shredding'}.`);
            navigate('/integrations/connected');
          })
        }
      />
    </div>
  );
}

function EditMetadataDialog({ open, integration, onClose, onSaved }: { open: boolean; integration: IntegrationDetail; onClose: () => void; onSaved: (i: IntegrationDetail) => void }) {
  const toast = useToast();
  const [form, setForm] = useState({ displayName: '', accountLabel: '', description: '', allowedResources: '' });
  useEffect(() => {
    if (open) setForm({ displayName: integration.displayName, accountLabel: integration.accountLabel, description: integration.description, allowedResources: integration.allowedResources.join('\n') });
  }, [open, integration]);
  const save = useMutation((body: unknown) => api.patch<IntegrationDetail>(`/integrations/${integration.id}`, body));
  const fe = save.fieldErrors;
  return (
    <Dialog
      open={open}
      onClose={onClose}
      title="Edit integration metadata"
      description="Non-secret metadata only."
      footer={
        <>
          <Button variant="outline" onClick={onClose}>
            Cancel
          </Button>
          <Button
            loading={save.pending}
            onClick={async () => {
              const r = await save.run({ ...form, allowedResources: splitList(form.allowedResources) });
              if (r) {
                onSaved(r);
                toast.success('Metadata updated');
                onClose();
              }
            }}
          >
            Save
          </Button>
        </>
      }
    >
      <div className="space-y-4">
        <FormError error={save.error} />
        <Field label="Integration name" error={fe.displayName}>
          <Input value={form.displayName} onChange={(e) => setForm({ ...form, displayName: e.target.value })} invalid={!!fe.displayName} />
        </Field>
        <Field label="Account / organization label" error={fe.accountLabel}>
          <Input value={form.accountLabel} onChange={(e) => setForm({ ...form, accountLabel: e.target.value })} />
        </Field>
        <Field label="Allowed repositories" error={fe['allowedResources.0'] ?? fe.allowedResources} hint="owner/repository per line">
          <Textarea rows={3} className="font-mono text-xs" value={form.allowedResources} onChange={(e) => setForm({ ...form, allowedResources: e.target.value })} />
        </Field>
        <Field label="Description">
          <Textarea rows={2} value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} />
        </Field>
      </div>
    </Dialog>
  );
}

function RotateDialog({ open, integration, onClose, onSaved }: { open: boolean; integration: IntegrationDetail; onClose: () => void; onSaved: (i: IntegrationDetail) => void }) {
  const toast = useToast();
  const [secret, setSecret] = useState('');
  const rotate = useMutation((s: string) => api.post<IntegrationDetail>(`/integrations/${integration.id}/rotate`, { secret: s }));
  useEffect(() => {
    if (!open) setSecret('');
  }, [open]);
  return (
    <Dialog
      open={open}
      onClose={onClose}
      title="Rotate / replace credential"
      description="The new token is sent to the customer webhook, which re-encrypts it under the same credential reference."
      footer={
        <>
          <Button variant="outline" onClick={onClose}>
            Cancel
          </Button>
          <Button
            loading={rotate.pending}
            disabled={secret.length < 20}
            onClick={async () => {
              const r = await rotate.run(secret);
              setSecret('');
              if (r) {
                onSaved(r);
                toast.success('Credential rotated', `New masked identifier ${r.maskedIdentifier}`);
                onClose();
              }
            }}
          >
            Rotate credential
          </Button>
        </>
      }
    >
      <div className="space-y-4">
        <FormError error={rotate.error} />
        <Field label="New Personal Access Token" error={rotate.fieldErrors.secret} hint="Minimum 20 characters. It will not be shown again.">
          <Input type="password" autoComplete="new-password" className="font-mono" value={secret} onChange={(e) => setSecret(e.target.value)} />
        </Field>
        <p className="text-xs text-slate-500">
          Current: <span className="font-mono">{integration.maskedIdentifier}</span> · reference <span className="font-mono">{integration.credentialReference}</span>
        </p>
      </div>
    </Dialog>
  );
}
