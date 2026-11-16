import { useEffect, useState } from 'react';
import { Link, useNavigate, useParams } from 'react-router-dom';
import { Ban, Github, Pencil, Play, Power, RefreshCw, Trash2 } from 'lucide-react';
import { PERMISSIONS, ROTATION_INTERVAL_OPTIONS, rotationState, type AccessMode, type IntegrationDetail } from '@token-vault/shared';
import { getProvider, operationLabel } from '@/lib/providers';
import { useApi, useMutation } from '@/hooks/useApi';
import { useAuth } from '@/context/AuthContext';
import { api } from '@/lib/api';
import { Button } from '@/components/ui/button';
import { Card, CardBody, CardHeader, DetailList } from '@/components/ui/card';
import { Badge, EnvBadge, StatusBadge } from '@/components/ui/badge';
import { Field, Input, RadioCard, Select, Textarea } from '@/components/ui/form';
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
              {getProvider(i.provider)?.auth.find((a) => a.id === i.authType)?.kind !== 'oauth2' && (
                <Button variant="outline" onClick={() => setDialog('rotate')}>
                  <RefreshCw className="h-4 w-4" /> Rotate / replace
                </Button>
              )}
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
                { label: 'Provider', value: i.authType === 'GITHUB_APP' ? 'GitHub App (per-request installation tokens)' : `${getProvider(i.provider)?.name ?? i.provider} (${getProvider(i.provider)?.auth.find((a) => a.id === i.authType)?.label ?? i.authType})` },
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
            <RotationReminder i={i} manage={manage} oauth={getProvider(i.provider)?.auth.find((a) => a.id === i.authType)?.kind === 'oauth2'} onSaved={setData} />
            <Callout tone="security">The secret value is not stored in Token Vault and cannot be displayed. Only the webhook can decrypt it, and only to inject it into an authorized upstream call.</Callout>
          </CardBody>
        </Card>
      </div>

      <AccessModeCard i={i} manage={manage} onSaved={setData} />

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
  const isApp = integration.authType === 'GITHUB_APP';
  const [secret, setSecret] = useState('');
  const rotate = useMutation((s: string) => api.post<IntegrationDetail>(`/integrations/${integration.id}/rotate`, isApp ? { privateKey: s } : { secret: s }));
  useEffect(() => {
    if (!open) setSecret('');
  }, [open]);
  return (
    <Dialog
      open={open}
      onClose={onClose}
      title="Rotate / replace credential"
      description={
        isApp
          ? 'The new App private key is sent to the customer webhook, verified with GitHub and re-encrypted under the same credential reference.'
          : 'The new token is sent to the customer webhook, which re-encrypts it under the same credential reference.'
      }
      footer={
        <>
          <Button variant="outline" onClick={onClose}>
            Cancel
          </Button>
          <Button
            loading={rotate.pending}
            disabled={isApp ? !secret.includes('PRIVATE KEY-----') : secret.length < (integration.authType === 'PAT' ? 20 : 8)}
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
        {isApp ? (
          <Field label="New App private key (PEM)" htmlFor="rotatePrivateKey" error={rotate.fieldErrors.privateKey} hint="Generate a new key in the GitHub App settings, then delete the old one there. If the key is configured on the webhook (GITHUB_APP_PRIVATE_KEY), rotate it in the webhook's environment instead.">
            <Textarea id="rotatePrivateKey" rows={4} spellCheck={false} autoComplete="off" className="font-mono text-xs [-webkit-text-security:disc]" value={secret} onChange={(e) => setSecret(e.target.value)} placeholder="-----BEGIN RSA PRIVATE KEY-----" />
          </Field>
        ) : (
          <Field label={`New ${getProvider(integration.provider)?.auth.find((a) => a.id === integration.authType)?.label ?? 'secret'}`} error={rotate.fieldErrors.secret} hint="It will not be shown again.">
            <Input type="password" autoComplete="new-password" className="font-mono" value={secret} onChange={(e) => setSecret(e.target.value)} />
          </Field>
        )}
        <p className="text-xs text-slate-500">
          Current: <span className="font-mono">{integration.maskedIdentifier}</span> · reference <span className="font-mono">{integration.credentialReference}</span>
        </p>
      </div>
    </Dialog>
  );
}

/** Rotation reminder: how often this credential should be rotated, and when it is next due. */
function RotationReminder({ i, manage, oauth, onSaved }: { i: IntegrationDetail; manage: boolean; oauth: boolean; onSaved: (next: IntegrationDetail) => void }) {
  const toast = useToast();
  const save = useMutation((intervalDays: number | null) => api.put<IntegrationDetail>(`/integrations/${i.id}/rotation-policy`, { intervalDays }));
  const r = rotationState(i);
  const options = ROTATION_INTERVAL_OPTIONS.includes(i.rotationIntervalDays as (typeof ROTATION_INTERVAL_OPTIONS)[number]) || !i.rotationIntervalDays ? ROTATION_INTERVAL_OPTIONS : [...ROTATION_INTERVAL_OPTIONS, i.rotationIntervalDays];
  const tone = r.state === 'overdue' ? 'border-amber-300 bg-amber-50 text-amber-900' : r.state === 'due_soon' ? 'border-sky-200 bg-sky-50 text-sky-900' : 'border-slate-200 bg-slate-50 text-slate-700';
  return (
    <div className={`space-y-2 rounded-lg border p-3 text-sm ${tone}`} data-testid="rotation-reminder">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <label htmlFor="rotationInterval" className="font-medium">
          Rotation reminder
        </label>
        <Select
          id="rotationInterval"
          className="w-44"
          disabled={!manage || save.pending}
          value={i.rotationIntervalDays ? String(i.rotationIntervalDays) : ''}
          onChange={async (e) => {
            const next = await save.run(e.target.value ? Number(e.target.value) : null);
            if (next) {
              onSaved(next);
              toast.success(next.rotationIntervalDays ? `Reminder set: every ${next.rotationIntervalDays} days` : 'Reminder removed');
            }
          }}
        >
          <option value="">No reminder</option>
          {options.map((d) => (
            <option key={d} value={d}>
              Every {d} days
            </option>
          ))}
        </Select>
      </div>
      <p>
        {r.state === 'none'
          ? 'No rotation schedule. Set one to get dashboard reminders before the credential is due.'
          : r.state === 'overdue'
            ? `Rotation overdue by ${r.days} day${r.days === 1 ? '' : 's'} (was due ${formatDateTime(r.dueAt)}). The credential keeps working until it is rotated.`
            : `Next rotation due ${formatDateTime(r.dueAt)} (in ${r.days} day${r.days === 1 ? '' : 's'}), counted from the ${i.rotatedAt ? 'last rotation' : 'connection'}.`}
        {r.state !== 'none' && oauth ? ' OAuth connections are renewed by connecting again.' : ''}
      </p>
      <FormError error={save.error} />
    </div>
  );
}

const ACCESS_MODE_TEXT: Record<AccessMode, { title: string; description: string }> = {
  BROKERED: {
    title: 'Brokered',
    description: 'Your webhook calls the application and returns the result. The agent never sees a credential, and Filter responses policies apply.',
  },
  DECISION_ONLY: {
    title: 'Decision only',
    description: 'Token Vault checks every policy and returns a signed decision token. The caller calls the application with its own credentials; your services can verify the token.',
  },
  SHORT_LIVED_CREDENTIAL: {
    title: 'Short-lived credential',
    description: 'Your webhook issues a token for the allowed request (a GitHub App token for one repository, or the OAuth access token) and the caller makes the call with it.',
  },
};

/** How allowed requests are carried out: by the webhook, or by the caller (decision only, short-lived credential). */
function AccessModeCard({ i, manage, onSaved }: { i: IntegrationDetail; manage: boolean; onSaved: (next: IntegrationDetail) => void }) {
  const toast = useToast();
  const [pick, setPick] = useState<AccessMode | null>(null);
  const save = useMutation((accessMode: AccessMode) => api.put<IntegrationDetail>(`/integrations/${i.id}/access-mode`, { accessMode }));
  const method = getProvider(i.provider)?.auth.find((a) => a.id === i.authType);
  const issuable = method?.kind === 'oauth2' || (method?.kind === 'plugin' && method.plugin === 'github_app');
  const apply = async (mode: AccessMode) => {
    const next = await save.run(mode);
    if (next) {
      onSaved(next);
      setPick(null);
      toast.success(`Access mode: ${ACCESS_MODE_TEXT[mode].title}`);
    }
  };
  return (
    <Card>
      <CardHeader title="Access mode" description="What happens after Token Vault allows a request for this integration." />
      <CardBody className="space-y-3">
        <div className="grid gap-3 lg:grid-cols-3" role="radiogroup" aria-label="Access mode">
          {(Object.keys(ACCESS_MODE_TEXT) as AccessMode[]).map((mode) => (
            <RadioCard
              key={mode}
              checked={i.accessMode === mode}
              disabled={!manage || save.pending || (mode === 'SHORT_LIVED_CREDENTIAL' && !issuable)}
              onChange={() => mode !== i.accessMode && (mode === 'BROKERED' ? void apply(mode) : setPick(mode))}
              title={ACCESS_MODE_TEXT[mode].title}
              badge={mode === 'BROKERED' ? <Badge tone="green">Most secure</Badge> : undefined}
              description={mode === 'SHORT_LIVED_CREDENTIAL' && !issuable ? 'Needs a GitHub App or OAuth connection: a stored key or token cannot be narrowed or made to expire.' : ACCESS_MODE_TEXT[mode].description}
            />
          ))}
        </div>
        {i.accessMode !== 'BROKERED' && (
          <Callout tone="warning">
            Token Vault does not see the application's response in this mode, so Filter responses policies cannot apply: requests they cover are refused.
            {i.accessMode === 'SHORT_LIVED_CREDENTIAL' && ' The webhook must allow it with WEBHOOK_ALLOW_CREDENTIAL_ISSUE=true.'}
          </Callout>
        )}
        <FormError error={save.error} />
      </CardBody>
      <ConfirmDialog
        open={!!pick}
        onClose={() => setPick(null)}
        tone="primary"
        title={`Switch to ${pick ? ACCESS_MODE_TEXT[pick].title.toLowerCase() : ''}?`}
        description={
          pick === 'DECISION_ONLY'
            ? 'Agents using this integration get a signed decision instead of a result, and call the application with credentials of their own. Every policy still applies to the decision.'
            : 'Agents using this integration receive a real, short-lived token and call the application themselves. They can use it for anything it allows until it expires (GitHub App tokens: 1 hour, this repository and permissions only).'
        }
        confirmLabel="Switch"
        loading={save.pending}
        onConfirm={() => pick && void apply(pick)}
      />
    </Card>
  );
}
