import { useEffect, useState } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import { Ban, Bot, KeyRound, Power, RefreshCw, ShieldOff } from 'lucide-react';
import { PERMISSIONS, operationLabel, type AccessRequest, type Agent, type Grant, type IssuedCredential } from '@token-vault/shared';
import { useApi, useMutation } from '@/hooks/useApi';
import { useAuth } from '@/context/AuthContext';
import { usePlayground } from '@/context/PlaygroundContext';
import { api } from '@/lib/api';
import { Button } from '@/components/ui/button';
import { Card, CardBody, CardHeader, DetailList } from '@/components/ui/card';
import { Badge, DecisionBadge, EnvBadge, StatusBadge } from '@/components/ui/badge';
import { Callout, EmptyState, ErrorState, FormError, PageSkeleton } from '@/components/ui/feedback';
import { ConfirmDialog } from '@/components/ui/dialog';
import { DataTable } from '@/components/ui/table';
import { PageHeader, Tabs } from '@/components/ui/navigation';
import { Mono, SecretOnceDialog } from '@/components/ui/secret';
import { useToast } from '@/components/ui/toast';
import { AGENT_TYPE_LABELS, formatDateTime, relativeTime } from '@/lib/utils';
import { AgentFields, agentToForm, formToBody, validateAgentForm, type AgentFormValues } from './AgentForm';

type AgentDetail = Agent & { grants: Grant[]; activity: AccessRequest[]; maskedKey: string };
type Tab = 'overview' | 'grants' | 'activity' | 'configuration';

export function AgentDetailPage() {
  const { id } = useParams();
  const navigate = useNavigate();
  const toast = useToast();
  const { can, session } = useAuth();
  const { setCredential } = usePlayground();
  const { data: a, error, loading, reload } = useApi<AgentDetail>(`/agents/${id}`);
  const [tab, setTab] = useState<Tab>('overview');
  const [confirm, setConfirm] = useState<null | 'rotate' | 'disable' | 'revoke'>(null);
  const [busy, setBusy] = useState(false);
  const [issued, setIssued] = useState<IssuedCredential | null>(null);

  if (error) return <ErrorState error={error} onRetry={reload} />;
  if (loading && !a) return <PageSkeleton />;
  if (!a) return null;

  const canManage = can(PERMISSIONS.AGENT_MANAGE) && (can(PERMISSIONS.AGENT_MANAGE_ANY) || a.ownerUserId === session?.user.id);

  async function act(fn: () => Promise<void>) {
    setBusy(true);
    try {
      await fn();
      await reload();
    } catch (e) {
      toast.error('Action failed', (e as Error).message);
    } finally {
      setBusy(false);
      setConfirm(null);
    }
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title={a.name}
        badge={<StatusBadge status={a.status} />}
        description={a.description}
        breadcrumbs={[{ label: 'Agents' }, { label: 'Agent Registry', to: '/agents' }, { label: a.name }]}
        actions={
          <>
            {canManage && (
              <>
                <Button variant="outline" onClick={() => setConfirm('rotate')}>
                  <RefreshCw className="h-4 w-4" /> Rotate API credential
                </Button>
                {a.status === 'ACTIVE' ? (
                  <Button variant="danger-outline" onClick={() => setConfirm('disable')}>
                    <Ban className="h-4 w-4" /> Disable agent
                  </Button>
                ) : (
                  <Button
                    variant="outline"
                    loading={busy}
                    onClick={() =>
                      act(async () => {
                        await api.post(`/agents/${a.id}/enable`);
                        toast.success('Agent enabled');
                      })
                    }
                  >
                    <Power className="h-4 w-4" /> Enable agent
                  </Button>
                )}
              </>
            )}
            {can(PERMISSIONS.GRANT_REVOKE) && (
              <Button variant="danger-outline" onClick={() => setConfirm('revoke')} disabled={a.activeGrants === 0 && !a.grants.some((g) => g.status === 'PENDING_APPROVAL')}>
                <ShieldOff className="h-4 w-4" /> Revoke all grants
              </Button>
            )}
          </>
        }
      />
      {!canManage && can(PERMISSIONS.AGENT_MANAGE) && <Callout tone="info">You can view this agent, but only its owner or an Organization Owner can change it.</Callout>}

      <Tabs
        value={tab}
        onChange={setTab}
        tabs={[
          { value: 'overview', label: 'Overview' },
          { value: 'grants', label: 'Access Grants', count: a.grants.length },
          { value: 'activity', label: 'Activity', count: a.activity.length },
          { value: 'configuration', label: 'Configuration' },
        ]}
      />

      {tab === 'overview' && (
        <div className="grid gap-6 xl:grid-cols-3">
          <Card className="xl:col-span-2">
            <CardHeader title="Identity" />
            <CardBody>
              <DetailList
                items={[
                  { label: 'Agent ID', value: <Mono>{a.id}</Mono> },
                  { label: 'Agent type', value: AGENT_TYPE_LABELS[a.agentType] },
                  { label: 'Environment', value: <EnvBadge env={a.environment} /> },
                  { label: 'Owner', value: `${a.ownerName} · ${a.ownerTeam}` },
                  { label: 'Created', value: formatDateTime(a.createdAt) },
                  { label: 'Last access', value: `${formatDateTime(a.lastAccessAt)} (${relativeTime(a.lastAccessAt)})` },
                  { label: 'Active grants', value: a.activeGrants },
                  { label: 'Allowed networks', value: a.allowedCidrs.length ? a.allowedCidrs.join(', ') : 'Any' },
                ]}
              />
            </CardBody>
          </Card>
          <Card>
            <CardHeader title="API credential" icon={<KeyRound className="h-4 w-4" />} />
            <CardBody className="space-y-3">
              <DetailList
                columns={1}
                items={[
                  { label: 'Key', value: <Mono>{a.maskedKey}</Mono> },
                  { label: 'Key ID', value: a.credentialKeyId, mono: true },
                  { label: 'Issued', value: formatDateTime(a.credentialIssuedAt) },
                ]}
              />
              <Callout tone="security">Only a scrypt hash is stored. The full credential was shown once at issuance; rotate to issue a new one (the old one stops working immediately).</Callout>
            </CardBody>
          </Card>
          <Card className="xl:col-span-3">
            <CardHeader title="Connect an AI agent (MCP)" description="Let Claude or any MCP client use this agent's grants. The GitHub credential never reaches the agent." icon={<Bot className="h-4 w-4" />} />
            <CardBody className="grid gap-4 lg:grid-cols-3">
              <div className="space-y-2 text-sm text-slate-600">
                <p className="font-medium text-slate-800">1. Get this agent's credential</p>
                <p>
                  Use <strong>Rotate API credential</strong> above. It is shown once; give it to the agent as the <code className="font-mono text-xs">TOKEN_VAULT_API_KEY</code> environment variable, never as a command-line argument.
                </p>
              </div>
              <div className="space-y-2 text-sm text-slate-600">
                <p className="font-medium text-slate-800">2. Print the client configuration</p>
                <p>From the Token Vault checkout, run:</p>
                <pre className="rounded-md bg-slate-950 px-3 py-2 font-mono text-xs text-slate-100">npm run mcp:config</pre>
                <p>It prints config for Claude Code and Claude Desktop with this machine's paths.</p>
              </div>
              <div className="space-y-2 text-sm text-slate-600">
                <p className="font-medium text-slate-800">3. Tools the agent gets</p>
                <p className="font-mono text-xs leading-relaxed text-slate-700">token_vault_list_access · github_get_repository · github_read_file · github_list_issues · github_create_issue</p>
                <p>Each call is authorized against this agent's grants and recorded in Access Logs. Revoking a grant applies to the agent's next call.</p>
              </div>
            </CardBody>
          </Card>
        </div>
      )}

      {tab === 'grants' && (
        <Card>
          <CardHeader
            title="Access grants"
            actions={
              can(PERMISSIONS.GRANT_MANAGE) &&
              a.status === 'ACTIVE' && (
                <Button size="sm" onClick={() => navigate(`/access/grants/new?agentId=${a.id}`)}>
                  Create grant
                </Button>
              )
            }
          />
          <DataTable
            rows={a.grants}
            rowKey={(g) => g.id}
            onRowClick={(g) => navigate(`/access/grants/${g.id}`)}
            empty={<EmptyState title="No grants" description="This agent cannot access any integration (deny by default)." />}
            columns={[
              { key: 'name', header: 'Grant', cell: (g) => <span className="font-medium text-slate-800">{g.name}{g.version > 1 && <span className="ml-1 text-xs text-slate-400">v{g.version}</span>}</span> },
              { key: 'int', header: 'Integration', cell: (g) => g.integrationName },
              { key: 'scopes', header: 'Permissions', cell: (g) => <div className="flex flex-wrap gap-1">{g.scopes.map((s) => <Badge key={s} tone="blue">{operationLabel(s)}</Badge>)}</div>, hideBelow: 'lg' },
              { key: 'status', header: 'Status', cell: (g) => <StatusBadge status={g.status} /> },
              { key: 'exp', header: 'Expiry', cell: (g) => <span className="text-slate-500">{relativeTime(g.expiresAt)}</span>, hideBelow: 'md' },
            ]}
          />
        </Card>
      )}

      {tab === 'activity' && (
        <Card>
          <CardHeader title="Recent activity" description="Last 25 access decisions for this agent" />
          <DataTable
            rows={a.activity}
            rowKey={(r) => r.id}
            onRowClick={can(PERMISSIONS.AUDIT_READ) ? (r) => navigate(`/audit/access-logs?request=${r.id}`) : undefined}
            empty={<EmptyState title="No activity yet" />}
            columns={[
              { key: 't', header: 'Time', cell: (r) => <span className="whitespace-nowrap text-slate-500">{formatDateTime(r.createdAt)}</span> },
              { key: 'op', header: 'Operation', cell: (r) => operationLabel(r.operation) },
              { key: 'res', header: 'Resource', cell: (r) => <span className="font-mono text-xs">{r.resource.repository ?? '—'}</span>, hideBelow: 'md' },
              { key: 'd', header: 'Decision', cell: (r) => <DecisionBadge decision={r.decision} code={r.decisionCode} /> },
              { key: 'reason', header: 'Reason', cell: (r) => <span className="text-slate-500">{r.decisionReason}</span>, hideBelow: 'lg' },
            ]}
          />
        </Card>
      )}

      {tab === 'configuration' && <ConfigurationTab agent={a} canManage={canManage} onSaved={reload} />}

      <ConfirmDialog
        open={confirm === 'rotate'}
        onClose={() => setConfirm(null)}
        tone="primary"
        title="Rotate API credential?"
        description="A new credential is issued and shown once. The current credential stops working immediately; update the agent's secret store."
        confirmLabel="Rotate credential"
        loading={busy}
        onConfirm={() =>
          act(async () => {
            const r = await api.post<{ credential: IssuedCredential }>(`/agents/${a.id}/rotate-credential`);
            setIssued(r.credential);
          })
        }
      />
      <ConfirmDialog
        open={confirm === 'disable'}
        onClose={() => setConfirm(null)}
        title="Disable agent?"
        description={`${a.name} will be denied on its next request (AGENT_DISABLED). Grants are kept and apply again if re-enabled.`}
        confirmLabel="Disable agent"
        loading={busy}
        onConfirm={() =>
          act(async () => {
            await api.post(`/agents/${a.id}/disable`);
            toast.success('Agent disabled');
          })
        }
      />
      <ConfirmDialog
        open={confirm === 'revoke'}
        onClose={() => setConfirm(null)}
        title="Revoke all grants?"
        description={`Every active, scheduled or pending grant for ${a.name} will be revoked. Revocation applies on the next authorization check.`}
        confirmLabel="Revoke all"
        loading={busy}
        onConfirm={() =>
          act(async () => {
            const r = await api.post<{ revoked: number }>(`/agents/${a.id}/revoke-grants`);
            toast.success(`${r.revoked} grant(s) revoked`);
          })
        }
      />
      {issued && (
        <SecretOnceDialog
          open
          title={`New API credential for ${a.name}`}
          description={`Key ${issued.keyId}`}
          secret={issued.apiKey}
          onDone={() => setIssued(null)}
          extraAction={{
            label: 'Use in Playground',
            onClick: () => {
              setCredential({ apiKey: issued.apiKey, agentId: a.id, agentName: a.name });
              setIssued(null);
              navigate('/playground');
            },
          }}
        />
      )}
    </div>
  );
}

function ConfigurationTab({ agent, canManage, onSaved }: { agent: Agent; canManage: boolean; onSaved: () => Promise<void> }) {
  const toast = useToast();
  const [form, setForm] = useState<AgentFormValues>(agentToForm(agent));
  const [errors, setErrors] = useState<Record<string, string>>({});
  const save = useMutation((body: unknown) => api.patch<Agent>(`/agents/${agent.id}`, body));
  useEffect(() => setForm(agentToForm(agent)), [agent]);
  return (
    <Card>
      <CardHeader title="Configuration" description="Agent type cannot be changed after registration." />
      <CardBody className="space-y-4">
        <FormError error={save.error} />
        <fieldset disabled={!canManage} className="disabled:opacity-70">
          <AgentFields value={form} onChange={setForm} errors={{ ...save.fieldErrors, ...errors }} lockType />
        </fieldset>
        {canManage && (
          <div className="flex justify-end">
            <Button
              loading={save.pending}
              onClick={async () => {
                const e = validateAgentForm(form);
                setErrors(e);
                if (Object.keys(e).length) return;
                const { agentType: _t, ...body } = formToBody(form);
                if (await save.run(body)) {
                  toast.success('Configuration saved');
                  await onSaved();
                }
              }}
            >
              Save changes
            </Button>
          </div>
        )}
      </CardBody>
    </Card>
  );
}
