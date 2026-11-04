import { useEffect, useMemo, useState } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { Bot, Plus, Search } from 'lucide-react';
import { PERMISSIONS, type Agent, type IssuedCredential } from '@token-vault/shared';
import { useApi, useMutation } from '@/hooks/useApi';
import { useAuth } from '@/context/AuthContext';
import { usePlayground } from '@/context/PlaygroundContext';
import { api } from '@/lib/api';
import { Button } from '@/components/ui/button';
import { Card } from '@/components/ui/card';
import { EnvBadge, StatusBadge } from '@/components/ui/badge';
import { Input, Select } from '@/components/ui/form';
import { Callout, EmptyState, ErrorState, FormError } from '@/components/ui/feedback';
import { Dialog } from '@/components/ui/dialog';
import { DataTable } from '@/components/ui/table';
import { PageHeader } from '@/components/ui/navigation';
import { Mono, SecretOnceDialog } from '@/components/ui/secret';
import { useToast } from '@/components/ui/toast';
import { AGENT_TYPE_LABELS, formatDateTime, relativeTime } from '@/lib/utils';
import { AgentFields, emptyAgentForm, formToBody, validateAgentForm, type AgentFormValues } from './AgentForm';

export function AgentRegistryPage() {
  const navigate = useNavigate();
  const [params, setParams] = useSearchParams();
  const { can } = useAuth();
  const { data, error, loading, reload } = useApi<{ items: Agent[] }>('/agents');
  const [q, setQ] = useState('');
  const [status, setStatus] = useState('');
  const [env, setEnv] = useState('');
  const registerOpen = params.get('register') === '1' && can(PERMISSIONS.AGENT_MANAGE);

  const rows = useMemo(
    () =>
      (data?.items ?? []).filter(
        (a) => (!q || a.name.toLowerCase().includes(q.toLowerCase()) || a.id.includes(q)) && (!status || a.status === status) && (!env || a.environment === env),
      ),
    [data, q, status, env],
  );

  return (
    <div>
      <PageHeader
        title="Agent Registry"
        description="AI agents and workload identities. Each agent authenticates with its own API credential."
        breadcrumbs={[{ label: 'Agents' }, { label: 'Agent Registry' }]}
        actions={
          can(PERMISSIONS.AGENT_MANAGE) && (
            <Button onClick={() => setParams({ register: '1' })}>
              <Plus className="h-4 w-4" /> Register agent
            </Button>
          )
        }
      />
      <div className="mb-4 flex flex-wrap gap-2">
        <div className="relative w-full sm:w-64">
          <Search className="absolute left-2.5 top-2.5 h-4 w-4 text-slate-400" />
          <Input className="pl-8" placeholder="Search name or ID" value={q} onChange={(e) => setQ(e.target.value)} />
        </div>
        <Select className="w-40" value={status} onChange={(e) => setStatus(e.target.value)} aria-label="Filter by status">
          <option value="">All statuses</option>
          <option value="ACTIVE">Active</option>
          <option value="DISABLED">Disabled</option>
        </Select>
        <Select className="w-44" value={env} onChange={(e) => setEnv(e.target.value)} aria-label="Filter by environment">
          <option value="">All environments</option>
          <option value="development">Development</option>
          <option value="staging">Staging</option>
          <option value="production">Production</option>
        </Select>
      </div>
      {error ? (
        <ErrorState error={error} onRetry={reload} />
      ) : (
        <Card>
          <DataTable
            rows={rows}
            loading={loading}
            rowKey={(a) => a.id}
            onRowClick={(a) => navigate(`/agents/${a.id}`)}
            empty={<EmptyState icon={<Bot className="h-5 w-5" />} title={data?.items.length ? 'No agents match the filters' : 'No agents registered'} description="Register an agent to issue it a Token Vault API credential." action={can(PERMISSIONS.AGENT_MANAGE) && !data?.items.length && <Button onClick={() => setParams({ register: '1' })}>Register agent</Button>} />}
            columns={[
              {
                key: 'name',
                header: 'Agent',
                cell: (a) => (
                  <div>
                    <p className="font-medium text-slate-900">{a.name}</p>
                    <p className="text-xs text-slate-500">{AGENT_TYPE_LABELS[a.agentType]}</p>
                  </div>
                ),
              },
              { key: 'id', header: 'Agent ID', cell: (a) => <Mono>{a.id}</Mono>, hideBelow: 'lg' },
              { key: 'env', header: 'Environment', cell: (a) => <EnvBadge env={a.environment} />, hideBelow: 'md' },
              { key: 'owner', header: 'Owner', cell: (a) => <span>{a.ownerName}<span className="block text-xs text-slate-500">{a.ownerTeam}</span></span>, hideBelow: 'xl' },
              { key: 'status', header: 'Status', cell: (a) => <StatusBadge status={a.status} /> },
              { key: 'grants', header: 'Active grants', cell: (a) => <span className="font-medium">{a.activeGrants}</span> },
              { key: 'last', header: 'Last access', cell: (a) => <span className="text-slate-500">{relativeTime(a.lastAccessAt)}</span>, hideBelow: 'md' },
              { key: 'created', header: 'Created', cell: (a) => <span className="text-slate-500">{formatDateTime(a.createdAt)}</span>, hideBelow: 'xl' },
            ]}
          />
        </Card>
      )}
      <RegisterAgentDialog
        open={registerOpen}
        onClose={() => setParams({})}
        onRegistered={() => {
          void reload();
        }}
      />
    </div>
  );
}

function RegisterAgentDialog({ open, onClose, onRegistered }: { open: boolean; onClose: () => void; onRegistered: () => void }) {
  const toast = useToast();
  const navigate = useNavigate();
  const { setCredential } = usePlayground();
  const [form, setForm] = useState<AgentFormValues>(emptyAgentForm);
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [issued, setIssued] = useState<{ agent: Agent; credential: IssuedCredential } | null>(null);
  const submit = useMutation((body: unknown) => api.post<{ agent: Agent; credential: IssuedCredential }>('/agents', body));

  useEffect(() => {
    if (open) {
      setForm(emptyAgentForm);
      setErrors({});
      submit.setError(null);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open]);

  async function onSubmit() {
    const e = validateAgentForm(form);
    setErrors(e);
    if (Object.keys(e).length) return;
    const r = await submit.run(formToBody(form));
    if (r) {
      onClose();
      setIssued(r);
      onRegistered();
      toast.success('Agent registered', `${r.agent.name} (${r.agent.id})`);
    }
  }

  return (
    <>
      <Dialog
        open={open}
        onClose={onClose}
        size="lg"
        title="Register agent"
        description="A unique Agent ID and API credential will be generated. The credential is shown once."
        footer={
          <>
            <Button variant="outline" onClick={onClose}>
              Cancel
            </Button>
            <Button loading={submit.pending} onClick={onSubmit}>
              Register agent
            </Button>
          </>
        }
      >
        <div className="space-y-4">
          <FormError error={submit.error} />
          <AgentFields value={form} onChange={setForm} errors={{ ...submit.fieldErrors, ...errors }} />
          <Callout tone="security">Token Vault stores only a scrypt hash of the agent credential. Agent identity on every request is derived from this credential, never from a caller-supplied agent ID.</Callout>
        </div>
      </Dialog>
      {issued && (
        <SecretOnceDialog
          open
          title={`API credential for ${issued.agent.name}`}
          description={`Agent ID ${issued.agent.id} · key ${issued.credential.keyId}`}
          secret={issued.credential.apiKey}
          onDone={() => {
            const id = issued.agent.id;
            setIssued(null);
            navigate(`/agents/${id}`);
          }}
          extraAction={{
            label: 'Use in Playground',
            onClick: () => {
              setCredential({ apiKey: issued.credential.apiKey, agentId: issued.agent.id, agentName: issued.agent.name });
              setIssued(null);
              navigate('/playground');
            },
          }}
        />
      )}
    </>
  );
}
