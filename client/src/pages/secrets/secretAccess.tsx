import { useMemo, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { Bot, Filter, KeyRound, Plus, ShieldOff } from 'lucide-react';
import {
  PERMISSIONS,
  orderedFields,
  type Agent,
  type SecretAccessGrantView,
  type SecretGrantStatus,
  type SecretSelector,
  type SecretTypeInfo,
  type SecretView,
} from '@token-vault/shared';
import { useMutation, usePost } from '@/hooks/useApi';
import { useAuth } from '@/context/AuthContext';
import { api, type ApiError } from '@/lib/api';
import { ENV_LABELS, formatDateTime, fromLocalInput, relativeTime, splitList } from '@/lib/utils';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardHeader } from '@/components/ui/card';
import { Checkbox, Field, Input, Select, Textarea } from '@/components/ui/form';
import { Callout, EmptyState, ErrorState } from '@/components/ui/feedback';
import { ConfirmDialog, Dialog } from '@/components/ui/dialog';
import { DataTable, type Column } from '@/components/ui/table';
import { Tabs } from '@/components/ui/navigation';
import { useToast } from '@/components/ui/toast';
import { ApiErrorCallout } from './secretUi';

/**
 * Secret access (spec 4.9.9, 4.9.15): grants that let an agent retrieve one secret or every
 * secret matching a selector, shown on the secret page, the Access tab and the agent page.
 * Default deny: an agent reads a secret only through an active grant.
 */

// ── section tabs ─────────────────────────────────────────────────

type Section = '/secrets' | '/secrets/access' | '/secrets/approvals' | '/secrets/rotations' | '/secrets/policies';

/** Tabs across the Secrets section: the list, every access grant, and held retrievals. */
export function SecretsSectionTabs({ current }: { current: Section }) {
  const navigate = useNavigate();
  return (
    <div className="mb-4" data-testid="secrets-section-tabs">
      <Tabs<Section>
        value={current}
        onChange={(v) => navigate(v)}
        tabs={[
          { value: '/secrets', label: 'Secrets' },
          { value: '/secrets/access', label: 'Access grants' },
          { value: '/secrets/approvals', label: 'Retrieval approvals' },
          { value: '/secrets/rotations', label: 'Rotations' },
          { value: '/secrets/policies', label: 'Expiry & retention' },
        ]}
      />
    </div>
  );
}

// ── display pieces ───────────────────────────────────────────────

const GRANT_STATUS: Record<SecretGrantStatus, { label: string; tone: 'green' | 'red' | 'gray' }> = {
  ACTIVE: { label: 'Active', tone: 'green' },
  REVOKED: { label: 'Revoked', tone: 'red' },
  EXPIRED: { label: 'Expired', tone: 'gray' },
};

export function GrantStatusBadge({ status }: { status: SecretGrantStatus }) {
  const m = GRANT_STATUS[status] ?? { label: status, tone: 'gray' as const };
  return (
    <span data-testid="secret-grant-status" data-status={status}>
      <Badge tone={m.tone} dot>
        {m.label}
      </Badge>
    </span>
  );
}

const SELECTOR_KEYS: [keyof SecretSelector, string][] = [
  ['project', 'project'],
  ['workspace', 'workspace'],
  ['environment', 'env'],
  ['typeKey', 'type'],
  ['tag', 'tag'],
];

export function selectorText(s: SecretSelector | null): string {
  if (!s) return '';
  return SELECTOR_KEYS.filter(([k]) => s[k])
    .map(([k, label]) => `${label}=${s[k]}`)
    .join(' · ');
}

/** What a grant covers: one secret (linked) or a selector. */
function GrantTarget({ g, linkSecret = true }: { g: SecretAccessGrantView; linkSecret?: boolean }) {
  if (g.secret) {
    return (
      <span className="flex flex-wrap items-center gap-1.5">
        <Badge tone="blue">Direct</Badge>
        {linkSecret ? (
          <Link className="text-brand-700 hover:underline" to={`/secrets/${g.secret.id}`} onClick={(e) => e.stopPropagation()}>
            {g.secret.name}
          </Link>
        ) : (
          <span className="text-slate-800">{g.secret.name}</span>
        )}
      </span>
    );
  }
  return (
    <span className="flex flex-wrap items-center gap-1.5">
      <Badge tone="violet">
        <Filter className="h-3 w-3" /> Selector
      </Badge>
      <span className="font-mono text-[12px] text-slate-600">{selectorText(g.selector)}</span>
    </span>
  );
}

function FieldsText({ fields }: { fields: string[] }) {
  if (!fields.length) return <span className="text-slate-500">All fields</span>;
  return (
    <div className="flex max-w-[14rem] flex-wrap gap-1">
      {fields.map((f) => (
        <Badge key={f}>{f}</Badge>
      ))}
    </div>
  );
}

/** Grants table shared by the secret page, the Access tab and the agent page. */
export function GrantsTable({
  grants,
  loading,
  empty,
  onRevoke,
  show = { agent: true, target: true },
  linkSecret = true,
}: {
  grants: SecretAccessGrantView[] | null | undefined;
  loading?: boolean;
  empty: React.ReactNode;
  onRevoke?: (g: SecretAccessGrantView) => void;
  show?: { agent: boolean; target: boolean };
  linkSecret?: boolean;
}) {
  const columns: Column<SecretAccessGrantView>[] = [
    {
      key: 'agent',
      header: show.agent ? 'Agent' : 'Grant',
      cell: (g) => (
        <div className="min-w-0" data-testid="secret-grant-row" data-grant-id={g.id} data-status={g.status}>
          {show.agent ? (
            <Link className="font-medium text-brand-700 hover:underline" to={`/agents/${g.agent.id}`} onClick={(e) => e.stopPropagation()}>
              {g.agent.name}
            </Link>
          ) : (
            <span className="font-mono text-xs text-slate-500">{g.id}</span>
          )}
          {g.description && <p className="max-w-xs truncate text-xs text-slate-500">{g.description}</p>}
        </div>
      ),
    },
    ...(show.target ? [{ key: 'target', header: 'Covers', cell: (g: SecretAccessGrantView) => <GrantTarget g={g} linkSecret={linkSecret} /> }] : []),
    { key: 'fields', header: 'Fields', cell: (g) => <FieldsText fields={g.fields} />, hideBelow: 'md' },
    { key: 'versions', header: 'Versions', cell: (g) => <span className="whitespace-nowrap text-slate-600">{g.versions === 'ANY' ? 'Any version' : 'Active only'}</span>, hideBelow: 'lg' },
    {
      key: 'cidrs',
      header: 'IP ranges',
      cell: (g) => (g.allowedCidrs.length ? <span className="font-mono text-[12px] text-slate-600">{g.allowedCidrs.join(', ')}</span> : <span className="text-slate-400">Any</span>),
      hideBelow: 'xl',
    },
    {
      key: 'approval',
      header: 'Approval',
      cell: (g) => (g.requireApproval ? <Badge tone="amber">Approval required</Badge> : <span className="text-slate-400">—</span>),
      hideBelow: 'lg',
    },
    {
      key: 'valid',
      header: 'Valid',
      cell: (g) => (
        <span className="whitespace-nowrap text-xs text-slate-500">
          <span className="block" title={formatDateTime(g.validFrom)}>
            from {formatDateTime(g.validFrom)}
          </span>
          <span className="block" title={g.expiresAt ? formatDateTime(g.expiresAt) : undefined}>
            {g.expiresAt ? `until ${formatDateTime(g.expiresAt)}` : 'no expiry'}
          </span>
        </span>
      ),
      hideBelow: 'xl',
    },
    {
      key: 'status',
      header: 'Status',
      cell: (g) => (
        <div>
          <GrantStatusBadge status={g.status} />
          {g.status === 'REVOKED' && g.revokedAt && (
            <span className="mt-0.5 block text-xs text-slate-500" title={g.revocationReason ?? undefined}>
              {relativeTime(g.revokedAt)}
              {g.revokedBy ? ` by ${g.revokedBy}` : ''}
            </span>
          )}
        </div>
      ),
    },
    {
      key: 'uses',
      header: 'Uses',
      cell: (g) => (
        <span className="whitespace-nowrap text-slate-600">
          {g.useCount}
          <span className="block text-xs text-slate-500">{g.lastUsedAt ? `last ${relativeTime(g.lastUsedAt)}` : 'never used'}</span>
        </span>
      ),
      hideBelow: 'md',
    },
    {
      key: 'created',
      header: 'Created',
      cell: (g) => (
        <span className="text-slate-500">
          {g.createdBy.name}
          <span className="block text-xs" title={formatDateTime(g.createdAt)}>
            {relativeTime(g.createdAt)}
          </span>
        </span>
      ),
      hideBelow: 'xl',
    },
  ];
  if (onRevoke) {
    columns.push({
      key: 'actions',
      header: '',
      className: 'text-right',
      cell: (g) =>
        g.status === 'ACTIVE' ? (
          <Button variant="ghost" size="sm" className="text-red-700 hover:bg-red-50 hover:text-red-800" onClick={() => onRevoke(g)} data-testid="secret-grant-revoke">
            <ShieldOff className="h-3.5 w-3.5" /> Revoke
          </Button>
        ) : null,
    });
  }
  return <DataTable rows={grants} loading={loading} rowKey={(g) => g.id} columns={columns} empty={empty} dense />;
}

// ── agents ───────────────────────────────────────────────────────

export function useAgents(enabled = true) {
  return usePost<{ items: Agent[] }>(enabled ? '/agent/getall' : null);
}

// ── grant dialog ─────────────────────────────────────────────────

const GRANT_FORM_FIELDS = ['agentId', 'secretId', 'fields', 'versions', 'allowedCidrs', 'requireApproval', 'expiresAt', 'description', 'selector', 'selector.project', 'selector.workspace', 'selector.environment', 'selector.typeKey', 'selector.tag'];

/**
 * Grants an agent access. With `secret`, the grant names that secret; without, the admin builds a
 * selector (project, workspace, environment, type, tag; at least one).
 */
export function GrantDialog({ secret, types, defaultAgentId, onClose, onDone }: { secret?: SecretView; types: SecretTypeInfo[]; defaultAgentId?: string; onClose: () => void; onDone: (g: SecretAccessGrantView) => void }) {
  const agents = useAgents();
  const [agentId, setAgentId] = useState(defaultAgentId ?? '');
  const [selector, setSelector] = useState<Required<Record<keyof SecretSelector, string>>>({ project: '', workspace: '', environment: '', typeKey: '', tag: '' });
  const [fields, setFields] = useState<string[]>([]);
  const [versions, setVersions] = useState<'ACTIVE' | 'ANY'>('ACTIVE');
  const [requireApproval, setRequireApproval] = useState(false);
  const [cidrs, setCidrs] = useState('');
  const [expiresAt, setExpiresAt] = useState('');
  const [description, setDescription] = useState('');
  const [errors, setErrors] = useState<Record<string, string>>({});
  const submit = useMutation((body: unknown) => api.post<SecretAccessGrantView>('/secretAccess/save', body));
  const allErrors: Record<string, string> = { ...submit.fieldErrors, ...errors };

  const typeKey = secret ? secret.typeKey : selector.typeKey;
  const type = types.find((t) => t.key === typeKey) ?? null;
  const typeFields = type ? orderedFields(type.fields) : [];
  const sortedTypes = useMemo(() => [...types].sort((a, b) => a.name.localeCompare(b.name)), [types]);
  const agentOptions = useMemo(() => [...(agents.data?.items ?? [])].sort((a, b) => a.name.localeCompare(b.name)), [agents.data]);

  const setSel = (k: keyof SecretSelector, v: string) => {
    setSelector((s) => ({ ...s, [k]: v }));
    if (k === 'typeKey') setFields([]);
  };

  async function onSubmit() {
    const e: Record<string, string> = {};
    if (!agentId) e.agentId = 'Choose an agent';
    const sel = Object.fromEntries(Object.entries(selector).map(([k, v]) => [k, v.trim()]).filter(([, v]) => v)) as SecretSelector;
    if (!secret && !Object.keys(sel).length) e.selector = 'Give at least one of project, workspace, environment, type or tag';
    const cidrList = splitList(cidrs);
    if (cidrList.length > 20) e.allowedCidrs = 'At most 20 ranges';
    if (expiresAt) {
      const t = Date.parse(fromLocalInput(expiresAt));
      if (Number.isNaN(t)) e.expiresAt = 'Not a valid date';
      else if (t <= Date.now()) e.expiresAt = 'Must be in the future';
    }
    setErrors(e);
    if (Object.keys(e).length) return;
    const r = await submit.run({
      agentId,
      ...(secret ? { secretId: secret.id } : { selector: sel }),
      ...(description.trim() ? { description: description.trim() } : {}),
      ...(fields.length && fields.length < typeFields.length ? { fields } : {}),
      versions,
      allowedCidrs: cidrList,
      requireApproval,
      ...(expiresAt ? { expiresAt: fromLocalInput(expiresAt) } : {}),
    });
    if (r) onDone(r);
  }

  return (
    <Dialog
      open
      onClose={onClose}
      size="lg"
      title={secret ? `Grant access to ${secret.name}` : 'Grant access by selector'}
      description={
        secret
          ? 'The agent may retrieve this secret through its own API key, within the limits below. Every retrieval is audited.'
          : 'The agent may retrieve every secret that matches all the given keys, including secrets created later. Every retrieval is audited.'
      }
      footer={
        <>
          <Button variant="outline" onClick={onClose}>
            Cancel
          </Button>
          <Button loading={submit.pending} onClick={onSubmit} data-testid="secret-grant-submit">
            <KeyRound className="h-4 w-4" /> Grant access
          </Button>
        </>
      }
    >
      <form
        className="space-y-5"
        data-testid="secret-grant-form"
        onSubmit={(ev) => {
          ev.preventDefault();
          void onSubmit();
        }}
      >
        <Field label="Agent" htmlFor="secret-grant-agent" required error={allErrors.agentId} hint={agents.error ? `Agents could not be loaded: ${agents.error.message}` : undefined}>
          <Select id="secret-grant-agent" value={agentId} onChange={(ev) => setAgentId(ev.target.value)} invalid={!!allErrors.agentId} data-testid="secret-grant-agent">
            <option value="">{agents.loading ? 'Loading agents…' : 'Choose an agent…'}</option>
            {agentOptions.map((a) => (
              <option key={a.id} value={a.id}>
                {a.name}
                {a.status !== 'ACTIVE' ? ` (${a.status.toLowerCase()})` : ''}
              </option>
            ))}
          </Select>
        </Field>

        {!secret && (
          <div className="space-y-3 rounded-lg border border-slate-200 p-4" data-testid="secret-grant-selector">
            <div>
              <p className="text-sm font-medium text-slate-800">Selector</p>
              <p className="text-xs text-slate-500">A secret is covered when it matches every key you fill in. Give at least one.</p>
            </div>
            <div className="grid gap-3 sm:grid-cols-2">
              <Field label="Project" htmlFor="secret-grant-project" error={allErrors['selector.project']}>
                <Input id="secret-grant-project" value={selector.project} onChange={(ev) => setSel('project', ev.target.value)} placeholder="payments" autoComplete="off" data-testid="secret-grant-project" />
              </Field>
              <Field label="Workspace" htmlFor="secret-grant-workspace" error={allErrors['selector.workspace']}>
                <Input id="secret-grant-workspace" value={selector.workspace} onChange={(ev) => setSel('workspace', ev.target.value)} placeholder="default" autoComplete="off" data-testid="secret-grant-workspace" />
              </Field>
              <Field label="Environment" htmlFor="secret-grant-environment" error={allErrors['selector.environment']}>
                <Select id="secret-grant-environment" value={selector.environment} onChange={(ev) => setSel('environment', ev.target.value)} data-testid="secret-grant-environment">
                  <option value="">Any environment</option>
                  {Object.entries(ENV_LABELS).map(([k, label]) => (
                    <option key={k} value={k}>
                      {label}
                    </option>
                  ))}
                </Select>
              </Field>
              <Field label="Secret type" htmlFor="secret-grant-type" error={allErrors['selector.typeKey']}>
                <Select id="secret-grant-type" value={selector.typeKey} onChange={(ev) => setSel('typeKey', ev.target.value)} data-testid="secret-grant-type">
                  <option value="">Any type</option>
                  {sortedTypes.map((t) => (
                    <option key={t.key} value={t.key}>
                      {t.name}
                    </option>
                  ))}
                </Select>
              </Field>
              <Field label="Tag" htmlFor="secret-grant-tag" error={allErrors['selector.tag']}>
                <Input id="secret-grant-tag" value={selector.tag} onChange={(ev) => setSel('tag', ev.target.value)} placeholder="ci" autoComplete="off" data-testid="secret-grant-tag" />
              </Field>
            </div>
            {allErrors.selector && <p className="text-xs text-red-600">{allErrors.selector}</p>}
            {allErrors.secretId && <p className="text-xs text-red-600">{allErrors.secretId}</p>}
          </div>
        )}
        {secret && allErrors.secretId && <Callout tone="danger">{allErrors.secretId}</Callout>}

        <div className="space-y-2" data-testid="secret-grant-fields">
          <p className="text-sm font-medium text-slate-700">Fields the agent may read</p>
          {type ? (
            <>
              <p className="text-xs text-slate-500">Leave all unticked to allow every field.</p>
              <div className="grid gap-2 sm:grid-cols-2">
                {typeFields.map(([k, f]) => (
                  <Checkbox key={k} id={`secret-grant-field-${k}`} checked={fields.includes(k)} onChange={(c) => setFields((xs) => (c ? [...xs, k] : xs.filter((x) => x !== k)))} label={f.label} description={f.sensitive ? 'Sensitive' : undefined} />
                ))}
              </div>
            </>
          ) : (
            <p className="text-xs text-slate-500">{secret ? `The secret type ${secret.typeKey} is not available; the grant allows every field.` : 'All fields. Choose a secret type in the selector to limit fields.'}</p>
          )}
          {allErrors.fields && <p className="text-xs text-red-600">{allErrors.fields}</p>}
        </div>

        <div className="grid gap-4 sm:grid-cols-2">
          <Field label="Versions" htmlFor="secret-grant-versions" error={allErrors.versions}>
            <Select id="secret-grant-versions" value={versions} onChange={(ev) => setVersions(ev.target.value as 'ACTIVE' | 'ANY')} data-testid="secret-grant-versions">
              <option value="ACTIVE">Active version only</option>
              <option value="ANY">Any version (incl. previous)</option>
            </Select>
          </Field>
          <Field label="Expires" htmlFor="secret-grant-expires" error={allErrors.expiresAt} hint="Empty: the grant does not expire.">
            <Input id="secret-grant-expires" type="datetime-local" value={expiresAt} onChange={(ev) => setExpiresAt(ev.target.value)} invalid={!!allErrors.expiresAt} data-testid="secret-grant-expires" />
          </Field>
        </div>

        <Field label="Allowed IP ranges" htmlFor="secret-grant-cidrs" error={allErrors.allowedCidrs} hint="CIDR ranges, separated by commas or new lines. Empty: any source address.">
          <Textarea id="secret-grant-cidrs" rows={2} value={cidrs} onChange={(ev) => setCidrs(ev.target.value)} placeholder="10.0.0.0/8, 192.168.1.0/24" spellCheck={false} className="font-mono text-[13px]" invalid={!!allErrors.allowedCidrs} data-testid="secret-grant-cidrs" />
        </Field>

        <div data-testid="secret-grant-approval">
          <Checkbox
            id="secret-grant-require-approval"
            checked={requireApproval}
            onChange={setRequireApproval}
            label="Require approval for each retrieval"
            description="The agent's request is held until another member approves it under Retrieval approvals (valid once, for 15 minutes)."
          />
        </div>

        <Field label="Description (optional)" htmlFor="secret-grant-description" error={allErrors.description}>
          <Input id="secret-grant-description" maxLength={300} value={description} onChange={(ev) => setDescription(ev.target.value)} placeholder="Billing worker reads the database login at start-up" data-testid="secret-grant-description" />
        </Field>

        <ApiErrorCallout error={submit.error} shownFields={GRANT_FORM_FIELDS} />
      </form>
    </Dialog>
  );
}

// ── revoke ───────────────────────────────────────────────────────

export function RevokeGrantDialog({ grant, onClose, onDone }: { grant: SecretAccessGrantView; onClose: () => void; onDone: () => void }) {
  const toast = useToast();
  const [reason, setReason] = useState('');
  const revoke = useMutation((body: unknown) => api.post<SecretAccessGrantView>('/secretAccess/revoke', body));
  const target = grant.secret ? grant.secret.name : `secrets matching ${selectorText(grant.selector)}`;
  return (
    <ConfirmDialog
      open
      onClose={onClose}
      title="Revoke access"
      confirmLabel="Revoke access"
      tone="danger"
      loading={revoke.pending}
      onConfirm={async () => {
        const r = await revoke.run({ id: grant.id, ...(reason.trim() ? { reason: reason.trim() } : {}) });
        if (r) {
          toast.success('Access revoked', `${grant.agent.name} can no longer read ${target}.`);
          onDone();
        }
      }}
      description={
        <>
          <strong>{grant.agent.name}</strong> can no longer read <strong>{target}</strong> through this grant. Retrievals waiting for approval under it are cancelled. This cannot be undone.
        </>
      }
    >
      <div className="space-y-3" data-testid="secret-grant-revoke-dialog">
        <Field label="Reason (recorded in the audit log)" htmlFor="secret-grant-revoke-reason">
          <Textarea id="secret-grant-revoke-reason" rows={2} maxLength={300} value={reason} onChange={(e) => setReason(e.target.value)} data-testid="secret-grant-revoke-reason" />
        </Field>
        <ApiErrorCallout error={revoke.error} />
      </div>
    </ConfirmDialog>
  );
}

// ── secret page card ─────────────────────────────────────────────

/** "Access" card on the secret page: the grants (direct and selector) that cover this secret. */
export function SecretAccessCard({ secret, types }: { secret: SecretView; types: SecretTypeInfo[] }) {
  const { can } = useAuth();
  const toast = useToast();
  const { data, error, loading, reload } = usePost<{ items: SecretAccessGrantView[]; total: number }>('/secretAccess/getall', { secretId: secret.id });
  const [granting, setGranting] = useState(false);
  const [revoking, setRevoking] = useState<SecretAccessGrantView | null>(null);
  const manage = can(PERMISSIONS.SECRET_MANAGE_ACCESS);
  const active = (data?.items ?? []).filter((g) => g.status === 'ACTIVE').length;

  return (
    <Card data-testid="secret-access-card">
      <CardHeader
        title={`Access${data ? ` (${active} active)` : ''}`}
        description="Default deny: agents can read this secret only through a grant below."
        icon={<Bot className="h-4 w-4" />}
        actions={
          manage &&
          secret.status !== 'DELETED' && (
            <Button size="sm" onClick={() => setGranting(true)} data-testid="secret-grant-new">
              <Plus className="h-3.5 w-3.5" /> Grant access
            </Button>
          )
        }
      />
      {error ? (
        <div className="p-4">
          <ErrorState error={error} onRetry={reload} />
        </div>
      ) : (
        <GrantsTable
          grants={data?.items}
          loading={loading && !data}
          onRevoke={manage ? setRevoking : undefined}
          linkSecret={false}
          empty={<EmptyState icon={<ShieldOff className="h-5 w-5" />} title="No agent can read this secret" description={manage ? 'Grant an agent access to let it retrieve the value with its API key.' : 'An administrator with secret:manage_access can grant agents access.'} />}
        />
      )}
      {granting && (
        <GrantDialog
          secret={secret}
          types={types}
          onClose={() => setGranting(false)}
          onDone={async (g) => {
            setGranting(false);
            toast.success('Access granted', `${g.agent.name} can now read ${secret.name}.`);
            await reload();
          }}
        />
      )}
      {revoking && (
        <RevokeGrantDialog
          grant={revoking}
          onClose={() => setRevoking(null)}
          onDone={async () => {
            setRevoking(null);
            await reload();
          }}
        />
      )}
    </Card>
  );
}

// ── agent page card ──────────────────────────────────────────────

/** Read-only "Secrets" card on the agent page. Hidden for members who cannot see secret metadata. */
export function AgentSecretsCard({ agentId, className }: { agentId: string; className?: string }) {
  const { can } = useAuth();
  const allowed = can(PERMISSIONS.SECRET_READ_METADATA);
  const { data, error, loading, reload } = usePost<{ items: SecretAccessGrantView[]; total: number }>(allowed ? '/secretAccess/getall' : null, { agentId });
  if (!allowed) return null;
  return (
    <Card className={className} data-testid="agent-secrets-card">
      <CardHeader
        title="Secrets"
        description="Secrets this agent may retrieve with its API key (default deny)."
        icon={<KeyRound className="h-4 w-4" />}
        actions={
          <Link className="text-sm text-brand-700 hover:underline" to={`/secrets/access?agentId=${encodeURIComponent(agentId)}`}>
            Manage
          </Link>
        }
      />
      {error ? (
        <div className="p-4">
          <ErrorState error={error} onRetry={reload} />
        </div>
      ) : (
        <GrantsTable grants={data?.items} loading={loading && !data} show={{ agent: false, target: true }} empty={<EmptyState title="No secret grants" description="This agent cannot read any secret." />} />
      )}
    </Card>
  );
}

// ── errors ───────────────────────────────────────────────────────

/** Title for an approve/reject failure, so separation of duties and expiry read clearly. */
export function decisionErrorTitle(e: ApiError): string {
  if (e.status === 403 && /separation of duties/i.test(e.message)) return 'Separation of duties';
  if (e.code === 'APPROVAL_EXPIRED') return 'The request expired';
  if (e.code === 'APPROVAL_NOT_PENDING') return 'Already decided';
  if (e.status === 403) return 'Permission denied';
  return 'Request failed';
}
