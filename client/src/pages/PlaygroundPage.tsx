import { useEffect, useMemo, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { Ban, CheckCircle2, CircleDashed, Eraser, ExternalLink, FlaskConical, KeyRound, Loader2, Send, ShieldX, XCircle } from 'lucide-react';
import { DECISION_LABELS, PERMISSIONS, roleHas, type Agent, type ExecuteResponseBody, type Integration, type Webhook } from '@token-vault/shared';
import { getOperation, getProvider, useProviders } from '@/lib/providers';
import { useApi } from '@/hooks/useApi';
import { useAuth } from '@/context/AuthContext';
import { usePlayground } from '@/context/PlaygroundContext';
import { api, executeAsAgent } from '@/lib/api';
import { Button } from '@/components/ui/button';
import { Card, CardBody, CardHeader, DetailList } from '@/components/ui/card';
import { Badge, DecisionBadge, SimulatedBadge, StatusBadge } from '@/components/ui/badge';
import { Field, Input, Select, Textarea } from '@/components/ui/form';
import { Callout, EmptyState } from '@/components/ui/feedback';
import { Dialog } from '@/components/ui/dialog';
import { PageHeader } from '@/components/ui/navigation';
import { JsonView, Mono } from '@/components/ui/secret';
import { useToast } from '@/components/ui/toast';
import { TrustBoundary, type FlowStage, type StageState } from '@/components/TrustBoundary';
import { cn, formatDateTime, formatDuration, formatTime } from '@/lib/utils';

interface Preset {
  id: string;
  label: string;
  scenario?: string;
  integration: 'primary' | 'staging' | 'partner';
  operation: string;
  repository: string;
  path?: string;
  input?: Record<string, unknown>;
  repeat?: number;
  invalidCredential?: boolean;
  hint?: string;
  expect: string;
}

const DEFAULT_INPUT = { title: 'Token Vault POC test', body: 'Issue created through authorized credential brokering.' };
const INVALID_CREDENTIAL = 'tvak_000000000000_thisIsNotAValidCredential0000';

const PRESETS: Preset[] = [
  { id: 'A', scenario: 'A', label: 'Authorized and successful', integration: 'primary', operation: 'github.issues.create', repository: 'demo-org/demo-repo', input: DEFAULT_INPUT, expect: 'ALLOWED' },
  { id: 'B1', scenario: 'B', label: 'Destructive operation', integration: 'primary', operation: 'github.repositories.delete', repository: 'demo-org/demo-repo', expect: 'POLICY_DENIED' },
  { id: 'B2', scenario: 'B', label: 'Scope denied (not granted)', integration: 'primary', operation: 'github.contents.read', repository: 'demo-org/demo-repo', path: 'README.md', expect: 'SCOPE_DENIED' },
  { id: 'C', scenario: 'C', label: 'Resource restriction', integration: 'primary', operation: 'github.issues.create', repository: 'demo-org/other-repo', input: DEFAULT_INPUT, expect: 'RESOURCE_DENIED' },
  { id: 'D', scenario: 'D', label: 'Revoked grant', integration: 'primary', operation: 'github.issues.create', repository: 'demo-org/demo-repo', input: DEFAULT_INPUT, hint: 'Revoke the grant first, then send this request.', expect: 'GRANT_REVOKED' },
  { id: 'E', scenario: 'E', label: 'Expired grant', integration: 'staging', operation: 'github.repositories.read', repository: 'demo-org/demo-repo', hint: 'Seeded grant "Staging Read Access" expired yesterday.', expect: 'GRANT_EXPIRED' },
  { id: 'F', scenario: 'F', label: 'Webhook unavailable', integration: 'primary', operation: 'github.issues.create', repository: 'demo-org/demo-repo', input: DEFAULT_INPUT, hint: 'Enable the simulated outage below, or stop the webhook process.', expect: 'WEBHOOK_UNAVAILABLE' },
  { id: 'U', label: 'Unauthorized agent', integration: 'primary', operation: 'github.repositories.read', repository: 'demo-org/demo-repo', invalidCredential: true, expect: 'AGENT_UNAUTHENTICATED' },
  { id: 'M', label: 'Missing grant', integration: 'partner', operation: 'github.repositories.read', repository: 'partner-org/shared-repo', expect: 'GRANT_MISSING' },
  { id: 'I', label: 'Integration unavailable', integration: 'primary', operation: 'github.repositories.read', repository: 'demo-org/demo-repo', hint: 'Disable the integration first (Integration → Disable).', expect: 'INTEGRATION_UNAVAILABLE' },
  { id: 'P', label: 'Upstream provider error', integration: 'primary', operation: 'github.issues.create', repository: 'demo-org/demo-repo', input: { title: '[simulate-upstream-500] provider failure', body: 'The mock GitHub returns HTTP 500 for this title.' }, expect: 'UPSTREAM_ERROR' },
  { id: 'R', label: 'Rate limit exceeded', integration: 'primary', operation: 'github.repositories.read', repository: 'demo-org/demo-repo', repeat: 12, hint: 'Sends 12 requests; the seeded grant allows 10/minute.', expect: 'RATE_LIMITED' },
  { id: 'X', label: 'Malformed request', integration: 'primary', operation: 'github.repositories.read', repository: 'not-a-repository', expect: 'MALFORMED_REQUEST' },
];

interface HistoryItem {
  at: string;
  httpStatus: number;
  body: ExecuteResponseBody;
  operation: string;
}

function stageStates(r: ExecuteResponseBody | null): Partial<Record<FlowStage, StageState>> {
  if (!r) return {};
  const code = r.decision_code;
  if (code === 'AGENT_UNAUTHENTICATED') return { agent: 'fail', control: 'fail', policy: 'skipped', webhook: 'skipped', provider: 'skipped' };
  if (['MALFORMED_REQUEST', 'UNKNOWN_OPERATION', 'INTEGRATION_NOT_FOUND'].includes(code)) return { agent: 'ok', control: 'fail', policy: 'skipped', webhook: 'skipped', provider: 'skipped' };
  if (r.decision === 'DENY') return { agent: 'ok', control: 'ok', policy: 'fail', webhook: 'skipped', provider: 'skipped' };
  if (code === 'WEBHOOK_UNAVAILABLE') return { agent: 'ok', control: 'ok', policy: 'ok', webhook: 'fail', provider: 'skipped' };
  const up = r.execution.upstream_status ?? 0;
  return { agent: 'ok', control: 'ok', policy: 'ok', webhook: 'ok', provider: up >= 200 && up < 300 ? 'ok' : 'fail' };
}

export function PlaygroundPage() {
  const { operations } = useProviders();
  const { session, can } = useAuth();
  const navigate = useNavigate();
  const toast = useToast();
  const { credential, setCredential } = usePlayground();
  const integrations = useApi<{ items: Integration[] }>('/integrations');
  const webhooks = useApi<{ items: Webhook[] }>('/webhooks');

  const [integrationId, setIntegrationId] = useState('');
  const [operation, setOperation] = useState('github.issues.create');
  const [repository, setRepository] = useState('demo-org/demo-repo');
  const [path, setPath] = useState('README.md');
  const [payload, setPayload] = useState(JSON.stringify(DEFAULT_INPUT, null, 2));
  const [payloadError, setPayloadError] = useState<string | null>(null);
  const [repeat, setRepeat] = useState(1);
  const [userToken, setUserToken] = useState('');
  const [useInvalid, setUseInvalid] = useState(false);
  const [activePreset, setActivePreset] = useState<Preset | null>(null);
  const [sending, setSending] = useState(false);
  const [progress, setProgress] = useState<string | null>(null);
  const [result, setResult] = useState<HistoryItem | null>(null);
  const [history, setHistory] = useState<HistoryItem[]>([]);
  const [credOpen, setCredOpen] = useState(false);

  const list = integrations.data?.items ?? [];
  useEffect(() => {
    if (!integrationId && list.length) setIntegrationId((list.find((i) => i.id === 'int_github_001') ?? list[0]!).id);
  }, [list, integrationId]);

  const op = getOperation(operation);
  const selected = list.find((i) => i.id === integrationId);
  const provider = selected ? getProvider(selected.provider) : undefined;
  const providerOps = provider ? operations.filter((o) => o.provider === provider.key) : operations;
  // Keep the operation consistent with the selected integration's provider.
  useEffect(() => {
    if (provider && !providerOps.some((o) => o.id === operation) && providerOps[0]) {
      setOperation(providerOps[0].id);
      if (provider.resource.example) setRepository(provider.resource.example);
    }
  }, [provider, providerOps, operation]);
  const webhook = webhooks.data?.items.find((w) => w.verifiedAt) ?? webhooks.data?.items[0];
  const effectiveKey = useInvalid ? INVALID_CREDENTIAL : credential?.apiKey ?? '';

  function resolveIntegration(kind: Preset['integration']): string {
    const byId = { primary: 'int_github_001', staging: 'int_github_002', partner: 'int_github_003' }[kind];
    const found = list.find((i) => i.id === byId) ?? (kind === 'staging' ? list.find((i) => i.environment === 'staging') : undefined) ?? list[0];
    return found?.id ?? '';
  }

  function applyPreset(p: Preset) {
    setActivePreset(p);
    setIntegrationId(resolveIntegration(p.integration));
    setOperation(p.operation);
    setRepository(p.repository);
    if (p.path) setPath(p.path);
    setPayload(JSON.stringify(p.input ?? {}, null, 2));
    setRepeat(p.repeat ?? 1);
    setUseInvalid(!!p.invalidCredential);
    setPayloadError(null);
  }

  function clear() {
    setActivePreset(null);
    setResult(null);
    setRepeat(1);
    setUseInvalid(false);
    setPayload(JSON.stringify(DEFAULT_INPUT, null, 2));
    setPayloadError(null);
  }

  async function send() {
    let input: Record<string, unknown> = {};
    try {
      input = payload.trim() ? JSON.parse(payload) : {};
      if (typeof input !== 'object' || Array.isArray(input) || input === null) throw new Error('Payload must be a JSON object');
      setPayloadError(null);
    } catch (e) {
      setPayloadError((e as Error).message);
      return;
    }
    if (!effectiveKey) {
      toast.error('Agent credential required', 'Get a credential for an agent first.');
      return;
    }
    setSending(true);
    try {
      let last: HistoryItem | null = null;
      for (let n = 0; n < repeat; n++) {
        setProgress(repeat > 1 ? `Sending ${n + 1} of ${repeat}…` : null);
        const res = await executeAsAgent(
          effectiveKey,
          {
            integration_id: integrationId,
            operation,
            resource: { [op?.resourceName ?? 'repository']: repository, ...(operation === 'github.contents.read' ? { path } : {}) },
            input: op?.mutating ? input : {},
            idempotency_key: `pg-${Date.now().toString(36)}-${n}`,
            ...(userToken.trim() ? { on_behalf_of: userToken.trim() } : {}),
          },
          session?.currentOrganization?.slug ?? '',
        );
        last = { at: new Date().toISOString(), httpStatus: res.httpStatus, body: res.body, operation };
        setHistory((h) => [last!, ...h].slice(0, 30));
      }
      setResult(last);
    } catch (e) {
      toast.error('Request failed', (e as Error).message);
    } finally {
      setSending(false);
      setProgress(null);
    }
  }

  async function toggleOutage(enabled: boolean) {
    if (!webhook) return;
    try {
      await api.post(`/webhooks/${webhook.id}/simulate-outage`, { enabled });
      await webhooks.reload();
      toast.info(enabled ? 'Simulated webhook outage enabled' : 'Simulated outage cleared');
    } catch (e) {
      toast.error('Could not toggle outage', (e as Error).message);
    }
  }

  const r = result?.body ?? null;
  const states = useMemo(() => stageStates(r), [r]);

  return (
    <div className="space-y-6">
      <PageHeader
        title="Agent Access Playground"
        badge={<SimulatedBadge />}
        description="Act as an AI agent: requests go to the real agent execution API, authenticated only by the agent's credential, and are brokered through your customer webhook."
        breadcrumbs={[{ label: 'Access Playground' }]}
      />

      <Card>
        <CardBody>
          <TrustBoundary states={states} compact />
        </CardBody>
      </Card>

      <div className="grid gap-6 xl:grid-cols-[minmax(0,1fr)_minmax(0,1.15fr)]">
        <div className="space-y-6">
          <Card>
            <CardHeader title="Scenario presets" description="Fill the request for a demo scenario" />
            <CardBody className="grid grid-cols-1 gap-2 sm:grid-cols-2">
              {PRESETS.map((p) => (
                <button key={p.id} onClick={() => applyPreset(p)} className={cn('rounded-lg border px-3 py-2 text-left transition', activePreset?.id === p.id ? 'border-brand-500 bg-brand-50/60 ring-1 ring-brand-500' : 'border-slate-200 hover:border-slate-300 hover:bg-slate-50')}>
                  <span className="flex items-center gap-2 text-sm font-medium text-slate-800">
                    {p.scenario && <span className="rounded bg-slate-900 px-1.5 text-[10px] font-semibold leading-4 text-white">{p.scenario}</span>}
                    {p.label}
                  </span>
                  <span className="mt-0.5 block font-mono text-[11px] text-slate-500">expect {p.expect}</span>
                </button>
              ))}
            </CardBody>
          </Card>

          <Card>
            <CardHeader title="Request" />
            <CardBody className="space-y-4">
              {activePreset?.hint && (
                <Callout
                  tone="info"
                  title={`Scenario: ${activePreset.label}`}
                  action={
                    activePreset.id === 'F' && webhook && can(PERMISSIONS.WEBHOOK_MANAGE) ? (
                      <Button size="sm" variant={webhook.simulateOutage ? 'outline' : 'primary'} onClick={() => toggleOutage(!webhook.simulateOutage)}>
                        {webhook.simulateOutage ? 'Clear outage' : 'Simulate outage'}
                      </Button>
                    ) : activePreset.id === 'D' ? (
                      <Button size="sm" variant="outline" onClick={() => navigate('/access/grants')}>
                        Open grants
                      </Button>
                    ) : activePreset.id === 'I' ? (
                      <Button size="sm" variant="outline" onClick={() => navigate(`/integrations/${integrationId}`)}>
                        Open integration
                      </Button>
                    ) : undefined
                  }
                >
                  {activePreset.hint}
                </Callout>
              )}
              {webhook?.simulateOutage && activePreset?.id !== 'F' && (
                <Callout tone="warning" action={can(PERMISSIONS.WEBHOOK_MANAGE) && <Button size="sm" variant="outline" onClick={() => toggleOutage(false)}>Clear</Button>}>
                  Simulated webhook outage is enabled.
                </Callout>
              )}

              <Field
                label={
                  <span className="flex items-center gap-1.5">
                    <KeyRound className="h-3.5 w-3.5 text-slate-400" /> Agent API credential
                  </span>
                }
                hint={useInvalid ? 'Using a well-formed but unknown credential for the Unauthorized agent scenario.' : credential?.agentName ? `Loaded for ${credential.agentName}. Held in memory only; cleared on reload.` : 'Held in memory only. Never stored in browser storage or URLs.'}
              >
                <div className="flex gap-2">
                  <Input
                    type="password"
                    autoComplete="off"
                    spellCheck={false}
                    className="font-mono"
                    placeholder="tvak_…"
                    value={effectiveKey}
                    disabled={useInvalid}
                    onChange={(e) => setCredential(e.target.value ? { apiKey: e.target.value.trim(), agentId: '', agentName: 'pasted credential' } : null)}
                  />
                  <Button variant="outline" onClick={() => setCredOpen(true)}>
                    Get a credential
                  </Button>
                </div>
              </Field>

              <div className="grid gap-4 sm:grid-cols-2">
                <Field label="Integration">
                  <Select value={integrationId} onChange={(e) => setIntegrationId(e.target.value)}>
                    {list.length === 0 && <option value="">No integrations</option>}
                    {list.map((i) => (
                      <option key={i.id} value={i.id}>
                        {i.displayName} ({i.environment}){i.credentialStatus !== 'CONNECTED' ? ` · ${i.credentialStatus.toLowerCase()}` : ''}
                      </option>
                    ))}
                  </Select>
                </Field>
                <Field label="Operation">
                  <Select value={operation} onChange={(e) => setOperation(e.target.value)}>
                    {providerOps.map((o) => (
                      <option key={o.id} value={o.id}>
                        {o.label}
                        {o.destructive ? ' (destructive)' : ''}
                      </option>
                    ))}
                  </Select>
                </Field>
                <Field label={provider?.resource.label ?? 'Repository / resource'}>
                  <Input aria-label="Resource" value={repository} onChange={(e) => setRepository(e.target.value)} className="font-mono text-sm" />
                </Field>
                {operation === 'github.contents.read' ? (
                  <Field label="Path">
                    <Input value={path} onChange={(e) => setPath(e.target.value)} className="font-mono text-sm" />
                  </Field>
                ) : (
                  <Field label="Repeat" hint="Send the request multiple times">
                    <Select value={repeat} onChange={(e) => setRepeat(Number(e.target.value))}>
                      {[1, 5, 12].map((n) => (
                        <option key={n} value={n}>
                          {n}×
                        </option>
                      ))}
                    </Select>
                  </Field>
                )}
              </div>
              {op?.mutating && (
                <Field label="Request payload (JSON)" error={payloadError ?? undefined}>
                  <Textarea rows={4} className="font-mono text-xs" value={payload} onChange={(e) => setPayload(e.target.value)} invalid={!!payloadError} />
                </Field>
              )}
              <Field label="On behalf of a user (optional)" hint="A signed user token (JWT) from an issuer under Settings → User Identity. Empty: the agent acts for itself.">
                <Textarea aria-label="User token" rows={2} className="font-mono text-xs" value={userToken} onChange={(e) => setUserToken(e.target.value)} placeholder="eyJhbGciOi…" />
              </Field>
            </CardBody>
            <div className="flex items-center justify-between gap-2 border-t border-slate-100 px-5 py-3.5">
              <Button variant="ghost" onClick={clear}>
                <Eraser className="h-4 w-4" /> Clear
              </Button>
              <div className="flex items-center gap-3">
                {progress && <span className="text-xs text-slate-500">{progress}</span>}
                <Button onClick={send} loading={sending} disabled={!integrationId}>
                  <Send className="h-4 w-4" /> Send request
                </Button>
              </div>
            </div>
          </Card>
        </div>

        <div className="space-y-6">
          <ResultPanel item={result} sending={sending} canAudit={can(PERMISSIONS.AUDIT_READ)} />
          <Card>
            <CardHeader title="Session history" description="Requests sent from this page (not persisted)" />
            {history.length === 0 ? (
              <EmptyState title="No requests yet" className="py-8" />
            ) : (
              <ul className="max-h-80 divide-y divide-slate-100 overflow-y-auto">
                {history.map((h) => (
                  <li key={h.body.request_id}>
                    <button onClick={() => setResult(h)} className={cn('flex w-full items-center gap-3 px-5 py-2.5 text-left text-sm hover:bg-slate-50', result?.body.request_id === h.body.request_id && 'bg-slate-50')}>
                      <span className="w-16 shrink-0 text-xs text-slate-500">{formatTime(h.at)}</span>
                      <span className="min-w-0 flex-1 truncate text-slate-700">{getOperation(h.operation)?.label ?? h.operation}</span>
                      <DecisionBadge decision={h.body.decision} code={h.body.decision_code} />
                    </button>
                  </li>
                ))}
              </ul>
            )}
          </Card>
        </div>
      </div>

      <CredentialDialog
        open={credOpen}
        onClose={() => setCredOpen(false)}
        onIssued={(c) => {
          setCredential(c);
          setUseInvalid(false);
          setCredOpen(false);
        }}
      />
    </div>
  );
}

function ResultPanel({ item, sending, canAudit }: { item: HistoryItem | null; sending: boolean; canAudit: boolean }) {
  if (sending && !item) {
    return (
      <Card>
        <CardBody className="flex items-center justify-center gap-2 py-16 text-sm text-slate-500">
          <Loader2 className="h-5 w-5 animate-spin" /> Authorizing and brokering…
        </CardBody>
      </Card>
    );
  }
  if (!item) {
    return (
      <Card>
        <EmptyState icon={<FlaskConical className="h-5 w-5" />} title="Send a request to see the decision" description="Pick a scenario preset or build a request, then click Send request." className="py-16" />
      </Card>
    );
  }
  const r = item.body;
  const allowedOk = r.decision === 'ALLOW' && r.execution.status === 'SUCCEEDED';
  const allowedFailed = r.decision === 'ALLOW' && r.execution.status === 'FAILED';
  const tone = allowedOk ? 'border-emerald-200 bg-emerald-50' : allowedFailed ? 'border-amber-200 bg-amber-50' : 'border-red-200 bg-red-50';
  const Icon = allowedOk ? CheckCircle2 : allowedFailed ? XCircle : r.decision_code === 'AGENT_UNAUTHENTICATED' ? Ban : ShieldX;
  const title = allowedOk ? 'Authorized and successful' : allowedFailed ? `Authorized, execution failed: ${DECISION_LABELS[r.decision_code] ?? r.decision_code}` : `Access denied: ${DECISION_LABELS[r.decision_code] ?? r.decision_code}`;

  return (
    <Card>
      <div className={cn('flex items-start gap-3 rounded-t-xl border-b p-4', tone)}>
        <Icon className={cn('h-6 w-6 shrink-0', allowedOk ? 'text-emerald-600' : allowedFailed ? 'text-amber-600' : 'text-red-600')} />
        <div className="min-w-0 flex-1">
          <p className="font-semibold text-slate-900">{title}</p>
          <p className="mt-0.5 text-sm text-slate-700">{r.reason}</p>
        </div>
        <span className="rounded bg-white/70 px-2 py-0.5 font-mono text-xs text-slate-600">HTTP {item.httpStatus}</span>
      </div>
      <CardBody className="space-y-5">
        <DetailList
          columns={3}
          items={[
            { label: 'Request ID', value: <Mono>{r.request_id}</Mono> },
            { label: 'Authorization decision', value: <DecisionBadge decision={r.decision} /> },
            { label: 'Decision code', value: r.decision_code, mono: true },
            { label: 'Policy / grant matched', value: r.matched_rule ? `${r.matched_rule.type}: ${r.matched_rule.name ?? r.matched_rule.id ?? '—'}` : '—' },
            { label: 'Execution status', value: <StatusBadge status={r.execution.status} /> },
            { label: 'Webhook status', value: r.execution.webhook_status, mono: true },
            { label: 'Upstream HTTP status', value: r.execution.upstream_status ?? '—' },
            { label: 'Execution duration', value: formatDuration(r.execution.duration_ms) },
            { label: 'Mode', value: r.execution.simulated ? <SimulatedBadge /> : <Badge tone="amber">Live GitHub</Badge> },
          ]}
        />
        {r.execution.idempotent_replay && <Callout tone="info">Idempotent replay: the cached result was returned after re-authorization.</Callout>}
        {r.execution.credential?.type === 'github_app_installation_token' && (
          <Callout tone="security">
            <span className="font-medium">Minted GitHub App token</span> scoped to{' '}
            <span className="font-mono">{r.execution.credential.repositories.join(', ') || 'all installation repositories'}</span> with{' '}
            <span className="font-mono">
              {Object.entries(r.execution.credential.permissions)
                .map(([k, v]) => `${k}:${v}`)
                .join(', ')}
            </span>
            {r.execution.credential.revoked ? ', revoked right after use.' : `, expiring ${formatDateTime(r.execution.credential.expires_at)}.`}
          </Callout>
        )}
        {r.execution.credential?.type === 'oauth2_access_token' && (
          <Callout tone="security">
            <span className="font-medium">OAuth access token</span> held by the customer webhook
            {r.execution.credential.refreshed ? ', refreshed for this request' : ''}
            {r.execution.credential.expires_at ? `, valid until ${formatDateTime(r.execution.credential.expires_at)}` : ''}.
          </Callout>
        )}

        <div>
          <p className="mb-2 text-xs font-semibold uppercase tracking-wide text-slate-500">Decision trace</p>
          <ol className="space-y-1">
            {r.checks.map((c) => (
              <li key={c.step} className="flex items-start gap-2 text-sm">
                {c.passed === true ? <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-emerald-600" /> : c.passed === false ? <XCircle className="mt-0.5 h-4 w-4 shrink-0 text-red-600" /> : <CircleDashed className="mt-0.5 h-4 w-4 shrink-0 text-slate-300" />}
                <span className={cn('min-w-0', c.passed === null && 'text-slate-400')}>
                  <span className="font-medium">{c.step}. {c.name}</span>
                  {c.passed !== null && <span className="text-slate-500"> · {c.detail}</span>}
                </span>
              </li>
            ))}
          </ol>
        </div>

        <div>
          <p className="mb-2 flex items-center justify-between text-xs font-semibold uppercase tracking-wide text-slate-500">
            Sanitized response
            <span className="font-normal normal-case text-slate-400">No credentials appear in requests or responses</span>
          </p>
          <JsonView value={r.result ?? { message: 'No upstream call was made.' }} />
        </div>

        {canAudit && (
          <Link to={`/audit/access-logs?request=${r.request_id}`} className="inline-flex items-center gap-1 text-sm text-brand-700 hover:underline">
            View audit record <ExternalLink className="h-3.5 w-3.5" />
          </Link>
        )}
      </CardBody>
    </Card>
  );
}

/** Issues a fresh credential for an agent (rotation) and loads it into the playground memory. */
function CredentialDialog({ open, onClose, onIssued }: { open: boolean; onClose: () => void; onIssued: (c: { apiKey: string; agentId: string; agentName: string }) => void }) {
  const { session } = useAuth();
  const toast = useToast();
  const agents = useApi<{ items: Agent[] }>(open ? '/agents' : null);
  const [agentId, setAgentId] = useState('');
  const [pending, setPending] = useState(false);
  const manageable = (agents.data?.items ?? []).filter((a) => roleHas(session?.role, PERMISSIONS.AGENT_MANAGE_ANY) || a.ownerUserId === session?.user.id);
  const canManage = roleHas(session?.role, PERMISSIONS.AGENT_MANAGE);

  useEffect(() => {
    if (open && !agentId && manageable.length) setAgentId((manageable.find((a) => a.name === 'GitHub Assistant') ?? manageable[0]!).id);
  }, [open, manageable, agentId]);

  return (
    <Dialog
      open={open}
      onClose={onClose}
      title="Get an agent credential"
      description="Rotates the selected agent's API credential and loads the new one into this page's memory. The previous credential stops working."
      footer={
        <>
          <Button variant="outline" onClick={onClose}>
            Cancel
          </Button>
          <Button
            disabled={!agentId || !canManage}
            loading={pending}
            onClick={async () => {
              setPending(true);
              try {
                const r = await api.post<{ agent: Agent; credential: { apiKey: string } }>(`/agents/${agentId}/rotate-credential`);
                onIssued({ apiKey: r.credential.apiKey, agentId: r.agent.id, agentName: r.agent.name });
                toast.success('Credential loaded', `New credential for ${r.agent.name} is held in memory only.`);
              } catch (e) {
                toast.error('Could not issue credential', (e as Error).message);
              } finally {
                setPending(false);
              }
            }}
          >
            Rotate & load
          </Button>
        </>
      }
    >
      {!canManage ? (
        <Callout tone="warning" title="Your role cannot issue agent credentials">
          Ask an Agent Developer or Owner for a credential, then paste it into the credential field.
        </Callout>
      ) : manageable.length === 0 ? (
        <Callout tone="info">You do not own any agents. Register one first.</Callout>
      ) : (
        <div className="space-y-3">
          <Field label="Agent">
            <Select value={agentId} onChange={(e) => setAgentId(e.target.value)}>
              {manageable.map((a) => (
                <option key={a.id} value={a.id}>
                  {a.name} ({a.status.toLowerCase()})
                </option>
              ))}
            </Select>
          </Field>
          <p className="text-xs text-slate-500">Agent identity is derived from this credential on every request; the playground never sends an agent ID.</p>
        </div>
      )}
    </Dialog>
  );
}
