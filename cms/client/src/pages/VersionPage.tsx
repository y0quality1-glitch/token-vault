import { useEffect, useMemo, useState } from 'react';
import { CheckCircle2, FileCheck2, Play, Save, Send, Undo2, XCircle } from 'lucide-react';
import { useParams } from 'react-router-dom';
import { DefinitionError, validateProviderDefinition, type CmsPreviewResult, type CmsVersionDetail } from '@token-vault/shared';
import { Badge } from '@ui/badge';
import { Button } from '@ui/button';
import { Card, CardBody, CardHeader, DetailList } from '@ui/card';
import { Dialog } from '@ui/dialog';
import { Callout, ErrorState, FormError, PageSkeleton } from '@ui/feedback';
import { Checkbox, Field, Input, Select, Textarea } from '@ui/form';
import { PageHeader, Tabs } from '@ui/navigation';
import { JsonView } from '@ui/secret';
import { useToast } from '@ui/toast';
import { useApi, useMutation } from '@tv-hooks/useApi';
import { DefinitionForm } from '@/components/DefinitionForm';
import { VersionBadge } from '@/components/VersionBadge';
import { api } from '@/lib/api';
import { formatDateTime } from '@/lib/utils';

type Tab = 'definition' | 'changes' | 'preview' | 'signature';

interface DefShape {
  name?: string;
  api?: { baseUrl?: string; allowedHosts?: string[] };
  resource?: { name?: string; label?: string; example?: string };
  resourceFields?: Record<string, { label?: string; example?: string }>;
  auth?: { id: string; label: string; kind: string }[];
  operations?: { id: string; label: string; risk: string; request?: { method?: string; path?: string }; input?: Record<string, unknown> }[];
}

/** Readable key order for the editor (PostgreSQL jsonb does not preserve the authored order). */
const ORDER = ['key', 'version', 'id', 'name', 'label', 'description', 'risk', 'kind', 'header', 'prefix', 'plugin', 'type', 'required', 'baseUrl', 'allowedHosts', 'headers', 'timeoutMs', 'method', 'path', 'query', 'body', 'pattern', 'example', 'caseInsensitive', 'secretPattern', 'secretHint', 'requiresResource', 'providerPermissions', 'input', 'request', 'response', 'fields', 'limit', 'mock', 'status', 'test', 'api', 'resource', 'resourceFields', 'auth', 'credentialTest', 'operations'];
const rank = (k: string) => (ORDER.includes(k) ? ORDER.indexOf(k) : ORDER.length);
function ordered(v: unknown): unknown {
  if (Array.isArray(v)) return v.map(ordered);
  if (v && typeof v === 'object') {
    return Object.fromEntries(
      Object.keys(v)
        .sort((a, b) => rank(a) - rank(b))
        .map((k) => [k, ordered((v as Record<string, unknown>)[k])]),
    );
  }
  return v;
}
const pretty = (v: unknown) => JSON.stringify(ordered(v), null, 2);

export function VersionPage() {
  const { key, version } = useParams() as { key: string; version: string };
  const path = `/applications/${key}/versions/${version}`;
  const toast = useToast();
  const v = useApi<CmsVersionDetail>(path);
  const [tab, setTab] = useState<Tab>('definition');
  const [text, setText] = useState('');
  const [view, setView] = useState<'form' | 'json'>('form');
  const [dialog, setDialog] = useState<null | 'approve' | 'reject'>(null);

  useEffect(() => {
    if (v.data) setText(pretty(v.data.definition));
  }, [v.data]);

  const parsed = useMemo(() => {
    try {
      return { value: JSON.parse(text) as unknown, error: null };
    } catch (e) {
      return { value: null, error: (e as Error).message };
    }
  }, [text]);

  // Live validation of the unsaved document (the same validator the API, Token Vault and webhooks use).
  const liveIssues = useMemo(() => {
    if (parsed.error || !parsed.value || typeof parsed.value !== 'object') return null;
    try {
      validateProviderDefinition(parsed.value);
      return [] as string[];
    } catch (e) {
      return e instanceof DefinitionError ? e.issues : [(e as Error).message];
    }
  }, [parsed]);

  const save = useMutation(() => api.put<CmsVersionDetail>(path, { definition: parsed.value }));
  const action = useMutation((name: 'submit' | 'withdraw') => api.post<CmsVersionDetail>(`${path}/${name}`, {}));

  if (v.error) return <ErrorState error={v.error} onRetry={v.reload} />;
  if (!v.data) return <PageSkeleton />;
  const d = v.data;
  const def = d.definition as DefShape;
  const dirty = text !== pretty(d.definition);
  const update = (next: CmsVersionDetail) => {
    v.setData(next);
    setText(pretty(next.definition));
  };

  return (
    <>
      <PageHeader
        breadcrumbs={[
          { label: 'Applications', to: '/applications' },
          { label: def.name ?? key, to: `/applications/${key}` },
          { label: `v${d.version}` },
        ]}
        title={`${def.name ?? key} v${d.version}`}
        badge={<VersionBadge status={d.status} />}
        description={`Created by ${d.createdBy} ${formatDateTime(d.createdAt)}${d.submittedAt ? ` · submitted ${formatDateTime(d.submittedAt)}` : ''}${d.publishedAt ? ` · published ${formatDateTime(d.publishedAt)}` : ''}`}
        actions={
          <>
            {d.can.submit && (
              <Button
                loading={action.pending}
                disabled={dirty}
                title={dirty ? 'Save your changes first' : undefined}
                onClick={async () => {
                  const r = await action.run('submit');
                  if (r) {
                    update(r);
                    toast.success('Submitted for review', 'A publisher who did not edit this version must approve it.');
                  }
                }}
              >
                <Send className="h-4 w-4" /> Submit for review
              </Button>
            )}
            {d.can.withdraw && (
              <Button variant="outline" loading={action.pending} onClick={async () => (await action.run('withdraw').then((r) => r && update(r)))}>
                <Undo2 className="h-4 w-4" /> Withdraw
              </Button>
            )}
            {d.status === 'IN_REVIEW' && (
              <>
                <Button variant="outline" disabled={!d.can.review} onClick={() => setDialog('reject')}>
                  <XCircle className="h-4 w-4" /> Request changes
                </Button>
                <Button disabled={!d.can.review} onClick={() => setDialog('approve')}>
                  <CheckCircle2 className="h-4 w-4" /> Approve & publish
                </Button>
              </>
            )}
          </>
        }
      />

      <div className="mb-4 space-y-3">
        <FormError error={action.error} />
        {d.status === 'DRAFT' && d.reviewNote && (
          <Callout tone="warning" title="Changes requested">
            {d.reviewNote}
          </Callout>
        )}
        {d.status === 'IN_REVIEW' && d.can.reviewBlockedReason && <Callout tone="info">{d.can.reviewBlockedReason}</Callout>}
        {d.status === 'IN_REVIEW' && d.diff.hostChange && (
          <Callout tone="warning" title={d.diff.againstVersion ? 'This version changes where credentials are sent' : 'First publication'}>
            Credentials will be sent to <span className="font-mono">{def.api?.baseUrl}</span> (allowed hosts: <span className="font-mono">{def.api?.allowedHosts?.join(', ')}</span>). The approver must confirm these hosts.
          </Callout>
        )}
        {d.status === 'PUBLISHED' && <Callout tone="security">Published and signed. This version is frozen; changes need a new version.</Callout>}
      </div>

      <Tabs
        value={tab}
        onChange={setTab}
        tabs={[
          { value: 'definition', label: 'Definition' },
          { value: 'changes', label: 'Changes', count: d.diff.changes.length },
          { value: 'preview', label: 'Request preview' },
          ...(d.digest ? [{ value: 'signature' as const, label: 'Signature' }] : []),
        ]}
      />

      <div className="mt-4">
        {tab === 'definition' && (
          <div className="grid gap-6 xl:grid-cols-5">
            <Card className="xl:col-span-3">
              <CardHeader
                title="Definition"
                description={d.can.edit ? 'Edit with the form or as JSON: both change the same document. The key and version are set by the CMS.' : 'Read-only in this state.'}
                actions={
                  <>
                    <div className="flex rounded-md border border-slate-200 p-0.5 text-xs" role="tablist" aria-label="Editor view">
                      {(['form', 'json'] as const).map((v) => (
                        <button
                          key={v}
                          role="tab"
                          aria-selected={view === v}
                          disabled={v === 'form' && !!parsed.error}
                          title={v === 'form' && parsed.error ? 'Fix the JSON first' : undefined}
                          onClick={() => setView(v)}
                          className={view === v ? 'rounded bg-slate-900 px-2.5 py-1 font-medium text-white' : 'rounded px-2.5 py-1 text-slate-600 hover:bg-slate-100 disabled:opacity-40'}
                        >
                          {v === 'form' ? 'Form' : 'JSON'}
                        </button>
                      ))}
                    </div>
                  {d.can.edit && (
                    <>
                      {view === 'json' && (
                        <Button variant="ghost" size="sm" disabled={!!parsed.error} onClick={() => setText(pretty(parsed.value))}>
                          Format
                        </Button>
                      )}
                      <Button
                        size="sm"
                        disabled={!dirty || !!parsed.error}
                        loading={save.pending}
                        onClick={async () => {
                          const r = await save.run();
                          if (r) {
                            update(r);
                            toast.success('Draft saved', r.issues.length ? `${r.issues.length} validation problem(s) to fix before submitting` : 'The definition is valid');
                          }
                        }}
                      >
                        <Save className="h-4 w-4" /> Save draft
                      </Button>
                    </>
                  )}
                  </>
                }
              />
              <CardBody className="space-y-3">
                <FormError error={save.error} />
                {parsed.error && <Callout tone="danger">Not valid JSON: {parsed.error}</Callout>}
                {view === 'form' && !parsed.error && parsed.value && typeof parsed.value === 'object' ? (
                  <DefinitionForm value={parsed.value as Record<string, unknown>} onChange={(next) => setText(pretty(next))} readOnly={!d.can.edit} issues={liveIssues ?? []} />
                ) : (
                  <Textarea
                    aria-label="Definition JSON"
                    spellCheck={false}
                    readOnly={!d.can.edit}
                    rows={30}
                    className="font-mono text-xs leading-relaxed"
                    value={text}
                    onChange={(e) => setText(e.target.value)}
                  />
                )}
                {dirty && <p className="text-xs text-amber-700">Unsaved changes</p>}
              </CardBody>
            </Card>
            <div className="space-y-6 xl:col-span-2">
              <Card>
                <CardHeader title="Validation" />
                <CardBody className="space-y-3">
                  {dirty && liveIssues && (
                    <p className={liveIssues.length ? 'text-sm text-amber-700' : 'text-sm text-emerald-700'} data-testid="live-validation">
                      {liveIssues.length ? `Unsaved changes: ${liveIssues.length} problem${liveIssues.length > 1 ? 's' : ''} (shown in the form sections)` : 'Unsaved changes are valid.'}
                    </p>
                  )}
                  {d.issues.length === 0 ? (
                    <p className="flex items-center gap-2 text-sm text-emerald-700">
                      <FileCheck2 className="h-4 w-4" /> The saved definition is valid.
                    </p>
                  ) : (
                    <ul className="space-y-1.5 text-sm text-red-700" data-testid="validation-issues">
                      {d.issues.map((i) => (
                        <li key={i} className="font-mono text-xs">
                          {i}
                        </li>
                      ))}
                    </ul>
                  )}
                </CardBody>
              </Card>
              <Summary def={def} />
            </div>
          </div>
        )}
        {tab === 'changes' && <Changes d={d} />}
        {tab === 'preview' && <Preview path={path} def={def} valid={d.issues.length === 0} />}
        {tab === 'signature' && d.digest && (
          <Card>
            <CardHeader title="Signature" description="Ed25519 over token-vault/provider-definition/v1:<digest>, where digest = sha256(canonical JSON)." />
            <CardBody>
              <DetailList
                columns={1}
                items={[
                  { label: 'Digest (sha256)', value: d.digest, mono: true },
                  {
                    label: 'Signed by keys',
                    value: (
                      <ul className="space-y-1" data-testid="signature-keys">
                        {d.signatures.map((s) => (
                          <li key={s.keyId} className="flex items-center gap-2">
                            <span className="font-mono text-xs">{s.keyId}</span>
                            {s.active ? <Badge tone="green">active key</Badge> : <Badge>previous key</Badge>}
                            <span className="text-xs text-slate-500">{formatDateTime(s.signedAt)}</span>
                          </li>
                        ))}
                      </ul>
                    ),
                  },
                  { label: 'Approved', value: `${formatDateTime(d.reviewedAt)}${d.reviewNote ? ` · “${d.reviewNote}”` : ''}` },
                ]}
              />
            </CardBody>
          </Card>
        )}
      </div>

      <ApproveDialog open={dialog === 'approve'} path={path} d={d} onClose={() => setDialog(null)} onDone={(r) => (update(r), setDialog(null), toast.success(`Published v${r.version}`, 'Signed and now served in the catalog.'))} />
      <RejectDialog open={dialog === 'reject'} path={path} onClose={() => setDialog(null)} onDone={(r) => (update(r), setDialog(null), toast.info('Changes requested', 'The version is back in draft.'))} />
    </>
  );
}

function Summary({ def }: { def: DefShape }) {
  return (
    <Card>
      <CardHeader title="Summary" />
      <CardBody className="space-y-4">
        <DetailList
          columns={1}
          items={[
            { label: 'Base URL', value: def.api?.baseUrl ?? '—', mono: true },
            { label: 'Allowed hosts', value: def.api?.allowedHosts?.join(', ') ?? '—', mono: true },
            { label: 'Resource', value: def.resource ? `${def.resource.label ?? def.resource.name} (${def.resource.name})` : '—' },
            { label: 'Auth methods', value: def.auth?.map((a) => `${a.label} (${a.kind})`).join(', ') ?? '—' },
          ]}
        />
        <div>
          <p className="mb-2 text-xs font-semibold uppercase tracking-wide text-slate-500">Operations</p>
          <ul className="space-y-2">
            {(def.operations ?? []).map((o) => (
              <li key={o.id} className="rounded-md border border-slate-200 p-2.5">
                <div className="flex items-center justify-between gap-2">
                  <span className="text-sm font-medium text-slate-800">{o.label}</span>
                  <Badge tone={o.risk === 'read' ? 'green' : o.risk === 'write' ? 'amber' : 'red'}>{o.risk}</Badge>
                </div>
                <p className="mt-1 font-mono text-xs text-slate-500">
                  {o.request?.method} {o.request?.path}
                </p>
              </li>
            ))}
          </ul>
        </div>
      </CardBody>
    </Card>
  );
}

function Changes({ d }: { d: CmsVersionDetail }) {
  return (
    <Card>
      <CardHeader title={d.diff.againstVersion ? `Compared with v${d.diff.againstVersion}` : 'First version'} />
      <CardBody className="space-y-3">
        {d.diff.hostChange && (
          <Callout tone="warning" title={d.diff.againstVersion ? 'API host changed' : 'New API hosts'}>
            api.baseUrl or api.allowedHosts {d.diff.againstVersion ? 'differ from the published version' : 'are published for the first time'}. Approval requires confirming them.
          </Callout>
        )}
        {d.diff.changes.length === 0 ? (
          <p className="text-sm text-slate-500">{d.diff.againstVersion ? 'No differences.' : 'Everything is new.'}</p>
        ) : (
          <ul className="divide-y divide-slate-100 text-sm">
            {d.diff.changes.map((c) => (
              <li key={c.area} className="flex items-center justify-between py-2">
                <span className="font-mono text-xs">{c.area}</span>
                <Badge tone={c.kind === 'added' ? 'green' : c.kind === 'removed' ? 'red' : 'amber'}>{c.kind}</Badge>
              </li>
            ))}
          </ul>
        )}
      </CardBody>
    </Card>
  );
}

function Preview({ path, def, valid }: { path: string; def: DefShape; valid: boolean }) {
  const ops = def.operations ?? [];
  const [operation, setOperation] = useState(ops[0]?.id ?? '');
  const fields = [def.resource?.name, ...Object.keys(def.resourceFields ?? {})].filter(Boolean) as string[];
  const [resource, setResource] = useState<Record<string, string>>(() => (def.resource?.name && def.resource.example ? { [def.resource.name]: def.resource.example } : {}));
  const [input, setInput] = useState('{}');
  const [result, setResult] = useState<CmsPreviewResult | null>(null);
  const run = useMutation(() => api.post<CmsPreviewResult>(`${path}/preview`, { operation, resource, input: JSON.parse(input || '{}') }));
  if (!valid) return <Callout tone="warning">Fix the validation problems to preview requests.</Callout>;
  return (
    <div className="grid gap-6 lg:grid-cols-2">
      <Card>
        <CardHeader title="Try an operation" description="Builds the request the customer webhook would send. No credential is involved." />
        <CardBody className="space-y-4">
          <Field label="Operation" htmlFor="previewOp">
            <Select id="previewOp" value={operation} onChange={(e) => setOperation(e.target.value)}>
              {ops.map((o) => (
                <option key={o.id} value={o.id}>
                  {o.label} ({o.id})
                </option>
              ))}
            </Select>
          </Field>
          {fields.map((f) => (
            <Field key={f} label={`resource.${f}`} htmlFor={`res-${f}`}>
              <Input id={`res-${f}`} className="font-mono" value={resource[f] ?? ''} onChange={(e) => setResource({ ...resource, [f]: e.target.value })} />
            </Field>
          ))}
          <Field label="input (JSON)" htmlFor="previewInput">
            <Textarea id="previewInput" rows={4} className="font-mono text-xs" value={input} onChange={(e) => setInput(e.target.value)} />
          </Field>
          <FormError error={run.error} />
          <Button onClick={async () => setResult((await run.run()) ?? null)} loading={run.pending}>
            <Play className="h-4 w-4" /> Preview request
          </Button>
        </CardBody>
      </Card>
      <Card>
        <CardHeader title="Result" />
        <CardBody className="space-y-4">
          {!result && !run.error && <p className="text-sm text-slate-500">Run a preview to see the request.</p>}
          {result?.error && <Callout tone="warning">{result.error}</Callout>}
          {result?.request.url && (
            <>
              <p className="break-all font-mono text-xs" data-testid="preview-url">
                <span className="font-semibold">{result.request.method}</span> {result.request.url}
              </p>
              <div>
                <p className="mb-1 text-xs font-semibold uppercase tracking-wide text-slate-500">Headers</p>
                <ul className="font-mono text-xs text-slate-600">
                  {result.request.headers.map((h) => (
                    <li key={h}>{h}</li>
                  ))}
                </ul>
              </div>
              {result.request.body !== null && <JsonView value={result.request.body} />}
              {result.mockResponse && (
                <div>
                  <p className="mb-1 text-xs font-semibold uppercase tracking-wide text-slate-500">Mock response after the allow-list (HTTP {result.mockResponse.status})</p>
                  <JsonView value={result.mockResponse.body} />
                </div>
              )}
            </>
          )}
        </CardBody>
      </Card>
    </div>
  );
}

function ApproveDialog({ open, path, d, onClose, onDone }: { open: boolean; path: string; d: CmsVersionDetail; onClose: () => void; onDone: (r: CmsVersionDetail) => void }) {
  const [note, setNote] = useState('');
  const [ack, setAck] = useState(false);
  const approve = useMutation(() => api.post<CmsVersionDetail>(`${path}/approve`, { note, acknowledgeHostChange: ack }));
  const def = d.definition as DefShape;
  return (
    <Dialog
      open={open}
      onClose={onClose}
      title={`Approve and publish v${d.version}`}
      description="The definition is signed with the CMS key and replaces the published version in the catalog."
      footer={
        <>
          <Button variant="outline" onClick={onClose}>
            Cancel
          </Button>
          <Button loading={approve.pending} disabled={d.diff.hostChange && !ack} onClick={async () => (await approve.run().then((r) => r && onDone(r)))}>
            Approve & publish
          </Button>
        </>
      }
    >
      <div className="space-y-4">
        <FormError error={approve.error} />
        {d.diff.hostChange && (
          <div className="space-y-2 rounded-lg border border-amber-200 bg-amber-50 p-3">
            <p className="text-sm text-amber-900">Customer credentials for this application will be sent to:</p>
            <ul className="font-mono text-xs text-amber-900">
              <li>{def.api?.baseUrl}</li>
              {def.api?.allowedHosts?.map((h) => (
                <li key={h}>allowed host: {h}</li>
              ))}
            </ul>
            <Checkbox checked={ack} onChange={setAck} label="I confirm these hosts belong to the provider" />
          </div>
        )}
        <Field label="Note (optional)" htmlFor="approveNote">
          <Textarea id="approveNote" rows={2} value={note} onChange={(e) => setNote(e.target.value)} />
        </Field>
      </div>
    </Dialog>
  );
}

function RejectDialog({ open, path, onClose, onDone }: { open: boolean; path: string; onClose: () => void; onDone: (r: CmsVersionDetail) => void }) {
  const [note, setNote] = useState('');
  const reject = useMutation(() => api.post<CmsVersionDetail>(`${path}/reject`, { note }));
  return (
    <Dialog
      open={open}
      onClose={onClose}
      title="Request changes"
      description="The version goes back to draft with your note."
      footer={
        <>
          <Button variant="outline" onClick={onClose}>
            Cancel
          </Button>
          <Button variant="danger" loading={reject.pending} onClick={async () => (await reject.run().then((r) => r && onDone(r)))}>
            Request changes
          </Button>
        </>
      }
    >
      <div className="space-y-4">
        <FormError error={reject.error} />
        <Field label="What needs to change" htmlFor="rejectNote" required error={reject.fieldErrors.note}>
          <Textarea id="rejectNote" rows={3} value={note} onChange={(e) => setNote(e.target.value)} />
        </Field>
      </div>
    </Dialog>
  );
}
