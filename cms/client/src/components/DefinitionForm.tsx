import { useState, type ReactNode } from 'react';
import { ArrowDown, ArrowUp, ChevronDown, ChevronRight, Copy, Plus, Trash2 } from 'lucide-react';
import { Badge } from '@ui/badge';
import { Button } from '@ui/button';
import { Checkbox, Field, Input, Select, Textarea } from '@ui/form';
import { cn } from '@/lib/utils';

/**
 * Form view of a provider definition. It edits the same document as the JSON view:
 * every change produces a new definition object, and properties the form does not show
 * are carried over untouched. Validation runs on the whole document (shared validator);
 * here, each section shows the problems that concern it.
 */
// The document is free-form JSON while being edited (it may be invalid), hence `any`.
// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Obj = Record<string, any>;

interface Props {
  value: Obj;
  onChange: (next: Obj) => void;
  readOnly: boolean;
  /** Problems in the current (unsaved) document, as reported by validateProviderDefinition. */
  issues: string[];
}

/** Applies a mutation to a deep copy and reports the copy. */
function useEditor(value: Obj, onChange: (v: Obj) => void) {
  return (fn: (draft: Obj) => void) => {
    const draft = structuredClone(value);
    fn(draft);
    onChange(draft);
  };
}

const issuesFor = (issues: string[], ...prefixes: string[]) => issues.filter((i) => prefixes.some((p) => i === p || i.startsWith(`${p}.`) || i.startsWith(`${p}:`) || i.startsWith(`${p} `) || i.startsWith(`${p}[`)));
const opIssues = (issues: string[], i: number) => issuesFor(issues, `operations.${i}`, `operations[${i}]`);

// ---------------------------------------------------------------- small building blocks

function Section({ title, description, issues, children, actions }: { title: string; description?: string; issues: string[]; children: ReactNode; actions?: ReactNode }) {
  return (
    <section className="rounded-lg border border-slate-200" aria-label={title}>
      <header className="flex items-start justify-between gap-3 border-b border-slate-100 px-4 py-3">
        <div>
          <h3 className="flex items-center gap-2 text-sm font-semibold text-slate-900">
            {title}
            {issues.length > 0 && <Badge tone="red">{issues.length} problem{issues.length > 1 ? 's' : ''}</Badge>}
          </h3>
          {description && <p className="mt-0.5 text-xs text-slate-500">{description}</p>}
        </div>
        {actions}
      </header>
      <div className="space-y-4 p-4">
        <IssueList issues={issues} />
        {children}
      </div>
    </section>
  );
}

function IssueList({ issues }: { issues: string[] }) {
  if (!issues.length) return null;
  return (
    <ul className="space-y-1 rounded-md bg-red-50 p-2.5" data-testid="section-issues">
      {issues.map((i) => (
        <li key={i} className="font-mono text-xs text-red-700">
          {i}
        </li>
      ))}
    </ul>
  );
}

function Text({ label, value, onChange, readOnly, mono, placeholder, hint, id }: { label: string; value: unknown; onChange: (v: string) => void; readOnly: boolean; mono?: boolean; placeholder?: string; hint?: ReactNode; id?: string }) {
  return (
    <Field label={label} htmlFor={id} hint={hint}>
      <Input id={id} aria-label={label} value={typeof value === 'string' || typeof value === 'number' ? String(value) : ''} onChange={(e) => onChange(e.target.value)} disabled={readOnly} placeholder={placeholder} className={mono ? 'font-mono text-xs' : undefined} />
    </Field>
  );
}

/** A list of strings, one per line. */
function Lines({ label, value, onChange, readOnly, hint, placeholder }: { label: string; value: unknown; onChange: (v: string[]) => void; readOnly: boolean; hint?: string; placeholder?: string }) {
  const list = Array.isArray(value) ? (value as string[]) : [];
  return (
    <Field label={label} hint={hint}>
      <Textarea
        aria-label={label}
        rows={Math.max(2, list.length)}
        className="font-mono text-xs"
        value={list.join('\n')}
        disabled={readOnly}
        placeholder={placeholder}
        onChange={(e) => onChange(e.target.value.split('\n').map((s) => s.trim()).filter((s, i, all) => s || i === all.length - 1))}
        onBlur={(e) => onChange(e.target.value.split('\n').map((s) => s.trim()).filter(Boolean))}
      />
    </Field>
  );
}

/** Key/value pairs (headers, query parameters, permissions, simple response fields). */
function Pairs({ label, value, onChange, readOnly, keyLabel = 'Name', valueLabel = 'Value', hint }: { label: string; value: unknown; onChange: (v: Obj) => void; readOnly: boolean; keyLabel?: string; valueLabel?: string; hint?: ReactNode }) {
  const entries = Object.entries(value && typeof value === 'object' && !Array.isArray(value) ? (value as Obj) : {});
  const rebuild = (list: [string, unknown][]) => onChange(Object.fromEntries(list));
  return (
    <div className="space-y-2">
      <div className="flex items-center justify-between">
        <p className="text-sm font-medium text-slate-700">{label}</p>
        {!readOnly && (
          <Button size="sm" variant="ghost" onClick={() => rebuild([...entries, [`${keyLabel.toLowerCase()}${entries.length + 1}`, '']])}>
            <Plus className="h-3.5 w-3.5" /> Add
          </Button>
        )}
      </div>
      {entries.length === 0 && <p className="text-xs text-slate-400">None.</p>}
      {entries.map(([k, v], i) => (
        <div key={i} className="flex items-center gap-2">
          <Input aria-label={`${label} ${keyLabel} ${i + 1}`} className="font-mono text-xs" value={k} disabled={readOnly} placeholder={keyLabel} onChange={(e) => rebuild(entries.map((x, j) => (j === i ? [e.target.value, x[1]] : x)))} />
          <Input
            aria-label={`${label} ${valueLabel} ${i + 1}`}
            className="font-mono text-xs"
            value={typeof v === 'string' || typeof v === 'number' ? String(v) : JSON.stringify(v)}
            disabled={readOnly || (typeof v === 'object' && v !== null)}
            title={typeof v === 'object' && v !== null ? 'Structured value: edit it in the JSON view' : undefined}
            placeholder={valueLabel}
            onChange={(e) => rebuild(entries.map((x, j) => (j === i ? [x[0], e.target.value] : x)))}
          />
          {!readOnly && (
            <button className="rounded p-1.5 text-slate-400 hover:bg-slate-100 hover:text-red-600" aria-label={`Remove ${k}`} onClick={() => rebuild(entries.filter((_, j) => j !== i))}>
              <Trash2 className="h-3.5 w-3.5" />
            </button>
          )}
        </div>
      ))}
      {hint && <p className="text-xs text-slate-500">{hint}</p>}
    </div>
  );
}

/** A nested JSON value (request body, mock body) edited as text; invalid JSON is kept local until fixed. */
function JsonValue({ label, value, onChange, readOnly, hint }: { label: string; value: unknown; onChange: (v: unknown) => void; readOnly: boolean; hint?: ReactNode }) {
  const [draft, setDraft] = useState<string | null>(null);
  const shown = draft ?? (value === undefined ? '' : JSON.stringify(value, null, 2));
  let error: string | null = null;
  if (draft !== null && draft.trim()) {
    try {
      JSON.parse(draft);
    } catch (e) {
      error = (e as Error).message;
    }
  }
  return (
    <Field label={label} hint={hint} error={error ?? undefined}>
      <Textarea
        aria-label={label}
        rows={Math.min(10, Math.max(3, shown.split('\n').length))}
        className="font-mono text-xs"
        value={shown}
        disabled={readOnly}
        onChange={(e) => {
          setDraft(e.target.value);
          if (!e.target.value.trim()) onChange(undefined);
          else
            try {
              onChange(JSON.parse(e.target.value));
            } catch {
              /* keep the text until it parses */
            }
        }}
        onBlur={() => !error && setDraft(null)}
      />
    </Field>
  );
}

function ListControls({ index, length, readOnly, onMove, onDuplicate, onRemove, noun }: { index: number; length: number; readOnly: boolean; onMove: (to: number) => void; onDuplicate?: () => void; onRemove: () => void; noun: string }) {
  if (readOnly) return null;
  const btn = 'rounded p-1.5 text-slate-400 hover:bg-slate-100 hover:text-slate-700 disabled:opacity-30';
  return (
    <div className="flex items-center gap-0.5" onClick={(e) => e.stopPropagation()}>
      <button className={btn} disabled={index === 0} onClick={() => onMove(index - 1)} aria-label={`Move ${noun} up`}>
        <ArrowUp className="h-3.5 w-3.5" />
      </button>
      <button className={btn} disabled={index === length - 1} onClick={() => onMove(index + 1)} aria-label={`Move ${noun} down`}>
        <ArrowDown className="h-3.5 w-3.5" />
      </button>
      {onDuplicate && (
        <button className={btn} onClick={onDuplicate} aria-label={`Duplicate ${noun}`}>
          <Copy className="h-3.5 w-3.5" />
        </button>
      )}
      <button className={cn(btn, 'hover:text-red-600')} onClick={onRemove} aria-label={`Remove ${noun}`}>
        <Trash2 className="h-3.5 w-3.5" />
      </button>
    </div>
  );
}

const move = <T,>(list: T[], from: number, to: number) => {
  const next = [...list];
  const [x] = next.splice(from, 1);
  next.splice(to, 0, x!);
  return next;
};

/** Placeholders a request template may use, shown under request fields. */
function PlaceholderHint({ def, op }: { def: Obj; op?: Obj }) {
  const names = [def.resource?.name, ...Object.keys(def.resourceFields ?? {})].filter(Boolean).map((n) => `{resource.${n}}`);
  const inputs = Object.keys(op?.input ?? {}).map((n) => `{input.${n}}`);
  return (
    <span>
      Placeholders: <span className="font-mono">{[...names, ...inputs].join(' ') || 'none'}</span>, with an optional default after |, e.g. <span className="font-mono">{`{resource.${def.resource?.name ?? 'name'}|default}`}</span>
    </span>
  );
}

// ---------------------------------------------------------------- the form

export function DefinitionForm({ value, onChange, readOnly, issues }: Props) {
  const edit = useEditor(value, onChange);
  const def = value;
  const auth: Obj[] = Array.isArray(def.auth) ? def.auth : [];
  const ops: Obj[] = Array.isArray(def.operations) ? def.operations : [];
  const [open, setOpen] = useState<number | null>(ops.length === 1 ? 0 : null);
  const ro = readOnly;

  return (
    <div className="space-y-5" data-testid="definition-form">
      <Section title="General" issues={issuesFor(issues, 'name', 'description', 'definition')}>
        <div className="grid gap-4 sm:grid-cols-2">
          <Text label="Name" value={def.name} readOnly={ro} onChange={(v) => edit((d) => (d.name = v))} />
          <Field label="Key" hint="Set by the CMS; prefixes every operation id">
            <Input value={String(def.key ?? '')} disabled className="font-mono text-xs" />
          </Field>
        </div>
        <Field label="Description">
          <Textarea aria-label="Description" rows={2} value={String(def.description ?? '')} disabled={ro} onChange={(e) => edit((d) => (d.description = e.target.value))} />
        </Field>
      </Section>

      <Section title="API" description="Where requests go. Credentials are only ever sent to the allowed hosts, over https." issues={issuesFor(issues, 'api')}>
        <div className="grid gap-4 sm:grid-cols-[1fr_10rem]">
          <Text label="Base URL" mono value={def.api?.baseUrl} readOnly={ro} placeholder="https://api.example.com/v1" onChange={(v) => edit((d) => ((d.api ??= {}).baseUrl = v))} />
          <Text label="Timeout (ms)" mono value={def.api?.timeoutMs ?? ''} readOnly={ro} placeholder="10000" onChange={(v) => edit((d) => ((d.api ??= {}).timeoutMs = v === '' ? undefined : Number(v)))} />
        </div>
        <Lines label="Allowed hosts" value={def.api?.allowedHosts} readOnly={ro} hint='One per line; "*.example.com" allows subdomains. The token endpoint of an OAuth method must be listed too.' placeholder="api.example.com" onChange={(v) => edit((d) => ((d.api ??= {}).allowedHosts = v))} />
        <Pairs label="Static headers" keyLabel="Header" value={def.api?.headers} readOnly={ro} hint="No credentials here: they are attached by the auth method." onChange={(v) => edit((d) => ((d.api ??= {}).headers = v))} />
      </Section>

      <Section title="Resource" description="What grants are scoped to (e.g. a repository or a project), and extra request fields." issues={issuesFor(issues, 'resource', 'resourceFields')}>
        <div className="grid gap-4 sm:grid-cols-2">
          <Text label="Field name" mono value={def.resource?.name} readOnly={ro} placeholder="project" onChange={(v) => edit((d) => ((d.resource ??= {}).name = v))} />
          <Text label="Label" value={def.resource?.label} readOnly={ro} placeholder="Project" onChange={(v) => edit((d) => ((d.resource ??= {}).label = v))} />
          <Text label="Pattern (anchored regex)" mono value={def.resource?.pattern} readOnly={ro} placeholder="^[A-Za-z0-9_-]{1,64}$" onChange={(v) => edit((d) => ((d.resource ??= {}).pattern = v))} />
          <Text label="Example" mono value={def.resource?.example} readOnly={ro} onChange={(v) => edit((d) => ((d.resource ??= {}).example = v || undefined))} />
        </div>
        <Checkbox checked={!!def.resource?.caseInsensitive} disabled={ro} onChange={(v) => edit((d) => ((d.resource ??= {}).caseInsensitive = v))} label="Case-insensitive" />
        <Pairs
          label="Extra resource fields (name → pattern)"
          keyLabel="Field"
          valueLabel="Pattern"
          value={Object.fromEntries(Object.entries((def.resourceFields ?? {}) as Obj).map(([k, f]) => [k, (f as Obj)?.pattern ?? '']))}
          readOnly={ro}
          hint="Labels and examples of extra fields can be edited in the JSON view."
          onChange={(v) =>
            edit((d) => {
              const prev = (d.resourceFields ?? {}) as Obj;
              d.resourceFields = Object.fromEntries(Object.entries(v).map(([k, p]) => [k, { ...(prev[k] ?? { label: k }), pattern: p }]));
            })
          }
        />
      </Section>

      <Section
        title="Authentication"
        description="How the customer's webhook attaches the credential."
        issues={issuesFor(issues, 'auth')}
        actions={
          !ro && (
            <Button size="sm" variant="outline" onClick={() => edit((d) => (d.auth = [...auth, { id: `METHOD_${auth.length + 1}`, label: 'API key', kind: 'bearer' }]))}>
              <Plus className="h-3.5 w-3.5" /> Add method
            </Button>
          )
        }
      >
        {auth.map((a, i) => (
          <div key={i} className="space-y-3 rounded-md border border-slate-200 p-3" aria-label={`Auth method ${a.id ?? i + 1}`}>
            <div className="flex items-center justify-between">
              <span className="text-xs font-semibold uppercase tracking-wide text-slate-500">Method {i + 1}</span>
              <ListControls index={i} length={auth.length} readOnly={ro} noun="method" onMove={(to) => edit((d) => (d.auth = move(auth, i, to)))} onRemove={() => edit((d) => (d.auth = auth.filter((_, j) => j !== i)))} />
            </div>
            <div className="grid gap-3 sm:grid-cols-3">
              <Text label="Id" mono value={a.id} readOnly={ro} placeholder="API_KEY" onChange={(v) => edit((d) => (d.auth[i].id = v))} />
              <Text label="Label" value={a.label} readOnly={ro} onChange={(v) => edit((d) => (d.auth[i].label = v))} />
              <Field label="Kind">
                <Select
                  aria-label={`Kind of method ${i + 1}`}
                  value={a.kind ?? 'bearer'}
                  disabled={ro || a.kind === 'plugin'}
                  onChange={(e) =>
                    edit((d) => {
                      const m = d.auth[i];
                      m.kind = e.target.value;
                      if (m.kind !== 'header') delete m.header;
                      if (m.kind === 'header') m.header ??= 'X-Api-Key';
                      if (m.kind === 'oauth2') m.oauth ??= { authorizeUrl: 'https://', tokenUrl: 'https://', scopes: [] };
                      else delete m.oauth;
                    })
                  }
                >
                  <option value="bearer">Bearer token</option>
                  <option value="header">Custom header</option>
                  <option value="basic">Basic auth</option>
                  <option value="oauth2">OAuth 2.0</option>
                  {a.kind === 'plugin' && <option value="plugin">Plugin ({a.plugin})</option>}
                </Select>
              </Field>
            </div>
            <Text label="Description" value={a.description} readOnly={ro} onChange={(v) => edit((d) => (d.auth[i].description = v))} />
            {a.kind === 'header' && (
              <div className="grid gap-3 sm:grid-cols-2">
                <Text label="Credential header" mono value={a.header} readOnly={ro} onChange={(v) => edit((d) => (d.auth[i].header = v))} />
                <Text label="Value prefix" mono value={a.prefix} readOnly={ro} placeholder="(none)" onChange={(v) => edit((d) => (d.auth[i].prefix = v || undefined))} />
              </div>
            )}
            {(a.kind === 'bearer' || a.kind === 'header' || a.kind === 'basic') && (
              <div className="grid gap-3 sm:grid-cols-2">
                <Text label="Secret format (regex)" mono value={a.secretPattern} readOnly={ro} placeholder="^td_[a-z0-9]{16,}$" onChange={(v) => edit((d) => (d.auth[i].secretPattern = v || undefined))} />
                <Text label="Secret hint" value={a.secretHint} readOnly={ro} placeholder="Starts with td_" onChange={(v) => edit((d) => (d.auth[i].secretHint = v || undefined))} />
              </div>
            )}
            {a.kind === 'oauth2' && (
              <div className="space-y-3 rounded-md bg-slate-50 p-3">
                <div className="grid gap-3 sm:grid-cols-2">
                  <Text label="Authorize URL" mono value={a.oauth?.authorizeUrl} readOnly={ro} onChange={(v) => edit((d) => ((d.auth[i].oauth ??= {}).authorizeUrl = v))} />
                  <Text label="Token URL" mono value={a.oauth?.tokenUrl} readOnly={ro} hint="Its host must be an allowed host" onChange={(v) => edit((d) => ((d.auth[i].oauth ??= {}).tokenUrl = v))} />
                </div>
                <div className="grid gap-3 sm:grid-cols-2">
                  <Lines label="Scopes" value={a.oauth?.scopes} readOnly={ro} onChange={(v) => edit((d) => ((d.auth[i].oauth ??= {}).scopes = v))} />
                  <Field label="Client authentication">
                    <Select aria-label="Client authentication" value={a.oauth?.clientAuth ?? 'body'} disabled={ro} onChange={(e) => edit((d) => ((d.auth[i].oauth ??= {}).clientAuth = e.target.value))}>
                      <option value="body">In the request body</option>
                      <option value="basic">HTTP basic</option>
                    </Select>
                  </Field>
                </div>
                <Pairs label="Extra authorize parameters" value={a.oauth?.authorizeParams} readOnly={ro} onChange={(v) => edit((d) => ((d.auth[i].oauth ??= {}).authorizeParams = v))} />
              </div>
            )}
          </div>
        ))}
      </Section>

      <Section title="Credential test" description="Request used to check a credential when it is connected." issues={issuesFor(issues, 'credentialTest')}>
        <div className="grid gap-3 sm:grid-cols-[7rem_1fr]">
          <Field label="Method">
            <Select aria-label="Credential test method" value={def.credentialTest?.request?.method ?? 'GET'} disabled={ro} onChange={(e) => edit((d) => (((d.credentialTest ??= {}).request ??= {}).method = e.target.value))}>
              {['GET', 'POST'].map((m) => (
                <option key={m}>{m}</option>
              ))}
            </Select>
          </Field>
          <Text label="Path" mono value={def.credentialTest?.request?.path} readOnly={ro} placeholder="/me" onChange={(v) => edit((d) => (((d.credentialTest ??= {}).request ??= {}).path = v))} />
        </div>
        <Pairs label="Response fields kept" keyLabel="Output" valueLabel="Source path" value={def.credentialTest?.response?.fields} readOnly={ro} onChange={(v) => edit((d) => (((d.credentialTest ??= {}).response ??= {}).fields = v))} />
      </Section>

      <Section
        title={`Operations (${ops.length})`}
        description="What agents can be granted. Destructive operations are known to policies but never executed."
        issues={[]}
        actions={
          !ro && (
            <Button
              size="sm"
              variant="outline"
              onClick={() => {
                const base = `${def.key ?? 'app'}.items.new`;
                let id = base;
                for (let n = 2; ops.some((o) => o.id === id); n++) id = `${base}${n}`;
                edit((d) => (d.operations = [...ops, { id, label: 'New operation', risk: 'read', request: { method: 'GET', path: `/projects/{resource.${def.resource?.name ?? 'project'}}/items` }, response: { fields: { id: 'id' } } }]));
                setOpen(ops.length);
              }}
            >
              <Plus className="h-3.5 w-3.5" /> Add operation
            </Button>
          )
        }
      >
        {ops.map((op, i) => {
          const probs = opIssues(issues, i);
          const expanded = open === i;
          const setOp = (fn: (o: Obj) => void) => edit((d) => fn(d.operations[i]));
          return (
            <div key={i} className="rounded-md border border-slate-200" aria-label={`Operation ${op.id ?? i + 1}`}>
              <div role="button" tabIndex={0} className="flex cursor-pointer items-center gap-2 px-3 py-2.5" onClick={() => setOpen(expanded ? null : i)} onKeyDown={(e) => e.key === 'Enter' && setOpen(expanded ? null : i)}>
                {expanded ? <ChevronDown className="h-4 w-4 text-slate-400" /> : <ChevronRight className="h-4 w-4 text-slate-400" />}
                <span className="text-sm font-medium text-slate-800">{op.label || op.id}</span>
                <span className="truncate font-mono text-xs text-slate-500">
                  {op.request?.method} {op.request?.path}
                </span>
                <span className="ml-auto flex items-center gap-2">
                  {probs.length > 0 && <Badge tone="red">{probs.length}</Badge>}
                  <Badge tone={op.risk === 'read' ? 'green' : op.risk === 'write' ? 'amber' : 'red'}>{op.risk}</Badge>
                  <ListControls
                    index={i}
                    length={ops.length}
                    readOnly={ro}
                    noun="operation"
                    onMove={(to) => {
                      edit((d) => (d.operations = move(ops, i, to)));
                      setOpen(to);
                    }}
                    onDuplicate={() => {
                      edit((d) => d.operations.splice(i + 1, 0, { ...structuredClone(op), id: `${op.id}-copy` }));
                      setOpen(i + 1);
                    }}
                    onRemove={() => {
                      edit((d) => (d.operations = ops.filter((_, j) => j !== i)));
                      setOpen(null);
                    }}
                  />
                </span>
              </div>
              {expanded && (
                <div className="space-y-4 border-t border-slate-100 p-3">
                  <IssueList issues={probs} />
                  <div className="grid gap-3 sm:grid-cols-3">
                    <Text label="Operation id" mono value={op.id} readOnly={ro} onChange={(v) => setOp((o) => (o.id = v))} />
                    <Text label="Label" value={op.label} readOnly={ro} onChange={(v) => setOp((o) => (o.label = v))} />
                    <Field label="Risk">
                      <Select aria-label="Risk" value={op.risk ?? 'read'} disabled={ro} onChange={(e) => setOp((o) => (o.risk = e.target.value))}>
                        <option value="read">read</option>
                        <option value="write">write</option>
                        <option value="destructive">destructive (never executed)</option>
                      </Select>
                    </Field>
                  </div>
                  <Text label="Operation description" value={op.description} readOnly={ro} onChange={(v) => setOp((o) => (o.description = v))} />
                  <Checkbox checked={op.requiresResource !== false} disabled={ro} onChange={(v) => setOp((o) => (o.requiresResource = v))} label={`Requires a ${def.resource?.label?.toLowerCase() ?? 'resource'}`} />
                  <div className="grid gap-3 sm:grid-cols-[7rem_1fr]">
                    <Field label="Method">
                      <Select aria-label="Request method" value={op.request?.method ?? 'GET'} disabled={ro} onChange={(e) => setOp((o) => ((o.request ??= {}).method = e.target.value))}>
                        {['GET', 'POST', 'PUT', 'PATCH', 'DELETE'].map((m) => (
                          <option key={m}>{m}</option>
                        ))}
                      </Select>
                    </Field>
                    <Text label="Request path" mono value={op.request?.path} readOnly={ro} hint={<PlaceholderHint def={def} op={op} />} onChange={(v) => setOp((o) => ((o.request ??= {}).path = v))} />
                  </div>
                  <Pairs label="Query parameters" value={op.request?.query} readOnly={ro} onChange={(v) => setOp((o) => ((o.request ??= {}).query = Object.keys(v).length ? v : undefined))} />
                  {op.request?.method !== 'GET' && (
                    <JsonValue label="Request body (JSON template)" value={op.request?.body} readOnly={ro} hint={<PlaceholderHint def={def} op={op} />} onChange={(v) => setOp((o) => ((o.request ??= {}).body = v))} />
                  )}
                  <InputFields op={op} readOnly={ro} onChange={(input) => setOp((o) => (o.input = input))} />
                  <Pairs label="Response fields kept" keyLabel="Output" valueLabel="Source path" value={op.response?.fields} readOnly={ro} hint='Only these fields are returned to Token Vault. Use the JSON view for transforms like {"path": "content", "decode": "base64"}.' onChange={(v) => setOp((o) => ((o.response ??= {}).fields = v))} />
                  <Pairs label="Provider permissions (for token-minting plugins)" keyLabel="Permission" valueLabel="read | write" value={op.providerPermissions} readOnly={ro} onChange={(v) => setOp((o) => (o.providerPermissions = v))} />
                  <div className="grid gap-3 sm:grid-cols-[8rem_1fr]">
                    <Text label="Mock status" mono value={op.mock?.status ?? ''} readOnly={ro} placeholder="200" onChange={(v) => setOp((o) => (o.mock = v === '' ? undefined : { ...(o.mock ?? {}), status: Number(v) }))} />
                    <JsonValue label="Mock response body" value={op.mock?.body} readOnly={ro || !op.mock} hint="Used in mock mode when there is no simulator for the host" onChange={(v) => setOp((o) => (o.mock = { ...(o.mock ?? { status: 200 }), body: v }))} />
                  </div>
                </div>
              )}
            </div>
          );
        })}
      </Section>
    </div>
  );
}

function InputFields({ op, readOnly, onChange }: { op: Obj; readOnly: boolean; onChange: (input: Obj) => void }) {
  const entries = Object.entries((op.input ?? {}) as Obj);
  const rebuild = (list: [string, Obj][]) => onChange(Object.fromEntries(list));
  return (
    <div className="space-y-2">
      <div className="flex items-center justify-between">
        <p className="text-sm font-medium text-slate-700">Input fields</p>
        {!readOnly && (
          <Button size="sm" variant="ghost" onClick={() => rebuild([...entries, [`field${entries.length + 1}`, { type: 'string' }]])}>
            <Plus className="h-3.5 w-3.5" /> Add input
          </Button>
        )}
      </div>
      {entries.length === 0 && <p className="text-xs text-slate-400">None. Only declared inputs can be used in templates; anything else an agent sends is dropped.</p>}
      {entries.map(([name, f], i) => (
        <div key={i} className="grid items-center gap-2 sm:grid-cols-[1fr_7rem_6rem_auto_auto]">
          <Input aria-label={`Input name ${i + 1}`} className="font-mono text-xs" value={name} disabled={readOnly} onChange={(e) => rebuild(entries.map((x, j) => (j === i ? [e.target.value, x[1]] : x)))} />
          <Select aria-label={`Input type ${i + 1}`} value={f.type ?? 'string'} disabled={readOnly} onChange={(e) => rebuild(entries.map((x, j) => (j === i ? [x[0], { ...x[1], type: e.target.value }] : x)))}>
            <option value="string">string</option>
            <option value="number">number</option>
            <option value="boolean">boolean</option>
          </Select>
          <Input aria-label={`Input max length ${i + 1}`} className="font-mono text-xs" placeholder="max len" value={f.maxLength ?? ''} disabled={readOnly} onChange={(e) => rebuild(entries.map((x, j) => (j === i ? [x[0], { ...x[1], maxLength: e.target.value ? Number(e.target.value) : undefined }] : x)))} />
          <Checkbox checked={!!f.required} disabled={readOnly} onChange={(v) => rebuild(entries.map((x, j) => (j === i ? [x[0], { ...x[1], required: v }] : x)))} label="required" />
          {!readOnly && (
            <button className="rounded p-1.5 text-slate-400 hover:bg-slate-100 hover:text-red-600" aria-label={`Remove input ${name}`} onClick={() => rebuild(entries.filter((_, j) => j !== i))}>
              <Trash2 className="h-3.5 w-3.5" />
            </button>
          )}
        </div>
      ))}
    </div>
  );
}
