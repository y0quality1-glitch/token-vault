import { useRef, useState } from 'react';
import { Link } from 'react-router-dom';
import { FileUp, ListChecks, Upload } from 'lucide-react';
import { SECRET_SCOPE_SLUG, type Environment, type SecretImportOutcome, type SecretImportReport, type SecretImportResult } from '@token-vault/shared';
import { useMutation } from '@/hooks/useApi';
import { api } from '@/lib/api';
import { ENV_LABELS } from '@/lib/utils';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardBody, CardHeader } from '@/components/ui/card';
import { Field, Input, RadioCard, Select, Textarea } from '@/components/ui/form';
import { Callout } from '@/components/ui/feedback';
import { DataTable } from '@/components/ui/table';
import { PageHeader } from '@/components/ui/navigation';
import { useToast } from '@/components/ui/toast';
import { ApiErrorCallout } from './secretUi';

type Format = 'json' | 'env';
type OnConflict = 'skip' | 'new_version' | 'fail';

/** Largest file read into the form (the server takes at most 200 secrets per import). */
const MAX_FILE_BYTES = 2 * 1024 * 1024;

const OUTCOMES: Record<SecretImportOutcome, { label: string; tone: 'green' | 'blue' | 'gray' | 'red' | 'amber' }> = {
  valid: { label: 'Valid', tone: 'green' },
  created: { label: 'Created', tone: 'green' },
  new_version: { label: 'New version', tone: 'blue' },
  skipped: { label: 'Skipped', tone: 'gray' },
  invalid: { label: 'Invalid', tone: 'red' },
  failed: { label: 'Failed', tone: 'red' },
};
const OUTCOME_ORDER: SecretImportOutcome[] = ['valid', 'created', 'new_version', 'skipped', 'invalid', 'failed'];

const JSON_EXAMPLE = `[
  {
    "name": "orders-db primary",
    "typeKey": "postgresql",
    "environment": "production",
    "payload": { "host": "db.internal", "database": "orders", "username": "app", "password": "…" }
  }
]`;

/** Import secrets from a JSON list (or a decrypted export) or a .env file (spec 4.9.14). */
export function SecretImportPage() {
  const toast = useToast();
  const fileRef = useRef<HTMLInputElement>(null);
  const [format, setFormat] = useState<Format>('json');
  const [content, setContent] = useState('');
  const [fileName, setFileName] = useState('');
  const [name, setName] = useState('');
  const [project, setProject] = useState('');
  const [workspace, setWorkspace] = useState('');
  const [environment, setEnvironment] = useState<Environment | ''>('');
  const [onConflict, setOnConflict] = useState<OnConflict>('skip');
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [report, setReport] = useState<SecretImportReport | null>(null);
  const submit = useMutation((body: unknown) => api.post<SecretImportReport>('/secret/import', body));
  const allErrors = { ...submit.fieldErrors, ...errors };

  function chooseFormat(f: Format) {
    setFormat(f);
    setReport(null);
  }

  async function readFile(file: File | undefined) {
    if (!file) return;
    if (file.size > MAX_FILE_BYTES) {
      setErrors({ content: 'The file is larger than 2 MB' });
      return;
    }
    const text = await file.text();
    setContent(text);
    setFileName(file.name);
    setReport(null);
    setErrors({});
    const lower = file.name.toLowerCase();
    if (lower.endsWith('.json')) setFormat('json');
    else if (lower.endsWith('.env') || lower.startsWith('.env')) {
      setFormat('env');
      // ".env.production" → "env.production": a valid secret name the member can change.
      if (!name.trim()) setName(file.name.replace(/^\.+/, '').slice(0, 120));
    }
    if (fileRef.current) fileRef.current.value = '';
  }

  function validate(): boolean {
    const e: Record<string, string> = {};
    if (!content.trim()) e.content = 'Paste or upload the file';
    if (format === 'json') {
      try {
        JSON.parse(content);
      } catch {
        if (content.trim()) e.content = 'Not valid JSON';
      }
    }
    if (format === 'env' && !name.trim()) e.name = 'Name the secret the variables go into';
    if (format === 'env' && !environment) e.environment = 'Choose development, staging or production';
    if (project.trim() && !SECRET_SCOPE_SLUG.test(project.trim())) e.project = 'Lower-case letters, digits and dashes (at most 63 characters)';
    if (workspace.trim() && !SECRET_SCOPE_SLUG.test(workspace.trim())) e.workspace = 'Lower-case letters, digits and dashes (at most 63 characters)';
    setErrors(e);
    return Object.keys(e).length === 0;
  }

  async function run(dryRun: boolean) {
    if (!validate()) {
      submit.setError(null);
      return;
    }
    const r = await submit.run({
      format,
      content,
      ...(format === 'env' ? { name: name.trim() } : {}),
      ...(project.trim() ? { project: project.trim() } : {}),
      ...(workspace.trim() ? { workspace: workspace.trim() } : {}),
      ...(environment ? { environment } : {}),
      onConflict,
      dryRun,
    });
    if (!r) return;
    setReport(r);
    if (!dryRun) {
      // The values were sent; do not keep them in the page.
      setContent('');
      setFileName('');
      const done = r.counts.created + r.counts.new_version;
      if (done) toast.success('Import finished', `${r.counts.created} created, ${r.counts.new_version} new version(s)`);
      else toast.error('Nothing imported', 'See the results below.');
    }
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="Import secrets"
        description="Bring existing secrets into Token Vault from a JSON file (including a decrypted export) or a .env file."
        breadcrumbs={[{ label: 'Secrets', to: '/secrets' }, { label: 'Import' }]}
      />
      <Callout tone="security" title="Imported secrets follow the same rules as any other">
        Every value is validated against its secret type, encrypted on your customer webhook and recorded in the audit log. Names already used in the same project, workspace and environment are handled by the conflict choice below, and values identical to an existing secret’s are pointed out (by fingerprint; values are never compared in clear).
      </Callout>

      <Card>
        <CardHeader title="File" description="Check first: nothing is stored until you import." icon={<FileUp className="h-4 w-4" />} />
        <CardBody className="space-y-5">
          <div className="grid gap-2 sm:grid-cols-2">
            <div data-testid="secret-import-format-json">
              <RadioCard checked={format === 'json'} onChange={() => chooseFormat('json')} title="JSON" description="A list of secrets with name, typeKey and payload, or a decrypted Token Vault export. At most 200." />
            </div>
            <div data-testid="secret-import-format-env">
              <RadioCard checked={format === 'env'} onChange={() => chooseFormat('env')} title=".env file" description="KEY=VALUE lines, stored as one “Environment variables” secret." />
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-3">
            <input ref={fileRef} id="secret-import-file" type="file" accept=".json,.env,.txt,application/json,text/plain" className="sr-only" onChange={(e) => void readFile(e.target.files?.[0])} data-testid="secret-import-file" />
            <Button variant="outline" onClick={() => fileRef.current?.click()}>
              <Upload className="h-4 w-4" /> Choose file
            </Button>
            <span className="min-w-0 truncate text-sm text-slate-500">{fileName ? fileName : 'or paste the content below'}</span>
          </div>

          <Field label="Content" htmlFor="secret-import-content" required error={allErrors.content} hint={format === 'json' ? 'An array of secrets, or {"secrets": [...]}.' : 'One KEY=VALUE per line; comments and export prefixes are allowed.'}>
            <Textarea
              id="secret-import-content"
              rows={10}
              className="font-mono text-[13px] [-webkit-text-security:disc] focus:[-webkit-text-security:none]"
              value={content}
              onChange={(e) => {
                setContent(e.target.value);
                setReport(null);
              }}
              invalid={!!allErrors.content}
              placeholder={format === 'json' ? JSON_EXAMPLE : 'DATABASE_URL=postgres://…\nSTRIPE_KEY=sk_live_…'}
              spellCheck={false}
              autoComplete="off"
              data-1p-ignore
              data-lpignore="true"
              data-testid="secret-import-content"
            />
          </Field>

          {format === 'env' && (
            <Field label="Secret name" htmlFor="secret-import-name" required error={allErrors.name} hint="The variables are stored together as one secret with this name.">
              <Input id="secret-import-name" value={name} onChange={(e) => setName(e.target.value)} invalid={!!allErrors.name} placeholder="orders-api env" data-testid="secret-import-name" />
            </Field>
          )}

          <div className="grid gap-4 sm:grid-cols-3">
            <Field label="Default project" htmlFor="secret-import-project" error={allErrors.project} hint="For items that do not say. Defaults to “default”.">
              <Input id="secret-import-project" value={project} onChange={(e) => setProject(e.target.value)} placeholder="default" invalid={!!allErrors.project} data-testid="secret-import-project" />
            </Field>
            <Field label="Default workspace" htmlFor="secret-import-workspace" error={allErrors.workspace} hint="Defaults to “default”.">
              <Input id="secret-import-workspace" value={workspace} onChange={(e) => setWorkspace(e.target.value)} placeholder="default" invalid={!!allErrors.workspace} data-testid="secret-import-workspace" />
            </Field>
            <Field label="Default environment" htmlFor="secret-import-environment" error={allErrors.environment} hint={format === 'env' ? 'Required for a .env file.' : 'For items that do not say.'}>
              <Select id="secret-import-environment" value={environment} onChange={(e) => setEnvironment(e.target.value as Environment | '')} invalid={!!allErrors.environment} data-testid="secret-import-environment">
                <option value="">{format === 'env' ? 'Choose…' : 'As in the file'}</option>
                {Object.entries(ENV_LABELS).map(([k, label]) => (
                  <option key={k} value={k}>
                    {label}
                  </option>
                ))}
              </Select>
            </Field>
          </div>

          <Field label="When a secret with the same name exists" htmlFor="secret-import-conflict" error={allErrors.onConflict} hint="Same name in the same project, workspace and environment.">
            <Select id="secret-import-conflict" className="sm:w-96" value={onConflict} onChange={(e) => setOnConflict(e.target.value as OnConflict)} data-testid="secret-import-conflict">
              <option value="skip">Skip it (keep the existing secret)</option>
              <option value="new_version">Store the imported value as a new version</option>
              <option value="fail">Report it as failed</option>
            </Select>
          </Field>

          <ApiErrorCallout error={submit.error} shownFields={['content', 'name', 'project', 'workspace', 'environment', 'onConflict']} />

          <div className="flex flex-wrap justify-end gap-2">
            <Button variant="outline" loading={submit.pending} onClick={() => void run(true)} data-testid="secret-import-check">
              <ListChecks className="h-4 w-4" /> Check
            </Button>
            <Button loading={submit.pending} onClick={() => void run(false)} data-testid="secret-import-run">
              <Upload className="h-4 w-4" /> Import
            </Button>
          </div>
        </CardBody>
      </Card>

      {report && <ImportReport report={report} />}
    </div>
  );
}

function ImportReport({ report }: { report: SecretImportReport }) {
  const counts = OUTCOME_ORDER.filter((o) => report.counts[o] > 0);
  return (
    <Card data-testid="secret-import-report" data-dry-run={report.dryRun ? 'true' : 'false'}>
      <CardHeader
        title={report.dryRun ? 'Check results' : 'Import results'}
        description={report.dryRun ? 'Nothing was stored. Fix the invalid items, then import.' : 'Created secrets are active and can be opened below.'}
      />
      <CardBody className="border-b border-slate-100">
        <div className="flex flex-wrap gap-2" data-testid="secret-import-counts">
          <span className="text-sm text-slate-600">{report.results.length} item(s):</span>
          {counts.length === 0 && <span className="text-sm text-slate-500">nothing to report</span>}
          {counts.map((o) => (
            <span key={o} data-outcome={o} data-count={report.counts[o]}>
              <Badge tone={OUTCOMES[o].tone}>
                {report.counts[o]} {OUTCOMES[o].label.toLowerCase()}
              </Badge>
            </span>
          ))}
        </div>
      </CardBody>
      <DataTable
        rows={report.results}
        rowKey={(r) => String(r.index)}
        dense
        empty={<p className="px-5 py-6 text-sm text-slate-500">The file holds no secrets.</p>}
        columns={[
          {
            key: 'name',
            header: 'Name',
            cell: (r: SecretImportResult) => (
              <div className="min-w-0" data-testid="secret-import-result" data-outcome={r.outcome} data-name={r.name}>
                {r.secretId ? (
                  <Link className="font-medium text-brand-700 hover:underline" to={`/secrets/${r.secretId}`}>
                    {r.name || `Item ${r.index + 1}`}
                  </Link>
                ) : (
                  <span className="font-medium text-slate-900">{r.name || `Item ${r.index + 1}`}</span>
                )}
                <span className="block text-xs text-slate-400">#{r.index + 1}</span>
              </div>
            ),
          },
          {
            key: 'outcome',
            header: 'Outcome',
            cell: (r: SecretImportResult) => (
              <Badge tone={OUTCOMES[r.outcome]?.tone ?? 'gray'} dot>
                {OUTCOMES[r.outcome]?.label ?? r.outcome}
              </Badge>
            ),
          },
          {
            key: 'issues',
            header: 'Issues',
            cell: (r: SecretImportResult) =>
              Object.keys(r.issues).length ? (
                <ul className="max-w-md space-y-0.5 text-xs" data-testid="secret-import-issues">
                  {Object.entries(r.issues).map(([k, v]) => (
                    <li key={k} className="break-words">
                      <span className="font-mono text-slate-700">{k}</span>: <span className={r.outcome === 'skipped' ? 'text-slate-600' : 'text-red-700'}>{v}</span>
                    </li>
                  ))}
                </ul>
              ) : (
                <span className="text-slate-400">—</span>
              ),
          },
          {
            key: 'same',
            header: 'Same value as',
            hideBelow: 'md',
            cell: (r: SecretImportResult) =>
              r.sameValueAs.length ? (
                <div className="flex max-w-xs flex-wrap gap-x-2 gap-y-0.5 text-xs" data-testid="secret-import-same-value">
                  {r.sameValueAs.map((x) => (
                    <Link key={x.id} className="text-brand-700 hover:underline" to={`/secrets/${x.id}`}>
                      {x.name}
                    </Link>
                  ))}
                </div>
              ) : (
                <span className="text-slate-400">—</span>
              ),
          },
        ]}
      />
    </Card>
  );
}
