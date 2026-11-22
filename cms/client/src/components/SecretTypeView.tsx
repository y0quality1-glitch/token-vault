import { CheckCircle2, MinusCircle } from 'lucide-react';
import { orderedFields } from '@token-vault/shared';
import { Badge } from '@ui/badge';
import { Card, CardBody, CardHeader, DetailList } from '@ui/card';
import { secretCategoryLabel } from '@/lib/kinds';

/**
 * Read-only views of a secret type definition (shared/src/secrets/schema.ts). They render the
 * document as it is being edited, so every property is optional and defaults are shown as the
 * schema applies them.
 */
interface FieldShape {
  label?: string;
  description?: string;
  kind?: string;
  required?: boolean;
  sensitive?: boolean;
  pattern?: string;
  minLength?: number;
  maxLength?: number;
  min?: number;
  max?: number;
  values?: string[];
  placeholder?: string;
  /** Display position (then name); jsonb does not keep key order. */
  order?: number;
}

export interface SecretTypeShape {
  name?: string;
  description?: string;
  category?: string;
  fields?: Record<string, FieldShape>;
  metadata?: Record<string, FieldShape>;
  identifiedBy?: string[];
  lifecycle?: { versioning?: boolean; rotation?: boolean; expiration?: boolean; dynamic?: boolean };
  defaults?: { rotationIntervalDays?: number; expiresInDays?: number; expiryWarningDays?: number };
  tags?: string[];
}

const asRecord = (v: unknown): Record<string, FieldShape> => (v && typeof v === 'object' && !Array.isArray(v) ? (v as Record<string, FieldShape>) : {});

/** The field's validation rules, in words. */
function rules(f: FieldShape): string[] {
  const out: string[] = [];
  if (f.values?.length) out.push(`one of ${f.values.join(', ')}`);
  if (f.pattern) out.push(`matches ${f.pattern}`);
  if (f.minLength !== undefined && f.maxLength !== undefined) out.push(`${f.minLength}–${f.maxLength} characters`);
  else if (f.minLength !== undefined) out.push(`at least ${f.minLength} characters`);
  else if (f.maxLength !== undefined) out.push(`at most ${f.maxLength} characters`);
  if (f.min !== undefined && f.max !== undefined) out.push(`${f.min}–${f.max}`);
  else if (f.min !== undefined) out.push(`≥ ${f.min}`);
  else if (f.max !== undefined) out.push(`≤ ${f.max}`);
  return out;
}

function FieldTable({ fields, sensitivity, identifiedBy = [] }: { fields: Record<string, FieldShape>; sensitivity: boolean; identifiedBy?: string[] }) {
  const entries = orderedFields(Object.fromEntries(Object.entries(fields).map(([n, f]) => [n, { ...(f && typeof f === 'object' ? f : {}), order: typeof f?.order === 'number' ? f.order : 0 }])));
  if (!entries.length) return <p className="px-5 py-4 text-sm text-slate-500">None.</p>;
  return (
    <div className="overflow-x-auto">
      <table className="min-w-full divide-y divide-slate-100 text-sm">
        <thead>
          <tr className="text-left text-xs font-semibold uppercase tracking-wide text-slate-500">
            <th className="px-5 py-2.5">Field</th>
            <th className="px-3 py-2.5">Kind</th>
            <th className="px-3 py-2.5">Required</th>
            {sensitivity && <th className="px-3 py-2.5">Sensitivity</th>}
            <th className="px-5 py-2.5">Validation</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-slate-100">
          {entries.map(([name, f]) => {
            const r = rules(f);
            const sensitive = f.sensitive ?? true;
            return (
              <tr key={name} className="align-top" data-testid={`secret-field-${name}`}>
                <td className="px-5 py-2.5">
                  <p className="font-medium text-slate-900">{f.label || <span className="text-slate-400">(no label)</span>}</p>
                  <p className="font-mono text-xs text-slate-500">
                    {name}
                    {identifiedBy.includes(name) && <span className="ml-1.5 font-sans text-brand-700">· identifies</span>}
                  </p>
                  {f.description && <p className="mt-0.5 text-xs text-slate-500">{f.description}</p>}
                </td>
                <td className="px-3 py-2.5">
                  <span className="font-mono text-xs">{f.kind ?? 'text'}</span>
                </td>
                <td className="px-3 py-2.5">
                  {f.required ? <CheckCircle2 className="h-4 w-4 text-emerald-600" aria-label="Required" /> : <MinusCircle className="h-4 w-4 text-slate-300" aria-label="Optional" />}
                </td>
                {sensitivity && (
                  <td className="px-3 py-2.5">
                    {sensitive ? <Badge tone="violet">Sensitive</Badge> : <Badge tone="amber">Shown in summaries</Badge>}
                  </td>
                )}
                <td className="px-5 py-2.5">
                  {r.length ? (
                    <ul className="space-y-0.5 text-xs text-slate-600">
                      {r.map((x) => (
                        <li key={x} className="break-all font-mono">
                          {x}
                        </li>
                      ))}
                    </ul>
                  ) : (
                    <span className="text-xs text-slate-400">—</span>
                  )}
                  {f.placeholder && <p className="mt-0.5 text-xs text-slate-400">e.g. {f.placeholder}</p>}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

/** Payload fields and metadata, as tables. */
export function SecretTypePreview({ def }: { def: SecretTypeShape }) {
  const fields = asRecord(def.fields);
  const metadata = asRecord(def.metadata);
  return (
    <div className="space-y-4">
      <div className="rounded-lg border border-slate-200">
        <div className="border-b border-slate-100 px-5 py-3">
          <p className="text-sm font-semibold text-slate-900">Payload fields ({Object.keys(fields).length})</p>
          <p className="text-xs text-slate-500">Every field is encrypted by the webhook. Sensitive fields are masked everywhere and only returned by an authorized retrieval.</p>
        </div>
        <FieldTable fields={fields} sensitivity identifiedBy={Array.isArray(def.identifiedBy) ? def.identifiedBy : []} />
      </div>
      <div className="rounded-lg border border-slate-200">
        <div className="border-b border-slate-100 px-5 py-3">
          <p className="text-sm font-semibold text-slate-900">Metadata ({Object.keys(metadata).length})</p>
          <p className="text-xs text-slate-500">Descriptive attributes kept with the secret in the control plane, in clear. Never sensitive.</p>
        </div>
        <FieldTable fields={metadata} sensitivity={false} />
      </div>
    </div>
  );
}

const yesNo = (v: boolean) => (v ? <Badge tone="green">Supported</Badge> : <Badge>No</Badge>);

/** Category, identity, lifecycle, defaults and tags. */
export function SecretTypeSummary({ def }: { def: SecretTypeShape }) {
  const l = def.lifecycle ?? {};
  const d = def.defaults ?? {};
  const days = (n: number | undefined) => (n === undefined ? '—' : `${n} day${n === 1 ? '' : 's'}`);
  return (
    <Card>
      <CardHeader title="Summary" />
      <CardBody className="space-y-4">
        <DetailList
          columns={1}
          items={[
            { label: 'Category', value: def.category ? secretCategoryLabel(def.category) : '—' },
            { label: 'Identified by', value: def.identifiedBy?.length ? def.identifiedBy.join(' + ') : '—', mono: !!def.identifiedBy?.length },
            { label: 'Tags', value: def.tags?.length ? <span className="flex flex-wrap gap-1">{def.tags.map((t) => <Badge key={t}>{t}</Badge>)}</span> : '—' },
          ]}
        />
        <div>
          <p className="mb-2 text-xs font-semibold uppercase tracking-wide text-slate-500">Lifecycle</p>
          <DetailList
            columns={2}
            items={[
              { label: 'Versioning', value: yesNo(l.versioning ?? true) },
              { label: 'Rotation', value: yesNo(l.rotation ?? true) },
              { label: 'Expiration', value: yesNo(l.expiration ?? true) },
              { label: 'Dynamic', value: yesNo(l.dynamic ?? false) },
            ]}
          />
        </div>
        <div>
          <p className="mb-2 text-xs font-semibold uppercase tracking-wide text-slate-500">Defaults</p>
          <DetailList
            columns={1}
            items={[
              { label: 'Rotation interval', value: days(d.rotationIntervalDays) },
              { label: 'Expires in', value: days(d.expiresInDays) },
              { label: 'Expiry warning', value: days(d.expiryWarningDays ?? 14) },
            ]}
          />
        </div>
      </CardBody>
    </Card>
  );
}
