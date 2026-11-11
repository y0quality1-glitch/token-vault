import { Plus, Trash2 } from 'lucide-react';
import { DATA_DETECTORS, INJECTION_MODES, type DataDetector, type InjectionMode, type ResponseFilter } from '@token-vault/shared';
import { Button } from '@/components/ui/button';
import { Checkbox, Field, Input } from '@/components/ui/form';
import { cn, splitList } from '@/lib/utils';

/** Editor state: removeFields as typed text. */
export interface FilterDraft {
  mask: DataDetector[];
  removeFields: string;
  patterns: { name: string; pattern: string }[];
  promptInjection: InjectionMode;
}

export const EMPTY_DRAFT: FilterDraft = { mask: ['email', 'secret'], removeFields: '', patterns: [], promptInjection: 'flag' };

export const toDraft = (f: ResponseFilter | null | undefined): FilterDraft => (f ? { mask: f.mask, removeFields: f.removeFields.join(', '), patterns: f.customPatterns, promptInjection: f.promptInjection } : EMPTY_DRAFT);

export const fromDraft = (d: FilterDraft): ResponseFilter => ({ mask: d.mask, removeFields: splitList(d.removeFields), customPatterns: d.patterns.map((p) => ({ name: p.name.trim(), pattern: p.pattern })), promptInjection: d.promptInjection });

/** "Masks email, secret; removes 2 fields; withholds likely prompt injection", for the policy list. */
export function describeFilter(f: ResponseFilter): string {
  const parts: string[] = [];
  const masks = [...f.mask.map((m) => DATA_DETECTORS.find((d) => d.id === m)?.label.split(' (')[0]?.toLowerCase() ?? m), ...f.customPatterns.map((p) => p.name)];
  if (masks.length) parts.push(`masks ${masks.join(', ')}`);
  if (f.removeFields.length) parts.push(`removes ${f.removeFields.join(', ')}`);
  if (f.promptInjection === 'flag') parts.push('flags likely prompt injection');
  if (f.promptInjection === 'block') parts.push('withholds results with likely prompt injection');
  return parts.join('; ');
}

/** What a Filter responses policy does to results before the agent gets them. */
export function ResponseFilterEditor({ value, onChange, error }: { value: FilterDraft; onChange: (v: FilterDraft) => void; error?: string }) {
  const set = (patch: Partial<FilterDraft>) => onChange({ ...value, ...patch });
  return (
    <section className="space-y-4 rounded-lg border border-violet-200 bg-violet-50/30 p-4">
      <div>
        <h3 className="text-sm font-semibold text-slate-900">Response filter</h3>
        <p className="text-xs text-slate-500">Applied by your webhook before results leave your side, so masked values never reach Token Vault or the agent. The access log records what was filtered, never the values.</p>
      </div>
      {error && <p className="text-sm text-red-600">{error}</p>}

      <div>
        <p className="mb-2 text-xs font-semibold uppercase tracking-wide text-slate-500">Mask</p>
        <div className="grid gap-2 sm:grid-cols-2">
          {DATA_DETECTORS.map((d) => (
            <div key={d.id} className="rounded-md border border-slate-200 bg-white p-2.5">
              <Checkbox id={`mask-${d.id}`} checked={value.mask.includes(d.id)} onChange={(on) => set({ mask: on ? [...value.mask, d.id] : value.mask.filter((x) => x !== d.id) })} label={d.label} description={<span className="font-mono">{d.example}</span>} />
            </div>
          ))}
        </div>
      </div>

      <div className="space-y-2">
        <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">Custom patterns (optional)</p>
        {value.patterns.map((p, i) => (
          <div key={i} className="grid gap-2 sm:grid-cols-[12rem_1fr_auto]">
            <Input aria-label={`Pattern ${i + 1} name`} className="font-mono text-xs" value={p.name} placeholder="employee_id" onChange={(e) => set({ patterns: value.patterns.map((x, j) => (j === i ? { ...x, name: e.target.value } : x)) })} />
            <Input aria-label={`Pattern ${i + 1} expression`} className="font-mono text-xs" value={p.pattern} placeholder="EMP-\d{3,}" onChange={(e) => set({ patterns: value.patterns.map((x, j) => (j === i ? { ...x, pattern: e.target.value } : x)) })} />
            <Button size="icon" variant="ghost" aria-label={`Remove pattern ${i + 1}`} onClick={() => set({ patterns: value.patterns.filter((_, j) => j !== i) })}>
              <Trash2 className="h-4 w-4" />
            </Button>
          </div>
        ))}
        {value.patterns.length < 10 && (
          <Button size="sm" variant="outline" onClick={() => set({ patterns: [...value.patterns, { name: '', pattern: '' }] })}>
            <Plus className="h-4 w-4" /> Add pattern
          </Button>
        )}
      </div>

      <Field label="Remove fields (optional)" htmlFor="rf-remove" hint="Comma separated: a field name removes it everywhere (email); a path ending removes it only there (author.email).">
        <Input id="rf-remove" className="font-mono text-xs" value={value.removeFields} onChange={(e) => set({ removeFields: e.target.value })} placeholder="author.email, billing" />
      </Field>

      <div>
        <p className="mb-2 text-xs font-semibold uppercase tracking-wide text-slate-500">Prompt injection</p>
        <div role="radiogroup" aria-label="Prompt injection" className="grid gap-2 sm:grid-cols-3">
          {INJECTION_MODES.map((m) => (
            <button
              key={m.id}
              type="button"
              role="radio"
              aria-checked={value.promptInjection === m.id}
              onClick={() => set({ promptInjection: m.id })}
              className={cn('rounded-md border bg-white p-2.5 text-left', value.promptInjection === m.id ? 'border-violet-500 ring-1 ring-violet-500' : 'border-slate-200 hover:border-slate-300')}
            >
              <span className="block text-sm font-medium text-slate-900">{m.label}</span>
              <span className="block text-xs text-slate-500">{m.hint}</span>
            </button>
          ))}
        </div>
        <p className="mt-1.5 text-xs text-slate-500">Looks for text in results that tries to instruct the model, such as "ignore previous instructions", chat markup, or "send this to https://…". It is a heuristic: it catches common attacks, not all.</p>
      </div>
    </section>
  );
}
