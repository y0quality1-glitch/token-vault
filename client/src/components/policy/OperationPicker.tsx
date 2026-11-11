import { useState } from 'react';
import { ChevronDown, ChevronRight, Search, X } from 'lucide-react';
import { OPERATION_RISKS, describeOperationSelector, type OperationDef } from '@token-vault/shared';
import { getProvider, operationLabel } from '@/lib/providers';
import { Checkbox } from '@/components/ui/form';

export const selectorLabel = (s: string) => describeOperationSelector(s, { operation: operationLabel, provider: (k) => getProvider(k)?.name ?? k });

const APPS_SHOWN = 25;

/**
 * What a policy covers. When the policy is limited to one application (`application`), only
 * that application's operations are offered and broad selections are tied to it ("All GitHub
 * writes"); otherwise broad selections span every application. Built for large catalogs:
 * search, a "selected only" view, and connected applications first.
 */
export function OperationPicker({
  value,
  onChange,
  application,
  providers,
  operations,
  connected,
}: {
  value: string[];
  onChange: (v: string[]) => void;
  /** The one application the policy applies to, or null for any application. */
  application: string | null;
  providers: { key: string; name: string }[];
  operations: OperationDef[];
  /** Applications with at least one integration in this organization. */
  connected: ReadonlySet<string>;
}) {
  const [query, setQuery] = useState('');
  const [selectedOnly, setSelectedOnly] = useState(false);
  const [showAll, setShowAll] = useState(false);
  const [open, setOpen] = useState<Record<string, boolean>>({});

  const has = (s: string) => value.includes(s);
  const toggle = (s: string, on: boolean) => onChange(on ? [...value, s] : value.filter((x) => x !== s));
  const everything = application ? has(`${application}.*`) : has('*');
  const covered = (o: OperationDef) => has('*') || has(`${o.provider}.*`) || has(`risk:${o.risk}`) || has(`${o.provider}:${o.risk}`) || has(o.id);
  const appName = (k: string) => providers.find((p) => p.key === k)?.name ?? k;

  // Broad selections: across applications, or within the one application.
  const broad = application
    ? [{ s: `${application}.*`, label: `All ${appName(application)} operations`, hint: 'Including ones added later' }, ...OPERATION_RISKS.map((r) => ({ s: `${application}:${r}`, label: `All ${appName(application)} ${r} operations`, hint: r === 'destructive' ? 'Delete, overwrite, …' : '' }))]
    : [{ s: '*', label: 'Any operation', hint: 'In every application' }, ...OPERATION_RISKS.map((r) => ({ s: `risk:${r}`, label: `All ${r} operations`, hint: r === 'destructive' ? 'Delete, overwrite, … in every application' : 'In every application' }))];

  // Which applications to list.
  const q = query.trim().toLowerCase();
  const all = providers.map((p) => ({ ...p, ops: operations.filter((o) => o.provider === p.key) })).filter((p) => p.ops.length > 0);
  const hasConnected = all.some((p) => connected.has(p.key));
  const inScope = application ? all.filter((p) => p.key === application) : all;
  const listed = inScope
    .filter((p) => application || showAll || q || !hasConnected || connected.has(p.key) || p.ops.some(covered))
    .map((p) => {
      const appMatch = !q || p.name.toLowerCase().includes(q) || p.key.includes(q);
      const ops = p.ops.filter((o) => (appMatch || `${o.label} ${o.id}`.toLowerCase().includes(q)) && (!selectedOnly || covered(o)));
      return { ...p, ops };
    })
    .filter((p) => p.ops.length > 0)
    .sort((a, b) => Number(connected.has(b.key)) - Number(connected.has(a.key)) || a.name.localeCompare(b.name));
  const hiddenCatalog = application || showAll || q || !hasConnected ? 0 : inScope.filter((p) => !connected.has(p.key) && !p.ops.some(covered)).length;

  return (
    <div className="space-y-3">
      {value.length > 0 && (
        <div className="flex flex-wrap gap-1.5" aria-label="Selected operations">
          {value.map((s) => (
            <span key={s} className={`inline-flex items-center gap-1 rounded-full py-0.5 pl-2.5 pr-1 text-xs font-medium ring-1 ring-inset ${s.includes('destructive') || operations.find((o) => o.id === s)?.destructive ? 'bg-red-50 text-red-700 ring-red-200' : 'bg-brand-50 text-brand-800 ring-brand-200'}`}>
              {selectorLabel(s)}
              <button type="button" onClick={() => toggle(s, false)} className="rounded-full p-0.5 hover:bg-white/70" aria-label={`Remove ${selectorLabel(s)}`}>
                <X className="h-3 w-3" />
              </button>
            </span>
          ))}
        </div>
      )}

      <div className="rounded-lg border border-slate-200 p-3">
        <p className="mb-2 text-xs font-semibold uppercase tracking-wide text-slate-500">Broad selections · also cover operations added later</p>
        <div className="grid gap-x-4 gap-y-2 sm:grid-cols-2">
          {broad.map((b, i) => (
            <Checkbox key={b.s} disabled={i > 0 && everything} checked={has(b.s) || (i > 0 && everything)} onChange={(v) => (i === 0 ? onChange(v ? [b.s] : []) : toggle(b.s, v))} label={b.label} description={b.hint || undefined} />
          ))}
        </div>
      </div>

      <div className="rounded-lg border border-slate-200">
        <div className="flex flex-wrap items-center gap-x-4 gap-y-2 border-b border-slate-200 px-3 py-2">
          <div className="flex min-w-[12rem] flex-1 items-center gap-2">
            <Search className="h-4 w-4 shrink-0 text-slate-400" />
            <input aria-label="Search operations" className="w-full border-0 bg-transparent p-0 text-sm outline-none placeholder:text-slate-400 focus:ring-0" placeholder={application ? `Search ${appName(application)} operations…` : 'Search applications and operations…'} value={query} onChange={(e) => setQuery(e.target.value)} />
          </div>
          <Checkbox checked={selectedOnly} onChange={setSelectedOnly} label={<span className="text-xs font-normal text-slate-600">Selected only</span>} />
        </div>

        <div className="divide-y divide-slate-200">
          {listed.slice(0, APPS_SHOWN).map((p) => {
            const appAll = has(`${p.key}.*`) || has('*');
            const total = all.find((x) => x.key === p.key)!.ops;
            const count = total.filter(covered).length;
            const isOpen = open[p.key] ?? (!!application || !!q || selectedOnly || total.some((o) => has(o.id)));
            const summary = appAll ? 'All selected' : count ? `${count} of ${total.length} selected` : `${total.length} operation${total.length === 1 ? '' : 's'}`;
            return (
              <div key={p.key}>
                <div className="flex items-center gap-3 px-3 py-2.5">
                  <button type="button" className="flex min-w-0 flex-1 items-center gap-2 text-left" onClick={() => setOpen((s) => ({ ...s, [p.key]: !isOpen }))} aria-expanded={isOpen} aria-label={`${isOpen ? 'Collapse' : 'Expand'} ${p.name} operations`}>
                    {isOpen ? <ChevronDown className="h-4 w-4 shrink-0 text-slate-400" /> : <ChevronRight className="h-4 w-4 shrink-0 text-slate-400" />}
                    <span className="truncate text-sm font-medium text-slate-800">{p.name}</span>
                    {connected.has(p.key) && <span className="shrink-0 rounded bg-emerald-50 px-1.5 py-px text-[11px] font-medium text-emerald-700 ring-1 ring-inset ring-emerald-200">Connected</span>}
                    <span className={count ? 'shrink-0 text-xs font-medium text-brand-700' : 'shrink-0 text-xs text-slate-500'}>{summary}</span>
                  </button>
                  {!application && (
                    <div className="shrink-0">
                      <Checkbox disabled={has('*')} checked={appAll} onChange={(v) => toggle(`${p.key}.*`, v)} label={<span className="text-xs font-normal text-slate-600">All {p.name}</span>} />
                    </div>
                  )}
                </div>
                {isOpen && (
                  <div className="grid gap-x-4 gap-y-2.5 bg-slate-50/60 px-3 pb-3 pl-9 pt-2.5 sm:grid-cols-2">
                    {p.ops.map((o) => {
                      const viaBroad = covered(o) && !has(o.id);
                      return (
                        <Checkbox
                          key={o.id}
                          disabled={viaBroad}
                          checked={covered(o)}
                          onChange={(v) => toggle(o.id, v)}
                          label={o.label}
                          description={
                            <>
                              <span className="block break-all font-mono">{o.id}</span>
                              {o.destructive && <span className="mt-1 block w-fit rounded bg-red-50 px-1.5 py-px text-[11px] font-medium text-red-700 ring-1 ring-inset ring-red-200">Destructive</span>}
                            </>
                          }
                        />
                      );
                    })}
                  </div>
                )}
              </div>
            );
          })}
          {listed.length === 0 && <p className="px-3 py-3 text-sm text-slate-500">{selectedOnly ? 'Nothing selected yet.' : 'No application or operation matches.'}</p>}
          {listed.length > APPS_SHOWN && <p className="px-3 py-2.5 text-xs text-slate-500">{listed.length - APPS_SHOWN} more applications: search to narrow the list.</p>}
          {hiddenCatalog > 0 && (
            <div className="px-3 py-2.5 text-xs text-slate-500">
              Showing applications connected in this organization.{' '}
              <button type="button" className="font-medium text-brand-700 hover:underline" onClick={() => setShowAll(true)}>
                Show all {inScope.length} catalog applications
              </button>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
