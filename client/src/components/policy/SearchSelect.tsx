import { useMemo, useState, type ReactNode } from 'react';
import { Search, X } from 'lucide-react';
import { cn } from '@/lib/utils';

export interface SearchOption {
  value: string;
  label: string;
  /** Secondary text (owner team, application, …), also searched. */
  hint?: string;
  /** Shown as a small tag, e.g. "Connected". */
  tag?: ReactNode;
}

const SHOWN = 50;

/**
 * Pick one item from a list that may hold hundreds: type to filter. The list is rendered
 * inline (not as a popover), so it is never clipped inside a scrolling dialog.
 */
export function SearchSelect({
  label,
  placeholder,
  options,
  value,
  onChange,
  emptyText = 'Nothing matches',
}: {
  label: string;
  placeholder: string;
  options: SearchOption[];
  value: string;
  onChange: (value: string) => void;
  emptyText?: string;
}) {
  const [query, setQuery] = useState('');
  const selected = options.find((o) => o.value === value);
  const matches = useMemo(() => {
    const q = query.trim().toLowerCase();
    return q ? options.filter((o) => `${o.label} ${o.hint ?? ''} ${o.value}`.toLowerCase().includes(q)) : options;
  }, [options, query]);

  if (selected) {
    return (
      <div className="flex items-center justify-between gap-2 rounded-md border border-brand-200 bg-brand-50/50 px-3 py-2 text-sm">
        <span className="min-w-0">
          <span className="block truncate font-medium text-slate-900">{selected.label}</span>
          {selected.hint && <span className="block truncate text-xs text-slate-500">{selected.hint}</span>}
        </span>
        <button type="button" onClick={() => onChange('')} className="shrink-0 rounded p-1 text-slate-400 hover:bg-white hover:text-slate-600" aria-label={`Clear ${label}`}>
          <X className="h-4 w-4" />
        </button>
      </div>
    );
  }

  return (
    <div className="rounded-md border border-slate-300 focus-within:border-brand-500 focus-within:ring-1 focus-within:ring-brand-500">
      <div className="flex items-center gap-2 border-b border-slate-100 px-3">
        <Search className="h-4 w-4 shrink-0 text-slate-400" />
        <input aria-label={label} className="w-full border-0 bg-transparent py-2 text-sm outline-none placeholder:text-slate-400 focus:ring-0" placeholder={placeholder} value={query} onChange={(e) => setQuery(e.target.value)} />
      </div>
      <div role="listbox" aria-label={`${label}: results`} className="max-h-48 overflow-y-auto py-1">
        {matches.slice(0, SHOWN).map((o) => (
          <button
            key={o.value}
            type="button"
            role="option"
            aria-selected={false}
            onClick={() => {
              onChange(o.value);
              setQuery('');
            }}
            className={cn('flex w-full items-center justify-between gap-3 px-3 py-1.5 text-left text-sm hover:bg-slate-50')}
          >
            <span className="min-w-0">
              <span className="block truncate text-slate-800">{o.label}</span>
              {o.hint && <span className="block truncate text-xs text-slate-500">{o.hint}</span>}
            </span>
            {o.tag}
          </button>
        ))}
        {matches.length === 0 && <p className="px-3 py-2 text-sm text-slate-500">{emptyText}</p>}
        {matches.length > SHOWN && <p className="px-3 py-2 text-xs text-slate-500">{matches.length - SHOWN} more: keep typing to narrow the list.</p>}
      </div>
    </div>
  );
}
