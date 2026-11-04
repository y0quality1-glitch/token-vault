import type { HTMLAttributes, ReactNode } from 'react';
import { cn } from '@/lib/utils';

export function Card({ className, ...props }: HTMLAttributes<HTMLDivElement>) {
  return <div className={cn('rounded-xl border border-slate-200 bg-white shadow-card', className)} {...props} />;
}

export function CardHeader({ title, description, actions, className, icon }: { title: ReactNode; description?: ReactNode; actions?: ReactNode; className?: string; icon?: ReactNode }) {
  return (
    <div className={cn('flex items-start justify-between gap-4 border-b border-slate-100 px-5 py-4', className)}>
      <div className="flex min-w-0 items-start gap-3">
        {icon && <div className="mt-0.5 text-slate-400">{icon}</div>}
        <div className="min-w-0">
          <h3 className="text-sm font-semibold text-slate-900">{title}</h3>
          {description && <p className="mt-0.5 text-sm text-slate-500">{description}</p>}
        </div>
      </div>
      {actions && <div className="flex shrink-0 items-center gap-2">{actions}</div>}
    </div>
  );
}

export function CardBody({ className, ...props }: HTMLAttributes<HTMLDivElement>) {
  return <div className={cn('px-5 py-4', className)} {...props} />;
}

/** Definition list for detail screens. */
export function DetailList({ items, columns = 2 }: { items: { label: string; value: ReactNode; mono?: boolean }[]; columns?: 1 | 2 | 3 }) {
  return (
    <dl className={cn('grid gap-x-6 gap-y-4', columns === 1 ? 'grid-cols-1' : columns === 2 ? 'grid-cols-1 sm:grid-cols-2' : 'grid-cols-1 sm:grid-cols-2 lg:grid-cols-3')}>
      {items.map((it) => (
        <div key={it.label} className="min-w-0">
          <dt className="text-xs font-medium uppercase tracking-wide text-slate-500">{it.label}</dt>
          <dd className={cn('mt-1 break-words text-sm text-slate-900', it.mono && 'font-mono text-[13px]')}>{it.value ?? '—'}</dd>
        </div>
      ))}
    </dl>
  );
}

export function StatCard({ label, value, icon, hint, tone = 'default', onClick }: { label: string; value: ReactNode; icon: ReactNode; hint?: ReactNode; tone?: 'default' | 'danger' | 'success' | 'warning'; onClick?: () => void }) {
  const toneCls = { default: 'bg-brand-50 text-brand-600', danger: 'bg-red-50 text-red-600', success: 'bg-emerald-50 text-emerald-600', warning: 'bg-amber-50 text-amber-600' }[tone];
  const Comp = onClick ? 'button' : 'div';
  return (
    <Comp onClick={onClick} className={cn('flex w-full items-start gap-3 rounded-xl border border-slate-200 bg-white p-4 text-left shadow-card', onClick && 'transition hover:border-brand-300 hover:shadow-md')}>
      <div className={cn('flex h-9 w-9 shrink-0 items-center justify-center rounded-lg', toneCls)}>{icon}</div>
      <div className="min-w-0">
        <p className="text-xs font-medium text-slate-500">{label}</p>
        <p className="mt-1 text-2xl font-semibold tracking-tight text-slate-900">{value}</p>
        {hint && <p className="mt-0.5 truncate text-xs text-slate-500">{hint}</p>}
      </div>
    </Comp>
  );
}
