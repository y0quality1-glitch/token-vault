import type { ReactNode } from 'react';
import { AlertTriangle, Info, Loader2, Lock, RefreshCw, ShieldAlert, XCircle } from 'lucide-react';
import { cn } from '@/lib/utils';
import type { ApiError } from '@/lib/api';
import { Button } from './button';

export function Skeleton({ className }: { className?: string }) {
  return <div className={cn('animate-pulse rounded bg-slate-200/80', className)} />;
}

export function Spinner({ className, label }: { className?: string; label?: string }) {
  return (
    <div className={cn('flex items-center justify-center gap-2 py-10 text-sm text-slate-500', className)}>
      <Loader2 className="h-5 w-5 animate-spin" /> {label ?? 'Loading…'}
    </div>
  );
}

export function PageSkeleton() {
  return (
    <div className="space-y-4">
      <Skeleton className="h-8 w-64" />
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        {Array.from({ length: 4 }).map((_, i) => (
          <Skeleton key={i} className="h-24" />
        ))}
      </div>
      <Skeleton className="h-64" />
    </div>
  );
}

export function EmptyState({ icon, title, description, action, className }: { icon?: ReactNode; title: string; description?: ReactNode; action?: ReactNode; className?: string }) {
  return (
    <div className={cn('flex flex-col items-center justify-center px-6 py-12 text-center', className)}>
      {icon && <div className="mb-3 flex h-12 w-12 items-center justify-center rounded-full bg-slate-100 text-slate-400">{icon}</div>}
      <h3 className="text-sm font-semibold text-slate-900">{title}</h3>
      {description && <p className="mt-1 max-w-md text-sm text-slate-500">{description}</p>}
      {action && <div className="mt-4">{action}</div>}
    </div>
  );
}

export function ErrorState({ error, onRetry }: { error: ApiError | Error; onRetry?: () => void }) {
  if ('status' in error && error.status === 403) return <PermissionDenied message={error.message} />;
  return (
    <div className="flex flex-col items-center justify-center rounded-xl border border-red-200 bg-red-50/50 px-6 py-10 text-center">
      <XCircle className="h-8 w-8 text-red-500" />
      <h3 className="mt-2 text-sm font-semibold text-slate-900">Something went wrong</h3>
      <p className="mt-1 max-w-md text-sm text-slate-600">{error.message}</p>
      {onRetry && (
        <Button variant="outline" size="sm" className="mt-4" onClick={onRetry}>
          <RefreshCw className="h-3.5 w-3.5" /> Retry
        </Button>
      )}
    </div>
  );
}

export function PermissionDenied({ message, required }: { message?: string; required?: string }) {
  return (
    <div className="flex flex-col items-center justify-center rounded-xl border border-slate-200 bg-white px-6 py-14 text-center shadow-card">
      <div className="flex h-12 w-12 items-center justify-center rounded-full bg-amber-50 text-amber-600">
        <Lock className="h-6 w-6" />
      </div>
      <h3 className="mt-3 text-sm font-semibold text-slate-900">Permission denied</h3>
      <p className="mt-1 max-w-md text-sm text-slate-500">{message ?? 'Your role does not include access to this area. Ask an Organization Owner to change your role.'}</p>
      {required && <p className="mt-2 font-mono text-xs text-slate-400">requires {required}</p>}
    </div>
  );
}

type CalloutTone = 'info' | 'warning' | 'danger' | 'security';
const CALLOUT: Record<CalloutTone, { cls: string; icon: ReactNode }> = {
  info: { cls: 'border-brand-200 bg-brand-50/60 text-brand-900', icon: <Info className="h-4 w-4 text-brand-600" /> },
  warning: { cls: 'border-amber-200 bg-amber-50 text-amber-900', icon: <AlertTriangle className="h-4 w-4 text-amber-600" /> },
  danger: { cls: 'border-red-200 bg-red-50 text-red-900', icon: <XCircle className="h-4 w-4 text-red-600" /> },
  security: { cls: 'border-slate-200 bg-slate-50 text-slate-800', icon: <ShieldAlert className="h-4 w-4 text-slate-600" /> },
};

/** Contextual help block used on security-sensitive screens. */
export function Callout({ tone = 'info', title, children, className, action }: { tone?: CalloutTone; title?: ReactNode; children?: ReactNode; className?: string; action?: ReactNode }) {
  const c = CALLOUT[tone];
  return (
    <div className={cn('flex gap-3 rounded-lg border p-3.5 text-sm', c.cls, className)}>
      <div className="mt-0.5 shrink-0">{c.icon}</div>
      <div className="min-w-0 flex-1">
        {title && <p className="font-medium">{title}</p>}
        {children && <div className={cn('text-[13px] leading-relaxed opacity-90', title && 'mt-0.5')}>{children}</div>}
      </div>
      {action && <div className="shrink-0 self-center">{action}</div>}
    </div>
  );
}

export function FormError({ error }: { error: ApiError | null }) {
  if (!error) return null;
  const hasFields = Object.keys(error.fieldErrors).length > 0;
  return (
    <Callout tone="danger" title={hasFields ? 'Please correct the highlighted fields' : error.status === 403 ? 'Permission denied' : 'Request failed'}>
      {hasFields ? null : error.message}
    </Callout>
  );
}
