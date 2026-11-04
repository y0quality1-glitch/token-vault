import type { ReactNode } from 'react';
import { DECISION_LABELS } from '@token-vault/shared';
import { cn } from '@/lib/utils';

type Tone = 'green' | 'red' | 'amber' | 'blue' | 'gray' | 'violet';
const TONES: Record<Tone, string> = {
  green: 'bg-emerald-50 text-emerald-700 ring-emerald-600/20',
  red: 'bg-red-50 text-red-700 ring-red-600/20',
  amber: 'bg-amber-50 text-amber-800 ring-amber-600/25',
  blue: 'bg-brand-50 text-brand-700 ring-brand-600/20',
  gray: 'bg-slate-100 text-slate-600 ring-slate-500/20',
  violet: 'bg-violet-50 text-violet-700 ring-violet-600/20',
};
const DOTS: Record<Tone, string> = { green: 'bg-emerald-500', red: 'bg-red-500', amber: 'bg-amber-500', blue: 'bg-brand-500', gray: 'bg-slate-400', violet: 'bg-violet-500' };

export function Badge({ tone = 'gray', children, dot, className }: { tone?: Tone; children: ReactNode; dot?: boolean; className?: string }) {
  return (
    <span className={cn('inline-flex items-center gap-1.5 whitespace-nowrap rounded-full px-2 py-0.5 text-xs font-medium ring-1 ring-inset', TONES[tone], className)}>
      {dot && <span className={cn('h-1.5 w-1.5 rounded-full', DOTS[tone])} />}
      {children}
    </span>
  );
}

/** Canonical status labels: Connected, Disconnected, Healthy, Unhealthy, Active, Revoked, Expired, Denied, ... */
const STATUS: Record<string, { label: string; tone: Tone }> = {
  CONNECTED: { label: 'Connected', tone: 'green' },
  HEALTHY: { label: 'Healthy', tone: 'green' },
  ACTIVE: { label: 'Active', tone: 'green' },
  ALLOW: { label: 'Allowed', tone: 'green' },
  SUCCEEDED: { label: 'Succeeded', tone: 'green' },
  SUCCESS: { label: 'Success', tone: 'green' },
  PENDING: { label: 'Pending verification', tone: 'amber' },
  PENDING_APPROVAL: { label: 'Pending approval', tone: 'amber' },
  SCHEDULED: { label: 'Scheduled', tone: 'blue' },
  ROTATION_REQUIRED: { label: 'Rotation required', tone: 'amber' },
  UNHEALTHY: { label: 'Unhealthy', tone: 'red' },
  DISCONNECTED: { label: 'Disconnected', tone: 'red' },
  NOT_CONFIGURED: { label: 'Not configured', tone: 'gray' },
  INVALID: { label: 'Invalid', tone: 'red' },
  REVOKED: { label: 'Revoked', tone: 'red' },
  DENY: { label: 'Denied', tone: 'red' },
  DENIED: { label: 'Denied', tone: 'red' },
  FAILED: { label: 'Failed', tone: 'red' },
  FAILURE: { label: 'Failure', tone: 'red' },
  EXPIRED: { label: 'Expired', tone: 'gray' },
  DISABLED: { label: 'Disabled', tone: 'gray' },
  SUPERSEDED: { label: 'Superseded', tone: 'gray' },
  NOT_EXECUTED: { label: 'Not executed', tone: 'gray' },
};

export function StatusBadge({ status, className }: { status: string; className?: string }) {
  const s = STATUS[status] ?? { label: status, tone: 'gray' as Tone };
  return (
    <Badge tone={s.tone} dot className={className}>
      {s.label}
    </Badge>
  );
}

export function DecisionBadge({ decision, code }: { decision: 'ALLOW' | 'DENY'; code?: string }) {
  if (decision === 'ALLOW' && code && code !== 'ALLOWED') {
    return <Badge tone="amber" dot>Allowed · {DECISION_LABELS[code] ?? code}</Badge>;
  }
  return <StatusBadge status={decision} />;
}

export function EnvBadge({ env }: { env: string }) {
  const tone: Tone = env === 'production' ? 'red' : env === 'staging' ? 'amber' : 'blue';
  return <Badge tone={tone}>{env.charAt(0).toUpperCase() + env.slice(1)}</Badge>;
}

export function SimulatedBadge({ className }: { className?: string }) {
  return (
    <Badge tone="violet" className={className}>
      Simulated
    </Badge>
  );
}
