import { ArrowRight, Bot, Building2, Cloud, Github, Lock, ShieldCheck } from 'lucide-react';
import { cn } from '@/lib/utils';

/**
 * Visualizes where credential material lives. Used on webhook, integration and
 * playground screens so the customer-controlled boundary is always explicit.
 */
export type FlowStage = 'agent' | 'control' | 'policy' | 'webhook' | 'provider';
export type StageState = 'idle' | 'ok' | 'fail' | 'skipped';

export function TrustBoundary({ states, compact }: { states?: Partial<Record<FlowStage, StageState>>; compact?: boolean }) {
  const s = (k: FlowStage): StageState => states?.[k] ?? 'idle';
  return (
    <div className={cn('grid items-stretch gap-3', compact ? 'grid-cols-1 lg:grid-cols-[1fr_auto_1.6fr_auto_1.6fr]' : 'grid-cols-1 lg:grid-cols-[1fr_auto_1.6fr_auto_1.6fr]')}>
      <Zone label="Agent / workload" tone="slate">
        <Node icon={<Bot className="h-4 w-4" />} title="AI agent" sub="Holds only its own Token Vault API key" state={s('agent')} />
      </Zone>
      <Arrow />
      <Zone label="Token Vault control plane" tone="brand" note="Metadata, grants, policies, audit. No provider secrets.">
        <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
          <Node icon={<Cloud className="h-4 w-4" />} title="Authenticate & broker" sub="Signs short-lived execution request" state={s('control')} />
          <Node icon={<ShieldCheck className="h-4 w-4" />} title="Policy / grant engine" sub="Deny by default" state={s('policy')} />
        </div>
      </Zone>
      <Arrow />
      <Zone label="Customer environment" tone="emerald" note="Credential decrypted only here, injected upstream." lock>
        <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
          <Node icon={<Building2 className="h-4 w-4" />} title="Webhook / vault agent" sub="AES-256-GCM encrypted store" state={s('webhook')} />
          <Node icon={<Github className="h-4 w-4" />} title="GitHub API" sub="Receives injected token" state={s('provider')} />
        </div>
      </Zone>
    </div>
  );
}

function Zone({ label, tone, note, children, lock }: { label: string; tone: 'slate' | 'brand' | 'emerald'; note?: string; children: React.ReactNode; lock?: boolean }) {
  const cls = { slate: 'border-slate-200 bg-slate-50/70', brand: 'border-brand-200 bg-brand-50/40', emerald: 'border-emerald-300 border-dashed bg-emerald-50/40' }[tone];
  return (
    <div className={cn('rounded-xl border p-3', cls)}>
      <p className="mb-2 flex items-center gap-1.5 text-[11px] font-semibold uppercase tracking-wide text-slate-500">
        {lock && <Lock className="h-3 w-3 text-emerald-600" />}
        {label}
      </p>
      {children}
      {note && <p className="mt-2 text-[11px] leading-snug text-slate-500">{note}</p>}
    </div>
  );
}

function Node({ icon, title, sub, state }: { icon: React.ReactNode; title: string; sub: string; state: StageState }) {
  const cls = {
    idle: 'border-slate-200 bg-white',
    ok: 'border-emerald-400 bg-emerald-50 ring-1 ring-emerald-400/40',
    fail: 'border-red-400 bg-red-50 ring-1 ring-red-400/40',
    skipped: 'border-slate-200 bg-slate-50 opacity-50',
  }[state];
  const iconCls = { idle: 'text-slate-500', ok: 'text-emerald-600', fail: 'text-red-600', skipped: 'text-slate-400' }[state];
  return (
    <div className={cn('flex items-start gap-2 rounded-lg border p-2.5 transition', cls)}>
      <span className={cn('mt-0.5', iconCls)}>{icon}</span>
      <span className="min-w-0">
        <span className="block text-xs font-semibold text-slate-800">{title}</span>
        <span className="block text-[11px] leading-snug text-slate-500">{sub}</span>
      </span>
    </div>
  );
}

function Arrow() {
  return (
    <div className="flex items-center justify-center text-slate-300">
      <ArrowRight className="hidden h-5 w-5 lg:block" />
      <ArrowRight className="h-5 w-5 rotate-90 lg:hidden" />
    </div>
  );
}
