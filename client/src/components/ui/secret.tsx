import { useEffect, useState } from 'react';
import { AlertTriangle, Check, Copy, KeyRound } from 'lucide-react';
import { cn } from '@/lib/utils';
import { Button } from './button';
import { Checkbox } from './form';
import { Dialog } from './dialog';

export function CopyButton({ value, label = 'Copy', className, onCopied }: { value: string; label?: string; className?: string; onCopied?: () => void }) {
  const [copied, setCopied] = useState(false);
  return (
    <Button
      variant="outline"
      size="sm"
      className={className}
      onClick={async () => {
        try {
          await navigator.clipboard.writeText(value);
        } catch {
          /* clipboard may be unavailable (non-secure context); the value is still selectable */
        }
        setCopied(true);
        onCopied?.();
        setTimeout(() => setCopied(false), 1800);
      }}
    >
      {copied ? <Check className="h-3.5 w-3.5 text-emerald-600" /> : <Copy className="h-3.5 w-3.5" />}
      {copied ? 'Copied' : label}
    </Button>
  );
}

/** Non-secret identifiers (references, IDs) rendered in monospace with a copy affordance. */
export function Mono({ children, className }: { children: string; className?: string }) {
  return <code className={cn('rounded bg-slate-100 px-1.5 py-0.5 font-mono text-[12px] text-slate-700', className)}>{children}</code>;
}

export function JsonView({ value, className }: { value: unknown; className?: string }) {
  return <pre className={cn('max-h-80 overflow-auto rounded-lg bg-slate-950 p-4 font-mono text-[12px] leading-relaxed text-slate-100', className)}>{JSON.stringify(value, null, 2)}</pre>;
}

/**
 * Displays a newly issued secret exactly once. After the dialog closes the value is
 * discarded from component state and cannot be retrieved again (only a hash is stored server-side).
 */
export function SecretOnceDialog({
  open,
  title,
  description,
  secret,
  onDone,
  extraAction,
}: {
  open: boolean;
  title: string;
  description: string;
  secret: string;
  onDone: () => void;
  extraAction?: { label: string; onClick: () => void };
}) {
  const [ack, setAck] = useState(false);
  const [revealed, setRevealed] = useState(true);
  useEffect(() => {
    if (open) {
      setAck(false);
      setRevealed(true);
    }
  }, [open]);
  return (
    <Dialog
      open={open}
      onClose={onDone}
      dismissible={false}
      title={
        <span className="flex items-center gap-2">
          <KeyRound className="h-5 w-5 text-brand-600" /> {title}
        </span>
      }
      description={description}
      footer={
        <>
          {extraAction && (
            <Button variant="outline" disabled={!ack} onClick={extraAction.onClick}>
              {extraAction.label}
            </Button>
          )}
          <Button disabled={!ack} onClick={onDone}>
            Done
          </Button>
        </>
      }
    >
      <div className="space-y-4">
        <div className="flex items-start gap-3 rounded-lg border border-amber-200 bg-amber-50 p-3 text-sm text-amber-900">
          <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-amber-600" />
          <span>
            <strong>This secret will not be shown again.</strong> Token Vault stores only a scrypt hash of it. Copy it into the agent's secret manager now. If it is lost, rotate the credential.
          </span>
        </div>
        <div className="rounded-lg border border-slate-200 bg-slate-50 p-3">
          <div className="flex items-center justify-between gap-2">
            <span className="text-xs font-medium uppercase tracking-wide text-slate-500">Agent API credential</span>
            <div className="flex gap-2">
              <Button variant="ghost" size="sm" onClick={() => setRevealed((r) => !r)}>
                {revealed ? 'Hide' : 'Reveal'}
              </Button>
              <CopyButton value={secret} />
            </div>
          </div>
          <code className="mt-2 block break-all font-mono text-[13px] text-slate-900">{revealed ? secret : secret.slice(0, 18) + '•'.repeat(24)}</code>
        </div>
        <Checkbox checked={ack} onChange={setAck} label="I have copied and securely stored this credential" />
      </div>
    </Dialog>
  );
}
