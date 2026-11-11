import { useEffect, useState, type ReactNode } from 'react';
import { createPortal } from 'react-dom';
import { AlertTriangle, X } from 'lucide-react';
import { cn } from '@/lib/utils';
import { Button } from './button';
import { Input } from './form';

export function Dialog({ open, onClose, title, description, children, footer, size = 'md', dismissible = true }: { open: boolean; onClose: () => void; title: ReactNode; description?: ReactNode; children?: ReactNode; footer?: ReactNode; size?: 'sm' | 'md' | 'lg' | 'xl'; dismissible?: boolean }) {
  useEffect(() => {
    if (!open || !dismissible) return;
    const onKey = (e: KeyboardEvent) => e.key === 'Escape' && onClose();
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [open, onClose, dismissible]);
  if (!open) return null;
  const width = { sm: 'max-w-md', md: 'max-w-lg', lg: 'max-w-2xl', xl: 'max-w-4xl' }[size];
  return createPortal(
    // The dialog never grows past the window: title and buttons stay in view, only the body scrolls.
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      <div className="fixed inset-0 animate-fade-in bg-slate-900/40" onClick={dismissible ? onClose : undefined} />
      <div role="dialog" aria-modal="true" className={cn('relative flex max-h-[calc(100dvh-2rem)] w-full animate-slide-in flex-col rounded-xl bg-white shadow-2xl', width)}>
        <div className="flex shrink-0 items-start justify-between gap-4 border-b border-slate-100 px-6 py-4">
          <div>
            <h2 className="text-base font-semibold text-slate-900">{title}</h2>
            {description && <p className="mt-1 text-sm text-slate-500">{description}</p>}
          </div>
          {dismissible && (
            <button onClick={onClose} className="rounded p-1 text-slate-400 hover:bg-slate-100 hover:text-slate-600" aria-label="Close dialog">
              <X className="h-4 w-4" />
            </button>
          )}
        </div>
        {children && <div className="min-h-0 flex-1 overflow-y-auto overscroll-contain px-6 py-5">{children}</div>}
        {footer && <div className="flex shrink-0 flex-wrap justify-end gap-2 rounded-b-xl border-t border-slate-100 bg-slate-50/60 px-6 py-3.5">{footer}</div>}
      </div>
    </div>,
    document.body,
  );
}

/** Confirmation dialog for revoke / disable / delete. Optionally requires typing a confirmation phrase. */
export function ConfirmDialog({
  open,
  onClose,
  onConfirm,
  title,
  description,
  confirmLabel = 'Confirm',
  tone = 'danger',
  loading,
  confirmText,
  children,
}: {
  open: boolean;
  onClose: () => void;
  onConfirm: () => void;
  title: string;
  description: ReactNode;
  confirmLabel?: string;
  tone?: 'danger' | 'primary';
  loading?: boolean;
  confirmText?: string;
  children?: ReactNode;
}) {
  const [typed, setTyped] = useState('');
  useEffect(() => {
    if (!open) setTyped('');
  }, [open]);
  const blocked = !!confirmText && typed !== confirmText;
  return (
    <Dialog
      open={open}
      onClose={onClose}
      size="sm"
      title={
        <span className="flex items-center gap-2">
          {tone === 'danger' && <AlertTriangle className="h-5 w-5 text-red-600" />}
          {title}
        </span>
      }
      footer={
        <>
          <Button variant="outline" onClick={onClose} disabled={loading}>
            Cancel
          </Button>
          <Button variant={tone === 'danger' ? 'danger' : 'primary'} onClick={onConfirm} loading={loading} disabled={blocked}>
            {confirmLabel}
          </Button>
        </>
      }
    >
      <div className="space-y-4 text-sm text-slate-600">
        <div>{description}</div>
        {children}
        {confirmText && (
          <div className="space-y-1.5">
            <label className="block text-xs font-medium text-slate-600">
              Type <span className="font-mono font-semibold text-slate-900">{confirmText}</span> to confirm
            </label>
            <Input value={typed} onChange={(e) => setTyped(e.target.value)} autoFocus />
          </div>
        )}
      </div>
    </Dialog>
  );
}

export function Drawer({ open, onClose, title, subtitle, children }: { open: boolean; onClose: () => void; title: ReactNode; subtitle?: ReactNode; children: ReactNode }) {
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => e.key === 'Escape' && onClose();
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [open, onClose]);
  if (!open) return null;
  return createPortal(
    <div className="fixed inset-0 z-50">
      <div className="absolute inset-0 animate-fade-in bg-slate-900/30" onClick={onClose} />
      <aside className="absolute inset-y-0 right-0 flex w-full max-w-xl animate-drawer-in flex-col bg-white shadow-2xl">
        <div className="flex items-start justify-between gap-4 border-b border-slate-200 px-6 py-4">
          <div className="min-w-0">
            <h2 className="truncate text-base font-semibold text-slate-900">{title}</h2>
            {subtitle && <p className="mt-0.5 truncate text-sm text-slate-500">{subtitle}</p>}
          </div>
          <button onClick={onClose} className="rounded p-1 text-slate-400 hover:bg-slate-100" aria-label="Close panel">
            <X className="h-4 w-4" />
          </button>
        </div>
        <div className="flex-1 overflow-y-auto px-6 py-5">{children}</div>
      </aside>
    </div>,
    document.body,
  );
}
