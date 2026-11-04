import { useState } from 'react';
import { FlaskConical, ShieldCheck, ShieldX } from 'lucide-react';
import { PERMISSIONS, type IntegrityReport } from '@token-vault/shared';
import { useAuth } from '@/context/AuthContext';
import { api } from '@/lib/api';
import { Button } from '@/components/ui/button';
import { Card, CardBody, CardHeader } from '@/components/ui/card';
import { ConfirmDialog } from '@/components/ui/dialog';
import { useToast } from '@/components/ui/toast';
import { cn, formatTime } from '@/lib/utils';

const TABLE_LABEL = { audit_events: 'Security events', access_requests: 'Access log' } as const;
const KIND_LABEL = { hash_mismatch: 'Modified', mac_invalid: 'Forged / bad signature', broken_link: 'Broken link', sequence_gap: 'Missing records' } as const;

/**
 * Verifies the tamper-evident audit chains: every record is hash-linked to the previous
 * one and signed with a key held outside the database.
 */
export function IntegrityPanel({ onChanged }: { onChanged?: () => void }) {
  const { can } = useAuth();
  const toast = useToast();
  const [report, setReport] = useState<IntegrityReport | null>(null);
  const [busy, setBusy] = useState(false);
  const [tamperOpen, setTamperOpen] = useState(false);

  async function verify() {
    setBusy(true);
    try {
      setReport(await api.get<IntegrityReport>('/audit-integrity'));
    } catch (e) {
      toast.error('Verification failed', (e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  async function tamper() {
    setBusy(true);
    try {
      const r = await api.post<{ seq: number }>('/demo/tamper-audit');
      toast.info('Audit record edited directly in the database', `Record #${r.seq} was changed with the append-only trigger switched off. Verify to see it detected.`);
      setTamperOpen(false);
      setReport(null);
      onChanged?.();
    } catch (e) {
      toast.error('Could not simulate tampering', (e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <Card>
      <CardHeader
        title="Audit integrity"
        description="Each record is hash-linked to the previous one and signed with a key held outside the database. Editing, deleting or forging a record breaks verification."
        icon={<ShieldCheck className="h-4 w-4" />}
        actions={
          <>
            {can(PERMISSIONS.DEMO_RESET) && (
              <Button variant="ghost" size="sm" onClick={() => setTamperOpen(true)} title="Demo control">
                <FlaskConical className="h-3.5 w-3.5" /> Simulate tampering
              </Button>
            )}
            <Button size="sm" loading={busy && !tamperOpen} onClick={verify}>
              Verify integrity
            </Button>
          </>
        }
      />
      {report && (
        <CardBody className="space-y-3">
          <div className={cn('flex items-center gap-2 rounded-lg border p-3 text-sm font-medium', report.ok ? 'border-emerald-200 bg-emerald-50 text-emerald-800' : 'border-red-200 bg-red-50 text-red-800')}>
            {report.ok ? <ShieldCheck className="h-5 w-5" /> : <ShieldX className="h-5 w-5" />}
            {report.ok ? 'Chain intact: no records were modified, removed or forged.' : 'Tampering detected: the audit history no longer matches what Token Vault wrote.'}
            <span className="ml-auto text-xs font-normal opacity-70">verified {formatTime(report.verifiedAt)}</span>
          </div>
          <div className="grid gap-3 md:grid-cols-2">
            {report.chains.map((c) => (
              <div key={c.table} className="rounded-lg border border-slate-200 p-3 text-sm">
                <p className="flex items-center justify-between font-medium text-slate-800">
                  {TABLE_LABEL[c.table]}
                  <span className={c.ok ? 'text-emerald-700' : 'text-red-700'}>{c.ok ? 'OK' : `${c.problems.length} problem${c.problems.length > 1 ? 's' : ''}`}</span>
                </p>
                <p className="mt-1 text-xs text-slate-500">
                  {c.chainedRecords} records verified{c.legacyRecords ? ` · ${c.legacyRecords} older records predate the chain` : ''}
                </p>
                {c.headSeq !== null && <p className="mt-1 font-mono text-[11px] text-slate-500">head #{c.headSeq} · {c.headHash?.slice(0, 16)}…</p>}
                {c.problems.length > 0 && (
                  <ul className="mt-2 space-y-1">
                    {c.problems.map((p) => (
                      <li key={`${p.kind}-${p.id}`} className="rounded bg-red-50 px-2 py-1 text-xs text-red-800">
                        <span className="font-semibold">{KIND_LABEL[p.kind]}</span> · {p.detail}
                        <span className="block font-mono text-[10px] opacity-70">{p.id}</span>
                      </li>
                    ))}
                  </ul>
                )}
              </div>
            ))}
          </div>
          <p className="text-xs text-slate-500">Limit: removing the newest records can only be detected against a copy of the chain head kept outside the database, so record the head periodically.</p>
        </CardBody>
      )}
      <ConfirmDialog
        open={tamperOpen}
        onClose={() => setTamperOpen(false)}
        title="Simulate database tampering?"
        description="Demo control: edits the newest security event directly in the database, switching off the append-only trigger the way someone with database access could. The edit cannot be undone except by resetting the demo data."
        confirmLabel="Edit a record in the database"
        loading={busy}
        onConfirm={tamper}
      />
    </Card>
  );
}
