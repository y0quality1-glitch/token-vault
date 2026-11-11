import { useCallback, useEffect, useState } from 'react';
import { Link, useLocation } from 'react-router-dom';
import { OctagonX, Play } from 'lucide-react';
import { PERMISSIONS } from '@token-vault/shared';
import { useAuth } from '@/context/AuthContext';
import { useMutation } from '@/hooks/useApi';
import { api } from '@/lib/api';
import { Button } from '@/components/ui/button';
import { Card, CardBody, CardHeader } from '@/components/ui/card';
import { Field, Textarea } from '@/components/ui/form';
import { FormError } from '@/components/ui/feedback';
import { Dialog } from '@/components/ui/dialog';
import { useToast } from '@/components/ui/toast';
import { formatDateTime, relativeTime } from '@/lib/utils';

export interface EmergencyStopState {
  stopped: boolean;
  stoppedAt: string | null;
  stoppedBy: string | null;
  stoppedByName: string | null;
  reason: string | null;
}

const CHANGED = 'tv:emergency-stop-changed';

/** The organization's emergency stop, refreshed on navigation, every 15 s and after a change on this page. */
export function useEmergencyStop() {
  const { pathname } = useLocation();
  const [state, setState] = useState<EmergencyStopState | null>(null);
  const load = useCallback(() => api.get<EmergencyStopState>('/organizations/current/emergency-stop').then(setState).catch(() => undefined), []);
  useEffect(() => {
    void load();
    const t = setInterval(load, 15_000);
    window.addEventListener(CHANGED, load);
    return () => {
      clearInterval(t);
      window.removeEventListener(CHANGED, load);
    };
  }, [load, pathname]);
  return state;
}

/** Shown on every page while agent access is stopped. */
export function EmergencyStopBanner() {
  const s = useEmergencyStop();
  if (!s?.stopped) return null;
  return (
    <div role="alert" className="flex flex-wrap items-center gap-x-3 gap-y-1 bg-red-600 px-4 py-2.5 text-sm text-white sm:px-6 lg:px-8">
      <OctagonX className="h-4 w-4 shrink-0" />
      <span className="font-semibold">All agent access is stopped.</span>
      <span className="text-red-50">
        Since {s.stoppedAt ? relativeTime(s.stoppedAt) : 'now'}
        {s.stoppedByName ? ` by ${s.stoppedByName}` : ''}
        {s.reason ? `: “${s.reason}”` : ''}. Every agent request is denied with EMERGENCY_STOP.
      </span>
      <Link to="/" className="ml-auto font-medium underline underline-offset-2">
        Manage
      </Link>
    </div>
  );
}

/** Overview card: stop (or resume) all agent access in the organization. */
export function EmergencyStopCard() {
  const s = useEmergencyStop();
  const { can } = useAuth();
  const [open, setOpen] = useState(false);
  if (!s) return null;
  const mayStop = can(PERMISSIONS.GRANT_REVOKE);
  const mayResume = can(PERMISSIONS.GRANT_APPROVE);

  return (
    <Card className={s.stopped ? 'border-red-300 ring-1 ring-red-200' : undefined}>
      <CardHeader title="Emergency stop" description="One switch that denies every agent request in this organization. Grants, keys and credentials stay as they are, so resuming restores access exactly." />
      <CardBody className="space-y-3 text-sm">
        {s.stopped ? (
          <>
            <p className="font-medium text-red-700">
              Agent access has been stopped since {formatDateTime(s.stoppedAt!)}
              {s.stoppedByName ? ` by ${s.stoppedByName}` : ''}.
            </p>
            {s.reason && <p className="text-slate-700">Reason: “{s.reason}”</p>}
            {mayResume ? (
              <Button onClick={() => setOpen(true)}>
                <Play className="h-4 w-4" /> Resume agent access…
              </Button>
            ) : (
              <p className="text-slate-500">Only Owners and Security Administrators can resume agent access.</p>
            )}
          </>
        ) : (
          <>
            <p className="text-slate-600">
              For a narrower stop, disable one agent (Agents → agent → <em>Disable</em>) or one integration (Connected Integrations → integration → <em>Disable</em>).
            </p>
            {mayStop ? (
              <Button variant="danger" onClick={() => setOpen(true)}>
                <OctagonX className="h-4 w-4" /> Stop all agent access…
              </Button>
            ) : (
              <p className="text-slate-500">Owners, Vault Administrators and Security Administrators can stop agent access.</p>
            )}
          </>
        )}
      </CardBody>
      <StopDialog open={open} stopping={!s.stopped} onClose={() => setOpen(false)} />
    </Card>
  );
}

function StopDialog({ open, stopping, onClose }: { open: boolean; stopping: boolean; onClose: () => void }) {
  const toast = useToast();
  const [text, setText] = useState('');
  const save = useMutation((t: string) => (stopping ? api.post<EmergencyStopState>('/organizations/current/emergency-stop', { reason: t }) : api.post<EmergencyStopState>('/organizations/current/emergency-stop/lift', { note: t })));
  useEffect(() => {
    if (open) {
      setText('');
      save.setError(null);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open, stopping]);

  return (
    <Dialog
      open={open}
      onClose={onClose}
      size="sm"
      title={stopping ? 'Stop all agent access?' : 'Resume agent access?'}
      description={
        stopping
          ? 'Every agent request in this organization is denied from the next request on, until someone resumes access. This is recorded as a critical security event.'
          : 'Agents get the access their grants give them again, from the next request on.'
      }
      footer={
        <>
          <Button variant="outline" onClick={onClose}>
            Cancel
          </Button>
          <Button
            variant={stopping ? 'danger' : 'primary'}
            loading={save.pending}
            disabled={stopping && text.trim().length < 3}
            onClick={async () => {
              if (await save.run(text)) {
                toast.success(stopping ? 'All agent access stopped' : 'Agent access resumed');
                window.dispatchEvent(new Event(CHANGED));
                onClose();
              }
            }}
          >
            {stopping ? 'Stop all agent access' : 'Resume agent access'}
          </Button>
        </>
      }
    >
      <div className="space-y-3">
        <FormError error={save.error} />
        <Field label={stopping ? 'Reason (shown to agents and recorded in audit)' : 'Note (recorded in audit)'} required={stopping} error={save.fieldErrors.reason}>
          <Textarea rows={3} value={text} onChange={(e) => setText(e.target.value)} placeholder={stopping ? 'e.g. Investigating unexpected issue creation' : ''} />
        </Field>
      </div>
    </Dialog>
  );
}
