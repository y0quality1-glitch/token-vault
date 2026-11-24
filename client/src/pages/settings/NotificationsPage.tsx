import { useMemo, useState, type ReactNode } from 'react';
import { Link } from 'react-router-dom';
import { AlertTriangle, Bell, KeyRound, Mail, MessageSquare, Pencil, Plus, RefreshCw, Send, Trash2, Webhook } from 'lucide-react';
import {
  SECRET_NOTIFICATION_EVENTS,
  SECRET_NOTIFICATION_EVENT_LABELS,
  SECRET_SCOPE_SLUG,
  type Environment,
  type NotificationChannelKind,
  type NotificationChannelView,
  type NotificationDeliveryStatus,
  type NotificationDeliveryView,
  type SecretNotificationEvent,
} from '@token-vault/shared';
import { useMutation, usePost } from '@/hooks/useApi';
import { api, type ApiError } from '@/lib/api';
import { ENV_LABELS, cn, formatDateTime, relativeTime, splitList } from '@/lib/utils';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardHeader } from '@/components/ui/card';
import { Checkbox, Field, Input, Select, Switch, Textarea } from '@/components/ui/form';
import { Callout, EmptyState, ErrorState } from '@/components/ui/feedback';
import { ConfirmDialog, Dialog } from '@/components/ui/dialog';
import { DataTable, FilterTabs } from '@/components/ui/table';
import { PageHeader } from '@/components/ui/navigation';
import { CopyButton } from '@/components/ui/secret';
import { useToast } from '@/components/ui/toast';

/**
 * Settings → Notifications (spec 4.9.18): where secret lifecycle events are sent (email, a signed
 * webhook or Slack), and the recent deliveries. Notifications never carry a secret value.
 */

const KIND_META: Record<NotificationChannelKind, { label: string; icon: ReactNode; description: string }> = {
  EMAIL: { label: 'Email', icon: <Mail className="h-4 w-4" />, description: 'Sent to a list of addresses. Needs SMTP on the control plane.' },
  WEBHOOK: { label: 'Webhook', icon: <Webhook className="h-4 w-4" />, description: 'A signed JSON POST to your URL.' },
  SLACK: { label: 'Slack', icon: <MessageSquare className="h-4 w-4" />, description: 'Posted through the Slack connection.' },
};

const DELIVERY_STATUS: Record<NotificationDeliveryStatus, { label: string; tone: 'green' | 'red' | 'amber' }> = {
  DELIVERED: { label: 'Delivered', tone: 'green' },
  FAILED: { label: 'Failed', tone: 'red' },
  PENDING: { label: 'Pending', tone: 'amber' },
};

function DeliveryStatusBadge({ status }: { status: NotificationDeliveryStatus }) {
  const m = DELIVERY_STATUS[status] ?? { label: status, tone: 'amber' as const };
  return (
    <Badge tone={m.tone} dot>
      {m.label}
    </Badge>
  );
}

function eventLabel(e: string): string {
  return e === 'notification.test' ? 'Test notification' : (SECRET_NOTIFICATION_EVENT_LABELS[e as SecretNotificationEvent] ?? e);
}

function scopeText(c: NotificationChannelView): string {
  const parts = [c.scope.project ? `project ${c.scope.project}` : null, c.scope.environment ? ENV_LABELS[c.scope.environment] : null].filter(Boolean);
  return parts.length ? parts.join(', ') : 'Every secret';
}

function targetText(c: NotificationChannelView): ReactNode {
  if (c.kind === 'EMAIL') return c.recipients.join(', ') || '—';
  if (c.kind === 'WEBHOOK')
    return (
      <>
        <span className="block break-all font-mono text-[13px]">{c.url}</span>
        {c.signingSecretHint && <span className="block text-xs text-slate-500">Signing secret {c.signingSecretHint}</span>}
      </>
    );
  return c.slackChannelId ? <span className="font-mono text-[13px]">{c.slackChannelId}</span> : 'The Slack connection’s channel';
}

/** The fields an update must carry again (the server replaces name, events, enabled and scope). */
function updateBody(c: NotificationChannelView) {
  return {
    id: c.id,
    name: c.name,
    enabled: c.enabled,
    events: c.events,
    scope: c.scope,
    ...(c.kind === 'SLACK' ? { slackChannelId: c.slackChannelId } : {}),
  };
}

type ChannelSaveResult = NotificationChannelView & { signingSecret?: string };

export function NotificationsPage() {
  const toast = useToast();
  const channels = usePost<{ items: NotificationChannelView[] }>('/notificationChannel/getall');
  const [deliveryFilter, setDeliveryFilter] = useState<NotificationDeliveryStatus | 'all'>('all');
  const deliveries = usePost<{ items: NotificationDeliveryView[] }>('/notificationChannel/getDeliveries');
  const [editing, setEditing] = useState<NotificationChannelView | 'new' | null>(null);
  const [removing, setRemoving] = useState<NotificationChannelView | null>(null);
  const [renewing, setRenewing] = useState<NotificationChannelView | null>(null);
  const [revealed, setRevealed] = useState<{ channel: string; secret: string } | null>(null);
  const [testResult, setTestResult] = useState<NotificationDeliveryView | null>(null);
  const [testing, setTesting] = useState<string | null>(null);
  const [toggling, setToggling] = useState<string | null>(null);
  const [retrying, setRetrying] = useState<string | null>(null);
  const remove = useMutation(async (id: string) => {
    await api.del<unknown>(`/notificationChannel/delete/${id}`);
    return true;
  });
  const renew = useMutation((c: NotificationChannelView) => api.post<ChannelSaveResult>('/notificationChannel/save', { ...updateBody(c), rotateSigningSecret: true }));

  const reloadAll = async () => {
    await Promise.all([channels.reload(), deliveries.reload()]);
  };

  async function toggle(c: NotificationChannelView, enabled: boolean) {
    setToggling(c.id);
    try {
      await api.post<ChannelSaveResult>('/notificationChannel/save', { ...updateBody(c), enabled });
      toast.success(enabled ? 'Channel enabled' : 'Channel disabled', c.name);
      await channels.reload();
    } catch (e) {
      toast.error('Could not change the channel', (e as ApiError).message);
    } finally {
      setToggling(null);
    }
  }

  async function sendTest(c: NotificationChannelView) {
    setTesting(c.id);
    setTestResult(null);
    try {
      const d = await api.post<NotificationDeliveryView>('/notificationChannel/test', { id: c.id });
      setTestResult(d);
      if (d.status === 'DELIVERED') toast.success('Test notification sent', `${c.name} received it.`);
      else toast.error('Test notification failed', d.lastError ?? undefined);
      await reloadAll();
    } catch (e) {
      toast.error('Test notification failed', (e as ApiError).message);
    } finally {
      setTesting(null);
    }
  }

  async function retry(d: NotificationDeliveryView) {
    setRetrying(d.id);
    try {
      const r = await api.post<NotificationDeliveryView>('/notificationChannel/retryDelivery', { id: d.id });
      if (r.status === 'DELIVERED') toast.success('Notification sent again', d.channel.name);
      else toast.error('Sending again failed', r.lastError ?? undefined);
      await reloadAll();
    } catch (e) {
      toast.error('Sending again failed', (e as ApiError).message);
    } finally {
      setRetrying(null);
    }
  }

  const deliveryItems = useMemo(() => deliveries.data?.items ?? [], [deliveries.data]);
  const deliveryCount = (s: NotificationDeliveryStatus) => deliveryItems.filter((d) => d.status === s).length;
  const deliveryRows = deliveryFilter === 'all' ? deliveryItems : deliveryItems.filter((d) => d.status === deliveryFilter);

  return (
    <div className="space-y-4">
      <PageHeader
        title="Notifications"
        description="Where secret lifecycle events are sent: expiry warnings, rotations, failures and more. Notifications never contain a secret value."
        breadcrumbs={[{ label: 'Settings' }, { label: 'Notifications' }]}
        actions={
          <Button onClick={() => setEditing('new')} data-testid="notification-channel-new">
            <Plus className="h-4 w-4" /> New channel
          </Button>
        }
      />
      <Callout tone="info">
        Email needs SMTP configured on the control plane (<code className="font-mono text-[12px]">SMTP_URL</code>). Slack channels post through the{' '}
        <Link className="text-brand-700 hover:underline" to="/settings/slack">
          Slack connection
        </Link>
        .
      </Callout>

      {testResult && (
        <div data-testid="notification-test-result" data-status={testResult.status}>
          <Callout tone={testResult.status === 'DELIVERED' ? 'info' : 'danger'} title={testResult.status === 'DELIVERED' ? `Test sent to ${testResult.channel.name}` : `Test to ${testResult.channel.name} failed`}>
            {testResult.status === 'DELIVERED' ? `Delivered ${relativeTime(testResult.deliveredAt ?? testResult.createdAt)}.` : (testResult.lastError ?? 'The channel did not accept the notification.')}
          </Callout>
        </div>
      )}

      {channels.error ? (
        <ErrorState error={channels.error} onRetry={channels.reload} />
      ) : (
        <Card data-testid="notification-channels">
          <CardHeader title="Channels" icon={<Bell className="h-4 w-4" />} />
          <DataTable
            rows={channels.data?.items}
            loading={channels.loading && !channels.data}
            rowKey={(c) => c.id}
            empty={
              <EmptyState
                icon={<Bell className="h-5 w-5" />}
                title="No notification channels"
                description="Add an email list, a webhook or a Slack channel to hear about expiring secrets, rotations and failures."
                action={
                  <Button variant="outline" onClick={() => setEditing('new')}>
                    <Plus className="h-4 w-4" /> New channel
                  </Button>
                }
              />
            }
            columns={[
              {
                key: 'name',
                header: 'Channel',
                cell: (c) => (
                  <div className="flex min-w-0 items-start gap-2" data-testid="notification-channel-row" data-kind={c.kind} data-channel-id={c.id} data-enabled={c.enabled ? 'true' : 'false'}>
                    <span className="mt-0.5 text-slate-500" title={KIND_META[c.kind].label}>
                      {KIND_META[c.kind].icon}
                    </span>
                    <span className="min-w-0">
                      <span className="block font-medium text-slate-900">{c.name}</span>
                      <span className="block text-xs text-slate-500">
                        {KIND_META[c.kind].label} · {scopeText(c)}
                      </span>
                    </span>
                  </div>
                ),
              },
              {
                key: 'events',
                header: 'Events',
                cell: (c) => (
                  <span className="block max-w-[16rem] text-xs text-slate-600" title={c.events.map(eventLabel).join(', ')}>
                    {c.events.length === SECRET_NOTIFICATION_EVENTS.length ? 'All events' : c.events.length <= 3 ? c.events.map(eventLabel).join(', ') : `${c.events.length} events`}
                  </span>
                ),
                hideBelow: 'md',
              },
              { key: 'target', header: 'Sent to', cell: (c) => <span className="block max-w-xs text-sm text-slate-600">{targetText(c)}</span>, hideBelow: 'lg' },
              {
                key: 'last',
                header: 'Last delivery',
                cell: (c) =>
                  c.lastDelivery ? (
                    <span className="block">
                      <DeliveryStatusBadge status={c.lastDelivery.status} />
                      <span className="mt-0.5 block text-xs text-slate-500" title={formatDateTime(c.lastDelivery.at)}>
                        {relativeTime(c.lastDelivery.at)}
                      </span>
                      {c.lastDelivery.error && <span className="block max-w-[14rem] truncate text-xs text-red-700" title={c.lastDelivery.error}>{c.lastDelivery.error}</span>}
                    </span>
                  ) : (
                    <span className="text-slate-400">None yet</span>
                  ),
                hideBelow: 'xl',
              },
              {
                key: 'enabled',
                header: 'Enabled',
                cell: (c) => (
                  <span data-testid="notification-channel-enabled">
                    <Switch checked={c.enabled} disabled={toggling === c.id} onChange={(v) => void toggle(c, v)} label={c.enabled ? `Disable ${c.name}` : `Enable ${c.name}`} />
                  </span>
                ),
              },
              {
                key: 'actions',
                header: '',
                className: 'text-right',
                cell: (c) => (
                  <div className="flex flex-wrap justify-end gap-1">
                    <Button variant="ghost" size="sm" loading={testing === c.id} onClick={() => void sendTest(c)} data-testid="notification-channel-test">
                      <Send className="h-3.5 w-3.5" /> Send test
                    </Button>
                    <Button variant="ghost" size="sm" onClick={() => setEditing(c)} data-testid="notification-channel-edit">
                      <Pencil className="h-3.5 w-3.5" /> Edit
                    </Button>
                    {c.kind === 'WEBHOOK' && (
                      <Button variant="ghost" size="sm" onClick={() => setRenewing(c)} data-testid="notification-channel-new-secret">
                        <KeyRound className="h-3.5 w-3.5" /> New signing secret
                      </Button>
                    )}
                    <Button variant="ghost" size="sm" className="text-red-700 hover:bg-red-50 hover:text-red-800" onClick={() => setRemoving(c)} data-testid="notification-channel-delete">
                      <Trash2 className="h-3.5 w-3.5" /> Delete
                    </Button>
                  </div>
                ),
              },
            ]}
          />
        </Card>
      )}

      <Card data-testid="notification-deliveries">
        <CardHeader
          title="Recent deliveries"
          description="Failed deliveries are retried automatically a few times; you can also send one again."
          actions={
            <Button variant="outline" size="sm" onClick={() => void deliveries.reload()} loading={deliveries.loading && !!deliveries.data}>
              <RefreshCw className="h-3.5 w-3.5" /> Refresh
            </Button>
          }
        />
        <div className="px-5 pt-3">
          <FilterTabs
            value={deliveryFilter}
            onChange={setDeliveryFilter}
            options={[
              { value: 'all', label: 'All', count: deliveryItems.length },
              { value: 'DELIVERED', label: 'Delivered', count: deliveryCount('DELIVERED') },
              { value: 'FAILED', label: 'Failed', count: deliveryCount('FAILED') },
              { value: 'PENDING', label: 'Pending', count: deliveryCount('PENDING') },
            ]}
          />
        </div>
        {deliveries.error ? (
          <div className="p-5">
            <ErrorState error={deliveries.error} onRetry={deliveries.reload} />
          </div>
        ) : (
          <DataTable
            rows={deliveryRows}
            loading={deliveries.loading && !deliveries.data}
            rowKey={(d) => d.id}
            dense
            empty={<EmptyState icon={<Send className="h-5 w-5" />} title="No deliveries here" description="Deliveries appear when an event matches a channel, or when you send a test." />}
            columns={[
              {
                key: 'event',
                header: 'Event',
                cell: (d) => (
                  <div className="min-w-0" data-testid="notification-delivery-row" data-status={d.status} data-event={d.event} data-channel-id={d.channel.id}>
                    <span className="block font-medium text-slate-800">{eventLabel(d.event)}</span>
                    {d.secret && (
                      <Link className="block text-xs text-brand-700 hover:underline" to={`/secrets/${d.secret.id}`}>
                        {d.secret.name}
                      </Link>
                    )}
                  </div>
                ),
              },
              {
                key: 'channel',
                header: 'Channel',
                cell: (d) => (
                  <span className="flex items-center gap-1.5 text-slate-600">
                    <span className="text-slate-400">{KIND_META[d.channel.kind]?.icon}</span>
                    {d.channel.name}
                  </span>
                ),
                hideBelow: 'md',
              },
              {
                key: 'status',
                header: 'Status',
                cell: (d) => (
                  <span className="block">
                    <DeliveryStatusBadge status={d.status} />
                    {d.lastError && <span className="mt-0.5 block max-w-xs break-words text-xs text-red-700">{d.lastError}</span>}
                  </span>
                ),
              },
              { key: 'attempts', header: 'Attempts', cell: (d) => <span className="text-slate-600">{d.attempts}</span>, hideBelow: 'lg' },
              {
                key: 'when',
                header: 'When',
                cell: (d) => (
                  <span className="whitespace-nowrap text-xs text-slate-500">
                    <span className="block" title={formatDateTime(d.createdAt)}>
                      {relativeTime(d.createdAt)}
                    </span>
                    {d.status === 'PENDING' && d.nextAttemptAt && <span className="block">next attempt {relativeTime(d.nextAttemptAt)}</span>}
                  </span>
                ),
                hideBelow: 'md',
              },
              {
                key: 'actions',
                header: '',
                className: 'text-right',
                cell: (d) =>
                  d.status === 'FAILED' ? (
                    <Button variant="ghost" size="sm" loading={retrying === d.id} onClick={() => void retry(d)} data-testid="notification-delivery-retry">
                      <RefreshCw className="h-3.5 w-3.5" /> Send again
                    </Button>
                  ) : null,
              },
            ]}
          />
        )}
      </Card>

      {editing && (
        <ChannelDialog
          key={editing === 'new' ? 'new' : editing.id}
          channel={editing === 'new' ? null : editing}
          onClose={() => setEditing(null)}
          onDone={async (r, created) => {
            setEditing(null);
            toast.success(created ? 'Channel created' : 'Channel saved', r.name);
            if (r.signingSecret) setRevealed({ channel: r.name, secret: r.signingSecret });
            await channels.reload();
          }}
        />
      )}
      {renewing && (
        <ConfirmDialog
          open
          onClose={() => {
            setRenewing(null);
            renew.setError(null);
          }}
          onConfirm={async () => {
            const r = await renew.run(renewing);
            if (r) {
              setRenewing(null);
              if (r.signingSecret) setRevealed({ channel: r.name, secret: r.signingSecret });
              toast.success('New signing secret issued', r.name);
              await channels.reload();
            }
          }}
          loading={renew.pending}
          tone="primary"
          title="New signing secret"
          confirmLabel="Issue new secret"
          description={
            <div className="space-y-2">
              <p>
                Deliveries to <strong>{renewing.name}</strong> are signed with the new secret from now on. Update your receiver right away, or it will reject them.
              </p>
              {renew.error && (
                <Callout tone="danger" title="Request failed">
                  {renew.error.message}
                </Callout>
              )}
            </div>
          }
        />
      )}
      {removing && (
        <ConfirmDialog
          open
          onClose={() => {
            setRemoving(null);
            remove.setError(null);
          }}
          onConfirm={async () => {
            const r = await remove.run(removing.id);
            if (r) {
              setRemoving(null);
              toast.success('Channel deleted', removing.name);
              await reloadAll();
            }
          }}
          loading={remove.pending}
          title="Delete channel"
          confirmLabel="Delete channel"
          description={
            <div className="space-y-2" data-testid="notification-channel-delete-dialog">
              <p>
                <strong>{removing.name}</strong> stops receiving notifications. Its past deliveries stay in the list.
              </p>
              {remove.error && (
                <Callout tone="danger" title="Request failed">
                  {remove.error.message}
                </Callout>
              )}
            </div>
          }
        />
      )}
      {revealed && <SigningSecretDialog channel={revealed.channel} secret={revealed.secret} onDone={() => setRevealed(null)} />}
    </div>
  );
}

// ── signing secret ───────────────────────────────────────────────

function SignatureHelp() {
  return (
    <p className="text-xs text-slate-500">
      Each request carries the header <code className="font-mono">Token-Vault-Signature: t=&lt;unix seconds&gt;,v1=&lt;signature&gt;</code>, where the signature is the hex HMAC-SHA256 of <code className="font-mono">t.body</code> (the timestamp, a dot and the raw body) with the signing secret. Check it, and reject old timestamps.
    </p>
  );
}

/** Shows a webhook channel's signing secret once; it is dropped from memory when the dialog closes. */
function SigningSecretDialog({ channel, secret, onDone }: { channel: string; secret: string; onDone: () => void }) {
  return (
    <Dialog
      open
      onClose={onDone}
      dismissible={false}
      title={
        <span className="flex items-center gap-2">
          <KeyRound className="h-5 w-5 text-brand-600" /> Signing secret for {channel}
        </span>
      }
      description="Your receiver uses it to check that deliveries come from Token Vault."
      footer={
        <Button onClick={onDone} data-testid="notification-signing-secret-done">
          Done
        </Button>
      }
    >
      <div className="space-y-4">
        <div className="flex items-start gap-3 rounded-lg border border-amber-200 bg-amber-50 p-3 text-sm text-amber-900">
          <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-amber-600" />
          <span>
            <strong>This secret will not be shown again.</strong> Copy it into your receiver's configuration now. If it is lost, issue a new signing secret.
          </span>
        </div>
        <div className="rounded-lg border border-slate-200 bg-slate-50 p-3">
          <div className="flex items-center justify-between gap-2">
            <span className="text-xs font-medium uppercase tracking-wide text-slate-500">Signing secret</span>
            <CopyButton value={secret} />
          </div>
          <code className="mt-2 block break-all font-mono text-[13px] text-slate-900" data-testid="notification-signing-secret">
            {secret}
          </code>
        </div>
        <SignatureHelp />
      </div>
    </Dialog>
  );
}

// ── create / edit ────────────────────────────────────────────────

function ChannelDialog({ channel, onClose, onDone }: { channel: NotificationChannelView | null; onClose: () => void; onDone: (r: ChannelSaveResult, created: boolean) => void }) {
  const editing = !!channel;
  const [kind, setKind] = useState<NotificationChannelKind>(channel?.kind ?? 'EMAIL');
  const [name, setName] = useState(channel?.name ?? '');
  const [enabled, setEnabled] = useState(channel?.enabled ?? true);
  const [events, setEvents] = useState<SecretNotificationEvent[]>(channel?.events ?? ['secret.expiring', 'secret.expired', 'secret.rotation_failed']);
  const [project, setProject] = useState(channel?.scope.project ?? '');
  const [environment, setEnvironment] = useState<Environment | ''>(channel?.scope.environment ?? '');
  const [recipients, setRecipients] = useState(channel?.recipients.join(', ') ?? '');
  const [url, setUrl] = useState(channel?.url ?? '');
  const [slackChannelId, setSlackChannelId] = useState(channel?.slackChannelId ?? '');
  const [errors, setErrors] = useState<Record<string, string>>({});
  const save = useMutation((body: unknown) => api.post<ChannelSaveResult>('/notificationChannel/save', body));
  const allErrors = { ...save.fieldErrors, ...errors };
  const allSelected = events.length === SECRET_NOTIFICATION_EVENTS.length;

  async function submit() {
    const e: Record<string, string> = {};
    if (!name.trim()) e.name = 'Name is required';
    if (!events.length) e.events = 'Choose at least one event';
    if (project.trim() && !SECRET_SCOPE_SLUG.test(project.trim())) e['scope.project'] = 'Lower-case letters, digits and dashes';
    const list = splitList(recipients.replace(/[\n;]/g, ','));
    if (kind === 'EMAIL' && !list.length) e.recipients = 'Give at least one email address';
    if (kind === 'WEBHOOK' && !url.trim()) e.url = 'Give the URL deliveries are sent to';
    if (kind === 'SLACK' && slackChannelId.trim() && !/^[CG][A-Z0-9]{6,20}$/.test(slackChannelId.trim())) e.slackChannelId = 'Use the channel ID (starts with C or G)';
    setErrors(e);
    if (Object.keys(e).length) return;
    const body = {
      ...(editing ? { id: channel.id } : { kind }),
      name: name.trim(),
      enabled,
      events: SECRET_NOTIFICATION_EVENTS.filter((x) => events.includes(x)),
      scope: { ...(project.trim() ? { project: project.trim() } : {}), ...(environment ? { environment } : {}) },
      ...(kind === 'EMAIL' ? { recipients: list } : {}),
      ...(kind === 'WEBHOOK' ? { url: url.trim() } : {}),
      ...(kind === 'SLACK' ? { slackChannelId: slackChannelId.trim() || null } : {}),
    };
    const r = await save.run(body);
    if (r) onDone(r, !editing);
  }

  const shown = ['name', 'kind', 'events', 'scope.project', 'scope.environment', 'recipients', 'url', 'slackChannelId'];
  const unshownErrors = Object.entries(save.fieldErrors).filter(([k]) => !shown.includes(k));

  return (
    <Dialog
      open
      onClose={onClose}
      size="lg"
      title={editing ? `Edit ${channel.name}` : 'New notification channel'}
      description={editing ? `${KIND_META[channel.kind].label} channel. The kind of a channel cannot change.` : 'Choose where the notifications go and which events they cover.'}
      footer={
        <>
          <Button variant="outline" onClick={onClose}>
            Cancel
          </Button>
          <Button loading={save.pending} onClick={submit} data-testid="notification-channel-save">
            {editing ? 'Save changes' : 'Create channel'}
          </Button>
        </>
      }
    >
      <form
        className="space-y-5"
        data-testid="notification-channel-form"
        autoComplete="off"
        onSubmit={(ev) => {
          ev.preventDefault();
          void submit();
        }}
      >
        {!editing && (
          <div className="grid gap-2 sm:grid-cols-3" role="radiogroup" aria-label="Channel kind">
            {(Object.keys(KIND_META) as NotificationChannelKind[]).map((k) => (
              <button
                key={k}
                type="button"
                role="radio"
                aria-checked={kind === k}
                onClick={() => setKind(k)}
                data-testid={`notification-channel-kind-${k}`}
                className={cn('flex flex-col items-start rounded-lg border p-3 text-left transition', kind === k ? 'border-brand-500 bg-brand-50/50 ring-1 ring-brand-500' : 'border-slate-200 bg-white hover:border-slate-300')}
              >
                <span className="flex items-center gap-2 text-sm font-medium text-slate-900">
                  {KIND_META[k].icon} {KIND_META[k].label}
                </span>
                <span className="mt-0.5 text-xs text-slate-500">{KIND_META[k].description}</span>
              </button>
            ))}
          </div>
        )}
        <div className="grid gap-4 sm:grid-cols-2">
          <Field label="Name" htmlFor="notification-channel-name" required error={allErrors.name}>
            <Input id="notification-channel-name" value={name} maxLength={80} onChange={(e) => setName(e.target.value)} invalid={!!allErrors.name} placeholder="Security team" data-testid="notification-channel-name" />
          </Field>
          <div className="flex items-end pb-1.5">
            <Checkbox id="notification-channel-enabled" checked={enabled} onChange={setEnabled} label="Enabled" description="Disabled channels receive nothing." />
          </div>
        </div>

        {kind === 'EMAIL' && (
          <Field label="Recipients" htmlFor="notification-channel-recipients" required error={allErrors.recipients} hint="Email addresses, separated by commas or new lines (at most 20).">
            <Textarea id="notification-channel-recipients" rows={2} value={recipients} onChange={(e) => setRecipients(e.target.value)} invalid={!!allErrors.recipients} placeholder="security@example.com, oncall@example.com" data-testid="notification-channel-recipients" />
          </Field>
        )}
        {kind === 'WEBHOOK' && (
          <div className="space-y-2">
            <Field label="URL" htmlFor="notification-channel-url" required error={allErrors.url} hint={editing ? `Signing secret ${channel.signingSecretHint ?? ''}. Use “New signing secret” in the list to replace it.` : 'A signing secret is created with the channel and shown once.'}>
              <Input id="notification-channel-url" type="url" value={url} onChange={(e) => setUrl(e.target.value)} invalid={!!allErrors.url} placeholder="https://hooks.example.com/token-vault" data-testid="notification-channel-url" />
            </Field>
            <SignatureHelp />
          </div>
        )}
        {kind === 'SLACK' && (
          <Field
            label="Slack channel ID"
            htmlFor="notification-channel-slack"
            error={allErrors.slackChannelId}
            hint={
              <>
                Starts with C or G. Leave empty to post to the channel of the{' '}
                <Link className="text-brand-700 hover:underline" to="/settings/slack">
                  Slack connection
                </Link>
                . Invite the Token Vault app to the channel.
              </>
            }
          >
            <Input id="notification-channel-slack" value={slackChannelId} onChange={(e) => setSlackChannelId(e.target.value.toUpperCase())} invalid={!!allErrors.slackChannelId} placeholder="C0123456789" className="font-mono text-[13px]" data-testid="notification-channel-slack" />
          </Field>
        )}

        <div className="space-y-2" data-testid="notification-channel-events">
          <div className="flex items-center justify-between gap-2">
            <p className="text-sm font-medium text-slate-700">
              Events<span className="ml-0.5 text-red-500">*</span>
            </p>
            <label className="flex cursor-pointer items-center gap-2 text-xs text-slate-600">
              <input
                type="checkbox"
                className="h-4 w-4 rounded border-slate-300 text-brand-600 focus:ring-brand-500"
                checked={allSelected}
                onChange={(e) => setEvents(e.target.checked ? [...SECRET_NOTIFICATION_EVENTS] : [])}
                data-testid="notification-event-all"
              />
              Select all
            </label>
          </div>
          <div className="grid gap-2 sm:grid-cols-2">
            {SECRET_NOTIFICATION_EVENTS.map((ev) => (
              <label key={ev} className="flex cursor-pointer items-start gap-2.5 rounded-md border border-slate-200 px-3 py-2 hover:bg-slate-50">
                <input
                  type="checkbox"
                  className="mt-0.5 h-4 w-4 rounded border-slate-300 text-brand-600 focus:ring-brand-500"
                  checked={events.includes(ev)}
                  onChange={(e) => setEvents((xs) => (e.target.checked ? [...xs, ev] : xs.filter((x) => x !== ev)))}
                  data-testid={`notification-event-${ev}`}
                />
                <span>
                  <span className="block text-sm text-slate-800">{SECRET_NOTIFICATION_EVENT_LABELS[ev]}</span>
                  <span className="block font-mono text-[11px] text-slate-400">{ev}</span>
                </span>
              </label>
            ))}
          </div>
          {allErrors.events && <p className="text-xs text-red-600">{allErrors.events}</p>}
        </div>

        <div className="grid gap-4 sm:grid-cols-2">
          <Field label="Project (optional)" htmlFor="notification-channel-project" error={allErrors['scope.project']} hint="Only secrets of this project. Empty: every project.">
            <Input id="notification-channel-project" value={project} onChange={(e) => setProject(e.target.value)} invalid={!!allErrors['scope.project']} placeholder="payments" data-testid="notification-channel-project" />
          </Field>
          <Field label="Environment (optional)" htmlFor="notification-channel-environment" error={allErrors['scope.environment']} hint="Only secrets of this environment.">
            <Select id="notification-channel-environment" value={environment} onChange={(e) => setEnvironment(e.target.value as Environment | '')} data-testid="notification-channel-environment">
              <option value="">Every environment</option>
              {(Object.keys(ENV_LABELS) as Environment[]).map((env) => (
                <option key={env} value={env}>
                  {ENV_LABELS[env]}
                </option>
              ))}
            </Select>
          </Field>
        </div>

        {save.error && (
          <div data-testid="notification-channel-error" data-code={save.error.code}>
            <Callout tone="danger" title={Object.keys(save.fieldErrors).length ? 'Please correct the highlighted fields' : 'Request failed'}>
              {Object.keys(save.fieldErrors).length
                ? unshownErrors.map(([k, v]) => (
                    <p key={k}>
                      {k}: {v}
                    </p>
                  ))
                : save.error.message}
            </Callout>
          </div>
        )}
      </form>
    </Dialog>
  );
}
