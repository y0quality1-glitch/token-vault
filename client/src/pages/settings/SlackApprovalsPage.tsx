import { useEffect, useState } from 'react';
import { MessageSquare, Send, Unplug } from 'lucide-react';
import { PERMISSIONS, type SlackSettingsView } from '@token-vault/shared';
import { useApi, useMutation } from '@/hooks/useApi';
import { useAuth } from '@/context/AuthContext';
import { api } from '@/lib/api';
import { Button } from '@/components/ui/button';
import { Card, CardBody, CardHeader, DetailList } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Field, Input, Switch } from '@/components/ui/form';
import { Callout, ErrorState, FormError, PageSkeleton } from '@/components/ui/feedback';
import { ConfirmDialog } from '@/components/ui/dialog';
import { PageHeader } from '@/components/ui/navigation';
import { CopyButton, Mono } from '@/components/ui/secret';
import { useToast } from '@/components/ui/toast';
import { formatDateTime } from '@/lib/utils';

/**
 * Settings → Slack approvals: post requests that need a human's approval to a Slack channel,
 * with Approve / Reject buttons. Clicks count only from Token Vault members allowed to approve.
 */
export function SlackApprovalsPage() {
  const { can } = useAuth();
  const toast = useToast();
  const manage = can(PERMISSIONS.POLICY_MANAGE);
  const { data, error, loading, reload, setData } = useApi<SlackSettingsView>('/slack-settings');
  const [f, setF] = useState({ botToken: '', signingSecret: '', channelId: '', enabled: true });
  const [confirmDisconnect, setConfirmDisconnect] = useState(false);
  useEffect(() => {
    if (data) setF((x) => ({ ...x, channelId: data.channelId ?? '', enabled: data.configured ? data.enabled : true }));
  }, [data]);
  const save = useMutation((body: unknown) => api.put<SlackSettingsView>('/slack-settings', body));
  const test = useMutation(() => api.post<{ sent: boolean }>('/slack-settings/test'));
  const disconnect = useMutation(() => api.del('/slack-settings'));
  const fe = save.fieldErrors;

  if (error) return <ErrorState error={error} onRetry={reload} />;
  if (loading || !data) return <PageSkeleton />;

  return (
    <div className="space-y-4">
      <PageHeader
        title="Slack approvals"
        description="Post requests that need a human's approval to a Slack channel, with Approve and Reject buttons."
        breadcrumbs={[{ label: 'Settings' }, { label: 'Slack approvals' }]}
        badge={data.configured ? <Badge tone={data.enabled ? 'green' : 'gray'} dot>{data.enabled ? 'Connected' : 'Paused'}</Badge> : undefined}
      />
      <Callout tone="security" title="Who can approve from Slack">
        A click counts only if the Slack user's email belongs to a member of this organization whose role can approve (Owner or Security Administrator), and the same rules as the console apply: an agent's owner can't approve its requests, and each request is decided once. Every click is checked against Slack's signature.
      </Callout>
      <div className="grid gap-4 xl:grid-cols-3">
        <Card className="xl:col-span-2">
          <CardHeader title={data.configured ? 'Connection' : 'Connect Slack'} icon={<MessageSquare className="h-4 w-4" />} description={data.configured ? 'Leave the token and secret empty to keep the stored ones.' : 'From your Slack app (api.slack.com/apps).'} />
          <CardBody className="space-y-4">
            <FormError error={save.error} />
            <div className="grid gap-4 md:grid-cols-2">
              <Field label="Bot token" htmlFor="slack-token" required={!data.configured} error={fe.botToken} hint={data.botTokenHint ? `Stored: ${data.botTokenHint}` : 'OAuth & Permissions → Bot User OAuth Token (xoxb-…)'}>
                <Input id="slack-token" type="password" autoComplete="off" value={f.botToken} onChange={(e) => setF({ ...f, botToken: e.target.value })} placeholder={data.configured ? 'Unchanged' : 'xoxb-…'} disabled={!manage} invalid={!!fe.botToken} />
              </Field>
              <Field label="Signing secret" htmlFor="slack-secret" required={!data.configured} error={fe.signingSecret} hint={data.configured ? 'Stored (never shown)' : 'Basic Information → App Credentials → Signing Secret'}>
                <Input id="slack-secret" type="password" autoComplete="off" value={f.signingSecret} onChange={(e) => setF({ ...f, signingSecret: e.target.value })} placeholder={data.configured ? 'Unchanged' : ''} disabled={!manage} invalid={!!fe.signingSecret} />
              </Field>
              <Field label="Channel ID" htmlFor="slack-channel" required error={fe.channelId} hint="Channel details → bottom of the About tab (C…). Invite the app to the channel.">
                <Input id="slack-channel" className="font-mono" value={f.channelId} onChange={(e) => setF({ ...f, channelId: e.target.value })} placeholder="C0123456789" disabled={!manage} invalid={!!fe.channelId} />
              </Field>
              <div className="flex items-center justify-between gap-4 rounded-lg border border-slate-200 p-3.5">
                <div>
                  <p className="text-sm font-medium text-slate-800">Post approval requests</p>
                  <p className="text-xs text-slate-500">Off: nothing is posted; requests still wait under Approvals.</p>
                </div>
                <Switch checked={f.enabled} onChange={(v) => setF({ ...f, enabled: v })} disabled={!manage} label="Post approval requests" />
              </div>
            </div>
            {manage && (
              <div className="flex flex-wrap gap-2">
                <Button
                  loading={save.pending}
                  onClick={async () => {
                    const r = await save.run({ channelId: f.channelId, enabled: f.enabled, ...(f.botToken ? { botToken: f.botToken } : {}), ...(f.signingSecret ? { signingSecret: f.signingSecret } : {}) });
                    if (r) {
                      setData(r);
                      setF((x) => ({ ...x, botToken: '', signingSecret: '' }));
                      toast.success(data.configured ? 'Slack settings saved' : 'Slack connected', r.teamName ?? undefined);
                    }
                  }}
                >
                  {data.configured ? 'Save' : 'Connect Slack'}
                </Button>
                {data.configured && (
                  <>
                    <Button
                      variant="outline"
                      loading={test.pending}
                      onClick={async () => {
                        if (await test.run()) toast.success('Test message sent', `Check the channel in ${data.teamName}.`);
                        else toast.error('Test message failed', test.error?.message);
                      }}
                    >
                      <Send className="h-4 w-4" /> Send test message
                    </Button>
                    <Button variant="danger-outline" onClick={() => setConfirmDisconnect(true)}>
                      <Unplug className="h-4 w-4" /> Disconnect
                    </Button>
                  </>
                )}
              </div>
            )}
          </CardBody>
        </Card>
        <div className="space-y-4">
          {data.configured && (
            <Card>
              <CardHeader title="Connected workspace" />
              <CardBody>
                <DetailList
                  columns={1}
                  items={[
                    { label: 'Workspace', value: `${data.teamName} (${data.teamId})` },
                    { label: 'Channel', value: data.channelId ?? '—', mono: true },
                    { label: 'Bot user', value: data.botUserId ?? '—', mono: true },
                    { label: 'Last changed', value: data.updatedAt ? `${formatDateTime(data.updatedAt)} by ${data.updatedByName ?? 'unknown'}` : '—' },
                  ]}
                />
              </CardBody>
            </Card>
          )}
          <Card>
            <CardHeader title="Set up the Slack app" />
            <CardBody className="space-y-3 text-sm text-slate-700">
              <ol className="list-decimal space-y-2 pl-5">
                <li>
                  Create an app at api.slack.com/apps and add the bot scopes <Mono>chat:write</Mono>, <Mono>users:read</Mono> and <Mono>users:read.email</Mono>. Install it to your workspace.
                </li>
                <li>
                  Turn on <strong>Interactivity</strong> and set the Request URL to:
                  <div className="mt-1 flex items-center gap-2">
                    <Mono className="break-all">{data.interactionsUrl}</Mono>
                    <CopyButton value={data.interactionsUrl} label="Copy URL" />
                  </div>
                  <span className="text-xs text-slate-500">It must be reachable from the internet (set API_PUBLIC_URL on the control plane).</span>
                </li>
                <li>Invite the app to the approvals channel, then connect it here and send a test message.</li>
              </ol>
            </CardBody>
          </Card>
        </div>
      </div>
      <ConfirmDialog
        open={confirmDisconnect}
        onClose={() => setConfirmDisconnect(false)}
        title="Disconnect Slack?"
        description="Approval requests are no longer posted, and buttons on messages already posted stop working. Requests still wait under Approvals in the console."
        confirmLabel="Disconnect"
        loading={disconnect.pending}
        onConfirm={async () => {
          if ((await disconnect.run()) !== undefined) {
            toast.success('Slack disconnected');
            setConfirmDisconnect(false);
            setF({ botToken: '', signingSecret: '', channelId: '', enabled: true });
            void reload();
          }
        }}
      />
    </div>
  );
}
