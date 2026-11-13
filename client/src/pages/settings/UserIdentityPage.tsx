import { useState } from 'react';
import { BadgeCheck, Pencil, Plus, Trash2, UserRoundCheck } from 'lucide-react';
import { PERMISSIONS, actingUserLabel, type ActingUser, type UserIssuer } from '@token-vault/shared';
import { useMutation, usePost } from '@/hooks/useApi';
import { useAuth } from '@/context/AuthContext';
import { api } from '@/lib/api';
import { Button } from '@/components/ui/button';
import { Card } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Field, Input, Switch, Textarea } from '@/components/ui/form';
import { Callout, EmptyState, ErrorState, FormError } from '@/components/ui/feedback';
import { ConfirmDialog, Dialog } from '@/components/ui/dialog';
import { DataTable } from '@/components/ui/table';
import { PageHeader } from '@/components/ui/navigation';
import { Mono } from '@/components/ui/secret';
import { useToast } from '@/components/ui/toast';
import { relativeTime } from '@/lib/utils';

/**
 * Settings → User Identity: the identity providers (or the customer's own application) trusted
 * to vouch for the users agents act for. Only public keys are stored.
 */
export function UserIdentityPage() {
  const { can } = useAuth();
  const toast = useToast();
  const manage = can(PERMISSIONS.POLICY_MANAGE);
  const { data, error, loading, reload } = usePost<{ items: UserIssuer[] }>('/userIssuer/getall');
  const [editing, setEditing] = useState<UserIssuer | 'new' | null>(null);
  const [deleting, setDeleting] = useState<UserIssuer | null>(null);
  const [checking, setChecking] = useState(false);
  const remove = useMutation((id: string) => api.del(`/userIssuer/delete/${id}`));

  return (
    <div className="space-y-4">
      <PageHeader
        title="User Identity"
        description="Identity providers trusted to say which user an agent is acting for."
        breadcrumbs={[{ label: 'Settings' }, { label: 'User Identity' }]}
        actions={
          manage && (
            <div className="flex gap-2">
              <Button variant="outline" onClick={() => setChecking(true)} disabled={!data?.items.length}>
                <BadgeCheck className="h-4 w-4" /> Check a user token
              </Button>
              <Button onClick={() => setEditing('new')}>
                <Plus className="h-4 w-4" /> Add issuer
              </Button>
            </div>
          )
        }
      />
      <Callout tone="security" title="How acting for a user works">
        Your application signs a short-lived token (a JWT) for the signed-in user, and the agent sends it with each request as <code>on_behalf_of</code>. Token Vault checks the signature with the public key registered here, then limits the request to what both the agent's grant and the user's token allow. The access log records which user each request was for. Token Vault never holds a key that can sign user tokens.
      </Callout>
      {error ? (
        <ErrorState error={error} onRetry={reload} />
      ) : (
        <Card>
          <DataTable
            rows={data?.items}
            loading={loading}
            rowKey={(i) => i.id}
            empty={<EmptyState icon={<UserRoundCheck className="h-5 w-5" />} title="No issuers yet" description="Until you add one, agents can act only for themselves: any request with a user token is denied." />}
            columns={[
              {
                key: 'name',
                header: 'Issuer',
                cell: (i) => (
                  <div className="min-w-0">
                    <div className="font-medium text-slate-800">{i.name}</div>
                    <div className="truncate text-xs text-slate-500">{i.issuer}</div>
                  </div>
                ),
              },
              { key: 'aud', header: 'Audience', cell: (i) => <Mono>{i.audience}</Mono>, hideBelow: 'md' },
              { key: 'key', header: 'Public key', cell: (i) => <Mono>{i.keyFingerprint}</Mono>, hideBelow: 'lg' },
              { key: 'status', header: 'Status', cell: (i) => (i.enabled ? <Badge tone="green" dot>Enabled</Badge> : <Badge tone="gray" dot>Disabled</Badge>) },
              { key: 'used', header: 'Last used', cell: (i) => <span className="text-slate-500">{relativeTime(i.lastUsedAt)}</span>, hideBelow: 'md' },
              {
                key: 'actions',
                header: '',
                cell: (i) =>
                  manage && (
                    <div className="flex justify-end gap-1">
                      <Button variant="ghost" size="sm" aria-label={`Edit ${i.name}`} onClick={() => setEditing(i)}>
                        <Pencil className="h-4 w-4" />
                      </Button>
                      <Button variant="ghost" size="sm" aria-label={`Delete ${i.name}`} onClick={() => setDeleting(i)}>
                        <Trash2 className="h-4 w-4" />
                      </Button>
                    </div>
                  ),
              },
            ]}
          />
        </Card>
      )}

      {editing && (
        <IssuerDialog
          issuer={editing === 'new' ? null : editing}
          onClose={() => setEditing(null)}
          onSaved={(i, isNew) => {
            setEditing(null);
            toast.success(isNew ? 'Issuer added' : 'Issuer saved', i.name);
            reload();
          }}
        />
      )}
      <ConfirmDialog
        open={!!deleting}
        onClose={() => setDeleting(null)}
        title="Delete this issuer?"
        description={`Agents can no longer act for users vouched for by ${deleting?.issuer ?? 'this issuer'}: their requests are denied. Past access records keep the users they name.`}
        confirmLabel="Delete issuer"
        loading={remove.pending}
        onConfirm={async () => {
          if (!deleting) return;
          const ok = await remove.run(deleting.id);
          if (ok !== undefined) {
            toast.success('Issuer deleted', deleting.name);
            setDeleting(null);
            reload();
          } else toast.error('Could not delete the issuer', remove.error?.message);
        }}
      />
      {checking && <CheckTokenDialog onClose={() => setChecking(false)} />}
    </div>
  );
}

const LIFETIMES = [
  { minutes: 5, label: '5 minutes' },
  { minutes: 15, label: '15 minutes' },
  { minutes: 60, label: '1 hour' },
  { minutes: 480, label: '8 hours' },
  { minutes: 1440, label: '24 hours' },
];

function IssuerDialog({ issuer, onClose, onSaved }: { issuer: UserIssuer | null; onClose: () => void; onSaved: (i: UserIssuer, isNew: boolean) => void }) {
  const [f, setF] = useState({
    name: issuer?.name ?? '',
    issuer: issuer?.issuer ?? '',
    audience: issuer?.audience ?? '',
    publicKey: issuer?.publicKey ?? '',
    groupsClaim: issuer?.groupsClaim ?? 'groups',
    lifetimeMinutes: String(Math.round((issuer?.maxTokenLifetimeSeconds ?? 3600) / 60)),
    enabled: issuer?.enabled ?? true,
  });
  const set = (patch: Partial<typeof f>) => setF((x) => ({ ...x, ...patch }));
  const save = useMutation((body: unknown) => (issuer ? api.post<UserIssuer>('/userIssuer/save', { ...(body as object), id: issuer.id }) : api.post<UserIssuer>('/userIssuer/save', body)));
  const fe = save.fieldErrors;

  return (
    <Dialog
      open
      onClose={onClose}
      size="lg"
      title={issuer ? 'Edit issuer' : 'Add issuer'}
      description="Values must match the tokens your application or identity provider issues."
      footer={
        <>
          <Button variant="outline" onClick={onClose}>
            Cancel
          </Button>
          <Button
            loading={save.pending}
            onClick={async () => {
              const r = await save.run({ name: f.name, issuer: f.issuer, audience: f.audience, publicKey: f.publicKey, groupsClaim: f.groupsClaim || 'groups', maxTokenLifetimeSeconds: Number(f.lifetimeMinutes) * 60, enabled: f.enabled });
              if (r) onSaved(r, !issuer);
            }}
          >
            {issuer ? 'Save issuer' : 'Add issuer'}
          </Button>
        </>
      }
    >
      <div className="space-y-4">
        <FormError error={save.error} />
        <Field label="Name" htmlFor="ui-name" required error={fe.name}>
          <Input id="ui-name" value={f.name} onChange={(e) => set({ name: e.target.value })} placeholder="Acme employee login" invalid={!!fe.name} />
        </Field>
        <div className="grid gap-4 sm:grid-cols-2">
          <Field label="Issuer (iss)" htmlFor="ui-iss" required error={fe.issuer} hint="Exactly as in the tokens' iss claim.">
            <Input id="ui-iss" value={f.issuer} onChange={(e) => set({ issuer: e.target.value })} placeholder="https://login.acme.com" invalid={!!fe.issuer} />
          </Field>
          <Field label="Audience (aud)" htmlFor="ui-aud" required error={fe.audience} hint="Tokens must name this audience, so tokens meant for other services are refused.">
            <Input id="ui-aud" value={f.audience} onChange={(e) => set({ audience: e.target.value })} placeholder="token-vault" invalid={!!fe.audience} />
          </Field>
        </div>
        <Field label="Public key" htmlFor="ui-key" required error={fe.publicKey} hint="PEM (-----BEGIN PUBLIC KEY-----) or JWK. RSA 2048+, EC P-256/P-384 or Ed25519. Never paste the private key.">
          <Textarea id="ui-key" rows={6} className="font-mono text-xs" value={f.publicKey} onChange={(e) => set({ publicKey: e.target.value })} placeholder="-----BEGIN PUBLIC KEY-----" invalid={!!fe.publicKey} />
        </Field>
        <div className="grid gap-4 sm:grid-cols-2">
          <Field label="Groups claim" htmlFor="ui-groups" error={fe.groupsClaim} hint="Where tokens list the user's groups, used by grants and policies.">
            <Input id="ui-groups" value={f.groupsClaim} onChange={(e) => set({ groupsClaim: e.target.value })} placeholder="groups" invalid={!!fe.groupsClaim} />
          </Field>
          <Field label="Longest token lifetime" htmlFor="ui-life" error={fe.maxTokenLifetimeSeconds} hint="Tokens valid for longer are refused. Shorter is safer.">
            <select id="ui-life" className="h-9 w-full rounded-md border border-slate-300 bg-white px-3 text-sm" value={f.lifetimeMinutes} onChange={(e) => set({ lifetimeMinutes: e.target.value })}>
              {LIFETIMES.map((l) => (
                <option key={l.minutes} value={l.minutes}>
                  {l.label}
                </option>
              ))}
            </select>
          </Field>
        </div>
        <div className="flex items-center justify-between rounded-md border border-slate-200 px-3 py-2">
          <div>
            <div className="text-sm font-medium text-slate-800">Enabled</div>
            <div className="text-xs text-slate-500">While disabled, every request with a token from this issuer is denied.</div>
          </div>
          <Switch checked={f.enabled} onChange={(v) => set({ enabled: v })} label="Enabled" />
        </div>
      </div>
    </Dialog>
  );
}

function CheckTokenDialog({ onClose }: { onClose: () => void }) {
  const [token, setToken] = useState('');
  const check = useMutation((t: string) => api.post<{ valid: true; user: ActingUser } | { valid: false; reason: string }>('/userIssuer/verifyToken', { token: t }));
  const [result, setResult] = useState<{ valid: true; user: ActingUser } | { valid: false; reason: string } | null>(null);
  return (
    <Dialog
      open
      onClose={onClose}
      size="lg"
      title="Check a user token"
      description="Verifies a token the way agent requests are verified. Nothing is run or recorded."
      footer={
        <>
          <Button variant="outline" onClick={onClose}>
            Close
          </Button>
          <Button loading={check.pending} disabled={!token.trim()} onClick={async () => setResult((await check.run(token.trim())) ?? null)}>
            Check token
          </Button>
        </>
      }
    >
      <div className="space-y-4">
        <FormError error={check.error} />
        <Field label="User token (JWT)" htmlFor="ut-token">
          <Textarea id="ut-token" rows={5} className="font-mono text-xs" value={token} onChange={(e) => setToken(e.target.value)} placeholder="eyJhbGciOi…" />
        </Field>
        {result &&
          (result.valid ? (
            <Callout tone="info" title={`Valid: ${actingUserLabel(result.user)}`}>
              <dl className="mt-1 grid grid-cols-[8rem_1fr] gap-x-3 gap-y-1 text-sm">
                <dt className="text-slate-500">Subject</dt>
                <dd className="font-mono">{result.user.sub}</dd>
                <dt className="text-slate-500">Issuer</dt>
                <dd>{result.user.issuer}</dd>
                <dt className="text-slate-500">Groups</dt>
                <dd>{result.user.groups.length ? result.user.groups.join(', ') : 'none'}</dd>
                <dt className="text-slate-500">Permissions</dt>
                <dd>{permissionsText(result.user.permissions)}</dd>
              </dl>
            </Callout>
          ) : (
            <Callout tone="danger" title="Not accepted">
              {result.reason}
            </Callout>
          ))}
      </div>
    </Dialog>
  );
}

export function permissionsText(p: ActingUser['permissions']): string {
  if (!p) return 'No limits beyond the grant';
  const parts = [p.operations ? `operations: ${p.operations.join(', ') || 'none'}` : null, p.resources ? `resources: ${p.resources.join(', ') || 'none'}` : null].filter(Boolean);
  return parts.length ? parts.join('; ') : 'No limits beyond the grant';
}
