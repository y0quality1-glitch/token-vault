import { useMemo, useState } from 'react';
import { Pencil, Plus, Timer, Trash2 } from 'lucide-react';
import { PERMISSIONS, SECRET_SCOPE_SLUG, type SecretPolicyScope, type SecretPolicySettings, type SecretPolicyView } from '@token-vault/shared';
import { useMutation, usePost } from '@/hooks/useApi';
import { useAuth } from '@/context/AuthContext';
import { api } from '@/lib/api';
import { formatDateTime, relativeTime } from '@/lib/utils';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card } from '@/components/ui/card';
import { Field, Input, Select } from '@/components/ui/form';
import { Callout, EmptyState, ErrorState } from '@/components/ui/feedback';
import { ConfirmDialog, Dialog } from '@/components/ui/dialog';
import { DataTable } from '@/components/ui/table';
import { PageHeader } from '@/components/ui/navigation';
import { useToast } from '@/components/ui/toast';
import { SecretsSectionTabs } from './secretAccess';
import { ApiErrorCallout } from './secretUi';

const SCOPE_LABELS: Record<SecretPolicyScope, string> = { ORGANIZATION: 'Organization', PROJECT: 'Project', WORKSPACE: 'Workspace' };
const SCOPE_ORDER: Record<SecretPolicyScope, number> = { ORGANIZATION: 0, PROJECT: 1, WORKSPACE: 2 };

type SettingKey = keyof SecretPolicySettings;
/** The four settings, their inputs and limits (as the server checks them). */
const SETTINGS: { key: SettingKey; label: string; hint: string; unit: string; min: number; max: number; testId: string }[] = [
  { key: 'expiryWarningDays', label: 'Expiry warning (days)', hint: 'Days before expiry when a secret becomes Expiring and people are notified.', unit: 'days before expiry', min: 1, max: 365, testId: 'secret-policy-warning' },
  { key: 'defaultExpiresInDays', label: 'Default expiry (days)', hint: 'Expiry given to new secrets, and to a secret again after each rotation.', unit: 'days', min: 1, max: 3650, testId: 'secret-policy-default-expiry' },
  { key: 'keepVersions', label: 'Keep versions', hint: 'Inactive versions kept: the newest n.', unit: 'newest', min: 0, max: 1000, testId: 'secret-policy-keep-versions' },
  { key: 'keepDays', label: 'Keep versions by age (days)', hint: 'Also kept: every version replaced less than this many days ago. Older ones are destroyed.', unit: 'days', min: 0, max: 3650, testId: 'secret-policy-keep-days' },
];

function settingText(key: SettingKey, v: number | null): string {
  if (v === null) return '—';
  if (key === 'keepVersions') return `Newest ${v}`;
  if (key === 'expiryWarningDays') return `${v} days before`;
  return `${v} days`;
}

function scopePath(p: Pick<SecretPolicyView, 'scope' | 'project' | 'workspace'>): string {
  if (p.scope === 'ORGANIZATION') return 'Every secret';
  if (p.scope === 'PROJECT') return p.project ?? '';
  return `${p.project ?? ''}/${p.workspace ?? ''}`;
}

/** Expiry and retention policies at organization, project and workspace level (spec 4.9.8, 4.9.12). */
export function SecretPoliciesPage() {
  const { can } = useAuth();
  const toast = useToast();
  const manage = can(PERMISSIONS.SECRET_MANAGE_VERSIONS);
  const { data, error, loading, reload } = usePost<{ items: SecretPolicyView[] }>('/secretPolicy/getall');
  const [editing, setEditing] = useState<SecretPolicyView | 'new' | null>(null);
  const [removing, setRemoving] = useState<SecretPolicyView | null>(null);
  const remove = useMutation(async (id: string) => {
    await api.del<unknown>(`/secretPolicy/delete/${id}`);
    return true;
  });

  const items = useMemo(
    () => [...(data?.items ?? [])].sort((a, b) => SCOPE_ORDER[a.scope] - SCOPE_ORDER[b.scope] || (a.project ?? '').localeCompare(b.project ?? '') || (a.workspace ?? '').localeCompare(b.workspace ?? '')),
    [data],
  );

  return (
    <div>
      <PageHeader
        title="Expiry and retention"
        description="When secrets warn before they expire, the expiry new secrets get, and how many replaced versions are kept."
        breadcrumbs={[{ label: 'Secrets', to: '/secrets' }, { label: 'Expiry and retention' }]}
        actions={
          manage && (
            <Button onClick={() => setEditing('new')} data-testid="secret-policy-new">
              <Plus className="h-4 w-4" /> New policy
            </Button>
          )
        }
      />
      <SecretsSectionTabs current="/secrets/policies" />
      <Callout tone="info" className="mb-4">
        The most specific level that sets a value wins: workspace, then project, then organization, then the secret type. A secret's own expiry date and rotation settings override all of them.
        {!manage && ' Only members with secret:manage_versions can change policies.'}
      </Callout>
      {error ? (
        <ErrorState error={error} onRetry={reload} />
      ) : (
        <Card data-testid="secret-policies">
          <DataTable
            rows={items}
            loading={loading && !data}
            rowKey={(p) => p.id}
            empty={
              <EmptyState
                icon={<Timer className="h-5 w-5" />}
                title="No policies yet"
                description="Without a policy each secret type's defaults apply, and replaced versions are kept until someone destroys them."
                action={
                  manage ? (
                    <Button variant="outline" onClick={() => setEditing('new')}>
                      <Plus className="h-4 w-4" /> New policy
                    </Button>
                  ) : undefined
                }
              />
            }
            columns={[
              {
                key: 'scope',
                header: 'Applies to',
                cell: (p) => (
                  <div className="min-w-0" data-testid="secret-policy-row" data-scope={p.scope} data-policy-id={p.id}>
                    <Badge tone={p.scope === 'ORGANIZATION' ? 'blue' : p.scope === 'PROJECT' ? 'violet' : 'gray'}>{SCOPE_LABELS[p.scope]}</Badge>
                    <span className={p.scope === 'ORGANIZATION' ? 'mt-1 block text-sm text-slate-600' : 'mt-1 block font-mono text-[13px] text-slate-800'}>{scopePath(p)}</span>
                  </div>
                ),
              },
              ...SETTINGS.map((x) => ({
                key: x.key,
                header: x.label.replace(/ \(days\)$/, ''),
                cell: (p: SecretPolicyView) => <span className={p[x.key] === null ? 'text-slate-400' : 'text-slate-700'}>{settingText(x.key, p[x.key])}</span>,
                hideBelow: x.key === 'expiryWarningDays' ? undefined : x.key === 'defaultExpiresInDays' ? ('md' as const) : ('lg' as const),
              })),
              {
                key: 'updated',
                header: 'Updated',
                cell: (p) => (
                  <span className="text-xs text-slate-500" title={formatDateTime(p.updatedAt)}>
                    {relativeTime(p.updatedAt)}
                    <span className="block">by {p.updatedBy.name}</span>
                  </span>
                ),
                hideBelow: 'xl',
              },
              {
                key: 'actions',
                header: '',
                className: 'text-right',
                cell: (p) =>
                  manage ? (
                    <div className="flex justify-end gap-1">
                      <Button variant="ghost" size="sm" onClick={() => setEditing(p)} data-testid="secret-policy-edit">
                        <Pencil className="h-3.5 w-3.5" /> Edit
                      </Button>
                      <Button variant="ghost" size="sm" className="text-red-700 hover:bg-red-50 hover:text-red-800" onClick={() => setRemoving(p)} data-testid="secret-policy-delete">
                        <Trash2 className="h-3.5 w-3.5" /> Delete
                      </Button>
                    </div>
                  ) : null,
              },
            ]}
          />
        </Card>
      )}
      {editing && (
        <PolicyDialog
          key={editing === 'new' ? 'new' : editing.id}
          policy={editing === 'new' ? null : editing}
          onClose={() => setEditing(null)}
          onDone={async (removed) => {
            setEditing(null);
            toast.success(removed ? 'Policy removed' : 'Policy saved', removed ? 'No setting was left, so the policy was removed.' : undefined);
            await reload();
          }}
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
              toast.success('Policy deleted');
              await reload();
            }
          }}
          loading={remove.pending}
          title="Delete policy"
          confirmLabel="Delete policy"
          description={
            <div className="space-y-2" data-testid="secret-policy-delete-dialog">
              <p>
                Secrets in <strong>{scopePath(removing)}</strong> fall back to the next broader level, or to their secret type's defaults.
              </p>
              <ApiErrorCallout error={remove.error} />
            </div>
          }
        />
      )}
    </div>
  );
}

type Values = { scope: SecretPolicyScope; project: string; workspace: string } & Record<SettingKey, string>;

function PolicyDialog({ policy, onClose, onDone }: { policy: SecretPolicyView | null; onClose: () => void; onDone: (removed: boolean) => void }) {
  const [v, setV] = useState<Values>(() => ({
    scope: policy?.scope ?? 'ORGANIZATION',
    project: policy?.project ?? '',
    workspace: policy?.workspace ?? '',
    expiryWarningDays: policy?.expiryWarningDays?.toString() ?? '',
    defaultExpiresInDays: policy?.defaultExpiresInDays?.toString() ?? '',
    keepVersions: policy?.keepVersions?.toString() ?? '',
    keepDays: policy?.keepDays?.toString() ?? '',
  }));
  const [errors, setErrors] = useState<Record<string, string>>({});
  const save = useMutation((body: unknown) => api.post<SecretPolicyView | { id: null; removed: true }>('/secretPolicy/save', body));
  const allErrors = { ...save.fieldErrors, ...errors };
  const set = (p: Partial<Values>) => setV((x) => ({ ...x, ...p }));
  const editing = !!policy;
  const allEmpty = SETTINGS.every((x) => !v[x.key].trim());

  async function submit() {
    const e: Record<string, string> = {};
    if (v.scope !== 'ORGANIZATION') {
      if (!v.project.trim()) e.project = 'Give the project';
      else if (!SECRET_SCOPE_SLUG.test(v.project.trim())) e.project = 'Lower-case letters, digits and dashes';
    }
    if (v.scope === 'WORKSPACE') {
      if (!v.workspace.trim()) e.workspace = 'Give the workspace';
      else if (!SECRET_SCOPE_SLUG.test(v.workspace.trim())) e.workspace = 'Lower-case letters, digits and dashes';
    }
    const settings = {} as Record<SettingKey, number | null>;
    for (const x of SETTINGS) {
      const raw = v[x.key].trim();
      const n = Number(raw);
      if (!raw) settings[x.key] = null;
      else if (!Number.isInteger(n) || n < x.min || n > x.max) e[x.key] = `A whole number from ${x.min} to ${x.max}, or empty`;
      else settings[x.key] = n;
    }
    setErrors(e);
    if (Object.keys(e).length) return;
    const r = await save.run({
      scope: v.scope,
      ...(v.scope !== 'ORGANIZATION' ? { project: v.project.trim() } : {}),
      ...(v.scope === 'WORKSPACE' ? { workspace: v.workspace.trim() } : {}),
      ...settings,
    });
    if (r) onDone('removed' in r && r.removed === true);
  }

  return (
    <Dialog
      open
      onClose={onClose}
      size="lg"
      title={editing ? `Edit ${SCOPE_LABELS[policy.scope].toLowerCase()} policy` : 'New policy'}
      description="Leave a setting empty to take it from a broader level. A policy with no setting is removed."
      footer={
        <>
          <Button variant="outline" onClick={onClose}>
            Cancel
          </Button>
          <Button loading={save.pending} onClick={submit} data-testid="secret-policy-save">
            {allEmpty && editing ? 'Remove policy' : 'Save policy'}
          </Button>
        </>
      }
    >
      <form
        className="space-y-5"
        data-testid="secret-policy-form"
        onSubmit={(e) => {
          e.preventDefault();
          void submit();
        }}
      >
        <div className="grid gap-4 sm:grid-cols-3">
          <Field label="Level" htmlFor="secret-policy-scope" error={allErrors.scope} hint={editing ? 'The level of a policy cannot change.' : undefined}>
            <Select id="secret-policy-scope" value={v.scope} disabled={editing} onChange={(e) => set({ scope: e.target.value as SecretPolicyScope })} data-testid="secret-policy-scope">
              <option value="ORGANIZATION">Organization</option>
              <option value="PROJECT">Project</option>
              <option value="WORKSPACE">Workspace</option>
            </Select>
          </Field>
          {v.scope !== 'ORGANIZATION' && (
            <Field label="Project" htmlFor="secret-policy-project" required error={allErrors.project}>
              <Input id="secret-policy-project" value={v.project} disabled={editing} onChange={(e) => set({ project: e.target.value })} invalid={!!allErrors.project} placeholder="payments" autoComplete="off" data-testid="secret-policy-project" />
            </Field>
          )}
          {v.scope === 'WORKSPACE' && (
            <Field label="Workspace" htmlFor="secret-policy-workspace" required error={allErrors.workspace}>
              <Input id="secret-policy-workspace" value={v.workspace} disabled={editing} onChange={(e) => set({ workspace: e.target.value })} invalid={!!allErrors.workspace} placeholder="checkout" autoComplete="off" data-testid="secret-policy-workspace" />
            </Field>
          )}
        </div>
        <p className="text-xs text-slate-500">The most specific level that sets a value wins: workspace, then project, then organization, then the secret type.</p>
        <div className="grid gap-4 sm:grid-cols-2">
          {SETTINGS.map((x) => (
            <Field key={x.key} label={x.label} htmlFor={x.testId} error={allErrors[x.key]} hint={x.hint}>
              <Input id={x.testId} type="number" min={x.min} max={x.max} step={1} value={v[x.key]} onChange={(e) => set({ [x.key]: e.target.value } as Partial<Values>)} invalid={!!allErrors[x.key]} placeholder="Not set" data-testid={x.testId} />
            </Field>
          ))}
        </div>
        {allEmpty && (
          <Callout tone={editing ? 'warning' : 'info'}>{editing ? 'Every setting is empty: saving removes this policy.' : 'Set at least one value; an empty policy is not stored.'}</Callout>
        )}
        <ApiErrorCallout error={save.error} shownFields={['scope', 'project', 'workspace', ...SETTINGS.map((x) => x.key)]} />
      </form>
    </Dialog>
  );
}
