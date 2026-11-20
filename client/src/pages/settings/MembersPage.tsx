import { Check, Minus } from 'lucide-react';
import { PERMISSIONS, ROLE_DESCRIPTIONS, ROLE_LABELS, ROLE_PERMISSIONS, type Member, type Permission, type Role } from '@token-vault/shared';
import { usePost } from '@/hooks/useApi';
import { useAuth } from '@/context/AuthContext';
import { api } from '@/lib/api';
import { Card, CardBody, CardHeader } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Select } from '@/components/ui/form';
import { ErrorState } from '@/components/ui/feedback';
import { DataTable } from '@/components/ui/table';
import { PageHeader } from '@/components/ui/navigation';
import { useToast } from '@/components/ui/toast';
import { formatDateTime } from '@/lib/utils';

const ROLES: Role[] = ['OWNER', 'VAULT_ADMIN', 'SECURITY_ADMIN', 'DEVELOPER', 'AUDITOR'];
const MATRIX: { label: string; perm: Permission }[] = [
  { label: 'Manage organization & members', perm: PERMISSIONS.MEMBERS_MANAGE },
  { label: 'Configure webhook', perm: PERMISSIONS.WEBHOOK_MANAGE },
  { label: 'Register & rotate credentials', perm: PERMISSIONS.INTEGRATION_MANAGE },
  { label: 'Register & manage agents', perm: PERMISSIONS.AGENT_MANAGE },
  { label: 'Create grants', perm: PERMISSIONS.GRANT_MANAGE },
  { label: 'Approve grants', perm: PERMISSIONS.GRANT_APPROVE },
  { label: 'Revoke grants', perm: PERMISSIONS.GRANT_REVOKE },
  { label: 'Manage policies', perm: PERMISSIONS.POLICY_MANAGE },
  { label: 'View audit logs', perm: PERMISSIONS.AUDIT_READ },
];

export function MembersPage() {
  const { can, session, refresh } = useAuth();
  const toast = useToast();
  const { data, error, loading, reload, setData } = usePost<{ items: Member[] }>('/member/getall');
  const manage = can(PERMISSIONS.MEMBERS_MANAGE);

  async function changeRole(m: Member, role: Role) {
    try {
      const updated = await api.post<Member>('/member/save', { id: m.id, role });
      setData({ items: data!.items.map((x) => (x.id === m.id ? updated : x)) });
      toast.success('Role updated', `${m.fullName} is now ${ROLE_LABELS[role]}`);
      if (m.userId === session?.user.id) await refresh();
    } catch (e) {
      toast.error('Could not change role', (e as Error).message);
      void reload();
    }
  }

  return (
    <div className="space-y-6">
      <PageHeader title="Members & Roles" description="POC permissions use a small fixed RBAC matrix." breadcrumbs={[{ label: 'Settings' }, { label: 'Members & Roles' }]} />
      {error ? (
        <ErrorState error={error} onRetry={reload} />
      ) : (
        <Card>
          <CardHeader title="Members" description={manage ? 'Change roles inline. Every change is audited.' : 'Only Organization Owners can change roles.'} />
          <DataTable
            rows={data?.items}
            loading={loading}
            rowKey={(m) => m.id}
            columns={[
              {
                key: 'name',
                header: 'Member',
                cell: (m) => (
                  <div>
                    <p className="font-medium text-slate-900">
                      {m.fullName} {m.userId === session?.user.id && <Badge tone="blue">You</Badge>}
                    </p>
                    <p className="text-xs text-slate-500">{m.email}</p>
                  </div>
                ),
              },
              {
                key: 'role',
                header: 'Role',
                cell: (m) =>
                  manage ? (
                    <Select className="w-56" value={m.role} onChange={(e) => changeRole(m, e.target.value as Role)} aria-label={`Role for ${m.fullName}`}>
                      {ROLES.map((r) => (
                        <option key={r} value={r}>
                          {ROLE_LABELS[r]}
                        </option>
                      ))}
                    </Select>
                  ) : (
                    ROLE_LABELS[m.role]
                  ),
              },
              { key: 'since', header: 'Member since', cell: (m) => <span className="text-slate-500">{formatDateTime(m.createdAt)}</span>, hideBelow: 'md' },
            ]}
          />
        </Card>
      )}

      <Card>
        <CardHeader title="Role permission matrix" />
        <div className="overflow-x-auto">
          <table className="min-w-full text-sm">
            <thead className="bg-slate-50/80">
              <tr>
                <th className="px-4 py-2.5 text-left text-xs font-semibold uppercase tracking-wide text-slate-500">Capability</th>
                {ROLES.map((r) => (
                  <th key={r} className="px-4 py-2.5 text-center text-xs font-semibold uppercase tracking-wide text-slate-500">
                    {ROLE_LABELS[r].replace(' (read-only)', '')}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {MATRIX.map((row) => (
                <tr key={row.perm}>
                  <td className="px-4 py-2.5 text-slate-700">{row.label}</td>
                  {ROLES.map((r) => (
                    <td key={r} className="px-4 py-2.5 text-center">
                      {ROLE_PERMISSIONS[r].includes(row.perm) ? <Check className="mx-auto h-4 w-4 text-emerald-600" /> : <Minus className="mx-auto h-4 w-4 text-slate-300" />}
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <CardBody className="grid gap-3 border-t border-slate-100 sm:grid-cols-2 lg:grid-cols-3">
          {ROLES.map((r) => (
            <div key={r}>
              <p className="text-sm font-medium text-slate-800">{ROLE_LABELS[r]}</p>
              <p className="text-xs text-slate-500">{ROLE_DESCRIPTIONS[r]}</p>
            </div>
          ))}
        </CardBody>
      </Card>
    </div>
  );
}
