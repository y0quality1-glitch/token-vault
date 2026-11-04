import { useEffect, useState } from 'react';
import { RotateCcw } from 'lucide-react';
import { PERMISSIONS, type Environment, type Organization } from '@token-vault/shared';
import { useMutation } from '@/hooks/useApi';
import { useAuth } from '@/context/AuthContext';
import { api } from '@/lib/api';
import { Button } from '@/components/ui/button';
import { Card, CardBody, CardHeader } from '@/components/ui/card';
import { Field, Input, Select } from '@/components/ui/form';
import { Callout, FormError } from '@/components/ui/feedback';
import { ConfirmDialog } from '@/components/ui/dialog';
import { PageHeader } from '@/components/ui/navigation';
import { Mono } from '@/components/ui/secret';
import { useToast } from '@/components/ui/toast';
import { formatDateTime } from '@/lib/utils';

export function OrganizationSettingsPage() {
  const { session, can, refresh } = useAuth();
  const toast = useToast();
  const org = session!.currentOrganization!;
  const [form, setForm] = useState({ name: org.name, environment: org.environment as Environment });
  const [reset, setReset] = useState(false);
  const [resetting, setResetting] = useState(false);
  const save = useMutation((body: unknown) => api.patch<Organization>('/organizations/current', body));
  const manage = can(PERMISSIONS.ORG_MANAGE);
  useEffect(() => setForm({ name: org.name, environment: org.environment }), [org]);

  return (
    <div className="space-y-6">
      <PageHeader title="Organization" description="Workspace settings for your Token Vault organization." breadcrumbs={[{ label: 'Settings' }, { label: 'Organization' }]} />
      {!manage && <Callout tone="info">Only Organization Owners can change these settings.</Callout>}
      <Card>
        <CardHeader title="General" />
        <CardBody className="space-y-4">
          <FormError error={save.error} />
          <div className="grid gap-4 md:grid-cols-2">
            <Field label="Organization name" error={save.fieldErrors.name}>
              <Input value={form.name} disabled={!manage} onChange={(e) => setForm({ ...form, name: e.target.value })} />
            </Field>
            <Field label="Default environment">
              <Select value={form.environment} disabled={!manage} onChange={(e) => setForm({ ...form, environment: e.target.value as Environment })}>
                <option value="development">Development</option>
                <option value="staging">Staging</option>
                <option value="production">Production</option>
              </Select>
            </Field>
            <Field label="Slug" hint="Used to attribute unauthenticated agent attempts in the audit log">
              <Input value={org.slug} disabled className="font-mono" />
            </Field>
            <Field label="Organization ID">
              <div className="flex h-9 items-center">
                <Mono>{org.id}</Mono>
              </div>
            </Field>
          </div>
          <p className="text-xs text-slate-500">Created {formatDateTime(org.createdAt)} · Status {org.status.toLowerCase()}</p>
        </CardBody>
        {manage && (
          <div className="flex justify-end border-t border-slate-100 px-5 py-3.5">
            <Button
              loading={save.pending}
              onClick={async () => {
                if (await save.run(form)) {
                  await refresh();
                  toast.success('Organization updated');
                }
              }}
            >
              Save changes
            </Button>
          </div>
        )}
      </Card>

      {can(PERMISSIONS.DEMO_RESET) && (
        <Card className="border-red-200">
          <CardHeader title="Demo controls" description="Proof-of-concept only" />
          <CardBody className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
            <p className="text-sm text-slate-600">Reset all control-plane data (organizations, agents, grants, policies, audit) to the seeded demonstration state.</p>
            <Button variant="danger-outline" onClick={() => setReset(true)}>
              <RotateCcw className="h-4 w-4" /> Reset demo data
            </Button>
          </CardBody>
        </Card>
      )}
      <ConfirmDialog
        open={reset}
        onClose={() => setReset(false)}
        title="Reset demo data?"
        description="Every change made during the demo is discarded and issued agent credentials become invalid."
        confirmText="RESET"
        confirmLabel="Reset demo"
        loading={resetting}
        onConfirm={async () => {
          setResetting(true);
          try {
            await api.post('/demo/reset');
            await refresh();
            toast.success('Demo data reset');
            setReset(false);
          } catch (e) {
            toast.error('Reset failed', (e as Error).message);
          } finally {
            setResetting(false);
          }
        }}
      />
    </div>
  );
}
