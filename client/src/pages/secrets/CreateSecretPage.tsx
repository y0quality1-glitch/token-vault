import { useMemo, useState } from 'react';
import { Link, useNavigate, useSearchParams } from 'react-router-dom';
import { ArrowLeft, LockKeyhole } from 'lucide-react';
import { SECRET_CERTIFICATE_TYPES, SECRET_KEY_CAPABILITIES, SECRET_SCOPE_SLUG, type Environment, type SecretDetail, type SecretTypeInfo } from '@token-vault/shared';
import { useMutation } from '@/hooks/useApi';
import { api } from '@/lib/api';
import { ENV_LABELS } from '@/lib/utils';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardBody, CardHeader } from '@/components/ui/card';
import { Checkbox, Field, Input, Select } from '@/components/ui/form';
import { Callout, ErrorState, PageSkeleton } from '@/components/ui/feedback';
import { PageHeader, Stepper } from '@/components/ui/navigation';
import { useToast } from '@/components/ui/toast';
import { ApiErrorCallout, SecretTypePicker, TypeFields, checkMetadata, checkPayload, initialValues, isArchivedType, useSecretTypes, type FieldValues } from './secretUi';
import { LifecycleFields, NameFields, SETTINGS_FIELDS, settingsBody, settingsForType, validateSettings, type SettingsValues } from './secretSettings';

/** New secret: pick a type, then fill a form generated from it. */
export function CreateSecretPage() {
  const [params, setParams] = useSearchParams();
  const types = useSecretTypes();
  const typeKey = params.get('type');
  // Archived custom types take no new secrets.
  const available = (types.data?.types ?? []).filter((t) => !isArchivedType(t));
  const type = available.find((t) => t.key === typeKey) ?? null;

  if (types.error) return <ErrorState error={types.error} onRetry={types.reload} />;
  if (types.loading && !types.data) return <PageSkeleton />;

  return (
    <div className="space-y-6">
      <PageHeader
        title="New secret"
        description="The value is validated against its type, encrypted and stored on your customer webhook. Token Vault keeps only metadata and a fingerprint."
        breadcrumbs={[{ label: 'Secrets', to: '/secrets' }, { label: 'New secret' }]}
      />
      <Stepper steps={['Choose a type', 'Enter the secret']} current={type ? 1 : 0} />
      {type ? (
        <CreateSecretForm key={type.key} type={type} onChangeType={() => setParams({})} />
      ) : (
        <Card>
          <CardHeader
            title="Secret type"
            description="The type decides the fields of the secret, which of them are sensitive, and its lifecycle."
            actions={
              <Link className="text-xs text-brand-700 hover:underline" to="/secrets/types">
                All secret types
              </Link>
            }
          />
          <CardBody>
            <SecretTypePicker types={available} value={typeKey} onChange={(key) => setParams({ type: key })} />
          </CardBody>
        </Card>
      )}
    </div>
  );
}

function CreateSecretForm({ type, onChangeType }: { type: SecretTypeInfo; onChangeType: () => void }) {
  const navigate = useNavigate();
  const toast = useToast();
  const [settings, setSettings] = useState<SettingsValues>(() => settingsForType(type));
  const [payload, setPayload] = useState<FieldValues>(() => initialValues(type.fields));
  const [metadata, setMetadata] = useState<FieldValues>(() => initialValues(type.metadata));
  const [project, setProject] = useState('');
  const [workspace, setWorkspace] = useState('');
  const [environment, setEnvironment] = useState<Environment | ''>('');
  const [activate, setActivate] = useState(true);
  const [errors, setErrors] = useState<Record<string, string>>({});
  const submit = useMutation((body: unknown) => api.post<SecretDetail>('/secret/save', body));

  const allErrors = useMemo(() => ({ ...submit.fieldErrors, ...errors }), [submit.fieldErrors, errors]);
  const hasMetadata = Object.keys(type.metadata).length > 0;

  async function onSubmit() {
    const p = checkPayload(type, payload);
    const m = checkMetadata(type, metadata);
    const e: Record<string, string> = { ...validateSettings(type, settings), ...p.issues, ...m.issues };
    if (project.trim() && !SECRET_SCOPE_SLUG.test(project.trim())) e.project = 'Lower-case letters, digits and dashes (at most 63 characters)';
    if (workspace.trim() && !SECRET_SCOPE_SLUG.test(workspace.trim())) e.workspace = 'Lower-case letters, digits and dashes (at most 63 characters)';
    if (!environment) e.environment = 'Choose development, staging or production';
    setErrors(e);
    if (Object.keys(e).length) {
      submit.setError(null);
      return;
    }
    const s = settingsBody(settings);
    const r = await submit.run({
      typeKey: type.key,
      ...s,
      description: s.description || undefined,
      project: project.trim() || undefined,
      workspace: workspace.trim() || undefined,
      environment,
      metadata: m.value,
      payload: p.value,
      expiresAt: type.lifecycle.expiration ? s.expiresAt : null,
      rotationEnabled: type.lifecycle.rotation ? s.rotationEnabled : false,
      activate,
    });
    if (r) {
      // Clear the value from component state before leaving.
      setPayload(initialValues(type.fields));
      toast.success('Secret created', `${r.name} · version ${r.activeVersion ?? 1}`);
      navigate(`/secrets/${r.id}`);
    }
  }

  return (
    <form
      className="space-y-6"
      data-testid="secret-create-form"
      onSubmit={(e) => {
        e.preventDefault();
        void onSubmit();
      }}
      autoComplete="off"
    >
      <Card>
        <CardHeader
          title={
            <span className="flex flex-wrap items-center gap-2">
              {type.name} <Badge>{type.categoryLabel}</Badge>
              {type.source === 'custom' && <Badge tone="amber">Custom type</Badge>}
            </span>
          }
          description={type.description || undefined}
          icon={<LockKeyhole className="h-4 w-4" />}
          actions={
            <Button variant="ghost" size="sm" onClick={onChangeType} data-testid="secret-change-type">
              <ArrowLeft className="h-3.5 w-3.5" /> Change type
            </Button>
          }
        />
        <CardBody className="space-y-4">
          <NameFields value={settings} onChange={setSettings} errors={allErrors} />
          <div className="grid gap-4 sm:grid-cols-3">
            <Field label="Project" htmlFor="secret-project" error={allErrors.project} hint="Defaults to “default”.">
              <Input id="secret-project" value={project} onChange={(e) => setProject(e.target.value)} placeholder="default" invalid={!!allErrors.project} data-testid="secret-project" />
            </Field>
            <Field label="Workspace" htmlFor="secret-workspace" error={allErrors.workspace} hint="Defaults to “default”.">
              <Input id="secret-workspace" value={workspace} onChange={(e) => setWorkspace(e.target.value)} placeholder="default" invalid={!!allErrors.workspace} data-testid="secret-workspace" />
            </Field>
            <Field label="Environment" htmlFor="secret-environment" required error={allErrors.environment}>
              <Select id="secret-environment" value={environment} onChange={(e) => setEnvironment(e.target.value as Environment)} invalid={!!allErrors.environment} data-testid="secret-environment">
                <option value="">Choose…</option>
                {Object.entries(ENV_LABELS).map(([k, label]) => (
                  <option key={k} value={k}>
                    {label}
                  </option>
                ))}
              </Select>
            </Field>
          </div>
        </CardBody>
      </Card>

      <Card>
        <CardHeader title="Value" description="Sensitive fields are masked here and everywhere else; they are only shown by an audited reveal." />
        <CardBody className="space-y-4" data-testid="secret-payload-fields">
          {type.lifecycle.dynamic && (
            <Callout tone="info" title="Administrative credential">
              This is the administrative credential leases are created with; applications never receive it. Each lease gets its own short-lived credential, created by the customer webhook and ended when the lease ends. Applications ask for a lease with <code className="font-mono text-[12px]">tv.secrets.lease()</code>.
            </Callout>
          )}
          {SECRET_CERTIFICATE_TYPES[type.key] && (
            <div data-testid="secret-create-certificate-note">
              <Callout tone="info" title="Read from the certificate">
                The expiry and the descriptive details (subject, issuer, names) are read from the certificate when it is stored. A private key stored with it must belong to the certificate; one that does not is refused.
              </Callout>
            </div>
          )}
          {SECRET_KEY_CAPABILITIES[type.key] && (
            <div data-testid="secret-create-key-note">
              <Callout tone="info" title="Used without being read">
                Applications can use this key ({SECRET_KEY_CAPABILITIES[type.key]!.operations.join(', ')}) through an access grant without ever reading it; the customer webhook performs each operation.
                {SECRET_KEY_CAPABILITIES[type.key]!.external && ` The key itself stays in ${SECRET_KEY_CAPABILITIES[type.key]!.external === 'aws-kms' ? 'AWS KMS' : 'Vault Transit'}: store how the webhook reaches it.`}
              </Callout>
            </div>
          )}
          <TypeFields prefix="payload" fields={type.fields} values={payload} onChange={setPayload} errors={allErrors} />
          {allErrors.payload && <p className="text-xs text-red-600">{allErrors.payload}</p>}
        </CardBody>
      </Card>

      {hasMetadata && (
        <Card>
          <CardHeader title="Details" description="Descriptive attributes kept with the metadata (not secret)." />
          <CardBody data-testid="secret-metadata-fields">
            <TypeFields prefix="metadata" fields={type.metadata} values={metadata} onChange={setMetadata} errors={allErrors} />
          </CardBody>
        </Card>
      )}

      <Card>
        <CardHeader title="Lifecycle" />
        <CardBody className="space-y-4">
          <LifecycleFields type={type} value={settings} onChange={setSettings} errors={allErrors} />
          <Checkbox id="secret-activate" checked={activate} onChange={setActivate} label="Activate now" description="Otherwise the secret is created Pending and cannot be retrieved until it is activated." />
        </CardBody>
      </Card>

      <ApiErrorCallout error={submit.error} shownFields={[...SETTINGS_FIELDS, 'project', 'workspace', 'environment', 'payload']} />
      <Callout tone="security">The value is sent once to Token Vault, which passes it to your customer webhook for encryption. It is not kept in this browser after you leave the page.</Callout>
      <div className="flex justify-end gap-2">
        <Button variant="outline" onClick={() => navigate('/secrets')}>
          Cancel
        </Button>
        <Button type="submit" loading={submit.pending} data-testid="secret-create-submit">
          Create secret
        </Button>
      </div>
    </form>
  );
}
