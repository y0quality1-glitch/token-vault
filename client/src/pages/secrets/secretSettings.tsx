import { SECRET_NAME, SECRET_TAG, type SecretTypeInfo, type SecretView } from '@token-vault/shared';
import { fromLocalInput, splitList, toLocalInput } from '@/lib/utils';
import { Checkbox, Field, Input, Textarea } from '@/components/ui/form';

/** The descriptive part of a secret, shared by the create form and "Edit metadata": name, description, tags, expiry, rotation. */
export interface SettingsValues {
  name: string;
  description: string;
  tags: string;
  /** datetime-local value; empty = no expiry. */
  expiresAt: string;
  rotationEnabled: boolean;
  rotationIntervalDays: string;
}

export const SETTINGS_FIELDS = ['name', 'description', 'tags', 'expiresAt', 'rotationEnabled', 'rotationIntervalDays'];

export function settingsForType(type: SecretTypeInfo): SettingsValues {
  const days = type.lifecycle.expiration ? type.defaults.expiresInDays : undefined;
  return {
    name: '',
    description: '',
    tags: '',
    expiresAt: days ? toLocalInput(new Date(Date.now() + days * 86400e3)) : '',
    rotationEnabled: type.lifecycle.rotation && !!type.defaults.rotationIntervalDays,
    rotationIntervalDays: type.lifecycle.rotation && type.defaults.rotationIntervalDays ? String(type.defaults.rotationIntervalDays) : '',
  };
}

export function settingsFromSecret(s: SecretView): SettingsValues {
  return {
    name: s.name,
    description: s.description,
    tags: s.tags.join(', '),
    expiresAt: s.expiresAt ? toLocalInput(s.expiresAt) : '',
    rotationEnabled: s.rotation.enabled,
    rotationIntervalDays: s.rotation.intervalDays ? String(s.rotation.intervalDays) : '',
  };
}

export function validateSettings(type: SecretTypeInfo, v: SettingsValues, opts: { allowPastExpiry?: boolean } = {}): Record<string, string> {
  const e: Record<string, string> = {};
  if (!v.name.trim()) e.name = 'Name is required';
  else if (!SECRET_NAME.test(v.name.trim())) e.name = 'Letters, digits, spaces and . _ / - (at most 120 characters, starting with a letter or digit)';
  if (v.description.length > 500) e.description = 'At most 500 characters';
  const tags = splitList(v.tags);
  if (tags.length > 20) e.tags = 'At most 20 tags';
  else if (tags.some((t) => !SECRET_TAG.test(t))) e.tags = 'Tags are lower-case letters, digits and : . _ - (at most 40 characters)';
  if (v.expiresAt) {
    const t = Date.parse(fromLocalInput(v.expiresAt));
    if (Number.isNaN(t)) e.expiresAt = 'Not a valid date';
    else if (!opts.allowPastExpiry && t <= Date.now()) e.expiresAt = 'Must be in the future';
    else if (!type.lifecycle.expiration) e.expiresAt = `${type.name} secrets do not expire`;
  }
  if (v.rotationEnabled) {
    const n = Number(v.rotationIntervalDays);
    if (!v.rotationIntervalDays.trim()) e.rotationIntervalDays = 'Give a rotation interval in days';
    else if (!Number.isInteger(n) || n < 1 || n > 3650) e.rotationIntervalDays = 'A whole number of days between 1 and 3650';
  }
  return e;
}

export function settingsBody(v: SettingsValues) {
  const days = v.rotationIntervalDays.trim() ? Number(v.rotationIntervalDays) : null;
  return {
    name: v.name.trim(),
    description: v.description.trim(),
    tags: [...new Set(splitList(v.tags))],
    expiresAt: v.expiresAt ? fromLocalInput(v.expiresAt) : null,
    rotationEnabled: v.rotationEnabled,
    rotationIntervalDays: v.rotationEnabled ? days : null,
  };
}

export function NameFields({ value, onChange, errors }: { value: SettingsValues; onChange: (v: SettingsValues) => void; errors: Record<string, string> }) {
  const set = (p: Partial<SettingsValues>) => onChange({ ...value, ...p });
  return (
    <div className="grid gap-4 sm:grid-cols-2">
      <Field label="Name" htmlFor="secret-name" required error={errors.name} hint="Unique within the project, workspace and environment.">
        <Input id="secret-name" value={value.name} onChange={(e) => set({ name: e.target.value })} invalid={!!errors.name} placeholder="orders-db primary" data-testid="secret-name" />
      </Field>
      <Field label="Tags" htmlFor="secret-tags" error={errors.tags} hint="Comma separated, lower case (e.g. team:payments, pci)">
        <Input id="secret-tags" value={value.tags} onChange={(e) => set({ tags: e.target.value })} invalid={!!errors.tags} data-testid="secret-tags" />
      </Field>
      <Field label="Description" htmlFor="secret-description" error={errors.description} className="sm:col-span-2">
        <Textarea id="secret-description" rows={2} value={value.description} onChange={(e) => set({ description: e.target.value })} invalid={!!errors.description} data-testid="secret-description" />
      </Field>
    </div>
  );
}

export function LifecycleFields({ type, value, onChange, errors }: { type: SecretTypeInfo; value: SettingsValues; onChange: (v: SettingsValues) => void; errors: Record<string, string> }) {
  const set = (p: Partial<SettingsValues>) => onChange({ ...value, ...p });
  return (
    <div className="grid gap-4 sm:grid-cols-2">
      <Field label="Expires" htmlFor="secret-expires" error={errors.expiresAt} hint={type.lifecycle.expiration ? 'Leave empty for no expiry.' : `${type.name} secrets do not expire.`}>
        <Input id="secret-expires" type="datetime-local" value={value.expiresAt} disabled={!type.lifecycle.expiration} onChange={(e) => set({ expiresAt: e.target.value })} invalid={!!errors.expiresAt} data-testid="secret-expires" />
      </Field>
      <div className="space-y-3">
        <Checkbox
          id="secret-rotation"
          checked={value.rotationEnabled}
          disabled={!type.lifecycle.rotation}
          onChange={(c) => set({ rotationEnabled: c, rotationIntervalDays: c && !value.rotationIntervalDays ? String(type.defaults.rotationIntervalDays ?? 90) : value.rotationIntervalDays })}
          label="Rotation reminder"
          description={type.lifecycle.rotation ? 'Marks the secret for rotation every N days.' : `${type.name} secrets are not rotated.`}
        />
        {errors.rotationEnabled && <p className="text-xs text-red-600">{errors.rotationEnabled}</p>}
        {value.rotationEnabled && (
          <Field label="Rotation interval (days)" htmlFor="secret-rotation-days" error={errors.rotationIntervalDays}>
            <Input id="secret-rotation-days" type="number" min={1} max={3650} step={1} value={value.rotationIntervalDays} onChange={(e) => set({ rotationIntervalDays: e.target.value })} invalid={!!errors.rotationIntervalDays} data-testid="secret-rotation-days" />
          </Field>
        )}
      </div>
    </div>
  );
}
