import type { OnBehalfOfMode } from '@token-vault/shared';
import { Field, Input, Select } from '@/components/ui/form';

export const ON_BEHALF_OF: { value: OnBehalfOfMode; label: string; hint: string }[] = [
  { value: 'ALLOWED', label: 'For itself or for a signed-in user', hint: 'Requests may carry a user token. When they do, the user is recorded and their own permissions apply.' },
  { value: 'REQUIRED', label: 'Only on behalf of a signed-in user', hint: 'Every request must carry a valid user token: the agent can never act on its own.' },
  { value: 'NOT_ALLOWED', label: 'Only for itself', hint: 'Requests carrying a user token are denied (for background jobs and service agents).' },
];

/** "Only on behalf of a signed-in user in engineering, ops", for summaries. */
export function actingForText(mode: OnBehalfOfMode | undefined, groups: string[] | undefined): string {
  const label = ON_BEHALF_OF.find((o) => o.value === (mode ?? 'ALLOWED'))!.label;
  return mode !== 'NOT_ALLOWED' && groups?.length ? `${label}; users in ${groups.join(', ')}` : label;
}

/** Grant fields: whether the agent acts for itself, for users, or either; and which user groups. */
export function ActingForFields({ mode, groups, onChange, errors = {} }: { mode: OnBehalfOfMode; groups: string; onChange: (v: { mode?: OnBehalfOfMode; groups?: string }) => void; errors?: Record<string, string> }) {
  return (
    <>
      <Field label="Acting for users" htmlFor="grant-on-behalf-of" error={errors.onBehalfOf} hint={ON_BEHALF_OF.find((o) => o.value === mode)?.hint}>
        <Select id="grant-on-behalf-of" value={mode} onChange={(e) => onChange({ mode: e.target.value as OnBehalfOfMode })}>
          {ON_BEHALF_OF.map((o) => (
            <option key={o.value} value={o.value}>
              {o.label}
            </option>
          ))}
        </Select>
      </Field>
      {mode !== 'NOT_ALLOWED' && (
        <Field label="Allowed user groups (optional)" htmlFor="grant-user-groups" error={errors.allowedUserGroups ?? errors['allowedUserGroups.0']} hint="Comma separated, from the user token's groups claim. Empty: any verified user.">
          <Input id="grant-user-groups" value={groups} onChange={(e) => onChange({ groups: e.target.value })} placeholder="engineering, support" invalid={!!errors.allowedUserGroups} />
        </Field>
      )}
    </>
  );
}
