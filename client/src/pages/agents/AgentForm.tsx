import { useEffect, useState } from 'react';
import type { Agent, AgentType, Environment } from '@token-vault/shared';
import { Field, Input, Select, Textarea } from '@/components/ui/form';
import { splitList } from '@/lib/utils';

export interface AgentFormValues {
  name: string;
  description: string;
  environment: Environment;
  ownerTeam: string;
  agentType: AgentType;
  callbackUrl: string;
  allowedCidrs: string;
}

export const emptyAgentForm: AgentFormValues = { name: '', description: '', environment: 'development', ownerTeam: '', agentType: 'AI_AGENT', callbackUrl: '', allowedCidrs: '' };

export function agentToForm(a: Agent): AgentFormValues {
  return { name: a.name, description: a.description, environment: a.environment, ownerTeam: a.ownerTeam, agentType: a.agentType, callbackUrl: a.callbackUrl, allowedCidrs: a.allowedCidrs.join(', ') };
}

export function formToBody(f: AgentFormValues) {
  return { ...f, allowedCidrs: splitList(f.allowedCidrs) };
}

export function validateAgentForm(f: AgentFormValues): Record<string, string> {
  const e: Record<string, string> = {};
  if (f.name.trim().length < 3) e.name = 'Name must be at least 3 characters';
  if (!f.ownerTeam.trim()) e.ownerTeam = 'Owner / team is required';
  if (f.callbackUrl && !/^https?:\/\/\S+$/.test(f.callbackUrl)) e.callbackUrl = 'Enter a valid URL';
  return e;
}

export function AgentFields({ value, onChange, errors, lockType }: { value: AgentFormValues; onChange: (v: AgentFormValues) => void; errors: Record<string, string>; lockType?: boolean }) {
  const [v, setV] = useState(value);
  useEffect(() => setV(value), [value]);
  const set = (k: keyof AgentFormValues) => (e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement>) => {
    const next = { ...v, [k]: e.target.value };
    setV(next);
    onChange(next);
  };
  return (
    <div className="space-y-4">
      <div className="grid gap-4 sm:grid-cols-2">
        <Field label="Agent name" required error={errors.name}>
          <Input value={v.name} onChange={set('name')} placeholder="GitHub Assistant" invalid={!!errors.name} />
        </Field>
        <Field label="Agent type" required error={errors.agentType}>
          <Select value={v.agentType} onChange={set('agentType')} disabled={lockType}>
            <option value="AI_AGENT">AI Agent</option>
            <option value="APPLICATION">Application</option>
            <option value="SERVICE">Service</option>
          </Select>
        </Field>
        <Field label="Environment" required error={errors.environment}>
          <Select value={v.environment} onChange={set('environment')}>
            <option value="development">Development</option>
            <option value="staging">Staging</option>
            <option value="production">Production</option>
          </Select>
        </Field>
        <Field label="Owner / team" required error={errors.ownerTeam}>
          <Input value={v.ownerTeam} onChange={set('ownerTeam')} placeholder="Platform AI" invalid={!!errors.ownerTeam} />
        </Field>
      </div>
      <Field label="Description" error={errors.description}>
        <Textarea rows={2} value={v.description} onChange={set('description')} placeholder="What does this agent do?" />
      </Field>
      <div className="grid gap-4 sm:grid-cols-2">
        <Field label="Callback URL (optional)" error={errors.callbackUrl}>
          <Input value={v.callbackUrl} onChange={set('callbackUrl')} placeholder="https://agent.internal/callback" invalid={!!errors.callbackUrl} />
        </Field>
        <Field label="Allowed network / IP range (optional)" error={errors['allowedCidrs.0'] ?? errors.allowedCidrs} hint="IPv4 CIDRs, comma separated. Enforced on every request.">
          <Input value={v.allowedCidrs} onChange={set('allowedCidrs')} placeholder="10.20.0.0/16" className="font-mono text-xs" />
        </Field>
      </div>
    </div>
  );
}
