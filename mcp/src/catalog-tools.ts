import { z, type ZodRawShape, type ZodTypeAny } from 'zod';
import type { AgentOperationsBody, AgentResourceField } from '@token-vault/shared';

export type ProviderShape = AgentOperationsBody['providers'][number];
export type OperationShape = ProviderShape['operations'][number];

/** GitHub operations that have hand-written tools (stable names, tailored descriptions). */
export const CURATED_GITHUB_OPERATIONS = new Set(['github.repositories.read', 'github.contents.read', 'github.issues.list', 'github.issues.create']);

/** MCP tool names allow [A-Za-z0-9_-]{1,64}: "slack.messages.post" -> "slack_messages_post". */
export const toolNameFor = (operationId: string) => operationId.replace(/[^A-Za-z0-9_]/g, '_').slice(0, 64);

export interface CatalogTool {
  name: string;
  title: string;
  description: string;
  provider: { key: string; name: string };
  operation: string;
  /** The primary resource's name (e.g. "channel"), used to narrow grants and access requests. */
  resourceName: string;
  inputSchema: ZodRawShape;
  annotations: { readOnlyHint: boolean; destructiveHint: boolean; idempotentHint: boolean; openWorldHint: boolean };
  /** Splits validated tool arguments into the Token Vault request parts. */
  split(args: Record<string, unknown>): { resource: Record<string, string>; input: Record<string, unknown>; integration?: string };
}

function pattern(f: AgentResourceField): RegExp | null {
  try {
    return new RegExp(f.pattern, f.case_insensitive ? 'i' : '');
  } catch {
    return null; // Token Vault validates the value anyway.
  }
}

function resourceSchema(f: AgentResourceField, required: boolean): ZodTypeAny {
  const re = pattern(f);
  let s = z.string().min(1).max(500);
  if (re) s = s.regex(re, `Not a valid ${f.label.toLowerCase()}${f.example ? ` (e.g. ${f.example})` : ''}`);
  const described = s.describe(`${f.label}${f.example ? `, e.g. ${f.example}` : ''}`);
  return required ? described : described.optional();
}

function inputSchema(i: OperationShape['input'][number]): ZodTypeAny {
  const base = i.type === 'number' ? z.number() : i.type === 'boolean' ? z.boolean() : z.string().max(i.max_length ?? 100_000);
  const described = base.describe(i.label ?? i.name);
  return i.required ? described : described.optional();
}

/** One MCP tool per non-destructive operation of the given providers (curated GitHub ones excluded). */
export function catalogTools(body: AgentOperationsBody): CatalogTool[] {
  return body.providers.flatMap((p) => p.operations.filter((o) => o.risk !== 'destructive' && !(p.key === 'github' && CURATED_GITHUB_OPERATIONS.has(o.id))).map((o) => buildTool(p, o)));
}

function buildTool(p: ProviderShape, o: OperationShape): CatalogTool {
  const shape: ZodRawShape = {};
  const resourceKeys = [p.resource, ...p.resource_fields].map((f) => f.name);
  shape[p.resource.name] = resourceSchema(p.resource, o.requires_resource);
  for (const f of p.resource_fields) shape[f.name] = resourceSchema(f, false);

  // Inputs are flattened next to the resource; a name already taken is prefixed with "input_".
  const inputKeys = new Map<string, string>();
  for (const i of o.input) {
    let key = i.name;
    if (key === 'integration' || key in shape) key = `input_${i.name}`;
    inputKeys.set(key, i.name);
    shape[key] = inputSchema(i);
  }
  shape.integration = z.string().optional().describe(`Token Vault integration ID or name. Optional when this agent has only one ${p.name} integration (see token_vault_list_access).`);

  const effect = o.risk === 'read' ? 'Reads data' : `Changes data in ${p.name}`;
  return {
    name: toolNameFor(o.id),
    title: `${p.name}: ${o.label}`,
    description: `${o.label} (${p.name}, operation ${o.id}) through Token Vault. ${o.description ? `${o.description} ` : ''}${effect}; only works where an administrator has granted it. The ${p.name} credential never reaches the agent.`,
    provider: { key: p.key, name: p.name },
    operation: o.id,
    resourceName: p.resource.name,
    inputSchema: shape,
    annotations: { readOnlyHint: o.risk === 'read', destructiveHint: false, idempotentHint: o.risk === 'read', openWorldHint: true },
    split(args) {
      const resource: Record<string, string> = {};
      for (const k of resourceKeys) if (typeof args[k] === 'string') resource[k] = args[k] as string;
      const input: Record<string, unknown> = {};
      for (const [key, name] of inputKeys) if (args[key] !== undefined) input[name] = args[key];
      return { resource, input, integration: typeof args.integration === 'string' ? args.integration : undefined };
    },
  };
}
