/**
 * What a policy's `operations` list may contain. Selectors are matched against the live
 * catalog at request time, so an operation published later is covered too:
 *
 *   "*"                   any operation
 *   "github.issues.create" one operation
 *   "github.*"            every operation of an application
 *   "risk:read" | "risk:write" | "risk:destructive"   every operation of that risk, in any application
 *   "github:write"        every operation of that risk in one application
 */
export type OperationRisk = 'read' | 'write' | 'destructive';
export const OPERATION_RISKS: OperationRisk[] = ['read', 'write', 'destructive'];
export const RISK_LABELS: Record<OperationRisk, string> = { read: 'read', write: 'write', destructive: 'destructive' };

export interface OperationFacts {
  id: string;
  provider: string;
  risk: OperationRisk;
}

const PROVIDER = '[a-z][a-z0-9_-]*';
const APP_ALL = new RegExp(`^(${PROVIDER})\\.\\*$`);
const APP_RISK = new RegExp(`^(${PROVIDER}):(read|write|destructive)$`);
const ANY_RISK = /^risk:(read|write|destructive)$/;

export type ParsedSelector =
  | { kind: 'any' }
  | { kind: 'operation'; id: string }
  | { kind: 'provider'; provider: string }
  | { kind: 'risk'; risk: OperationRisk; provider?: string };

export function parseOperationSelector(s: string): ParsedSelector {
  if (s === '*') return { kind: 'any' };
  let m = ANY_RISK.exec(s);
  if (m) return { kind: 'risk', risk: m[1] as OperationRisk };
  m = APP_RISK.exec(s);
  if (m) return { kind: 'risk', risk: m[2] as OperationRisk, provider: m[1]! };
  m = APP_ALL.exec(s);
  if (m) return { kind: 'provider', provider: m[1]! };
  return { kind: 'operation', id: s };
}

export function operationSelectorMatches(selector: string, op: OperationFacts): boolean {
  const p = parseOperationSelector(selector);
  switch (p.kind) {
    case 'any':
      return true;
    case 'operation':
      return p.id === op.id;
    case 'provider':
      return p.provider === op.provider;
    case 'risk':
      return p.risk === op.risk && (!p.provider || p.provider === op.provider);
  }
}

/** Problem with a selector given the known operations and applications, or null. */
export function operationSelectorProblem(selector: string, known: { operationIds: string[]; providers: string[] }): string | null {
  const p = parseOperationSelector(selector);
  if (p.kind === 'operation') return known.operationIds.includes(p.id) ? null : `Unknown operation "${p.id}"`;
  if ((p.kind === 'provider' || (p.kind === 'risk' && p.provider)) && !known.providers.includes((p as { provider: string }).provider)) {
    return `Unknown application "${(p as { provider: string }).provider}"`;
  }
  return null;
}

/** The application a selector is tied to, or null for application-independent ones ("*", "risk:write"). */
export function selectorApplication(selector: string, providerOf: (operationId: string) => string | undefined): string | null {
  const p = parseOperationSelector(selector);
  if (p.kind === 'provider') return p.provider;
  if (p.kind === 'risk') return p.provider ?? null;
  if (p.kind === 'operation') return providerOf(p.id) ?? null;
  return null;
}

/**
 * Narrows a policy's operation selectors to one application (when its "where" is one
 * application or integration): selectors of other applications are dropped, and broad ones
 * are tied to the application ("*" -> "github.*", "risk:write" -> "github:write") so the
 * policy keeps its meaning if its "where" is widened later. With no application, unchanged.
 */
export function scopeSelectors(selectors: string[], application: string | null, providerOf: (operationId: string) => string | undefined): string[] {
  if (!application) return selectors;
  const out = selectors.flatMap((s) => {
    const p = parseOperationSelector(s);
    if (p.kind === 'any') return [`${application}.*`];
    if (p.kind === 'risk' && !p.provider) return [`${application}:${p.risk}`];
    return selectorApplication(s, providerOf) === application ? [s] : [];
  });
  return [...new Set(out)];
}

export function describeOperationSelector(selector: string, labels: { operation: (id: string) => string; provider: (key: string) => string }): string {
  const p = parseOperationSelector(selector);
  switch (p.kind) {
    case 'any':
      return 'Any operation';
    case 'operation':
      return labels.operation(p.id);
    case 'provider':
      return `All ${labels.provider(p.provider)} operations`;
    case 'risk':
      return p.provider ? `All ${labels.provider(p.provider)} ${RISK_LABELS[p.risk]} operations` : `All ${RISK_LABELS[p.risk]} operations`;
  }
}
