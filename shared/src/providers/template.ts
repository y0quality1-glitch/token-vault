import type { FieldSpec, ResponseMap } from './schema';

/**
 * Placeholders: {resource.repository}, {input.title}, optionally with a default:
 * {resource.path|README.md}. Only the resource and input namespaces exist, so a
 * template can never reference a credential.
 */
const PLACEHOLDER = /\{([a-z]+\.[A-Za-z0-9_]+)(?:\|([^{}]*))?\}/g;
const WHOLE = /^\{([a-z]+\.[A-Za-z0-9_]+)(?:\|([^{}]*))?\}$/;

export interface Placeholder {
  name: string;
  fallback?: string;
}

export function placeholdersIn(s: string): Placeholder[] {
  return [...s.matchAll(PLACEHOLDER)].map((m) => ({ name: m[1]!, ...(m[2] !== undefined ? { fallback: m[2] } : {}) }));
}

export interface TemplateVars {
  resource: Record<string, string | undefined>;
  input: Record<string, unknown>;
}

export class TemplateError extends Error {}

function lookup(vars: TemplateVars, name: string): unknown {
  const [ns, key] = name.split('.', 2) as [string, string];
  if (ns === 'resource') return vars.resource[key];
  if (ns === 'input') return vars.input[key];
  return undefined;
}

const present = (v: unknown) => v !== undefined && v !== null && v !== '';

/** Renders a URL path. Each value is encoded per segment; empty, "." and ".." segments are refused. */
export function renderPath(path: string, vars: TemplateVars): string {
  return path.replace(PLACEHOLDER, (_m, name: string, fallback?: string) => {
    const v = lookup(vars, name);
    const value = present(v) ? String(v) : fallback;
    if (value === undefined || value === '') throw new TemplateError(`missing value for {${name}}`);
    return value
      .split('/')
      .map((seg) => {
        if (seg === '' || seg === '.' || seg === '..') throw new TemplateError(`invalid path segment in {${name}}`);
        return encodeURIComponent(seg);
      })
      .join('/');
  });
}

/** Renders a string value; missing placeholders become their default or an empty string. */
export function renderString(s: string, vars: TemplateVars): string {
  return s.replace(PLACEHOLDER, (_m, name: string, fallback?: string) => {
    const v = lookup(vars, name);
    return present(v) ? String(v) : (fallback ?? '');
  });
}

/**
 * Renders a JSON body template. A string that is exactly one placeholder keeps the
 * value's type and is omitted when missing (so optional inputs are not sent as "").
 */
export function renderBody(t: unknown, vars: TemplateVars): unknown {
  if (typeof t === 'string') {
    const whole = WHOLE.exec(t);
    if (whole) {
      const v = lookup(vars, whole[1]!);
      return present(v) ? v : whole[2];
    }
    return renderString(t, vars);
  }
  if (Array.isArray(t)) return t.map((x) => renderBody(x, vars)).filter((x) => x !== undefined);
  if (t && typeof t === 'object') {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(t)) {
      const r = renderBody(v, vars);
      if (r !== undefined) out[k] = r;
    }
    return out;
  }
  return t;
}

// ---------------------------------------------------------------- response allow-list

function get(obj: unknown, path: string): unknown {
  let cur: unknown = obj;
  for (const part of path.split('.')) {
    if (cur === null || typeof cur !== 'object') return undefined;
    cur = (cur as Record<string, unknown>)[part];
  }
  return cur;
}

function decodeBase64(s: string): string {
  const bin = atob(s.replace(/\s/g, ''));
  return new TextDecoder().decode(Uint8Array.from(bin, (c) => c.charCodeAt(0)));
}

function field(src: unknown, spec: FieldSpec): unknown {
  if (typeof spec === 'string') return get(src, spec);
  if (spec.const !== undefined) return spec.const;
  let v = get(src, spec.path!);
  if (spec.pluck && Array.isArray(v)) v = v.map((e) => (e && typeof e === 'object' ? (e as Record<string, unknown>)[spec.pluck!] : e));
  if (spec.decode === 'base64' && typeof v === 'string') {
    try {
      v = decodeBase64(v);
    } catch {
      v = undefined;
    }
  }
  if (spec.maxLength && typeof v === 'string') v = v.slice(0, spec.maxLength);
  return v;
}

function pick(src: unknown, map: ResponseMap): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [name, spec] of Object.entries(map.fields)) {
    const v = field(src, spec);
    if (v !== undefined) out[name] = v;
  }
  return out;
}

/** Keeps only the fields a definition allows; arrays are mapped element-wise up to `limit`. */
export function mapResponse(json: unknown, map: ResponseMap): unknown {
  if (Array.isArray(json)) return json.slice(0, map.limit).map((item) => pick(item, map));
  return pick(json, map);
}
