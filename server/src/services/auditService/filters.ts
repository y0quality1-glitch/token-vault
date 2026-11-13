/** A parseable date as ISO 8601, otherwise undefined (invalid dates are ignored, as before). */
export const isoOrUndefined = (v: unknown) => {
  if (typeof v !== 'string' || !v) return undefined;
  const d = new Date(v);
  return Number.isNaN(d.getTime()) ? undefined : d.toISOString();
};

/** The audit lists' old `limit` (default 200, at most 500) as the template's pageSize. */
export function pageBody(body: unknown): Record<string, unknown> {
  const b = (body && typeof body === 'object' ? body : {}) as Record<string, unknown>;
  const { limit, ...rest } = b;
  return { ...rest, pageSize: rest.pageSize ?? Math.min(Number(limit ?? 200) || 200, 500) };
}
