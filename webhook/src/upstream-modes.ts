export type UpstreamMode = 'mock' | 'live';

/**
 * Upstream modes from the environment. The default for every application is UPSTREAM_MODE,
 * or the older GITHUB_MODE, else "mock" (simulated). PROVIDER_MODES overrides it per
 * application, e.g. "github=live,slack=mock", so providers can go live one at a time.
 * Throws on anything it does not understand: a typo must not silently stay simulated (or go live).
 */
export function parseUpstreamModes(env: Record<string, string | undefined>): { defaultMode: UpstreamMode; providerModes: Record<string, UpstreamMode> } {
  const asMode = (v: string | undefined, name: string): UpstreamMode | undefined => {
    if (v === undefined || v.trim() === '') return undefined;
    if (v.trim() !== 'mock' && v.trim() !== 'live') throw new Error(`${name} must be "mock" or "live" (got "${v}")`);
    return v.trim() as UpstreamMode;
  };
  const defaultMode = asMode(env.UPSTREAM_MODE, 'UPSTREAM_MODE') ?? asMode(env.GITHUB_MODE, 'GITHUB_MODE') ?? 'mock';
  const providerModes: Record<string, UpstreamMode> = {};
  for (const part of (env.PROVIDER_MODES ?? '').split(',').map((p) => p.trim()).filter(Boolean)) {
    const [key = '', value, ...rest] = part.split('=').map((x) => x.trim());
    if (!/^[a-z][a-z0-9_-]{1,39}$/.test(key) || rest.length) throw new Error(`PROVIDER_MODES: "${part}" is not <application key>=mock|live`);
    const mode = asMode(value, `PROVIDER_MODES (${key})`);
    if (!mode) throw new Error(`PROVIDER_MODES: "${part}" is not <application key>=mock|live`);
    providerModes[key] = mode;
  }
  return { defaultMode, providerModes };
}
