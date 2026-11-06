import { describe, expect, it } from 'vitest';
import { parseUpstreamModes } from '../src/upstream-modes';

describe('upstream modes (live or simulated, per application)', () => {
  it('defaults to simulated, honours UPSTREAM_MODE and the older GITHUB_MODE', () => {
    expect(parseUpstreamModes({})).toEqual({ defaultMode: 'mock', providerModes: {} });
    expect(parseUpstreamModes({ GITHUB_MODE: 'live' }).defaultMode).toBe('live');
    expect(parseUpstreamModes({ UPSTREAM_MODE: 'mock', GITHUB_MODE: 'live' }).defaultMode).toBe('mock');
  });

  it('overrides the default per application', () => {
    expect(parseUpstreamModes({ PROVIDER_MODES: ' github=live , slack=mock ' })).toEqual({ defaultMode: 'mock', providerModes: { github: 'live', slack: 'mock' } });
    expect(parseUpstreamModes({ UPSTREAM_MODE: 'live', PROVIDER_MODES: 'openai=mock' })).toEqual({ defaultMode: 'live', providerModes: { openai: 'mock' } });
  });

  it('refuses anything it does not understand rather than guessing', () => {
    expect(() => parseUpstreamModes({ GITHUB_MODE: 'real' })).toThrow(/GITHUB_MODE must be "mock" or "live"/);
    expect(() => parseUpstreamModes({ PROVIDER_MODES: 'github' })).toThrow(/not <application key>=mock\|live/);
    expect(() => parseUpstreamModes({ PROVIDER_MODES: 'github=on' })).toThrow(/must be "mock" or "live"/);
    expect(() => parseUpstreamModes({ PROVIDER_MODES: 'GitHub=live' })).toThrow(/not <application key>/);
    expect(() => parseUpstreamModes({ PROVIDER_MODES: 'a=b=c' })).toThrow(/not <application key>/);
  });
});
