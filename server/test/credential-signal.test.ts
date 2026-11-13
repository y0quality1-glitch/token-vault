import { describe, expect, it } from 'vitest';
import { isCredentialRejection } from '../src/services/integrationService/credentialSignal';

describe('credential rejection signals', () => {
  it('treats a 401 from the provider as a rejected credential', () => {
    expect(isCredentialRejection({ upstreamStatus: 401 })).toBe(true);
  });
  it('does not treat outages, rate limits or missing permissions as rejections', () => {
    for (const upstreamStatus of [200, 403, 404, 429, 500, 503, null]) expect(isCredentialRejection({ upstreamStatus })).toBe(false);
  });
  it('treats credential-level webhook errors as rejections, unless the provider was down', () => {
    expect(isCredentialRejection({ errorCode: 'OAUTH_REFRESH_FAILED', errorUpstreamStatus: 400 })).toBe(true); // invalid_grant: refresh token revoked
    expect(isCredentialRejection({ errorCode: 'OAUTH_REFRESH_FAILED', errorUpstreamStatus: null })).toBe(true); // no refresh token left
    expect(isCredentialRejection({ errorCode: 'APP_AUTH_FAILED', errorUpstreamStatus: 401 })).toBe(true);
    expect(isCredentialRejection({ errorCode: 'INSTALLATION_NOT_FOUND', errorUpstreamStatus: 404 })).toBe(true); // App uninstalled
    expect(isCredentialRejection({ errorCode: 'OAUTH_REFRESH_FAILED', errorUpstreamStatus: 503 })).toBe(false);
    expect(isCredentialRejection({ errorCode: 'OAUTH_REFRESH_FAILED', errorUpstreamStatus: 429 })).toBe(false);
    expect(isCredentialRejection({ errorCode: 'TOKEN_MINT_FAILED', errorUpstreamStatus: 422 })).toBe(false); // repository not in the installation
    expect(isCredentialRejection({ errorCode: 'CREDENTIAL_UNREADABLE' })).toBe(false); // webhook key problem, not the provider
  });
});
