/** Pure rule: does a signal from the webhook mean the provider rejected the stored credential? */

/** Webhook error codes that mean the credential itself is no longer accepted. */
const REJECTION_CODES = new Set(['APP_AUTH_FAILED', 'INSTALLATION_NOT_FOUND', 'OAUTH_REFRESH_FAILED']);

export type HealthSignal = { upstreamStatus?: number | null; errorCode?: string | null; errorUpstreamStatus?: number | null };

/** True if the signal says the provider rejected the credential (not an outage or a permission issue). */
export function isCredentialRejection(s: HealthSignal): boolean {
  if (s.upstreamStatus === 401) return true;
  if (!s.errorCode || !REJECTION_CODES.has(s.errorCode)) return false;
  return !(typeof s.errorUpstreamStatus === 'number' && (s.errorUpstreamStatus >= 500 || s.errorUpstreamStatus === 429));
}
