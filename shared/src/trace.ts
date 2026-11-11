/**
 * Session tracing: W3C Trace Context (https://www.w3.org/TR/trace-context/) and agent sessions.
 *
 * An agent may send `traceparent: 00-<trace-id>-<parent-span-id>-<flags>` (what OpenTelemetry
 * propagates) and a `session_id` for the conversation, task or job a call belongs to. Token
 * Vault records both, creates its own span per request, and passes the trace on to the webhook.
 */

export const SESSION_ID = /^[A-Za-z0-9._:-]{1,128}$/;
export const MAX_SESSION_LABEL = 120;

const TRACEPARENT = /^([0-9a-f]{2})-([0-9a-f]{32})-([0-9a-f]{16})-([0-9a-f]{2})$/;

/** Parses a traceparent header. Invalid or all-zero ids (and version ff) are rejected, as the spec requires. */
export function parseTraceparent(header: string | undefined | null): { traceId: string; parentSpanId: string; sampled: boolean } | null {
  const m = TRACEPARENT.exec((header ?? '').trim().toLowerCase());
  if (!m) return null;
  const [, version, traceId, spanId, flags] = m as unknown as [string, string, string, string, string];
  if (version === 'ff' || /^0+$/.test(traceId) || /^0+$/.test(spanId)) return null;
  return { traceId, parentSpanId: spanId, sampled: (parseInt(flags, 16) & 1) === 1 };
}

export function formatTraceparent(traceId: string, spanId: string, sampled = true): string {
  return `00-${traceId}-${spanId}-${sampled ? '01' : '00'}`;
}

/** "Fix flaky test (s_8f2c…)" or the id, for display. */
export function sessionDisplayName(s: { sessionId: string; sessionLabel?: string | null }): string {
  return s.sessionLabel ? `${s.sessionLabel} (${s.sessionId.length > 18 ? `${s.sessionId.slice(0, 16)}…` : s.sessionId})` : s.sessionId;
}
