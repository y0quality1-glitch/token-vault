/**
 * Removes anything that looks like secret material before data reaches audit
 * records, logs or error messages. Allow-listed keys are known to be non-secret.
 */
const SECRET_KEY = /(secret|password|passwd|token|authorization|api[_-]?key|private[_-]?key|cookie)/i;
const ALLOWED = new Set(['credentialReference', 'credential_ref', 'credentialFingerprint', 'maskedIdentifier', 'keyId', 'maskedKey']);
const SECRET_VALUE = /(-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----|tvak_[0-9a-f]{12}_\S+|gh[pousr]_[A-Za-z0-9]{10,}|github_pat_\S+|mock_ghp_\S+|Bearer\s+\S+)/g;

export function sanitize<T>(value: T, depth = 0): T {
  if (depth > 6) return '[truncated]' as T;
  if (typeof value === 'string') return value.replace(SECRET_VALUE, '[REDACTED]') as T;
  if (Array.isArray(value)) return value.map((v) => sanitize(v, depth + 1)) as T;
  if (value && typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value)) {
      out[k] = SECRET_KEY.test(k) && !ALLOWED.has(k) ? '[REDACTED]' : sanitize(v, depth + 1);
    }
    return out as T;
  }
  return value;
}
