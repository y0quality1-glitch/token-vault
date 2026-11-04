import { existsSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';

/**
 * Fails the run if any secret value reached the control-plane, webhook or CMS logs:
 * provider tokens (real or mock) or agent API credentials.
 */
const SECRET_PATTERNS: [string, RegExp][] = [
  ['mock provider token', /mock_ghp_[A-Za-z0-9_-]{8,}/],
  ['GitHub token', /\b(gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})/],
  ['agent API credential', /tvak_[0-9a-f]{12}_[A-Za-z0-9_-]{20,}/],
  ['bearer header', /Bearer\s+[A-Za-z0-9._-]{20,}/],
  ['private key', /-----BEGIN [A-Z ]*PRIVATE KEY-----/],
];

const LOGS = ['server.log', 'webhook.log', 'cms.log'];

export default function globalTeardown() {
  const dir = resolve(import.meta.dirname, '.logs');
  const findings: string[] = [];
  for (const name of LOGS) {
    const file = resolve(dir, name);
    if (!existsSync(file)) continue;
    const text = readFileSync(file, 'utf8');
    for (const [label, re] of SECRET_PATTERNS) if (re.test(text)) findings.push(`${name}: ${label}`);
  }
  // The signing secret and encryption key must never be printed either.
  for (const v of ['WEBHOOK_SIGNING_SECRET', 'VAULT_ENCRYPTION_KEY', 'AUDIT_SIGNING_KEY', 'CMS_SIGNING_PRIVATE_KEY']) {
    const value = process.env[v];
    if (!value) continue;
    for (const name of LOGS) {
      const file = resolve(dir, name);
      if (existsSync(file) && readFileSync(file, 'utf8').includes(value)) findings.push(`${name}: ${v}`);
    }
  }
  if (findings.length) throw new Error(`Secret material found in service logs:\n  ${findings.join('\n  ')}`);
  console.log('[e2e] log scan: no secret material in server, webhook or CMS logs');
}
