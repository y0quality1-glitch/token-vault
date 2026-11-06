// Rotates the customer webhook's credential encryption key in webhook/.env (development).
//
//   npm run vault:rotate-key               new VAULT_ENCRYPTION_KEY; the old one moves to
//                                          VAULT_PREVIOUS_ENCRYPTION_KEYS so nothing becomes unreadable
//   npm run vault:rotate-key -- --retire   removes the previous keys once nothing needs them
//
// After the first step, restart the webhook: it re-encrypts every credential under the new
// key at start-up. Run --retire only when the Webhook Health page (or the webhook's health
// response) shows no credentials left on an older key. The script prints key ids, never keys.
// In other environments, follow the same order with your secret manager (README: rotating keys).
import { createHash, randomBytes } from 'node:crypto';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const env = resolve(root, 'webhook/.env');

// Same one-way id as webhook/src/security/keyring.ts.
const keyId = (b64) => 'kid_' + createHash('sha256').update('token-vault/vault-key-id:').update(Buffer.from(b64, 'base64')).digest('hex').slice(0, 16);

function readVar(name) {
  const m = readFileSync(env, 'utf8').match(new RegExp(`^${name}=(.*)$`, 'm'));
  return m?.[1]?.trim();
}
function writeVar(name, value) {
  const text = readFileSync(env, 'utf8');
  const line = `${name}=${value}`;
  writeFileSync(env, new RegExp(`^${name}=.*$`, 'm').test(text) ? text.replace(new RegExp(`^${name}=.*$`, 'm'), () => line) : text.trimEnd() + `\n${line}\n`);
}

if (!existsSync(env) || !readVar('VAULT_ENCRYPTION_KEY')) {
  console.error('[rotate] webhook/.env has no VAULT_ENCRYPTION_KEY. Run "npm run setup" first.');
  process.exit(1);
}
const current = readVar('VAULT_ENCRYPTION_KEY');
const previous = (readVar('VAULT_PREVIOUS_ENCRYPTION_KEYS') ?? '').split(',').map((k) => k.trim()).filter(Boolean);

if (process.argv.includes('--retire')) {
  writeVar('VAULT_PREVIOUS_ENCRYPTION_KEYS', '');
  console.log(`[rotate] webhook/.env: removed previous keys ${previous.map(keyId).join(', ') || '(none)'}; current key ${keyId(current)}`);
  console.log('[rotate] Restart the webhook. Credentials still encrypted with a removed key would become unreadable, so check the Webhook Health page first.');
  process.exit(0);
}

const next = randomBytes(32).toString('base64');
writeVar('VAULT_ENCRYPTION_KEY', next);
writeVar('VAULT_PREVIOUS_ENCRYPTION_KEYS', [current, ...previous.filter((k) => k !== current)].join(','));
console.log(`[rotate] webhook/.env: encryption key ${keyId(current)} -> ${keyId(next)} (old key kept as a previous key)`);
console.log('[rotate] Restart the webhook: it re-encrypts every credential under the new key at start-up.');
console.log('[rotate] When Webhook Health shows no credentials on an older key, run: npm run vault:rotate-key -- --retire');
