// Rotates the control plane <-> webhook signing secret in the local .env files (development),
// in three steps so no request fails in between:
//
//   npm run webhook:rotate-secret                 1. webhook: new secret, old one still accepted -> restart the webhook
//   npm run webhook:rotate-secret -- --switch     2. Token Vault signs with the new secret         -> restart the control plane
//   npm run webhook:rotate-secret -- --retire     3. both sides forget the old secret              -> restart both
//
// The webhook answers each request with the secret it was signed with, so step 1 works while the
// control plane still uses the old secret. The last health check on Webhook Health says which step
// is next. In other environments, follow the same order with your secret manager (README).
// The script never prints secrets.
import { randomBytes } from 'node:crypto';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const webhookEnv = resolve(root, 'webhook/.env');
const serverEnv = resolve(root, 'server/.env');

function readVar(file, name) {
  const m = readFileSync(file, 'utf8').match(new RegExp(`^${name}=(.*)$`, 'm'));
  return m?.[1]?.trim() ?? '';
}
function writeVar(file, name, value) {
  const text = readFileSync(file, 'utf8');
  const line = `${name}=${value}`;
  writeFileSync(file, new RegExp(`^${name}=.*$`, 'm').test(text) ? text.replace(new RegExp(`^${name}=.*$`, 'm'), () => line) : text.trimEnd() + `\n${line}\n`);
}
const list = (v) => v.split(',').map((x) => x.trim()).filter(Boolean);

for (const f of [webhookEnv, serverEnv]) {
  if (!existsSync(f) || !readVar(f, 'WEBHOOK_SIGNING_SECRET')) {
    console.error(`[rotate] ${f.replace(root + '/', '')} has no WEBHOOK_SIGNING_SECRET. Run "npm run setup" first.`);
    process.exit(1);
  }
}
const step = process.argv.includes('--retire') ? 'retire' : process.argv.includes('--switch') ? 'switch' : 'start';
const webhookCurrent = readVar(webhookEnv, 'WEBHOOK_SIGNING_SECRET');
const serverCurrent = readVar(serverEnv, 'WEBHOOK_SIGNING_SECRET');

if (step === 'start') {
  if (webhookCurrent !== serverCurrent) {
    console.error('[rotate] A rotation is already in progress (the two .env files hold different secrets). Run "-- --switch" next, or "-- --retire" to finish.');
    process.exit(1);
  }
  writeVar(webhookEnv, 'WEBHOOK_SIGNING_SECRET', randomBytes(32).toString('base64url'));
  writeVar(webhookEnv, 'WEBHOOK_PREVIOUS_SIGNING_SECRETS', serverCurrent);
  console.log('[rotate] 1/3 webhook/.env: new signing secret; the old one is still accepted.');
  console.log('[rotate] Restart the webhook. Then run: npm run webhook:rotate-secret -- --switch');
} else if (step === 'switch') {
  if (webhookCurrent === serverCurrent) {
    console.error('[rotate] Nothing to switch: run step 1 (npm run webhook:rotate-secret) first.');
    process.exit(1);
  }
  if (!list(readVar(webhookEnv, 'WEBHOOK_PREVIOUS_SIGNING_SECRETS')).includes(serverCurrent)) {
    console.error("[rotate] webhook/.env does not accept the control plane's current secret; switching now would break requests. Check WEBHOOK_PREVIOUS_SIGNING_SECRETS.");
    process.exit(1);
  }
  writeVar(serverEnv, 'WEBHOOK_SIGNING_SECRET', webhookCurrent);
  writeVar(serverEnv, 'WEBHOOK_PREVIOUS_SIGNING_SECRETS', serverCurrent);
  console.log('[rotate] 2/3 server/.env: Token Vault now signs with the new secret (the old one is still accepted on responses).');
  console.log('[rotate] Restart the control plane. Once Webhook Health shows the next health check passing, run: npm run webhook:rotate-secret -- --retire');
} else {
  if (webhookCurrent !== serverCurrent) {
    console.error('[rotate] The control plane does not use the new secret yet: run "-- --switch" and restart it first.');
    process.exit(1);
  }
  writeVar(webhookEnv, 'WEBHOOK_PREVIOUS_SIGNING_SECRETS', '');
  writeVar(serverEnv, 'WEBHOOK_PREVIOUS_SIGNING_SECRETS', '');
  console.log('[rotate] 3/3 old signing secret removed from both .env files. Restart the webhook and the control plane.');
}
