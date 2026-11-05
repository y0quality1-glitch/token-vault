// Rotates the provider CMS signing key in the local .env files (development).
//
//   npm run cms:rotate-key               new CMS key; consumers pin the new AND the old key
//   npm run cms:rotate-key -- --retire   consumers stop pinning keys other than the CMS's current one
//
// After the first step, restart everything: the CMS signs every published version with the
// new key on start-up, and consumers accept either key in the meantime. Run --retire once
// every consumer has synced (their /api/v1/providers or webhook health shows a recent sync).
// In other environments, follow the same order with your secret manager (docs/CMS.md).
import { createHash, createPrivateKey, createPublicKey, generateKeyPairSync } from 'node:crypto';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const cmsEnv = resolve(root, 'cms/api/.env');
const consumers = [
  ['server/.env', resolve(root, 'server/.env')],
  ['webhook/.env', resolve(root, 'webhook/.env')],
];

const unescape = (v) => v.replace(/\\n/g, '\n');
const escape = (v) => v.trim().replace(/\n/g, '\\n');
const keyId = (pub) => createHash('sha256').update(pub.export({ type: 'spki', format: 'der' })).digest('hex').slice(0, 16);
const pems = (bundle) => unescape(bundle).match(/-----BEGIN PUBLIC KEY-----[\s\S]*?-----END PUBLIC KEY-----/g) ?? [];

function readVar(file, name) {
  const m = readFileSync(file, 'utf8').match(new RegExp(`^${name}=(.*)$`, 'm'));
  return m?.[1];
}
function writeVar(file, name, value) {
  const text = readFileSync(file, 'utf8');
  const line = `${name}=${value}`;
  writeFileSync(file, new RegExp(`^${name}=.*$`, 'm').test(text) ? text.replace(new RegExp(`^${name}=.*$`, 'm'), () => line) : text.trimEnd() + `\n${line}\n`);
}

if (!existsSync(cmsEnv) || !readVar(cmsEnv, 'CMS_SIGNING_PRIVATE_KEY')) {
  console.error('[rotate] cms/api/.env has no CMS_SIGNING_PRIVATE_KEY. Run "npm run setup" first.');
  process.exit(1);
}
const current = createPublicKey(createPrivateKey(unescape(readVar(cmsEnv, 'CMS_SIGNING_PRIVATE_KEY'))));

if (process.argv.includes('--retire')) {
  const keep = current.export({ type: 'spki', format: 'pem' }).toString();
  for (const [name, file] of consumers) {
    if (!existsSync(file)) continue;
    const before = pems(readVar(file, 'CMS_PUBLIC_KEY') ?? '').map((p) => keyId(createPublicKey(p)));
    writeVar(file, 'CMS_PUBLIC_KEY', escape(keep));
    console.log(`[rotate] ${name}: pinned ${before.join(', ') || 'nothing'} -> ${keyId(current)}`);
  }
  console.log('[rotate] Restart the control plane and the webhook to apply.');
  process.exit(0);
}

const next = generateKeyPairSync('ed25519');
writeVar(cmsEnv, 'CMS_SIGNING_PRIVATE_KEY', escape(next.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString()));
const nextPem = next.publicKey.export({ type: 'spki', format: 'pem' }).toString();
for (const [name, file] of consumers) {
  if (!existsSync(file)) continue;
  const pinned = pems(readVar(file, 'CMS_PUBLIC_KEY') ?? '');
  writeVar(file, 'CMS_PUBLIC_KEY', escape([...pinned, nextPem.trim()].join('\n')));
  console.log(`[rotate] ${name}: now pins ${[...pinned.map((p) => keyId(createPublicKey(p))), keyId(next.publicKey)].join(' + ')}`);
}
console.log(`[rotate] cms/api/.env: signing key ${keyId(current)} -> ${keyId(next.publicKey)}`);
console.log('[rotate] Restart all services. The CMS signs every published version with the new key on start-up.');
console.log('[rotate] Once the control plane and webhooks have synced, run: npm run cms:rotate-key -- --retire');
