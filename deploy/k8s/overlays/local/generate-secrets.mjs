// Writes the Secrets of the local Kubernetes overlay to deploy/k8s/overlays/local/secrets/
// (git-ignored): one env file per service, with fresh random values.
//
//   node deploy/k8s/overlays/local/generate-secrets.mjs           create (refuses to overwrite)
//   node deploy/k8s/overlays/local/generate-secrets.mjs --force   replace (stored credentials become unreadable!)
//
// Each service gets only its own keys: the webhook's file is the only one with VAULT_ENCRYPTION_KEY,
// the CMS's the only one with the signing key. Prints key ids, never secrets.
import { createHash, generateKeyPairSync, randomBytes } from 'node:crypto';
import { existsSync, mkdirSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const dir = resolve(dirname(fileURLToPath(import.meta.url)), 'secrets');
if (existsSync(resolve(dir, 'webhook.env')) && !process.argv.includes('--force')) {
  console.error(`[k8s] ${dir} already has secrets. Keep them: VAULT_ENCRYPTION_KEY decrypts the stored credentials.`);
  console.error('[k8s] To start over: kubectl delete -k deploy/k8s/overlays/local (and the postgres volume), then run again with --force.');
  process.exit(1);
}
mkdirSync(dir, { recursive: true, mode: 0o700 });

const secret = () => randomBytes(32).toString('base64url');
const escape = (pem) => pem.trim().replace(/\n/g, '\\n');
const cms = generateKeyPairSync('ed25519');
const cmsPublic = escape(cms.publicKey.export({ type: 'spki', format: 'pem' }).toString());
const cmsKeyId = createHash('sha256').update(cms.publicKey.export({ type: 'spki', format: 'der' })).digest('hex').slice(0, 16);
const db = { cp: secret(), wh: secret(), cms: secret() };
const signing = secret();
const host = 'postgres.token-vault-data.svc.cluster.local:5432';

const files = {
  'postgres.env': [`POSTGRES_PASSWORD=${secret()}`, `CONTROL_PLANE_DB_PASSWORD=${db.cp}`, `WEBHOOK_DB_PASSWORD=${db.wh}`, `CMS_DB_PASSWORD=${db.cms}`],
  'server.env': [`DATABASE_URL=postgres://token_vault:${db.cp}@${host}/token_vault`, `WEBHOOK_SIGNING_SECRET=${signing}`, 'WEBHOOK_PREVIOUS_SIGNING_SECRETS=', `AUDIT_SIGNING_KEY=${secret()}`, `CMS_PUBLIC_KEY=${cmsPublic}`],
  'webhook.env': [
    `WEBHOOK_DATABASE_URL=postgres://token_vault_customer:${db.wh}@${host}/token_vault_customer`,
    `WEBHOOK_SIGNING_SECRET=${signing}`,
    'WEBHOOK_PREVIOUS_SIGNING_SECRETS=',
    `VAULT_ENCRYPTION_KEY=${randomBytes(32).toString('base64')}`,
    'VAULT_PREVIOUS_ENCRYPTION_KEYS=',
    `CMS_PUBLIC_KEY=${cmsPublic}`,
  ],
  'cms-api.env': [`CMS_DATABASE_URL=postgres://token_vault_cms:${db.cms}@${host}/token_vault_cms`, `CMS_SIGNING_PRIVATE_KEY=${escape(cms.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString())}`],
};
for (const [name, lines] of Object.entries(files)) writeFileSync(resolve(dir, name), lines.join('\n') + '\n', { mode: 0o600 });
console.log(`[k8s] wrote ${Object.keys(files).join(', ')} to ${dir} (mode 600). CMS signing key id ${cmsKeyId}.`);
console.log('[k8s] Next: kubectl apply -k deploy/k8s/overlays/local');
