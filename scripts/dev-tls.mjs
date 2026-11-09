// Creates a development CA and the two mTLS certificates for the control plane <-> webhook link.
//
//   npm run tls:dev-certs [-- --out <dir>] [-- --force]      (default dir: deploy/compose/tls)
//
//   ca.pem                      the CA: the webhook trusts it for client certificates, the control plane for the server one
//   webhook.pem, webhook-key.pem              server certificate for the webhook (localhost, webhook,
//                                             webhook.token-vault-customer.svc[.cluster.local], 127.0.0.1)
//   control-plane.pem, control-plane-key.pem  client certificate, identity URI:spiffe://token-vault/control-plane
//
// Development only: the CA key stays in the same directory. In production, issue these from your
// own CA (cert-manager, Vault PKI, ...). Needs the openssl command. Prints no key material.
import { execFileSync } from 'node:child_process';
import { chmodSync, existsSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const outArg = process.argv.indexOf('--out');
const out = resolve(outArg > -1 ? process.argv[outArg + 1] : resolve(root, 'deploy/compose/tls'));
if (existsSync(resolve(out, 'ca.pem')) && !process.argv.includes('--force')) {
  console.error(`[tls] ${out} already has certificates (use --force to replace them).`);
  process.exit(1);
}
try {
  execFileSync('openssl', ['version'], { stdio: 'ignore' });
} catch {
  console.error('[tls] the openssl command is required.');
  process.exit(1);
}
mkdirSync(out, { recursive: true, mode: 0o755 });
const f = (name) => resolve(out, name);
const ssl = (...args) => execFileSync('openssl', args, { stdio: ['ignore', 'ignore', 'pipe'] });

// CA (P-256, 5 years)
ssl('ecparam', '-name', 'prime256v1', '-genkey', '-noout', '-out', f('ca-key.pem'));
ssl('req', '-x509', '-new', '-key', f('ca-key.pem'), '-sha256', '-days', '1825', '-subj', '/CN=Token Vault development webhook CA', '-addext', 'basicConstraints=critical,CA:TRUE', '-addext', 'keyUsage=critical,keyCertSign,cRLSign', '-out', f('ca.pem'));

function issue(name, subject, ext) {
  ssl('ecparam', '-name', 'prime256v1', '-genkey', '-noout', '-out', f(`${name}-key.pem`));
  ssl('req', '-new', '-key', f(`${name}-key.pem`), '-subj', subject, '-out', f(`${name}.csr`));
  writeFileSync(f(`${name}.ext`), ext);
  ssl('x509', '-req', '-in', f(`${name}.csr`), '-CA', f('ca.pem'), '-CAkey', f('ca-key.pem'), '-CAcreateserial', '-sha256', '-days', '397', '-extfile', f(`${name}.ext`), '-out', f(`${name}.pem`));
  rmSync(f(`${name}.csr`));
  rmSync(f(`${name}.ext`));
}
issue(
  'webhook',
  '/CN=webhook',
  'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost,DNS:webhook,DNS:webhook.token-vault-customer.svc,DNS:webhook.token-vault-customer.svc.cluster.local,IP:127.0.0.1\n',
);
issue('control-plane', '/CN=control-plane', 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=clientAuth\nsubjectAltName=URI:spiffe://token-vault/control-plane\n');
rmSync(f('ca.srl'), { force: true });

// Keys readable by the services' container users (uid 1000) in compose; never commit this directory.
for (const k of ['ca-key.pem', 'webhook-key.pem', 'control-plane-key.pem']) chmodSync(f(k), 0o644);
console.log(`[tls] wrote a development CA and the webhook (server) and control-plane (client) certificates to ${out}`);
console.log('[tls] control-plane identity: URI:spiffe://token-vault/control-plane (use it in WEBHOOK_TLS_ALLOWED_CLIENTS)');
