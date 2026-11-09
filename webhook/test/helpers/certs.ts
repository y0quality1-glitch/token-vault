import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

export interface DevCerts {
  dir: string;
  ca: string;
  webhook: { cert: string; key: string };
  controlPlane: { cert: string; key: string };
  /** Issue one more certificate from this CA (e.g. a client with another identity). */
  issue(name: string, subject: string, ext: string): { cert: string; key: string };
}

/** A throwaway CA and certificates from scripts/dev-tls.mjs (needs openssl). */
export function devCerts(): DevCerts {
  const dir = mkdtempSync(join(tmpdir(), 'tv-tls-'));
  execFileSync(process.execPath, [resolve(__dirname, '../../../scripts/dev-tls.mjs'), '--out', dir], { stdio: 'ignore' });
  const read = (f: string) => readFileSync(join(dir, f), 'utf8');
  const ssl = (...args: string[]) => execFileSync('openssl', args, { stdio: ['ignore', 'ignore', 'pipe'] });
  return {
    dir,
    ca: read('ca.pem'),
    webhook: { cert: read('webhook.pem'), key: read('webhook-key.pem') },
    controlPlane: { cert: read('control-plane.pem'), key: read('control-plane-key.pem') },
    issue(name, subject, ext) {
      const f = (s: string) => join(dir, `${name}${s}`);
      ssl('ecparam', '-name', 'prime256v1', '-genkey', '-noout', '-out', f('-key.pem'));
      ssl('req', '-new', '-key', f('-key.pem'), '-subj', subject, '-out', f('.csr'));
      writeFileSync(f('.ext'), ext);
      ssl('x509', '-req', '-in', f('.csr'), '-CA', join(dir, 'ca.pem'), '-CAkey', join(dir, 'ca-key.pem'), '-CAcreateserial', '-sha256', '-days', '30', '-extfile', f('.ext'), '-out', f('.pem'));
      return { cert: read(`${name}.pem`), key: read(`${name}-key.pem`) };
    },
  };
}
