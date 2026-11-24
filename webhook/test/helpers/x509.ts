import 'reflect-metadata';
import * as x509 from '@peculiar/x509';
import { webcrypto } from 'node:crypto';

/** Test certificates made in memory (no openssl): a CA, certificates it issues, self-signed ones. */
x509.cryptoProvider.set(webcrypto as unknown as Crypto);
const subtle = webcrypto.subtle;
const EC = { name: 'ECDSA', namedCurve: 'P-256', hash: 'SHA-256' } as const;
const RSA = { name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' } as const;

export interface TestCert {
  certificate: string;
  privateKey: string;
  keys: CryptoKeyPair;
  cert: x509.X509Certificate;
}

const pem = (der: ArrayBuffer, label: string) => `-----BEGIN ${label}-----\n${Buffer.from(der).toString('base64').match(/.{1,64}/g)!.join('\n')}\n-----END ${label}-----\n`;
const day = 86_400_000;
let serial = 1;

async function finish(cert: x509.X509Certificate, keys: CryptoKeyPair): Promise<TestCert> {
  return { certificate: cert.toString('pem'), privateKey: pem(await subtle.exportKey('pkcs8', keys.privateKey), 'PRIVATE KEY'), keys, cert };
}

export async function testCa(name = 'CN=Test Root CA, O=Token Vault Tests', opts: { days?: number } = {}): Promise<TestCert> {
  const keys = (await subtle.generateKey(EC, true, ['sign', 'verify'])) as CryptoKeyPair;
  const cert = await x509.X509CertificateGenerator.createSelfSigned({
    serialNumber: (serial++).toString(16).padStart(2, '0'),
    name,
    notBefore: new Date(Date.now() - day),
    notAfter: new Date(Date.now() + (opts.days ?? 3650) * day),
    keys,
    signingAlgorithm: EC,
    extensions: [new x509.BasicConstraintsExtension(true, undefined, true), new x509.KeyUsagesExtension(x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign, true), await x509.SubjectKeyIdentifierExtension.create(keys.publicKey)],
  });
  return finish(cert, keys);
}

/** A leaf certificate issued by `ca` (or self-signed without one); `days` may be negative (already expired). */
export async function testLeaf(subject: string, opts: { ca?: TestCert; dns?: string[]; days?: number; rsa?: boolean } = {}): Promise<TestCert> {
  const alg = opts.rsa ? RSA : EC;
  const keys = (await subtle.generateKey(alg, true, ['sign', 'verify'])) as CryptoKeyPair;
  const days = opts.days ?? 90;
  const notAfter = new Date(Date.now() + days * day);
  const notBefore = new Date(Math.min(Date.now() - day, notAfter.getTime() - day));
  const extensions = [new x509.BasicConstraintsExtension(false), ...(opts.dns?.length ? [new x509.SubjectAlternativeNameExtension(opts.dns.map((value) => ({ type: 'dns' as const, value })))] : [])];
  const cert = opts.ca
    ? await x509.X509CertificateGenerator.create({ serialNumber: (serial++).toString(16).padStart(2, '0'), subject, issuer: opts.ca.cert.subject, notBefore, notAfter, publicKey: keys.publicKey, signingKey: opts.ca.keys.privateKey, signingAlgorithm: EC, extensions })
    : await x509.X509CertificateGenerator.createSelfSigned({ serialNumber: (serial++).toString(16).padStart(2, '0'), name: subject, notBefore, notAfter, keys, signingAlgorithm: alg, extensions });
  return finish(cert, keys);
}

/** Signs a CSR with `ca`, as an outside certificate authority would. */
export async function signCsr(csrPem: string, ca: TestCert, days = 90): Promise<string> {
  const csr = new x509.Pkcs10CertificateRequest(csrPem);
  const san = csr.getExtension('2.5.29.17') as x509.SubjectAlternativeNameExtension | null;
  const cert = await x509.X509CertificateGenerator.create({
    serialNumber: (serial++).toString(16).padStart(2, '0'),
    subject: csr.subjectName,
    issuer: ca.cert.subjectName,
    notBefore: new Date(Date.now() - 60_000),
    notAfter: new Date(Date.now() + days * day),
    publicKey: csr.publicKey,
    signingKey: ca.keys.privateKey,
    signingAlgorithm: EC,
    extensions: [new x509.BasicConstraintsExtension(false), ...(san ? [new x509.SubjectAlternativeNameExtension(san.names.toJSON())] : [])],
  });
  return cert.toString('pem');
}

export { x509 };
