import 'reflect-metadata'; // @peculiar/x509 (tsyringe) needs it before it loads
import * as x509 from '@peculiar/x509';
import forge from 'node-forge';
import { createPrivateKey, createPublicKey, randomBytes, webcrypto, X509Certificate, type KeyObject } from 'node:crypto';
import type { CertificateInfo, CertificateKeyAlgorithm, SecretPayload } from '@token-vault/shared';

/**
 * Certificates (Secret Management phase 6, spec 4.9.3 F), read by the customer webhook, which is
 * the only place their private keys exist:
 *  - what a stored certificate says (subject, issuer, validity, names, fingerprint), whether the
 *    stored private key belongs to it, and whether its chain links up;
 *  - for a renewal, a new key pair and a PKCS#10 request (the key is stored encrypted until the
 *    certificate comes back);
 *  - issuing a certificate for such a request with a CA secret's key.
 * Nothing here logs a key, a passphrase or a bundle.
 */

x509.cryptoProvider.set(webcrypto as unknown as Crypto);
const subtle = webcrypto.subtle;

export class CertificateError extends Error {
  constructor(
    public readonly code: 'SECRET_INVALID' | 'CERTIFICATE_KEY_MISMATCH' | 'CERTIFICATE_EXPIRED' | 'CERTIFICATE_ISSUER_INVALID',
    message: string,
    /** The payload field at fault. */
    public readonly field?: string,
  ) {
    super(message);
  }
}

const SAN_OID = '2.5.29.17';
const PEM_CERTIFICATE = /-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g;

/** Every certificate in a PEM text, in order. */
export function pemCertificates(text: unknown, field: string): X509Certificate[] {
  const blocks = typeof text === 'string' ? (text.match(PEM_CERTIFICATE) ?? []) : [];
  return blocks.map((b, i) => {
    try {
      return new X509Certificate(b);
    } catch {
      throw new CertificateError('SECRET_INVALID', `Certificate ${i + 1} cannot be read (not an X.509 certificate in PEM)`, field);
    }
  });
}

function privateKeyOf(pem: unknown, field: string, passphrase?: string): KeyObject | null {
  if (typeof pem !== 'string' || !pem.trim()) return null;
  try {
    return createPrivateKey(passphrase ? { key: pem, passphrase } : pem);
  } catch {
    throw new CertificateError('SECRET_INVALID', passphrase ? 'The private key cannot be read (or the passphrase is wrong)' : 'The private key cannot be read (PEM, unencrypted)', field);
  }
}

/** "RSA 2048", "EC P-256", "Ed25519". */
export function describeKey(k: KeyObject): string {
  const d = k.asymmetricKeyDetails ?? {};
  if (k.asymmetricKeyType === 'rsa' || k.asymmetricKeyType === 'rsa-pss') return `RSA ${d.modulusLength ?? ''}`.trim();
  if (k.asymmetricKeyType === 'ec') return `EC ${({ prime256v1: 'P-256', secp384r1: 'P-384', secp521r1: 'P-521' } as Record<string, string>)[d.namedCurve ?? ''] ?? d.namedCurve ?? ''}`.trim();
  if (k.asymmetricKeyType === 'ed25519') return 'Ed25519';
  return k.asymmetricKeyType ?? 'unknown';
}

const date = (c: X509Certificate, which: 'validFrom' | 'validTo') => new Date((c as unknown as Record<string, Date | undefined>)[`${which}Date`] ?? c[which]).toISOString();
const oneLine = (dn: string) => dn.split('\n').filter(Boolean).join(', ');
const signed = (child: X509Certificate, parent: X509Certificate) => child.checkIssued(parent) && child.verify(parent.publicKey);

function describe(cert: X509Certificate, chain: X509Certificate[], key: KeyObject | null): CertificateInfo {
  const all = [cert, ...chain];
  return {
    subject: oneLine(cert.subject),
    commonName: /(?:^|\n)CN=([^\n]+)/.exec(cert.subject)?.[1] ?? null,
    issuer: oneLine(cert.issuer),
    serialNumber: cert.serialNumber.toUpperCase(),
    notBefore: date(cert, 'validFrom'),
    notAfter: date(cert, 'validTo'),
    subjectAltNames: cert.subjectAltName ? cert.subjectAltName.split(', ').filter(Boolean) : [],
    fingerprintSha256: cert.fingerprint256,
    publicKey: describeKey(cert.publicKey),
    isCA: cert.ca,
    selfSigned: signed(cert, cert),
    privateKey: key ? 'matches' : 'absent',
    chain: chain.map((c) => ({ subject: oneLine(c.subject), issuer: oneLine(c.issuer), notAfter: date(c, 'validTo') })),
    chainValid: chain.length ? all.slice(0, -1).every((c, i) => signed(c, all[i + 1]!)) : null,
  };
}

/** PKCS#12 bundle → the first key and its certificate, then the other certificates (node-forge reads it; Node checks it). */
function readPkcs12(bundle: unknown, passphrase: unknown): { cert: X509Certificate; chain: X509Certificate[]; key: KeyObject | null } {
  const b64 = typeof bundle === 'string' ? bundle.replace(/\s+/g, '') : '';
  let p12: forge.pkcs12.Pkcs12Pfx;
  try {
    p12 = forge.pkcs12.pkcs12FromAsn1(forge.asn1.fromDer(Buffer.from(b64, 'base64').toString('binary')), typeof passphrase === 'string' ? passphrase : '');
  } catch (e) {
    const wrongPass = /MAC could not be verified|wrong password|Invalid password/i.test((e as Error).message ?? '');
    throw new CertificateError('SECRET_INVALID', wrongPass ? 'Wrong passphrase for this bundle' : 'Not a PKCS#12 bundle (base64 of a .p12 or .pfx file)', wrongPass ? 'passphrase' : 'bundle');
  }
  const bags = (type: string) => p12.getBags({ bagType: type })[type] ?? [];
  const der = (a: forge.asn1.Asn1) => Buffer.from(forge.asn1.toDer(a).getBytes(), 'binary');
  // forge decodes RSA only; for other keys and certificates it keeps the ASN.1, which Node reads.
  const keyBag = [...bags(forge.pki.oids.pkcs8ShroudedKeyBag!), ...bags(forge.pki.oids.keyBag!)][0];
  let key: KeyObject | null = null;
  if (keyBag) {
    const asn1 = (keyBag as { asn1?: forge.asn1.Asn1 }).asn1 ?? (keyBag.key ? forge.pki.wrapRsaPrivateKey(forge.pki.privateKeyToAsn1(keyBag.key)) : null);
    if (asn1) {
      try {
        key = createPrivateKey({ key: der(asn1), format: 'der', type: 'pkcs8' });
      } catch {
        throw new CertificateError('SECRET_INVALID', 'The private key in the bundle cannot be read', 'bundle');
      }
    }
  }
  const certs = bags(forge.pki.oids.certBag!).map((bag) => {
    const asn1 = (bag as { asn1?: forge.asn1.Asn1 }).asn1 ?? (bag.cert ? forge.pki.certificateToAsn1(bag.cert) : null);
    if (!asn1) throw new CertificateError('SECRET_INVALID', 'A certificate in the bundle cannot be read', 'bundle');
    return new X509Certificate(der(asn1));
  });
  if (!certs.length) throw new CertificateError('SECRET_INVALID', 'The bundle holds no certificate', 'bundle');
  // The key's certificate first; the others form the chain (leaf to root, as far as they link).
  const leaf = (key && certs.find((c) => c.checkPrivateKey(key!))) ?? certs[0]!;
  const rest = certs.filter((c) => c !== leaf);
  const chain: X509Certificate[] = [];
  for (let cur = leaf; ; ) {
    const next = rest.find((c) => !chain.includes(c) && cur.checkIssued(c) && c !== cur);
    if (!next) break;
    chain.push(next);
    cur = next;
  }
  return { cert: leaf, chain: [...chain, ...rest.filter((c) => !chain.includes(c))], key };
}

/**
 * What a certificate secret holds, or null for other types. Throws CertificateError for a value
 * that cannot be read, a private key that does not belong to the certificate, or (with
 * `refuseExpired`) a certificate whose validity has ended.
 */
export function readCertificate(typeKey: string, payload: SecretPayload, opts: { refuseExpired?: boolean } = {}): CertificateInfo | null {
  let cert: X509Certificate;
  let chain: X509Certificate[];
  let key: KeyObject | null;
  if (typeKey === 'tls-certificate' || typeKey === 'ca-certificate') {
    const certs = pemCertificates(payload.certificate, 'certificate');
    if (!certs.length) throw new CertificateError('SECRET_INVALID', 'No certificate in PEM (-----BEGIN CERTIFICATE-----)', 'certificate');
    cert = certs[0]!;
    chain = [...certs.slice(1), ...(typeKey === 'tls-certificate' ? pemCertificates(payload.chain, 'chain') : [])];
    key = privateKeyOf(payload.privateKey, 'privateKey');
  } else if (typeKey === 'pkcs12') {
    ({ cert, chain, key } = readPkcs12(payload.bundle, payload.passphrase));
  } else return null;
  if (key && !cert.checkPrivateKey(key)) throw new CertificateError('CERTIFICATE_KEY_MISMATCH', 'The private key does not belong to this certificate', typeKey === 'pkcs12' ? 'bundle' : 'privateKey');
  const info = describe(cert, chain, key);
  if (opts.refuseExpired && Date.parse(info.notAfter) <= Date.now()) throw new CertificateError('CERTIFICATE_EXPIRED', `This certificate expired on ${info.notAfter}`, typeKey === 'pkcs12' ? 'bundle' : 'certificate');
  return info;
}

// ── renewal: a new key and a CSR ────────────────────────────────────

type Algorithm = RsaHashedKeyGenParams | EcKeyGenParams;
const KEY_ALGORITHMS: Record<CertificateKeyAlgorithm, Algorithm & { hash: string }> = {
  'EC-P256': { name: 'ECDSA', namedCurve: 'P-256', hash: 'SHA-256' },
  'EC-P384': { name: 'ECDSA', namedCurve: 'P-384', hash: 'SHA-384' },
  'RSA-2048': { name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
  'RSA-3072': { name: 'RSASSA-PKCS1-v1_5', modulusLength: 3072, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
  'RSA-4096': { name: 'RSASSA-PKCS1-v1_5', modulusLength: 4096, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
};

/** The renewal key algorithm that matches a certificate's current key. */
export function keyAlgorithmOf(publicKey: string): CertificateKeyAlgorithm {
  return ({ 'EC P-256': 'EC-P256', 'EC P-384': 'EC-P384', 'RSA 3072': 'RSA-3072', 'RSA 4096': 'RSA-4096' } as Record<string, CertificateKeyAlgorithm>)[publicKey] ?? (publicKey.startsWith('RSA') ? 'RSA-2048' : 'EC-P256');
}

const toPem = (der: ArrayBuffer, label: string) => `-----BEGIN ${label}-----\n${Buffer.from(der).toString('base64').match(/.{1,64}/g)!.join('\n')}\n-----END ${label}-----\n`;

/**
 * A new key pair and a CSR with the current certificate's subject and alternative names (the
 * request a CA needs to renew it). The key is returned to be stored encrypted; it is never shown.
 */
export async function renewalRequest(currentCertificatePem: string, algorithm: CertificateKeyAlgorithm): Promise<{ privateKey: string; csr: string; subject: string; subjectAltNames: string[] }> {
  const current = new x509.X509Certificate(currentCertificatePem.match(PEM_CERTIFICATE)?.[0] ?? currentCertificatePem);
  const alg = KEY_ALGORITHMS[algorithm];
  const keys = (await subtle.generateKey(alg, true, ['sign', 'verify'])) as CryptoKeyPair;
  const san = current.getExtension<x509.SubjectAlternativeNameExtension>(SAN_OID);
  const csr = await x509.Pkcs10CertificateRequestGenerator.create({
    name: current.subjectName,
    keys,
    signingAlgorithm: alg,
    extensions: san ? [new x509.SubjectAlternativeNameExtension(san.names.toJSON())] : [],
  });
  const native = new X509Certificate(currentCertificatePem.match(PEM_CERTIFICATE)?.[0] ?? currentCertificatePem);
  return {
    privateKey: toPem(await subtle.exportKey('pkcs8', keys.privateKey), 'PRIVATE KEY'),
    csr: csr.toString('pem'),
    subject: oneLine(native.subject),
    subjectAltNames: native.subjectAltName ? native.subjectAltName.split(', ') : [],
  };
}

/** WebCrypto parameters for a CA key (Node KeyObject → algorithm). */
function signingAlgorithmOf(key: KeyObject): RsaHashedImportParams | EcKeyImportParams | Algorithm | { name: 'Ed25519' } {
  if (key.asymmetricKeyType === 'rsa') return { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' } as RsaHashedImportParams;
  if (key.asymmetricKeyType === 'ec') {
    const curve = ({ prime256v1: 'P-256', secp384r1: 'P-384', secp521r1: 'P-521' } as Record<string, string>)[key.asymmetricKeyDetails?.namedCurve ?? ''];
    if (!curve) throw new CertificateError('CERTIFICATE_ISSUER_INVALID', 'The CA key uses a curve this webhook cannot sign with');
    return { name: 'ECDSA', namedCurve: curve, hash: curve === 'P-256' ? 'SHA-256' : curve === 'P-384' ? 'SHA-384' : 'SHA-512' } as EcKeyImportParams & { hash: string };
  }
  if (key.asymmetricKeyType === 'ed25519') return { name: 'Ed25519' };
  throw new CertificateError('CERTIFICATE_ISSUER_INVALID', 'The CA key type cannot sign certificates here');
}

/**
 * Issues a certificate for a CSR with a CA secret (its certificate and private key): the CSR's
 * subject, alternative names and public key, valid `days` (never past the CA's own expiry), for
 * TLS servers and clients. Returns the certificate and the CA chain to store with it.
 */
export async function issueCertificate(csrPem: string, ca: SecretPayload, days: number): Promise<{ certificate: string; chain: string }> {
  const caCerts = pemCertificates(ca.certificate, 'certificate');
  const caKey = privateKeyOf(ca.privateKey, 'privateKey');
  if (!caCerts.length || !caKey) throw new CertificateError('CERTIFICATE_ISSUER_INVALID', 'That CA secret holds no private key to issue certificates with');
  const caCert = caCerts[0]!;
  if (!caCert.ca) throw new CertificateError('CERTIFICATE_ISSUER_INVALID', 'That certificate is not a certificate authority (basicConstraints CA:FALSE)');
  if (!caCert.checkPrivateKey(caKey)) throw new CertificateError('CERTIFICATE_ISSUER_INVALID', 'The CA private key does not belong to its certificate');
  const caNotAfter = Date.parse(date(caCert, 'validTo'));
  if (caNotAfter <= Date.now()) throw new CertificateError('CERTIFICATE_ISSUER_INVALID', 'The CA certificate has expired');

  const csr = new x509.Pkcs10CertificateRequest(csrPem);
  if (!(await csr.verify())) throw new CertificateError('SECRET_INVALID', 'The certificate request is not signed by its key');
  const alg = signingAlgorithmOf(caKey);
  const signingKey = await subtle.importKey('pkcs8', caKey.export({ type: 'pkcs8', format: 'der' }), alg, false, ['sign']);
  const caX509 = new x509.X509Certificate(caCert.raw);
  const san = (csr.getExtension(SAN_OID) as x509.SubjectAlternativeNameExtension | null);
  const serial = randomBytes(16);
  serial[0] = serial[0]! & 0x7f; // positive
  const notBefore = new Date(Date.now() - 60_000);
  const notAfter = new Date(Math.min(Date.now() + days * 86_400_000, caNotAfter));
  const cert = await x509.X509CertificateGenerator.create({
    serialNumber: serial.toString('hex'),
    subject: csr.subjectName,
    issuer: caX509.subjectName,
    notBefore,
    notAfter,
    publicKey: csr.publicKey,
    signingKey,
    signingAlgorithm: alg as Algorithm,
    extensions: [
      new x509.BasicConstraintsExtension(false, undefined, true),
      new x509.KeyUsagesExtension(x509.KeyUsageFlags.digitalSignature | x509.KeyUsageFlags.keyEncipherment, true),
      new x509.ExtendedKeyUsageExtension([x509.ExtendedKeyUsage.serverAuth, x509.ExtendedKeyUsage.clientAuth]),
      await x509.SubjectKeyIdentifierExtension.create(csr.publicKey),
      await x509.AuthorityKeyIdentifierExtension.create(caX509),
      ...(san ? [new x509.SubjectAlternativeNameExtension(san.names.toJSON())] : []),
    ],
  });
  return { certificate: cert.toString('pem'), chain: caCerts.map((c) => c.toString()).join('\n') };
}

/** The public key of a stored private key, to compare with an uploaded certificate. */
export function publicKeyPem(privateKeyPemText: string): string {
  return createPublicKey(createPrivateKey(privateKeyPemText)).export({ type: 'spki', format: 'pem' }).toString();
}
