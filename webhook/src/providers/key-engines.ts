import { createCipheriv, createDecipheriv, createHmac, createPrivateKey, createPublicKey, constants, randomBytes, sign as cryptoSign, type CipherGCMTypes, verify as cryptoVerify, privateDecrypt, publicEncrypt, timingSafeEqual, type KeyObject } from 'node:crypto';
import { DecryptCommand, DescribeKeyCommand, EncryptCommand, GenerateMacCommand, KMSClient, SignCommand, VerifyCommand, VerifyMacCommand } from '@aws-sdk/client-kms';
import { KEY_OPERATION_MAX_BYTES, SECRET_KEY_CAPABILITIES, type KeyOperation, type SecretPayload } from '@token-vault/shared';
import { config } from '../config';
import { ProviderError, hostAllowed } from './secret-engines';

/**
 * Key operations (Secret Management phase 6, spec 4.9.3 E): the customer webhook uses a key for
 * an application that never sees it.
 *  - keys stored in Token Vault (aes-key, rsa-private-key, ecc-private-key, signing-key,
 *    hmac-secret, jwt-signing-secret) are used here, with Node's crypto;
 *  - keys held by Vault Transit or AWS KMS are used there, with the stored credential (Vault
 *    addresses only on PROVIDER_ALLOWED_HOSTS).
 * Inputs and outputs are base64. Nothing here logs a key, an input or an output.
 */

export class KeyOperationError extends Error {
  constructor(
    public readonly code: 'KEY_ALGORITHM_NOT_SUPPORTED' | 'KEY_INPUT_INVALID' | 'KEY_INPUT_TOO_LARGE' | 'KEY_UNREADABLE' | 'DECRYPTION_FAILED' | 'KEY_OPERATION_NOT_SUPPORTED' | 'KEY_OPERATION_FAILED',
    message: string,
  ) {
    super(message);
  }
}

export interface KeyRequest {
  operation: KeyOperation;
  /** The Token Vault version of the key (put in and checked against "tv:v<n>:" ciphertexts). */
  version: number;
  algorithm?: string;
  data?: string;
  signature?: string;
  mac?: string;
  ciphertext?: string;
  aad?: string;
}

export interface KeyResult {
  algorithm: string;
  signature?: string;
  mac?: string;
  valid?: boolean;
  ciphertext?: string;
  plaintext?: string;
}

const B64 = /^[A-Za-z0-9+/_-]*={0,2}$/;
function bytes(v: unknown, what: string, required = true): Buffer {
  if (v === undefined || v === null || v === '') {
    if (required) throw new KeyOperationError('KEY_INPUT_INVALID', `${what} is required (base64)`);
    return Buffer.alloc(0);
  }
  if (typeof v !== 'string' || !B64.test(v)) throw new KeyOperationError('KEY_INPUT_INVALID', `${what} must be base64`);
  const b = Buffer.from(v, v.includes('-') || v.includes('_') ? 'base64url' : 'base64');
  if (b.length > KEY_OPERATION_MAX_BYTES) throw new KeyOperationError('KEY_INPUT_TOO_LARGE', `${what} is larger than ${KEY_OPERATION_MAX_BYTES} bytes`);
  return b;
}

const HASH: Record<string, string> = { '256': 'sha256', '384': 'sha384', '512': 'sha512' };
const hashOf = (alg: string) => HASH[alg.slice(-3)]!;

// ── keys stored in Token Vault ──────────────────────────────────────

function privateKey(p: SecretPayload): KeyObject {
  try {
    return createPrivateKey(typeof p.passphrase === 'string' && p.passphrase ? { key: String(p.privateKey), passphrase: p.passphrase } : String(p.privateKey));
  } catch {
    throw new KeyOperationError('KEY_UNREADABLE', 'The stored private key cannot be read (or its passphrase is wrong)');
  }
}

/** Signing algorithms a key can use; the first is the default. */
function signAlgorithms(k: KeyObject): string[] {
  if (k.asymmetricKeyType === 'rsa') return ['PS256', 'PS384', 'PS512', 'RS256', 'RS384', 'RS512'];
  if (k.asymmetricKeyType === 'ec') return [({ prime256v1: 'ES256', secp384r1: 'ES384', secp521r1: 'ES512' } as Record<string, string>)[k.asymmetricKeyDetails?.namedCurve ?? ''] ?? ''].filter(Boolean);
  if (k.asymmetricKeyType === 'ed25519') return ['EdDSA'];
  return [];
}

function pick(asked: string | undefined, allowed: string[], what: string): string {
  if (!allowed.length) throw new KeyOperationError('KEY_ALGORITHM_NOT_SUPPORTED', `This key cannot ${what}`);
  if (!asked) return allowed[0]!;
  if (!allowed.includes(asked)) throw new KeyOperationError('KEY_ALGORITHM_NOT_SUPPORTED', `This key can ${what} with ${allowed.join(', ')}, not ${asked}`);
  return asked;
}

function signOpts(alg: string, key: KeyObject) {
  if (alg.startsWith('PS')) return { key, padding: constants.RSA_PKCS1_PSS_PADDING, saltLength: constants.RSA_PSS_SALTLEN_DIGEST };
  if (alg.startsWith('RS')) return { key, padding: constants.RSA_PKCS1_PADDING };
  if (alg.startsWith('ES')) return { key, dsaEncoding: 'ieee-p1363' as const };
  return { key };
}

const TV_CIPHERTEXT = /^tv:v(\d{1,6}):([A-Za-z0-9+/]+={0,2})$/;

/** The version a "tv:v<n>:" ciphertext names (the control plane picks that version's key). */
export function ciphertextVersion(ciphertext: unknown): number | null {
  const m = typeof ciphertext === 'string' ? TV_CIPHERTEXT.exec(ciphertext) : null;
  return m ? Number(m[1]) : null;
}

function parseCiphertext(c: unknown, version: number): Buffer {
  const m = typeof c === 'string' ? TV_CIPHERTEXT.exec(c) : null;
  if (!m) throw new KeyOperationError('KEY_INPUT_INVALID', 'ciphertext must be "tv:v<version>:<base64>" as encrypt returned it');
  if (Number(m[1]) !== version) throw new KeyOperationError('KEY_INPUT_INVALID', `That ciphertext was made with version ${m[1]}`);
  return Buffer.from(m[2]!, 'base64');
}

function hmacKeyOf(p: SecretPayload): Buffer {
  // The secret as text (how JWT libraries and webhook signers use it).
  return Buffer.from(String(p.secret ?? ''), 'utf8');
}

function local(typeKey: string, p: SecretPayload, r: KeyRequest): KeyResult {
  const op = r.operation;
  if (typeKey === 'aes-key') {
    const key = Buffer.from(String(p.key ?? ''), 'base64');
    if (![16, 24, 32].includes(key.length)) throw new KeyOperationError('KEY_UNREADABLE', 'The stored AES key is not 128, 192 or 256 bits');
    const alg = pick(r.algorithm, [`A${key.length * 8}GCM`], 'encrypt');
    const aad = bytes(r.aad, 'aad', false);
    if (op === 'encrypt') {
      const iv = randomBytes(12);
      const c = createCipheriv(`aes-${key.length * 8}-gcm` as CipherGCMTypes, key, iv);
      if (aad.length) c.setAAD(aad);
      const ct = Buffer.concat([c.update(bytes(r.data, 'data')), c.final()]);
      return { algorithm: alg, ciphertext: `tv:v${r.version}:${Buffer.concat([iv, ct, c.getAuthTag()]).toString('base64')}` };
    }
    if (op === 'decrypt') {
      const raw = parseCiphertext(r.ciphertext, r.version);
      if (raw.length < 28) throw new KeyOperationError('DECRYPTION_FAILED', 'The ciphertext is too short');
      try {
        const d = createDecipheriv(`aes-${key.length * 8}-gcm` as CipherGCMTypes, key, raw.subarray(0, 12));
        if (aad.length) d.setAAD(aad);
        d.setAuthTag(raw.subarray(raw.length - 16));
        return { algorithm: alg, plaintext: Buffer.concat([d.update(raw.subarray(12, raw.length - 16)), d.final()]).toString('base64') };
      } catch {
        throw new KeyOperationError('DECRYPTION_FAILED', 'The ciphertext could not be decrypted with this key version (changed, or a different aad)');
      }
    }
  }

  if (typeKey === 'hmac-secret' || typeKey === 'jwt-signing-secret') {
    const alg = pick(r.algorithm, ['HS256', 'HS384', 'HS512'], 'compute MACs');
    const mac = createHmac(hashOf(alg), hmacKeyOf(p)).update(bytes(r.data, 'data')).digest();
    if (op === 'mac') return { algorithm: alg, mac: mac.toString('base64') };
    if (op === 'verify') {
      const given = bytes(r.mac ?? r.signature, 'mac');
      return { algorithm: alg, valid: given.length === mac.length && timingSafeEqual(given, mac) };
    }
  }

  if (typeKey === 'rsa-private-key' || typeKey === 'ecc-private-key' || typeKey === 'signing-key') {
    const key = privateKey(p);
    if (op === 'sign' || op === 'verify') {
      const alg = pick(r.algorithm, signAlgorithms(key), 'sign');
      const hash = alg === 'EdDSA' ? null : hashOf(alg);
      const data = bytes(r.data, 'data');
      if (op === 'sign') return { algorithm: alg, signature: cryptoSign(hash, data, signOpts(alg, key)).toString('base64') };
      return { algorithm: alg, valid: cryptoVerify(hash, data, signOpts(alg, createPublicKey(key)) as Parameters<typeof cryptoVerify>[2], bytes(r.signature, 'signature')) };
    }
    if ((op === 'encrypt' || op === 'decrypt') && key.asymmetricKeyType === 'rsa') {
      const alg = pick(r.algorithm, ['RSA-OAEP-256'], 'encrypt');
      const oaep = { padding: constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' };
      if (op === 'encrypt') {
        const data = bytes(r.data, 'data');
        const max = (key.asymmetricKeyDetails?.modulusLength ?? 2048) / 8 - 66;
        if (data.length > max) throw new KeyOperationError('KEY_INPUT_TOO_LARGE', `RSA-OAEP with this key encrypts at most ${max} bytes; encrypt a data key instead`);
        return { algorithm: alg, ciphertext: `tv:v${r.version}:${publicEncrypt({ key: createPublicKey(key), ...oaep }, data).toString('base64')}` };
      }
      try {
        return { algorithm: alg, plaintext: privateDecrypt({ key, ...oaep }, parseCiphertext(r.ciphertext, r.version)).toString('base64') };
      } catch (e) {
        if (e instanceof KeyOperationError) throw e;
        throw new KeyOperationError('DECRYPTION_FAILED', 'The ciphertext could not be decrypted with this key version');
      }
    }
  }
  throw new KeyOperationError('KEY_OPERATION_NOT_SUPPORTED', `This key cannot ${op}`);
}

// ── Vault Transit ───────────────────────────────────────────────────

const VAULT_SIGN: Record<string, Record<string, string>> = {
  PS256: { hash_algorithm: 'sha2-256', signature_algorithm: 'pss' },
  PS384: { hash_algorithm: 'sha2-384', signature_algorithm: 'pss' },
  PS512: { hash_algorithm: 'sha2-512', signature_algorithm: 'pss' },
  RS256: { hash_algorithm: 'sha2-256', signature_algorithm: 'pkcs1v15' },
  RS384: { hash_algorithm: 'sha2-384', signature_algorithm: 'pkcs1v15' },
  RS512: { hash_algorithm: 'sha2-512', signature_algorithm: 'pkcs1v15' },
  ES256: { hash_algorithm: 'sha2-256', marshaling_algorithm: 'jws' },
  ES384: { hash_algorithm: 'sha2-384', marshaling_algorithm: 'jws' },
  ES512: { hash_algorithm: 'sha2-512', marshaling_algorithm: 'jws' },
  EdDSA: {},
};
const VAULT_MAC: Record<string, string> = { HS256: 'sha2-256', HS384: 'sha2-384', HS512: 'sha2-512' };

async function vaultTransit(p: SecretPayload, r: KeyRequest): Promise<KeyResult> {
  let base: URL;
  try {
    base = new URL(String(p.address));
  } catch {
    throw new KeyOperationError('KEY_UNREADABLE', 'The stored Vault address is not a URL');
  }
  const port = Number(base.port) || (base.protocol === 'https:' ? 443 : 80);
  if (!hostAllowed(base.hostname, port)) throw new ProviderError('PROVIDER_HOST_NOT_ALLOWED', `This webhook may not connect to ${base.hostname}:${port} (add it to PROVIDER_ALLOWED_HOSTS)`);
  const mount = String(p.mount || 'transit');
  const keyName = encodeURIComponent(String(p.keyName));
  const call = async (path: string, body: Record<string, unknown>) => {
    let res: Response;
    try {
      res = await fetch(`${base.origin}/v1/${mount}/${path}/${keyName}`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', 'x-vault-token': String(p.token ?? ''), ...(p.namespace ? { 'x-vault-namespace': String(p.namespace) } : {}) },
        body: JSON.stringify(body),
        signal: AbortSignal.timeout(5_000),
        redirect: 'error',
      });
    } catch {
      throw new ProviderError('PROVIDER_UNAVAILABLE', `Vault at ${base.host} could not be reached`, true);
    }
    const json = (await res.json().catch(() => ({}))) as { data?: Record<string, unknown>; errors?: string[] };
    if (res.ok) return json.data ?? {};
    const detail = String(json.errors?.[0] ?? '').replace(/\s+/g, ' ').slice(0, 160);
    if (res.status === 403) throw new ProviderError('PROVIDER_AUTH_FAILED', 'Vault refused the stored token for this key');
    if (res.status >= 500 || res.status === 429) throw new ProviderError('PROVIDER_UNAVAILABLE', `Vault could not ${path} (HTTP ${res.status})`, true);
    throw new KeyOperationError('KEY_OPERATION_FAILED', `Vault refused to ${path}${detail ? `: ${detail}` : ''}`);
  };
  const input = () => bytes(r.data, 'data').toString('base64');
  const signParams = (alg?: string) => {
    if (alg && !VAULT_SIGN[alg]) throw new KeyOperationError('KEY_ALGORITHM_NOT_SUPPORTED', `Vault Transit signs with ${Object.keys(VAULT_SIGN).join(', ')}`);
    return alg ? VAULT_SIGN[alg]! : {};
  };
  const macParams = (alg?: string) => {
    if (alg && !VAULT_MAC[alg]) throw new KeyOperationError('KEY_ALGORITHM_NOT_SUPPORTED', 'Vault Transit computes HS256, HS384 or HS512');
    return { algorithm: VAULT_MAC[alg ?? 'HS256'] };
  };
  switch (r.operation) {
    case 'sign': {
      const d = await call('sign', { input: input(), ...signParams(r.algorithm) });
      return { algorithm: r.algorithm ?? 'vault-default', signature: String(d.signature) };
    }
    case 'mac': {
      const d = await call('hmac', { input: input(), ...macParams(r.algorithm) });
      return { algorithm: r.algorithm ?? 'HS256', mac: String(d.hmac) };
    }
    case 'verify': {
      const isMac = r.mac !== undefined;
      if (typeof (r.mac ?? r.signature) !== 'string') throw new KeyOperationError('KEY_INPUT_INVALID', 'signature (or mac) is required');
      const d = await call('verify', { input: input(), ...(isMac ? { hmac: r.mac, ...macParams(r.algorithm) } : { signature: r.signature, ...signParams(r.algorithm) }) });
      return { algorithm: r.algorithm ?? (isMac ? 'HS256' : 'vault-default'), valid: d.valid === true };
    }
    case 'encrypt': {
      const aad = bytes(r.aad, 'aad', false);
      const d = await call('encrypt', { plaintext: input(), ...(aad.length ? { context: aad.toString('base64') } : {}) });
      return { algorithm: 'vault-transit', ciphertext: String(d.ciphertext) };
    }
    case 'decrypt': {
      if (typeof r.ciphertext !== 'string' || !r.ciphertext.startsWith('vault:')) throw new KeyOperationError('KEY_INPUT_INVALID', 'ciphertext must be "vault:v<n>:…" as encrypt returned it');
      const aad = bytes(r.aad, 'aad', false);
      const d = await call('decrypt', { ciphertext: r.ciphertext, ...(aad.length ? { context: aad.toString('base64') } : {}) });
      return { algorithm: 'vault-transit', plaintext: String(d.plaintext) };
    }
  }
}

// ── AWS KMS ─────────────────────────────────────────────────────────

const KMS_SIGN: Record<string, string> = {
  PS256: 'RSASSA_PSS_SHA_256', PS384: 'RSASSA_PSS_SHA_384', PS512: 'RSASSA_PSS_SHA_512',
  RS256: 'RSASSA_PKCS1_V1_5_SHA_256', RS384: 'RSASSA_PKCS1_V1_5_SHA_384', RS512: 'RSASSA_PKCS1_V1_5_SHA_512',
  ES256: 'ECDSA_SHA_256', ES384: 'ECDSA_SHA_384', ES512: 'ECDSA_SHA_512',
};
const KMS_MAC: Record<string, string> = { HS256: 'HMAC_SHA_256', HS384: 'HMAC_SHA_384', HS512: 'HMAC_SHA_512' };
const KMS_SIZE: Record<string, number> = { ES256: 32, ES384: 48, ES512: 66 };
const KMS_RAW_MAX = 4096;

/** ECDSA DER (KMS) ↔ r || s (JWS), so ES* signatures look the same whichever key made them. */
function derToJose(der: Buffer, size: number): Buffer {
  let i = 2 + (der[1]! & 0x80 ? der[1]! & 0x7f : 0);
  const int = () => {
    const len = der[i + 1]!;
    const v = der.subarray(i + 2, i + 2 + len);
    i += 2 + len;
    const t = v[0] === 0 ? v.subarray(1) : v;
    return Buffer.concat([Buffer.alloc(Math.max(0, size - t.length)), t]);
  };
  return Buffer.concat([int(), int()]);
}
function joseToDer(sig: Buffer, size: number): Buffer {
  if (sig.length !== size * 2) throw new KeyOperationError('KEY_INPUT_INVALID', `An ECDSA signature for this key is ${size * 2} bytes (r || s)`);
  const int = (b: Buffer) => {
    let v = b;
    while (v.length > 1 && v[0] === 0 && !(v[1]! & 0x80)) v = v.subarray(1);
    if (v[0]! & 0x80) v = Buffer.concat([Buffer.from([0]), v]);
    return Buffer.concat([Buffer.from([0x02, v.length]), v]);
  };
  const body = Buffer.concat([int(sig.subarray(0, size)), int(sig.subarray(size))]);
  return Buffer.concat([Buffer.from(body.length < 128 ? [0x30, body.length] : [0x30, 0x81, body.length]), body]);
}

const describeCache = new Map<string, { until: number; signing: string[]; mac: string[]; encryption: string[] }>();

async function awsKms(p: SecretPayload, r: KeyRequest): Promise<KeyResult> {
  const client = new KMSClient({
    region: String(p.region),
    endpoint: config.awsKmsEndpoint,
    credentials: { accessKeyId: String(p.accessKeyId), secretAccessKey: String(p.secretAccessKey) },
    maxAttempts: 2,
  });
  const KeyId = String(p.keyId);
  const fail = (e: unknown, what: string): never => {
    if (e instanceof KeyOperationError || e instanceof ProviderError) throw e;
    const err = e as { name?: string; $metadata?: { httpStatusCode?: number } };
    const status = err.$metadata?.httpStatusCode;
    if (err.name === 'KMSInvalidSignatureException') throw new KeyOperationError('KEY_INPUT_INVALID', 'invalid signature');
    if (err.name === 'InvalidCiphertextException') throw new KeyOperationError('DECRYPTION_FAILED', 'The ciphertext could not be decrypted with this key');
    if (!status || status >= 500 || err.name === 'TimeoutError' || err.name === 'KMSInternalException') throw new ProviderError('PROVIDER_UNAVAILABLE', `AWS KMS could not be reached to ${what}`, true);
    if (status === 403 || ['AccessDeniedException', 'UnrecognizedClientException', 'InvalidSignatureException'].includes(err.name ?? '')) throw new ProviderError('PROVIDER_AUTH_FAILED', `AWS refused the stored key (${what}: ${err.name})`);
    throw new KeyOperationError('KEY_OPERATION_FAILED', `AWS KMS refused to ${what} (${err.name ?? `HTTP ${status}`})`);
  };
  const describe = async () => {
    const hit = describeCache.get(`${p.region}|${KeyId}`);
    if (hit && hit.until > Date.now()) return hit;
    try {
      const m = (await client.send(new DescribeKeyCommand({ KeyId }))).KeyMetadata;
      const v = { until: Date.now() + 300_000, signing: m?.SigningAlgorithms ?? [], mac: m?.MacAlgorithms ?? [], encryption: m?.EncryptionAlgorithms ?? [] };
      describeCache.set(`${p.region}|${KeyId}`, v);
      return v;
    } catch (e) {
      return fail(e, 'describe the key');
    }
  };
  const data = () => {
    const d = bytes(r.data, 'data');
    if (d.length > KMS_RAW_MAX) throw new KeyOperationError('KEY_INPUT_TOO_LARGE', `AWS KMS accepts at most ${KMS_RAW_MAX} bytes`);
    return d;
  };
  const choose = (table: Record<string, string>, available: string[], what: string) => {
    const usable = Object.keys(table).filter((a) => available.includes(table[a]!));
    return pick(r.algorithm, usable, what);
  };
  try {
    switch (r.operation) {
      case 'sign':
      case 'verify': {
        const d = await describe();
        if (r.operation === 'verify' && r.mac !== undefined) {
          const alg = choose(KMS_MAC, d.mac, 'compute MACs');
          const out = await client.send(new VerifyMacCommand({ KeyId, Message: data(), Mac: bytes(r.mac, 'mac'), MacAlgorithm: KMS_MAC[alg] as never }));
          return { algorithm: alg, valid: out.MacValid === true };
        }
        const alg = choose(KMS_SIGN, d.signing, 'sign');
        const size = KMS_SIZE[alg];
        if (r.operation === 'sign') {
          const out = await client.send(new SignCommand({ KeyId, Message: data(), MessageType: 'RAW', SigningAlgorithm: KMS_SIGN[alg] as never }));
          const sig = Buffer.from(out.Signature ?? []);
          return { algorithm: alg, signature: (size ? derToJose(sig, size) : sig).toString('base64') };
        }
        const given = bytes(r.signature, 'signature');
        try {
          const out = await client.send(new VerifyCommand({ KeyId, Message: data(), MessageType: 'RAW', Signature: size ? joseToDer(given, size) : given, SigningAlgorithm: KMS_SIGN[alg] as never }));
          return { algorithm: alg, valid: out.SignatureValid === true };
        } catch (e) {
          if ((e as { name?: string }).name === 'KMSInvalidSignatureException') return { algorithm: alg, valid: false };
          throw e;
        }
      }
      case 'mac': {
        const alg = choose(KMS_MAC, (await describe()).mac, 'compute MACs');
        const out = await client.send(new GenerateMacCommand({ KeyId, Message: data(), MacAlgorithm: KMS_MAC[alg] as never }));
        return { algorithm: alg, mac: Buffer.from(out.Mac ?? []).toString('base64') };
      }
      case 'encrypt':
      case 'decrypt': {
        const rsa = r.algorithm === 'RSA-OAEP-256';
        if (r.algorithm && !rsa && r.algorithm !== 'A256GCM') throw new KeyOperationError('KEY_ALGORITHM_NOT_SUPPORTED', 'AWS KMS encrypts with A256GCM (symmetric keys) or RSA-OAEP-256');
        const EncryptionAlgorithm = rsa ? 'RSAES_OAEP_SHA_256' : 'SYMMETRIC_DEFAULT';
        const aad = bytes(r.aad, 'aad', false);
        // KMS takes an encryption context (strings), not bytes: the aad goes in as base64.
        const EncryptionContext = aad.length && !rsa ? { aad: aad.toString('base64') } : undefined;
        if (r.operation === 'encrypt') {
          const out = await client.send(new EncryptCommand({ KeyId, Plaintext: data(), EncryptionAlgorithm, EncryptionContext }));
          return { algorithm: rsa ? 'RSA-OAEP-256' : 'A256GCM', ciphertext: Buffer.from(out.CiphertextBlob ?? []).toString('base64') };
        }
        const out = await client.send(new DecryptCommand({ KeyId, CiphertextBlob: bytes(r.ciphertext, 'ciphertext'), EncryptionAlgorithm, EncryptionContext }));
        return { algorithm: rsa ? 'RSA-OAEP-256' : 'A256GCM', plaintext: Buffer.from(out.Plaintext ?? []).toString('base64') };
      }
    }
  } catch (e) {
    return fail(e, r.operation);
  }
}

/**
 * Keys stored in Token Vault are parsed before they are stored: a key that cannot be used (an
 * unreadable PEM, the wrong kind of key for its type, an AES key of the wrong length) is refused
 * with the field at fault. null: nothing to report.
 */
export function checkStoredKey(typeKey: string, p: SecretPayload): { field: string; message: string } | null {
  if (typeKey === 'aes-key') {
    const n = Buffer.from(String(p.key ?? ''), 'base64').length;
    return [16, 24, 32].includes(n) ? null : { field: 'key', message: 'must be 128, 192 or 256 bits (base64)' };
  }
  if (typeKey !== 'rsa-private-key' && typeKey !== 'ecc-private-key' && typeKey !== 'signing-key') return null;
  let k: KeyObject;
  try {
    k = privateKey(p);
  } catch {
    return { field: 'privateKey', message: typeKey === 'rsa-private-key' ? 'cannot be read as a private key (or the passphrase is wrong)' : 'cannot be read as a private key (PEM)' };
  }
  if (typeKey === 'rsa-private-key' && k.asymmetricKeyType !== 'rsa') return { field: 'privateKey', message: 'is not an RSA key' };
  if (typeKey === 'ecc-private-key' && k.asymmetricKeyType !== 'ec' && k.asymmetricKeyType !== 'ed25519') return { field: 'privateKey', message: 'is not an elliptic-curve or Ed25519 key' };
  return null;
}

/** Performs one key operation with a stored value of a key type (SECRET_KEY_CAPABILITIES). */
export async function keyOperation(typeKey: string, payload: SecretPayload, r: KeyRequest): Promise<KeyResult> {
  const caps = SECRET_KEY_CAPABILITIES[typeKey];
  if (!caps || !caps.operations.includes(r.operation)) throw new KeyOperationError('KEY_OPERATION_NOT_SUPPORTED', `${typeKey} keys cannot ${r.operation}`);
  if (caps.external === 'vault-transit') return vaultTransit(payload, r);
  if (caps.external === 'aws-kms') return awsKms(payload, r);
  return local(typeKey, payload, r);
}
