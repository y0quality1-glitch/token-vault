import { DecryptCommand, EncryptCommand, KMSClient } from '@aws-sdk/client-kms';
import { KeyAccessDeniedError, KeyServiceUnavailableError, type KeyProvider } from '../key-provider';

/** AWS errors that mean "this key or ciphertext will not open", as opposed to "try again later". */
const DENIED = new Set([
  'AccessDeniedException',
  'InvalidCiphertextException',
  'IncorrectKeyException',
  'NotFoundException',
  'DisabledException',
  'KMSInvalidStateException',
  'InvalidKeyUsageException',
  'InvalidGrantTokenException',
]);

function classify(e: unknown, action: string): Error {
  const err = e as Error & { name?: string; $fault?: string };
  if (err?.name && DENIED.has(err.name)) return new KeyAccessDeniedError(`AWS KMS refused to ${action} (${err.name})`);
  // Throttling, KMS internal errors, timeouts, network and credential problems: the data is fine, retry later.
  return new KeyServiceUnavailableError(`AWS KMS could not ${action} (${err?.name ?? 'error'})`);
}

/**
 * AWS KMS: data keys are encrypted under a KMS key (symmetric, ENCRYPT_DECRYPT). The credential
 * reference is passed as encryption context, so it is authenticated and appears in CloudTrail.
 * Credentials come from the default AWS chain (IRSA / Pod Identity, ECS task role, instance
 * profile, or environment variables); the webhook never stores AWS credentials itself.
 */
export function awsKmsProvider(opts: { keyId: string; region?: string; endpoint?: string; timeoutMs?: number }): KeyProvider {
  // Short timeouts and one retry: an outage must surface well within the control plane's webhook timeout.
  const timeout = opts.timeoutMs ?? 2000;
  const client = new KMSClient({ region: opts.region, endpoint: opts.endpoint, maxAttempts: 2, requestHandler: { connectionTimeout: Math.min(1000, timeout), requestTimeout: timeout } });
  const ref = `aws-kms:${opts.keyId}`;
  return {
    kind: 'aws-kms',
    ref,
    handles: (r) => r.startsWith('aws-kms:'),
    async wrap(dataKey, context) {
      try {
        const out = await client.send(new EncryptCommand({ KeyId: opts.keyId, Plaintext: dataKey, EncryptionContext: context }));
        if (!out.CiphertextBlob) throw new KeyServiceUnavailableError('AWS KMS returned no ciphertext');
        return Buffer.from(out.CiphertextBlob).toString('base64');
      } catch (e) {
        throw e instanceof KeyServiceUnavailableError ? e : classify(e, 'wrap a data key');
      }
    },
    async unwrap(wrapped, context, recordRef) {
      try {
        // Name the key the record was wrapped with: KMS then refuses a ciphertext from any other key.
        const out = await client.send(new DecryptCommand({ CiphertextBlob: Buffer.from(wrapped, 'base64'), EncryptionContext: context, KeyId: recordRef.slice('aws-kms:'.length) }));
        if (!out.Plaintext) throw new KeyAccessDeniedError('AWS KMS returned no plaintext');
        return Buffer.from(out.Plaintext);
      } catch (e) {
        throw e instanceof KeyAccessDeniedError ? e : classify(e, 'unwrap a data key');
      }
    },
  };
}
