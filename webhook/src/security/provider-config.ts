/**
 * Which key protects the credential store, from the environment:
 *
 *   VAULT_KEY_PROVIDER=env (default)   VAULT_ENCRYPTION_KEY seals records directly (development, simple setups)
 *   VAULT_KEY_PROVIDER=aws-kms         KMS_KEY_ID (key id, ARN or alias), AWS_REGION, optional KMS_ENDPOINT
 *   VAULT_KEY_PROVIDER=vault-transit   VAULT_ADDR, VAULT_TRANSIT_KEY, optional VAULT_TRANSIT_MOUNT (transit),
 *                                      VAULT_TOKEN or VAULT_K8S_ROLE (+ VAULT_K8S_MOUNT, VAULT_K8S_TOKEN_PATH),
 *                                      optional VAULT_NAMESPACE
 *   KMS_DATA_KEY_CACHE_SECONDS         how long unwrapped data keys stay in memory (default 300; 0 = never cached)
 *   KMS_TIMEOUT_MS                     per call to the key service (default 2000): kept well under the control
 *                                      plane's webhook timeout, so an outage is reported as such
 *
 * With a KMS, VAULT_ENCRYPTION_KEY becomes optional: if set, it only opens records written before
 * the switch, which are then re-encrypted under the KMS at start-up. Anything malformed throws:
 * a typo must not silently fall back to another key.
 */
export type KeyProviderConfig =
  | { kind: 'env' }
  | { kind: 'aws-kms'; keyId: string; region?: string; endpoint?: string; timeoutMs: number }
  | { kind: 'vault-transit'; addr: string; mount: string; key: string; token?: string; k8sRole?: string; k8sMount?: string; k8sTokenPath?: string; namespace?: string; timeoutMs: number };

const v = (env: Record<string, string | undefined>, name: string) => env[name]?.trim() || undefined;

export function parseKeyProviderConfig(env: Record<string, string | undefined>): { provider: KeyProviderConfig; cacheSeconds: number } {
  const kind = v(env, 'VAULT_KEY_PROVIDER') ?? 'env';
  const cacheRaw = v(env, 'KMS_DATA_KEY_CACHE_SECONDS') ?? '300';
  const cacheSeconds = Number(cacheRaw);
  if (!/^\d+$/.test(cacheRaw) || cacheSeconds > 86_400) throw new Error('KMS_DATA_KEY_CACHE_SECONDS must be a whole number of seconds, at most 86400');

  const timeoutRaw = v(env, 'KMS_TIMEOUT_MS') ?? '2000';
  const timeoutMs = Number(timeoutRaw);
  if (!/^\d+$/.test(timeoutRaw) || timeoutMs < 100 || timeoutMs > 30_000) throw new Error('KMS_TIMEOUT_MS must be between 100 and 30000 milliseconds');

  if (kind === 'env') return { provider: { kind }, cacheSeconds };
  if (kind === 'aws-kms') {
    const keyId = v(env, 'KMS_KEY_ID');
    if (!keyId) throw new Error('VAULT_KEY_PROVIDER=aws-kms needs KMS_KEY_ID (a key id, ARN or alias/…)');
    const region = v(env, 'AWS_REGION') ?? v(env, 'AWS_DEFAULT_REGION');
    if (!region && !keyId.startsWith('arn:')) throw new Error('VAULT_KEY_PROVIDER=aws-kms needs AWS_REGION (or a key ARN)');
    const endpoint = v(env, 'KMS_ENDPOINT');
    if (endpoint && !/^https?:\/\//.test(endpoint)) throw new Error('KMS_ENDPOINT must be an http(s) URL');
    return { provider: { kind, keyId, region: region ?? keyId.split(':')[3], endpoint, timeoutMs }, cacheSeconds };
  }
  if (kind === 'vault-transit') {
    const addr = v(env, 'VAULT_ADDR');
    const key = v(env, 'VAULT_TRANSIT_KEY');
    if (!addr || !/^https?:\/\//.test(addr)) throw new Error('VAULT_KEY_PROVIDER=vault-transit needs VAULT_ADDR (an http(s) URL)');
    if (!key || !/^[A-Za-z0-9_.-]{1,128}$/.test(key)) throw new Error('VAULT_KEY_PROVIDER=vault-transit needs VAULT_TRANSIT_KEY (the Transit key name)');
    const mount = v(env, 'VAULT_TRANSIT_MOUNT') ?? 'transit';
    if (!/^[A-Za-z0-9_.\/-]{1,128}$/.test(mount) || mount.startsWith('/') || mount.includes('..')) throw new Error('VAULT_TRANSIT_MOUNT is not a valid mount path');
    const token = v(env, 'VAULT_TOKEN');
    const k8sRole = v(env, 'VAULT_K8S_ROLE');
    if (!token && !k8sRole) throw new Error('VAULT_KEY_PROVIDER=vault-transit needs VAULT_TOKEN or VAULT_K8S_ROLE (Kubernetes auth)');
    return { provider: { kind, addr, mount, key, token, k8sRole, k8sMount: v(env, 'VAULT_K8S_MOUNT'), k8sTokenPath: v(env, 'VAULT_K8S_TOKEN_PATH'), namespace: v(env, 'VAULT_NAMESPACE'), timeoutMs }, cacheSeconds };
  }
  throw new Error(`VAULT_KEY_PROVIDER must be env, aws-kms or vault-transit (got "${kind}")`);
}
