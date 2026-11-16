import type { SignedDefinition } from '@token-vault/shared';
import { In } from 'typeorm';
import { SIGNING } from '../../config';
import { notFound } from '../../core/ApiError';
import { sha256Hex } from '../../core/Crypto';
import AppDatabase from '../../databases/database';
import { SigningKeyEntity } from '../../entities/signingKeyEntity';
import { UserEntity } from '../../entities/userEntity';
import { VersionEntity } from '../../entities/versionEntity';
import { VersionSignatureEntity } from '../../entities/versionSignatureEntity';

/**
 * The public, signed catalog for consumers (control plane, customer webhooks). Definitions
 * are not secret; they are trusted because each one is signed with the CMS key, which
 * consumers pin. Its wire format is a contract with every deployed consumer, so it does not
 * use the admin API's response envelope.
 */
export default class CatalogService {
  private get m() {
    return AppDatabase.getInstance().manager;
  }

  async publishedEnvelopes(key?: string): Promise<SignedDefinition[]> {
    const q = this.m
      .createQueryBuilder(VersionEntity, 'v')
      .innerJoin('applications', 'app', 'app.id = v.application_id')
      .where("v.status = 'PUBLISHED' AND app.archived_at IS NULL")
      .orderBy('app.key', 'ASC');
    if (key) q.andWhere('app.key = :key', { key });
    const rows = await q.getMany();
    const people = new Map((await this.m.find(UserEntity, { select: { id: true, full_name: true } })).map((u) => [u.id, u.full_name]));
    const sigs = rows.length ? await this.m.find(VersionSignatureEntity, { where: { version_id: In(rows.map((v) => v.id)) }, order: { signed_at: 'ASC' } }) : [];
    return rows.map((v) => {
      // The active key's signature first; older keys' signatures follow (rotation overlap).
      const all = sigs.filter((x) => x.version_id === v.id).sort((a, b) => Number(b.key_id === SIGNING.keyId) - Number(a.key_id === SIGNING.keyId));
      const signatures = all.length ? all.map((x) => ({ key_id: x.key_id, signature: x.signature })) : [{ key_id: v.key_id!, signature: v.signature! }];
      return {
        definition: v.definition,
        digest: v.digest!,
        signature: signatures[0]!.signature,
        key_id: signatures[0]!.key_id,
        signatures,
        published_at: v.published_at!,
        published_by: people.get(v.submitted_by ?? '') ?? v.created_by,
        approved_by: people.get(v.reviewed_by ?? '') ?? 'System',
      };
    });
  }

  /** ETag over digests and signing keys, so consumers fetch again when a new key has signed the catalog. */
  etag(definitions: SignedDefinition[]): string {
    return `"${sha256Hex(definitions.map((d) => `${d.digest}:${(d.signatures ?? []).map((x) => x.key_id).join('+')}`).join(',')).slice(0, 32)}"`;
  }

  async definition(key: string): Promise<SignedDefinition> {
    const [def] = await this.publishedEnvelopes(key);
    if (!def) throw notFound(`Published definition "${key}"`);
    return def;
  }

  /** The active key, plus every key that has signed published versions (for rotation). */
  async publicKeys() {
    const keys = await this.m.find(SigningKeyEntity, { order: { first_used_at: 'ASC' } });
    return {
      algorithm: 'Ed25519',
      key_id: SIGNING.keyId,
      public_key_pem: SIGNING.publicKeyPem,
      keys: keys.map((k) => ({ key_id: k.key_id, public_key_pem: k.public_key_pem, active: k.key_id === SIGNING.keyId, first_used_at: k.first_used_at })),
    };
  }
}
