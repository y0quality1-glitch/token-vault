import { and, asc, eq, isNull } from 'drizzle-orm';
import { Router } from 'express';
import type { SignedDefinition } from '@token-vault/shared';
import { config } from '../config';
import { db } from '../db/client';
import { applications, users, versions } from '../db/schema';
import { sha256Hex } from '../lib/crypto';
import { notFound } from '../lib/http';

/**
 * Public, read-only catalog for consumers (control plane, customer webhooks). Definitions
 * are not secret; they are trusted because each one is signed with the CMS key, which
 * consumers pin. Served with an ETag so consumers can poll cheaply.
 */
export const catalogRouter = Router();

async function publishedEnvelopes(key?: string): Promise<SignedDefinition[]> {
  const rows = await db
    .select({ v: versions, app: applications })
    .from(versions)
    .innerJoin(applications, eq(applications.id, versions.applicationId))
    .where(and(eq(versions.status, 'PUBLISHED'), isNull(applications.archivedAt), key ? eq(applications.key, key) : undefined))
    .orderBy(asc(applications.key));
  const people = new Map((await db.select({ id: users.id, fullName: users.fullName }).from(users)).map((u) => [u.id, u.fullName]));
  return rows.map(({ v }) => ({
    definition: v.definition,
    digest: v.digest!,
    signature: v.signature!,
    key_id: v.keyId!,
    published_at: v.publishedAt!,
    published_by: people.get(v.submittedBy ?? '') ?? v.createdBy,
    approved_by: people.get(v.reviewedBy ?? '') ?? 'System',
  }));
}

catalogRouter.get('/public-key', (_req, res) => {
  res.json({ algorithm: 'Ed25519', key_id: config.keyId, public_key_pem: config.publicKeyPem });
});

catalogRouter.get('/definitions', async (req, res) => {
  const definitions = await publishedEnvelopes();
  const etag = `"${sha256Hex(definitions.map((d) => d.digest).join(',')).slice(0, 32)}"`;
  res.setHeader('ETag', etag);
  res.setHeader('Cache-Control', 'no-cache');
  if (req.headers['if-none-match'] === etag) {
    res.status(304).end();
    return;
  }
  res.json({ key_id: config.keyId, generated_at: new Date().toISOString(), definitions });
});

catalogRouter.get('/definitions/:key', async (req, res) => {
  const [def] = await publishedEnvelopes(String(req.params.key));
  if (!def) throw notFound(`Published definition "${req.params.key}"`);
  res.json(def);
});
