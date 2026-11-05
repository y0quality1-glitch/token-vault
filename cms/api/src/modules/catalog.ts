import { and, asc, eq, inArray, isNull } from "drizzle-orm";
import { Router } from "express";
import type { SignedDefinition } from "@token-vault/shared";
import { config } from "../config";
import { db } from "../db/client";
import {
  applications,
  signingKeys,
  users,
  versionSignatures,
  versions,
} from "../db/schema";
import { sha256Hex } from "../lib/crypto";
import { notFound } from "../lib/http";

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
    .where(
      and(
        eq(versions.status, "PUBLISHED"),
        isNull(applications.archivedAt),
        key ? eq(applications.key, key) : undefined,
      ),
    )
    .orderBy(asc(applications.key));
  const people = new Map(
    (
      await db.select({ id: users.id, fullName: users.fullName }).from(users)
    ).map((u) => [u.id, u.fullName]),
  );
  const sigs = rows.length
    ? await db
        .select()
        .from(versionSignatures)
        .where(
          inArray(
            versionSignatures.versionId,
            rows.map((r) => r.v.id),
          ),
        )
        .orderBy(asc(versionSignatures.signedAt))
    : [];
  return rows.map(({ v }) => {
    // The active key's signature first; older keys' signatures follow (rotation overlap).
    const all = sigs
      .filter((x) => x.versionId === v.id)
      .sort(
        (a, b) =>
          Number(b.keyId === config.keyId) - Number(a.keyId === config.keyId),
      );
    const signatures = all.length
      ? all.map((x) => ({ key_id: x.keyId, signature: x.signature }))
      : [{ key_id: v.keyId!, signature: v.signature! }];
    return {
      definition: v.definition,
      digest: v.digest!,
      signature: signatures[0]!.signature,
      key_id: signatures[0]!.key_id,
      signatures,
      published_at: v.publishedAt!,
      published_by: people.get(v.submittedBy ?? "") ?? v.createdBy,
      approved_by: people.get(v.reviewedBy ?? "") ?? "System",
    };
  });
}

/** The active key, plus every key that has signed published versions (for rotation). */
catalogRouter.get("/public-key", async (_req, res) => {
  const keys = await db
    .select()
    .from(signingKeys)
    .orderBy(asc(signingKeys.firstUsedAt));
  res.json({
    algorithm: "Ed25519",
    key_id: config.keyId,
    public_key_pem: config.publicKeyPem,
    keys: keys.map((k) => ({
      key_id: k.keyId,
      public_key_pem: k.publicKeyPem,
      active: k.keyId === config.keyId,
      first_used_at: k.firstUsedAt,
    })),
  });
});

catalogRouter.get("/definitions", async (req, res) => {
  const definitions = await publishedEnvelopes();
  // Covers signatures too, so consumers fetch again when a new key has signed the catalog.
  const etag = `"${sha256Hex(definitions.map((d) => `${d.digest}:${(d.signatures ?? []).map((x) => x.key_id).join("+")}`).join(",")).slice(0, 32)}"`;
  res.setHeader("ETag", etag);
  res.setHeader("Cache-Control", "no-cache");
  if (req.headers["if-none-match"] === etag) {
    res.status(304).end();
    return;
  }
  res.json({
    key_id: config.keyId,
    generated_at: new Date().toISOString(),
    definitions,
  });
});

catalogRouter.get("/definitions/:key", async (req, res) => {
  const [def] = await publishedEnvelopes(String(req.params.key));
  if (!def) throw notFound(`Published definition "${req.params.key}"`);
  res.json(def);
});
