import { and, eq, inArray, sql } from 'drizzle-orm';
import { githubDefinition, validateProviderDefinition, type ProviderDefinitionInput } from '@token-vault/shared';
import { config } from './config';
import { db, transaction, type Tx } from './db/client';
import { applications, users, versions } from './db/schema';
import { hashPassword, newId, signDefinition } from './lib/crypto';
import { SYSTEM_ACTOR, audit } from './modules/audit';
import { COMING_SOON_DEFINITIONS } from './seed-catalog';
import { registerActiveKey, signPublishedWithActiveKey } from './modules/signing';

/** Local demo accounts (development only). */
export const DEMO_PASSWORD = 'TokenVault-Demo-2026';
export const SEED_USERS = [
  { id: 'cmsu_editor', email: 'editor@cms.test', fullName: 'Elena Editor', role: 'EDITOR' as const },
  { id: 'cmsu_publisher', email: 'publisher@cms.test', fullName: 'Priya Publisher', role: 'PUBLISHER' as const },
  { id: 'cmsu_admin', email: 'admin@cms.test', fullName: 'Ada Admin', role: 'ADMIN' as const },
];

/** Definitions published at seed time: GitHub (bundled with Token Vault) and the "coming soon" catalog entries. */
const SEEDED = () => [githubDefinition, ...COMING_SOON_DEFINITIONS];

/** Seeds the demo users and the seeded definitions (published and signed), as the system. */
export async function seed() {
  await transaction(async (tx) => {
    const t = new Date().toISOString();
    const hash = hashPassword(DEMO_PASSWORD);
    await tx.insert(users).values(SEED_USERS.map((u) => ({ ...u, passwordHash: hash, createdAt: t })));
    await registerActiveKey(tx);
    await publishSeeded(tx, SEEDED(), t);
  });
}

/** Publishes seeded definitions as the system (signed with the active key). */
async function publishSeeded(tx: Tx, inputs: ProviderDefinitionInput[], t: string) {
  for (const input of inputs) {
    const def = validateProviderDefinition(input);
    const app = { id: newId('app'), key: def.key, name: def.name, description: def.description, createdBy: 'System', createdAt: t, updatedAt: t };
    await tx.insert(applications).values(app);
    const signed = signDefinition(def);
    await tx.insert(versions).values({
      id: newId('ver'),
      applicationId: app.id,
      version: def.version,
      status: 'PUBLISHED',
      definition: def,
      ...signed,
      createdBy: 'System',
      createdAt: t,
      updatedAt: t,
      authors: [],
      reviewedBy: 'system',
      reviewedAt: t,
      reviewNote: def.key === 'github' ? 'Imported from the bundled GitHub definition' : 'Seeded catalog entry (coming soon)',
      publishedAt: t,
      hostChangeAcknowledged: true,
    });
    await audit(tx, SYSTEM_ACTOR, 'version.published', { key: def.key, version: def.version }, { digest: signed.digest, keyId: signed.keyId, seeded: true });
  }
  await signPublishedWithActiveKey(tx);
}

/**
 * Existing databases: publish seeded catalog entries whose application key does not exist
 * yet. An entry an admin archived or changed keeps its key, so it is never re-added.
 */
async function seedMissingCatalogEntries() {
  await transaction(async (tx) => {
    const existing = new Set((await tx.select({ key: applications.key }).from(applications)).map((a) => a.key));
    const missing = COMING_SOON_DEFINITIONS.filter((d) => !existing.has(d.key));
    if (missing.length) {
      await registerActiveKey(tx);
      await publishSeeded(tx, missing, new Date().toISOString());
      console.log(`[cms] added catalog entries: ${missing.map((d) => d.key).join(', ')}`);
    }
    await addGithubCatalogListing(tx);
  });
}

/**
 * Databases seeded before catalog listings existed hold GitHub v1 without one. If that
 * version is still the untouched system seed, publish the next version with only the
 * bundled catalog listing added (audited). A GitHub definition anyone has changed is left alone.
 */
async function addGithubCatalogListing(tx: Tx) {
  const [row] = await tx
    .select({ v: versions, app: applications })
    .from(versions)
    .innerJoin(applications, eq(applications.id, versions.applicationId))
    .where(and(eq(applications.key, 'github'), eq(versions.status, 'PUBLISHED')));
  const current = row?.v.definition as { catalog?: unknown; version: number } | undefined;
  if (!row || current?.catalog || row.v.reviewedBy !== 'system' || row.v.authors.length) return;
  const [open] = await tx.select({ id: versions.id }).from(versions).where(and(eq(versions.applicationId, row.app.id), inArray(versions.status, ['DRAFT', 'IN_REVIEW'])));
  if (open) return;
  const t = new Date().toISOString();
  const def = validateProviderDefinition({ ...(row.v.definition as object), version: row.v.version + 1, catalog: githubDefinition.catalog });
  const signed = signDefinition(def);
  await tx.update(versions).set({ status: 'SUPERSEDED', updatedAt: t }).where(eq(versions.id, row.v.id));
  const id = newId('ver');
  await tx.insert(versions).values({
    id,
    applicationId: row.app.id,
    version: def.version,
    status: 'PUBLISHED',
    definition: def,
    ...signed,
    createdBy: 'System',
    createdAt: t,
    updatedAt: t,
    authors: [],
    reviewedBy: 'system',
    reviewedAt: t,
    reviewNote: 'Upgrade: catalog listing added (category, icon, docs link); nothing else changed',
    publishedAt: t,
    hostChangeAcknowledged: false,
  });
  await registerActiveKey(tx);
  await signPublishedWithActiveKey(tx);
  await audit(tx, SYSTEM_ACTOR, 'version.published', { key: 'github', version: def.version }, { digest: signed.digest, keyId: signed.keyId, supersedes: row.v.version, upgrade: 'catalog listing' });
  console.log(`[cms] published GitHub v${def.version}: catalog listing added`);
}

export async function resetDatabase() {
  // TRUNCATE does not fire the row-level append-only / immutability triggers (test and e2e reset only).
  await db.execute(sql`TRUNCATE cms_audit_events, cms_sessions, cms_version_signatures, cms_signing_keys, application_versions, applications, cms_users RESTART IDENTITY CASCADE`);
  await seed();
}

export async function initData() {
  if (config.seedMode === 'reset') {
    await resetDatabase();
    console.log('[cms] database reset and reseeded (SEED_MODE=reset)');
    return;
  }
  const [{ count }] = (await db.execute(sql`select count(*)::int as count from cms_users`)).rows as [{ count: number }];
  if (count === 0) {
    await seed();
    console.log('[cms] seeded demo users, the GitHub definition and the coming-soon catalog entries');
  } else {
    await seedMissingCatalogEntries();
  }
}
