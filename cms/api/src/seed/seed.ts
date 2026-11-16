import { In, type EntityManager } from 'typeorm';
import { githubDefinition, validateProviderDefinition, type ProviderDefinitionInput } from '@token-vault/shared';
import { SEED_MODE } from '../config';
import { hashPassword, newId, signDefinition } from '../core/Crypto';
import AppDatabase from '../databases/database';
import { ApplicationEntity } from '../entities/applicationEntity';
import { UserEntity } from '../entities/userEntity';
import { VersionEntity } from '../entities/versionEntity';
import { SYSTEM_ACTOR, audit } from '../services/auditService/auditService.service';
import { registerActiveKey, signPublishedWithActiveKey } from '../services/signingService/signingService.service';
import { COMING_SOON_DEFINITIONS } from './seedCatalog';

/** Local demo accounts (development only). */
export const DEMO_PASSWORD = 'TokenVault-Demo-2026';
export const SEED_USERS = [
  { id: 'cmsu_editor', email: 'editor@cms.test', fullName: 'Elena Editor', role: 'EDITOR' as const },
  { id: 'cmsu_publisher', email: 'publisher@cms.test', fullName: 'Priya Publisher', role: 'PUBLISHER' as const },
  { id: 'cmsu_admin', email: 'admin@cms.test', fullName: 'Ada Admin', role: 'ADMIN' as const },
];

/** Definitions published at seed time: GitHub (bundled with Token Vault) and the "coming soon" catalog entries. */
const SEEDED = () => [githubDefinition, ...COMING_SOON_DEFINITIONS];

const db = () => AppDatabase.getInstance();

/** Seeds the demo users and the seeded definitions (published and signed), as the system. */
export async function seed() {
  await db().executeInTransaction(async (m) => {
    const t = new Date().toISOString();
    const hash = hashPassword(DEMO_PASSWORD);
    await m.insert(
      UserEntity,
      SEED_USERS.map((u) => ({ id: u.id, email: u.email, full_name: u.fullName, role: u.role, password_hash: hash, created_at: t })),
    );
    await registerActiveKey(m);
    await publishSeeded(m, SEEDED(), t);
  });
}

/** Publishes seeded definitions as the system (signed with the active key). */
async function publishSeeded(m: EntityManager, inputs: ProviderDefinitionInput[], t: string) {
  for (const input of inputs) {
    const def = validateProviderDefinition(input);
    const app = { id: newId('app'), key: def.key, name: def.name, description: def.description, created_by: 'System', created_at: t, updated_at: t, archived_at: null };
    await m.insert(ApplicationEntity, app);
    const signed = signDefinition(def);
    await m.insert(VersionEntity, {
      id: newId('ver'),
      application_id: app.id,
      version: def.version,
      status: 'PUBLISHED',
      definition: def,
      digest: signed.digest,
      signature: signed.signature,
      key_id: signed.keyId,
      created_by: 'System',
      created_at: t,
      updated_at: t,
      authors: [],
      reviewed_by: 'system',
      reviewed_at: t,
      review_note: def.key === 'github' ? 'Imported from the bundled GitHub definition' : 'Seeded catalog entry (coming soon)',
      published_at: t,
      host_change_acknowledged: true,
    });
    await audit(m, SYSTEM_ACTOR, 'version.published', { key: def.key, version: def.version }, { digest: signed.digest, keyId: signed.keyId, seeded: true });
  }
  await signPublishedWithActiveKey(m);
}

/**
 * Existing databases: publish seeded catalog entries whose application key does not exist
 * yet. An entry an admin archived or changed keeps its key, so it is never re-added.
 */
async function seedMissingCatalogEntries() {
  await db().executeInTransaction(async (m) => {
    const existing = new Set((await m.find(ApplicationEntity, { select: { key: true } })).map((a) => a.key));
    const missing = COMING_SOON_DEFINITIONS.filter((d) => !existing.has(d.key));
    if (missing.length) {
      await registerActiveKey(m);
      await publishSeeded(m, missing, new Date().toISOString());
      console.log(`[cms] added catalog entries: ${missing.map((d) => d.key).join(', ')}`);
    }
    await addGithubCatalogListing(m);
  });
}

/**
 * Databases seeded before catalog listings existed hold GitHub v1 without one. If that
 * version is still the untouched system seed, publish the next version with only the
 * bundled catalog listing added (audited). A GitHub definition anyone has changed is left alone.
 */
async function addGithubCatalogListing(m: EntityManager) {
  const app = await m.findOneBy(ApplicationEntity, { key: 'github' });
  const row = app ? await m.findOneBy(VersionEntity, { application_id: app.id, status: 'PUBLISHED' }) : null;
  const current = row?.definition as { catalog?: unknown; version: number } | undefined;
  if (!app || !row || current?.catalog || row.reviewed_by !== 'system' || row.authors.length) return;
  if (await m.existsBy(VersionEntity, { application_id: app.id, status: In(['DRAFT', 'IN_REVIEW']) })) return;
  const t = new Date().toISOString();
  const def = validateProviderDefinition({ ...(row.definition as object), version: row.version + 1, catalog: githubDefinition.catalog });
  const signed = signDefinition(def);
  await m.update(VersionEntity, { id: row.id }, { status: 'SUPERSEDED', updated_at: t });
  await m.insert(VersionEntity, {
    id: newId('ver'),
    application_id: app.id,
    version: def.version,
    status: 'PUBLISHED',
    definition: def,
    digest: signed.digest,
    signature: signed.signature,
    key_id: signed.keyId,
    created_by: 'System',
    created_at: t,
    updated_at: t,
    authors: [],
    reviewed_by: 'system',
    reviewed_at: t,
    review_note: 'Upgrade: catalog listing added (category, icon, docs link); nothing else changed',
    published_at: t,
    host_change_acknowledged: false,
  });
  await registerActiveKey(m);
  await signPublishedWithActiveKey(m);
  await audit(m, SYSTEM_ACTOR, 'version.published', { key: 'github', version: def.version }, { digest: signed.digest, keyId: signed.keyId, supersedes: row.version, upgrade: 'catalog listing' });
  console.log(`[cms] published GitHub v${def.version}: catalog listing added`);
}

export async function resetDatabase() {
  // TRUNCATE does not fire the row-level append-only / immutability triggers (test and e2e reset only).
  await db().executeExternalQuery('TRUNCATE cms_audit_events, cms_sessions, cms_version_signatures, cms_signing_keys, application_versions, applications, cms_users RESTART IDENTITY CASCADE');
  await seed();
}

export async function initData() {
  if (SEED_MODE === 'reset') {
    await resetDatabase();
    console.log('[cms] database reset and reseeded (SEED_MODE=reset)');
    return;
  }
  const count = await db().manager.count(UserEntity);
  if (count === 0) {
    await seed();
    console.log('[cms] seeded demo users, the GitHub definition and the coming-soon catalog entries');
  } else {
    await seedMissingCatalogEntries();
  }
}
