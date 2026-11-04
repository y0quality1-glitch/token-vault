import { sql } from 'drizzle-orm';
import { githubDefinition, validateProviderDefinition } from '@token-vault/shared';
import { config } from './config';
import { db, transaction } from './db/client';
import { applications, users, versions } from './db/schema';
import { hashPassword, newId, signDefinition } from './lib/crypto';
import { SYSTEM_ACTOR, audit } from './modules/audit';

/** Local demo accounts (development only). */
export const DEMO_PASSWORD = 'TokenVault-Demo-2026';
export const SEED_USERS = [
  { id: 'cmsu_editor', email: 'editor@cms.test', fullName: 'Elena Editor', role: 'EDITOR' as const },
  { id: 'cmsu_publisher', email: 'publisher@cms.test', fullName: 'Priya Publisher', role: 'PUBLISHER' as const },
  { id: 'cmsu_admin', email: 'admin@cms.test', fullName: 'Ada Admin', role: 'ADMIN' as const },
];

/** Seeds the demo users and GitHub v1 (published and signed), as the system. */
export async function seed() {
  await transaction(async (tx) => {
    const t = new Date().toISOString();
    const hash = hashPassword(DEMO_PASSWORD);
    await tx.insert(users).values(SEED_USERS.map((u) => ({ ...u, passwordHash: hash, createdAt: t })));
    const def = validateProviderDefinition(githubDefinition);
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
      reviewNote: 'Imported from the bundled GitHub definition',
      publishedAt: t,
      hostChangeAcknowledged: true,
    });
    await audit(tx, SYSTEM_ACTOR, 'version.published', { key: def.key, version: def.version }, { digest: signed.digest, keyId: signed.keyId, seeded: true });
  });
}

export async function resetDatabase() {
  // TRUNCATE does not fire the row-level append-only / immutability triggers (test and e2e reset only).
  await db.execute(sql`TRUNCATE cms_audit_events, cms_sessions, application_versions, applications, cms_users RESTART IDENTITY CASCADE`);
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
    console.log('[cms] seeded demo users and the GitHub definition');
  }
}
