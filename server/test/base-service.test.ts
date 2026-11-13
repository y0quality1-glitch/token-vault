import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { randomBytes } from 'node:crypto';

/**
 * BaseServices (template: services/baseService.ts) against a real PostgreSQL database: lists are
 * scoped to the organization, paged (always limited), searchable and report the total; lookups
 * never reach another organization's records. Skipped unless TEST_DATABASE_URL is set.
 */
const url = process.env.TEST_DATABASE_URL;
const suite = url ? describe : describe.skip;

suite('BaseServices', () => {
  let m: {
    client: typeof import('../src/databases/client');
    seed: typeof import('../src/store/seed');
    agents: InstanceType<typeof import('../src/services/agentService/agentService.service').default>;
    policies: InstanceType<typeof import('../src/services/policyService/policyService.service').default>;
    members: InstanceType<typeof import('../src/services/memberService/memberService.service').default>;
    events: InstanceType<typeof import('../src/services/auditEventService/auditEventService.service').default>;
  };

  beforeAll(async () => {
    process.env.DATABASE_URL = url;
    process.env.WEBHOOK_SIGNING_SECRET ??= randomBytes(32).toString('base64url');
    process.env.AUDIT_SIGNING_KEY ??= randomBytes(32).toString('base64url');
    process.env.DB_POOL_MAX = '4';
    const client = await import('../src/databases/client');
    const seed = await import('../src/store/seed');
    await client.runMigrations();
    await seed.resetDatabase();
    m = {
      client,
      seed,
      agents: new (await import('../src/services/agentService/agentService.service')).default(),
      policies: new (await import('../src/services/policyService/policyService.service')).default(),
      members: new (await import('../src/services/memberService/memberService.service')).default(),
      events: new (await import('../src/services/auditEventService/auditEventService.service')).default(),
    };
  }, 60_000);

  afterAll(async () => {
    await m?.client.closeDatabase();
  });

  it('lists the organization’s records in the module’s order, with the total', async () => {
    const all = await m.agents.list(m.seed.IDS.demoOrg);
    // Agents: oldest first.
    const created = all.items.map((a) => a.createdAt);
    expect(created).toEqual([...created].sort());
    expect(new Set(all.items.map((a) => a.id))).toEqual(new Set([m.seed.IDS.agtAssistant, m.seed.IDS.agtRelease, m.seed.IDS.agtTriage]));
    expect(all.total).toBe(3);
    // Sandbox agents are never listed for the demo organization, and the other way round.
    expect((await m.agents.list(m.seed.IDS.sandboxOrg)).items.every((a) => a.organizationId === m.seed.IDS.sandboxOrg)).toBe(true);
    const p = await m.policies.list(m.seed.IDS.demoOrg);
    expect(p.items.map((x) => x.priority)).toEqual([...p.items.map((x) => x.priority)].sort((a, b) => a - b));
  });

  it('pages (always limited), and the total counts every page', async () => {
    const page1 = await m.agents.list(m.seed.IDS.demoOrg, { pageNumber: 1, pageSize: 2 });
    const page2 = await m.agents.list(m.seed.IDS.demoOrg, { pageNumber: 2, pageSize: 2 });
    expect(page1.items).toHaveLength(2);
    expect(page2.items).toHaveLength(1);
    expect(page1.total).toBe(3);
    expect(new Set([...page1.items, ...page2.items].map((a) => a.id)).size).toBe(3);
    // A huge pageSize is clamped (template fix B-09).
    expect((await m.agents.list(m.seed.IDS.demoOrg, { pageSize: 1_000_000 })).items.length).toBeLessThanOrEqual(500);
  });

  it('searches the module’s columns with escaped input', async () => {
    expect((await m.agents.list(m.seed.IDS.demoOrg, { search: 'release' })).items.map((a) => a.id)).toEqual([m.seed.IDS.agtRelease]);
    expect((await m.agents.list(m.seed.IDS.demoOrg, { search: '%' })).items).toEqual([]);
    expect((await m.members.list(m.seed.IDS.demoOrg, { search: 'security@demo' })).items.map((x) => x.email)).toEqual(['security@demo.test']);
    // The audit lists keep their old `limit` and filters.
    const events = await m.events.list(m.seed.IDS.demoOrg, { limit: 2, eventType: 'grant.' });
    expect(events.items).toHaveLength(2);
    expect(events.items.every((e) => e.eventType.startsWith('grant.'))).toBe(true);
    expect(events.total).toBeGreaterThan(2);
  });

  it('never returns another organization’s record, nor any record for a missing id', async () => {
    await expect(m.agents.getById(m.seed.IDS.demoOrg, m.seed.IDS.agtAssistant)).resolves.toMatchObject({ id: m.seed.IDS.agtAssistant });
    await expect(m.agents.getById(m.seed.IDS.sandboxOrg, m.seed.IDS.agtAssistant)).rejects.toMatchObject({ status: 404 });
    await expect(m.agents.getById(m.seed.IDS.demoOrg, undefined as unknown as string)).rejects.toMatchObject({ status: 404 });
    await expect(m.agents.getById(m.seed.IDS.demoOrg, '')).rejects.toMatchObject({ status: 404 });
  });
});
