import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { randomBytes } from 'node:crypto';

/**
 * Tamper evidence and access reviews against a real PostgreSQL database. Skipped unless
 * TEST_DATABASE_URL is set. The database is wiped and reseeded.
 */
const url = process.env.TEST_DATABASE_URL;
const suite = url ? describe : describe.skip;

suite('audit integrity and access reviews', () => {
  let m: {
    client: typeof import('../src/databases/client');
    config: typeof import('../src/config');
    seed: typeof import('../src/store/seed');
    repos: typeof import('../src/store/repos');
    chain: typeof import('../src/services/auditService/chain');
    audit: typeof import('../src/services/auditService/auditService.service');
    reviews: typeof import('../src/services/accessReviewService/accessReviewService.service');
  };
  const ORG = 'org_demo0000000001';

  const verifyEvents = async () => {
    const { rows, legacy } = await m.repos.auditRepo.chainRows('audit_events', ORG);
    return m.chain.verify(m.config.config.auditSigningKey, 'audit_events', ORG, rows, legacy);
  };
  /** What an attacker with database write access can do: bypass the append-only trigger. */
  const asDbAttacker = async (statement: string, params: unknown[]) => {
    await m.client.transaction(async (tx) => {
      await tx.query('ALTER TABLE audit_events DISABLE TRIGGER audit_events_append_only');
      await tx.query(statement, params);
      await tx.query('ALTER TABLE audit_events ENABLE TRIGGER audit_events_append_only');
    });
  };

  beforeAll(async () => {
    process.env.DATABASE_URL = url;
    process.env.WEBHOOK_SIGNING_SECRET ??= randomBytes(32).toString('base64url');
    process.env.AUDIT_SIGNING_KEY ??= randomBytes(32).toString('base64url');
    process.env.DB_POOL_MAX = '8';
    m = {
      client: await import('../src/databases/client'),
      config: await import('../src/config'),
      seed: await import('../src/store/seed'),
      repos: await import('../src/store/repos'),
      chain: await import('../src/services/auditService/chain'),
      audit: await import('../src/services/auditService/auditService.service'),
      reviews: await import('../src/services/accessReviewService/accessReviewService.service'),
    };
    await m.client.runMigrations();
    await m.seed.resetDatabase();
  }, 60_000);

  afterAll(async () => {
    await m?.client.closeDatabase();
  });

  it('the seeded history is fully chained and verifies, in both tables', async () => {
    const events = await verifyEvents();
    expect(events).toMatchObject({ ok: true, legacyRecords: 0 });
    expect(events.chainedRecords).toBeGreaterThan(10);
    const { rows, legacy } = await m.repos.auditRepo.chainRows('access_requests', ORG);
    expect(m.chain.verify(m.config.config.auditSigningKey, 'access_requests', ORG, rows, legacy)).toMatchObject({ ok: true, legacyRecords: 0 });
  });

  it('concurrent writers extend one unbroken chain', async () => {
    const before = (await verifyEvents()).headSeq!;
    await Promise.all(
      Array.from({ length: 25 }, (_, i) =>
        m.audit.recordEvent({ orgId: ORG, actor: m.audit.SYSTEM_ACTOR, eventType: 'test.concurrent', target: { type: 'test', id: String(i), name: `t${i}` } }),
      ),
    );
    const after = await verifyEvents();
    expect(after.ok).toBe(true);
    expect(after.headSeq).toBe(before + 25);
  });

  it('detects a record edited in the database', async () => {
    const head = (await verifyEvents()).headSeq!;
    const target = head - 3;
    await asDbAttacker(`UPDATE audit_events SET actor_name = 'Mallory' WHERE organization_id = $1 AND seq = $2`, [ORG, target]);
    const r = await verifyEvents();
    expect(r.ok).toBe(false);
    expect(r.problems).toContainEqual(expect.objectContaining({ seq: target, kind: 'hash_mismatch' }));
  });

  it('detects a deleted record and a forged one', async () => {
    await m.seed.resetDatabase();
    const head = (await verifyEvents()).headSeq!;
    await asDbAttacker('DELETE FROM audit_events WHERE organization_id = $1 AND seq = $2', [ORG, head - 1]);
    expect((await verifyEvents()).problems).toContainEqual(expect.objectContaining({ seq: head, kind: 'sequence_gap' }));

    await m.seed.resetDatabase();
    const { rows } = await m.repos.auditRepo.chainRows('audit_events', ORG);
    const last = rows.at(-1)!;
    const forged = { ...(last as Record<string, unknown>), id: 'evt_forged000000000', actorName: 'Mallory', createdAt: new Date().toISOString() };
    const fields = m.chain.link(randomBytes(32).toString('hex'), 'audit_events', ORG, { seq: last.seq, hash: last.hash! }, forged);
    const { AuditEventEntity } = await import('../src/entities');
    await m.client.db.insert(AuditEventEntity, { ...m.chain.content(forged), ...fields } as never);
    expect((await verifyEvents()).problems).toContainEqual(expect.objectContaining({ seq: last.seq + 1, kind: 'mac_invalid' }));
  });

  it('flags grants due for review, certifies them, and refuses inactive grants', async () => {
    await m.seed.resetDatabase();
    const { IDS } = m.seed;
    const review = await m.reviews.buildReview(ORG);
    const item = (id: string) => review.items.find((i) => i.grant.id === id);
    expect(item(IDS.grtRelease)).toMatchObject({ due: true, lastReviewedAt: null });
    expect(item(IDS.grtIssue)).toMatchObject({ due: false, lastReviewedByName: 'Sam Okafor' });
    expect(item(IDS.grtStaging)).toBeUndefined(); // expired grants are not reviewed, they are already inactive
    expect(review.due).toBeGreaterThanOrEqual(1);

    await m.repos.grantRepo.updateGrant(IDS.grtRelease, { lastReviewedAt: new Date().toISOString(), lastReviewedBy: IDS.securityAdmin });
    expect((await m.reviews.buildReview(ORG)).items.find((i) => i.grant.id === IDS.grtRelease)).toMatchObject({ due: false, lastReviewedByName: 'Sam Okafor' });
  });
});
