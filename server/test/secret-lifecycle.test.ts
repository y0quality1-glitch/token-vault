import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { createHmac, randomBytes } from 'node:crypto';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { BUILTIN_SECRET_TYPES, generatableSecretFields, generateSecretFieldValue, summarizeSecretPayload, validateSecretPayload, validateSecretTypeDefinition, type SecretPayload } from '@token-vault/shared';

/**
 * Secret Management phase 4 against a real PostgreSQL database: the lifecycle job (expiry,
 * scheduled rotation, retries, version retention) with expiry and retention policies, and
 * notifications (signed outbound webhooks, email) for the events it produces. The customer
 * webhook is an in-memory stand-in that also generates values. Skipped unless TEST_DATABASE_URL
 * is set. The database is reseeded.
 */
const url = process.env.TEST_DATABASE_URL;
const suite = url ? describe : describe.skip;

const vault = vi.hoisted(() => ({
  values: new Map<string, { org: string; secret: string; version: number; type: string; payload: Record<string, unknown> }>(),
  down: false,
}));
vi.mock('../src/services/webhookService/webhook.client', async (orig) => {
  const real = await orig<typeof import('../src/services/webhookService/webhook.client')>();
  const types = new Map(BUILTIN_SECRET_TYPES.map((t) => [t.key, validateSecretTypeDefinition(t)]));
  let n = 0;
  const put = (v: { org: string; secret: string; version: number; type: string; payload: Record<string, unknown> }, extra = {}) => {
    const ref = `sval_${++n}`;
    vault.values.set(ref, v);
    return { status: 201, latencyMs: 1, body: { value_ref: ref, version: v.version, fingerprint: `fp_${n}`, summary: summarizeSecretPayload(types.get(v.type)!, v.payload as SecretPayload), type_version: 2, ...extra } };
  };
  return {
    ...real,
    callWebhook: async (_wh: unknown, _method: string, path: string, body: Record<string, any>) => {
      if (vault.down) throw new real.WebhookUnavailableError('UNREACHABLE', 'Customer webhook unreachable');
      if (path === '/internal/v1/secrets/store') {
        const { issues, value } = validateSecretPayload(types.get(body.type_key)!, body.payload);
        if (Object.keys(issues).length) return { status: 400, latencyMs: 1, body: { error: { code: 'SECRET_INVALID', details: { fields: issues } } } };
        return put({ org: body.org_id, secret: body.secret_id, version: body.version, type: body.type_key, payload: value });
      }
      const v = vault.values.get(body.value_ref ?? body.from_ref);
      const mine = v && v.org === body.org_id && v.secret === body.secret_id;
      if (path === '/internal/v1/secrets/read') return mine ? { status: 200, latencyMs: 1, body: { version: v.version, payload: v.payload } } : { status: 404, latencyMs: 1, body: {} };
      if (path === '/internal/v1/secrets/generate') {
        if (!mine) return { status: 404, latencyMs: 1, body: {} };
        const type = types.get(v.type)!;
        const fields = generatableSecretFields(type);
        if (!fields.length) return { status: 409, latencyMs: 1, body: { error: { code: 'SECRET_NOT_GENERATABLE', message: 'cannot generate' } } };
        const payload = { ...v.payload, ...Object.fromEntries(fields.map((f) => [f, generateSecretFieldValue(type.fields[f]!.generate!)])) };
        return put({ ...v, version: body.version, payload }, { generated_fields: fields });
      }
      if (path === '/internal/v1/secrets/destroy') {
        const destroyed = (body.value_refs as string[]).filter((r) => vault.values.get(r)?.secret === body.secret_id);
        destroyed.forEach((r) => vault.values.delete(r));
        return { status: 200, latencyMs: 1, body: { destroyed } };
      }
      return { status: 404, latencyMs: 1, body: {} };
    },
  };
});

suite('Secret lifecycle: expiry, rotation, retention, notifications', () => {
  let m: {
    client: typeof import('../src/databases/client');
    seed: typeof import('../src/store/seed');
    entities: typeof import('../src/entities');
    job: typeof import('../src/services/secretService/secretLifecycle.job');
    notify: typeof import('../src/services/notificationService/notificationService.service');
    svc: InstanceType<typeof import('../src/services/secretService/secretService.service').default>;
    policies: InstanceType<typeof import('../src/services/secretPolicyService/secretPolicyService.service').default>;
    channels: InstanceType<typeof import('../src/services/notificationService/notificationService.service').default>;
  };
  let ctx: any;
  let receiver: Server;
  let receiverUrl = '';
  const received: { headers: Record<string, string | string[] | undefined>; body: string }[] = [];
  let receiverStatus = 200;
  const mails: { to: string[]; subject: string; text: string }[] = [];

  const sql = (q: string, params: unknown[] = []) => m.client.db.query(q, params);
  const events = async (secretId: string) => ((await m.client.db.find(m.entities.AuditEventEntity, { where: { targetId: secretId }, order: { createdAt: 'ASC' } })) as any[]).map((e) => e.eventType);
  const secret = (id: string) => m.client.db.findOneByOrFail(m.entities.SecretEntity, { id });
  const create = (name: string, extra: Record<string, unknown> = {}) =>
    m.svc.create(ctx, { name, typeKey: 'hmac-secret', project: 'billing', environment: 'production', payload: { secret: 'an initial shared secret of 32+ chars' }, ...extra } as any);
  const run = async () => (await m.job.runSecretLifecycle())!;

  beforeAll(async () => {
    process.env.DATABASE_URL = url;
    process.env.WEBHOOK_SIGNING_SECRET ??= randomBytes(32).toString('base64url');
    process.env.AUDIT_SIGNING_KEY ??= randomBytes(32).toString('base64url');
    process.env.DB_POOL_MAX = '4';
    process.env.CMS_CATALOG_URL = '';
    const notify = await import('../src/services/notificationService/notificationService.service');
    m = {
      client: await import('../src/databases/client'),
      seed: await import('../src/store/seed'),
      entities: await import('../src/entities'),
      job: await import('../src/services/secretService/secretLifecycle.job'),
      notify,
      svc: new (await import('../src/services/secretService/secretService.service')).default(),
      policies: new (await import('../src/services/secretPolicyService/secretPolicyService.service')).default(),
      channels: new notify.default(),
    };
    m.notify.mailer.send = async (msg) => void mails.push(msg);
    await m.client.runMigrations();
    await m.seed.resetDatabase();
    ctx = { user: { id: m.seed.IDS.owner, fullName: 'Olivia Owner' }, org: { id: m.seed.IDS.demoOrg, name: 'Demo Organization' }, role: 'OWNER' };
    receiver = createServer((req, res) => {
      let body = '';
      req.on('data', (c) => (body += c));
      req.on('end', () => {
        received.push({ headers: req.headers, body });
        res.writeHead(receiverStatus).end();
      });
    });
    await new Promise<void>((r) => receiver.listen(0, '127.0.0.1', r));
    receiverUrl = `http://127.0.0.1:${(receiver.address() as AddressInfo).port}/hooks/token-vault`;
  }, 60_000);
  beforeEach(() => {
    vault.down = false;
  });
  afterAll(async () => {
    receiver?.close();
    await m?.client.closeDatabase();
  });

  it('expiry: ACTIVE → EXPIRING inside the warning window → EXPIRED, and back to ACTIVE when renewed', async () => {
    const s = await create('expiring-key', { expiresAt: new Date(Date.now() + 3 * 86_400_000).toISOString(), rotationEnabled: false });
    expect(s.status).toBe('ACTIVE');
    await run();
    expect((await secret(s.id)).status).toBe('EXPIRING');
    expect(await events(s.id)).toContain('secret.expiring');
    // Still retrievable while expiring.
    expect((await m.svc.retrieve(ctx, { id: s.id } as any)).version).toBe(1);

    await sql(`UPDATE secrets SET expires_at = now() + interval '100 days' WHERE id = $1`, [s.id]);
    await run();
    expect((await secret(s.id)).status).toBe('ACTIVE');

    await sql(`UPDATE secrets SET expires_at = now() - interval '1 minute' WHERE id = $1`, [s.id]);
    const r = await run();
    expect(r.expired).toBeGreaterThanOrEqual(1);
    expect((await secret(s.id)).status).toBe('EXPIRED');
    await expect(m.svc.retrieve(ctx, { id: s.id } as any)).rejects.toMatchObject({ code: 'SECRET_EXPIRED' });
    expect((await events(s.id)).filter((e) => e === 'secret.expired')).toHaveLength(1);
    await run(); // nothing more happens to it
    expect((await events(s.id)).filter((e) => e === 'secret.expired')).toHaveLength(1);
  });

  it('policies: the most specific level wins; a default expiry is given to new secrets', async () => {
    await expect(m.policies.save(ctx, { scope: 'PROJECT', expiryWarningDays: 5 } as any)).rejects.toMatchObject({ status: 400, details: { fields: { project: expect.any(String) } } });
    await m.policies.save(ctx, { scope: 'ORGANIZATION', expiryWarningDays: 30, defaultExpiresInDays: 90 } as any);
    await m.policies.save(ctx, { scope: 'PROJECT', project: 'billing', expiryWarningDays: 5 } as any);

    const billing = await create('billing-key', { expiresAt: new Date(Date.now() + 10 * 86_400_000).toISOString(), rotationEnabled: false });
    const other = await create('other-key', { project: 'search', expiresAt: new Date(Date.now() + 10 * 86_400_000).toISOString(), rotationEnabled: false });
    expect(billing.policy).toMatchObject({ expiryWarningDays: { value: 5, source: 'PROJECT' }, defaultExpiresInDays: { value: 90, source: 'ORGANIZATION' }, keepVersions: { value: null, source: 'NONE' } });
    await run();
    expect((await secret(billing.id)).status).toBe('ACTIVE'); // 10 days left, warned 5 days ahead
    expect((await secret(other.id)).status).toBe('EXPIRING'); // warned 30 days ahead

    const fresh = await create('fresh-key', { rotationEnabled: false });
    expect(Date.parse(fresh.expiresAt!) - Date.now()).toBeGreaterThan(89 * 86_400_000);
    expect((await m.policies.list(ctx.org.id)).items.map((p) => p.scope)).toEqual(['ORGANIZATION', 'PROJECT']);

    // A policy with nothing set is removed.
    expect(await m.policies.save(ctx, { scope: 'ORGANIZATION' } as any)).toEqual({ id: null, removed: true });
    await m.policies.save(ctx, { scope: 'PROJECT', project: 'billing' } as any);
    expect((await m.policies.list(ctx.org.id)).items).toEqual([]);
    expect(await events(fresh.id)).not.toContain('secret.expiring');
  });

  it('scheduled manual rotation: ROTATION_PENDING and notified; storing the new value completes it', async () => {
    const s = await m.svc.create(ctx, { name: 'reporting-db', typeKey: 'postgresql', project: 'billing', environment: 'production', metadata: { host: 'db.internal' }, payload: { username: 'reports', password: 'first password value' } } as any);
    expect(s.rotation).toMatchObject({ enabled: true, strategy: 'manual', generatable: false });
    await expect(m.svc.updateMetadata(ctx, { id: s.id, name: s.name, rotationStrategy: 'generated' } as any)).rejects.toMatchObject({ status: 400, details: { fields: { rotationStrategy: expect.stringMatching(/cannot be generated/) } } });

    await sql(`UPDATE secrets SET next_rotation_at = now() - interval '1 minute' WHERE id = $1`, [s.id]);
    const r = await run();
    expect(r.rotationsScheduled).toBeGreaterThanOrEqual(1);
    expect((await secret(s.id)).status).toBe('ROTATION_PENDING');
    let d = await m.svc.detail(ctx, s.id);
    expect(d.rotationJobs).toMatchObject([{ trigger: 'SCHEDULED', strategy: 'manual', status: 'WAITING_FOR_VALUE', fromVersion: 1 }]);
    expect(await events(s.id)).toContain('secret.rotation_scheduled');
    await run(); // no second job
    expect((await m.svc.detail(ctx, s.id)).rotationJobs).toHaveLength(1);
    // Still retrievable while the rotation waits.
    expect((await m.svc.retrieve(ctx, { id: s.id } as any)).payload.password).toBe('first password value');

    await m.svc.updateValue(ctx, { id: s.id, payload: { username: 'reports', password: 'second password value' } } as any);
    d = await m.svc.detail(ctx, s.id);
    expect(d).toMatchObject({ status: 'ACTIVE', activeVersion: 2, rotation: { lastRotatedAt: expect.any(String) } });
    expect(Date.parse(d.rotation.nextRotationAt!)).toBeGreaterThan(Date.now() + 80 * 86_400_000);
    expect(d.rotationJobs[0]).toMatchObject({ status: 'SUCCEEDED', fromVersion: 1, toVersion: 2 });
    expect(d.versions.find((v) => v.version === 1)!.supersededAt).toEqual(expect.any(String));
    expect((await events(s.id)).at(-1)).toBe('secret.rotated');
  });

  it('scheduled generated rotation: the webhook creates the value; no person involved', async () => {
    const s = await create('signing-key', { rotationStrategy: 'generated', rotationIntervalDays: 30 });
    expect(s.rotation).toMatchObject({ strategy: 'generated', generatable: true, graceHours: 24 });
    await sql(`UPDATE secrets SET next_rotation_at = now() - interval '1 minute' WHERE id = $1`, [s.id]);
    const r = await run();
    expect(r.rotationsSucceeded).toBeGreaterThanOrEqual(1);
    const d = await m.svc.detail(ctx, s.id);
    expect(d).toMatchObject({ status: 'ACTIVE', activeVersion: 2, rotationJobs: [{ trigger: 'SCHEDULED', strategy: 'generated', status: 'SUCCEEDED', attempts: 1, toVersion: 2 }] });
    const v1 = (await m.svc.retrieve(ctx, { id: s.id, version: 1 } as any)).payload.secret;
    const v2 = (await m.svc.retrieve(ctx, { id: s.id } as any)).payload.secret;
    expect(v2).not.toBe(v1);
    expect(v2).toMatch(/^[A-Za-z0-9_-]{43}$/);
    const rotated = (await m.client.db.find(m.entities.AuditEventEntity, { where: { targetId: s.id, eventType: 'secret.rotated' } })) as any[];
    expect(rotated[0]).toMatchObject({ actorType: 'SYSTEM', metadata: { trigger: 'SCHEDULED', strategy: 'generated', version: 2 } });
    expect(JSON.stringify(rotated)).not.toContain(String(v2));

    // Rotate now, from the API, without giving a value.
    expect((await m.svc.rotate(ctx, { id: s.id, reason: 'suspected leak' } as any)).activeVersion).toBe(3);
  });

  it('a failed generated rotation is retried while the webhook is unavailable, then fails; the old version stays active', async () => {
    const s = await create('retry-key', { rotationStrategy: 'generated', rotationIntervalDays: 30 });
    await sql(`UPDATE secrets SET next_rotation_at = now() - interval '1 minute' WHERE id = $1`, [s.id]);
    vault.down = true;
    expect((await run()).rotationsRetrying).toBeGreaterThanOrEqual(1);
    let d = await m.svc.detail(ctx, s.id);
    expect(d).toMatchObject({ status: 'ACTIVE', activeVersion: 1, rotationJobs: [{ status: 'PENDING', attempts: 1, errorCode: 'WEBHOOK_UNAVAILABLE', nextAttemptAt: expect.any(String) }] });
    expect(await events(s.id)).toContain('secret.provider_failure');

    await sql(`UPDATE rotation_jobs SET next_attempt_at = now() - interval '1 second' WHERE secret_id = $1`, [s.id]);
    await run();
    await sql(`UPDATE rotation_jobs SET next_attempt_at = now() - interval '1 second' WHERE secret_id = $1`, [s.id]);
    expect((await run()).rotationsFailed).toBeGreaterThanOrEqual(1);
    d = await m.svc.detail(ctx, s.id);
    expect(d).toMatchObject({ status: 'ACTIVE', activeVersion: 1, rotationJobs: [{ status: 'FAILED', attempts: 3 }] });
    expect(Date.parse(d.rotation.nextRotationAt!)).toBeGreaterThan(Date.now() + 23 * 3_600_000); // tried again tomorrow
    expect((await events(s.id)).filter((e) => e === 'secret.rotation_failed')).toHaveLength(1);

    // A manual "rotate now" while the webhook is down fails visibly, and is recorded.
    await expect(m.svc.rotate(ctx, { id: s.id } as any)).rejects.toMatchObject({ code: 'WEBHOOK_UNAVAILABLE' });
    expect((await m.svc.detail(ctx, s.id)).rotationJobs[0]).toMatchObject({ trigger: 'MANUAL', status: 'FAILED' });
    vault.down = false;
    expect((await m.svc.rotate(ctx, { id: s.id } as any)).activeVersion).toBe(2);
  });

  it('expiration-based rotation: a generated secret about to expire rotates and gets a new lifetime', async () => {
    await m.policies.save(ctx, { scope: 'WORKSPACE', project: 'billing', workspace: 'edge', defaultExpiresInDays: 60 } as any);
    const s = await create('edge-key', { workspace: 'edge', rotationStrategy: 'generated', rotationIntervalDays: 365 });
    await sql(`UPDATE secrets SET expires_at = now() + interval '2 days' WHERE id = $1`, [s.id]);
    await run(); // → EXPIRING, rotation queued (EXPIRY) and run
    const d = await m.svc.detail(ctx, s.id);
    expect(d.rotationJobs[0]).toMatchObject({ trigger: 'EXPIRY', status: 'SUCCEEDED' });
    expect(d.status).toBe('ACTIVE');
    expect(Date.parse(d.expiresAt!) - Date.now()).toBeGreaterThan(59 * 86_400_000);
    await m.policies.save(ctx, { scope: 'WORKSPACE', project: 'billing', workspace: 'edge' } as any);
  });

  it('retention: inactive versions beyond the policy are destroyed on the webhook, never inside the grace period', async () => {
    const s = await create('retained-key', { rotationEnabled: false, rotationGraceHours: 0 });
    for (let i = 2; i <= 5; i++) await m.svc.updateValue(ctx, { id: s.id, payload: { secret: `value number ${i} of the shared secret` } } as any);
    const graced = await create('graced-key', { rotationEnabled: false, rotationGraceHours: 48 });
    await m.svc.updateValue(ctx, { id: graced.id, payload: { secret: 'a second value of the shared secret!' } } as any);
    await m.svc.updateValue(ctx, { id: graced.id, payload: { secret: 'a third value of the shared secret!!' } } as any);

    await m.policies.save(ctx, { scope: 'PROJECT', project: 'billing', keepVersions: 1 } as any);
    const before = vault.values.size;
    const r = await run();
    expect(r.versionsDestroyed).toBeGreaterThanOrEqual(3);
    const d = await m.svc.detail(ctx, s.id);
    expect(d.versions.map((v) => `${v.version}:${v.state}`)).toEqual(['5:ACTIVE', '4:PREVIOUS', '3:DESTROYED', '2:DESTROYED', '1:DESTROYED']);
    expect(vault.values.size).toBeLessThan(before);
    const destroyed = (await m.client.db.find(m.entities.AuditEventEntity, { where: { targetId: s.id, eventType: 'secret.version_destroyed' } })) as any[];
    expect(destroyed).toHaveLength(3);
    expect(destroyed[0]).toMatchObject({ actorType: 'SYSTEM', metadata: { reason: 'Retention policy (keep the newest 1)' } });
    // Inside its 48-hour grace period nothing is destroyed.
    expect((await m.svc.detail(ctx, graced.id)).versions.every((v) => v.state !== 'DESTROYED')).toBe(true);
    await m.policies.save(ctx, { scope: 'PROJECT', project: 'billing' } as any);
  });

  it('notifications: matching channels receive signed webhooks and emails, never a value; failures are retried', async () => {
    await expect(m.channels.save(ctx, { name: 'bad', kind: 'WEBHOOK', events: ['secret.expiring'], url: 'https://user:pass@example.com/hook' } as any)).rejects.toMatchObject({ details: { fields: { url: expect.stringMatching(/credentials/) } } });
    const hook = await m.channels.save(ctx, { name: 'Ops webhook', kind: 'WEBHOOK', enabled: true, events: ['secret.rotation_succeeded', 'secret.expiring'], scope: { project: 'billing' }, url: receiverUrl } as any);
    expect(hook.signingSecret).toMatch(/^whsec_/);
    expect(hook.signingSecretHint).toMatch(/^whsec_…/);
    const mail = await m.channels.save(ctx, { name: 'Security team', kind: 'EMAIL', enabled: true, events: ['secret.rotation_succeeded', 'secret.revoked'], recipients: ['Security@Example.com'] } as any);
    expect(mail.recipients).toEqual(['security@example.com']);
    expect((await m.channels.list(ctx.org.id)).items.map((c) => c.signingSecretHint ?? null)).not.toContain(hook.signingSecret);

    const s = await create('notified-key', { rotationStrategy: 'generated', rotationIntervalDays: 30 });
    const outside = await create('outside-key', { project: 'search', rotationStrategy: 'generated', rotationIntervalDays: 30 });
    await m.svc.rotate(ctx, { id: s.id } as any);
    await m.svc.rotate(ctx, { id: outside.id } as any);
    received.length = 0;
    mails.length = 0;
    await m.notify.deliverDueNotifications();

    // The webhook channel is limited to the billing project; email hears about every secret.
    expect(received).toHaveLength(1);
    const { headers, body } = received[0]!;
    const payload = JSON.parse(body);
    expect(payload).toMatchObject({ event: 'secret.rotation_succeeded', secret: { id: s.id, name: 'notified-key', project: 'billing', activeVersion: 2 }, details: { trigger: 'MANUAL', version: 2, actor: 'Olivia Owner' }, consoleUrl: expect.stringContaining(`/secrets/${s.id}`) });
    expect(headers['token-vault-event']).toBe('secret.rotation_succeeded');
    const [, t, v1] = /^t=(\d+),v1=([0-9a-f]{64})$/.exec(String(headers['token-vault-signature']))!;
    expect(v1).toBe(createHmac('sha256', hook.signingSecret!).update(`${t}.${body}`).digest('hex'));
    const values = [...vault.values.values()].filter((v) => v.secret === s.id).map((v) => String(v.payload.secret));
    for (const v of values) expect(body).not.toContain(v);
    expect(mails.map((x) => x.subject).sort()).toEqual(['[Token Vault] Rotation successful: notified-key', '[Token Vault] Rotation successful: outside-key']);
    expect(mails[0]!.to).toEqual(['security@example.com']);

    // A failing endpoint: kept PENDING with the error, tried again later.
    receiverStatus = 500;
    await m.svc.rotate(ctx, { id: s.id } as any);
    await m.notify.deliverDueNotifications();
    const failing = (await m.channels.deliveries(ctx.org.id, { channelId: hook.id })).items[0]!;
    expect(failing).toMatchObject({ status: 'PENDING', attempts: 1, lastError: 'The endpoint answered HTTP 500', nextAttemptAt: expect.any(String) });
    expect(await m.notify.deliverDueNotifications()).toBe(0); // not due yet
    receiverStatus = 200;
    await sql(`UPDATE notification_deliveries SET next_attempt_at = now() WHERE id = $1`, [failing.id]);
    await m.notify.deliverDueNotifications();
    expect((await m.channels.deliveries(ctx.org.id, { channelId: hook.id })).items[0]).toMatchObject({ id: failing.id, status: 'DELIVERED', attempts: 2 });
    expect((await m.channels.list(ctx.org.id)).items.find((c) => c.id === hook.id)!.lastDelivery).toMatchObject({ status: 'DELIVERED' });

    // A test notification is sent at once; a channel turned off receives nothing else.
    expect(await m.channels.test(ctx, hook.id)).toMatchObject({ event: 'notification.test', status: 'DELIVERED' });
    await m.channels.save(ctx, { id: hook.id, name: 'Ops webhook', enabled: false, events: ['secret.rotation_succeeded'] } as any);
    received.length = 0;
    await m.svc.rotate(ctx, { id: s.id } as any);
    await m.notify.deliverDueNotifications();
    expect(received).toHaveLength(0);
    // Without SMTP, email fails visibly.
    const realSend = m.notify.mailer.send;
    m.notify.mailer.send = async () => {
      throw new Error('Email is not configured on the control plane (SMTP_URL)');
    };
    expect(await m.channels.test(ctx, mail.id)).toMatchObject({ status: 'FAILED', lastError: expect.stringMatching(/SMTP_URL/) });
    m.notify.mailer.send = realSend;
    await m.channels.remove(ctx, hook.id);
    await m.channels.remove(ctx, mail.id);
  });

  it('runs on one instance at a time (database lock)', async () => {
    const qr = m.client.db.connection.createQueryRunner();
    await qr.connect();
    await qr.query('SELECT pg_advisory_lock(4909012)');
    try {
      expect(await m.job.runSecretLifecycle()).toBeNull();
    } finally {
      await qr.query('SELECT pg_advisory_unlock(4909012)');
      await qr.release();
    }
    expect(await m.job.runSecretLifecycle()).not.toBeNull();
  });
});
