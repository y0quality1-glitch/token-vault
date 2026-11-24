import type { MigrationInterface, QueryRunner } from 'typeorm';

/**
 * Secret Management, phase 4 (spec 4.9.8, 4.9.11, 4.9.12, 4.9.18): rotation strategy and grace
 * period on secrets, when each version was replaced, rotation history, expiry and retention
 * policies by organization, project and workspace, and notification channels with their
 * delivery queue. None of these tables holds a secret value.
 */
export class SecretLifecycle1795200000000 implements MigrationInterface {
  name = 'SecretLifecycle1795200000000';

  async up(qr: QueryRunner): Promise<void> {
    await qr.query(`
      ALTER TABLE secrets
        ADD COLUMN rotation_strategy text NOT NULL DEFAULT 'manual',
        ADD COLUMN rotation_grace_hours integer NOT NULL DEFAULT 24,
        ADD COLUMN last_rotated_at timestamp(3) with time zone,
        ADD CONSTRAINT secrets_rotation_strategy_check CHECK (rotation_strategy IN ('manual', 'generated')),
        ADD CONSTRAINT secrets_rotation_grace_check CHECK (rotation_grace_hours BETWEEN 0 AND 720)`);
    await qr.query(`ALTER TABLE secret_versions ADD COLUMN superseded_at timestamp(3) with time zone`);
    // Versions replaced before this migration: replaced when the next version was created.
    await qr.query(`
      UPDATE secret_versions v SET superseded_at = (
        SELECT min(n.created_at) FROM secret_versions n WHERE n.secret_id = v.secret_id AND n.version > v.version
      ) WHERE v.state <> 'ACTIVE'`);

    await qr.query(`
      CREATE TABLE rotation_jobs (
        id text PRIMARY KEY NOT NULL,
        organization_id text NOT NULL REFERENCES organizations(id),
        secret_id text NOT NULL REFERENCES secrets(id),
        trigger text NOT NULL,
        strategy text NOT NULL,
        status text NOT NULL,
        attempts integer NOT NULL DEFAULT 0,
        from_version integer,
        to_version integer,
        error_code text,
        error_message text,
        requested_by text,
        requested_by_name text,
        scheduled_for timestamp(3) with time zone NOT NULL,
        started_at timestamp(3) with time zone,
        finished_at timestamp(3) with time zone,
        next_attempt_at timestamp(3) with time zone,
        created_at timestamp(3) with time zone NOT NULL,
        CONSTRAINT rotation_jobs_trigger_check CHECK (trigger IN ('SCHEDULED', 'MANUAL', 'EXPIRY')),
        CONSTRAINT rotation_jobs_strategy_check CHECK (strategy IN ('manual', 'generated')),
        CONSTRAINT rotation_jobs_status_check CHECK (status IN ('PENDING', 'RUNNING', 'WAITING_FOR_VALUE', 'SUCCEEDED', 'FAILED', 'CANCELLED'))
      )`);
    // At most one rotation in progress per secret.
    await qr.query(`CREATE UNIQUE INDEX rotation_jobs_open ON rotation_jobs (secret_id) WHERE status IN ('PENDING', 'RUNNING', 'WAITING_FOR_VALUE')`);
    await qr.query(`CREATE INDEX rotation_jobs_org ON rotation_jobs (organization_id, created_at DESC)`);

    await qr.query(`
      CREATE TABLE secret_policies (
        id text PRIMARY KEY NOT NULL,
        organization_id text NOT NULL REFERENCES organizations(id),
        scope text NOT NULL,
        project text,
        workspace text,
        expiry_warning_days integer,
        default_expires_in_days integer,
        keep_versions integer,
        keep_days integer,
        updated_by text NOT NULL,
        updated_by_name text NOT NULL,
        updated_at timestamp(3) with time zone NOT NULL,
        CONSTRAINT secret_policies_scope_check CHECK (
          (scope = 'ORGANIZATION' AND project IS NULL AND workspace IS NULL) OR
          (scope = 'PROJECT' AND project IS NOT NULL AND workspace IS NULL) OR
          (scope = 'WORKSPACE' AND project IS NOT NULL AND workspace IS NOT NULL)),
        CONSTRAINT secret_policies_values_check CHECK (
          (expiry_warning_days IS NULL OR expiry_warning_days BETWEEN 1 AND 365) AND
          (default_expires_in_days IS NULL OR default_expires_in_days BETWEEN 1 AND 3650) AND
          (keep_versions IS NULL OR keep_versions BETWEEN 0 AND 1000) AND
          (keep_days IS NULL OR keep_days BETWEEN 0 AND 3650))
      )`);
    await qr.query(`CREATE UNIQUE INDEX secret_policies_scope ON secret_policies (organization_id, scope, coalesce(project, ''), coalesce(workspace, ''))`);

    await qr.query(`
      CREATE TABLE notification_channels (
        id text PRIMARY KEY NOT NULL,
        organization_id text NOT NULL REFERENCES organizations(id),
        name text NOT NULL,
        kind text NOT NULL,
        enabled boolean NOT NULL DEFAULT true,
        events jsonb NOT NULL DEFAULT '[]'::jsonb,
        scope jsonb NOT NULL DEFAULT '{}'::jsonb,
        recipients jsonb NOT NULL DEFAULT '[]'::jsonb,
        url text,
        signing_secret_sealed text,
        signing_secret_hint text,
        slack_channel_id text,
        created_by text NOT NULL,
        created_by_name text NOT NULL,
        created_at timestamp(3) with time zone NOT NULL,
        updated_at timestamp(3) with time zone NOT NULL,
        CONSTRAINT notification_channels_kind_check CHECK (kind IN ('EMAIL', 'WEBHOOK', 'SLACK')),
        CONSTRAINT notification_channels_webhook_check CHECK (kind <> 'WEBHOOK' OR (url IS NOT NULL AND signing_secret_sealed IS NOT NULL))
      )`);
    await qr.query(`CREATE INDEX notification_channels_org ON notification_channels (organization_id) WHERE enabled`);

    await qr.query(`
      CREATE TABLE notification_deliveries (
        id text PRIMARY KEY NOT NULL,
        organization_id text NOT NULL REFERENCES organizations(id),
        channel_id text NOT NULL REFERENCES notification_channels(id) ON DELETE CASCADE,
        event text NOT NULL,
        secret_id text,
        payload jsonb NOT NULL,
        status text NOT NULL,
        attempts integer NOT NULL DEFAULT 0,
        last_error text,
        next_attempt_at timestamp(3) with time zone,
        created_at timestamp(3) with time zone NOT NULL,
        delivered_at timestamp(3) with time zone,
        CONSTRAINT notification_deliveries_status_check CHECK (status IN ('PENDING', 'DELIVERED', 'FAILED'))
      )`);
    await qr.query(`CREATE INDEX notification_deliveries_due ON notification_deliveries (next_attempt_at) WHERE status = 'PENDING'`);
    await qr.query(`CREATE INDEX notification_deliveries_channel ON notification_deliveries (channel_id, created_at DESC)`);
  }

  async down(qr: QueryRunner): Promise<void> {
    await qr.query('DROP TABLE IF EXISTS notification_deliveries');
    await qr.query('DROP TABLE IF EXISTS notification_channels');
    await qr.query('DROP TABLE IF EXISTS secret_policies');
    await qr.query('DROP TABLE IF EXISTS rotation_jobs');
    await qr.query('ALTER TABLE secret_versions DROP COLUMN IF EXISTS superseded_at');
    await qr.query('ALTER TABLE secrets DROP CONSTRAINT IF EXISTS secrets_rotation_grace_check, DROP CONSTRAINT IF EXISTS secrets_rotation_strategy_check, DROP COLUMN IF EXISTS last_rotated_at, DROP COLUMN IF EXISTS rotation_grace_hours, DROP COLUMN IF EXISTS rotation_strategy');
  }
}
