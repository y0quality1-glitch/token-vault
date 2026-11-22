import type { MigrationInterface, QueryRunner } from 'typeorm';

/**
 * Secret Management, phase 2 (spec 4.9.5, 4.9.8): secret metadata and version metadata. No
 * table here holds a value: values live on the customer webhook, referenced by value_ref.
 * A name is unique per organization, project, workspace and environment among secrets that
 * are not deleted (a deleted secret keeps its row as an audit tombstone).
 */
export class Secrets1795000000000 implements MigrationInterface {
  name = 'Secrets1795000000000';

  async up(qr: QueryRunner): Promise<void> {
    await qr.query(`
      CREATE TABLE secrets (
        id text PRIMARY KEY NOT NULL,
        organization_id text NOT NULL REFERENCES organizations(id),
        name text NOT NULL,
        description text NOT NULL DEFAULT '',
        type_key text NOT NULL,
        category text NOT NULL,
        project text NOT NULL DEFAULT 'default',
        workspace text NOT NULL DEFAULT 'default',
        environment text NOT NULL,
        tags jsonb NOT NULL DEFAULT '[]'::jsonb,
        metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
        status text NOT NULL,
        active_version integer,
        webhook_id text NOT NULL REFERENCES webhooks(id),
        integration_id text,
        expires_at timestamp(3) with time zone,
        rotation_enabled boolean NOT NULL DEFAULT false,
        rotation_interval_days integer,
        next_rotation_at timestamp(3) with time zone,
        last_retrieved_at timestamp(3) with time zone,
        created_by text NOT NULL,
        created_by_name text NOT NULL,
        created_at timestamp(3) with time zone NOT NULL,
        updated_by text NOT NULL,
        updated_by_name text NOT NULL,
        updated_at timestamp(3) with time zone NOT NULL,
        deleted_at timestamp(3) with time zone,
        CONSTRAINT secrets_status_check CHECK (status IN ('PENDING', 'ACTIVE', 'EXPIRING', 'EXPIRED', 'ROTATION_PENDING', 'ROTATING', 'REVOKED', 'ARCHIVED', 'DELETED')),
        CONSTRAINT secrets_environment_check CHECK (environment IN ('development', 'staging', 'production')),
        CONSTRAINT secrets_rotation_interval_check CHECK (rotation_interval_days IS NULL OR rotation_interval_days BETWEEN 1 AND 3650)
      )`);
    await qr.query(`CREATE UNIQUE INDEX secrets_unique_name ON secrets (organization_id, project, workspace, environment, lower(name)) WHERE status <> 'DELETED'`);
    await qr.query(`CREATE INDEX secrets_org_status ON secrets (organization_id, status)`);
    await qr.query(`CREATE INDEX secrets_org_expiry ON secrets (organization_id, expires_at) WHERE expires_at IS NOT NULL`);
    await qr.query(`
      CREATE TABLE secret_versions (
        id text PRIMARY KEY NOT NULL,
        secret_id text NOT NULL REFERENCES secrets(id),
        organization_id text NOT NULL,
        version integer NOT NULL,
        value_ref text,
        fingerprint text NOT NULL,
        summary jsonb NOT NULL DEFAULT '{}'::jsonb,
        type_version integer NOT NULL,
        state text NOT NULL,
        reason text NOT NULL DEFAULT '',
        copied_from integer,
        created_by text NOT NULL,
        created_by_name text NOT NULL,
        created_at timestamp(3) with time zone NOT NULL,
        destroyed_at timestamp(3) with time zone,
        CONSTRAINT secret_versions_state_check CHECK (state IN ('ACTIVE', 'PREVIOUS', 'DESTROYED')),
        CONSTRAINT secret_versions_destroyed_check CHECK ((state = 'DESTROYED') = (value_ref IS NULL))
      )`);
    await qr.query(`CREATE UNIQUE INDEX secret_versions_secret_version ON secret_versions (secret_id, version)`);
    await qr.query(`CREATE UNIQUE INDEX secret_versions_one_active ON secret_versions (secret_id) WHERE state = 'ACTIVE'`);
  }

  async down(qr: QueryRunner): Promise<void> {
    await qr.query('DROP TABLE IF EXISTS secret_versions');
    await qr.query('DROP TABLE IF EXISTS secrets');
  }
}
