import type { MigrationInterface, QueryRunner } from 'typeorm';

/**
 * Secret Management, phase 5 (spec 4.9.3 J and K, 4.9.14, 4.9.16): provider health on secrets,
 * the "provider" rotation strategy, leases of dynamic secrets, organization-defined secret types,
 * and export requests. No table holds a secret value; an export's file is encrypted with the
 * requester's passphrase and kept only until it is downloaded or expires.
 */
export class SecretProviders1795300000000 implements MigrationInterface {
  name = 'SecretProviders1795300000000';

  async up(qr: QueryRunner): Promise<void> {
    await qr.query(`
      ALTER TABLE secrets
        ADD COLUMN provider_status text,
        ADD COLUMN provider_checked_at timestamp(3) with time zone,
        ADD COLUMN provider_error text,
        DROP CONSTRAINT secrets_rotation_strategy_check,
        ADD CONSTRAINT secrets_rotation_strategy_check CHECK (rotation_strategy IN ('manual', 'generated', 'provider')),
        ADD CONSTRAINT secrets_provider_status_check CHECK (provider_status IS NULL OR provider_status IN ('OK', 'FAILING'))`);
    await qr.query(`
      ALTER TABLE rotation_jobs
        DROP CONSTRAINT rotation_jobs_strategy_check,
        ADD CONSTRAINT rotation_jobs_strategy_check CHECK (strategy IN ('manual', 'generated', 'provider'))`);

    await qr.query(`
      CREATE TABLE secret_leases (
        id text PRIMARY KEY NOT NULL,
        organization_id text NOT NULL REFERENCES organizations(id),
        secret_id text NOT NULL REFERENCES secrets(id),
        holder_type text NOT NULL,
        holder_id text NOT NULL,
        holder_name text NOT NULL,
        grant_id text,
        username text NOT NULL,
        status text NOT NULL,
        renewable boolean NOT NULL DEFAULT false,
        reason text NOT NULL DEFAULT '',
        created_at timestamp(3) with time zone NOT NULL,
        expires_at timestamp(3) with time zone NOT NULL,
        max_expires_at timestamp(3) with time zone NOT NULL,
        renewed_at timestamp(3) with time zone,
        renew_count integer NOT NULL DEFAULT 0,
        revoked_at timestamp(3) with time zone,
        revoked_by text,
        revocation_reason text,
        last_error text,
        CONSTRAINT secret_leases_holder_check CHECK (holder_type IN ('AGENT', 'USER')),
        CONSTRAINT secret_leases_status_check CHECK (status IN ('ACTIVE', 'EXPIRED', 'REVOKED', 'REVOKE_FAILED'))
      )`);
    await qr.query(`CREATE INDEX secret_leases_secret ON secret_leases (secret_id, created_at DESC)`);
    await qr.query(`CREATE INDEX secret_leases_due ON secret_leases (expires_at) WHERE status IN ('ACTIVE', 'REVOKE_FAILED')`);
    await qr.query(`CREATE INDEX secret_leases_holder ON secret_leases (organization_id, holder_id) WHERE status = 'ACTIVE'`);

    await qr.query(`
      CREATE TABLE custom_secret_types (
        id text PRIMARY KEY NOT NULL,
        organization_id text NOT NULL REFERENCES organizations(id),
        key text NOT NULL,
        version integer NOT NULL,
        definition jsonb NOT NULL,
        digest text NOT NULL,
        created_by text NOT NULL,
        created_by_name text NOT NULL,
        created_at timestamp(3) with time zone NOT NULL,
        updated_by text NOT NULL,
        updated_by_name text NOT NULL,
        updated_at timestamp(3) with time zone NOT NULL,
        archived_at timestamp(3) with time zone,
        CONSTRAINT custom_secret_types_key_check CHECK (key LIKE 'custom-%')
      )`);
    await qr.query(`CREATE UNIQUE INDEX custom_secret_types_key ON custom_secret_types (organization_id, key)`);

    await qr.query(`
      CREATE TABLE secret_export_requests (
        id text PRIMARY KEY NOT NULL,
        organization_id text NOT NULL REFERENCES organizations(id),
        requested_by text NOT NULL,
        requested_by_name text NOT NULL,
        secret_ids jsonb NOT NULL,
        reason text NOT NULL,
        status text NOT NULL,
        created_at timestamp(3) with time zone NOT NULL,
        decided_by text,
        decided_by_name text,
        decided_at timestamp(3) with time zone,
        note text NOT NULL DEFAULT '',
        expires_at timestamp(3) with time zone,
        file jsonb,
        download_token_hash text,
        downloaded_at timestamp(3) with time zone,
        CONSTRAINT secret_export_requests_status_check CHECK (status IN ('PENDING', 'APPROVED', 'REJECTED', 'READY', 'DOWNLOADED', 'EXPIRED'))
      )`);
    await qr.query(`CREATE INDEX secret_export_requests_org ON secret_export_requests (organization_id, created_at DESC)`);
  }

  async down(qr: QueryRunner): Promise<void> {
    await qr.query('DROP TABLE IF EXISTS secret_export_requests');
    await qr.query('DROP TABLE IF EXISTS custom_secret_types');
    await qr.query('DROP TABLE IF EXISTS secret_leases');
    await qr.query(`ALTER TABLE rotation_jobs DROP CONSTRAINT rotation_jobs_strategy_check, ADD CONSTRAINT rotation_jobs_strategy_check CHECK (strategy IN ('manual', 'generated'))`);
    await qr.query(`ALTER TABLE secrets DROP CONSTRAINT secrets_provider_status_check, DROP CONSTRAINT secrets_rotation_strategy_check, ADD CONSTRAINT secrets_rotation_strategy_check CHECK (rotation_strategy IN ('manual', 'generated')), DROP COLUMN provider_error, DROP COLUMN provider_checked_at, DROP COLUMN provider_status`);
  }
}
