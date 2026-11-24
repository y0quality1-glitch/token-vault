import type { MigrationInterface, QueryRunner } from 'typeorm';

/**
 * Secret Management, phase 6 (spec 4.9.3 E and F): keys used through the agent API without being
 * handed out, and certificates.
 *  - secrets.key_operations: what a key may be used for (null: everything its type supports);
 *  - secret_versions.key_enabled: a key version can be deactivated (null for other types);
 *  - secret_versions.certificate: what the version's certificate says (read by the webhook);
 *  - grants: allow_retrieve (false: use the key, never read it) and key_operations;
 *  - approvals: the operation asked for and a SHA-256 of its input;
 *  - certificate_requests: renewals (a new key waits on the webhook until its certificate comes).
 */
export class SecretKeysCertificates1795400000000 implements MigrationInterface {
  name = 'SecretKeysCertificates1795400000000';

  async up(qr: QueryRunner): Promise<void> {
    await qr.query(`ALTER TABLE secrets ADD COLUMN key_operations jsonb`);
    await qr.query(`
      ALTER TABLE secret_versions
        ADD COLUMN key_enabled boolean,
        ADD COLUMN certificate jsonb`);
    await qr.query(`
      ALTER TABLE secret_access_grants
        ADD COLUMN allow_retrieve boolean NOT NULL DEFAULT true,
        ADD COLUMN key_operations jsonb NOT NULL DEFAULT '[]'::jsonb`);
    await qr.query(`
      ALTER TABLE secret_retrieval_approvals
        ADD COLUMN operation text NOT NULL DEFAULT 'retrieve',
        ADD COLUMN input_digest text,
        ADD CONSTRAINT secret_retrieval_approvals_operation_check CHECK (operation IN ('retrieve', 'lease', 'sign', 'verify', 'encrypt', 'decrypt', 'mac'))`);
    await qr.query(`
      CREATE TABLE certificate_requests (
        id text PRIMARY KEY NOT NULL,
        organization_id text NOT NULL REFERENCES organizations(id),
        secret_id text NOT NULL REFERENCES secrets(id),
        status text NOT NULL CHECK (status IN ('PENDING', 'COMPLETED', 'CANCELLED', 'EXPIRED')),
        key_algorithm text NOT NULL,
        subject text NOT NULL,
        subject_alt_names jsonb NOT NULL DEFAULT '[]'::jsonb,
        csr text NOT NULL,
        request_ref text,
        created_by text NOT NULL,
        created_by_name text NOT NULL,
        created_at timestamp(3) with time zone NOT NULL,
        expires_at timestamp(3) with time zone NOT NULL,
        completed_at timestamp(3) with time zone,
        completed_version integer,
        issuer_secret_id text,
        issuer_name text,
        cancelled_reason text
      )`);
    await qr.query(`CREATE INDEX certificate_requests_secret_idx ON certificate_requests (secret_id, created_at DESC)`);
    // One renewal at a time per certificate.
    await qr.query(`CREATE UNIQUE INDEX certificate_requests_one_pending ON certificate_requests (secret_id) WHERE status = 'PENDING'`);
    await qr.query(`CREATE INDEX certificate_requests_expiry_idx ON certificate_requests (expires_at) WHERE status = 'PENDING'`);
  }

  async down(qr: QueryRunner): Promise<void> {
    await qr.query(`DROP TABLE certificate_requests`);
    await qr.query(`ALTER TABLE secret_retrieval_approvals DROP CONSTRAINT secret_retrieval_approvals_operation_check, DROP COLUMN input_digest, DROP COLUMN operation`);
    await qr.query(`ALTER TABLE secret_access_grants DROP COLUMN key_operations, DROP COLUMN allow_retrieve`);
    await qr.query(`ALTER TABLE secret_versions DROP COLUMN certificate, DROP COLUMN key_enabled`);
    await qr.query(`ALTER TABLE secrets DROP COLUMN key_operations`);
  }
}
