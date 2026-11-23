import type { MigrationInterface, QueryRunner } from 'typeorm';

/**
 * Secret Management, phase 3 (spec 4.9.9, 4.9.15): which agents may retrieve which secrets, and
 * retrievals held for approval. A grant names one secret or a selector, never both.
 */
export class SecretAccess1795100000000 implements MigrationInterface {
  name = 'SecretAccess1795100000000';

  async up(qr: QueryRunner): Promise<void> {
    await qr.query(`
      CREATE TABLE secret_access_grants (
        id text PRIMARY KEY NOT NULL,
        organization_id text NOT NULL REFERENCES organizations(id),
        agent_id text NOT NULL REFERENCES agents(id),
        secret_id text REFERENCES secrets(id),
        selector jsonb,
        description text NOT NULL DEFAULT '',
        fields jsonb NOT NULL DEFAULT '[]'::jsonb,
        versions text NOT NULL DEFAULT 'ACTIVE',
        allowed_cidrs jsonb NOT NULL DEFAULT '[]'::jsonb,
        require_approval boolean NOT NULL DEFAULT false,
        valid_from timestamp(3) with time zone NOT NULL,
        expires_at timestamp(3) with time zone,
        status text NOT NULL,
        created_by text NOT NULL,
        created_by_name text NOT NULL,
        created_at timestamp(3) with time zone NOT NULL,
        revoked_at timestamp(3) with time zone,
        revoked_by text,
        revocation_reason text,
        last_used_at timestamp(3) with time zone,
        use_count integer NOT NULL DEFAULT 0,
        CONSTRAINT secret_access_grants_target_check CHECK ((secret_id IS NULL) <> (selector IS NULL)),
        CONSTRAINT secret_access_grants_versions_check CHECK (versions IN ('ACTIVE', 'ANY')),
        CONSTRAINT secret_access_grants_status_check CHECK (status IN ('ACTIVE', 'REVOKED'))
      )`);
    await qr.query(`CREATE INDEX secret_access_grants_agent ON secret_access_grants (organization_id, agent_id) WHERE status = 'ACTIVE'`);
    await qr.query(`CREATE INDEX secret_access_grants_secret ON secret_access_grants (secret_id)`);
    await qr.query(`
      CREATE TABLE secret_retrieval_approvals (
        id text PRIMARY KEY NOT NULL,
        organization_id text NOT NULL REFERENCES organizations(id),
        grant_id text NOT NULL REFERENCES secret_access_grants(id),
        agent_id text NOT NULL REFERENCES agents(id),
        secret_id text NOT NULL REFERENCES secrets(id),
        version integer,
        fields jsonb NOT NULL DEFAULT '[]'::jsonb,
        reason text NOT NULL DEFAULT '',
        status text NOT NULL,
        requested_at timestamp(3) with time zone NOT NULL,
        expires_at timestamp(3) with time zone NOT NULL,
        decided_by text,
        decided_by_name text,
        decided_at timestamp(3) with time zone,
        note text NOT NULL DEFAULT '',
        used_at timestamp(3) with time zone,
        CONSTRAINT secret_retrieval_approvals_status_check CHECK (status IN ('PENDING', 'APPROVED', 'REJECTED', 'USED', 'EXPIRED'))
      )`);
    await qr.query(`CREATE INDEX secret_retrieval_approvals_org_status ON secret_retrieval_approvals (organization_id, status)`);
  }

  async down(qr: QueryRunner): Promise<void> {
    await qr.query('DROP TABLE IF EXISTS secret_retrieval_approvals');
    await qr.query('DROP TABLE IF EXISTS secret_access_grants');
  }
}
