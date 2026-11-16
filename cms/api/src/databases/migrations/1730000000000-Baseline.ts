import type { MigrationInterface, QueryRunner } from 'typeorm';

/**
 * The CMS schema as it stood before TypeORM: tables, partial unique indexes ("one open and
 * one published version per application") and the triggers that keep the audit log and
 * signatures append-only and published versions immutable.
 *
 * Databases created earlier (by Drizzle migrations 0000-0002) already have all of it: the
 * migration then only records itself, so no data is touched.
 */
const STATEMENTS: string[] = [
  "CREATE TABLE \"applications\" (\n\t\"id\" text PRIMARY KEY NOT NULL,\n\t\"key\" text NOT NULL,\n\t\"name\" text NOT NULL,\n\t\"description\" text DEFAULT '' NOT NULL,\n\t\"created_by\" text NOT NULL,\n\t\"created_at\" timestamp(3) with time zone NOT NULL,\n\t\"updated_at\" timestamp(3) with time zone NOT NULL,\n\t\"archived_at\" timestamp(3) with time zone,\n\tCONSTRAINT \"applications_key_unique\" UNIQUE(\"key\")\n);",
  "CREATE TABLE \"cms_audit_events\" (\n\t\"id\" bigserial PRIMARY KEY NOT NULL,\n\t\"at\" timestamp(3) with time zone NOT NULL,\n\t\"actor_id\" text NOT NULL,\n\t\"actor_name\" text NOT NULL,\n\t\"action\" text NOT NULL,\n\t\"application_key\" text,\n\t\"version\" integer,\n\t\"details\" jsonb NOT NULL\n);",
  "CREATE TABLE \"cms_sessions\" (\n\t\"token_hash\" text PRIMARY KEY NOT NULL,\n\t\"user_id\" text NOT NULL,\n\t\"expires_at\" timestamp(3) with time zone NOT NULL,\n\t\"created_at\" timestamp(3) with time zone NOT NULL\n);",
  "CREATE TABLE \"cms_users\" (\n\t\"id\" text PRIMARY KEY NOT NULL,\n\t\"email\" text NOT NULL,\n\t\"full_name\" text NOT NULL,\n\t\"role\" text NOT NULL,\n\t\"password_hash\" text NOT NULL,\n\t\"created_at\" timestamp(3) with time zone NOT NULL,\n\tCONSTRAINT \"cms_users_email_unique\" UNIQUE(\"email\")\n);",
  "CREATE TABLE \"application_versions\" (\n\t\"id\" text PRIMARY KEY NOT NULL,\n\t\"application_id\" text NOT NULL,\n\t\"version\" integer NOT NULL,\n\t\"status\" text NOT NULL,\n\t\"definition\" jsonb NOT NULL,\n\t\"digest\" text,\n\t\"signature\" text,\n\t\"key_id\" text,\n\t\"created_by\" text NOT NULL,\n\t\"created_at\" timestamp(3) with time zone NOT NULL,\n\t\"updated_at\" timestamp(3) with time zone NOT NULL,\n\t\"authors\" text[] DEFAULT '{}'::text[] NOT NULL,\n\t\"submitted_by\" text,\n\t\"submitted_at\" timestamp(3) with time zone,\n\t\"reviewed_by\" text,\n\t\"reviewed_at\" timestamp(3) with time zone,\n\t\"review_note\" text,\n\t\"published_at\" timestamp(3) with time zone,\n\t\"host_change_acknowledged\" boolean DEFAULT false NOT NULL\n);",
  "ALTER TABLE \"cms_sessions\" ADD CONSTRAINT \"cms_sessions_user_id_cms_users_id_fk\" FOREIGN KEY (\"user_id\") REFERENCES \"public\".\"cms_users\"(\"id\") ON DELETE cascade ON UPDATE no action;",
  "ALTER TABLE \"application_versions\" ADD CONSTRAINT \"application_versions_application_id_applications_id_fk\" FOREIGN KEY (\"application_id\") REFERENCES \"public\".\"applications\"(\"id\") ON DELETE no action ON UPDATE no action;",
  "CREATE INDEX \"cms_audit_events_app\" ON \"cms_audit_events\" USING btree (\"application_key\",\"at\");",
  "CREATE UNIQUE INDEX \"application_versions_app_version\" ON \"application_versions\" USING btree (\"application_id\",\"version\");",
  "CREATE UNIQUE INDEX \"application_versions_one_open\" ON \"application_versions\" USING btree (\"application_id\") WHERE status in ('DRAFT', 'IN_REVIEW');",
  "CREATE UNIQUE INDEX \"application_versions_one_published\" ON \"application_versions\" USING btree (\"application_id\") WHERE status = 'PUBLISHED';",
  "-- The CMS audit log is append-only: UPDATE and DELETE are rejected at the database level.\n-- (TRUNCATE, used only by the test/e2e reset, does not fire row-level triggers.)\nCREATE OR REPLACE FUNCTION cms_reject_audit_mutation() RETURNS trigger AS $$\nBEGIN\n  RAISE EXCEPTION 'table % is append-only (% rejected)', TG_TABLE_NAME, TG_OP\n    USING ERRCODE = 'insufficient_privilege';\nEND;\n$$ LANGUAGE plpgsql;",
  "CREATE TRIGGER cms_audit_events_append_only\n  BEFORE UPDATE OR DELETE ON cms_audit_events\n  FOR EACH ROW EXECUTE FUNCTION cms_reject_audit_mutation();",
  "-- A published version is frozen: its definition, digest and signature can never change,\n-- and the only allowed transition is PUBLISHED -> SUPERSEDED. Published versions are never deleted.\nCREATE OR REPLACE FUNCTION cms_protect_published_version() RETURNS trigger AS $$\nBEGIN\n  IF TG_OP = 'DELETE' THEN\n    IF OLD.status IN ('PUBLISHED', 'SUPERSEDED') THEN\n      RAISE EXCEPTION 'published versions cannot be deleted' USING ERRCODE = 'insufficient_privilege';\n    END IF;\n    RETURN OLD;\n  END IF;\n  IF OLD.status IN ('PUBLISHED', 'SUPERSEDED') THEN\n    IF NEW.definition IS DISTINCT FROM OLD.definition OR NEW.digest IS DISTINCT FROM OLD.digest\n       OR NEW.signature IS DISTINCT FROM OLD.signature OR NEW.version IS DISTINCT FROM OLD.version\n       OR NOT (NEW.status = OLD.status OR (OLD.status = 'PUBLISHED' AND NEW.status = 'SUPERSEDED')) THEN\n      RAISE EXCEPTION 'published version % is immutable', OLD.version USING ERRCODE = 'insufficient_privilege';\n    END IF;\n  END IF;\n  RETURN NEW;\nEND;\n$$ LANGUAGE plpgsql;",
  "CREATE TRIGGER application_versions_protect_published\n  BEFORE UPDATE OR DELETE ON application_versions\n  FOR EACH ROW EXECUTE FUNCTION cms_protect_published_version();",
  "CREATE TABLE \"cms_signing_keys\" (\n\t\"key_id\" text PRIMARY KEY NOT NULL,\n\t\"algorithm\" text NOT NULL,\n\t\"public_key_pem\" text,\n\t\"first_used_at\" timestamp(3) with time zone NOT NULL\n);",
  "CREATE TABLE \"cms_version_signatures\" (\n\t\"version_id\" text NOT NULL,\n\t\"key_id\" text NOT NULL,\n\t\"signature\" text NOT NULL,\n\t\"signed_at\" timestamp(3) with time zone NOT NULL\n);",
  "ALTER TABLE \"cms_version_signatures\" ADD CONSTRAINT \"cms_version_signatures_version_id_application_versions_id_fk\" FOREIGN KEY (\"version_id\") REFERENCES \"public\".\"application_versions\"(\"id\") ON DELETE no action ON UPDATE no action;",
  "ALTER TABLE \"cms_version_signatures\" ADD CONSTRAINT \"cms_version_signatures_key_id_cms_signing_keys_key_id_fk\" FOREIGN KEY (\"key_id\") REFERENCES \"public\".\"cms_signing_keys\"(\"key_id\") ON DELETE no action ON UPDATE no action;",
  "CREATE UNIQUE INDEX \"cms_version_signatures_version_key\" ON \"cms_version_signatures\" USING btree (\"version_id\",\"key_id\");",
  "-- Signatures are append-only: a signature is never changed or removed (rotation adds new ones).\nCREATE TRIGGER cms_version_signatures_append_only\n  BEFORE UPDATE OR DELETE ON cms_version_signatures\n  FOR EACH ROW EXECUTE FUNCTION cms_reject_audit_mutation();",
  "-- Carry over the signatures made before this migration (their public keys are filled in\n-- when the CMS next starts with that key).\nINSERT INTO cms_signing_keys (key_id, algorithm, public_key_pem, first_used_at)\n  SELECT key_id, 'Ed25519', NULL, min(published_at) FROM application_versions\n  WHERE key_id IS NOT NULL GROUP BY key_id\n  ON CONFLICT DO NOTHING;",
  "INSERT INTO cms_version_signatures (version_id, key_id, signature, signed_at)\n  SELECT id, key_id, signature, published_at FROM application_versions\n  WHERE key_id IS NOT NULL AND signature IS NOT NULL\n  ON CONFLICT DO NOTHING;"
];

export class Baseline1730000000000 implements MigrationInterface {
  name = 'Baseline1730000000000';

  async up(qr: QueryRunner): Promise<void> {
    const [{ existing }] = await qr.query(`SELECT to_regclass('public.cms_version_signatures') IS NOT NULL AS existing`);
    if (existing) return;
    for (const sql of STATEMENTS) await qr.query(sql);
  }

  async down(): Promise<void> {
    throw new Error('The baseline cannot be reverted: drop the database instead.');
  }
}
