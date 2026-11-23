import type { MigrationInterface, QueryRunner } from 'typeorm';

/**
 * Catalog entries get a kind: provider definitions (every existing row) or secret types.
 * Both are reviewed, signed and published the same way; each kind is signed under its own
 * context and served at its own catalog endpoint.
 */
export class CatalogKinds1731000000000 implements MigrationInterface {
  name = 'CatalogKinds1731000000000';

  async up(qr: QueryRunner): Promise<void> {
    await qr.query(`ALTER TABLE applications ADD COLUMN IF NOT EXISTS kind text NOT NULL DEFAULT 'provider'`);
    await qr.query(`ALTER TABLE applications DROP CONSTRAINT IF EXISTS applications_kind_check`);
    await qr.query(`ALTER TABLE applications ADD CONSTRAINT applications_kind_check CHECK (kind IN ('provider', 'secret_type'))`);
    await qr.query(`CREATE INDEX IF NOT EXISTS applications_kind_key ON applications (kind, key)`);
  }

  async down(qr: QueryRunner): Promise<void> {
    await qr.query(`DROP INDEX IF EXISTS applications_kind_key`);
    await qr.query(`ALTER TABLE applications DROP CONSTRAINT IF EXISTS applications_kind_check`);
    await qr.query(`ALTER TABLE applications DROP COLUMN IF EXISTS kind`);
  }
}
