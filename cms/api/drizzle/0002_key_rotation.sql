CREATE TABLE "cms_signing_keys" (
	"key_id" text PRIMARY KEY NOT NULL,
	"algorithm" text NOT NULL,
	"public_key_pem" text,
	"first_used_at" timestamp(3) with time zone NOT NULL
);
--> statement-breakpoint
CREATE TABLE "cms_version_signatures" (
	"version_id" text NOT NULL,
	"key_id" text NOT NULL,
	"signature" text NOT NULL,
	"signed_at" timestamp(3) with time zone NOT NULL
);
--> statement-breakpoint
ALTER TABLE "cms_version_signatures" ADD CONSTRAINT "cms_version_signatures_version_id_application_versions_id_fk" FOREIGN KEY ("version_id") REFERENCES "public"."application_versions"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "cms_version_signatures" ADD CONSTRAINT "cms_version_signatures_key_id_cms_signing_keys_key_id_fk" FOREIGN KEY ("key_id") REFERENCES "public"."cms_signing_keys"("key_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
CREATE UNIQUE INDEX "cms_version_signatures_version_key" ON "cms_version_signatures" USING btree ("version_id","key_id");--> statement-breakpoint
-- Signatures are append-only: a signature is never changed or removed (rotation adds new ones).
CREATE TRIGGER cms_version_signatures_append_only
  BEFORE UPDATE OR DELETE ON cms_version_signatures
  FOR EACH ROW EXECUTE FUNCTION cms_reject_audit_mutation();
--> statement-breakpoint
-- Carry over the signatures made before this migration (their public keys are filled in
-- when the CMS next starts with that key).
INSERT INTO cms_signing_keys (key_id, algorithm, public_key_pem, first_used_at)
  SELECT key_id, 'Ed25519', NULL, min(published_at) FROM application_versions
  WHERE key_id IS NOT NULL GROUP BY key_id
  ON CONFLICT DO NOTHING;
--> statement-breakpoint
INSERT INTO cms_version_signatures (version_id, key_id, signature, signed_at)
  SELECT id, key_id, signature, published_at FROM application_versions
  WHERE key_id IS NOT NULL AND signature IS NOT NULL
  ON CONFLICT DO NOTHING;
