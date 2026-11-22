CREATE TABLE "secret_values" (
	"value_ref" text PRIMARY KEY NOT NULL,
	"org_id" text NOT NULL,
	"secret_id" text NOT NULL,
	"version" integer NOT NULL,
	"type_key" text NOT NULL,
	"iv" text NOT NULL,
	"ciphertext" text NOT NULL,
	"auth_tag" text NOT NULL,
	"encryption_key_ref" text NOT NULL,
	"wrapped_key" text,
	"fingerprint" text NOT NULL,
	"created_at" timestamp(3) with time zone NOT NULL
);
--> statement-breakpoint
CREATE INDEX "secret_values_org_secret_idx" ON "secret_values" USING btree ("org_id","secret_id");--> statement-breakpoint
CREATE UNIQUE INDEX "secret_values_org_secret_version" ON "secret_values" USING btree ("org_id","secret_id","version");