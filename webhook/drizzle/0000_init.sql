CREATE TABLE "credentials" (
	"credential_ref" text PRIMARY KEY NOT NULL,
	"org_id" text NOT NULL,
	"provider" text NOT NULL,
	"iv" text NOT NULL,
	"ciphertext" text NOT NULL,
	"auth_tag" text NOT NULL,
	"encryption_key_ref" text NOT NULL,
	"masked_identifier" text NOT NULL,
	"fingerprint" text NOT NULL,
	"metadata" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"status" text NOT NULL,
	"created_at" timestamp(3) with time zone NOT NULL,
	"rotated_at" timestamp(3) with time zone
);
--> statement-breakpoint
CREATE TABLE "used_nonces" (
	"nonce" text PRIMARY KEY NOT NULL,
	"expires_at" timestamp(3) with time zone NOT NULL
);
--> statement-breakpoint
CREATE INDEX "credentials_org_idx" ON "credentials" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "used_nonces_expires_at_idx" ON "used_nonces" USING btree ("expires_at");