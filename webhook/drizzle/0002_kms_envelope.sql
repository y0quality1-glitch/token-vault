CREATE TABLE "vault_settings" (
	"name" text PRIMARY KEY NOT NULL,
	"wrapped_value" text NOT NULL,
	"key_ref" text NOT NULL,
	"created_at" timestamp(3) with time zone NOT NULL
);
--> statement-breakpoint
ALTER TABLE "credentials" ADD COLUMN "wrapped_key" text;