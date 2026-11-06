ALTER TABLE "agents" ADD COLUMN "previous_credential_key_id" text;--> statement-breakpoint
ALTER TABLE "agents" ADD COLUMN "previous_credential_hash" text;--> statement-breakpoint
ALTER TABLE "agents" ADD COLUMN "previous_credential_expires_at" timestamp(3) with time zone;--> statement-breakpoint
ALTER TABLE "agents" ADD COLUMN "previous_credential_last_used_at" timestamp(3) with time zone;--> statement-breakpoint
ALTER TABLE "agents" ADD CONSTRAINT "agents_previous_credential_key_id_unique" UNIQUE("previous_credential_key_id");