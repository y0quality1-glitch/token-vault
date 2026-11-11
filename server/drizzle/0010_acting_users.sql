CREATE TABLE "user_issuers" (
	"id" text PRIMARY KEY NOT NULL,
	"organization_id" text NOT NULL,
	"name" text NOT NULL,
	"issuer" text NOT NULL,
	"audience" text NOT NULL,
	"public_key" text NOT NULL,
	"key_fingerprint" text NOT NULL,
	"groups_claim" text DEFAULT 'groups' NOT NULL,
	"max_token_lifetime_seconds" integer DEFAULT 3600 NOT NULL,
	"enabled" boolean DEFAULT true NOT NULL,
	"created_at" timestamp(3) with time zone NOT NULL,
	"updated_at" timestamp(3) with time zone NOT NULL,
	"last_used_at" timestamp(3) with time zone
);
--> statement-breakpoint
ALTER TABLE "access_requests" ADD COLUMN "on_behalf_of" jsonb;--> statement-breakpoint
ALTER TABLE "grants" ADD COLUMN "on_behalf_of" text DEFAULT 'ALLOWED' NOT NULL;--> statement-breakpoint
ALTER TABLE "grants" ADD COLUMN "allowed_user_groups" jsonb DEFAULT '[]'::jsonb NOT NULL;--> statement-breakpoint
ALTER TABLE "operation_approvals" ADD COLUMN "on_behalf_of" jsonb;--> statement-breakpoint
ALTER TABLE "user_issuers" ADD CONSTRAINT "user_issuers_organization_id_organizations_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE UNIQUE INDEX "user_issuers_org_issuer_uq" ON "user_issuers" USING btree ("organization_id","issuer");