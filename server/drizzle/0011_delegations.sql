CREATE TABLE "delegations" (
	"id" text PRIMARY KEY NOT NULL,
	"organization_id" text NOT NULL,
	"agent_id" text NOT NULL,
	"grant_id" text NOT NULL,
	"parent_delegation_id" text,
	"depth" integer NOT NULL,
	"label" text NOT NULL,
	"operations" jsonb NOT NULL,
	"resources" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"max_requests" integer,
	"on_behalf_of" jsonb,
	"key_id" text NOT NULL,
	"credential_hash" text NOT NULL,
	"created_at" timestamp(3) with time zone NOT NULL,
	"expires_at" timestamp(3) with time zone NOT NULL,
	"revoked_at" timestamp(3) with time zone,
	"revoked_by" text,
	"revocation_reason" text,
	"last_used_at" timestamp(3) with time zone,
	CONSTRAINT "delegations_key_id_unique" UNIQUE("key_id")
);
--> statement-breakpoint
ALTER TABLE "access_requests" ADD COLUMN "delegation" jsonb;--> statement-breakpoint
ALTER TABLE "operation_approvals" ADD COLUMN "delegation" jsonb;--> statement-breakpoint
ALTER TABLE "delegations" ADD CONSTRAINT "delegations_organization_id_organizations_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "delegations" ADD CONSTRAINT "delegations_agent_id_agents_id_fk" FOREIGN KEY ("agent_id") REFERENCES "public"."agents"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "delegations_org_idx" ON "delegations" USING btree ("organization_id");--> statement-breakpoint
CREATE INDEX "delegations_agent_idx" ON "delegations" USING btree ("agent_id");--> statement-breakpoint
CREATE INDEX "delegations_grant_idx" ON "delegations" USING btree ("grant_id");--> statement-breakpoint
CREATE INDEX "delegations_parent_idx" ON "delegations" USING btree ("parent_delegation_id");