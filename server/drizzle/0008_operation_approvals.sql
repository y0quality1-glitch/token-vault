CREATE TABLE "operation_approvals" (
	"id" text PRIMARY KEY NOT NULL,
	"organization_id" text NOT NULL,
	"agent_id" text NOT NULL,
	"integration_id" text NOT NULL,
	"policy_id" text NOT NULL,
	"policy_name" text NOT NULL,
	"operation" text NOT NULL,
	"resource" jsonb NOT NULL,
	"input" jsonb NOT NULL,
	"request_digest" text NOT NULL,
	"status" text NOT NULL,
	"requested_by_request_id" text NOT NULL,
	"created_at" timestamp(3) with time zone NOT NULL,
	"expires_at" timestamp(3) with time zone NOT NULL,
	"decided_by" text,
	"decided_at" timestamp(3) with time zone,
	"decision_note" text,
	"executed_at" timestamp(3) with time zone,
	"executed_request_id" text
);
--> statement-breakpoint
ALTER TABLE "operation_approvals" ADD CONSTRAINT "operation_approvals_organization_id_organizations_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "operation_approvals" ADD CONSTRAINT "operation_approvals_agent_id_agents_id_fk" FOREIGN KEY ("agent_id") REFERENCES "public"."agents"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "operation_approvals" ADD CONSTRAINT "operation_approvals_integration_id_integrations_id_fk" FOREIGN KEY ("integration_id") REFERENCES "public"."integrations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "operation_approvals_org_status_idx" ON "operation_approvals" USING btree ("organization_id","status");--> statement-breakpoint
CREATE INDEX "operation_approvals_agent_digest_idx" ON "operation_approvals" USING btree ("agent_id","request_digest");