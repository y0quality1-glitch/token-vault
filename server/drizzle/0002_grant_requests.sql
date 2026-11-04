CREATE TABLE "grant_requests" (
	"id" text PRIMARY KEY NOT NULL,
	"organization_id" text NOT NULL,
	"agent_id" text NOT NULL,
	"integration_id" text NOT NULL,
	"operations" jsonb NOT NULL,
	"repositories" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"justification" text NOT NULL,
	"requested_duration_minutes" integer NOT NULL,
	"denied_request_id" text,
	"status" text NOT NULL,
	"created_at" timestamp(3) with time zone NOT NULL,
	"expires_at" timestamp(3) with time zone NOT NULL,
	"decided_by" text,
	"decided_at" timestamp(3) with time zone,
	"decision_note" text,
	"approved_duration_minutes" integer,
	"grant_id" text
);
--> statement-breakpoint
ALTER TABLE "grant_requests" ADD CONSTRAINT "grant_requests_organization_id_organizations_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "grant_requests" ADD CONSTRAINT "grant_requests_agent_id_agents_id_fk" FOREIGN KEY ("agent_id") REFERENCES "public"."agents"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "grant_requests" ADD CONSTRAINT "grant_requests_integration_id_integrations_id_fk" FOREIGN KEY ("integration_id") REFERENCES "public"."integrations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "grant_requests_org_status_idx" ON "grant_requests" USING btree ("organization_id","status");--> statement-breakpoint
CREATE INDEX "grant_requests_agent_idx" ON "grant_requests" USING btree ("agent_id");