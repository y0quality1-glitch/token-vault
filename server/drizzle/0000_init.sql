CREATE TABLE "access_requests" (
	"id" text PRIMARY KEY NOT NULL,
	"organization_id" text NOT NULL,
	"agent_id" text,
	"agent_name" text NOT NULL,
	"integration_id" text,
	"integration_name" text NOT NULL,
	"grant_id" text,
	"grant_name" text,
	"operation" text NOT NULL,
	"resource" jsonb NOT NULL,
	"decision" text NOT NULL,
	"decision_code" text NOT NULL,
	"decision_reason" text NOT NULL,
	"matched_rule" jsonb,
	"execution_status" text NOT NULL,
	"upstream_status_code" integer,
	"webhook_status" text NOT NULL,
	"duration_ms" integer NOT NULL,
	"correlation_id" text NOT NULL,
	"source_ip" text NOT NULL,
	"source" text NOT NULL,
	"idempotency_key" text,
	"checks" jsonb NOT NULL,
	"created_at" timestamp(3) with time zone NOT NULL
);
--> statement-breakpoint
CREATE TABLE "agents" (
	"id" text PRIMARY KEY NOT NULL,
	"organization_id" text NOT NULL,
	"name" text NOT NULL,
	"description" text DEFAULT '' NOT NULL,
	"agent_type" text NOT NULL,
	"environment" text NOT NULL,
	"owner_user_id" text NOT NULL,
	"owner_team" text NOT NULL,
	"callback_url" text DEFAULT '' NOT NULL,
	"allowed_cidrs" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"credential_key_id" text NOT NULL,
	"credential_hash" text NOT NULL,
	"credential_issued_at" timestamp(3) with time zone NOT NULL,
	"status" text NOT NULL,
	"last_access_at" timestamp(3) with time zone,
	"created_at" timestamp(3) with time zone NOT NULL,
	CONSTRAINT "agents_credential_key_id_unique" UNIQUE("credential_key_id")
);
--> statement-breakpoint
CREATE TABLE "audit_events" (
	"id" text PRIMARY KEY NOT NULL,
	"organization_id" text NOT NULL,
	"actor_type" text NOT NULL,
	"actor_id" text NOT NULL,
	"actor_name" text NOT NULL,
	"event_type" text NOT NULL,
	"target_type" text NOT NULL,
	"target_id" text NOT NULL,
	"target_name" text NOT NULL,
	"outcome" text NOT NULL,
	"severity" text NOT NULL,
	"metadata" jsonb NOT NULL,
	"correlation_id" text NOT NULL,
	"created_at" timestamp(3) with time zone NOT NULL
);
--> statement-breakpoint
CREATE TABLE "grants" (
	"id" text PRIMARY KEY NOT NULL,
	"organization_id" text NOT NULL,
	"agent_id" text NOT NULL,
	"integration_id" text NOT NULL,
	"name" text NOT NULL,
	"environment" text NOT NULL,
	"scopes" jsonb NOT NULL,
	"resource_constraints" jsonb NOT NULL,
	"rate_limit_per_minute" integer NOT NULL,
	"allowed_cidrs" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"valid_from" timestamp(3) with time zone NOT NULL,
	"expires_at" timestamp(3) with time zone NOT NULL,
	"approval_required" boolean DEFAULT false NOT NULL,
	"status" text NOT NULL,
	"version" integer DEFAULT 1 NOT NULL,
	"previous_version_id" text,
	"created_by" text NOT NULL,
	"created_at" timestamp(3) with time zone NOT NULL,
	"approved_by" text,
	"approved_at" timestamp(3) with time zone,
	"revoked_at" timestamp(3) with time zone,
	"revoked_by" text,
	"revocation_reason" text,
	"last_used_at" timestamp(3) with time zone,
	"usage_count" integer DEFAULT 0 NOT NULL
);
--> statement-breakpoint
CREATE TABLE "integrations" (
	"id" text PRIMARY KEY NOT NULL,
	"organization_id" text NOT NULL,
	"webhook_id" text NOT NULL,
	"provider" text NOT NULL,
	"display_name" text NOT NULL,
	"environment" text NOT NULL,
	"account_label" text NOT NULL,
	"auth_type" text NOT NULL,
	"credential_reference" text NOT NULL,
	"credential_status" text NOT NULL,
	"masked_identifier" text DEFAULT '' NOT NULL,
	"credential_fingerprint" text DEFAULT '' NOT NULL,
	"allowed_resources" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"description" text DEFAULT '' NOT NULL,
	"created_by" text NOT NULL,
	"created_at" timestamp(3) with time zone NOT NULL,
	"updated_at" timestamp(3) with time zone NOT NULL,
	"last_validated_at" timestamp(3) with time zone,
	"rotated_at" timestamp(3) with time zone,
	"deleted_at" timestamp(3) with time zone
);
--> statement-breakpoint
CREATE TABLE "organization_members" (
	"id" text PRIMARY KEY NOT NULL,
	"organization_id" text NOT NULL,
	"user_id" text NOT NULL,
	"role" text NOT NULL,
	"created_at" timestamp(3) with time zone NOT NULL
);
--> statement-breakpoint
CREATE TABLE "organizations" (
	"id" text PRIMARY KEY NOT NULL,
	"name" text NOT NULL,
	"slug" text NOT NULL,
	"status" text NOT NULL,
	"environment" text NOT NULL,
	"created_at" timestamp(3) with time zone NOT NULL,
	"updated_at" timestamp(3) with time zone NOT NULL,
	CONSTRAINT "organizations_slug_unique" UNIQUE("slug")
);
--> statement-breakpoint
CREATE TABLE "policies" (
	"id" text PRIMARY KEY NOT NULL,
	"organization_id" text NOT NULL,
	"name" text NOT NULL,
	"description" text DEFAULT '' NOT NULL,
	"effect" text NOT NULL,
	"conditions" jsonb NOT NULL,
	"priority" integer NOT NULL,
	"enabled" boolean NOT NULL,
	"created_at" timestamp(3) with time zone NOT NULL,
	"updated_at" timestamp(3) with time zone NOT NULL
);
--> statement-breakpoint
CREATE TABLE "sessions" (
	"token_hash" text PRIMARY KEY NOT NULL,
	"user_id" text NOT NULL,
	"organization_id" text,
	"created_at" timestamp(3) with time zone NOT NULL,
	"expires_at" timestamp(3) with time zone NOT NULL
);
--> statement-breakpoint
CREATE TABLE "users" (
	"id" text PRIMARY KEY NOT NULL,
	"email" text NOT NULL,
	"password_hash" text NOT NULL,
	"full_name" text NOT NULL,
	"status" text NOT NULL,
	"created_at" timestamp(3) with time zone NOT NULL,
	CONSTRAINT "users_email_unique" UNIQUE("email")
);
--> statement-breakpoint
CREATE TABLE "webhooks" (
	"id" text PRIMARY KEY NOT NULL,
	"organization_id" text NOT NULL,
	"name" text NOT NULL,
	"endpoint_url" text NOT NULL,
	"environment" text NOT NULL,
	"description" text DEFAULT '' NOT NULL,
	"authentication_type" text NOT NULL,
	"signing_secret_ref" text NOT NULL,
	"status" text NOT NULL,
	"instance_id" text,
	"software_version" text,
	"last_heartbeat_at" timestamp(3) with time zone,
	"last_error" text,
	"simulate_outage" boolean DEFAULT false NOT NULL,
	"registration_challenge" text,
	"health_history" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"created_at" timestamp(3) with time zone NOT NULL,
	"verified_at" timestamp(3) with time zone
);
--> statement-breakpoint
ALTER TABLE "access_requests" ADD CONSTRAINT "access_requests_organization_id_organizations_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "agents" ADD CONSTRAINT "agents_organization_id_organizations_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "agents" ADD CONSTRAINT "agents_owner_user_id_users_id_fk" FOREIGN KEY ("owner_user_id") REFERENCES "public"."users"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "audit_events" ADD CONSTRAINT "audit_events_organization_id_organizations_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "grants" ADD CONSTRAINT "grants_organization_id_organizations_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "grants" ADD CONSTRAINT "grants_agent_id_agents_id_fk" FOREIGN KEY ("agent_id") REFERENCES "public"."agents"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "grants" ADD CONSTRAINT "grants_integration_id_integrations_id_fk" FOREIGN KEY ("integration_id") REFERENCES "public"."integrations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "integrations" ADD CONSTRAINT "integrations_organization_id_organizations_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "integrations" ADD CONSTRAINT "integrations_webhook_id_webhooks_id_fk" FOREIGN KEY ("webhook_id") REFERENCES "public"."webhooks"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "organization_members" ADD CONSTRAINT "organization_members_organization_id_organizations_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "organization_members" ADD CONSTRAINT "organization_members_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "policies" ADD CONSTRAINT "policies_organization_id_organizations_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "webhooks" ADD CONSTRAINT "webhooks_organization_id_organizations_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "access_requests_org_created_idx" ON "access_requests" USING btree ("organization_id","created_at");--> statement-breakpoint
CREATE INDEX "access_requests_grant_idx" ON "access_requests" USING btree ("grant_id");--> statement-breakpoint
CREATE INDEX "access_requests_agent_idx" ON "access_requests" USING btree ("agent_id");--> statement-breakpoint
CREATE INDEX "access_requests_correlation_idx" ON "access_requests" USING btree ("correlation_id");--> statement-breakpoint
CREATE INDEX "agents_org_idx" ON "agents" USING btree ("organization_id");--> statement-breakpoint
CREATE INDEX "audit_events_org_created_idx" ON "audit_events" USING btree ("organization_id","created_at");--> statement-breakpoint
CREATE INDEX "audit_events_correlation_idx" ON "audit_events" USING btree ("correlation_id");--> statement-breakpoint
CREATE INDEX "grants_org_idx" ON "grants" USING btree ("organization_id");--> statement-breakpoint
CREATE INDEX "grants_agent_integration_idx" ON "grants" USING btree ("agent_id","integration_id");--> statement-breakpoint
CREATE INDEX "integrations_org_idx" ON "integrations" USING btree ("organization_id");--> statement-breakpoint
CREATE UNIQUE INDEX "organization_members_org_user_uq" ON "organization_members" USING btree ("organization_id","user_id");--> statement-breakpoint
CREATE INDEX "policies_org_idx" ON "policies" USING btree ("organization_id");--> statement-breakpoint
CREATE INDEX "sessions_expires_at_idx" ON "sessions" USING btree ("expires_at");--> statement-breakpoint
CREATE INDEX "webhooks_org_idx" ON "webhooks" USING btree ("organization_id");