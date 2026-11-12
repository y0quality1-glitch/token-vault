CREATE TABLE "slack_settings" (
	"organization_id" text PRIMARY KEY NOT NULL,
	"team_id" text NOT NULL,
	"team_name" text NOT NULL,
	"bot_user_id" text NOT NULL,
	"channel_id" text NOT NULL,
	"bot_token_sealed" text NOT NULL,
	"bot_token_hint" text NOT NULL,
	"signing_secret_sealed" text NOT NULL,
	"enabled" boolean DEFAULT true NOT NULL,
	"updated_at" timestamp(3) with time zone NOT NULL,
	"updated_by" text NOT NULL
);
--> statement-breakpoint
ALTER TABLE "operation_approvals" ADD COLUMN "notifications" jsonb;--> statement-breakpoint
ALTER TABLE "slack_settings" ADD CONSTRAINT "slack_settings_organization_id_organizations_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;