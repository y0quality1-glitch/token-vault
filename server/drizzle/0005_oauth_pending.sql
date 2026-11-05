CREATE TABLE "oauth_pending" (
	"state_hash" text PRIMARY KEY NOT NULL,
	"organization_id" text NOT NULL,
	"user_id" text NOT NULL,
	"webhook_id" text NOT NULL,
	"credential_reference" text NOT NULL,
	"draft" jsonb NOT NULL,
	"created_at" timestamp(3) with time zone NOT NULL,
	"expires_at" timestamp(3) with time zone NOT NULL
);
