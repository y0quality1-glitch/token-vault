CREATE TABLE "applications" (
	"id" text PRIMARY KEY NOT NULL,
	"key" text NOT NULL,
	"name" text NOT NULL,
	"description" text DEFAULT '' NOT NULL,
	"created_by" text NOT NULL,
	"created_at" timestamp(3) with time zone NOT NULL,
	"updated_at" timestamp(3) with time zone NOT NULL,
	"archived_at" timestamp(3) with time zone,
	CONSTRAINT "applications_key_unique" UNIQUE("key")
);
--> statement-breakpoint
CREATE TABLE "cms_audit_events" (
	"id" bigserial PRIMARY KEY NOT NULL,
	"at" timestamp(3) with time zone NOT NULL,
	"actor_id" text NOT NULL,
	"actor_name" text NOT NULL,
	"action" text NOT NULL,
	"application_key" text,
	"version" integer,
	"details" jsonb NOT NULL
);
--> statement-breakpoint
CREATE TABLE "cms_sessions" (
	"token_hash" text PRIMARY KEY NOT NULL,
	"user_id" text NOT NULL,
	"expires_at" timestamp(3) with time zone NOT NULL,
	"created_at" timestamp(3) with time zone NOT NULL
);
--> statement-breakpoint
CREATE TABLE "cms_users" (
	"id" text PRIMARY KEY NOT NULL,
	"email" text NOT NULL,
	"full_name" text NOT NULL,
	"role" text NOT NULL,
	"password_hash" text NOT NULL,
	"created_at" timestamp(3) with time zone NOT NULL,
	CONSTRAINT "cms_users_email_unique" UNIQUE("email")
);
--> statement-breakpoint
CREATE TABLE "application_versions" (
	"id" text PRIMARY KEY NOT NULL,
	"application_id" text NOT NULL,
	"version" integer NOT NULL,
	"status" text NOT NULL,
	"definition" jsonb NOT NULL,
	"digest" text,
	"signature" text,
	"key_id" text,
	"created_by" text NOT NULL,
	"created_at" timestamp(3) with time zone NOT NULL,
	"updated_at" timestamp(3) with time zone NOT NULL,
	"authors" text[] DEFAULT '{}'::text[] NOT NULL,
	"submitted_by" text,
	"submitted_at" timestamp(3) with time zone,
	"reviewed_by" text,
	"reviewed_at" timestamp(3) with time zone,
	"review_note" text,
	"published_at" timestamp(3) with time zone,
	"host_change_acknowledged" boolean DEFAULT false NOT NULL
);
--> statement-breakpoint
ALTER TABLE "cms_sessions" ADD CONSTRAINT "cms_sessions_user_id_cms_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."cms_users"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "application_versions" ADD CONSTRAINT "application_versions_application_id_applications_id_fk" FOREIGN KEY ("application_id") REFERENCES "public"."applications"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "cms_audit_events_app" ON "cms_audit_events" USING btree ("application_key","at");--> statement-breakpoint
CREATE UNIQUE INDEX "application_versions_app_version" ON "application_versions" USING btree ("application_id","version");--> statement-breakpoint
CREATE UNIQUE INDEX "application_versions_one_open" ON "application_versions" USING btree ("application_id") WHERE status in ('DRAFT', 'IN_REVIEW');--> statement-breakpoint
CREATE UNIQUE INDEX "application_versions_one_published" ON "application_versions" USING btree ("application_id") WHERE status = 'PUBLISHED';