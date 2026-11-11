ALTER TABLE "grants" ADD COLUMN "max_requests_per_day" integer;--> statement-breakpoint
ALTER TABLE "grants" ADD COLUMN "max_writes_per_hour" integer;--> statement-breakpoint
ALTER TABLE "organizations" ADD COLUMN "emergency_stopped_at" timestamp(3) with time zone;--> statement-breakpoint
ALTER TABLE "organizations" ADD COLUMN "emergency_stopped_by" text;--> statement-breakpoint
ALTER TABLE "organizations" ADD COLUMN "emergency_stop_reason" text;