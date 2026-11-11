ALTER TABLE "access_requests" ADD COLUMN "filtering" jsonb;--> statement-breakpoint
ALTER TABLE "policies" ADD COLUMN "response_filter" jsonb;