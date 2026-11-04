ALTER TABLE "access_requests" ADD COLUMN "seq" bigint;--> statement-breakpoint
ALTER TABLE "access_requests" ADD COLUMN "prev_hash" text;--> statement-breakpoint
ALTER TABLE "access_requests" ADD COLUMN "hash" text;--> statement-breakpoint
ALTER TABLE "access_requests" ADD COLUMN "mac" text;--> statement-breakpoint
ALTER TABLE "audit_events" ADD COLUMN "seq" bigint;--> statement-breakpoint
ALTER TABLE "audit_events" ADD COLUMN "prev_hash" text;--> statement-breakpoint
ALTER TABLE "audit_events" ADD COLUMN "hash" text;--> statement-breakpoint
ALTER TABLE "audit_events" ADD COLUMN "mac" text;--> statement-breakpoint
ALTER TABLE "grants" ADD COLUMN "last_reviewed_at" timestamp(3) with time zone;--> statement-breakpoint
ALTER TABLE "grants" ADD COLUMN "last_reviewed_by" text;--> statement-breakpoint
CREATE UNIQUE INDEX "access_requests_org_seq_uq" ON "access_requests" USING btree ("organization_id","seq");--> statement-breakpoint
CREATE UNIQUE INDEX "audit_events_org_seq_uq" ON "audit_events" USING btree ("organization_id","seq");