CREATE TABLE "provider_catalog_state" (
	"id" integer PRIMARY KEY NOT NULL,
	"envelopes" jsonb NOT NULL,
	"high_water" jsonb NOT NULL,
	"saved_at" timestamp(3) with time zone NOT NULL
);
