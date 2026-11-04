-- The CMS audit log is append-only: UPDATE and DELETE are rejected at the database level.
-- (TRUNCATE, used only by the test/e2e reset, does not fire row-level triggers.)
CREATE OR REPLACE FUNCTION cms_reject_audit_mutation() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION 'table % is append-only (% rejected)', TG_TABLE_NAME, TG_OP
    USING ERRCODE = 'insufficient_privilege';
END;
$$ LANGUAGE plpgsql;
--> statement-breakpoint
CREATE TRIGGER cms_audit_events_append_only
  BEFORE UPDATE OR DELETE ON cms_audit_events
  FOR EACH ROW EXECUTE FUNCTION cms_reject_audit_mutation();
--> statement-breakpoint
-- A published version is frozen: its definition, digest and signature can never change,
-- and the only allowed transition is PUBLISHED -> SUPERSEDED. Published versions are never deleted.
CREATE OR REPLACE FUNCTION cms_protect_published_version() RETURNS trigger AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    IF OLD.status IN ('PUBLISHED', 'SUPERSEDED') THEN
      RAISE EXCEPTION 'published versions cannot be deleted' USING ERRCODE = 'insufficient_privilege';
    END IF;
    RETURN OLD;
  END IF;
  IF OLD.status IN ('PUBLISHED', 'SUPERSEDED') THEN
    IF NEW.definition IS DISTINCT FROM OLD.definition OR NEW.digest IS DISTINCT FROM OLD.digest
       OR NEW.signature IS DISTINCT FROM OLD.signature OR NEW.version IS DISTINCT FROM OLD.version
       OR NOT (NEW.status = OLD.status OR (OLD.status = 'PUBLISHED' AND NEW.status = 'SUPERSEDED')) THEN
      RAISE EXCEPTION 'published version % is immutable', OLD.version USING ERRCODE = 'insufficient_privilege';
    END IF;
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;
--> statement-breakpoint
CREATE TRIGGER application_versions_protect_published
  BEFORE UPDATE OR DELETE ON application_versions
  FOR EACH ROW EXECUTE FUNCTION cms_protect_published_version();
