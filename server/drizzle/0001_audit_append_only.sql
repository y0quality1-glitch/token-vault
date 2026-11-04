-- Audit records are append-only: UPDATE and DELETE are rejected at the database level,
-- so not even a bug in the application can rewrite history. (TRUNCATE, used only by the
-- POC's demo reset, does not fire row-level triggers.)
CREATE OR REPLACE FUNCTION token_vault_reject_audit_mutation() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION 'table % is append-only (% rejected)', TG_TABLE_NAME, TG_OP
    USING ERRCODE = 'insufficient_privilege';
END;
$$ LANGUAGE plpgsql;
--> statement-breakpoint
CREATE TRIGGER access_requests_append_only
  BEFORE UPDATE OR DELETE ON access_requests
  FOR EACH ROW EXECUTE FUNCTION token_vault_reject_audit_mutation();
--> statement-breakpoint
CREATE TRIGGER audit_events_append_only
  BEFORE UPDATE OR DELETE ON audit_events
  FOR EACH ROW EXECUTE FUNCTION token_vault_reject_audit_mutation();
