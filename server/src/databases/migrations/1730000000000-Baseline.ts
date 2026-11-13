import type { MigrationInterface, QueryRunner } from 'typeorm';

/**
 * The control-plane schema as built by the Drizzle migrations 0000-0016 (tables, indexes, the
 * append-only and hash-chain triggers). Drizzle recorded each applied step in
 * drizzle.__drizzle_migrations with its timestamp; this migration applies, in order, exactly
 * the steps a database has not had yet (all of them on an empty database, none on an
 * up-to-date one), then leaves schema changes to TypeORM migrations.
 */
const STEPS: { tag: string; when: number; statements: string[] }[] = [
  {
    tag: "0000_init",
    when: 1793782725909,
    statements: [
      "CREATE TABLE \"access_requests\" (\n\t\"id\" text PRIMARY KEY NOT NULL,\n\t\"organization_id\" text NOT NULL,\n\t\"agent_id\" text,\n\t\"agent_name\" text NOT NULL,\n\t\"integration_id\" text,\n\t\"integration_name\" text NOT NULL,\n\t\"grant_id\" text,\n\t\"grant_name\" text,\n\t\"operation\" text NOT NULL,\n\t\"resource\" jsonb NOT NULL,\n\t\"decision\" text NOT NULL,\n\t\"decision_code\" text NOT NULL,\n\t\"decision_reason\" text NOT NULL,\n\t\"matched_rule\" jsonb,\n\t\"execution_status\" text NOT NULL,\n\t\"upstream_status_code\" integer,\n\t\"webhook_status\" text NOT NULL,\n\t\"duration_ms\" integer NOT NULL,\n\t\"correlation_id\" text NOT NULL,\n\t\"source_ip\" text NOT NULL,\n\t\"source\" text NOT NULL,\n\t\"idempotency_key\" text,\n\t\"checks\" jsonb NOT NULL,\n\t\"created_at\" timestamp(3) with time zone NOT NULL\n);",
      "CREATE TABLE \"agents\" (\n\t\"id\" text PRIMARY KEY NOT NULL,\n\t\"organization_id\" text NOT NULL,\n\t\"name\" text NOT NULL,\n\t\"description\" text DEFAULT '' NOT NULL,\n\t\"agent_type\" text NOT NULL,\n\t\"environment\" text NOT NULL,\n\t\"owner_user_id\" text NOT NULL,\n\t\"owner_team\" text NOT NULL,\n\t\"callback_url\" text DEFAULT '' NOT NULL,\n\t\"allowed_cidrs\" jsonb DEFAULT '[]'::jsonb NOT NULL,\n\t\"credential_key_id\" text NOT NULL,\n\t\"credential_hash\" text NOT NULL,\n\t\"credential_issued_at\" timestamp(3) with time zone NOT NULL,\n\t\"status\" text NOT NULL,\n\t\"last_access_at\" timestamp(3) with time zone,\n\t\"created_at\" timestamp(3) with time zone NOT NULL,\n\tCONSTRAINT \"agents_credential_key_id_unique\" UNIQUE(\"credential_key_id\")\n);",
      "CREATE TABLE \"audit_events\" (\n\t\"id\" text PRIMARY KEY NOT NULL,\n\t\"organization_id\" text NOT NULL,\n\t\"actor_type\" text NOT NULL,\n\t\"actor_id\" text NOT NULL,\n\t\"actor_name\" text NOT NULL,\n\t\"event_type\" text NOT NULL,\n\t\"target_type\" text NOT NULL,\n\t\"target_id\" text NOT NULL,\n\t\"target_name\" text NOT NULL,\n\t\"outcome\" text NOT NULL,\n\t\"severity\" text NOT NULL,\n\t\"metadata\" jsonb NOT NULL,\n\t\"correlation_id\" text NOT NULL,\n\t\"created_at\" timestamp(3) with time zone NOT NULL\n);",
      "CREATE TABLE \"grants\" (\n\t\"id\" text PRIMARY KEY NOT NULL,\n\t\"organization_id\" text NOT NULL,\n\t\"agent_id\" text NOT NULL,\n\t\"integration_id\" text NOT NULL,\n\t\"name\" text NOT NULL,\n\t\"environment\" text NOT NULL,\n\t\"scopes\" jsonb NOT NULL,\n\t\"resource_constraints\" jsonb NOT NULL,\n\t\"rate_limit_per_minute\" integer NOT NULL,\n\t\"allowed_cidrs\" jsonb DEFAULT '[]'::jsonb NOT NULL,\n\t\"valid_from\" timestamp(3) with time zone NOT NULL,\n\t\"expires_at\" timestamp(3) with time zone NOT NULL,\n\t\"approval_required\" boolean DEFAULT false NOT NULL,\n\t\"status\" text NOT NULL,\n\t\"version\" integer DEFAULT 1 NOT NULL,\n\t\"previous_version_id\" text,\n\t\"created_by\" text NOT NULL,\n\t\"created_at\" timestamp(3) with time zone NOT NULL,\n\t\"approved_by\" text,\n\t\"approved_at\" timestamp(3) with time zone,\n\t\"revoked_at\" timestamp(3) with time zone,\n\t\"revoked_by\" text,\n\t\"revocation_reason\" text,\n\t\"last_used_at\" timestamp(3) with time zone,\n\t\"usage_count\" integer DEFAULT 0 NOT NULL\n);",
      "CREATE TABLE \"integrations\" (\n\t\"id\" text PRIMARY KEY NOT NULL,\n\t\"organization_id\" text NOT NULL,\n\t\"webhook_id\" text NOT NULL,\n\t\"provider\" text NOT NULL,\n\t\"display_name\" text NOT NULL,\n\t\"environment\" text NOT NULL,\n\t\"account_label\" text NOT NULL,\n\t\"auth_type\" text NOT NULL,\n\t\"credential_reference\" text NOT NULL,\n\t\"credential_status\" text NOT NULL,\n\t\"masked_identifier\" text DEFAULT '' NOT NULL,\n\t\"credential_fingerprint\" text DEFAULT '' NOT NULL,\n\t\"allowed_resources\" jsonb DEFAULT '[]'::jsonb NOT NULL,\n\t\"description\" text DEFAULT '' NOT NULL,\n\t\"created_by\" text NOT NULL,\n\t\"created_at\" timestamp(3) with time zone NOT NULL,\n\t\"updated_at\" timestamp(3) with time zone NOT NULL,\n\t\"last_validated_at\" timestamp(3) with time zone,\n\t\"rotated_at\" timestamp(3) with time zone,\n\t\"deleted_at\" timestamp(3) with time zone\n);",
      "CREATE TABLE \"organization_members\" (\n\t\"id\" text PRIMARY KEY NOT NULL,\n\t\"organization_id\" text NOT NULL,\n\t\"user_id\" text NOT NULL,\n\t\"role\" text NOT NULL,\n\t\"created_at\" timestamp(3) with time zone NOT NULL\n);",
      "CREATE TABLE \"organizations\" (\n\t\"id\" text PRIMARY KEY NOT NULL,\n\t\"name\" text NOT NULL,\n\t\"slug\" text NOT NULL,\n\t\"status\" text NOT NULL,\n\t\"environment\" text NOT NULL,\n\t\"created_at\" timestamp(3) with time zone NOT NULL,\n\t\"updated_at\" timestamp(3) with time zone NOT NULL,\n\tCONSTRAINT \"organizations_slug_unique\" UNIQUE(\"slug\")\n);",
      "CREATE TABLE \"policies\" (\n\t\"id\" text PRIMARY KEY NOT NULL,\n\t\"organization_id\" text NOT NULL,\n\t\"name\" text NOT NULL,\n\t\"description\" text DEFAULT '' NOT NULL,\n\t\"effect\" text NOT NULL,\n\t\"conditions\" jsonb NOT NULL,\n\t\"priority\" integer NOT NULL,\n\t\"enabled\" boolean NOT NULL,\n\t\"created_at\" timestamp(3) with time zone NOT NULL,\n\t\"updated_at\" timestamp(3) with time zone NOT NULL\n);",
      "CREATE TABLE \"sessions\" (\n\t\"token_hash\" text PRIMARY KEY NOT NULL,\n\t\"user_id\" text NOT NULL,\n\t\"organization_id\" text,\n\t\"created_at\" timestamp(3) with time zone NOT NULL,\n\t\"expires_at\" timestamp(3) with time zone NOT NULL\n);",
      "CREATE TABLE \"users\" (\n\t\"id\" text PRIMARY KEY NOT NULL,\n\t\"email\" text NOT NULL,\n\t\"password_hash\" text NOT NULL,\n\t\"full_name\" text NOT NULL,\n\t\"status\" text NOT NULL,\n\t\"created_at\" timestamp(3) with time zone NOT NULL,\n\tCONSTRAINT \"users_email_unique\" UNIQUE(\"email\")\n);",
      "CREATE TABLE \"webhooks\" (\n\t\"id\" text PRIMARY KEY NOT NULL,\n\t\"organization_id\" text NOT NULL,\n\t\"name\" text NOT NULL,\n\t\"endpoint_url\" text NOT NULL,\n\t\"environment\" text NOT NULL,\n\t\"description\" text DEFAULT '' NOT NULL,\n\t\"authentication_type\" text NOT NULL,\n\t\"signing_secret_ref\" text NOT NULL,\n\t\"status\" text NOT NULL,\n\t\"instance_id\" text,\n\t\"software_version\" text,\n\t\"last_heartbeat_at\" timestamp(3) with time zone,\n\t\"last_error\" text,\n\t\"simulate_outage\" boolean DEFAULT false NOT NULL,\n\t\"registration_challenge\" text,\n\t\"health_history\" jsonb DEFAULT '[]'::jsonb NOT NULL,\n\t\"created_at\" timestamp(3) with time zone NOT NULL,\n\t\"verified_at\" timestamp(3) with time zone\n);",
      "ALTER TABLE \"access_requests\" ADD CONSTRAINT \"access_requests_organization_id_organizations_id_fk\" FOREIGN KEY (\"organization_id\") REFERENCES \"public\".\"organizations\"(\"id\") ON DELETE cascade ON UPDATE no action;",
      "ALTER TABLE \"agents\" ADD CONSTRAINT \"agents_organization_id_organizations_id_fk\" FOREIGN KEY (\"organization_id\") REFERENCES \"public\".\"organizations\"(\"id\") ON DELETE cascade ON UPDATE no action;",
      "ALTER TABLE \"agents\" ADD CONSTRAINT \"agents_owner_user_id_users_id_fk\" FOREIGN KEY (\"owner_user_id\") REFERENCES \"public\".\"users\"(\"id\") ON DELETE no action ON UPDATE no action;",
      "ALTER TABLE \"audit_events\" ADD CONSTRAINT \"audit_events_organization_id_organizations_id_fk\" FOREIGN KEY (\"organization_id\") REFERENCES \"public\".\"organizations\"(\"id\") ON DELETE cascade ON UPDATE no action;",
      "ALTER TABLE \"grants\" ADD CONSTRAINT \"grants_organization_id_organizations_id_fk\" FOREIGN KEY (\"organization_id\") REFERENCES \"public\".\"organizations\"(\"id\") ON DELETE cascade ON UPDATE no action;",
      "ALTER TABLE \"grants\" ADD CONSTRAINT \"grants_agent_id_agents_id_fk\" FOREIGN KEY (\"agent_id\") REFERENCES \"public\".\"agents\"(\"id\") ON DELETE no action ON UPDATE no action;",
      "ALTER TABLE \"grants\" ADD CONSTRAINT \"grants_integration_id_integrations_id_fk\" FOREIGN KEY (\"integration_id\") REFERENCES \"public\".\"integrations\"(\"id\") ON DELETE no action ON UPDATE no action;",
      "ALTER TABLE \"integrations\" ADD CONSTRAINT \"integrations_organization_id_organizations_id_fk\" FOREIGN KEY (\"organization_id\") REFERENCES \"public\".\"organizations\"(\"id\") ON DELETE cascade ON UPDATE no action;",
      "ALTER TABLE \"integrations\" ADD CONSTRAINT \"integrations_webhook_id_webhooks_id_fk\" FOREIGN KEY (\"webhook_id\") REFERENCES \"public\".\"webhooks\"(\"id\") ON DELETE no action ON UPDATE no action;",
      "ALTER TABLE \"organization_members\" ADD CONSTRAINT \"organization_members_organization_id_organizations_id_fk\" FOREIGN KEY (\"organization_id\") REFERENCES \"public\".\"organizations\"(\"id\") ON DELETE cascade ON UPDATE no action;",
      "ALTER TABLE \"organization_members\" ADD CONSTRAINT \"organization_members_user_id_users_id_fk\" FOREIGN KEY (\"user_id\") REFERENCES \"public\".\"users\"(\"id\") ON DELETE cascade ON UPDATE no action;",
      "ALTER TABLE \"policies\" ADD CONSTRAINT \"policies_organization_id_organizations_id_fk\" FOREIGN KEY (\"organization_id\") REFERENCES \"public\".\"organizations\"(\"id\") ON DELETE cascade ON UPDATE no action;",
      "ALTER TABLE \"webhooks\" ADD CONSTRAINT \"webhooks_organization_id_organizations_id_fk\" FOREIGN KEY (\"organization_id\") REFERENCES \"public\".\"organizations\"(\"id\") ON DELETE cascade ON UPDATE no action;",
      "CREATE INDEX \"access_requests_org_created_idx\" ON \"access_requests\" USING btree (\"organization_id\",\"created_at\");",
      "CREATE INDEX \"access_requests_grant_idx\" ON \"access_requests\" USING btree (\"grant_id\");",
      "CREATE INDEX \"access_requests_agent_idx\" ON \"access_requests\" USING btree (\"agent_id\");",
      "CREATE INDEX \"access_requests_correlation_idx\" ON \"access_requests\" USING btree (\"correlation_id\");",
      "CREATE INDEX \"agents_org_idx\" ON \"agents\" USING btree (\"organization_id\");",
      "CREATE INDEX \"audit_events_org_created_idx\" ON \"audit_events\" USING btree (\"organization_id\",\"created_at\");",
      "CREATE INDEX \"audit_events_correlation_idx\" ON \"audit_events\" USING btree (\"correlation_id\");",
      "CREATE INDEX \"grants_org_idx\" ON \"grants\" USING btree (\"organization_id\");",
      "CREATE INDEX \"grants_agent_integration_idx\" ON \"grants\" USING btree (\"agent_id\",\"integration_id\");",
      "CREATE INDEX \"integrations_org_idx\" ON \"integrations\" USING btree (\"organization_id\");",
      "CREATE UNIQUE INDEX \"organization_members_org_user_uq\" ON \"organization_members\" USING btree (\"organization_id\",\"user_id\");",
      "CREATE INDEX \"policies_org_idx\" ON \"policies\" USING btree (\"organization_id\");",
      "CREATE INDEX \"sessions_expires_at_idx\" ON \"sessions\" USING btree (\"expires_at\");",
      "CREATE INDEX \"webhooks_org_idx\" ON \"webhooks\" USING btree (\"organization_id\");",
    ],
  },
  {
    tag: "0001_audit_append_only",
    when: 1793782726679,
    statements: [
      "-- Audit records are append-only: UPDATE and DELETE are rejected at the database level,\n-- so not even a bug in the application can rewrite history. (TRUNCATE, used only by the\n-- POC's demo reset, does not fire row-level triggers.)\nCREATE OR REPLACE FUNCTION token_vault_reject_audit_mutation() RETURNS trigger AS $$\nBEGIN\n  RAISE EXCEPTION 'table % is append-only (% rejected)', TG_TABLE_NAME, TG_OP\n    USING ERRCODE = 'insufficient_privilege';\nEND;\n$$ LANGUAGE plpgsql;",
      "CREATE TRIGGER access_requests_append_only\n  BEFORE UPDATE OR DELETE ON access_requests\n  FOR EACH ROW EXECUTE FUNCTION token_vault_reject_audit_mutation();",
      "CREATE TRIGGER audit_events_append_only\n  BEFORE UPDATE OR DELETE ON audit_events\n  FOR EACH ROW EXECUTE FUNCTION token_vault_reject_audit_mutation();",
    ],
  },
  {
    tag: "0002_grant_requests",
    when: 1793791682813,
    statements: [
      "CREATE TABLE \"grant_requests\" (\n\t\"id\" text PRIMARY KEY NOT NULL,\n\t\"organization_id\" text NOT NULL,\n\t\"agent_id\" text NOT NULL,\n\t\"integration_id\" text NOT NULL,\n\t\"operations\" jsonb NOT NULL,\n\t\"repositories\" jsonb DEFAULT '[]'::jsonb NOT NULL,\n\t\"justification\" text NOT NULL,\n\t\"requested_duration_minutes\" integer NOT NULL,\n\t\"denied_request_id\" text,\n\t\"status\" text NOT NULL,\n\t\"created_at\" timestamp(3) with time zone NOT NULL,\n\t\"expires_at\" timestamp(3) with time zone NOT NULL,\n\t\"decided_by\" text,\n\t\"decided_at\" timestamp(3) with time zone,\n\t\"decision_note\" text,\n\t\"approved_duration_minutes\" integer,\n\t\"grant_id\" text\n);",
      "ALTER TABLE \"grant_requests\" ADD CONSTRAINT \"grant_requests_organization_id_organizations_id_fk\" FOREIGN KEY (\"organization_id\") REFERENCES \"public\".\"organizations\"(\"id\") ON DELETE cascade ON UPDATE no action;",
      "ALTER TABLE \"grant_requests\" ADD CONSTRAINT \"grant_requests_agent_id_agents_id_fk\" FOREIGN KEY (\"agent_id\") REFERENCES \"public\".\"agents\"(\"id\") ON DELETE no action ON UPDATE no action;",
      "ALTER TABLE \"grant_requests\" ADD CONSTRAINT \"grant_requests_integration_id_integrations_id_fk\" FOREIGN KEY (\"integration_id\") REFERENCES \"public\".\"integrations\"(\"id\") ON DELETE no action ON UPDATE no action;",
      "CREATE INDEX \"grant_requests_org_status_idx\" ON \"grant_requests\" USING btree (\"organization_id\",\"status\");",
      "CREATE INDEX \"grant_requests_agent_idx\" ON \"grant_requests\" USING btree (\"agent_id\");",
    ],
  },
  {
    tag: "0003_audit_chain_access_reviews",
    when: 1793805669142,
    statements: [
      "ALTER TABLE \"access_requests\" ADD COLUMN \"seq\" bigint;",
      "ALTER TABLE \"access_requests\" ADD COLUMN \"prev_hash\" text;",
      "ALTER TABLE \"access_requests\" ADD COLUMN \"hash\" text;",
      "ALTER TABLE \"access_requests\" ADD COLUMN \"mac\" text;",
      "ALTER TABLE \"audit_events\" ADD COLUMN \"seq\" bigint;",
      "ALTER TABLE \"audit_events\" ADD COLUMN \"prev_hash\" text;",
      "ALTER TABLE \"audit_events\" ADD COLUMN \"hash\" text;",
      "ALTER TABLE \"audit_events\" ADD COLUMN \"mac\" text;",
      "ALTER TABLE \"grants\" ADD COLUMN \"last_reviewed_at\" timestamp(3) with time zone;",
      "ALTER TABLE \"grants\" ADD COLUMN \"last_reviewed_by\" text;",
      "CREATE UNIQUE INDEX \"access_requests_org_seq_uq\" ON \"access_requests\" USING btree (\"organization_id\",\"seq\");",
      "CREATE UNIQUE INDEX \"audit_events_org_seq_uq\" ON \"audit_events\" USING btree (\"organization_id\",\"seq\");",
    ],
  },
  {
    tag: "0004_provider_catalog_state",
    when: 1793852893970,
    statements: [
      "CREATE TABLE \"provider_catalog_state\" (\n\t\"id\" integer PRIMARY KEY NOT NULL,\n\t\"envelopes\" jsonb NOT NULL,\n\t\"high_water\" jsonb NOT NULL,\n\t\"saved_at\" timestamp(3) with time zone NOT NULL\n);",
    ],
  },
  {
    tag: "0005_oauth_pending",
    when: 1793854828201,
    statements: [
      "CREATE TABLE \"oauth_pending\" (\n\t\"state_hash\" text PRIMARY KEY NOT NULL,\n\t\"organization_id\" text NOT NULL,\n\t\"user_id\" text NOT NULL,\n\t\"webhook_id\" text NOT NULL,\n\t\"credential_reference\" text NOT NULL,\n\t\"draft\" jsonb NOT NULL,\n\t\"created_at\" timestamp(3) with time zone NOT NULL,\n\t\"expires_at\" timestamp(3) with time zone NOT NULL\n);",
    ],
  },
  {
    tag: "0006_agent_key_grace",
    when: 1793986405600,
    statements: [
      "ALTER TABLE \"agents\" ADD COLUMN \"previous_credential_key_id\" text;",
      "ALTER TABLE \"agents\" ADD COLUMN \"previous_credential_hash\" text;",
      "ALTER TABLE \"agents\" ADD COLUMN \"previous_credential_expires_at\" timestamp(3) with time zone;",
      "ALTER TABLE \"agents\" ADD COLUMN \"previous_credential_last_used_at\" timestamp(3) with time zone;",
      "ALTER TABLE \"agents\" ADD CONSTRAINT \"agents_previous_credential_key_id_unique\" UNIQUE(\"previous_credential_key_id\");",
    ],
  },
  {
    tag: "0007_integration_rotation_interval",
    when: 1793987352224,
    statements: [
      "ALTER TABLE \"integrations\" ADD COLUMN \"rotation_interval_days\" integer;",
    ],
  },
  {
    tag: "0008_operation_approvals",
    when: 1794302159816,
    statements: [
      "CREATE TABLE \"operation_approvals\" (\n\t\"id\" text PRIMARY KEY NOT NULL,\n\t\"organization_id\" text NOT NULL,\n\t\"agent_id\" text NOT NULL,\n\t\"integration_id\" text NOT NULL,\n\t\"policy_id\" text NOT NULL,\n\t\"policy_name\" text NOT NULL,\n\t\"operation\" text NOT NULL,\n\t\"resource\" jsonb NOT NULL,\n\t\"input\" jsonb NOT NULL,\n\t\"request_digest\" text NOT NULL,\n\t\"status\" text NOT NULL,\n\t\"requested_by_request_id\" text NOT NULL,\n\t\"created_at\" timestamp(3) with time zone NOT NULL,\n\t\"expires_at\" timestamp(3) with time zone NOT NULL,\n\t\"decided_by\" text,\n\t\"decided_at\" timestamp(3) with time zone,\n\t\"decision_note\" text,\n\t\"executed_at\" timestamp(3) with time zone,\n\t\"executed_request_id\" text\n);",
      "ALTER TABLE \"operation_approvals\" ADD CONSTRAINT \"operation_approvals_organization_id_organizations_id_fk\" FOREIGN KEY (\"organization_id\") REFERENCES \"public\".\"organizations\"(\"id\") ON DELETE cascade ON UPDATE no action;",
      "ALTER TABLE \"operation_approvals\" ADD CONSTRAINT \"operation_approvals_agent_id_agents_id_fk\" FOREIGN KEY (\"agent_id\") REFERENCES \"public\".\"agents\"(\"id\") ON DELETE no action ON UPDATE no action;",
      "ALTER TABLE \"operation_approvals\" ADD CONSTRAINT \"operation_approvals_integration_id_integrations_id_fk\" FOREIGN KEY (\"integration_id\") REFERENCES \"public\".\"integrations\"(\"id\") ON DELETE no action ON UPDATE no action;",
      "CREATE INDEX \"operation_approvals_org_status_idx\" ON \"operation_approvals\" USING btree (\"organization_id\",\"status\");",
      "CREATE INDEX \"operation_approvals_agent_digest_idx\" ON \"operation_approvals\" USING btree (\"agent_id\",\"request_digest\");",
    ],
  },
  {
    tag: "0009_budgets_emergency_stop",
    when: 1794310987904,
    statements: [
      "ALTER TABLE \"grants\" ADD COLUMN \"max_requests_per_day\" integer;",
      "ALTER TABLE \"grants\" ADD COLUMN \"max_writes_per_hour\" integer;",
      "ALTER TABLE \"organizations\" ADD COLUMN \"emergency_stopped_at\" timestamp(3) with time zone;",
      "ALTER TABLE \"organizations\" ADD COLUMN \"emergency_stopped_by\" text;",
      "ALTER TABLE \"organizations\" ADD COLUMN \"emergency_stop_reason\" text;",
    ],
  },
  {
    tag: "0010_acting_users",
    when: 1794383032445,
    statements: [
      "CREATE TABLE \"user_issuers\" (\n\t\"id\" text PRIMARY KEY NOT NULL,\n\t\"organization_id\" text NOT NULL,\n\t\"name\" text NOT NULL,\n\t\"issuer\" text NOT NULL,\n\t\"audience\" text NOT NULL,\n\t\"public_key\" text NOT NULL,\n\t\"key_fingerprint\" text NOT NULL,\n\t\"groups_claim\" text DEFAULT 'groups' NOT NULL,\n\t\"max_token_lifetime_seconds\" integer DEFAULT 3600 NOT NULL,\n\t\"enabled\" boolean DEFAULT true NOT NULL,\n\t\"created_at\" timestamp(3) with time zone NOT NULL,\n\t\"updated_at\" timestamp(3) with time zone NOT NULL,\n\t\"last_used_at\" timestamp(3) with time zone\n);",
      "ALTER TABLE \"access_requests\" ADD COLUMN \"on_behalf_of\" jsonb;",
      "ALTER TABLE \"grants\" ADD COLUMN \"on_behalf_of\" text DEFAULT 'ALLOWED' NOT NULL;",
      "ALTER TABLE \"grants\" ADD COLUMN \"allowed_user_groups\" jsonb DEFAULT '[]'::jsonb NOT NULL;",
      "ALTER TABLE \"operation_approvals\" ADD COLUMN \"on_behalf_of\" jsonb;",
      "ALTER TABLE \"user_issuers\" ADD CONSTRAINT \"user_issuers_organization_id_organizations_id_fk\" FOREIGN KEY (\"organization_id\") REFERENCES \"public\".\"organizations\"(\"id\") ON DELETE cascade ON UPDATE no action;",
      "CREATE UNIQUE INDEX \"user_issuers_org_issuer_uq\" ON \"user_issuers\" USING btree (\"organization_id\",\"issuer\");",
    ],
  },
  {
    tag: "0011_delegations",
    when: 1794385945402,
    statements: [
      "CREATE TABLE \"delegations\" (\n\t\"id\" text PRIMARY KEY NOT NULL,\n\t\"organization_id\" text NOT NULL,\n\t\"agent_id\" text NOT NULL,\n\t\"grant_id\" text NOT NULL,\n\t\"parent_delegation_id\" text,\n\t\"depth\" integer NOT NULL,\n\t\"label\" text NOT NULL,\n\t\"operations\" jsonb NOT NULL,\n\t\"resources\" jsonb DEFAULT '[]'::jsonb NOT NULL,\n\t\"max_requests\" integer,\n\t\"on_behalf_of\" jsonb,\n\t\"key_id\" text NOT NULL,\n\t\"credential_hash\" text NOT NULL,\n\t\"created_at\" timestamp(3) with time zone NOT NULL,\n\t\"expires_at\" timestamp(3) with time zone NOT NULL,\n\t\"revoked_at\" timestamp(3) with time zone,\n\t\"revoked_by\" text,\n\t\"revocation_reason\" text,\n\t\"last_used_at\" timestamp(3) with time zone,\n\tCONSTRAINT \"delegations_key_id_unique\" UNIQUE(\"key_id\")\n);",
      "ALTER TABLE \"access_requests\" ADD COLUMN \"delegation\" jsonb;",
      "ALTER TABLE \"operation_approvals\" ADD COLUMN \"delegation\" jsonb;",
      "ALTER TABLE \"delegations\" ADD CONSTRAINT \"delegations_organization_id_organizations_id_fk\" FOREIGN KEY (\"organization_id\") REFERENCES \"public\".\"organizations\"(\"id\") ON DELETE cascade ON UPDATE no action;",
      "ALTER TABLE \"delegations\" ADD CONSTRAINT \"delegations_agent_id_agents_id_fk\" FOREIGN KEY (\"agent_id\") REFERENCES \"public\".\"agents\"(\"id\") ON DELETE no action ON UPDATE no action;",
      "CREATE INDEX \"delegations_org_idx\" ON \"delegations\" USING btree (\"organization_id\");",
      "CREATE INDEX \"delegations_agent_idx\" ON \"delegations\" USING btree (\"agent_id\");",
      "CREATE INDEX \"delegations_grant_idx\" ON \"delegations\" USING btree (\"grant_id\");",
      "CREATE INDEX \"delegations_parent_idx\" ON \"delegations\" USING btree (\"parent_delegation_id\");",
    ],
  },
  {
    tag: "0012_response_filtering",
    when: 1794392709065,
    statements: [
      "ALTER TABLE \"access_requests\" ADD COLUMN \"filtering\" jsonb;",
      "ALTER TABLE \"policies\" ADD COLUMN \"response_filter\" jsonb;",
    ],
  },
  {
    tag: "0013_session_tracing",
    when: 1794395913704,
    statements: [
      "ALTER TABLE \"access_requests\" ADD COLUMN \"trace\" jsonb;",
      "CREATE INDEX \"access_requests_org_session_idx\" ON \"access_requests\" USING btree (\"organization_id\",(\"trace\"->>'sessionId'));",
    ],
  },
  {
    tag: "0014_slack_approvals",
    when: 1794397717540,
    statements: [
      "CREATE TABLE \"slack_settings\" (\n\t\"organization_id\" text PRIMARY KEY NOT NULL,\n\t\"team_id\" text NOT NULL,\n\t\"team_name\" text NOT NULL,\n\t\"bot_user_id\" text NOT NULL,\n\t\"channel_id\" text NOT NULL,\n\t\"bot_token_sealed\" text NOT NULL,\n\t\"bot_token_hint\" text NOT NULL,\n\t\"signing_secret_sealed\" text NOT NULL,\n\t\"enabled\" boolean DEFAULT true NOT NULL,\n\t\"updated_at\" timestamp(3) with time zone NOT NULL,\n\t\"updated_by\" text NOT NULL\n);",
      "ALTER TABLE \"operation_approvals\" ADD COLUMN \"notifications\" jsonb;",
      "ALTER TABLE \"slack_settings\" ADD CONSTRAINT \"slack_settings_organization_id_organizations_id_fk\" FOREIGN KEY (\"organization_id\") REFERENCES \"public\".\"organizations\"(\"id\") ON DELETE cascade ON UPDATE no action;",
    ],
  },
  {
    tag: "0015_slack_team_unique",
    when: 1794474550912,
    statements: [
      "CREATE UNIQUE INDEX \"slack_settings_team_uq\" ON \"slack_settings\" USING btree (\"team_id\");",
    ],
  },
  {
    tag: "0016_integration_access_mode",
    when: 1794485161516,
    statements: [
      "ALTER TABLE \"integrations\" ADD COLUMN \"access_mode\" text DEFAULT 'BROKERED' NOT NULL;",
    ],
  }
];

export class Baseline1730000000000 implements MigrationInterface {
  name = 'Baseline1730000000000';

  async up(qr: QueryRunner): Promise<void> {
    const [{ tracked }] = await qr.query(`SELECT to_regclass('drizzle.__drizzle_migrations') IS NOT NULL AS tracked`);
    let last = 0;
    if (tracked) {
      const [row] = await qr.query('SELECT max(created_at)::text AS last FROM drizzle.__drizzle_migrations');
      last = Number(row?.last ?? 0);
    }
    for (const step of STEPS) {
      if (step.when <= last) continue;
      for (const sql of step.statements) await qr.query(sql);
    }
  }

  async down(): Promise<void> {
    throw new Error('The baseline cannot be reverted: drop the database instead.');
  }
}
