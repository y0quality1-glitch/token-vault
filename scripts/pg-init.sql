-- Local PostgreSQL bootstrap (development only; credentials are local defaults, not secrets).
-- Runs automatically when the Docker volume is first created. It is idempotent, so for an
-- existing volume you can apply it with:  npm run db:init
--
-- Three services, three roles:
--   token_vault           control plane      -> token_vault, token_vault_test, token_vault_e2e
--   token_vault_customer  customer webhook   -> token_vault_customer, *_test, *_e2e
--   token_vault_cms       provider CMS       -> token_vault_cms, *_test, *_e2e
-- The control plane's role cannot connect to the customer or CMS databases.

SELECT 'CREATE DATABASE token_vault_test OWNER token_vault'
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'token_vault_test') \gexec
SELECT 'CREATE DATABASE token_vault_e2e OWNER token_vault'
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'token_vault_e2e') \gexec

DO $$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'token_vault_customer') THEN
    CREATE ROLE token_vault_customer LOGIN PASSWORD 'token_vault_customer';
  END IF;
END $$;

SELECT 'CREATE DATABASE token_vault_customer OWNER token_vault_customer'
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'token_vault_customer') \gexec
SELECT 'CREATE DATABASE token_vault_customer_test OWNER token_vault_customer'
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'token_vault_customer_test') \gexec
SELECT 'CREATE DATABASE token_vault_customer_e2e OWNER token_vault_customer'
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'token_vault_customer_e2e') \gexec

REVOKE CONNECT ON DATABASE token_vault_customer, token_vault_customer_test, token_vault_customer_e2e FROM PUBLIC;

DO $$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'token_vault_cms') THEN
    CREATE ROLE token_vault_cms LOGIN PASSWORD 'token_vault_cms';
  END IF;
END $$;

SELECT 'CREATE DATABASE token_vault_cms OWNER token_vault_cms'
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'token_vault_cms') \gexec
SELECT 'CREATE DATABASE token_vault_cms_test OWNER token_vault_cms'
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'token_vault_cms_test') \gexec
SELECT 'CREATE DATABASE token_vault_cms_e2e OWNER token_vault_cms'
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'token_vault_cms_e2e') \gexec

REVOKE CONNECT ON DATABASE token_vault_cms, token_vault_cms_test, token_vault_cms_e2e FROM PUBLIC;
