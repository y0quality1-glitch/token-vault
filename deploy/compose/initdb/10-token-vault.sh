#!/bin/sh
# Creates one role and one database per Token Vault service, on first start of the volume.
# Passwords come from the environment (deploy/compose/.env), never from this file.
# Like production, each service can reach only its own database.
set -eu
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname postgres \
  -v cp_pw="$CONTROL_PLANE_DB_PASSWORD" -v wh_pw="$WEBHOOK_DB_PASSWORD" -v cms_pw="$CMS_DB_PASSWORD" <<'SQL'
CREATE ROLE token_vault LOGIN PASSWORD :'cp_pw';
CREATE ROLE token_vault_customer LOGIN PASSWORD :'wh_pw';
CREATE ROLE token_vault_cms LOGIN PASSWORD :'cms_pw';
CREATE DATABASE token_vault OWNER token_vault;
CREATE DATABASE token_vault_customer OWNER token_vault_customer;
CREATE DATABASE token_vault_cms OWNER token_vault_cms;
REVOKE CONNECT ON DATABASE token_vault, token_vault_customer, token_vault_cms FROM PUBLIC;
GRANT CONNECT ON DATABASE token_vault TO token_vault;
GRANT CONNECT ON DATABASE token_vault_customer TO token_vault_customer;
GRANT CONNECT ON DATABASE token_vault_cms TO token_vault_cms;
SQL
