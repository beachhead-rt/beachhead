-- 005_drop_azure_tables.sql — remove Entra ID / Azure ARM tables
-- Beachhead is ADO-only; these Azure-specific tables are unused.

DROP TABLE IF EXISTS identities;
DROP TABLE IF EXISTS role_assignments;
DROP TABLE IF EXISTS service_principals;
DROP TABLE IF EXISTS oauth_grants;
DROP TABLE IF EXISTS managed_identities;
DROP TABLE IF EXISTS group_members;
DROP TABLE IF EXISTS devices;
