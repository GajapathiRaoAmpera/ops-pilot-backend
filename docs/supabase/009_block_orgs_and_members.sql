-- Organizations can be blocked (suspended) or archived; memberships can be blocked. Run once after 008.
BEGIN;

ALTER TABLE opspilot.organizations ADD COLUMN status VARCHAR(16) NOT NULL DEFAULT 'active';
ALTER TABLE opspilot.organizations ADD COLUMN status_changed_at TIMESTAMP WITH TIME ZONE;
ALTER TABLE opspilot.memberships ADD COLUMN blocked BOOLEAN NOT NULL DEFAULT false;

UPDATE opspilot.alembic_version SET version_num = 'a7d3e9b2c4f1' WHERE version_num = 'f2a6c9e1d357';

COMMIT;
