BEGIN;

CREATE SCHEMA IF NOT EXISTS opspilot;

-- Running upgrade f6b7cee9de3a -> fa1c95ae6ab3

ALTER TABLE opspilot.users ADD COLUMN must_change_password BOOLEAN DEFAULT 'false' NOT NULL;

UPDATE opspilot.alembic_version SET version_num='fa1c95ae6ab3' WHERE opspilot.alembic_version.version_num = 'f6b7cee9de3a';

COMMIT;

