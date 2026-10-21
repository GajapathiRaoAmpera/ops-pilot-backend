BEGIN;

CREATE SCHEMA IF NOT EXISTS opspilot;

-- Running upgrade 6d32349ab86e -> 9c1e4a7b2d10

ALTER TABLE opspilot.integrations ADD COLUMN secret_ciphertext TEXT;

ALTER TABLE opspilot.integrations ADD COLUMN updated_by UUID;

ALTER TABLE opspilot.integrations ADD COLUMN updated_at TIMESTAMP WITH TIME ZONE;

UPDATE opspilot.alembic_version SET version_num='9c1e4a7b2d10' WHERE opspilot.alembic_version.version_num = '6d32349ab86e';

COMMIT;

