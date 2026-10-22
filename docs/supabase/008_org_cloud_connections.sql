-- Google Cloud connections belong to the organization (one per org), not a workspace. Run once after 007.
BEGIN;

CREATE TABLE opspilot.cloud_connections (
    id UUID PRIMARY KEY,
    org_id UUID NOT NULL REFERENCES opspilot.organizations (id),
    provider VARCHAR(32) NOT NULL,
    config JSON NOT NULL,
    secret_ciphertext TEXT,
    last_synced_at TIMESTAMP WITH TIME ZONE,
    updated_by UUID,
    updated_at TIMESTAMP WITH TIME ZONE,
    UNIQUE (org_id, provider)
);
CREATE INDEX ix_opspilot_cloud_connections_org_id ON opspilot.cloud_connections (org_id);
ALTER TABLE opspilot.cloud_connections ENABLE ROW LEVEL SECURITY;

-- Move existing per-workspace Google Cloud connections: the most recently updated one per organization.
INSERT INTO opspilot.cloud_connections (id, org_id, provider, config, secret_ciphertext, last_synced_at, updated_by, updated_at)
SELECT DISTINCT ON (org_id) id, org_id, provider, config, secret_ciphertext, last_synced_at, updated_by, updated_at
FROM opspilot.integrations WHERE provider = 'gcp'
ORDER BY org_id, updated_at DESC NULLS LAST;
DELETE FROM opspilot.integrations WHERE provider = 'gcp';

UPDATE opspilot.alembic_version SET version_num = 'f2a6c9e1d357' WHERE version_num = 'e5f1b7d3a204';

COMMIT;
