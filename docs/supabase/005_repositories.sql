-- Many GitHub repositories per workspace. Run once in the Supabase SQL editor (after 004).
BEGIN;

CREATE TABLE opspilot.repositories (
    id UUID PRIMARY KEY,
    org_id UUID NOT NULL REFERENCES opspilot.organizations (id),
    workspace_id UUID NOT NULL REFERENCES opspilot.workspaces (id),
    provider VARCHAR(32) NOT NULL,
    full_name VARCHAR(200) NOT NULL,
    secret_ciphertext TEXT,
    last_synced_at TIMESTAMP WITH TIME ZONE,
    created_by UUID,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
    UNIQUE (workspace_id, provider, full_name)
);
CREATE INDEX ix_opspilot_repositories_workspace_id ON opspilot.repositories (workspace_id);
CREATE INDEX ix_opspilot_repositories_full_name ON opspilot.repositories (full_name);
CREATE INDEX ix_opspilot_pipeline_runs_repo ON opspilot.pipeline_runs (workspace_id, repo);
ALTER TABLE opspilot.repositories ENABLE ROW LEVEL SECURITY;  -- same as the other tables: only the API's role reads it

-- Carry each workspace's existing repository over; it keeps using the workspace token.
INSERT INTO opspilot.repositories (id, org_id, workspace_id, provider, full_name, last_synced_at, created_by, created_at)
SELECT gen_random_uuid(), org_id, workspace_id, 'github', config->>'repo', last_synced_at, updated_by, now()
FROM opspilot.integrations WHERE provider = 'github' AND config->>'repo' IS NOT NULL;

UPDATE opspilot.alembic_version SET version_num = 'b3d9f2a6c871' WHERE version_num = '9c1e4a7b2d10';

COMMIT;
