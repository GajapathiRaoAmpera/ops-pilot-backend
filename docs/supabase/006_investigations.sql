-- AI investigations of failed runs. Run once in the Supabase SQL editor (after 005).
BEGIN;

CREATE TABLE opspilot.investigations (
    id UUID PRIMARY KEY,
    org_id UUID NOT NULL REFERENCES opspilot.organizations (id),
    workspace_id UUID NOT NULL REFERENCES opspilot.workspaces (id),
    run_id UUID NOT NULL REFERENCES opspilot.pipeline_runs (id),
    summary TEXT NOT NULL,
    root_cause TEXT NOT NULL,
    confidence VARCHAR(16) NOT NULL,
    evidence JSON NOT NULL,
    evidence_verified BOOLEAN NOT NULL,
    next_steps JSON NOT NULL,
    suggested_action VARCHAR(64) NOT NULL,
    suggestion_reason TEXT NOT NULL,
    model VARCHAR(100) NOT NULL,
    created_by UUID NOT NULL REFERENCES opspilot.users (id),
    created_at TIMESTAMP WITH TIME ZONE NOT NULL
);
CREATE INDEX ix_opspilot_investigations_workspace_id ON opspilot.investigations (workspace_id);
CREATE INDEX ix_opspilot_investigations_run_id ON opspilot.investigations (run_id);
CREATE INDEX ix_opspilot_investigations_created_at ON opspilot.investigations (created_at);
ALTER TABLE opspilot.investigations ENABLE ROW LEVEL SECURITY;

UPDATE opspilot.alembic_version SET version_num = 'd4e8a1c5b902' WHERE version_num = 'b3d9f2a6c871';

COMMIT;
