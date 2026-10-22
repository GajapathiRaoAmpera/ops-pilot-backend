-- Fix agent: proposed code changes, linked to approval requests. Run once in the Supabase SQL editor (after 006).
BEGIN;

CREATE TABLE opspilot.fix_proposals (
    id UUID PRIMARY KEY,
    org_id UUID NOT NULL REFERENCES opspilot.organizations (id),
    workspace_id UUID NOT NULL REFERENCES opspilot.workspaces (id),
    run_id UUID NOT NULL REFERENCES opspilot.pipeline_runs (id),
    status VARCHAR(16) NOT NULL,
    title VARCHAR(200) NOT NULL,
    explanation TEXT NOT NULL,
    files JSON NOT NULL,
    diff TEXT NOT NULL,
    base_branch VARCHAR(200) NOT NULL,
    base_sha VARCHAR(40) NOT NULL,
    model VARCHAR(100) NOT NULL,
    trace JSON NOT NULL,
    created_by UUID NOT NULL REFERENCES opspilot.users (id),
    created_at TIMESTAMP WITH TIME ZONE NOT NULL
);
CREATE INDEX ix_opspilot_fix_proposals_workspace_id ON opspilot.fix_proposals (workspace_id);
CREATE INDEX ix_opspilot_fix_proposals_run_id ON opspilot.fix_proposals (run_id);
CREATE INDEX ix_opspilot_fix_proposals_created_at ON opspilot.fix_proposals (created_at);
ALTER TABLE opspilot.fix_proposals ENABLE ROW LEVEL SECURITY;

ALTER TABLE opspilot.action_requests ADD COLUMN proposal_id UUID REFERENCES opspilot.fix_proposals (id);

UPDATE opspilot.alembic_version SET version_num = 'e5f1b7d3a204' WHERE version_num = 'd4e8a1c5b902';

COMMIT;
