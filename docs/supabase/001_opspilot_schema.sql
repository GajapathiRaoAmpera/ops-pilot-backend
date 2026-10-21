BEGIN;

CREATE SCHEMA IF NOT EXISTS opspilot;

CREATE TABLE opspilot.alembic_version (
    version_num VARCHAR(32) NOT NULL, 
    CONSTRAINT alembic_version_pkc PRIMARY KEY (version_num)
);

-- Running upgrade  -> f6b7cee9de3a

CREATE TABLE opspilot.audit_events (
    id SERIAL NOT NULL, 
    ts TIMESTAMP WITH TIME ZONE NOT NULL, 
    org_id UUID, 
    workspace_id UUID, 
    actor_id UUID, 
    action VARCHAR(100) NOT NULL, 
    resource VARCHAR(200) NOT NULL, 
    outcome VARCHAR(20) NOT NULL, 
    detail TEXT NOT NULL, 
    PRIMARY KEY (id)
);

CREATE INDEX ix_opspilot_audit_events_org_id ON opspilot.audit_events (org_id);

CREATE INDEX ix_opspilot_audit_events_ts ON opspilot.audit_events (ts);

CREATE TABLE opspilot.organizations (
    id UUID NOT NULL, 
    name VARCHAR(200) NOT NULL, 
    PRIMARY KEY (id)
);

CREATE TABLE opspilot.roles (
    id UUID NOT NULL, 
    key VARCHAR(64) NOT NULL, 
    label VARCHAR(100) NOT NULL, 
    PRIMARY KEY (id), 
    UNIQUE (key)
);

CREATE TABLE opspilot.users (
    id UUID NOT NULL, 
    email VARCHAR(320) NOT NULL, 
    name VARCHAR(200) NOT NULL, 
    password_hash VARCHAR(255) NOT NULL, 
    disabled BOOLEAN NOT NULL, 
    PRIMARY KEY (id), 
    UNIQUE (email)
);

CREATE TABLE opspilot.role_permissions (
    role_id UUID NOT NULL, 
    permission VARCHAR(100) NOT NULL, 
    PRIMARY KEY (role_id, permission), 
    FOREIGN KEY(role_id) REFERENCES opspilot.roles (id)
);

CREATE TABLE opspilot.sessions (
    id_hash VARCHAR(64) NOT NULL, 
    user_id UUID NOT NULL, 
    created_at TIMESTAMP WITH TIME ZONE NOT NULL, 
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL, 
    revoked_at TIMESTAMP WITH TIME ZONE, 
    PRIMARY KEY (id_hash), 
    FOREIGN KEY(user_id) REFERENCES opspilot.users (id)
);

CREATE INDEX ix_opspilot_sessions_user_id ON opspilot.sessions (user_id);

CREATE TABLE opspilot.workspaces (
    id UUID NOT NULL, 
    org_id UUID NOT NULL, 
    name VARCHAR(200) NOT NULL, 
    PRIMARY KEY (id), 
    FOREIGN KEY(org_id) REFERENCES opspilot.organizations (id)
);

CREATE INDEX ix_opspilot_workspaces_org_id ON opspilot.workspaces (org_id);

CREATE TABLE opspilot.integrations (
    id UUID NOT NULL, 
    org_id UUID NOT NULL, 
    workspace_id UUID NOT NULL, 
    provider VARCHAR(32) NOT NULL, 
    config JSON NOT NULL, 
    last_synced_at TIMESTAMP WITH TIME ZONE, 
    PRIMARY KEY (id), 
    FOREIGN KEY(org_id) REFERENCES opspilot.organizations (id), 
    FOREIGN KEY(workspace_id) REFERENCES opspilot.workspaces (id), 
    UNIQUE (workspace_id, provider)
);

CREATE INDEX ix_opspilot_integrations_workspace_id ON opspilot.integrations (workspace_id);

CREATE TABLE opspilot.memberships (
    id UUID NOT NULL, 
    user_id UUID NOT NULL, 
    org_id UUID NOT NULL, 
    workspace_id UUID, 
    role_id UUID NOT NULL, 
    PRIMARY KEY (id), 
    FOREIGN KEY(org_id) REFERENCES opspilot.organizations (id), 
    FOREIGN KEY(role_id) REFERENCES opspilot.roles (id), 
    FOREIGN KEY(user_id) REFERENCES opspilot.users (id), 
    FOREIGN KEY(workspace_id) REFERENCES opspilot.workspaces (id), 
    UNIQUE (user_id, org_id, workspace_id)
);

CREATE INDEX ix_opspilot_memberships_user_id ON opspilot.memberships (user_id);

CREATE TABLE opspilot.pipeline_runs (
    id UUID NOT NULL, 
    org_id UUID NOT NULL, 
    workspace_id UUID NOT NULL, 
    provider VARCHAR(32) NOT NULL, 
    external_id VARCHAR(64) NOT NULL, 
    repo VARCHAR(200) NOT NULL, 
    workflow VARCHAR(200) NOT NULL, 
    branch VARCHAR(200) NOT NULL, 
    commit_sha VARCHAR(64) NOT NULL, 
    status VARCHAR(32) NOT NULL, 
    conclusion VARCHAR(32), 
    html_url VARCHAR(500) NOT NULL, 
    started_at TIMESTAMP WITH TIME ZONE, 
    fetched_at TIMESTAMP WITH TIME ZONE NOT NULL, 
    PRIMARY KEY (id), 
    FOREIGN KEY(org_id) REFERENCES opspilot.organizations (id), 
    FOREIGN KEY(workspace_id) REFERENCES opspilot.workspaces (id), 
    UNIQUE (workspace_id, provider, external_id)
);

CREATE INDEX ix_opspilot_pipeline_runs_workspace_id ON opspilot.pipeline_runs (workspace_id);

CREATE TABLE opspilot.action_requests (
    id UUID NOT NULL, 
    org_id UUID NOT NULL, 
    workspace_id UUID NOT NULL, 
    run_id UUID NOT NULL, 
    type VARCHAR(64) NOT NULL, 
    risk VARCHAR(16) NOT NULL, 
    status VARCHAR(16) NOT NULL, 
    reason VARCHAR(1000) NOT NULL, 
    requested_by UUID NOT NULL, 
    created_at TIMESTAMP WITH TIME ZONE NOT NULL, 
    PRIMARY KEY (id), 
    FOREIGN KEY(org_id) REFERENCES opspilot.organizations (id), 
    FOREIGN KEY(requested_by) REFERENCES opspilot.users (id), 
    FOREIGN KEY(run_id) REFERENCES opspilot.pipeline_runs (id), 
    FOREIGN KEY(workspace_id) REFERENCES opspilot.workspaces (id)
);

CREATE INDEX ix_opspilot_action_requests_status ON opspilot.action_requests (status);

CREATE INDEX ix_opspilot_action_requests_workspace_id ON opspilot.action_requests (workspace_id);

CREATE TABLE opspilot.approvals (
    id UUID NOT NULL, 
    request_id UUID NOT NULL, 
    decided_by UUID NOT NULL, 
    decision VARCHAR(16) NOT NULL, 
    reason VARCHAR(1000) NOT NULL, 
    decided_at TIMESTAMP WITH TIME ZONE NOT NULL, 
    PRIMARY KEY (id), 
    FOREIGN KEY(decided_by) REFERENCES opspilot.users (id), 
    FOREIGN KEY(request_id) REFERENCES opspilot.action_requests (id), 
    UNIQUE (request_id)
);

CREATE TABLE opspilot.executions (
    id UUID NOT NULL, 
    request_id UUID NOT NULL, 
    idempotency_key VARCHAR(128) NOT NULL, 
    status VARCHAR(16) NOT NULL, 
    started_at TIMESTAMP WITH TIME ZONE NOT NULL, 
    ended_at TIMESTAMP WITH TIME ZONE, 
    result JSON NOT NULL, 
    error VARCHAR(500) NOT NULL, 
    PRIMARY KEY (id), 
    FOREIGN KEY(request_id) REFERENCES opspilot.action_requests (id), 
    UNIQUE (idempotency_key), 
    UNIQUE (request_id)
);

ALTER TABLE opspilot.audit_events ENABLE ROW LEVEL SECURITY;

ALTER TABLE opspilot.organizations ENABLE ROW LEVEL SECURITY;

ALTER TABLE opspilot.roles ENABLE ROW LEVEL SECURITY;

ALTER TABLE opspilot.users ENABLE ROW LEVEL SECURITY;

ALTER TABLE opspilot.role_permissions ENABLE ROW LEVEL SECURITY;

ALTER TABLE opspilot.sessions ENABLE ROW LEVEL SECURITY;

ALTER TABLE opspilot.workspaces ENABLE ROW LEVEL SECURITY;

ALTER TABLE opspilot.integrations ENABLE ROW LEVEL SECURITY;

ALTER TABLE opspilot.memberships ENABLE ROW LEVEL SECURITY;

ALTER TABLE opspilot.pipeline_runs ENABLE ROW LEVEL SECURITY;

ALTER TABLE opspilot.action_requests ENABLE ROW LEVEL SECURITY;

ALTER TABLE opspilot.approvals ENABLE ROW LEVEL SECURITY;

ALTER TABLE opspilot.executions ENABLE ROW LEVEL SECURITY;

DO $$
        BEGIN
          IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'anon') THEN
            REVOKE ALL ON SCHEMA opspilot FROM anon;
            REVOKE ALL ON ALL TABLES IN SCHEMA opspilot FROM anon;
          END IF;
          IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authenticated') THEN
            REVOKE ALL ON SCHEMA opspilot FROM authenticated;
            REVOKE ALL ON ALL TABLES IN SCHEMA opspilot FROM authenticated;
          END IF;
        END $$;;

INSERT INTO opspilot.alembic_version (version_num) VALUES ('f6b7cee9de3a') RETURNING opspilot.alembic_version.version_num;

COMMIT;

