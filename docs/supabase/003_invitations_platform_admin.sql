BEGIN;

CREATE SCHEMA IF NOT EXISTS opspilot;

-- Running upgrade fa1c95ae6ab3 -> 6d32349ab86e

CREATE TABLE opspilot.invitations (
    id UUID NOT NULL, 
    kind VARCHAR(16) NOT NULL, 
    token_hash VARCHAR(64) NOT NULL, 
    org_id UUID NOT NULL, 
    workspace_id UUID, 
    role_id UUID, 
    email VARCHAR(320) NOT NULL, 
    user_id UUID, 
    invited_by UUID, 
    created_at TIMESTAMP WITH TIME ZONE NOT NULL, 
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL, 
    accepted_at TIMESTAMP WITH TIME ZONE, 
    revoked_at TIMESTAMP WITH TIME ZONE, 
    PRIMARY KEY (id), 
    FOREIGN KEY(invited_by) REFERENCES opspilot.users (id), 
    FOREIGN KEY(org_id) REFERENCES opspilot.organizations (id), 
    FOREIGN KEY(role_id) REFERENCES opspilot.roles (id), 
    FOREIGN KEY(user_id) REFERENCES opspilot.users (id), 
    FOREIGN KEY(workspace_id) REFERENCES opspilot.workspaces (id), 
    UNIQUE (token_hash)
);

CREATE INDEX ix_opspilot_invitations_org_id ON opspilot.invitations (org_id);

ALTER TABLE opspilot.users ADD COLUMN is_platform_admin BOOLEAN DEFAULT 'false' NOT NULL;

ALTER TABLE opspilot.invitations ENABLE ROW LEVEL SECURITY;

UPDATE opspilot.alembic_version SET version_num='6d32349ab86e' WHERE opspilot.alembic_version.version_num = 'fa1c95ae6ab3';

COMMIT;

