"""repositories: many GitHub repositories per workspace

Revision ID: b3d9f2a6c871
Revises: 9c1e4a7b2d10
"""
import sqlalchemy as sa
from alembic import op

revision = "b3d9f2a6c871"
down_revision = "9c1e4a7b2d10"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "repositories",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("org_id", sa.Uuid(), sa.ForeignKey("opspilot.organizations.id"), nullable=False),
        sa.Column("workspace_id", sa.Uuid(), sa.ForeignKey("opspilot.workspaces.id"), nullable=False),
        sa.Column("provider", sa.String(32), nullable=False),
        sa.Column("full_name", sa.String(200), nullable=False),
        sa.Column("secret_ciphertext", sa.Text(), nullable=True),
        sa.Column("last_synced_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_by", sa.Uuid(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("workspace_id", "provider", "full_name"),
        schema="opspilot",
    )
    op.create_index("ix_opspilot_repositories_workspace_id", "repositories", ["workspace_id"], schema="opspilot")
    op.create_index("ix_opspilot_repositories_full_name", "repositories", ["full_name"], schema="opspilot")
    op.create_index("ix_opspilot_pipeline_runs_repo", "pipeline_runs", ["workspace_id", "repo"], schema="opspilot")
    # Carry each workspace's single repository over; it keeps using the workspace token (no own token).
    if op.get_bind().dialect.name == "postgresql":
        op.execute("""
            INSERT INTO opspilot.repositories (id, org_id, workspace_id, provider, full_name, last_synced_at, created_by, created_at)
            SELECT gen_random_uuid(), org_id, workspace_id, 'github', config->>'repo', last_synced_at, updated_by, now()
            FROM opspilot.integrations WHERE provider = 'github' AND config->>'repo' IS NOT NULL
        """)


def downgrade() -> None:
    op.drop_index("ix_opspilot_pipeline_runs_repo", table_name="pipeline_runs", schema="opspilot")
    op.drop_table("repositories", schema="opspilot")
