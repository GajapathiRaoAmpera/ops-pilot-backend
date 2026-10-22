"""investigations: AI diagnoses of failed runs

Revision ID: d4e8a1c5b902
Revises: b3d9f2a6c871
"""
import sqlalchemy as sa
from alembic import op

revision = "d4e8a1c5b902"
down_revision = "b3d9f2a6c871"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "investigations",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("org_id", sa.Uuid(), sa.ForeignKey("opspilot.organizations.id"), nullable=False),
        sa.Column("workspace_id", sa.Uuid(), sa.ForeignKey("opspilot.workspaces.id"), nullable=False),
        sa.Column("run_id", sa.Uuid(), sa.ForeignKey("opspilot.pipeline_runs.id"), nullable=False),
        sa.Column("summary", sa.Text(), nullable=False),
        sa.Column("root_cause", sa.Text(), nullable=False),
        sa.Column("confidence", sa.String(16), nullable=False),
        sa.Column("evidence", sa.JSON(), nullable=False),
        sa.Column("evidence_verified", sa.Boolean(), nullable=False),
        sa.Column("next_steps", sa.JSON(), nullable=False),
        sa.Column("suggested_action", sa.String(64), nullable=False),
        sa.Column("suggestion_reason", sa.Text(), nullable=False),
        sa.Column("model", sa.String(100), nullable=False),
        sa.Column("created_by", sa.Uuid(), sa.ForeignKey("opspilot.users.id"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        schema="opspilot",
    )
    for col in ("workspace_id", "run_id", "created_at"):
        op.create_index(f"ix_opspilot_investigations_{col}", "investigations", [col], schema="opspilot")


def downgrade() -> None:
    op.drop_table("investigations", schema="opspilot")
