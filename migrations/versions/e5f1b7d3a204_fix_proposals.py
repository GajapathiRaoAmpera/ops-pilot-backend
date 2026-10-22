"""fix proposals: code changes proposed by the fix agent, linked to action requests

Revision ID: e5f1b7d3a204
Revises: d4e8a1c5b902
"""
import sqlalchemy as sa
from alembic import op

revision = "e5f1b7d3a204"
down_revision = "d4e8a1c5b902"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "fix_proposals",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("org_id", sa.Uuid(), sa.ForeignKey("opspilot.organizations.id"), nullable=False),
        sa.Column("workspace_id", sa.Uuid(), sa.ForeignKey("opspilot.workspaces.id"), nullable=False),
        sa.Column("run_id", sa.Uuid(), sa.ForeignKey("opspilot.pipeline_runs.id"), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("title", sa.String(200), nullable=False),
        sa.Column("explanation", sa.Text(), nullable=False),
        sa.Column("files", sa.JSON(), nullable=False),
        sa.Column("diff", sa.Text(), nullable=False),
        sa.Column("base_branch", sa.String(200), nullable=False),
        sa.Column("base_sha", sa.String(40), nullable=False),
        sa.Column("model", sa.String(100), nullable=False),
        sa.Column("trace", sa.JSON(), nullable=False),
        sa.Column("created_by", sa.Uuid(), sa.ForeignKey("opspilot.users.id"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        schema="opspilot",
    )
    for col in ("workspace_id", "run_id", "created_at"):
        op.create_index(f"ix_opspilot_fix_proposals_{col}", "fix_proposals", [col], schema="opspilot")
    op.add_column("action_requests", sa.Column("proposal_id", sa.Uuid(), sa.ForeignKey("opspilot.fix_proposals.id"),
                                               nullable=True), schema="opspilot")


def downgrade() -> None:
    op.drop_column("action_requests", "proposal_id", schema="opspilot")
    op.drop_table("fix_proposals", schema="opspilot")
