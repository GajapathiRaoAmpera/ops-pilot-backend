"""organizations can be suspended or archived; memberships can be blocked

Revision ID: a7d3e9b2c4f1
Revises: f2a6c9e1d357
"""
import sqlalchemy as sa
from alembic import op

revision = "a7d3e9b2c4f1"
down_revision = "f2a6c9e1d357"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("organizations", sa.Column("status", sa.String(16), nullable=False, server_default="active"), schema="opspilot")
    op.add_column("organizations", sa.Column("status_changed_at", sa.DateTime(timezone=True), nullable=True), schema="opspilot")
    op.add_column("memberships", sa.Column("blocked", sa.Boolean(), nullable=False, server_default=sa.false()), schema="opspilot")


def downgrade() -> None:
    op.drop_column("memberships", "blocked", schema="opspilot")
    op.drop_column("organizations", "status_changed_at", schema="opspilot")
    op.drop_column("organizations", "status", schema="opspilot")
