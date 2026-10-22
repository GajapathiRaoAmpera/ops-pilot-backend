"""cloud connections belong to the organization, not a workspace

Revision ID: f2a6c9e1d357
Revises: e5f1b7d3a204
"""
import sqlalchemy as sa
from alembic import op

revision = "f2a6c9e1d357"
down_revision = "e5f1b7d3a204"
branch_labels = None
depends_on = None

MOVE = """
INSERT INTO opspilot.cloud_connections (id, org_id, provider, config, secret_ciphertext, last_synced_at, updated_by, updated_at)
SELECT DISTINCT ON (org_id) id, org_id, provider, config, secret_ciphertext, last_synced_at, updated_by, updated_at
FROM opspilot.integrations WHERE provider = 'gcp'
ORDER BY org_id, updated_at DESC NULLS LAST;
DELETE FROM opspilot.integrations WHERE provider = 'gcp';
"""


def upgrade() -> None:
    op.create_table(
        "cloud_connections",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("org_id", sa.Uuid(), sa.ForeignKey("opspilot.organizations.id"), nullable=False),
        sa.Column("provider", sa.String(32), nullable=False),
        sa.Column("config", sa.JSON(), nullable=False),
        sa.Column("secret_ciphertext", sa.Text(), nullable=True),
        sa.Column("last_synced_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("updated_by", sa.Uuid(), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint("org_id", "provider"),
        schema="opspilot",
    )
    op.create_index("ix_opspilot_cloud_connections_org_id", "cloud_connections", ["org_id"], schema="opspilot")
    if op.get_bind().dialect.name == "postgresql":
        op.execute(MOVE)


def downgrade() -> None:
    op.drop_table("cloud_connections", schema="opspilot")  # connections are not moved back; reconnect after downgrading
